#!/usr/bin/env bash
# fetch-corpus-bundle.sh — download ONE policy's advisory-corpus bundle from a corpus release and pin
# it before the scanner sees it. Called by action.yml's "Fetch the advisory corpus bundle" step; also
# runnable by hand.
#
# Inputs (env):
#   CORPUS_REPO    owner/repo of the public corpus repository (e.g. ferralon-ai/vulnerability-corpus)
#   CORPUS_REF     `corpus-<12 hex>` names a release; `latest` or `main` resolves the latest release;
#                  anything else (a branch or commit SHA) cannot name a release -> route=git
#   CORPUS_POLICY  policy id, e.g. published-7d
#   CORPUS_SIGNER_IDENTITY  certificate identity the release's bundles.json must be signed by
#   CORPUS_SIGNER_ISSUER    OIDC issuer of that identity
#                  Both are required whenever a release is read; neither has a default (Assay names no
#                  signer of its own). Unused on the route=git exit for a ref that names no release.
#   DEST           directory the verified bundle is written into, as DEST/<policy>.jsonl.gz
#   CORPUS_REQUIRE_BUNDLE  (optional) "1" turns both route=git exits into failures: the run reads a
#                  verified bundle or nothing. action.yml sets it for the default policy.
#   PATH           must carry cosign 3.x; action.yml puts the pinned scripts/install-cosign.sh binary first
#   CORPUS_GITHUB  (optional) base URL for releases + git, default https://github.com
#   CORPUS_RAW     (optional) base URL for raw repository files, default https://raw.githubusercontent.com
#
# Outputs (appended to $GITHUB_OUTPUT when set, always echoed):
#   route=bundle   DEST/<policy>.jsonl.gz exists and passed every check below
#   route=git      the release carries no bundle for this policy (a manifest-only policy) or the ref is
#                  not a release; the caller falls back to the git tree fetch at git-ref
#   git-ref=<ref>  the ref the git fallback should fetch: the RESOLVED release tag when one was
#                  resolved (so both routes read the same corpus state), else CORPUS_REF unchanged
#   corpus-signer-identity=<id>, corpus-signer-issuer=<issuer>
#                  route=bundle only: the identity and issuer cosign verified bundles.json against
#   signals-path=<path>
#                  whenever a release was read (route=bundle, and route=git for a manifest-only
#                  policy): DEST/signals.json.gz, the release's EPSS/KEV signals asset, after it passed
#                  check S below. Absent on the route=git exit for a ref that names no release.
#
# THE PIN. Every check anchors the bundle one step further from the release asset it arrived as:
#   0. cosign verify-blob bundles.json against bundles.json.sigstore.json, with the EXACT caller-named
#      certificate identity and OIDC issuer, before anything in bundles.json is read
#                                                                  (sidecar is the signer's)
#   S. bundle_version is 1.1 or later and bundles.json carries a `signals` object (INTEL-276), and
#      sha256(signals.json.gz) == bundles.json .signals.sha256     (signals intact vs. the sidecar)
#      A 1.0.x sidecar predates the signals asset and fails, naming its version: the run never
#      proceeds without signals. Checked before the policy lookup, so every exit that read a release
#      hands the scanner signals that passed it.
#   1. sha256(<policy>.jsonl.gz) == bundles.json .digest           (asset intact vs. its sidecar)
#   2. the policy manifest is read from the git commit the release TAG points at, and
#      sha256(manifest.json) == bundles.json .manifest_digest      (sidecar agrees with the git tree)
#   3. manifest .corpus_digest starts with the tag's 12 hex, and its provenance names this policy
#                                                                  (manifest is the one the tag names)
#   4. the bundle's (identifier, output_digest) set == the manifest's (identifier, output_digest) set
#                                                                  (bundle members are the manifest's)
# The scanner then checks every record's bytes against its inline output_digest on each lookup, so a
# record that is used is chained back to the policy manifest in git.
#
# TRUST LIMIT. The signature makes bundles.json the signer's: a release whose sidecar was not signed
# by CORPUS_SIGNER_IDENTITY (as issued by CORPUS_SIGNER_ISSUER) fails, and so does a sidecar altered
# after signing. Steps 1-4 then carry that to the bundle bytes. What is still TRUSTED, not verified:
#   - the Sigstore public-good trust root (Fulcio, Rekor), which cosign fetches from the Sigstore TUF
#     CDN, so the runner must reach it;
#   - the identity and issuer the caller supplies: the check proves "signed by the named identity",
#     never that the named identity is the right one;
#   - the git tree read on the route=git exits: a ref that names no release, or a policy the release
#     ships no bundle for, is read by the Action's git fetch, which no signature covers. With
#     CORPUS_REQUIRE_BUNDLE=1 (the Action's default policy) both exits fail instead.
# The tag -> commit lookup is unsigned too, but it only says where to read the manifest from; the
# manifest's bytes are pinned by the signed manifest_digest.
# A signals-only refresh updates a release in place and re-signs bundles.json (INTEL-277), so a run
# that straddles one can pair the old bundles.json with the new signals.json.gz; check S then fails
# the run, and a re-run reads a consistent pair.
#
# Presents NO credential, same as the git corpus fetch: the corpus must be publicly readable.
set -euo pipefail

: "${CORPUS_REPO:?CORPUS_REPO is required}"
: "${CORPUS_REF:?CORPUS_REF is required}"
: "${CORPUS_POLICY:?CORPUS_POLICY is required}"
: "${DEST:?DEST is required}"
GH="${CORPUS_GITHUB:-https://github.com}"
RAW="${CORPUS_RAW:-https://raw.githubusercontent.com}"

unset GITHUB_TOKEN GH_TOKEN GIT_ASKPASS SSH_ASKPASS || true
export GIT_TERMINAL_PROMPT=0

die() {
  echo "::error::ferralon-assay: advisory corpus bundle: $*" >&2
  exit 1
}

emit() {
  echo "$1"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "$1" >>"$GITHUB_OUTPUT"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Every value below lands in a URL or a filesystem path, so each is shape-checked before use.
[[ "$CORPUS_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "advisory-corpus-repo '$CORPUS_REPO' is not owner/repo"
[[ "$CORPUS_POLICY" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "advisory-corpus-policy '$CORPUS_POLICY' is not a policy id (lowercase letters, digits, '-')"
command -v jq >/dev/null 2>&1 || die "jq is required to verify a corpus bundle and was not found on this runner"
command -v curl >/dev/null 2>&1 || die "curl is required to fetch a corpus bundle and was not found on this runner"

rm -rf "$DEST"
mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)" # signals-path is handed to a later step, so it is absolute
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CURL=(curl -fsSL --retry 3 --retry-connrefused)

# --- 1. resolve the release tag ------------------------------------------------------------------
tag_re='^corpus-[0-9a-f]{12}$'
case "$CORPUS_REF" in
  latest | main)
    # One resolution, reused for every asset: two separate "latest" downloads could straddle a
    # release cut and pair one release's bundles.json with the next release's bundle. The redirect
    # is read unauthenticated from the web UI, not the REST API, so it spends no API rate limit.
    loc="$(curl -fsSI --retry 3 "$GH/$CORPUS_REPO/releases/latest" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}' | tail -n1)" || loc=""
    TAG="${loc##*/}"
    [[ "$TAG" =~ $tag_re ]] || die "could not resolve the latest corpus release of $CORPUS_REPO (got '${loc:-no redirect}')"
    ;;
  *)
    if [[ "$CORPUS_REF" =~ $tag_re ]]; then
      TAG="$CORPUS_REF"
    else
      [ "${CORPUS_REQUIRE_BUNDLE:-}" != 1 ] \
        || die "advisory-corpus-ref '$CORPUS_REF' names no corpus release, and the default policy reads only a signed release bundle. Set advisory-corpus-ref to a corpus-<12 hex> tag, main or latest, or name advisory-corpus-policy explicitly to accept the unsigned git fetch"
      echo "==> advisory-corpus-ref '$CORPUS_REF' names no corpus release; using the git corpus fetch"
      emit "route=git"
      emit "git-ref=$CORPUS_REF"
      exit 0
    fi
    ;;
esac
echo "==> Corpus release: $CORPUS_REPO@$TAG"

# A release is read from here on, so its signature is checked; there is no unverified mode. Each
# requirement is checked before anything is downloaded from the release.
SIGNER_ID="${CORPUS_SIGNER_IDENTITY:-}"
SIGNER_ISSUER="${CORPUS_SIGNER_ISSUER:-}"
[ -n "$SIGNER_ID" ] ||
  die "corpus-signer-identity is not set; a corpus release is only used once its signature verifies, so set it to the certificate identity that signs $CORPUS_REPO releases"
[ -n "$SIGNER_ISSUER" ] ||
  die "corpus-signer-issuer is not set; a corpus release is only used once its signature verifies, so set it to the OIDC issuer of corpus-signer-identity"
[[ "$SIGNER_ID$SIGNER_ISSUER" != *[$'\n\r']* ]] || die "corpus-signer-identity and corpus-signer-issuer must each be one line"
command -v cosign >/dev/null 2>&1 ||
  die "cosign is required to verify the corpus release signature and was not found on this runner"

COMMIT="$(git ls-remote "$GH/$CORPUS_REPO.git" "refs/tags/$TAG" | awk '{print $1}' | head -n1)" || COMMIT=""
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "release tag $TAG has no git tag in $CORPUS_REPO to anchor the policy manifest to"

# --- 2. the sidecar, signature-verified before it is read ----------------------------------------
"${CURL[@]}" -o "$WORK/bundles.json" "$GH/$CORPUS_REPO/releases/download/$TAG/bundles.json" ||
  die "release $TAG of $CORPUS_REPO has no bundles.json"
"${CURL[@]}" -o "$WORK/bundles.json.sigstore.json" "$GH/$CORPUS_REPO/releases/download/$TAG/bundles.json.sigstore.json" ||
  die "release $TAG of $CORPUS_REPO has no bundles.json.sigstore.json signature; refusing an unsigned corpus release"
# The exact identity, never --certificate-identity-regexp: the caller names one signer.
cosign verify-blob --bundle "$WORK/bundles.json.sigstore.json" \
  --certificate-identity "$SIGNER_ID" --certificate-oidc-issuer "$SIGNER_ISSUER" "$WORK/bundles.json" ||
  die "bundles.json of $TAG is not signed by '$SIGNER_ID' (issuer '$SIGNER_ISSUER'): wrong signer identity or issuer, a bad signature, or a tampered bundles.json (cosign's reason is above)"
echo "==> bundles.json of $TAG signature verified: $SIGNER_ID ($SIGNER_ISSUER)"
jq -e '(.bundle_version | type == "string" and startswith("1.")) and (.bundles | type == "array")' \
  "$WORK/bundles.json" >/dev/null || die "bundles.json of $TAG is not a bundle_version 1.x sidecar"

# --- S. the signals asset, pinned to the sidecar --------------------------------------------------
# Every release from bundle_version 1.1.0 on ships the EPSS/KEV signals as signals.json.gz, named in
# bundles.json's `signals` object. Without it the scan would rank nothing, so a sidecar that cannot
# name one fails the run rather than proceeding without signals.
bundle_version="$(jq -r '.bundle_version' "$WORK/bundles.json")"
[[ "$bundle_version" =~ ^1\.([0-9]+)\.[0-9]+$ ]] ||
  die "bundles.json of $TAG has a bundle_version that is not 1.<minor>.<patch>"
(( 10#${BASH_REMATCH[1]} >= 1 )) ||
  die "bundles.json of $TAG is bundle_version $bundle_version, which predates the signals asset (1.1.0); the release ships no verifiable EPSS/KEV signals, so it is refused rather than scanned without them"
jq -e '.signals | type == "object"' "$WORK/bundles.json" >/dev/null ||
  die "bundles.json of $TAG (bundle_version $bundle_version) has no signals object; every release from 1.1.0 on lists its signals.json.gz there"
SIGNALS="signals.json.gz"
sig_asset="$(jq -r '.signals.asset' "$WORK/bundles.json")"
want_sig="$(jq -r '.signals.sha256' "$WORK/bundles.json")"
sig_digest="$(jq -r '.signals.signals_digest' "$WORK/bundles.json")"
# As for the bundle, the sidecar's asset name must be exactly the one expected; it never steers the
# download anywhere else.
[ "$sig_asset" = "$SIGNALS" ] || die "bundles.json of $TAG names '$sig_asset' as the signals asset, want '$SIGNALS'"
[[ "$want_sig" =~ ^[0-9a-f]{64}$ ]] || die "bundles.json signals sha256 of $TAG is not 64 lowercase hex"
[[ "$sig_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "bundles.json signals_digest of $TAG is not sha256:<hex>"
"${CURL[@]}" -o "$WORK/$SIGNALS" "$GH/$CORPUS_REPO/releases/download/$TAG/$SIGNALS" ||
  die "could not download $SIGNALS from release $TAG, which its bundles.json lists"
got_sig="$(sha256_of "$WORK/$SIGNALS")"
[ "$got_sig" = "$want_sig" ] || die "$SIGNALS from $TAG hashes to $got_sig, but bundles.json's signals object says $want_sig"
echo "==> Signals asset verified: $SIGNALS of $TAG (sha256 $got_sig)"
# Only the sha256 is checked here; the sidecar's signals_digest is printed as it claims it.
echo "    bundles.json signals_digest (claimed, not checked by this script): $sig_digest"

# accept_signals hands the verified signals to the scan step. Called on each exit that read a release,
# last, so a run that fails after check S emits no signals path.
accept_signals() {
  mv "$WORK/$SIGNALS" "$DEST/$SIGNALS"
  emit "signals-path=$DEST/$SIGNALS"
}

entry="$(jq -c --arg p "$CORPUS_POLICY" '[.bundles[] | select(.policy_id == $p)]' "$WORK/bundles.json")"
case "$(jq 'length' <<<"$entry")" in
  0)
    [ "${CORPUS_REQUIRE_BUNDLE:-}" != 1 ] \
      || die "$TAG publishes no bundle for policy '$CORPUS_POLICY', and the default policy reads only a signed release bundle; refusing the unsigned git fetch"
    echo "==> Policy '$CORPUS_POLICY' has no bundle in $TAG (manifest-only); using the git corpus fetch at $TAG"
    emit "route=git"
    emit "git-ref=$TAG"
    accept_signals
    exit 0
    ;;
  1) ;;
  *) die "bundles.json of $TAG lists policy '$CORPUS_POLICY' more than once" ;;
esac
entry="$(jq -c '.[0]' <<<"$entry")"
asset="$(jq -r '.path' <<<"$entry")"
want_gz="$(jq -r '.digest' <<<"$entry")"
want_manifest="$(jq -r '.manifest_digest' <<<"$entry")"
want_members="$(jq -r '.members' <<<"$entry")"
# The asset name is taken from the sidecar only after it is shown to be exactly the name the policy
# implies; a sidecar never steers the download anywhere else.
[ "$asset" = "$CORPUS_POLICY.jsonl.gz" ] || die "bundles.json names '$asset' for policy '$CORPUS_POLICY', want '$CORPUS_POLICY.jsonl.gz'"
[[ "$want_gz" =~ ^sha256:[0-9a-f]{64}$ ]] || die "bundles.json digest for '$CORPUS_POLICY' is not sha256:<hex>"
[[ "$want_manifest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "bundles.json manifest_digest for '$CORPUS_POLICY' is not sha256:<hex>"
[[ "$want_members" =~ ^[0-9]+$ ]] || die "bundles.json members for '$CORPUS_POLICY' is not a count"

# --- 3. the bundle, pinned to the sidecar --------------------------------------------------------
"${CURL[@]}" -o "$WORK/$asset" "$GH/$CORPUS_REPO/releases/download/$TAG/$asset" ||
  die "could not download $asset from release $TAG"
got_gz="sha256:$(sha256_of "$WORK/$asset")"
[ "$got_gz" = "$want_gz" ] || die "$asset from $TAG hashes to $got_gz, but bundles.json says $want_gz"

# --- 4. the policy manifest, pinned to the sidecar and to the tag --------------------------------
"${CURL[@]}" -o "$WORK/manifest.json" "$RAW/$CORPUS_REPO/$COMMIT/policies/$CORPUS_POLICY/manifest.json" ||
  die "could not read policies/$CORPUS_POLICY/manifest.json at $TAG ($COMMIT)"
got_manifest="sha256:$(sha256_of "$WORK/manifest.json")"
[ "$got_manifest" = "$want_manifest" ] ||
  die "policies/$CORPUS_POLICY/manifest.json at $COMMIT hashes to $got_manifest, but bundles.json says $want_manifest"
jq -e --arg p "$CORPUS_POLICY" --arg d "sha256:${TAG#corpus-}" '
    (.corpus_digest | type == "string" and startswith($d))
    and (.provenance.policy_id == $p)
    and (.record_count == (.records | length))' "$WORK/manifest.json" >/dev/null ||
  die "policies/$CORPUS_POLICY/manifest.json at $COMMIT does not belong to $TAG (corpus_digest, policy_id, or record_count disagrees)"

# --- 5. bundle membership == manifest membership --------------------------------------------------
jq -r '.records[] | [.identifier, .output_digest] | @tsv' "$WORK/manifest.json" | LC_ALL=C sort >"$WORK/manifest.tsv"
gzip -dc "$WORK/$asset" | jq -r '[.identifier, .output_digest] | @tsv' | LC_ALL=C sort >"$WORK/bundle.tsv" ||
  die "$asset from $TAG does not decompress to JSON lines"
cmp -s "$WORK/manifest.tsv" "$WORK/bundle.tsv" ||
  die "$asset from $TAG does not carry exactly the members of policies/$CORPUS_POLICY/manifest.json (identifier or output_digest differs)"
got_members="$(wc -l <"$WORK/bundle.tsv" | tr -d ' ')"
[ "$got_members" = "$want_members" ] || die "$asset has $got_members members, but bundles.json says $want_members"

mv "$WORK/$asset" "$DEST/$asset"
echo "==> Advisory corpus bundle verified: $DEST/$asset ($got_members records, $got_gz, $CORPUS_REPO@$TAG = $COMMIT)"
emit "route=bundle"
emit "git-ref=$TAG"
emit "corpus-signer-identity=$SIGNER_ID"
emit "corpus-signer-issuer=$SIGNER_ISSUER"
accept_signals
