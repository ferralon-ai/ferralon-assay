// internal/checkout/git.go
package checkout

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/hostmatch"
)

// githubForge is the presentation allowlist for the GitHub App installation token. GitHub App
// installation tokens are valid ONLY for github.com and the GitHub-controlled *.ghe.com
// data-residency namespace. This list is duplicated in service admission (validate.go) with the
// same comment — keep them in sync. (2 elements; a shared package was deemed not worth coupling
// service admission to checkout's deps.)
var githubForge = mustForge("github.com", "*.ghe.com")

// mustForge compiles a STATIC forge allowlist. Panic on a static-pattern compile failure is
// correct — it can only fail if the code is wrong.
func mustForge(patterns ...string) *hostmatch.Matcher {
	m, err := hostmatch.New(patterns)
	if err != nil {
		panic("checkout: static GitHub forge patterns must compile: " + err.Error())
	}
	return m
}

// GitCheckout is the real Checkout: it shells out to `git` (no SDK, mirroring sandbox.DockerRunner)
// to clone repo@revision into a fresh temp dir. It is wired only when explicitly enabled
// (TEGRON_REAL_CHECKOUT=1 in tegrond), so the default pipeline stays hermetic.
type GitCheckout struct {
	Bin string // git binary; "" means "git"
}

// NewGitCheckout returns a GitCheckout using the "git" binary on PATH.
func NewGitCheckout() *GitCheckout { return &GitCheckout{Bin: "git"} }

func (g *GitCheckout) bin() string {
	if g.Bin == "" {
		return "git"
	}
	return g.Bin
}

// Fetch clones repo into a temp dir and checks out revision, then detects the source language of
// the materialized tree. On any failure it removes the partial dir and returns an error
// (inv.5: no silent half-checkout). A clone that is neither a Go module nor a Java source tree
// is rejected the same way (no recognizable source to inventory).
func (g *GitCheckout) Fetch(ctx context.Context, repo, revision string) (WorkspacePlan, error) {
	// The per-fire ownership token (if any) rides in-flight on the context — never on the
	// Checkout seam signature, never on this struct, never on disk. An empty credential (public
	// repo / hermetic fake / local ambient-cred dev) takes the bare-clone path unchanged.
	cred := CredentialFrom(ctx)
	dir, err := os.MkdirTemp("", "tegron-checkout-")
	if err != nil {
		return WorkspacePlan{}, fmt.Errorf("checkout: mkdtemp: %w", err)
	}
	cleanup := func(cause error) (WorkspacePlan, error) {
		_ = os.RemoveAll(dir)
		return WorkspacePlan{}, cause
	}
	url := normalizeCloneURL(repo)
	// PRESENTATION decision (flag #7). Admission ("may we clone here") ≠ presentation ("may the
	// token go here"): the credential is a GitHub App installation token, valid ONLY at a GitHub
	// forge, so a non-GitHub clone host — or a mid-clone redirect to one — must NOT receive it.
	// Decide the EFFECTIVE credential and the host it is scoped to here, before any network op.
	effCred := cred
	var credHost string
	if !cred.IsEmpty() {
		if host, ok := cloneURLHost(url); ok {
			allowed, err := githubForge.Allows(host)
			switch {
			case err != nil:
				// A malformed host reaching here is an upstream plumbing bug; withhold rather
				// than guess. Never interpolate the token (Credential.String redacts anyway).
				fmt.Fprintf(os.Stderr, "checkout: withholding credential: malformed clone host %q: %v\n", host, err)
				effCred = Credential{}
			case allowed:
				credHost = host
			default:
				// Non-GitHub host: WITHHOLD the GitHub installation token; clone unauthenticated.
				fmt.Fprintf(os.Stderr, "checkout: credential supplied for non-GitHub host %q, cloning unauthenticated\n", host)
				effCred = Credential{}
			}
		} else {
			effCred = Credential{} // no network host (local path / unparseable) — nothing to present to
		}
	}
	// clone + fetch are the network ops that may need auth; the credential authenticates them
	// without ever appearing in the URL/argv (the token is fed to git via the environment) and is
	// scoped to credHost so a redirect cannot replay it elsewhere. The later local ops (checkout
	// FETCH_HEAD, rev-parse) never touch the network, so they run with no credential — leaving them
	// byte-identical to today.
	if _, err := g.run(ctx, "", effCred, credHost, "clone", "--depth", "1", url, dir); err != nil {
		return cleanup(fmt.Errorf("checkout: git clone %q: %w", url, err))
	}
	if revision != "" {
		// Fetch the requested revision (branch, tag, or commit SHA) shallowly into FETCH_HEAD,
		// then check that out detached. A `--depth 1` clone only materializes the remote's
		// DEFAULT branch locally, and `git fetch origin <rev>` writes the result to FETCH_HEAD
		// WITHOUT creating a local branch or remote-tracking ref named <rev>. So a subsequent
		// `git checkout <rev>` by name fails with "pathspec '<rev>' did not match any file(s)"
		// for any non-default branch (the default-branch case only worked incidentally, because
		// the clone already checked it out). Checking out FETCH_HEAD pins the exact fetched
		// commit and works uniformly for a branch, tag, or SHA.
		// TODO(checkout): plumb the resolved commit SHA (git rev-parse HEAD here) out through the
		// Checkout.Fetch signature so the pipeline can pin Case.ResolvedCommit; currently
		// subject_repo_ref persists empty because that value never leaves this function.
		if _, err := g.run(ctx, dir, effCred, credHost, "fetch", "--depth", "1", "origin", revision); err != nil {
			return cleanup(fmt.Errorf("checkout: git fetch %q: %w", revision, err))
		}
		if _, err := g.run(ctx, dir, Credential{}, "", "checkout", "--detach", "FETCH_HEAD"); err != nil {
			return cleanup(fmt.Errorf("checkout: git checkout %q (FETCH_HEAD): %w", revision, err))
		}
	}
	lang := DetectLanguage(dir)
	if lang == LangUnknown {
		return cleanup(fmt.Errorf("checkout: cloned repo %q@%q is not a recognized source tree (no go.mod, no .java, no .js/.ts, no .py, and no .cs/.csproj sources)", repo, revision))
	}
	return singleProjectPlan(dir, lang), nil
}

func (g *GitCheckout) run(ctx context.Context, workdir string, cred Credential, credHost string, args ...string) (string, error) {
	full := args
	var env []string // nil ⇒ inherit the parent env (the EMPTY-credential path stays byte-identical to today)
	if !cred.IsEmpty() {
		// Authenticated path: prepend the credential-config flags (which carry NO token value —
		// only a reference to an env var, host-scoped to credHost) and hand git a child
		// environment that (a) carries the token, (b) isolates ambient git config so nothing can
		// preempt our helper, and (c) never blocks on an interactive prompt. The token reaches git
		// ONLY through this env, so it is absent from argv / ps and from git's own error strings
		// (which quote argv, not env).
		full = append(credentialConfigArgs(credHost), args...)
		env = credentialEnv(cred)
	}
	cmd := exec.CommandContext(ctx, g.bin(), full...)
	if workdir != "" {
		cmd.Dir = workdir
	}
	if env != nil {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// credEnvVar is the environment variable the inline credential helper reads the token from. The
// token lives in the child git process's environment for the duration of one clone/fetch and
// nowhere else — never in argv, never on disk, never in the parent process env.
const credEnvVar = "TEGRON_CHECKOUT_CRED"

// credHelperArg returns the value for `-c credential.helper=…`: an inline shell helper that, on a
// git `get`, emits the fixed GitHub installation-token username (`x-access-token`) and the token
// read from $TEGRON_CHECKOUT_CRED. The token VALUE never appears in this string — only the name of
// the env var git's child shell dereferences — so this flag is safe to appear in argv / ps.
func credHelperArg() string {
	return `!f(){ test "$1" = get && printf 'username=x-access-token\npassword=%s\n' "$` + credEnvVar + `"; }; f`
}

// credentialConfigArgs returns the `-c` flags that install our inline credential helper, SCOPED to
// host. It first RESETS the helper list (an empty `credential.helper` clears any helper a poisoned
// local .git/config could carry) and then adds our inline helper under a
// host-specific key `credential.https://<host>.helper` — so git offers the token ONLY for a
// credential request whose context host is <host> (flag #7). This closes the redirect-leak gap: a
// clone that redirects to another host produces a credential request with a DIFFERENT host, which
// matches no helper, so git sends no token. No shell host-parsing is needed. The token value is
// never here; see credHelperArg. Combined with the config isolation in credentialEnv, this makes
// our token the ONLY credential source and binds it to the validated GitHub host.
func credentialConfigArgs(host string) []string {
	return []string{
		"-c", "credential.helper=",
		"-c", "credential.https://" + host + ".helper=" + credHelperArg(),
	}
}

// credentialEnv builds the child git environment for the authenticated path. It starts from the
// parent env (git still needs PATH etc.), AUTHORITATIVELY overrides the four keys we control
// (dropping any inherited duplicates so a parent value cannot win), and injects the token. The
// isolation vars exist because on a developer box the ambient system/global git config (an
// osxkeychain helper, a `url.<base>.insteadOf` OAuth-token rewrite) would otherwise preempt our
// helper — the only reliable way to drop Apple's system config is GIT_CONFIG_NOSYSTEM=1, and
// GIT_CONFIG_GLOBAL=/dev/null loads an empty global so no url-rewrite survives. On the fenced fire
// VM there is no ambient config, so this is defense-in-depth there.
func credentialEnv(cred Credential) []string {
	override := map[string]string{
		"GIT_CONFIG_NOSYSTEM": "1",        // drop system git config (only NOSYSTEM drops Apple's)
		"GIT_CONFIG_GLOBAL":   os.DevNull, // empty global ⇒ no url.insteadOf / ambient helper can preempt
		"GIT_TERMINAL_PROMPT": "0",        // never block on an interactive credential prompt
		credEnvVar:            cred.token, // the token — process-scoped, in-flight, never at rest
	}
	base := os.Environ()
	out := make([]string, 0, len(base)+len(override))
	for _, kv := range base {
		if key, _, ok := strings.Cut(kv, "="); ok {
			if _, shadowed := override[key]; shadowed {
				continue // drop the inherited value; we set an authoritative one below
			}
		}
		out = append(out, kv)
	}
	for k, v := range override {
		out = append(out, k+"="+v)
	}
	return out
}

// normalizeCloneURL turns a scheme-less Go module path (e.g. "github.com/owner/repo", the form
// stored in a Case's Codebase.Repo) into an https clone URL ("https://github.com/owner/repo").
// git treats a bare host/path argument as a LOCAL path, so without this a module-path repo fails
// with "repository does not exist". Inputs that already carry a scheme, scp-style remotes
// (git@host:path), and local paths are returned unchanged.
func normalizeCloneURL(repo string) string {
	if repo == "" {
		return repo
	}
	if strings.Contains(repo, "://") || strings.ContainsRune(repo, '@') {
		return repo // already a URL or scp-like remote
	}
	if strings.HasPrefix(repo, "/") || strings.HasPrefix(repo, ".") {
		return repo // local path
	}
	// Bare host/owner/repo (Go module path form): the first segment must look like a host
	// (contain a dot), to avoid rewriting a single bare name or a relative-ish path.
	if i := strings.IndexByte(repo, '/'); i > 0 && strings.Contains(repo[:i], ".") {
		return "https://" + repo
	}
	return repo
}

// cloneURLHost extracts the network host from a normalized clone URL, for the flag-#7 presentation
// decision. It handles both an https/ssh URL (url.Parse → Hostname) and an scp-like remote
// (git@host:path, which has no scheme). A local path, a bare name, or an otherwise host-less /
// unparseable input yields ("", false) ⇒ "no network host" ⇒ the caller takes the public path
// (no credential presented — there is nowhere to present it to).
//
// The host is lower-cased: DNS names are case-insensitive, so this canonicalizes the value used
// both for the githubForge check and for the host-scoped credential key, rather than relying on
// git's own urlmatch normalization to reconcile a mixed-case key (e.g. GitHub.COM) with the
// lower-cased host git derives from the URL it dials. Worst case a mismatch is fail-safe (a
// withheld token, never a leak), but canonicalizing removes the ambiguity outright.
func cloneURLHost(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	// scp-like remote ([user@]host:path): no scheme; the host ends at the first ':'.
	if !strings.Contains(raw, "://") && strings.ContainsRune(raw, '@') {
		rest := raw[strings.IndexByte(raw, '@')+1:]
		if colon := strings.IndexByte(rest, ':'); colon > 0 {
			if host := rest[:colon]; host != "" {
				return strings.ToLower(host), true
			}
		}
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if host := u.Hostname(); host != "" {
		return strings.ToLower(host), true
	}
	return "", false
}

// ResolveHead returns the concrete 40-hex commit SHA that `dir` is checked out at by shelling
// `git -C dir rev-parse HEAD` (no SDK, mirroring GitCheckout). It is the T1 reproducibility anchor:
// after a Fetch materializes repo@revision (a branch/tag/ref), this pins the assessment to the exact
// commit. It FAILS SOFT — returns "" with a nil error — when `dir` is not a git working tree (the
// vendored_repro / FakeCheckout paths are not git checkouts), so callers can set ResolvedCommit
// unconditionally without breaking the hermetic pipeline. A non-nil error is reserved for a usable
// git tree whose HEAD cannot be resolved.
func ResolveHead(ctx context.Context, dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return "", nil // not a git working tree (vendored fixture) — fail soft
	}
	g := &GitCheckout{}
	out, err := g.run(ctx, dir, Credential{}, "", "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("checkout: rev-parse HEAD in %q: %w", dir, err)
	}
	return strings.TrimSpace(out), nil
}

// GitAvailable reports whether the git CLI is usable, for gating the live e2e test (mirroring
// sandbox.DockerAvailable()).
func GitAvailable() bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	return exec.Command("git", "version").Run() == nil
}
