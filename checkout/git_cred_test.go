// internal/checkout/git_cred_test.go
//
// GitCheckout authenticates a PRIVATE-repo clone from the per-fire ownership token WITHOUT
// leaking it. These tests prove the security-critical properties:
//
//   - the token NEVER appears in the child git argv / URL (so it cannot leak via ps),
//   - the token NEVER appears in git's error output (so a failed clone cannot log it),
//   - the token is NOT persisted to the materialized tree on disk,
//   - the EMPTY-credential path is byte-identical to today's bare clone (public / ambient-cred),
//   - the credential really DOES reach git (a private clone would authenticate).
//
// The leak/branch tests use a FAKE git (GitCheckout.Bin → a capture script) so they are fully
// hermetic and can inspect exactly what argv + env the child received. The delivery test uses the
// REAL git credential machinery (gated on GitAvailable) to prove the helper actually authenticates.
package checkout

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "ghs_TEG042s3cr3tInstallationToken" // sentinel: MUST NOT appear in argv/error/disk

// fakeGit writes a shell script that stands in for `git`: it records, per subcommand, the exact
// argv (one element per line) and the full environment into capDir, materializes a go.mod on
// `clone` (so DetectLanguage sees a Go module), and — when TEGRON_FAKE_FAIL=1 — fails `clone`
// with an error that ECHOES its argv to stderr (never its env), simulating git quoting the URL in
// a failure. It returns the script path to assign to GitCheckout.Bin.
func fakeGit(t *testing.T, capDir string) string {
	t.Helper()
	script := `#!/bin/sh
set -e
capdir="` + capDir + `"
# Find the subcommand by skipping leading "-c VALUE" global options.
sub=""
skip=0
for a in "$@"; do
  if [ "$skip" = "1" ]; then skip=0; continue; fi
  case "$a" in
    -c) skip=1; continue ;;
    -*) continue ;;
    *) sub="$a"; break ;;
  esac
done
# Record argv (one element per line) and the full environment for this subcommand.
for a in "$@"; do printf '%s\n' "$a"; done >> "$capdir/$sub.argv"
env >> "$capdir/$sub.env"
if [ "$sub" = "clone" ]; then
  dest=""
  for a in "$@"; do dest="$a"; done   # last arg is the destination dir
  mkdir -p "$dest"
  printf 'module example.com/svc\n\ngo 1.22\n' > "$dest/go.mod"
  if [ "${TEGRON_FAKE_FAIL}" = "1" ]; then
    printf 'fatal: could not read from remote repository for args: %s\n' "$*" >&2
    exit 128
  fi
fi
exit 0
`
	p := filepath.Join(t.TempDir(), "fakegit.sh")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func readCap(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture %q: %v", path, err)
	}
	return string(b)
}

// AC #2 + AC #4: on the authenticated path the token reaches git ONLY through the environment —
// never argv, never the URL — and the config-isolation env is applied.
func TestFetchAuthenticatedTokenNeverInArgvOrURL(t *testing.T) {
	capDir := t.TempDir()
	gc := &GitCheckout{Bin: fakeGit(t, capDir)}

	ctx := WithCredential(context.Background(), NewCredential(testToken))
	url := "https://github.com/ferralon-demo/demo-go-svc"
	dir, lang, err := gc.Fetch(ctx, url, "main")
	if err != nil {
		t.Fatalf("Fetch (authenticated): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if lang != LangGo {
		t.Fatalf("lang = %q, want %q", lang, LangGo)
	}

	// The clone AND fetch argv must carry the credential-config flags but NOT the token, and the
	// URL must be clean.
	for _, sub := range []string{"clone", "fetch"} {
		argv := readCap(t, filepath.Join(capDir, sub+".argv"))
		if strings.Contains(argv, testToken) {
			t.Fatalf("%s argv leaked the token:\n%s", sub, argv)
		}
		if !strings.Contains(argv, "credential.https://github.com.helper=") {
			t.Fatalf("%s argv missing the host-scoped credential helper config:\n%s", sub, argv)
		}
	}
	// The URL line must be exactly the clean https URL (no token spliced in).
	cloneArgv := readCap(t, filepath.Join(capDir, "clone.argv"))
	if !strings.Contains(cloneArgv, url+"\n") {
		t.Fatalf("clone argv missing the clean URL %q:\n%s", url, cloneArgv)
	}
	if strings.Contains(cloneArgv, "@github.com") || strings.Contains(cloneArgv, "x-access-token:") {
		t.Fatalf("clone URL appears to embed a credential:\n%s", cloneArgv)
	}

	// The token IS delivered via the child env, and the isolation vars are set.
	cloneEnv := readCap(t, filepath.Join(capDir, "clone.env"))
	if !strings.Contains(cloneEnv, credEnvVar+"="+testToken) {
		t.Fatalf("token was not delivered to git via $%s", credEnvVar)
	}
	for _, want := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_TERMINAL_PROMPT=0"} {
		if !strings.Contains(cloneEnv, want) {
			t.Fatalf("clone env missing isolation var %q", want)
		}
	}
}

// AC #2: a FAILED authenticated clone must not leak the token through git's error output.
func TestFetchAuthenticatedTokenAbsentFromError(t *testing.T) {
	capDir := t.TempDir()
	gc := &GitCheckout{Bin: fakeGit(t, capDir)}

	t.Setenv("TEGRON_FAKE_FAIL", "1")
	ctx := WithCredential(context.Background(), NewCredential(testToken))
	_, _, err := gc.Fetch(ctx, "https://github.com/ferralon-demo/demo-go-svc", "main")
	if err == nil {
		t.Fatal("expected the simulated clone failure to surface an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("git error output leaked the token: %v", err)
	}
	// Sanity: the error is the clone failure we simulated (proves we exercised the failing path).
	if !strings.Contains(err.Error(), "could not read from remote") {
		t.Fatalf("unexpected error (did the failing clone path run?): %v", err)
	}
}

// AC #2: the token is not written into the materialized tree on disk.
func TestFetchAuthenticatedTokenNotOnDisk(t *testing.T) {
	capDir := t.TempDir()
	gc := &GitCheckout{Bin: fakeGit(t, capDir)}

	ctx := WithCredential(context.Background(), NewCredential(testToken))
	dir, _, err := gc.Fetch(ctx, "https://github.com/ferralon-demo/demo-go-svc", "main")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		if strings.Contains(string(b), testToken) {
			t.Fatalf("token found persisted on disk at %s", path)
		}
		return nil
	})
}

// AC #3: the EMPTY-credential path is byte-identical to today's bare clone — no credential-config
// flags on argv and no credential/isolation env. This is the public-repo / ambient-cred / hermetic
// branch, which must be unaffected.
func TestFetchEmptyCredentialIsByteIdenticalBareClone(t *testing.T) {
	capDir := t.TempDir()
	gc := &GitCheckout{Bin: fakeGit(t, capDir)}

	// A plain context with no credential.
	dir, _, err := gc.Fetch(context.Background(), "https://github.com/ferralon-demo/demo-go-svc", "main")
	if err != nil {
		t.Fatalf("Fetch (empty cred): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	cloneArgv := strings.Split(strings.TrimRight(readCap(t, filepath.Join(capDir, "clone.argv")), "\n"), "\n")
	want := []string{"clone", "--depth", "1", "https://github.com/ferralon-demo/demo-go-svc", dir}
	if len(cloneArgv) != len(want) {
		t.Fatalf("empty-cred clone argv = %q, want exactly %q (no -c flags)", cloneArgv, want)
	}
	for i := range want {
		if cloneArgv[i] != want[i] {
			t.Fatalf("empty-cred clone argv[%d] = %q, want %q", i, cloneArgv[i], want[i])
		}
	}
	// No credential/isolation env on the empty path (the child simply inherited the parent env, so
	// our sentinel token env var must be absent).
	cloneEnv := readCap(t, filepath.Join(capDir, "clone.env"))
	if strings.Contains(cloneEnv, credEnvVar+"=") {
		t.Fatalf("empty-cred path must not set $%s", credEnvVar)
	}
}

// AC #4 defense-in-depth: a Credential redacts under every fmt verb, so it cannot leak via a log
// line or a wrapped error.
func TestCredentialRedacts(t *testing.T) {
	c := NewCredential(testToken)
	for _, s := range []string{c.String(), c.GoString()} {
		if strings.Contains(s, testToken) {
			t.Fatalf("Credential stringer leaked the token: %q", s)
		}
	}
	if c.IsEmpty() {
		t.Fatal("non-empty token must not report IsEmpty")
	}
	if !NewCredential("").IsEmpty() {
		t.Fatal("empty token must report IsEmpty")
	}
	// WithCredential(empty) is a no-op: the bare path never sees a credential in context.
	if !CredentialFrom(WithCredential(context.Background(), NewCredential(""))).IsEmpty() {
		t.Fatal("WithCredential(empty) must not stash a credential")
	}
}

// captureStderr swaps os.Stderr for a pipe, runs fn, and returns whatever fn wrote to stderr. Not
// safe for t.Parallel (it mutates the package-global os.Stderr), so callers must stay serial.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

// argvHasResetHelper reports whether argv (newline-joined argv elements) contains the reset line —
// an exact `credential.helper=` element with an empty value (the poisoned-helper reset).
func argvHasResetHelper(argv string) bool {
	for _, line := range strings.Split(argv, "\n") {
		if line == "credential.helper=" {
			return true
		}
	}
	return false
}

// flag #7: host-bound credential presentation. The GitHub App installation token is offered ONLY
// when the clone host is a GitHub forge (github.com / *.ghe.com), and then ONLY via a host-scoped
// helper key; a non-GitHub host withholds the token entirely (public clone). An scp-like remote
// resolves its host the same way. In every case the token never appears in argv, and the inline
// helper is never installed GLOBALLY (unscoped).
func TestFetchCredentialPresentationHostBinding(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		wantScope string // the host the helper must be scoped to; "" ⇒ credential WITHHELD (public path)
	}{
		{"github.com", "https://github.com/ferralon-demo/demo-go-svc", "github.com"},
		{"uppercase host canonicalized", "https://GitHub.COM/ferralon-demo/demo-go-svc", "github.com"},
		{"ghe.com data-residency", "https://acme.ghe.com/org/repo", "acme.ghe.com"},
		{"scp-like github", "git@github.com:ferralon-demo/demo-go-svc", "github.com"},
		{"non-github gitlab", "https://gitlab.com/org/repo", ""},
		{"non-github evil", "https://evil.com/org/repo", ""},
		{"userinfo spoof withholds", "https://github.com@evil.com/org/repo", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capDir := t.TempDir()
			gc := &GitCheckout{Bin: fakeGit(t, capDir)}
			ctx := WithCredential(context.Background(), NewCredential(testToken))

			var dir string
			warn := captureStderr(t, func() {
				var err error
				dir, _, err = gc.Fetch(ctx, tc.url, "main")
				if err != nil {
					t.Fatalf("Fetch(%q): %v", tc.url, err)
				}
			})
			t.Cleanup(func() { _ = os.RemoveAll(dir) })

			cloneArgv := readCap(t, filepath.Join(capDir, "clone.argv"))
			cloneEnv := readCap(t, filepath.Join(capDir, "clone.env"))

			// Invariant across every path: the token is never on argv, and the inline helper is
			// never installed as a GLOBAL (unscoped) `credential.helper=!f(){...}` entry.
			if strings.Contains(cloneArgv, testToken) {
				t.Fatalf("clone argv leaked the token:\n%s", cloneArgv)
			}
			if strings.Contains(cloneArgv, "credential.helper=!f(){") {
				t.Fatalf("inline helper was installed GLOBALLY (unscoped):\n%s", cloneArgv)
			}

			if tc.wantScope == "" {
				// WITHHELD: byte-identical bare clone — no -c flags, no token env, and a warning.
				for _, line := range strings.Split(strings.TrimRight(cloneArgv, "\n"), "\n") {
					if line == "-c" {
						t.Fatalf("withheld path must carry no -c flags:\n%s", cloneArgv)
					}
				}
				if strings.Contains(cloneEnv, credEnvVar+"=") {
					t.Fatalf("withheld path must NOT deliver the token via $%s:\n%s", credEnvVar, cloneEnv)
				}
				if !strings.Contains(warn, "cloning unauthenticated") {
					t.Fatalf("expected a withhold warning on stderr, got: %q", warn)
				}
				return
			}

			// AUTHENTICATED: the helper is scoped to the validated host, the reset is present, and
			// the token rides only in the child env.
			wantHelper := "credential.https://" + tc.wantScope + ".helper=" + credHelperArg()
			if !strings.Contains(cloneArgv, wantHelper+"\n") {
				t.Fatalf("clone argv missing host-scoped helper %q:\n%s", wantHelper, cloneArgv)
			}
			if !argvHasResetHelper(cloneArgv) {
				t.Fatalf("clone argv missing the reset `credential.helper=`:\n%s", cloneArgv)
			}
			if !strings.Contains(cloneEnv, credEnvVar+"="+testToken) {
				t.Fatalf("token not delivered via $%s:\n%s", credEnvVar, cloneEnv)
			}
			if strings.Contains(warn, "unauthenticated") {
				t.Fatalf("authenticated path must not warn about withholding, got: %q", warn)
			}
		})
	}
}

// AC #1/#2 positive proof (REAL git): under our config isolation + env, git's own credential
// machinery resolves the fixed installation-token username and the token — so a private clone
// WOULD authenticate — while the token value is never in the argv we pass. Gated on a usable git.
func TestCredentialHelperDeliversTokenToRealGit(t *testing.T) {
	if !GitAvailable() {
		t.Skip("git CLI not available")
	}
	cred := NewCredential(testToken)

	// The config args we hand git carry no token value.
	for _, a := range credentialConfigArgs("github.com") {
		if strings.Contains(a, testToken) {
			t.Fatalf("credentialConfigArgs leaked the token: %q", a)
		}
	}

	args := append(credentialConfigArgs("github.com"), "credential", "fill")
	cmd := exec.Command("git", args...)
	cmd.Env = credentialEnv(cred)
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git credential fill: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "username=x-access-token") {
		t.Fatalf("helper did not supply the installation-token username:\n%s", s)
	}
	if !strings.Contains(s, "password="+testToken) {
		t.Fatalf("helper did not supply the token as the password:\n%s", s)
	}
}
