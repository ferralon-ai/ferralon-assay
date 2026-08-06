// internal/checkout/git_test.go
package checkout

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ResolveHead on a non-git directory must fail SOFT: "" with a nil error, so the vendored_repro /
// FakeCheckout paths (not git trees) leave ResolvedCommit empty without breaking the pipeline.
func TestResolveHeadNonGitDirFailsSoft(t *testing.T) {
	sha, err := ResolveHead(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("ResolveHead on a non-git dir must not error, got %v", err)
	}
	if sha != "" {
		t.Fatalf("ResolveHead on a non-git dir must return empty SHA, got %q", sha)
	}
}

// ResolveHead on a real git working tree returns the 40-hex commit SHA HEAD points at. Gated on a
// usable git CLI; otherwise skipped (mirrors the live-checkout test gating).
func TestResolveHeadReturnsCommitSHA(t *testing.T) {
	if !GitAvailable() {
		t.Skip("git CLI not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	run("commit", "--allow-empty", "-q", "-m", "seed")

	sha, err := ResolveHead(context.Background(), dir)
	if err != nil {
		t.Fatalf("ResolveHead: %v", err)
	}
	if !hex40.MatchString(sha) {
		t.Fatalf("ResolveHead must return a 40-hex SHA, got %q", sha)
	}
	// Cross-check against git itself.
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	want, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, w := sha, filepath.Clean(string(want[:40])); got != w {
		t.Fatalf("ResolveHead = %q, want %q", got, w)
	}
}

// normalizeCloneURL is a pure string transform, so this is fully hermetic — no git, no network.
func TestNormalizeCloneURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare go module path gets https", "github.com/ferralon-ai/tegron-corpus-repros", "https://github.com/ferralon-ai/tegron-corpus-repros"},
		{"https left untouched", "https://github.com/golang/example", "https://github.com/golang/example"},
		{"http left untouched", "http://example.com/x/y", "http://example.com/x/y"},
		{"ssh scheme left untouched", "ssh://git@github.com/golang/example", "ssh://git@github.com/golang/example"},
		{"scp-like remote left untouched", "git@github.com:golang/example.git", "git@github.com:golang/example.git"},
		{"absolute local path left untouched", "/tmp/local/repo", "/tmp/local/repo"},
		{"relative local path left untouched", "./repo", "./repo"},
		{"single-segment (no host) left untouched", "justname", "justname"},
		{"empty left untouched", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeCloneURL(tc.in); got != tc.want {
				t.Errorf("normalizeCloneURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %q: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

// TestGitCheckoutNonDefaultRef is a regression test for the checkout bug where a `--depth 1`
// clone makes only the remote's DEFAULT branch reachable locally, so `git checkout <non-default
// branch>` failed with "pathspec '<rev>' did not match any file(s) known to git". It uses a local
// temp git repo with two branches (mirroring demo-go-svc's vulnerable/patched layout) — no
// network. The non-default branch must check out and its tree must reflect that branch's content.
func TestGitCheckoutNonDefaultRef(t *testing.T) {
	if !GitAvailable() {
		t.Skip("git not available")
	}
	ctx := context.Background()

	origin := t.TempDir()
	gitT(t, origin, "init", "-q")
	gitT(t, origin, "config", "user.email", "test@tegron.test")
	gitT(t, origin, "config", "user.name", "tegron test")
	// "vulnerable" is the default branch (first branch with a commit, HEAD points here).
	gitT(t, origin, "checkout", "-q", "-b", "vulnerable")
	if err := writeFile(filepath.Join(origin, "go.mod"), "module example.com/svc\n\ngo 1.22\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(origin, "svc.go"), "package svc\n\nconst Variant = \"vulnerable\"\n"); err != nil {
		t.Fatal(err)
	}
	gitT(t, origin, "add", "-A")
	gitT(t, origin, "commit", "-q", "-m", "vulnerable")
	// "patched" is a SECOND, non-default branch — this is the ref the bug failed on.
	gitT(t, origin, "checkout", "-q", "-b", "patched")
	if err := writeFile(filepath.Join(origin, "svc.go"), "package svc\n\nconst Variant = \"patched\"\n"); err != nil {
		t.Fatal(err)
	}
	gitT(t, origin, "add", "-A")
	gitT(t, origin, "commit", "-q", "-m", "patched")
	patchedSHA := strings.TrimSpace(gitT(t, origin, "rev-parse", "HEAD"))
	// Leave HEAD on the default branch so a fresh shallow clone gets "vulnerable" by default.
	gitT(t, origin, "checkout", "-q", "vulnerable")

	gc := NewGitCheckout()
	// file:// so `git clone --depth 1` performs a real shallow clone (local-path clones ignore
	// --depth), matching the daemon's remote-clone behavior.
	url := "file://" + origin

	t.Run("non-default branch checks out", func(t *testing.T) {
		dir, lang, err := gc.Fetch(ctx, url, "patched")
		if err != nil {
			t.Fatalf("Fetch(patched): %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		if lang != LangGo {
			t.Fatalf("lang = %q, want %q", lang, LangGo)
		}
		got, err := os.ReadFile(filepath.Join(dir, "svc.go"))
		if err != nil {
			t.Fatalf("read svc.go: %v", err)
		}
		if !strings.Contains(string(got), `Variant = "patched"`) {
			t.Fatalf("checked-out tree is not the patched branch: %s", got)
		}
	})

	t.Run("commit SHA checks out", func(t *testing.T) {
		dir, _, err := gc.Fetch(ctx, url, patchedSHA)
		if err != nil {
			t.Fatalf("Fetch(%s): %v", patchedSHA, err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		got, err := os.ReadFile(filepath.Join(dir, "svc.go"))
		if err != nil {
			t.Fatalf("read svc.go: %v", err)
		}
		if !strings.Contains(string(got), `Variant = "patched"`) {
			t.Fatalf("SHA checkout did not land the patched commit: %s", got)
		}
	})

	t.Run("default branch still checks out", func(t *testing.T) {
		dir, _, err := gc.Fetch(ctx, url, "vulnerable")
		if err != nil {
			t.Fatalf("Fetch(vulnerable): %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		got, err := os.ReadFile(filepath.Join(dir, "svc.go"))
		if err != nil {
			t.Fatalf("read svc.go: %v", err)
		}
		if !strings.Contains(string(got), `Variant = "vulnerable"`) {
			t.Fatalf("default-branch checkout regressed: %s", got)
		}
	})
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
