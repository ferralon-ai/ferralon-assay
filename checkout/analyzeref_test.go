package checkout

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// upstreamWithBaseline returns an upstream whose main is docs-only and whose baseline branch holds
// a Go module under svc/, plus its baseline commit.
func upstreamWithBaseline(t *testing.T) (string, string) {
	t.Helper()
	if !GitAvailable() {
		t.Skip("git CLI not available")
	}
	up := t.TempDir()
	gitIn(t, up, "init", "-q")
	if err := os.MkdirAll(filepath.Join(up, "svc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(up, "svc", "README.md"), []byte("docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, up, "add", "-A")
	gitIn(t, up, "commit", "-q", "-m", "main")
	gitIn(t, up, "checkout", "-q", "-b", "baseline")
	if err := os.WriteFile(filepath.Join(up, "svc", "go.mod"), []byte("module example.com/svc\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, up, "add", "-A")
	gitIn(t, up, "commit", "-q", "-m", "baseline")
	sha := gitIn(t, up, "rev-parse", "HEAD")
	gitIn(t, up, "checkout", "-q", "main")
	return up, sha
}

// A full (non-shallow) clone — a developer's checkout — is fetched without --depth, so the redirect
// never converts it to a shallow repository. A target below the repository root maps to the same
// subdirectory of the worktree.
func TestWorktreeAtRef_FullCloneStaysFullAndSubdirMaps(t *testing.T) {
	up, sha := upstreamWithBaseline(t)
	clone := filepath.Join(t.TempDir(), "ws")
	gitIn(t, filepath.Dir(clone), "clone", "-q", "file://"+up, clone)

	dir, commit, cleanup, err := NewGitCheckout().WorktreeAtRef(context.Background(), filepath.Join(clone, "svc"), "baseline")
	if err != nil {
		t.Fatalf("WorktreeAtRef: %v", err)
	}
	defer cleanup()
	if commit != sha {
		t.Fatalf("commit = %s, want %s", commit, sha)
	}
	if filepath.Base(dir) != "svc" {
		t.Fatalf("dir %q must be the svc subdirectory of the worktree", dir)
	}
	if lang := DetectLanguage(dir); lang != LangGo {
		t.Fatalf("worktree svc/ must hold baseline's module, detected %q", lang)
	}
	if s := gitIn(t, clone, "rev-parse", "--is-shallow-repository"); s != "false" {
		t.Fatalf("a full clone must stay full, is-shallow = %s", s)
	}
}

// AC3 at the git boundary: the ref is one argv element handed straight to git, never a shell
// string. Even when a caller skips repoconfig validation, shell metacharacters are inert — git
// rejects the refspec and nothing executes — and option- or refspec-shaped values are refused
// before git runs.
func TestWorktreeAtRef_InjectionLookingRefIsInert(t *testing.T) {
	up, _ := upstreamWithBaseline(t)
	clone := filepath.Join(t.TempDir(), "ws")
	gitIn(t, filepath.Dir(clone), "clone", "-q", "--depth", "1", "file://"+up, clone)
	sentinel := filepath.Join(t.TempDir(), "pwned")

	for _, ref := range []string{
		"$(touch " + sentinel + ")",
		"`touch " + sentinel + "`",
		"main;touch${IFS}" + sentinel,
		"--upload-pack=touch " + sentinel,
		"main:refs/heads/pwned",
	} {
		t.Run(ref, func(t *testing.T) {
			_, _, cleanup, err := NewGitCheckout().WorktreeAtRef(context.Background(), clone, ref)
			if err == nil {
				cleanup()
				t.Fatalf("ref %q must not resolve", ref)
			}
			if cleanup != nil {
				t.Fatal("cleanup must be nil on failure")
			}
		})
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("a ref payload was executed")
	}
	if out := gitIn(t, clone, "branch", "--list", "pwned"); out != "" {
		t.Fatal("a refspec-shaped ref wrote a local branch")
	}
}

func TestWorktreeAtRef_NotAGitCheckout(t *testing.T) {
	if !GitAvailable() {
		t.Skip("git CLI not available")
	}
	_, _, _, err := NewGitCheckout().WorktreeAtRef(context.Background(), t.TempDir(), "baseline")
	if err == nil || !strings.Contains(err.Error(), "not inside a git checkout") {
		t.Fatalf("want a not-a-git-checkout error, got %v", err)
	}
}
