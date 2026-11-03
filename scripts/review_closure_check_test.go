// Hermetic test for review-closure-check.sh. It builds one throwaway git repository (a base
// commit, then a revision commit that changes a.go and docs/b.md) and runs the script against a
// table of findings files. No network.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

func closureGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := gittest.Command(args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestReviewClosureCheck(t *testing.T) {
	script, err := filepath.Abs("review-closure-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	closureGit(t, repo, "init", "-q", "-b", "main")
	write("a.go", "1\n")
	write("c.go", "1\n")
	closureGit(t, repo, "add", "-A")
	closureGit(t, repo, "commit", "-q", "-m", "base")
	write("a.go", "2\n")
	write("docs/b.md", "new\n")
	closureGit(t, repo, "add", "-A")
	closureGit(t, repo, "commit", "-q", "-m", "revision")

	cases := []struct {
		name     string
		findings string
		wantExit int
		wantOut  []string // substrings required in stdout
		noOut    []string // substrings forbidden in stdout
	}{
		{"all changed", "a.go:3 - rename\ndocs/b.md - typo\n", 0, []string{"review-closure-check: OK"}, []string{"OPEN:"}},
		{"one unaddressed", "a.go - rename\nc.go:9 - missing nil check\n", 1, []string{"OPEN: c.go:9 - missing nil check"}, []string{"OK", "OPEN: a.go"}},
		{"two unaddressed", "c.go - x\nd.go - y\n", 1, []string{"OPEN: c.go - x", "OPEN: d.go - y"}, nil},
		{"answered with reason", "c.go:9 - why?\n\n## Answered\nc.go:9 - why? => kept on purpose, see comment\n", 0, []string{"OK"}, nil},
		{"answered bare", "c.go:9 - why?\n\n## Answered\nc.go:9 - why?\n", 1, []string{"OPEN: c.go:9 - why?"}, nil},
		{"answered empty reason", "c.go:9 - why?\n\n## Answered\nc.go:9 - why? =>   \n", 1, []string{"OPEN: c.go:9 - why?"}, nil},
		{"no path open", "Title is too long\n", 1, []string{"OPEN: Title is too long"}, nil},
		{"no path answered", "Title is too long\n\n## Answered\nTitle is too long => retitled\n", 0, []string{"OK"}, nil},
		{"bulleted and crlf", "- a.go - rename\r\n* c.go - x\r\n", 1, []string{"OPEN: c.go - x"}, []string{"OPEN: a.go"}},
		{"empty file", "", 0, []string{"OK"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "findings.md")
			if err := os.WriteFile(f, []byte(c.findings), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", script, f, "HEAD~1")
			cmd.Dir = repo
			cmd.Env = gittest.Env()
			out, err := cmd.Output()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.wantExit {
				t.Errorf("exit %d, want %d\n%s", code, c.wantExit, out)
			}
			for _, s := range c.wantOut {
				if !strings.Contains(string(out), s) {
					t.Errorf("stdout missing %q:\n%s", s, out)
				}
			}
			for _, s := range c.noOut {
				if strings.Contains(string(out), s) {
					t.Errorf("stdout has %q:\n%s", s, out)
				}
			}
		})
	}
}
