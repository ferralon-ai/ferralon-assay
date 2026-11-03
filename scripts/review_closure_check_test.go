// Hermetic test for review-closure-check.sh. It builds one throwaway git repository (a base
// commit, then a revision commit that changes a.go and docs/b.md) and runs the script against a
// table of findings files. No network.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

func closureGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := gittest.Command(args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
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
	closureGit(t, repo, "init", "-q", "-b", "main")
	// Two commits through one fast-import: a base, then a revision that changes a.go and adds docs/b.md.
	commit := func(msg string, files map[string]string) string {
		out := "commit refs/heads/main\ncommitter t <t@example.com> 1700000000 +0000\ndata " + strconv.Itoa(len(msg)) + "\n" + msg + "\n"
		for _, name := range []string{"a.go", "c.go", "docs/b.md"} {
			if body, ok := files[name]; ok {
				out += "M 100644 inline " + name + "\ndata " + strconv.Itoa(len(body)) + "\n" + body + "\n"
			}
		}
		return out
	}
	stream := commit("base", map[string]string{"a.go": "1\n", "c.go": "1\n"}) +
		commit("revision", map[string]string{"a.go": "2\n", "docs/b.md": "new\n"})
	imp := gittest.Command("fast-import", "--quiet")
	imp.Dir = repo
	imp.Stdin = strings.NewReader(stream)
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("git fast-import: %v\n%s", err, out)
	}

	// Each case is one script run, so a file carries several findings and wantOpen is the exact
	// set of OPEN lines expected.
	cases := []struct {
		name     string
		findings string
		wantExit int
		wantOpen []string
	}{
		{"empty file", "", 0, nil},
		{"all closed", "a.go:3 - rename\ndocs/b.md - typo\n- a.go - bulleted\r\n" +
			"c.go:9 - why?\nTitle is too long\n\n## Answered\n" +
			"c.go:9 - why? => kept on purpose\nTitle is too long => retitled\n", 0, nil},
		{"open findings", "a.go - rename\nc.go:9 - missing nil check\nd.go - y\n" +
			"c.go - bare\ne.go - blank reason\nTitle is too long\n\n## Answered\n" +
			"c.go - bare\ne.go - blank reason =>   \n", 1,
			[]string{"OPEN: c.go:9 - missing nil check", "OPEN: d.go - y", "OPEN: c.go - bare",
				"OPEN: e.go - blank reason", "OPEN: Title is too long"}},
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
			var open []string
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if strings.HasPrefix(l, "OPEN: ") {
					open = append(open, l)
				}
			}
			if strings.Join(open, "|") != strings.Join(c.wantOpen, "|") {
				t.Errorf("OPEN lines %q, want %q", open, c.wantOpen)
			}
			if ok := strings.Contains(string(out), "review-closure-check: OK"); ok != (c.wantExit == 0) {
				t.Errorf("OK line present=%v with exit %d:\n%s", ok, c.wantExit, out)
			}
		})
	}
}
