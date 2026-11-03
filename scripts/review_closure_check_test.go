// Hermetic test for review-closure-check.sh. It builds one throwaway git repository (a main commit,
// the reviewed PR commit, then a revision commit) and runs the script against a table of findings
// files. No network, and no git command reads the developer's git config.
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

// closureEnv is gittest.Env without the developer's global and system git config, for every git
// command the test runs, the script's included.
func closureEnv() []string {
	return append(gittest.Env(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
}

func closureGit(t *testing.T, dir, stdin string, args ...string) {
	t.Helper()
	cmd := gittest.Command(args...)
	cmd.Dir = dir
	cmd.Env = closureEnv()
	cmd.Stdin = strings.NewReader(stdin)
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
	closureGit(t, repo, "", "init", "-q", "-b", "main")
	// Three commits through one fast-import. The PR commit is the reviewed head: it changes line 9
	// of a.go and line 2 of p.go. The revision after it changes line 3 of a.go, inserts a line after
	// line 2 of c.go and adds docs/b.md. origin/main is the main commit.
	commit := func(mark, msg string, files map[string]string) string {
		out := "commit refs/heads/main\nmark :" + mark + "\ncommitter t <t@example.com> 1700000000 +0000\ndata " + strconv.Itoa(len(msg)) + "\n" + msg + "\n"
		for _, name := range []string{"a.go", "c.go", "p.go", "docs/b.md"} {
			if body, ok := files[name]; ok {
				out += "M 100644 inline " + name + "\ndata " + strconv.Itoa(len(body)) + "\n" + body + "\n"
			}
		}
		return out
	}
	lines := func(n int, edits map[int]string) string {
		var b strings.Builder
		for i := 1; i <= n; i++ {
			if s, ok := edits[i]; ok {
				b.WriteString(s + "\n")
			} else {
				b.WriteString(strconv.Itoa(i) + "\n")
			}
		}
		return b.String()
	}
	stream := commit("1", "main", map[string]string{"a.go": lines(10, nil), "c.go": lines(3, nil), "p.go": lines(10, nil)}) +
		commit("2", "pr", map[string]string{"a.go": lines(10, map[int]string{9: "nine"}), "p.go": lines(10, map[int]string{2: "two"})}) +
		commit("3", "revision", map[string]string{"a.go": lines(10, map[int]string{3: "three", 9: "nine"}),
			"c.go": "1\n2\nnew\n3\n", "docs/b.md": "new\n"}) +
		"reset refs/remotes/origin/main\nfrom :1\n\n"
	marks := filepath.Join(t.TempDir(), "marks")
	closureGit(t, repo, stream, "fast-import", "--quiet", "--export-marks="+marks)
	m, err := os.ReadFile(marks)
	if err != nil {
		t.Fatal(err)
	}
	reviewed := "" // the PR commit, mark :2
	for _, l := range strings.Split(string(m), "\n") {
		if sha, ok := strings.CutPrefix(l, ":2 "); ok {
			reviewed = sha
		}
	}
	pwn := filepath.Join(t.TempDir(), "pwn")

	// Each case is one script run, so a file carries several findings and want is the exact list
	// of OPEN and TOUCHED lines expected, in file order. base "" runs the script without a base.
	cases := []struct {
		name     string
		findings string
		base     string
		mode     os.FileMode
		wantExit int
		want     []string
	}{
		// origin/main...HEAD is the whole PR, so with origin/main as a default this would read closed.
		{"no base", "p.go - missing nil check\n", "", 0o644, 2, nil},
		{"base read as an option", "a.go:3 - rename\n", "--output=" + pwn, 0o644, 2, nil},
		{"empty file", "", reviewed, 0o644, 2, nil},
		{"headings only", "# Review of #412\n### Findings\n\n## Answered\n", reviewed, 0o644, 2, nil},
		{"unreadable file", "a.go:3 - rename\n", reviewed, 0o000, 2, nil},
		// p.go changed in the reviewed PR commit only, so its findings are untouched. a.go:3 is
		// covered by the revision's hunk and a.go:9 is not. c.go:1 is not next to the line inserted
		// after c.go:2. f.go:4 sits under Answered without " => ", and the blank-reason answer and
		// the duplicate "c.go - bare" leave their findings open, printed once.
		{"open and touched", "p.go:2 - missing nil check\np.go:9 - wrong error text\na.go:3 - rename\n" +
			"a.go:9 - wrong error text\n#409 duplicates the parser\na.go - whole file\nc.go:1 - missing nil check\n" +
			"d.go - y\nc.go - bare\ne.go - blank reason\nTitle is too long\n\n## Answered\n" +
			"c.go - bare\ne.go - blank reason =>   \nf.go:4 - added later\n", reviewed, 0o644, 1,
			[]string{"OPEN: p.go:2 - missing nil check", "OPEN: p.go:9 - wrong error text",
				"OPEN: a.go:9 - wrong error text", "OPEN: #409 duplicates the parser", "TOUCHED: a.go - whole file",
				"OPEN: c.go:1 - missing nil check", "OPEN: d.go - y", "TOUCHED: c.go - bare",
				"OPEN: e.go - blank reason", "OPEN: Title is too long", "OPEN: f.go:4 - added later"}},
		// c.go:3 is next to the inserted line and docs/b.md:1 is in a new file.
		{"all closed", "`a.go:3` - rename\nc.go:3 - guard before this\n- docs/b.md:1 - bulleted\r\n" +
			"#409 duplicates the parser\nc.go - whole file\nTitle is too long\n\n## Answered\n" +
			"#409 duplicates the parser => kept on purpose\nc.go - whole file => confirmed, see the new guard\n" +
			"Title is too long => retitled\n", reviewed, 0o644, 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "findings.md")
			if err := os.WriteFile(f, []byte(c.findings), c.mode); err != nil {
				t.Fatal(err)
			}
			if c.mode == 0o000 {
				if fh, err := os.Open(f); err == nil {
					fh.Close()
					t.Skip("mode 000 is readable to this user")
				}
			}
			args := []string{script, f}
			if c.base != "" {
				args = append(args, c.base)
			}
			cmd := exec.Command("bash", args...)
			cmd.Dir = repo
			cmd.Env = closureEnv()
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
			var got []string
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if strings.HasPrefix(l, "OPEN: ") || strings.HasPrefix(l, "TOUCHED: ") {
					got = append(got, l)
				}
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("OPEN/TOUCHED lines %q, want %q", got, c.want)
			}
			if ok := strings.Contains(string(out), "review-closure-check: OK"); ok != (c.wantExit == 0) {
				t.Errorf("OK line present=%v with exit %d:\n%s", ok, c.wantExit, out)
			}
			if _, err := os.Stat(pwn + "...HEAD"); err == nil {
				t.Errorf("a base starting with - reached git as an option: %s...HEAD was written", pwn)
			}
		})
	}
}
