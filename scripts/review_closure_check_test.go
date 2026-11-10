// Hermetic test for review-closure-check.sh. It builds one throwaway bare git repository (a main
// commit, the reviewed PR commit, then a revision commit, plus a later main commit, the PR rebased
// onto it and a merge of it into the revision) and runs the script against a table of findings
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
// command the test runs, the script's included. gitDir goes first on PATH: it is git's exec-path,
// which holds the git binary itself, so the script's git calls skip a wrapper such as macOS's
// /usr/bin/git, which costs about as much CPU again as the git it starts.
func closureEnv(gitDir string) []string {
	return append(gittest.Env(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"PATH="+gitDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestReviewClosureCheck(t *testing.T) {
	script, err := filepath.Abs("review-closure-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	// The script only compares commits, so a bare repository laid out by hand (HEAD, objects/,
	// refs/) is enough, and costs less CPU than a git init.
	repo := t.TempDir()
	for _, d := range []string{"objects", "refs"} {
		if err := os.Mkdir(filepath.Join(repo, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	head := func(branch string) {
		if err := os.WriteFile(filepath.Join(repo, "HEAD"), []byte("ref: refs/heads/"+branch+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	head("main")
	execPath, err := gittest.Command("--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	env := closureEnv(strings.TrimSpace(string(execPath)))
	// Six commits through one fast-import. On main, the PR commit is the reviewed head: it changes
	// line 9 of a.go and line 2 of p.go. The revision after it changes line 3 of a.go, inserts a
	// line after line 2 of c.go and adds docs/b.md. upstream is main moved on from the first
	// commit, changing line 2 of m.go; rebased is the PR commit replayed onto upstream, and merged
	// is the revision with upstream merged into it.
	commit := func(ref, mark, parents, msg string, files map[string]string) string {
		out := "commit refs/heads/" + ref + "\nmark :" + mark + "\ncommitter t <t@example.com> 1700000000 +0000\ndata " + strconv.Itoa(len(msg)) + "\n" + msg + "\n" + parents
		for _, name := range []string{"a.go", "c.go", "m.go", "p.go", "docs/b.md"} {
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
	pr := map[string]string{"a.go": lines(10, map[int]string{9: "nine"}), "p.go": lines(10, map[int]string{2: "two"})}
	upstream := map[string]string{"m.go": lines(3, map[int]string{2: "two"})}
	stream := commit("main", "1", "", "main", map[string]string{"a.go": lines(10, nil), "c.go": lines(3, nil), "m.go": lines(3, nil), "p.go": lines(10, nil)}) +
		commit("main", "2", "", "pr", pr) +
		commit("main", "3", "", "revision", map[string]string{"a.go": lines(10, map[int]string{3: "three", 9: "nine"}),
			"c.go": "1\n2\nnew\n3\n", "docs/b.md": "new\n"}) +
		commit("upstream", "4", "from :1\n", "upstream", upstream) +
		commit("rebased", "5", "from :4\n", "pr", pr) +
		commit("merged", "6", "from :3\nmerge :4\n", "merge upstream", upstream)
	marks := filepath.Join(t.TempDir(), "marks")
	imp := gittest.Command("fast-import", "--quiet", "--export-marks="+marks)
	imp.Dir = repo
	imp.Env = env
	imp.Stdin = strings.NewReader(stream)
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("git fast-import: %v\n%s", err, out)
	}
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
	// of OPEN and TOUCHED lines expected, in file order. base "" runs the script without a base,
	// head is the branch HEAD names ("" is main, the revision) and wantErr is text stderr must hold.
	cases := []struct {
		name     string
		findings string
		base     string
		head     string
		mode     os.FileMode
		wantExit int
		want     []string
		wantErr  string
	}{
		// The base is required: there is no default to fall back to.
		{"no base", "p.go - missing nil check\n", "", "", 0o644, 2, nil, "usage:"},
		{"base read as an option", "a.go:3 - rename\n", "--output=" + pwn, "", 0o644, 2, nil, "not a commit"},
		{"empty file", "", reviewed, "", 0o644, 2, nil, "no findings"},
		{"headings only", "# Review of #412\n### Findings\n\n## Answered\n", reviewed, "", 0o644, 2, nil, "no findings"},
		{"unreadable file", "a.go:3 - rename\n", reviewed, "", 0o000, 2, nil, "cannot read"},
		// p.go changed in the reviewed PR commit only, so its findings are untouched. a.go:3 is
		// covered by the revision's hunk and a.go:9 is not. c.go:1 is not next to the line inserted
		// after c.go:2. f.go:4 sits under Answered without " => ", and the blank-reason answer and
		// the duplicate "c.go - bare" leave their findings open, printed once.
		{"open and touched", "p.go:2 - missing nil check\np.go:9 - wrong error text\na.go:3 - rename\n" +
			"a.go:9 - wrong error text\n#409 duplicates the parser\na.go - whole file\nc.go:1 - missing nil check\n" +
			"d.go - y\nc.go - bare\ne.go - blank reason\nTitle is too long\n\n## Answered\n" +
			"c.go - bare\ne.go - blank reason =>   \nf.go:4 - added later\n", reviewed, "", 0o644, 1,
			[]string{"OPEN: p.go:2 - missing nil check", "OPEN: p.go:9 - wrong error text",
				"OPEN: a.go:9 - wrong error text", "OPEN: #409 duplicates the parser", "TOUCHED: a.go - whole file",
				"OPEN: c.go:1 - missing nil check", "OPEN: d.go - y", "TOUCHED: c.go - bare",
				"OPEN: e.go - blank reason", "OPEN: Title is too long", "OPEN: f.go:4 - added later"}, ""},
		// c.go:3 is next to the inserted line and docs/b.md:1 is in a new file. a.go:9 is untouched
		// and holds " => " in its own text, so only an answer split at the last arrow closes it.
		{"all closed", "`a.go:3` - rename\nc.go:3 - guard before this\n- docs/b.md:1 - bulleted\r\n" +
			"#409 duplicates the parser\nc.go - whole file\nTitle is too long\na.go:9 - map k => v\n\n## Answered\n" +
			"#409 duplicates the parser => kept on purpose\nc.go - whole file => confirmed, see the new guard\n" +
			"Title is too long => retitled\na.go:9 - map k => v => kept\n", reviewed, "", 0o644, 0, nil, ""},
		// An Answered entry is a finding itself, so a file of answers alone is checked, not empty.
		{"answered only", "## Answered\na.go:9 - wording => kept\n", reviewed, "", 0o644, 0, nil, ""},
		// Both would print OK without the refusal: after the rebase the merge base is main's first
		// commit, so the diff is the whole replayed PR and covers a.go:9, and after the merge the diff
		// carries upstream's change to m.go:2.
		{"rebased onto main", "a.go:9 - finding the review already saw\n", reviewed, "rebased", 0o644, 2, nil, "not an ancestor of HEAD"},
		{"merged main", "m.go:2 - finding on a line only main changed\n", reviewed, "merged", 0o644, 2, nil, "merge commits since the reviewed head"},
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
			if c.head == "" {
				head("main")
			} else {
				head(c.head)
			}
			var stderr strings.Builder
			cmd := exec.Command("bash", args...)
			cmd.Dir = repo
			cmd.Env = env
			cmd.Stderr = &stderr
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
			if !strings.Contains(stderr.String(), c.wantErr) {
				t.Errorf("stderr %q does not hold %q", stderr.String(), c.wantErr)
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
