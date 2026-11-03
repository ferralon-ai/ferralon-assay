// Self-test for pr-ready-check.sh. The throwaway repository is built once per test binary and
// each case copies it, adds a branch commit, and runs the script.
package scripts

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

var (
	prReadyOnce sync.Once
	prReadyTpl  string // removed by TestMain
)

func prGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := gittest.Command(append([]string{"-C", dir,
		"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func prWrite(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// prBase returns a path to a repo with one commit on main containing package a.
func prBase(t *testing.T) string {
	prReadyOnce.Do(func() {
		dir, err := os.MkdirTemp("", "prready")
		if err != nil {
			t.Fatal(err)
		}
		prReadyTpl = dir
		prGit(t, dir, "init", "-q", "-b", "main")
		prWrite(t, dir, "go.mod", "module example.com/m\n\ngo 1.21\n")
		prWrite(t, dir, "a/a.go", "package a\n\nfunc A() int { return 1 }\n")
		prGit(t, dir, "add", "-A")
		prGit(t, dir, "commit", "-q", "-m", "base")
	})
	dst := t.TempDir()
	if out, err := exec.Command("cp", "-R", prReadyTpl+"/.", dst).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v\n%s", err, out)
	}
	return dst
}

func TestPRReadyCheck(t *testing.T) {
	script, err := filepath.Abs("pr-ready-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := os.ReadFile(filepath.Join("..", ".github", "PULL_REQUEST_TEMPLATE.md"))
	if err != nil {
		t.Fatal(err)
	}
	good := "package a\n\nfunc A() int { return 2 }\n"
	goodTest := "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { _ = A() }\n"
	unformatted := "package a\nfunc A() int {return 2}\n"
	pGood := "package p\n\nfunc P() int { return 1 }\n"
	pTest := "package p\n\nimport \"testing\"\n\nfunc TestP(t *testing.T) { _ = P() }\n"
	plugMod := "module example.com/plug\n\ngo 1.21\n"
	docOnly := map[string]string{"README.md": "docs\n"} // no Go change: (a) and (c) have nothing to check
	const realDesc = "Fixes the widget.\n"
	cases := []struct {
		name  string
		files map[string]string
		desc  *string
		base  string                         // default "main"
		setup func(t *testing.T, dir string) // after the branch commit
		cwd   string                         // run from this subdirectory, with the description there by a relative path
		want  string                         // substring of output; "" means clean pass
		code  int                            // exit status when want is set
	}{
		{name: "clean", files: map[string]string{"a/a.go": good, "a/a_test.go": goodTest}, desc: ptr(realDesc)},
		{name: "missing test", files: map[string]string{"a/a.go": good}, desc: ptr(realDesc), want: "package a changed but no _test.go", code: 1},
		{name: "empty description", files: docOnly, desc: ptr("\n  \n"), want: "empty or still the template", code: 1},
		{name: "template description", files: docOnly,
			desc: ptr("## Summary\n<!-- Describe your changes -->\n\n## Testing\n<!-- how -->\n"), want: "empty or still the template", code: 1},
		{name: "repository PR template", files: docOnly, desc: ptr(string(tpl)), want: "empty or still the template", code: 1},
		{name: "no description given", files: docOnly, want: "no PR description file", code: 1},
		{name: "relative description from a subdirectory", files: docOnly, desc: ptr(realDesc), cwd: "a"},
		{name: "unknown base", files: docOnly, desc: ptr(realDesc), base: "nope", want: "unknown base ref 'nope'", code: 2},
		{name: "no merge base", files: map[string]string{"a/a.go": good}, desc: ptr(realDesc), base: "other",
			setup: func(t *testing.T, dir string) {
				prGit(t, dir, "checkout", "-q", "--orphan", "other")
				prGit(t, dir, "commit", "-q", "-m", "unrelated")
				prGit(t, dir, "checkout", "-q", "feature")
			}, want: "no merge base", code: 2},
		{name: "uncommitted fix", files: map[string]string{"a/a.go": unformatted, "a/a_test.go": goodTest}, desc: ptr(realDesc),
			setup: func(t *testing.T, dir string) { prWrite(t, dir, "a/a.go", good) }, want: "commit or stash", code: 2},
		{name: "gofmt", files: map[string]string{"a/a.go": unformatted, "a/a_test.go": goodTest}, desc: ptr(realDesc), want: "gofmt reports a/a.go", code: 1},
		{name: "testdata skipped", files: map[string]string{"a/a.go": good, "a/a_test.go": goodTest, "a/testdata/f.go": "package f\nfunc F() {return}\n"}, desc: ptr(realDesc)},
		{name: "vet", files: map[string]string{"a/a.go": "package a\n\nimport \"fmt\"\n\nfunc A() int { fmt.Printf(\"%d\\n\"); return 2 }\n", "a/a_test.go": goodTest}, desc: ptr(realDesc), want: "go vet reports", code: 1},
		{name: "nested module", files: map[string]string{"plug/go.mod": plugMod, "plug/p/p.go": pGood, "plug/p/p_test.go": pTest}, desc: ptr(realDesc)},
		{name: "nested module vet", files: map[string]string{"plug/go.mod": plugMod, "plug/p/p.go": "package p\n\nimport \"fmt\"\n\nfunc P() { fmt.Printf(\"%d\\n\") }\n", "plug/p/p_test.go": pTest},
			desc: ptr(realDesc), want: "go vet reports problems in module plug", code: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := prBase(t)
			prGit(t, dir, "checkout", "-q", "-b", "feature")
			for rel, body := range c.files {
				prWrite(t, dir, rel, body)
			}
			prGit(t, dir, "add", "-A")
			prGit(t, dir, "commit", "-q", "-m", "change")
			if c.setup != nil {
				c.setup(t, dir)
			}
			base := c.base
			if base == "" {
				base = "main"
			}
			args := []string{script, base}
			cmd := exec.Command("bash")
			cmd.Dir = dir
			if c.desc != nil {
				if c.cwd != "" {
					cmd.Dir = filepath.Join(dir, c.cwd)
					prWrite(t, cmd.Dir, "desc.md", *c.desc)
					args = append(args, "desc.md")
				} else {
					descPath := filepath.Join(t.TempDir(), "desc.md")
					prWrite(t, filepath.Dir(descPath), "desc.md", *c.desc)
					args = append(args, descPath)
				}
			}
			cmd.Args = append(cmd.Args, args...)
			cmd.Env = gittest.Env()
			out, err := cmd.CombinedOutput()
			if c.want == "" {
				if err != nil || !strings.Contains(string(out), "OK") {
					t.Fatalf("want clean pass, got %v\n%s", err, out)
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != c.code {
				t.Fatalf("want exit %d with %q, got %v\n%s", c.code, c.want, err, out)
			}
			if !strings.Contains(string(out), c.want) {
				t.Fatalf("output lacks %q:\n%s", c.want, out)
			}
		})
	}
}

func ptr(s string) *string { return &s }
