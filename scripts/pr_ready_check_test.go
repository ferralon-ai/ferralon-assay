// Self-test for pr-ready-check.sh. The throwaway repository is built once per test binary and
// each case copies it, adds a branch commit, and runs the script.
package scripts

import (
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
	prReadyTpl  string
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
		prGit(t, dir, "init", "-q", "-b", "main")
		prWrite(t, dir, "go.mod", "module example.com/m\n\ngo 1.21\n")
		prWrite(t, dir, "a/a.go", "package a\n\nfunc A() int { return 1 }\n")
		prGit(t, dir, "add", "-A")
		prGit(t, dir, "commit", "-q", "-m", "base")
		prReadyTpl = dir
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
	good := "package a\n\nfunc A() int { return 2 }\n"
	goodTest := "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { _ = A() }\n"
	const realDesc = "Fixes the widget.\n"
	cases := []struct {
		name  string
		files map[string]string
		desc  *string
		want  string // substring of output; "" means clean pass
	}{
		{"clean", map[string]string{"a/a.go": good, "a/a_test.go": goodTest}, ptr(realDesc), ""},
		{"missing test", map[string]string{"a/a.go": good}, ptr(realDesc), "package a changed but no _test.go"},
		{"empty description", map[string]string{"a/a.go": good, "a/a_test.go": goodTest}, ptr("\n  \n"), "empty or still the template"},
		{"template description", map[string]string{"a/a.go": good, "a/a_test.go": goodTest},
			ptr("## Summary\n<!-- Describe your changes -->\n\n## Testing\n<!-- how -->\n"), "empty or still the template"},
		{"no description given", map[string]string{"a/a.go": good, "a/a_test.go": goodTest}, nil, "no PR description file"},
		{"gofmt", map[string]string{"a/a.go": "package a\nfunc A() int {return 2}\n", "a/a_test.go": goodTest}, ptr(realDesc), "gofmt reports a/a.go"},
		{"vet", map[string]string{"a/a.go": "package a\n\nimport \"fmt\"\n\nfunc A() int { fmt.Printf(\"%d\\n\"); return 2 }\n", "a/a_test.go": goodTest}, ptr(realDesc), "go vet reports"},
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
			args := []string{script, "main"}
			if c.desc != nil {
				descPath := filepath.Join(t.TempDir(), "desc.md")
				prWrite(t, filepath.Dir(descPath), "desc.md", *c.desc)
				args = append(args, descPath)
			}
			cmd := exec.Command("bash", args...)
			cmd.Dir = dir
			cmd.Env = gittest.Env()
			out, err := cmd.CombinedOutput()
			if c.want == "" {
				if err != nil || !strings.Contains(string(out), "OK") {
					t.Fatalf("want clean pass, got %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("want failure containing %q, got exit 0\n%s", c.want, out)
			}
			if !strings.Contains(string(out), c.want) {
				t.Fatalf("output lacks %q:\n%s", c.want, out)
			}
		})
	}
}

func ptr(s string) *string { return &s }
