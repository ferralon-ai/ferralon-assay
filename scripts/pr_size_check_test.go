// Self-test for pr-size-check.sh. Each case builds its own throwaway repository (a base commit and
// one branch commit), so nothing touches the network or the real checkout.
package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func sizeGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// sizeWrite writes a file of n lines under dir.
func sizeWrite(t *testing.T, dir, rel string, n int) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Repeat("line\n", n)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// sizeBranch cuts a branch from main, writes files (path -> line count) and commits them.
func sizeBranch(t *testing.T, dir, name string, files map[string]int) {
	t.Helper()
	sizeGit(t, dir, "checkout", "-q", "-B", name, "main")
	for rel, n := range files {
		sizeWrite(t, dir, rel, n)
	}
	sizeGit(t, dir, "add", "-A")
	sizeGit(t, dir, "commit", "-q", "-m", name)
}

func runSize(t *testing.T, dir string, env []string, args ...string) (string, int) {
	t.Helper()
	script, err := filepath.Abs("pr-size-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

type sizeCase struct {
	files    map[string]int
	env      []string
	base     string
	wantCode int
	want     []string
	notWant  []string
}

func checkSize(t *testing.T, c sizeCase) {
	t.Helper()
	dir := t.TempDir()
	sizeGit(t, dir, "init", "-q", "-b", "main")
	sizeWrite(t, dir, "README.md", 1)
	sizeGit(t, dir, "add", "-A")
	sizeGit(t, dir, "commit", "-q", "-m", "base")
	sizeBranch(t, dir, "topic", c.files)
	out, code := runSize(t, dir, c.env, c.base)
	if code != c.wantCode {
		t.Fatalf("exit %d, want %d\n%s", code, c.wantCode, out)
	}
	for _, w := range c.want {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q:\n%s", w, out)
		}
	}
	for _, w := range c.notWant {
		if strings.Contains(out, w) {
			t.Errorf("output has unwanted %q:\n%s", w, out)
		}
	}
}

func TestPRSizeWithinLimits(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 10, "b/y.go": 5}, base: "main", wantCode: 0,
		want: []string{"pr-size-check: OK"}, notWant: []string{"OVER:", "SPLIT:"}})
}

func TestPRSizeOverLines(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 601}, base: "main", wantCode: 1,
		want:    []string{"OVER: 601 changed lines (limit 600)", "SPLIT: a: 601 lines"},
		notWant: []string{"files changed", "directories"}})
}

func TestPRSizeOverFiles(t *testing.T) {
	many := map[string]int{}
	for i := 0; i < 21; i++ {
		many[fmt.Sprintf("a/f%d.txt", i)] = 1
	}
	checkSize(t, sizeCase{files: many, base: "main", wantCode: 1,
		want:    []string{"OVER: 21 files changed (limit 20)"},
		notWant: []string{"changed lines", "directories"}})
}

func TestPRSizeOverAreas(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/1": 1, "b/1": 2, "c/1": 3, "d/1": 4}, base: "main", wantCode: 1,
		want:    []string{"OVER: 4 top-level directories touched (limit 3)", "SPLIT: a: 1 lines", "SPLIT: d: 4 lines"},
		notWant: []string{"changed lines", "files changed"}})
}

func TestPRSizeExcludesGenerated(t *testing.T) {
	checkSize(t, sizeCase{
		files: map[string]int{"a/x.go": 5, "go.sum": 5000, "api/x.pb.go": 5000, "gen/zz_generated.deepcopy.go": 5000},
		base:  "main", wantCode: 0, want: []string{"pr-size-check: OK"}})
}

func TestPRSizeEnvRaisesLimit(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 601}, env: []string{"PR_SIZE_MAX_LINES=700"}, base: "main",
		wantCode: 0, want: []string{"pr-size-check: OK"}})
}

func TestPRSizeEnvLowersLimit(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 10, "b/y.go": 5}, env: []string{"PR_SIZE_MAX_AREAS=1"}, base: "main",
		wantCode: 1, want: []string{"OVER: 2 top-level directories touched (limit 1)"}})
}

func TestPRSizeUnknownBase(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 1}, base: "nope", wantCode: 2, want: []string{"unknown base ref"}})
}

func TestPRSizeBadLimit(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 1}, env: []string{"PR_SIZE_MAX_FILES=lots"}, base: "main",
		wantCode: 2, want: []string{"non-negative integers"}})
}
