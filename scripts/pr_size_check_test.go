// Self-test for pr-size-check.sh. Each case builds its own throwaway repository in one git
// fast-import (a base commit, one branch commit, and an unrelated root commit where a case needs
// one), so nothing touches the network or the real checkout.
package scripts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type sizeCase struct {
	baseTexts map[string]string // extra files in the base commit, path -> content
	files     map[string]int    // files the branch writes, path -> line count
	texts     map[string]string // files the branch writes, path -> content
	moves     map[string]string // files the branch moves, old path -> new path
	deletes   []string          // files the branch deletes
	orphan    bool              // add branch "lonely", a root commit sharing no history with HEAD
	env       []string
	base      string
	wantCode  int
	want      []string
	notWant   []string
}

// sizeQuote writes a path as fast-import's C-style quoted string.
func sizeQuote(path string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\t", `\t`, "\n", `\n`).Replace(path) + `"`
}

// sizeCommit appends one fast-import commit to branch: the moves and deletes, then files written
// (path -> content).
func sizeCommit(s *strings.Builder, branch, from string, files, moves map[string]string, deletes []string) {
	fmt.Fprintf(s, "commit refs/heads/%s\ncommitter t <t@example.com> 0 +0000\ndata 1\n%s\n", branch, branch[:1])
	if from != "" {
		fmt.Fprintf(s, "from %s\n", from)
	}
	for old, to := range moves {
		fmt.Fprintf(s, "R %s %s\n", sizeQuote(old), sizeQuote(to))
	}
	for _, rel := range deletes {
		fmt.Fprintf(s, "D %s\n", sizeQuote(rel))
	}
	for rel, text := range files {
		fmt.Fprintf(s, "M 100644 inline %s\ndata %d\n%s\n", sizeQuote(rel), len(text), text)
	}
}

// sizeRepo builds the case's repository: main holds README.md and the base files, and topic, which
// HEAD names, changes them.
func sizeRepo(t *testing.T, c sizeCase) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "-b", "topic", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	base := map[string]string{"README.md": "line\n"}
	for rel, text := range c.baseTexts {
		base[rel] = text
	}
	topic := map[string]string{}
	for rel, n := range c.files {
		topic[rel] = strings.Repeat("line\n", n)
	}
	for rel, text := range c.texts {
		topic[rel] = text
	}
	var s strings.Builder
	sizeCommit(&s, "main", "", base, nil, nil)
	sizeCommit(&s, "topic", "refs/heads/main", topic, c.moves, c.deletes)
	if c.orphan {
		sizeCommit(&s, "lonely", "", map[string]string{"other.txt": "line\n"}, nil, nil)
	}
	cmd := exec.Command("git", "fast-import", "--quiet")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(s.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git fast-import: %v\n%s", err, out)
	}
	return dir
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

func checkSize(t *testing.T, c sizeCase) {
	t.Helper()
	out, code := runSize(t, sizeRepo(t, c), c.env, c.base)
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

// SPLIT lists the largest directory first, by count, not by the count's text.
func TestPRSizeSplitLargestFirst(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/1": 2, "b/1": 3, "c/1": 10}, env: []string{"PR_SIZE_MAX_AREAS=1"},
		base: "main", wantCode: 1,
		want: []string{"OVER: 3 top-level directories touched (limit 1)\nSPLIT: c: 10 lines\nSPLIT: b: 3 lines\nSPLIT: a: 2 lines\n"}})
}

func TestPRSizeExcludesGenerated(t *testing.T) {
	checkSize(t, sizeCase{
		files: map[string]int{"a/x.go": 5, "go.sum": 5000, "api/x.pb.go": 5000, "gen/zz_generated.deepcopy.go": 5000},
		base:  "main", wantCode: 0, want: []string{"pr-size-check: OK"}})
}

// A vendored tree and the lock files count toward nothing, like go.sum.
func TestPRSizeExcludesVendorAndLockFiles(t *testing.T) {
	checkSize(t, sizeCase{
		files: map[string]int{
			"a/x.txt": 5,
			"corpus/testdata/repros/r/vendor/golang.org/x/text/tables.go": 50,
			"vendor/modules.txt":    50,
			"web/package-lock.json": 50, "yarn.lock": 50, "web/pnpm-lock.yaml": 50,
		},
		env: []string{"PR_SIZE_MAX_FILES=1", "PR_SIZE_MAX_AREAS=1", "PR_SIZE_MAX_LINES=5"}, base: "main",
		wantCode: 0, want: []string{"pr-size-check: OK"}})
}

// A .go file is generated when Go's marker comes before the package clause, whatever its name; that
// holds for a deleted file too. The marker after the package clause does not count.
func TestPRSizeExcludesGeneratedHeader(t *testing.T) {
	gen := "// Code generated by stringer; DO NOT EDIT.\n\npackage a\n" + strings.Repeat("var _ = 0\n", 50)
	late := "package b\n\n// Code generated by stringer; DO NOT EDIT.\n" + strings.Repeat("var _ = 0\n", 7)
	checkSize(t, sizeCase{
		baseTexts: map[string]string{"old/tables.go": gen},
		deletes:   []string{"old/tables.go"},
		texts:     map[string]string{"a/tables.go": gen, "b/hand.go": late},
		env:       []string{"PR_SIZE_MAX_LINES=10", "PR_SIZE_MAX_AREAS=0"}, base: "main", wantCode: 1,
		want:    []string{"OVER: 1 top-level directories touched (limit 0)", "SPLIT: b: 10 lines"},
		notWant: []string{"SPLIT: a:", "SPLIT: old:", "changed lines", "files changed"}})
}

// A pure move is one file with no changed lines, in the directory it moved to.
func TestPRSizeMoveCountsOnce(t *testing.T) {
	checkSize(t, sizeCase{
		baseTexts: map[string]string{"a/big.txt": strings.Repeat("line\n", 400)},
		moves:     map[string]string{"a/big.txt": "b/big.txt"},
		env:       []string{"PR_SIZE_MAX_LINES=0", "PR_SIZE_MAX_FILES=0", "PR_SIZE_MAX_AREAS=0"}, base: "main",
		wantCode: 1, want: []string{"OVER: 1 files changed (limit 0)", "OVER: 1 top-level directories touched (limit 0)",
			"SPLIT: b: 0 lines"},
		notWant: []string{"changed lines", "SPLIT: a:"}})
}

// A path with a quote, a backslash or a tab is read whole: its directory is right and its name still
// matches the generated pattern.
func TestPRSizeOddPath(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.txt": 5, "a/we\"i\\rd\tq.pb.go": 5000, "b\"c/y.txt": 3},
		env: []string{"PR_SIZE_MAX_AREAS=1"}, base: "main", wantCode: 1,
		want:    []string{"OVER: 2 top-level directories touched (limit 1)", "SPLIT: a: 5 lines", "SPLIT: b\"c: 3 lines"},
		notWant: []string{"changed lines", "files changed"}})
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

func TestPRSizeOptionShapedBase(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 1}, base: "--output=x", wantCode: 2, want: []string{"unknown base ref"}})
}

// A base that shares no history with HEAD, as on a shallow clone, is a git error, not an empty diff.
func TestPRSizeNoMergeBase(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 1}, orphan: true, base: "lonely", wantCode: 2,
		want: []string{"no merge base", "--unshallow"}})
}

func TestPRSizeBadLimit(t *testing.T) {
	checkSize(t, sizeCase{files: map[string]int{"a/x.go": 1}, env: []string{"PR_SIZE_MAX_FILES=lots"}, base: "main",
		wantCode: 2, want: []string{"non-negative integers"}})
}
