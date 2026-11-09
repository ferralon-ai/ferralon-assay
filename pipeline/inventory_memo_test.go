package pipeline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// gitCallLog puts a git on PATH that records each invocation and runs the real one, and returns a
// func reporting how many times git has run so far.
func gitCallLog(t *testing.T) func() int {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	bin, logFile := t.TempDir(), filepath.Join(t.TempDir(), "calls")
	script := "#!/bin/sh\necho \"$@\" >> '" + logFile + "'\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() int {
		b, err := os.ReadFile(logFile)
		if err != nil {
			return 0
		}
		return strings.Count(string(b), "\n")
	}
}

func runInventoryOnce(t *testing.T, stage codebaseInventory, acq assessment.Acquisition) (payload []byte, c *assessment.Assessment) {
	t.Helper()
	store := artifact.NewMemStore()
	c = &assessment.Assessment{ID: "case-inventory-memo", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-TEST-NO-SUCH-ADVISORY", Source: "corpus"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "v1", Acquisition: acq},
	}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory.Run: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeInventory)
	if err != nil || len(arts) != 1 {
		t.Fatalf("inventory artifacts = %d, %v", len(arts), err)
	}
	return arts[0].Payload, c
}

// TestInventoryMemo_SecondRunReusesTheFirst: the checkout-constant reads codebase_inventory makes
// run once per memo. A second run over the same tree writes the same inventory and the same pinned
// commit, and spawns no git; without the memo it spawns the same git calls again, so the count is
// the memo's doing and not the shim missing them.
func TestInventoryMemo_SecondRunReusesTheFirst(t *testing.T) {
	cases := []struct {
		name string
		mode string
	}{
		{"checkout fetched", "git"},
		{"vendored_repro", "vendored_repro"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{
				"go.mod":  "module example.com/target\n\ngo 1.22\n",
				"main.go": "package main\n\nfunc main() {}\n",
			}))
			gitTree(t, tree, "v1.2.3")
			calls := gitCallLog(t)
			acq := assessment.Acquisition{Mode: tc.mode, Path: tree}
			stage := func(memo *InventoryMemo) codebaseInventory {
				return codebaseInventory{checkout: dirCheckout{dir: tree, lang: "go"}, memo: memo}
			}

			memo := NewInventoryMemo()
			first, c1 := runInventoryOnce(t, stage(memo), acq)
			afterFirst := calls()
			if afterFirst == 0 {
				t.Fatal("the first run spawned no git: the shim is not seeing the stage's calls")
			}
			second, c2 := runInventoryOnce(t, stage(memo), acq)
			if n := calls() - afterFirst; n != 0 {
				t.Errorf("the second run spawned git %d times, want 0", n)
			}
			if !reflect.DeepEqual(first, second) {
				t.Errorf("inventory differs between runs:\n first: %s\nsecond: %s", first, second)
			}
			if c1.Subject.ResolvedCommit == "" || c1.Subject.ResolvedCommit != c2.Subject.ResolvedCommit {
				t.Errorf("resolved commit = %q then %q, want the same non-empty sha", c1.Subject.ResolvedCommit, c2.Subject.ResolvedCommit)
			}

			base := calls()
			runInventoryOnce(t, stage(nil), acq)
			if calls()-base != afterFirst {
				t.Errorf("a run without a memo spawned git %d times, want the first run's %d", calls()-base, afterFirst)
			}
		})
	}
}

// TestInventoryMemo_GoWorkIsPartOfTheKey: runs that state a different go.work share a memo and still
// each get their own workspace, whichever asks first.
func TestInventoryMemo_GoWorkIsPartOfTheKey(t *testing.T) {
	tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{
		"a/go.mod": "module example.com/mono/a\n\ngo 1.22\n",
		"go.work":  "go 1.22\n\nuse ./a\n",
	}))
	gitTree(t, tree)
	withWork := GoWorkspace{File: filepath.Join(tree, "go.work")}
	cases := []struct {
		name         string
		firstDeclare string
		firstWant    GoWorkspace
		thenDeclare  string
		thenWant     GoWorkspace
	}{
		{"found, then off", "", withWork, "off", GoWorkspace{}},
		{"off, then found", "off", GoWorkspace{}, "", withWork},
		{"auto, then off", "auto", withWork, "off", GoWorkspace{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			memo := NewInventoryMemo()
			for _, step := range []struct {
				declared string
				want     GoWorkspace
			}{{tc.firstDeclare, tc.firstWant}, {tc.thenDeclare, tc.thenWant}} {
				stage := codebaseInventory{checkout: dirCheckout{dir: filepath.Join(tree, "a"), lang: "go"}, subjectGoWork: step.declared, memo: memo}
				store := artifact.NewMemStore()
				c := &assessment.Assessment{ID: "case-inventory-memo-gowork", Request: assessment.Request{
					Vulnerability: assessment.VulnRef{ID: "CVE-TEST-NO-SUCH-ADVISORY", Source: "corpus"},
					Codebase:      assessment.CodebaseRef{Repo: "example.com/mono", Revision: "v1"},
				}}
				if err := stage.Run(context.Background(), c, store); err != nil {
					t.Fatalf("declared %q: %v", step.declared, err)
				}
				got, err := InventoryGoWorkspace(store, c.ID)
				if err != nil || got != step.want {
					t.Fatalf("declared %q: workspace = %+v, %v; want %+v", step.declared, got, err, step.want)
				}
			}
		})
	}
}

// TestInventoryMemo_UnsettledAnswersAreNotKept: a read that failed, or ran under a cancelled
// context, is asked again by the next caller.
func TestInventoryMemo_UnsettledAnswersAreNotKept(t *testing.T) {
	t.Run("table", func(t *testing.T) {
		var tbl memoTable[string, int]
		runs := 0
		for _, settled := range []bool{false, false, true, true} {
			tbl.do("k", func() (int, bool) { runs++; return runs, settled })
		}
		if runs != 3 {
			t.Errorf("ran %d times, want 3 (two unsettled, one settled then served from cache)", runs)
		}
	})
	t.Run("head under a cancelled context", func(t *testing.T) {
		tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{"go.mod": "module example.com/target\n\ngo 1.22\n"}))
		gitTree(t, tree)
		want, err := checkout.ResolveHead(context.Background(), tree)
		if err != nil || want == "" {
			t.Fatalf("ResolveHead = %q, %v", want, err)
		}
		memo := NewInventoryMemo()
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if sha, err := memo.resolveHead(cancelled, tree); err == nil {
			t.Fatalf("resolveHead under a cancelled context = %q, nil; want an error", sha)
		}
		if sha, err := memo.resolveHead(context.Background(), tree); err != nil || sha != want {
			t.Errorf("resolveHead afterwards = %q, %v; want %q", sha, err, want)
		}
	})
	t.Run("root package under a cancelled context", func(t *testing.T) {
		tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{"go.mod": "module example.com/target\n\ngo 1.22\n"}))
		gitTree(t, tree, "v1.2.3")
		memo := NewInventoryMemo()
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		memo.readRootPackage(cancelled, tree, checkout.LangGo)
		if got, ok := memo.readRootPackage(context.Background(), tree, checkout.LangGo); !ok || got.Version != "v1.2.3" {
			t.Errorf("readRootPackage afterwards = %+v, %v; want version v1.2.3", got, ok)
		}
	})
}

// failFirstGit puts a git on PATH that fails the first invocation whose arguments contain match
// and runs the real one otherwise, standing in for a transient git failure.
func failFirstGit(t *testing.T, match string) {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	bin, flag := t.TempDir(), filepath.Join(t.TempDir(), "failed")
	script := "#!/bin/sh\ncase \"$*\" in *'" + match + "'*)\n  if [ ! -e '" + flag + "' ]; then : > '" + flag + "'; echo transient >&2; exit 1; fi;;\nesac\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestInventoryMemo_GitErrorIsNotKept: a git read that fails inside an answer affects only the
// caller that hit it; the next caller asks again and gets the real answer.
func TestInventoryMemo_GitErrorIsNotKept(t *testing.T) {
	t.Run("root package tag lookup", func(t *testing.T) {
		tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{"go.mod": "module example.com/target\n\ngo 1.22\n"}))
		gitTree(t, tree, "v1.2.3")
		failFirstGit(t, "--points-at")
		memo := NewInventoryMemo()
		if got, _ := memo.readRootPackage(context.Background(), tree, checkout.LangGo); got.Version != "" {
			t.Fatalf("first read with a failing git = %+v; want no version", got)
		}
		if got, ok := memo.readRootPackage(context.Background(), tree, checkout.LangGo); !ok || got.Version != "v1.2.3" {
			t.Errorf("second read = %+v, %v; want version v1.2.3 (the failure was cached)", got, ok)
		}
	})
	t.Run("bazel workspace above the module", func(t *testing.T) {
		tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{
			"MODULE.bazel": "module(name = \"top\")\n",
			"sub/go.mod":   "module example.com/target\n\ngo 1.22\n",
		}))
		gitTree(t, tree)
		failFirstGit(t, "--show-toplevel")
		memo := NewInventoryMemo()
		root := filepath.Join(tree, "sub")
		if memo.bazelWorkspaceAbove(root) {
			t.Fatal("first answer with a failing git = true; want false")
		}
		if !memo.bazelWorkspaceAbove(root) {
			t.Error("second answer = false; want true (the undetermined answer was cached)")
		}
	})
}

// TestInventoryMemo_RootPackageIsKeyedByLanguage: one directory read as two languages gives each
// its own root package.
func TestInventoryMemo_RootPackageIsKeyedByLanguage(t *testing.T) {
	tree, _ := filepath.EvalSymlinks(writeTree(t, map[string]string{
		"go.mod":       "module example.com/target\n\ngo 1.22\n",
		"package.json": "{\"name\":\"npm-target\",\"version\":\"1.0.0\"}\n",
	}))
	gitTree(t, tree, "v1.2.3")
	memo := NewInventoryMemo()
	ctx := context.Background()
	goPkg, goOK := memo.readRootPackage(ctx, tree, checkout.LangGo)
	jsPkg, jsOK := memo.readRootPackage(ctx, tree, checkout.LangJS)
	wantGo, _ := ReadRootPackage(ctx, tree, checkout.LangGo)
	wantJS, _ := ReadRootPackage(ctx, tree, checkout.LangJS)
	if !goOK || !jsOK || !reflect.DeepEqual(goPkg, wantGo) || !reflect.DeepEqual(jsPkg, wantJS) || reflect.DeepEqual(goPkg, jsPkg) {
		t.Errorf("go = %+v, js = %+v; want %+v and %+v", goPkg, jsPkg, wantGo, wantJS)
	}
}
