package gomodtree

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeTree writes files (relative path -> contents) into a fresh temp dir and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// unbounded is a module the walk names by directory alone.
func unbounded(dir, path string) Module { return Module{Dir: dir, Path: path} }

// TestNested: every go.mod below the root that the build root's module graph does not include
// (through its go.work, or a required filesystem replace) is named, relative to the root and sorted,
// at any depth; the go command's own skips (testdata, vendor, dot and underscore directories) are
// not module source. A module whose go.mod declares go 1.17 or later is bounded by what it requires.
func TestNested(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		buildDir string // relative to the root; "" is the root
		want     []Module
	}{
		{"root only", map[string]string{"go.mod": "module r\n"}, "", nil},
		{"stub root above nested modules", map[string]string{
			"go.mod":                      "module r\n",
			"receiver/a/go.mod":           "module r/receiver/a\n",
			"exporter/b/go.mod":           "module r/exporter/b\n",
			"internal/x/y/z/deep/go.mod":  "module r/deep\n",
			"receiver/a/internal/main.go": "package internal\n",
		}, "", []Module{unbounded("exporter/b", "r/exporter/b"), unbounded("internal/x/y/z/deep", "r/deep"), unbounded("receiver/a", "r/receiver/a")}},
		{"go 1.17 or later is bounded by its requires and versioned replaces", map[string]string{
			"go.mod": "module r\n",
			"a/go.mod": "module r/a\n\ngo 1.21\n\nrequire (\n\texample.test/z v1.0.0\n\texample.test/y v1.0.0 // indirect\n)\n\n" +
				"replace example.test/z => example.test/fork v1.1.0\n",
			"b/go.mod": "module r/b\n\ngo 1.17\n",
		}, "", []Module{
			{Dir: "a", Path: "r/a", Bounded: true, Requires: []string{"example.test/fork", "example.test/y", "example.test/z"}},
			{Dir: "b", Path: "r/b", Bounded: true},
		}},
		{"below go 1.17, or unparseable, is unbounded", map[string]string{
			"go.mod":   "module r\n",
			"a/go.mod": "module r/a\n\ngo 1.16\n\nrequire example.test/z v1.0.0\n",
			"b/go.mod": "not a go.mod\n",
		}, "", []Module{unbounded("a", "r/a"), unbounded("b", "")}},
		{"go command skips", map[string]string{
			"go.mod":                "module r\n",
			"testdata/m/go.mod":     "module t\n",
			"vendor/v/go.mod":       "module v\n",
			".github/m/go.mod":      "module g\n",
			"_examples/go.mod":      "module e\n",
			"pkg/testdata/go.mod":   "module t2\n",
			"tools/go.mod":          "module tools\n",
			"tools/vendor/w/go.mod": "module w\n",
		}, "", []Module{unbounded("tools", "tools")}},
		{"go.work members are resolved with the root", map[string]string{
			"go.mod":   "module r\n",
			"go.work":  "go 1.21\n\nuse (\n\t.\n\t./a\n)\n",
			"a/go.mod": "module a\n",
			"b/go.mod": "module b\n",
		}, "", []Module{unbounded("b", "b")}},
		{"a required filesystem replace is resolved with the root", map[string]string{
			"go.mod":   "module r\n\nrequire example.test/a v0.0.0\n\nreplace example.test/a => ./a\n",
			"a/go.mod": "module example.test/a\n",
			"b/go.mod": "module example.test/b\n",
		}, "", []Module{unbounded("b", "example.test/b")}},
		{"a replace nothing requires is not", map[string]string{
			"go.mod": "module r\n\nreplace example.test/a => ./a\n", "a/go.mod": "module example.test/a\n",
		}, "", []Module{unbounded("a", "example.test/a")}},
		{"unparseable go.work lists nothing", map[string]string{
			"go.mod": "module r\n", "go.work": "not a go.work\n", "a/go.mod": "module a\n",
		}, "", []Module{unbounded("a", "a")}},
		{"a directory named go.mod is not a module", map[string]string{
			"go.mod": "module r\n", "a/go.mod/keep": "x\n",
		}, "", nil},
		{"sibling top-level modules with no root go.mod", map[string]string{
			"api/go.mod": "module api\n", "worker/go.mod": "module worker\n", "api/inner/go.mod": "module inner\n",
		}, "api", []Module{unbounded("api/inner", "inner"), unbounded("worker", "worker")}},
		{"a build root under a skipped name is still walked", map[string]string{
			"_build/go.mod": "module b\n", "_build/sub/go.mod": "module s\n", "_other/go.mod": "module o\n",
		}, "_build", []Module{unbounded("_build/sub", "s")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, tc.files)
			got := Nested(root, filepath.Join(root, tc.buildDir))
			if !got.Complete || !reflect.DeepEqual(got.Modules, tc.want) {
				t.Fatalf("Nested = %+v, want complete %+v", got, tc.want)
			}
		})
	}
}

// TestNested_UnreadableSubtreeIsIncomplete: a directory the walk cannot read may hold a module, so
// the walk reports itself incomplete instead of naming nothing, and still names what it could read.
func TestNested_UnreadableSubtreeIsIncomplete(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module r\n", "a/go.mod": "module a\n", "locked/m/go.mod": "module m\n"})
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("directory permissions are not enforced for this user")
	}
	got := Nested(root, root)
	if got.Complete || !reflect.DeepEqual(got.Modules, []Module{unbounded("a", "a")}) {
		t.Fatalf("Nested = %+v, want incomplete with only a", got)
	}
}

// TestTreeMayRequire: a tree may require a module unless the walk was complete and every module it
// found is bounded and names neither the module nor a path it lies under.
func TestTreeMayRequire(t *testing.T) {
	crypto := Module{Dir: "a", Path: "r/a", Bounded: true, Requires: []string{"golang.org/x/crypto"}}
	cases := []struct {
		name   string
		tree   Tree
		module string
		want   bool
	}{
		{"no modules", Tree{Complete: true}, "golang.org/x/crypto", false},
		{"required", Tree{Complete: true, Modules: []Module{crypto}}, "golang.org/x/crypto", true},
		{"a package path under a required module", Tree{Complete: true, Modules: []Module{crypto}}, "golang.org/x/crypto/ssh", true},
		{"required by none", Tree{Complete: true, Modules: []Module{crypto}}, "golang.org/x/text", false},
		{"a module path that merely shares a prefix", Tree{Complete: true, Modules: []Module{crypto}}, "golang.org/x/cryptography", false},
		{"the nested module itself", Tree{Complete: true, Modules: []Module{crypto}}, "r/a", true},
		{"unbounded", Tree{Complete: true, Modules: []Module{crypto, unbounded("b", "r/b")}}, "golang.org/x/text", true},
		{"incomplete walk", Tree{Modules: []Module{crypto}}, "golang.org/x/text", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tree.MayRequire(tc.module); got != tc.want {
				t.Fatalf("MayRequire(%q) = %v, want %v", tc.module, got, tc.want)
			}
		})
	}
}
