package jsanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestBuildTreeSkipped pins the shared skip rule: exactly node_modules and site-packages,
// case-sensitive, and nothing else. This walker, its skip rule, and the symlinked-directory and
// symlink-to-a-non-regular-file rules resolutionOverridden applies are copied from
// internal/plugin/buildtree at bc0233d (blob 0219ca2d925dae344581fe87d7774381431c7e62); a
// change to either must be made to both.
func TestBuildTreeSkipped(t *testing.T) {
	for name, want := range map[string]bool{
		"node_modules":  true,
		"site-packages": true,
		"Node_Modules":  false,
		"node_modules2": false,
		"dist-packages": false,
		".git":          false,
		".circleci":     false,
		".venv":         false,
		"vendor":        false,
		"build":         false,
		"dist":          false,
		"":              false,
	} {
		if got := buildTreeSkipped(name); got != want {
			t.Errorf("buildTreeSkipped(%q) = %v, want %v", name, got, want)
		}
	}
}

func treeWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func treeSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

type buildTreeSeen struct {
	Symlink, Escapes, Skipped bool
}

// TestWalkBuildTree_SkipRuleAndSymlinks: the walk enters everything but node_modules and
// site-packages (.git and build included), visits those without entering them, never follows
// a symlink, and flags the ones that leave root or do not resolve.
func TestWalkBuildTree_SkipRuleAndSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "build")
	outside := filepath.Join(base, "outside")
	treeWrite(t, filepath.Join(outside, "dep.txt"), "x")
	treeWrite(t, filepath.Join(outside, "pkg", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, ".git", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "build", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "a", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "node_modules", "lib", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "py", "lib", "site-packages", "lib", "dep.txt"), "x")
	treeSymlink(t, filepath.Join(root, "a", "dep.txt"), filepath.Join(root, "in-file.txt"))
	treeSymlink(t, "a", filepath.Join(root, "in-dir"))
	treeSymlink(t, filepath.Join(outside, "dep.txt"), filepath.Join(root, "out-file.txt"))
	treeSymlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "out-dir"))
	treeSymlink(t, filepath.Join(root, "missing"), filepath.Join(root, "dangling.txt"))
	if err := os.MkdirAll(filepath.Join(root, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	treeSymlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "linked", "node_modules"))

	got := map[string]buildTreeSeen{}
	if err := walkBuildTree(root, func(e buildTreeEntry, err error) error {
		if err != nil {
			t.Fatalf("walk %s: %v", e.Path, err)
		}
		rel, _ := filepath.Rel(root, e.Path)
		got[filepath.ToSlash(rel)] = buildTreeSeen{e.Symlink, e.Escapes, e.Skipped}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]buildTreeSeen{
		".":                    {},
		".git":                 {},
		".git/dep.txt":         {},
		"a":                    {},
		"a/dep.txt":            {},
		"build":                {},
		"build/dep.txt":        {},
		"dangling.txt":         {Symlink: true, Escapes: true},
		"dep.txt":              {},
		"in-dir":               {Symlink: true},
		"in-file.txt":          {Symlink: true},
		"linked":               {},
		"linked/node_modules":  {Symlink: true, Escapes: true, Skipped: true},
		"node_modules":         {Skipped: true},
		"out-dir":              {Symlink: true, Escapes: true},
		"out-file.txt":         {Symlink: true, Escapes: true},
		"py":                   {},
		"py/lib":               {},
		"py/lib/site-packages": {Skipped: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("visited:\n%v\nwant:\n%v", got, want)
	}
}
