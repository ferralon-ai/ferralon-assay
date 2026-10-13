package pythonanalysis

// These tests pin the build-tree walk copied into buildtree.go. They are the tests of
// internal/plugin/buildtree/buildtree_test.go at commit bc0233d, for buildtree.go blob
// 0219ca2d925dae344581fe87d7774381431c7e62, renamed to match the copy and otherwise unchanged.
// A change that makes one fail has drifted from the shared walker.

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestBuildTreeSkipped pins the skip rule other walkers copy: exactly node_modules and site-packages,
// case-sensitive, and nothing else.
func TestBuildTreeSkipped(t *testing.T) {
	for name, want := range map[string]bool{
		"node_modules":  true,
		"site-packages": true,
		"Node_Modules":  false,
		"node_modules2": false,
		"dist-packages": false,
		".git":          false,
		".venv":         false,
		"venv":          false,
		"vendor":        false,
		"build":         false,
		"dist":          false,
		"__pycache__":   false,
		".tox":          false,
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

// tree builds a build dir exercising every rule, plus a sibling directory outside it.
func buildTreeFixture(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "build")
	outside = filepath.Join(base, "outside")
	treeWrite(t, filepath.Join(outside, "dep.txt"), "x")
	treeWrite(t, filepath.Join(outside, "pkg", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, ".git", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "build", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "a", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "node_modules", "lib", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "py", "lib", "site-packages", "lib", "dep.txt"), "x")
	treeWrite(t, filepath.Join(root, "other.txt"), "x")
	treeSymlink(t, filepath.Join(root, "a", "dep.txt"), filepath.Join(root, "in-file.txt"))
	treeSymlink(t, "a", filepath.Join(root, "in-dir"))
	treeSymlink(t, filepath.Join(outside, "dep.txt"), filepath.Join(root, "out-file.txt"))
	treeSymlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "out-dir"))
	treeSymlink(t, filepath.Join(root, "missing"), filepath.Join(root, "dangling.txt"))
	if err := os.MkdirAll(filepath.Join(root, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	treeSymlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "linked", "node_modules"))
	return root, outside
}

type buildTreeSeen struct {
	Symlink, Escapes, Skipped bool
}

// TestWalkBuildTree_SkipRuleAndSymlinks: Walk enters everything but node_modules and site-packages
// (.git and build included), never follows a symlink, and flags the ones that leave root.
func TestWalkBuildTree_SkipRuleAndSymlinks(t *testing.T) {
	root, _ := buildTreeFixture(t)
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
		"other.txt":            {},
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

// TestBuildTreeCandidates: matches come back with FullyRead from the lane only for regular files; a
// symlinked file, every symlink that escapes root, and every unreadable entry is a candidate that
// is not fully read. in-dir links to a directory the walk reads at its real path, so it is not one.
func TestBuildTreeCandidates(t *testing.T) {
	root, _ := buildTreeFixture(t)
	match := func(path string, head []byte) (string, bool) {
		return "dep", filepath.Base(path) == "dep.txt" || strings.HasSuffix(path, "in-file.txt")
	}
	var asked []string
	fullyRead := func(path string) bool {
		rel, _ := filepath.Rel(root, path)
		asked = append(asked, filepath.ToSlash(rel))
		return true
	}
	type row struct {
		Path, Why string
		FullyRead bool
	}
	var got []row
	for _, c := range buildTreeCandidates(root, match, fullyRead) {
		rel, _ := filepath.Rel(root, c.Path)
		got = append(got, row{filepath.ToSlash(rel), c.Why, c.FullyRead})
	}
	want := []row{
		{".git/dep.txt", "dep", true},
		{"a/dep.txt", "dep", true},
		{"build/dep.txt", "dep", true},
		{"dangling.txt", "symlink leaves the build dir", false},
		{"dep.txt", "dep", true},
		{"in-file.txt", "dep", false},
		{"linked/node_modules", "symlink leaves the build dir", false},
		{"out-dir", "symlink leaves the build dir", false},
		{"out-file.txt", "symlink leaves the build dir", false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidates:\n%v\nwant:\n%v", got, want)
	}
	if wantAsked := []string{".git/dep.txt", "a/dep.txt", "build/dep.txt", "dep.txt"}; !reflect.DeepEqual(asked, wantAsked) {
		t.Errorf("fullyRead asked about %v, want only the regular-file matches %v", asked, wantAsked)
	}
	if buildTreeAllFullyRead(buildTreeCandidates(root, match, fullyRead)) {
		t.Error("buildTreeAllFullyRead = true with symlinked candidates")
	}
}

// TestBuildTreeCandidates_SymlinkedDirs: a symlinked directory inside root is read in full, through its
// target, only when the walk enters that target at its real path. A target under a Skipped
// directory or one the walk cannot list, and a link cycle, stay candidates that are not fully read.
func TestBuildTreeCandidates_SymlinkedDirs(t *testing.T) {
	type row struct {
		Path, Why string
		FullyRead bool
	}
	tests := []struct {
		name  string
		links map[string]string // link → target, relative to the link's directory
		want  []row
	}{
		{"lib64 to lib", map[string]string{".venv/lib64": "lib"}, nil},
		{"link to root", map[string]string{"self": "."}, nil},
		{"link through a linked directory", map[string]string{"a": ".venv", "b": "a/lib"}, nil},
		{"link into node_modules", map[string]string{"vendor": "node_modules/lib"},
			[]row{{"vendor", "symlinked directory the walk does not read", false}}},
		{"link to node_modules", map[string]string{"deps": "node_modules"},
			[]row{{"deps", "symlinked directory the walk does not read", false}}},
		{"link into site-packages", map[string]string{"pkgs": ".venv/lib/site-packages"},
			[]row{{"pkgs", "symlinked directory the walk does not read", false}}},
		{"symlink cycle", map[string]string{"loop1": "loop2", "loop2": "loop1"},
			[]row{{"loop1", "symlink leaves the build dir", false}, {"loop2", "symlink leaves the build dir", false}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			treeWrite(t, filepath.Join(root, ".venv", "lib", "dep.txt"), "x")
			treeWrite(t, filepath.Join(root, ".venv", "lib", "site-packages", "x", "dep.txt"), "x")
			treeWrite(t, filepath.Join(root, "node_modules", "lib", "dep.txt"), "x")
			for link, target := range tt.links {
				treeSymlink(t, target, filepath.Join(root, link))
			}
			never := func(string, []byte) (string, bool) { return "", false }
			var got []row
			for _, c := range buildTreeCandidates(root, never, func(string) bool { return true }) {
				rel, _ := filepath.Rel(root, c.Path)
				got = append(got, row{filepath.ToSlash(rel), c.Why, c.FullyRead})
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("candidates:\n%v\nwant:\n%v", got, tt.want)
			}
		})
	}
}

// TestBuildTreeCandidates_LinkToUnreadable: a symlinked directory whose target the walk cannot list is
// not read through its target.
func TestBuildTreeCandidates_LinkToUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	treeWrite(t, filepath.Join(locked, "dep.txt"), "x")
	treeSymlink(t, "locked", filepath.Join(root, "via"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	var got []string
	for _, c := range buildTreeCandidates(root, func(string, []byte) (string, bool) { return "", false }, func(string) bool { return true }) {
		if c.FullyRead {
			t.Errorf("%s fully read", c.Path)
		}
		got = append(got, filepath.Base(c.Path))
	}
	if want := []string{"locked", "via"}; !reflect.DeepEqual(got, want) {
		t.Errorf("candidates = %v, want %v", got, want)
	}
}

// TestBuildTreeCandidates_Unreadable: a directory the walk cannot list is a candidate that is not fully
// read, since what it holds cannot be classified.
func TestBuildTreeCandidates_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	treeWrite(t, filepath.Join(locked, "dep.txt"), "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	cs := buildTreeCandidates(root, func(string, []byte) (string, bool) { return "", false }, func(string) bool { return true })
	if len(cs) != 1 || cs[0].Path != locked || cs[0].Why != "unreadable" || cs[0].FullyRead {
		t.Errorf("candidates = %+v, want one unreadable, not fully read, at %s", cs, locked)
	}
}

func TestBuildTreeCandidates_NoMatches(t *testing.T) {
	root := t.TempDir()
	treeWrite(t, filepath.Join(root, "README.md"), "hello")
	cs := buildTreeCandidates(root, func(string, []byte) (string, bool) { return "", false }, func(string) bool { return false })
	if len(cs) != 0 || !buildTreeAllFullyRead(cs) {
		t.Errorf("candidates = %+v, want none (and buildTreeAllFullyRead true)", cs)
	}
}

func TestBuildTreeHead(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, content string
		want          []byte
	}{
		{"text", "requests==2.0\n", []byte("requests==2.0\n")},
		{"empty", "", nil},
		{"binary", "PK\x03\x04\x00\x00", nil},
		{"long", strings.Repeat("a", buildTreeHeadSize+10), bytes.Repeat([]byte("a"), buildTreeHeadSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name)
			treeWrite(t, p, tc.content)
			got, err := buildTreeHead(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("Head = %d bytes, want %d", len(got), len(tc.want))
			}
		})
	}
	if _, err := buildTreeHead(filepath.Join(dir, "missing")); err == nil {
		t.Error("Head of a missing file returned no error")
	}
}
