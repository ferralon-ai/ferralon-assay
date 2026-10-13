package buildtree

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestSkipped pins the skip rule other walkers copy: exactly node_modules and site-packages,
// case-sensitive, and nothing else.
func TestSkipped(t *testing.T) {
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
		if got := Skipped(name); got != want {
			t.Errorf("Skipped(%q) = %v, want %v", name, got, want)
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

// tree builds a build dir exercising every rule, plus a sibling directory outside it.
func tree(t *testing.T) (root, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "build")
	outside = filepath.Join(base, "outside")
	write(t, filepath.Join(outside, "dep.txt"), "x")
	write(t, filepath.Join(outside, "pkg", "dep.txt"), "x")
	write(t, filepath.Join(root, "dep.txt"), "x")
	write(t, filepath.Join(root, ".git", "dep.txt"), "x")
	write(t, filepath.Join(root, "build", "dep.txt"), "x")
	write(t, filepath.Join(root, "a", "dep.txt"), "x")
	write(t, filepath.Join(root, "node_modules", "lib", "dep.txt"), "x")
	write(t, filepath.Join(root, "py", "lib", "site-packages", "lib", "dep.txt"), "x")
	write(t, filepath.Join(root, "other.txt"), "x")
	symlink(t, filepath.Join(root, "a", "dep.txt"), filepath.Join(root, "in-file.txt"))
	symlink(t, "a", filepath.Join(root, "in-dir"))
	symlink(t, filepath.Join(outside, "dep.txt"), filepath.Join(root, "out-file.txt"))
	symlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "out-dir"))
	symlink(t, filepath.Join(root, "missing"), filepath.Join(root, "dangling.txt"))
	if err := os.MkdirAll(filepath.Join(root, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink(t, filepath.Join(outside, "pkg"), filepath.Join(root, "linked", "node_modules"))
	return root, outside
}

type seen struct {
	Symlink, Escapes, Skipped bool
}

// TestWalk_SkipRuleAndSymlinks: Walk enters everything but node_modules and site-packages
// (.git and build included), never follows a symlink, and flags the ones that leave root.
func TestWalk_SkipRuleAndSymlinks(t *testing.T) {
	root, _ := tree(t)
	got := map[string]seen{}
	if err := Walk(root, func(e Entry, err error) error {
		if err != nil {
			t.Fatalf("walk %s: %v", e.Path, err)
		}
		rel, _ := filepath.Rel(root, e.Path)
		got[filepath.ToSlash(rel)] = seen{e.Symlink, e.Escapes, e.Skipped}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]seen{
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

// TestCandidates: matches come back with FullyRead from the lane only for regular files; every
// symlink, escaping or not, and every unreadable entry is a candidate that is not fully read.
func TestCandidates(t *testing.T) {
	root, _ := tree(t)
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
	for _, c := range Candidates(root, match, fullyRead) {
		rel, _ := filepath.Rel(root, c.Path)
		got = append(got, row{filepath.ToSlash(rel), c.Why, c.FullyRead})
	}
	want := []row{
		{".git/dep.txt", "dep", true},
		{"a/dep.txt", "dep", true},
		{"build/dep.txt", "dep", true},
		{"dangling.txt", "symlink leaves the build dir", false},
		{"dep.txt", "dep", true},
		{"in-dir", "symlinked directory", false},
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
	if AllFullyRead(Candidates(root, match, fullyRead)) {
		t.Error("AllFullyRead = true with symlinked candidates")
	}
}

// TestCandidates_Unreadable: a directory the walk cannot list is a candidate that is not fully
// read, since what it holds cannot be classified.
func TestCandidates_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	write(t, filepath.Join(locked, "dep.txt"), "x")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	cs := Candidates(root, func(string, []byte) (string, bool) { return "", false }, func(string) bool { return true })
	if len(cs) != 1 || cs[0].Path != locked || cs[0].Why != "unreadable" || cs[0].FullyRead {
		t.Errorf("candidates = %+v, want one unreadable, not fully read, at %s", cs, locked)
	}
}

func TestCandidates_NoMatches(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "README.md"), "hello")
	cs := Candidates(root, func(string, []byte) (string, bool) { return "", false }, func(string) bool { return false })
	if len(cs) != 0 || !AllFullyRead(cs) {
		t.Errorf("candidates = %+v, want none (and AllFullyRead true)", cs)
	}
}

func TestHead(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, content string
		want          []byte
	}{
		{"text", "requests==2.0\n", []byte("requests==2.0\n")},
		{"empty", "", nil},
		{"binary", "PK\x03\x04\x00\x00", nil},
		{"long", strings.Repeat("a", HeadSize+10), bytes.Repeat([]byte("a"), HeadSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name)
			write(t, p, tc.content)
			got, err := Head(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("Head = %d bytes, want %d", len(got), len(tc.want))
			}
		})
	}
	if _, err := Head(filepath.Join(dir, "missing")); err == nil {
		t.Error("Head of a missing file returned no error")
	}
}
