package buildtree

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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

// TestCandidates: matches come back with FullyRead from the lane only for regular files; a
// symlinked file, every symlink that escapes root, and every unreadable entry is a candidate that
// is not fully read. in-dir links to a directory the walk reads at its real path, so it is not one.
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

// TestCandidates_SymlinkedDirs: a symlinked directory inside root is read in full, through its
// target, only when the walk enters that target at its real path. A target under a Skipped
// directory or one the walk cannot list, and a link cycle, stay candidates that are not fully read.
func TestCandidates_SymlinkedDirs(t *testing.T) {
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
			write(t, filepath.Join(root, ".venv", "lib", "dep.txt"), "x")
			write(t, filepath.Join(root, ".venv", "lib", "site-packages", "x", "dep.txt"), "x")
			write(t, filepath.Join(root, "node_modules", "lib", "dep.txt"), "x")
			for link, target := range tt.links {
				symlink(t, target, filepath.Join(root, link))
			}
			never := func(string, []byte) (string, bool) { return "", false }
			var got []row
			for _, c := range Candidates(root, never, func(string) bool { return true }) {
				rel, _ := filepath.Rel(root, c.Path)
				got = append(got, row{filepath.ToSlash(rel), c.Why, c.FullyRead})
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("candidates:\n%v\nwant:\n%v", got, tt.want)
			}
		})
	}
}

// TestCandidates_LinkToUnreadable: a symlinked directory whose target the walk cannot list is
// not read through its target.
func TestCandidates_LinkToUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	write(t, filepath.Join(locked, "dep.txt"), "x")
	symlink(t, "locked", filepath.Join(root, "via"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	var got []string
	for _, c := range Candidates(root, func(string, []byte) (string, bool) { return "", false }, func(string) bool { return true }) {
		if c.FullyRead {
			t.Errorf("%s fully read", c.Path)
		}
		got = append(got, filepath.Base(c.Path))
	}
	if want := []string{"locked", "via"}; !reflect.DeepEqual(got, want) {
		t.Errorf("candidates = %v, want %v", got, want)
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

// TestNULHeadMatch: a nil head is re-read and judged with its NULs removed and with them made
// newlines; a re-read that fails is a match, since the file went unread.
func TestNULHeadMatch(t *testing.T) {
	dir := t.TempDir()
	equals := func(want string) func(string, []byte) (string, bool) {
		return func(_ string, head []byte) (string, bool) { return "rule", string(head) == want }
	}
	cases := []struct {
		name, content string
		missing       bool
		rule          func(string, []byte) (string, bool)
		wantWhy       string
		wantOK        bool
	}{
		{name: "NUL removed", content: "a\x00b", rule: equals("ab"), wantWhy: "rule (NUL in head)", wantOK: true},
		{name: "NUL made a newline", content: "a\x00b", rule: equals("a\nb"), wantWhy: "rule (NUL in head)", wantOK: true},
		{name: "no match", content: "a\x00b", rule: equals("c")},
		{name: "empty", content: "", rule: equals("")},
		{name: "only NULs, removed", content: "\x00\x00", rule: equals("")},
		{name: "unreadable", missing: true, rule: equals("ab"), wantWhy: "unreadable", wantOK: true},
		{name: "UTF-16LE BOM decoded", content: "\xff\xfea\x00\n\x00b\x00", rule: equals("a\nb"), wantWhy: "rule (NUL in head)", wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			if !tc.missing {
				write(t, p, tc.content)
			}
			why, ok := NULHeadMatch(p, tc.rule)
			if why != tc.wantWhy || ok != tc.wantOK {
				t.Errorf("NULHeadMatch = %q, %v; want %q, %v", why, ok, tc.wantWhy, tc.wantOK)
			}
		})
	}
}

func TestBOMDecode(t *testing.T) {
	cases := []struct {
		name, head, want string
		wantOK           bool
	}{
		{"UTF-8", "\xef\xbb\xbfab", "ab", true},
		{"UTF-16LE", "\xff\xfea\x00\xe9\x00", "a\u00e9", true},
		{"UTF-16BE", "\xfe\xff\x00a\x00\xe9", "a\u00e9", true},
		{"UTF-16LE surrogate pair", "\xff\xfe\x3d\xd8\x00\xde", "\U0001F600", true},
		{"UTF-16LE cut mid code unit", "\xff\xfea\x00b", "a", true},
		{"UTF-32LE", "\xff\xfe\x00\x00a\x00\x00\x00", "a", true},
		{"UTF-32BE", "\x00\x00\xfe\xff\x00\x00\x00a", "a", true},
		{"no BOM", "ab", "", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := BOMDecode([]byte(tc.head))
			if string(got) != tc.want || ok != tc.wantOK {
				t.Errorf("BOMDecode(%q) = %q, %v; want %q, %v", tc.head, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// A head the match rejects is judged again without its byte-order mark, and only then: a mark
// adds candidates, never removes one, and a BOM-free head is matched once.
func TestCandidates_BOMHead(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "bom"), "\xef\xbb\xbfwant")
	write(t, filepath.Join(root, "bom-raw"), "\xef\xbb\xbfraw")
	write(t, filepath.Join(root, "plain"), "want")
	write(t, filepath.Join(root, "other"), "\xef\xbb\xbfother")
	calls := map[string]int{}
	match := func(path string, head []byte) (string, bool) {
		calls[filepath.Base(path)]++
		switch string(head) {
		case "want":
			return "decoded", true
		case "\xef\xbb\xbfraw":
			return "raw", true
		}
		return "", false
	}
	var got []string
	for _, c := range Candidates(root, match, func(string) bool { return true }) {
		got = append(got, filepath.Base(c.Path)+":"+c.Why)
	}
	want := []string{"bom:decoded", "bom-raw:raw", "plain:decoded"}
	if !slices.Equal(got, want) {
		t.Errorf("candidates = %v, want %v", got, want)
	}
	if want := map[string]int{"bom": 2, "bom-raw": 1, "plain": 1, "other": 2}; !maps.Equal(calls, want) {
		t.Errorf("match calls = %v, want %v", calls, want)
	}
}
