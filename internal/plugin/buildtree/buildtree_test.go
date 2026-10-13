package buildtree

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
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
	endsWith := func(want string) func(string, []byte) (string, bool) {
		return func(_ string, head []byte) (string, bool) { return "rule", bytes.HasSuffix(head, []byte(want)) }
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
		{name: "UTF-16LE BOM, canonical NUL removed", content: "\xff\xfea\x00\x00\x00b\x00", rule: equals("ab"), wantWhy: "rule (NUL in head)", wantOK: true},
		{name: "UTF-16LE BOM, canonical NUL made a newline", content: "\xff\xfea\x00\x00\x00b\x00", rule: equals("a\nb"), wantWhy: "rule (NUL in head)", wantOK: true},
		{name: "UTF-16LE BOM, ASCII past the HeadSize bytes, NUL code point", content: utf16LE(strings.Repeat("a", 40000) + "\x00b"), rule: endsWith("ab"), wantWhy: "rule (NUL in head)", wantOK: true},
		{name: "undecodable after its mark, NUL removed", content: "\xfe\xff\xdc\x00\x00pyjwt", rule: equals("\xfe\xff\xdcpyjwt"), wantWhy: "rule (NUL in head)", wantOK: true},
		{name: "undecodable after its mark, NUL made a newline", content: "\xfe\xff\xdc\x00\x00pyjwt", rule: equals("\xfe\xff\xdc\n\npyjwt"), wantWhy: "rule (NUL in head)", wantOK: true},
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

// rawHead gives a file that starts with a byte-order mark its canonical content: the text in
// UTF-8 without the mark (and one more U+FEFF), or its bytes when the text does not decode.
func TestRawHead_Canonical(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, content, want string
	}{
		{"UTF-8", "\xef\xbb\xbfab", "ab"},
		{"UTF-16LE", "\xff\xfea\x00\xe9\x00", "a\u00e9"},
		{"UTF-16BE", "\xfe\xff\x00a\x00\xe9", "a\u00e9"},
		{"UTF-16LE surrogate pair", "\xff\xfe\x3d\xd8\x00\xde", "\U0001F600"},
		{"UTF-16LE odd trailing byte", "\xff\xfea\x00b", "a"},
		{"UTF-16LE high surrogate at the end", "\xff\xfea\x00\x3d\xd8", "a"},
		{"UTF-32LE", "\xff\xfe\x00\x00a\x00\x00\x00", "a"},
		{"UTF-32BE", "\x00\x00\xfe\xff\x00\x00\x00a", "a"},
		{"UTF-16LE double BOM", "\xff\xfe\xff\xfea\x00", "a"},
		{"UTF-16BE double BOM", "\xfe\xff\xfe\xff\x00a", "a"},
		{"UTF-8 double BOM", "\xef\xbb\xbf\xef\xbb\xbfa", "a"},
		{"UTF-32LE double BOM", "\xff\xfe\x00\x00\xff\xfe\x00\x00a\x00\x00\x00", "a"},
		{"UTF-16LE triple BOM keeps the third", "\xff\xfe\xff\xfe\xff\xfea\x00", "\ufeffa"},
		{"UTF-16LE NUL code point", "\xff\xfea\x00\x00\x00b\x00", "a\x00b"},
		{"UTF-16LE unpaired low surrogate", "\xff\xfe\x00\xdca\x00", "\xff\xfe\x00\xdca\x00"},
		{"UTF-16LE high surrogate without its pair", "\xff\xfe\x3d\xd8a\x00", "\xff\xfe\x3d\xd8a\x00"},
		{"UTF-32LE past U+10FFFF", "\xff\xfe\x00\x00\x00\x00\x11\x00", "\xff\xfe\x00\x00\x00\x00\x11\x00"},
		{"no BOM", "ab", "ab"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			write(t, p, tc.content)
			got, err := rawHead(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("rawHead(%q) = %q, want %q", tc.content, got, tc.want)
			}
		})
	}
}

// A doubled mark spends one more code unit (or three more bytes) before the text: the head still
// holds HeadSize canonical bytes, the twin's.
func TestRawHead_DoubledMarkFillsTheHead(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("a", HeadSize+10)
	for _, enc := range bomForms {
		t.Run(enc, func(t *testing.T) {
			p := filepath.Join(dir, enc)
			marked := encodeText(enc, body)
			mark := map[string]int{"UTF-8": 3, "UTF-16LE": 2, "UTF-16BE": 2, "UTF-32LE": 4, "UTF-32BE": 4}[enc]
			write(t, p, marked[:mark]+marked)
			got, err := rawHead(p)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != body[:HeadSize] {
				t.Errorf("rawHead = %d bytes, want HeadSize bytes of a", len(got))
			}
		})
	}
}

// A marked file is matched once, on its canonical head, and never on its raw bytes; a file whose
// text does not decode after its mark is matched on its bytes.
func TestCandidates_BOMHead(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "bom"), "\xef\xbb\xbfwant")
	write(t, filepath.Join(root, "bom-raw"), "\xef\xbb\xbfraw")
	write(t, filepath.Join(root, "plain"), "want")
	write(t, filepath.Join(root, "undecodable"), "\xfe\xff\xdcAwant")
	calls := map[string]int{}
	match := func(path string, head []byte) (string, bool) {
		calls[filepath.Base(path)]++
		switch string(head) {
		case "want":
			return "canonical", true
		case "\xef\xbb\xbfraw":
			return "raw", true
		case "\xfe\xff\xdcAwant":
			return "bytes", true
		}
		return "", false
	}
	var got []string
	for _, c := range Candidates(root, match, func(string) bool { return true }) {
		got = append(got, filepath.Base(c.Path)+":"+c.Why)
	}
	want := []string{"bom:canonical", "plain:canonical", "undecodable:bytes"}
	if !slices.Equal(got, want) {
		t.Errorf("candidates = %v, want %v", got, want)
	}
	if want := map[string]int{"bom": 1, "bom-raw": 1, "plain": 1, "undecodable": 1}; !maps.Equal(calls, want) {
		t.Errorf("match calls = %v, want %v", calls, want)
	}
}

// utf16LE encodes ASCII s as UTF-16LE behind its byte-order mark.
func utf16LE(s string) string {
	b := []byte("\xff\xfe")
	for _, c := range []byte(s) {
		b = append(b, c, 0)
	}
	return string(b)
}

// encodeBOM encodes ASCII s behind the named byte-order mark.
func encodeBOM(enc, s string) string {
	var b []byte
	switch enc {
	case "UTF-8":
		return "\xef\xbb\xbf" + s
	case "UTF-16LE":
		return utf16LE(s)
	case "UTF-16BE":
		b = []byte("\xfe\xff")
		for _, c := range []byte(s) {
			b = append(b, 0, c)
		}
	case "UTF-32LE":
		b = []byte("\xff\xfe\x00\x00")
		for _, c := range []byte(s) {
			b = append(b, c, 0, 0, 0)
		}
	case "UTF-32BE":
		b = []byte("\x00\x00\xfe\xff")
		for _, c := range []byte(s) {
			b = append(b, 0, 0, 0, c)
		}
	}
	return string(b)
}

// bomForms are the five byte-order marks rawHead decodes.
var bomForms = []string{"UTF-8", "UTF-16LE", "UTF-16BE", "UTF-32LE", "UTF-32BE"}

// encodeText encodes UTF-8 text s behind the named byte-order mark.
func encodeText(enc, s string) string {
	if enc == "UTF-8" {
		return "\xef\xbb\xbf" + s
	}
	var b []byte
	put := func(order binary.AppendByteOrder, unit int, v uint32) {
		if unit == 2 {
			b = order.AppendUint16(b, uint16(v))
		} else {
			b = order.AppendUint32(b, v)
		}
	}
	order, unit := binary.AppendByteOrder(binary.LittleEndian), 2
	switch enc {
	case "UTF-16BE":
		order = binary.BigEndian
	case "UTF-32LE":
		unit = 4
	case "UTF-32BE":
		order, unit = binary.BigEndian, 4
	}
	put(order, unit, 0xFEFF)
	for _, r := range s {
		if unit == 4 {
			put(order, unit, uint32(r))
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			put(order, unit, uint32(u))
		}
	}
	return string(b)
}

// TestBOMTwins pins that a byte-order mark never changes a verdict: a file in each of the five
// marked encodings gets the same Head, and the same Candidates verdict and FullyRead, as its
// twin, the same text in UTF-8 without the mark. The bodies straddle HeadSize in UTF-8 bytes,
// cross it in one encoding and not the other (CJK text is shorter raw in UTF-16 than in UTF-8,
// ASCII longer), and carry a NUL, so every rule that reads the head, its length or its NULs
// judges the marked file over exactly the twin's bytes.
//
// The scope is what a rule reads from the head: its bytes, its length and its NULs. A lane's
// fullyRead that parses a name-matched manifest in full reads the file itself, and the lane tests
// pin that a marked one withholds.
func TestBOMTwins(t *testing.T) {
	const req = "pyjwt==2.0\n"
	comments := func(line string, n int) string { // n UTF-8 bytes of comment lines, then ASCII fill
		var b strings.Builder
		for b.Len()+len(line) <= n {
			b.WriteString(line)
		}
		b.WriteString(strings.Repeat("#", n-b.Len()))
		return b.String()
	}
	eLine := "# r\u00e9sum\u00e9 caf\u00e9 \u00e9\u00e9\u00e9\r\n"
	cjkLine := "# \u4e2d\u6587\u6ce8\u91ca\u4e2d\u6587\u6ce8\u91ca\n"
	bodies := []struct{ name, body string }{
		{"empty", ""},
		{"ASCII", "# deps\n" + req},
		{"e-heavy", comments(eLine, 20000) + "\n" + req},
		{"requirement ends at the cut", comments(eLine, HeadSize-len(req)-1) + "\n" + req},
		{"requirement straddles the cut", comments(eLine, HeadSize-5) + "\n" + req},
		{"requirement starts at the cut", comments(eLine, HeadSize-1) + "\n" + req},
		{"requirement past the cut", comments(eLine, HeadSize+100) + "\n" + req},
		{"NUL before the requirement", "# a\x00b\n" + req},
		{"NUL past the cut", comments(eLine, HeadSize+10) + "\x00\n" + req},
		{"CJK, UTF-8 past the cut, UTF-16 within it", comments(cjkLine, 72000) + "\n" + req},
		{"ASCII, UTF-8 within the cut, UTF-16 and UTF-32 past it", comments("# some words\n", 40000) + "\n" + req},
		{"ASCII filling the cut exactly", comments("# x\n", HeadSize)},
		{"astral character straddling the cut", comments("# x\n", HeadSize-1) + "\U0001F600\n" + req},
	}
	content := func(_ string, head []byte) (string, bool) {
		for _, l := range strings.Split(string(head), "\n") {
			if strings.HasPrefix(l, "pyjwt") {
				return "requirement", true
			}
		}
		return "", false
	}
	// Two rules, judged apart so neither masks the other: one reads the head's lines (through
	// NULHeadMatch when the head is nil), one only its length, as installRewriteConfig does.
	byLines := func(path string, head []byte) (string, bool) {
		if head == nil {
			return NULHeadMatch(path, content)
		}
		return content(path, head)
	}
	byLength := func(_ string, head []byte) (string, bool) {
		return "fills the head", len(head) == HeadSize // the file may go on past it
	}
	fullyRead := func(string) bool { return true }
	verdict := func(dir string) string {
		var got []string
		for _, match := range []func(string, []byte) (string, bool){byLines, byLength} {
			var cs []string
			for _, c := range Candidates(dir, match, fullyRead) {
				cs = append(cs, fmt.Sprintf("%s:%v", c.Why, c.FullyRead))
			}
			got = append(got, "["+strings.Join(cs, ",")+"]")
		}
		return strings.Join(got, " ")
	}
	for _, b := range bodies {
		twinDir := t.TempDir()
		twin := filepath.Join(twinDir, "deps")
		write(t, twin, b.body)
		wantHead, err := Head(twin)
		if err != nil {
			t.Fatal(err)
		}
		wantVerdict := verdict(twinDir)
		for _, enc := range bomForms {
			t.Run(b.name+"/"+enc, func(t *testing.T) {
				dir := t.TempDir()
				p := filepath.Join(dir, "deps")
				write(t, p, encodeText(enc, b.body))
				head, err := Head(p)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(head, wantHead) || (head == nil) != (wantHead == nil) {
					t.Errorf("Head = %d bytes (nil %v), want the twin's %d bytes (nil %v)", len(head), head == nil, len(wantHead), wantHead == nil)
				}
				if got := verdict(dir); got != wantVerdict {
					t.Errorf("verdict = %q, want the twin's %q", got, wantVerdict)
				}
			})
		}
	}
}
