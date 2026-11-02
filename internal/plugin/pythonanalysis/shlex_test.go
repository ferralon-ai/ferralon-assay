package pythonanalysis

import (
	"slices"
	"testing"
)

// TestShellSplit: each row is what Python's shlex.split returns for the line, or false where
// it raises.
func TestShellSplit(t *testing.T) {
	for _, tt := range []struct {
		line string
		want []string
		ok   bool
	}{
		{`-r a.txt`, []string{`-r`, `a.txt`}, true},
		{`-r  "a  b.txt"`, []string{`-r`, `a  b.txt`}, true},
		{`-c c\".txt`, []string{`-c`, `c".txt`}, true},
		{`-c "sub\c.txt"`, []string{`-c`, `sub\c.txt`}, true},
		{`-c "x\\y"`, []string{`-c`, `x\y`}, true},
		{`-c 'a\b'`, []string{`-c`, `a\b`}, true},
		{`-c a"b c"d`, []string{`-c`, `ab cd`}, true},
		{`-c ""`, []string{`-c`, ``}, true},
		{`-c ''`, []string{`-c`, ``}, true},
		{`-c "c.txt`, nil, false},
		{`-c 'c.txt`, nil, false},
		{`-c c.txt\`, nil, false},
		{`-c "c.txt\"`, nil, false},
		{"-c\tc.txt", []string{`-c`, `c.txt`}, true},
		{"-c a\u00a0b", []string{`-c`, "a\u00a0b"}, true},
		{`-r dev.txt;python_version<"3"`, []string{`-r`, `dev.txt;python_version<3`}, true},
		{`-c \ c.txt`, []string{`-c`, ` c.txt`}, true},
		{`-c a#b`, []string{`-c`, `a#b`}, true},
		{`-c "a\$b"`, []string{`-c`, `a\$b`}, true},
	} {
		got, ok := shellSplit(tt.line)
		if ok != tt.ok || !slices.Equal(got, tt.want) {
			t.Errorf("shellSplit(%q) = %q, %v, want %q, %v", tt.line, got, ok, tt.want, tt.ok)
		}
	}
}
