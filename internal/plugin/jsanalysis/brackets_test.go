package jsanalysis

import (
	"math/rand"
	"testing"
)

// TestBracketIndex pins that the index answers enclosingOpen at every position and closeOf at
// every opening bracket exactly as the walks do, unbalanced and mismatched text included.
func TestBracketIndex(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "empty", src: ""},
		{name: "no brackets", src: "a = b + c;"},
		{name: "nested", src: "f(a, [b, {c: (d)}], e)"},
		{name: "unclosed at end", src: "function f() { g(["},
		{name: "stray closers first", src: ")) ]} a(b)"},
		{name: "stray closer inside", src: "{ a ) b } c ( d"},
		{name: "mismatched kinds", src: "( ] { ) [ }"},
		{name: "closer pairs the innermost", src: "{ ( ] x } y"},
		{name: "opener at the end", src: "a {"},
	}
	rng := rand.New(rand.NewSource(1))
	for k := 0; k < 500; k++ {
		r := make([]rune, rng.Intn(40))
		for i := range r {
			r[i] = []rune("([{)]}a")[rng.Intn(7)]
		}
		tests = append(tests, struct {
			name string
			src  string
		}{name: "random", src: string(r)})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clean := []rune(tt.src)
			bi := newBracketIndex(clean)
			for i := range clean {
				if got, want := bi.enclosingOpen(i), enclosingOpen(clean, i); got != want {
					t.Errorf("enclosingOpen(%d) = %d, want %d", i, got, want)
				}
				switch clean[i] {
				case '(', '[', '{':
					if got, want := bi.closeOf(i), closeOf(clean, i); got != want {
						t.Errorf("closeOf(%d) = %d, want %d", i, got, want)
					}
				}
			}
		})
	}
}
