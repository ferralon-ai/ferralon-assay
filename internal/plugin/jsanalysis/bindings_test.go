package jsanalysis

import "testing"

// TestSpecifierAtDecodesEscapes: a literal reads as the value the engine gives it, and a
// malformed escape reads as no literal rather than as a look-alike.
func TestSpecifierAtDecodesEscapes(t *testing.T) {
	cases := []struct {
		name, lit, want string
	}{
		{"plain", `'constructor'`, "constructor"},
		{"single-character escapes", `'a\'b\"c\\d'`, `a'b"c\d`},
		{"control escapes", `'\b\f\n\r\t\v'`, "\b\f\n\r\t\v"},
		{"identity escape", `'\c\onstructor'`, "constructor"},
		{"hex escape", `'\x63onstructor'`, "constructor"},
		{"upper-case hex digits", `'\x4Fk'`, "Ok"},
		{"four-digit unicode escape", `'\u0063onstructor'`, "constructor"},
		{"code point escape", `'\u{63}onstructor'`, "constructor"},
		{"code point escape with leading zeros", `'\u{0000000063}onstructor'`, "constructor"},
		{"astral code point escape", `'\u{1F600}'`, "\U0001F600"},
		{"surrogate pair of unicode escapes", `'\uD83D\uDE00'`, "\U0001F600"},
		{"lone surrogate unicode escape", `'\uD83D'`, "\uFFFD"},
		{"surrogate pair of code point escapes", `'\u{D83D}\u{DE00}'`, "\U0001F600"},
		{"line continuation LF", "'constr\\\nuctor'", "constructor"},
		{"line continuation CR", "'constr\\\ructor'", "constructor"},
		{"line continuation CRLF", "'constr\\\r\nuctor'", "constructor"},
		{"line continuation U+2028", "'constr\\ uctor'", "constructor"},
		{"line continuation U+2029", "'constr\\ uctor'", "constructor"},
		{"legacy octal escape", `'\143onstructor'`, "constructor"},
		{"legacy octal stops at three digits", `'\1431'`, "c1"},
		{"legacy octal above 3 takes two digits", `'\477'`, "\x277"},
		{"legacy octal NUL before 8", `'\08'`, "\x008"},
		{"non-octal decimal escape", `'\8'`, "8"},
		{"mixed spelling", `'\x63on\u{73}t\
r\165ctor'`, "constructor"},
		{"double-quoted", `"\x72equire"`, "require"},
		{"template without interpolation", "`\\x63onstructor`", "constructor"},
		{"template NUL escape", "`a\\0`", "a\x00"},
		{"template raw CRLF reads as LF", "`a\r\nb`", "a\nb"},
		{"template interpolation", "`./${n}`", "./${"},
		{"escaped template interpolation", "`\\${n}`", "${n}"},
		{"malformed short hex", `'\x6'`, ""},
		{"malformed hex digit", `'\x6g'`, ""},
		{"malformed short unicode", `'\u063'`, ""},
		{"malformed empty code point", `'\u{}'`, ""},
		{"code point past the last", `'\u{110000}'`, ""},
		{"code point overflowing 32 bits", `'\u{100000063}onstructor'`, ""},
		{"unterminated code point", `'\u{63'`, ""},
		{"lone backslash", `'\`, ""},
		{"template octal escape", "`\\143onstructor`", ""},
		{"template decimal escape", "`\\8`", ""},
		{"line break in a string", "'constr\nuctor'", ""},
		{"unterminated", `'constructor`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := specifierAt([]rune(tc.lit), 0); got != tc.want {
				t.Errorf("specifierAt(%q) = %q; want %q", tc.lit, got, tc.want)
			}
		})
	}
}

// TestInterpolatedReadsTheRawTemplate: an interpolation after a malformed escape still marks
// the template computed.
func TestInterpolatedReadsTheRawTemplate(t *testing.T) {
	cases := []struct {
		lit  string
		want bool
	}{
		{"`./${n}`", true},
		{"`\\x6${n}`", true},
		{"`\\${n}`", false},
		{"`./plugins`", false},
		{"'${n}'", false},
	}
	for _, tc := range cases {
		if got := interpolated([]rune(tc.lit), 0); got != tc.want {
			t.Errorf("interpolated(%q) = %v; want %v", tc.lit, got, tc.want)
		}
	}
}
