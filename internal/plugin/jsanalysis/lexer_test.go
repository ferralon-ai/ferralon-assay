package jsanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestStripJS_HidesNoCode: each source holds code the lexer must keep (keep) and literal
// text it must blank (drop). Sources write a backtick as '^'. Every output keeps the
// source's rune length and line breaks, which the position-reading scanners rely on.
func TestStripJS_HidesNoCode(t *testing.T) {
	cases := []struct {
		name string
		src  string
		keep []string
		drop []string
	}{
		{"call inside a template substitution", "f(^a${g(x)}b^)", []string{"g(x)"}, []string{"a", "b"}},
		{"nested template", "^o${^i${g(x)}^}^", []string{"g(x)"}, []string{"o", "i"}},
		{"braces and a string holding a brace inside a substitution", "^${ {k: '}'}.k + g(x) }t^; h()", []string{"{k: _  }.k + g(x)", "h()"}, []string{"t"}},
		{"regex inside a substitution", "^${/}/.test(s) && g(x)}^", []string{"g(x)"}, []string{"}/"}},
		{"string ends at a line break", "x = 'abc\ng()", []string{"g()"}, []string{"abc"}},
		{"double-quoted string ends at a line break", "x = \"abc\ng()", []string{"g()"}, []string{"abc"}},
		{"string continued by a backslash-newline", "x = 'a\\\ng() b'; h()", []string{"h()"}, []string{"g()"}},
		{"string continued by a backslash-CRLF", "x = 'a\\\r\ng() b'; h()", []string{"h()"}, []string{"g()"}},
		{"regex after return", "return /'/.test(s); g() // it's", []string{"g()"}, []string{"'", "it"}},
		{"regex after typeof-like keywords", "x = void /'/; y = typeof /'/; throw /'/; g()", []string{"g()"}, []string{"'"}},
		{"regex after a statement condition", "if (s) /'/.test(s); g() // it's", []string{"g()"}, []string{"'", "it"}},
		{"division after a call's close paren", "x = f(a) / 2; g() // c", []string{"/ 2; g()"}, []string{" c"}},
		{"division after a property named like a keyword", "x = o.return / 2; g() // c", []string{"/ 2; g()"}, nil},
		{"division after postfix increment", "n = i++ / 2; g() // c", []string{"/ 2; g()"}, nil},
		{"division after postfix decrement", "n = i-- / 2; g() // c", []string{"/ 2; g()"}, nil},
		{"JSX closing tag", "<p>hi</p>; g() // c", []string{"</p>; g()"}, nil},
		{"a regex that does not close on its line is a division", "x = / g()\nh()", []string{"/ g()", "h()"}, nil},
		{"a template that never closes is code", "a = 1 ^ b\ng()", []string{"b", "g()"}, nil},
		{"a block comment that never closes is code", "a = 1 /* b\ng()", []string{"/* b", "g()"}, nil},
		{"a substitution whose template never closes is code", "^${a}b\ng()", []string{"a", "b", "g()"}, nil},
		{"template literal text stays literal", "^require(x) ${y}^", []string{"y"}, []string{"require", "x"}},
		{"multi-line template is one literal", "^it's\nrequire(\"x\")\n^; g()", []string{"g()"}, []string{"it", "require", "x"}},
		{"regex holding a quote and a backtick", "return /[^'\"]/.test(s); g()", []string{"g()"}, []string{"'", "\""}},
		{"regex character class holding a slash", "x = /[/'\"]/; g()", []string{"g()"}, []string{"'"}},
		{"regex after a ternary operator", "x = a ? /'/ : b; g()", []string{": b; g()"}, []string{"'"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.ReplaceAll(tc.src, "^", "`")
			got := stripJS(src)
			sr, gr := []rune(src), []rune(got)
			if len(sr) != len(gr) {
				t.Fatalf("stripJS changed the rune length: %d -> %d\n%q", len(sr), len(gr), got)
			}
			for k := range sr {
				if (sr[k] == '\n') != (gr[k] == '\n') {
					t.Fatalf("stripJS moved a line break at rune %d\n%q", k, got)
				}
			}
			for _, k := range tc.keep {
				if !strings.Contains(got, k) {
					t.Errorf("stripJS hid %q\n%q", k, got)
				}
			}
			for _, d := range tc.drop {
				if strings.Contains(got, d) {
					t.Errorf("stripJS kept literal text %q\n%q", d, got)
				}
			}
		})
	}
}

// TestCallGraph_EdgesInsideTemplateSubstitutions: a call inside a template substitution is
// an edge, including through a nested template and a substitution holding braces and
// strings; the same text in a template's literal part is not.
func TestCallGraph_EdgesInsideTemplateSubstitutions(t *testing.T) {
	src := strings.ReplaceAll(`
function plain(s) { return ^v=${helper(s)}^; }
function nested(s) { return ^a${^b${other(s)}^}^; }
function braced(s) { return ^${[s].map(x => { return '}' + x; }).join() + third(s)}^; }
function literal(s) { return ^helper(s) other(s) third(s) ${s}^; }
function helper(s) { return s; }
function other(s) { return s; }
function third(s) { return s; }
`, "^", "`")
	dir := writeProgram(t, map[string]string{"t.js": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	fn := func(name string) string { return funcSCIP("t", nil, name, 1) }
	for _, e := range [][2]string{{"plain", "helper"}, {"nested", "other"}, {"braced", "third"}} {
		if !hasEdge(res.Edges, fn(e[0]), fn(e[1])) {
			t.Errorf("missing edge %s -> %s; edges=%+v", e[0], e[1], res.Edges)
		}
	}
	for _, callee := range []string{"helper", "other", "third"} {
		if hasEdge(res.Edges, fn("literal"), fn(callee)) {
			t.Errorf("edge literal -> %s from template text", callee)
		}
	}
}
