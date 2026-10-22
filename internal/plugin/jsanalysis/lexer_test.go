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
		{"division after a variable named of", "let of = 4; x = of / 2; g() // c", []string{"/ 2; g()"}, nil},
		{"division after variables named yield and await", "x = yield / 2 + await / 3; g() // c", []string{"/ 2 + await / 3; g()"}, nil},
		{"regex after of in a for head", "for (const m of /'/.exec(s)) g() // it's", []string{"g()"}, []string{"'", "it"}},
		{"regex after export default", "export default /'/; g() // it's", []string{"g()"}, []string{"'", "it"}},
		{"regex after a spread", "a = [.../'/.exec(s)]; g() // it's", []string{"g()"}, []string{"'", "it"}},
		{"regex after a spaced less-than", "b = x < /'/.exec(s); g() // it's", []string{"g()"}, []string{"'", "it"}},
		{"division after a method named if", "x = o.if(a) / 2; g() / 3", []string{"/ 2; g() / 3"}, nil},
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

// TestStripJS_TagKeepsItsName checks that a tag written flush against its template reads as
// its own name, so every recognizer keyed on that name still sees it.
func TestStripJS_TagKeepsItsName(t *testing.T) {
	for _, tc := range []struct{ src, tag string }{
		{"require`./x`;", "require"},
		{"Function`return 1`;", "Function"},
		{"g.constructor`c`;", "constructor"},
		{"x = _`a${b}c`;", "_"},
	} {
		clean := []rune(stripJS(tc.src))
		i := strings.Index(tc.src, tc.tag+"`")
		if w, _ := readWord(clean, i); w != tc.tag {
			t.Errorf("%q: word at the tag = %q, want %q (clean %q)", tc.src, w, tc.tag, string(clean))
		}
	}
}

// TestHiddenLoads_DeclaresWhatBlankedTextLoads checks that a loader occurrence inside
// block-comment or template text is declared without becoming a binding, and that JSDoc
// types and prose naming a loader are not.
func TestHiddenLoads_DeclaresWhatBlankedTextLoads(t *testing.T) {
	for _, tc := range []struct {
		name, src   string
		ev, cr, dyn bool
	}{
		{"require between a stray backtick and a template", "a = <p>Run `npm i</p>;\nconst m = require(x);\nb = `ok`;\n", false, true, false},
		{"eval between a stray opener and a comment", "a = <p>src/*</p>;\neval(x);\n/* c */\n", true, false, false},
		{"import in a comment", "/* import(x) */\n", false, false, true},
		{"loader alias declared in a comment", "/* const r = require; */\nr(x);\n", false, true, false},
		{"text nested in blanked text", "a = <p>src/*</p>;\nc = <p>Run `npm i</p>;\nrequire(x);\nb = `ok`;\n/* c */\n", false, true, false},
		{"JSDoc types", "/** @param {Function} f\n * @returns {import(x).T} */\n", false, false, false},
		{"prose", "/* Function that this returns, eval it and require the rest; we require. */\n", false, false, false},
		{"prose naming module after a JSX apostrophe", "a = <p>Don't run the real module, mutated (module paths) on module</p>;\n", false, false, false},
		{"module.require after a JSX apostrophe", "a = <p>Don't {module.require(x)}</p>;\n", false, true, false},
		{"module handed on after a JSX apostrophe", "a = <p>Don't {f(module)}</p>;\n", false, true, false},
		{"module after return in a comment", "/* return module */\n", false, true, false},
		{"brackets from separate templates", "a = `x]`;\nb = `[k]`;\nc = `[j]`;\n", false, false, false},
		{"computed index pair in a comment", "/* o[a][b]() */\n", true, false, false},
		{"require alias declared in code, used after a JSX apostrophe", "const r = createRequire(u);\na = <p>Don't {r(x)}</p>;\n", false, true, false},
		{"createRequire alias declared in code, used after a JSX apostrophe", "const { createRequire: mk } = m;\na = <p>Don't {mk(u)(x)}</p>;\n", false, true, false},
		{"require alias declared in a comment beside one declared in code", "/* const r = createRequire(u); */\nconst a = createRequire(u);\nr(x);\n", false, true, false},
		{"createRequire alias declared in a comment", "/* import { createRequire as mk } from 'module'; */\nmk(u)(x);\n", false, true, false},
		{"eval after a non-JSDoc @word", "a = <p>Don't mail me@home {eval(x)}</p>;\n", true, false, false},
		{"JSDoc type left open on its line", "/** @param {Object\n * eval(x) } */\n", true, false, false},
		{"name after a JSDoc tag", "a = <p>Don't @param me {eval(x)}</p>;\n", true, false, false},
		{"eval asserted as a type after a JSX apostrophe", "a = <p>Don't {(eval as any)(x)}</p>;\n", true, false, false},
		{"eval tested with in after a JSX apostrophe", "a = <p>Don't {eval in o}</p>;\n", true, false, false},
		{"identifier-escaped eval after a JSX apostrophe", "a = <p>Don't {\\u0065val(x)}</p>;\n", true, false, false},
		{"text nested within the layer bound is lexed", "x = 'a" + strings.Repeat(" \\'b", 7) + " \"require(y)\"\n", false, false, false},
		{"text nested past the layer bound is read unlexed", "x = 'a" + strings.Repeat(" \\'b", 8) + " \"require(y)\"\n", false, true, false},
		{"class extending Function in a comment", "/* class F extends Function {} */\n", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []rune(tc.src)
			clean, hidden := lexJS(tc.src)
			mb := hiddenLoads(clean, raw, hidden)
			if mb.evaluated != tc.ev || mb.computedReq != tc.cr || mb.dynImport != tc.dyn {
				t.Errorf("evaluated=%v computedReq=%v dynImport=%v; want %v %v %v", mb.evaluated, mb.computedReq, mb.dynImport, tc.ev, tc.cr, tc.dyn)
			}
			if len(mb.imports) != 0 {
				t.Errorf("hidden text bound %v", mb.imports)
			}
		})
	}
}
