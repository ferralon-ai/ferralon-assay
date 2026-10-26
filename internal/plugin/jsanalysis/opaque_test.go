package jsanalysis

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestOpaqueSiteAt reads every position of each snippet through opaqueSiteAt and lists the
// opaque sites it finds, as "callee/arity".
func TestOpaqueSiteAt(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"call on a call", "get()(1)", []string{"get()/1"}},
		{"computed member", "t[k](1)", []string{"t[k]/1"}},
		{"index", "hs[0](1, 2)", []string{"hs[0]/2"}},
		{"comma expression", "(0, sink)(1)", []string{"(0, sink)/1"}},
		{"optional call on an index", "t[k]?.(1)", []string{"t[k]/1"}},
		{"optional call on a call", "f()?.()", []string{"f()/0"}},
		{"tagged template", "sink`a${x}b${y}c`", []string{"sink/3"}},
		{"tag set off by a space", "sink `x`", []string{"sink/1"}},
		{"member tag", "a.b`x`", []string{"a.b/1"}},
		{"new without arguments", "x = new C;", []string{"new C/0"}},
		{"new of a member without arguments", "x = new a.B", []string{"new a.B/0"}},
		{"super call", "super(a, b)", []string{"super/2"}},
		{"bare decorator", "@dec\nclass C {}", []string{"@dec/1"}},
		{"bare member decorator", "@a.b class C {}", []string{"@a.b/1"}},
		{"two bare decorators", "@a @b class C {}", []string{"@a/1", "@b/1"}},
		{"non-null call", "f!(x)", []string{"f/1"}},
		{"chain then call on its result", "a.b.c()(x)", []string{"a.b.c()/1"}},
		{"index inside a chain", "x.y[0].z()(1)", []string{"x.y[0].z()/1"}},
		{"call on a parenthesized name after a condition", "if (x) (f)(1)", []string{"(f)/1"}},
		{"call on a call taking a function", "foo(function () {})(1)", []string{"foo(function () {})/1"}},
		{"call on a load keeps its literal", "require('debug')('ns')", []string{"require('debug')/1"}},
		// Not opaque: the chain scan's calls, conditions, in-place function expressions, keys.
		{"name call", "f(1)", nil},
		{"chain call", "a.b(1)", nil},
		{"optional call on a name", "g?.(1)", nil},
		{"condition", "if (x) (y)", nil},
		{"loop header", "for (;;) (c)", nil},
		{"while condition", "while (a) (b)", nil},
		{"function expression called in place", "(function () { return 1; })()", nil},
		{"arrow called in place", "(() => 1)()", nil},
		{"async arrow called in place", "(async () => {})()", nil},
		{"computed method name", "o = { [k](x) { return x; } }", nil},
		{"static computed method", "class C { static [k]() {} }", nil},
		{"untagged template", "return `x`", nil},
		{"new with arguments", "new C(1)", nil},
		{"new with type arguments", "new C<T>()", nil},
		{"new.target", "new.target", nil},
		{"super member", "super.m()", nil},
		{"decorator call", "@dec() class C {}", nil},
		{"at sign in text", "<p>mail@x.com</p>", nil},
		{"array literal", "x = [a, b]", nil},
		{"inequality", "a != (b)", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := lexJS(tc.src)
			raw := []rune(tc.src)
			var got []string
			for i := range r {
				if s, ok := opaqueSiteAt(r, raw, i); ok {
					got = append(got, fmt.Sprintf("%s/%d", s.written, s.arity))
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("opaque sites = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWrittenSpan_CutsALongCallee: a callee over maxWritten runes keeps its head and ends in
// "…"; whitespace runs collapse.
func TestWrittenSpan_CutsALongCallee(t *testing.T) {
	src := []rune("(" + strings.Repeat("a,\n  ", 40) + "b)")
	got := writtenSpan(src, nil, 0, len(src)-1)
	want := string([]rune("(" + strings.Repeat("a, ", 40))[:maxWritten-1]) + "…"
	if got != want {
		t.Errorf("writtenSpan = %q, want %q", got, want)
	}
	if got := writtenSpan([]rune("t[ k ]"), nil, 0, 5); got != "t[ k ]" {
		t.Errorf("writtenSpan = %q, want %q", got, "t[ k ]")
	}
}

// TestParseFile_OpaqueSitesHaveTheirFrame: an opaque site is attributed to the frame it runs
// in, like any call.
func TestParseFile_OpaqueSitesHaveTheirFrame(t *testing.T) {
	res := parseFile("app", "function run(k) { return t[k](1); }\nconst x = get()(2);\n")
	var got []string
	for _, cs := range res.calls {
		if cs.opaque {
			got = append(got, cs.callerName+" "+cs.written)
		}
	}
	want := []string{"run t[k]", moduleInitFunc + " get()"}
	if !slices.Equal(got, want) {
		t.Errorf("opaque sites = %q, want %q", got, want)
	}
}

// TestParseFile_SkippedStretchesAreListed: a call in a parameter default runs in the function's
// own frame, and one in a class heritage clause in the frame holding the class; each is listed,
// never connected.
func TestParseFile_SkippedStretchesAreListed(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string // "caller callee"
	}{
		{"function default", "function run(a = sink(1), b = t[k](2)) { return a; }\n", []string{"run sink", "run t[k]"}},
		{"arrow default", "const run = (a = sink(1)) => { return a; };\n", []string{"run sink"}},
		{"method default", "class C { run(a = this.m(1)) { return a; } }\n", []string{"run this.m"}},
		{"destructured default", "function run({ a = sink(1) } = {}) { return a; }\n", []string{"run sink"}},
		{"function expression in a default", "function run(cb = function named(x) { return x; }) { return cb; }\n", nil},
		{"heritage clause", "class C extends mix(A) {}\n", []string{moduleInitFunc + " mix"}},
		{"after a dynamic import on its line", "function run() { return import('./x').then(sink); }\n", []string{"run then"}},
		{"after import.meta on its line", "function run() { return f(import.meta.url, g(1)); }\n", []string{"run g"}},
		{"import statement", "import { a } from './a';\nimport b = require('./b');\n", nil},
		{"no default", "function run(a, b) { return a; }\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, cs := range parseFile("app", tc.src).calls {
				if cs.opaque || cs.unconnected {
					got = append(got, cs.callerName+" "+calleeOrWritten(cs))
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("listed = %q, want %q", got, tc.want)
			}
		})
	}
}

func calleeOrWritten(cs callSite) string {
	if cs.opaque {
		return cs.written
	}
	return calleeAsWritten(cs)
}
