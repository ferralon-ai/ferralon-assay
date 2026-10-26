package jsanalysis

import "testing"

// TestMarkRebound: a call's callee name (or its receiver) is rebound when any binding the
// resolver does not read may be in force where the call runs. Each row parses one module and
// reads the flag on the call to callee.
func TestMarkRebound(t *testing.T) {
	const decl = "function sink(x) { return x; }\nfunction f() {}\n"
	cases := []struct {
		name   string
		src    string
		callee string
		want   bool
	}{
		{"no other binding", decl + "function run() { return f(1); }\n", "f", false},
		{"a sibling function's parameter", decl + "function other(f) { return 0; }\nfunction run() { return f(1); }\n", "f", false},
		{"top-level function-valued var", "var f = function (a, b) {};\nfunction run() { return f(1); }\n", "f", false},
		{"import binding", "const { f } = require('./lib');\nfunction run() { return f(1); }\n", "f", false},
		{"tracked instance", "class Jar { put(a) {} }\nconst j = new Jar();\nfunction run() { return j.put(); }\n", "j.put", false},
		{"self call in a declaration", "function f(n) { return n ? f(n - 1) : 0; }\n", "f", false},

		{"parameter", decl + "function run(f) { return f(1); }\n", "f", true},
		{"destructured parameter", decl + "function run({ f }) { return f(1); }\n", "f", true},
		{"array-destructured parameter", decl + "function run([f]) { return f(1); }\n", "f", true},
		{"defaulted parameter", decl + "function run(f = sink) { return f(1); }\n", "f", true},
		{"rest parameter", decl + "function run(...f) { return f(1); }\n", "f", true},
		{"arrow parameter", decl + "const run = (f) => f(1);\n", "f", true},
		{"bare arrow parameter", decl + "const run = f => f(1);\n", "f", true},
		{"method parameter", decl + "class C { run(f) { return f(1); } }\n", "f", true},
		{"const", decl + "function run() { const f = sink; return f(1); }\n", "f", true},
		{"let in an inner block", decl + "function run(x) { if (x) { let f = sink; } return f(1); }\n", "f", true},
		{"var in a nested block", decl + "function run(x) { if (x) { var f = sink; } return f(1); }\n", "f", true},
		{"destructuring const", decl + "function run(o) { const { f } = o; return f(1); }\n", "f", true},
		{"renamed destructuring", decl + "function run(o) { const { a: f } = o; return f(1); }\n", "f", true},
		{"catch binding", decl + "function run() { try { return 0; } catch (f) { return f(1); } }\n", "f", true},
		{"destructured catch binding", decl + "function run() { try { return 0; } catch ({ f }) { return f(1); } }\n", "f", true},
		{"inner function declaration", decl + "function run() { function f(a, b) {} return f(1); }\n", "f", true},
		{"inner class", decl + "function run() { class f {} return f(1); }\n", "f", true},
		{"named function expression", "function f() {}\nconst run = function f(a) { return a ? f(0) : 1; };\n", "f", true},
		{"for-of head", decl + "function run(fs) { for (const f of fs) f(1); }\n", "f", true},
		{"for-of head with no declaration", decl + "function run(fs) { for (f of fs) {} return f(1); }\n", "f", true},
		{"destructuring assignment", decl + "function run(o) { ({ f } = o); return f(1); }\n", "f", true},
		{"logical assignment", decl + "function run() { f ||= sink; return f(1); }\n", "f", true},
		{"top-level assignment", decl + "f = sink;\nfunction run() { return f(1); }\n", "f", true},
		{"top-level var beside the declaration", decl + "var f = sink;\nfunction run() { return f(1); }\n", "f", true},
		{"with statement", decl + "function run(o) { with (o) { return f(1); } }\n", "f", true},
		{"receiver is a parameter", "class Jar { put(a) {} }\nconst j = new Jar();\nfunction run(j) { return j.put(); }\n", "j.put", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parseFile("app", tc.src)
			var site *callSite
			for k := range res.calls {
				if cs := res.calls[k]; !cs.opaque && calleeAsWritten(cs) == tc.callee && site == nil {
					site = &res.calls[k]
				}
			}
			if site == nil {
				t.Fatalf("no call to %s in %+v", tc.callee, res.calls)
			}
			if site.rebound != tc.want {
				t.Errorf("rebound = %v, want %v", site.rebound, tc.want)
			}
		})
	}
}
