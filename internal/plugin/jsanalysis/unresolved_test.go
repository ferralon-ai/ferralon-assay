package jsanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestMain holds every call-graph build the package's tests make to the completeness contract
// (completenessViolations), so the contract is checked on every fixture, not only on the ones
// listed below.
func TestMain(m *testing.M) {
	var mu sync.Mutex
	var broken []string
	graphBuilt = func(dir string, b builtGraph) {
		if v := completenessViolations(b); len(v) > 0 {
			mu.Lock()
			broken = append(broken, dir+": "+strings.Join(v, "; "))
			mu.Unlock()
		}
	}
	code := m.Run()
	if len(broken) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d call-graph builds broke the completeness contract:\n", len(broken))
		for _, b := range broken {
			fmt.Fprintln(os.Stderr, "  "+b)
		}
		code = 1
	}
	os.Exit(code)
}

// siteReasons are the reasons a declined call or load contributes, so the ones an Unresolved
// entry must carry unless unlisted_sites is declared.
var siteReasons = []string{
	plugin.PartialReasonDynamicDispatch,
	plugin.PartialReasonUninspectablePackage,
	plugin.PartialReasonDynamicImportSpecifier,
	plugin.PartialReasonComputedRequireSpecifier,
	plugin.PartialReasonUnresolvedModule,
	plugin.PartialReasonEvaluatedCode,
}

// completenessViolations checks one build against Eric's contract: every declined site is an
// Unresolved entry; unlisted_sites is declared exactly when a declined site is not; every site
// reason the graph declares is carried by an entry (or unlisted_sites is declared); an entry's
// reason is one the graph declares; Targets appears only on a declined name; Escaped is a set of
// roots.
func completenessViolations(b builtGraph) []string {
	var v []string
	res := b.res
	if len(res.Unresolved) != b.declined {
		v = append(v, fmt.Sprintf("%d Unresolved entries for %d declined sites", len(res.Unresolved), b.declined))
	}
	if got := hasReason(res.Partiality, plugin.PartialReasonUnlistedSites); got != b.unlisted {
		v = append(v, fmt.Sprintf("unlisted_sites declared=%v, unlisted=%v", got, b.unlisted))
	}
	carried := map[string]bool{}
	for _, u := range res.Unresolved {
		carried[u.Reason] = true
		if !hasReason(res.Partiality, u.Reason) {
			v = append(v, fmt.Sprintf("entry %s→%s carries %s, which the graph does not declare", u.Caller.SCIP, u.Callee, u.Reason))
		}
		if len(u.Targets) > 0 && u.Reason != plugin.PartialReasonDynamicDispatch {
			v = append(v, fmt.Sprintf("entry %s→%s lists Targets under %s", u.Caller.SCIP, u.Callee, u.Reason))
		}
	}
	if !b.unlisted {
		for _, r := range siteReasons {
			if hasReason(res.Partiality, r) && !carried[r] {
				v = append(v, "reason "+r+" is carried by no entry")
			}
		}
	}
	roots := map[string]bool{}
	for _, r := range res.Roots {
		roots[r.SCIP] = true
	}
	for _, e := range res.Escaped {
		if !roots[e.SCIP] {
			v = append(v, "escaped "+e.SCIP+" is not a root")
		}
	}
	return v
}

// ssrfPathRemoving builds the FERRALON-JS-SSRF-0001 tree after tegron's path-removing patch
// (service/internal/reasoning/testdata/js-ssrf-0001/path-removing.diff): the patched app.js
// from testdata beside the vulnerable fetcher.js, which the patch leaves alone.
func ssrfPathRemoving(t *testing.T) string {
	t.Helper()
	app, err := os.ReadFile(filepath.Join("testdata", "ssrf0001-path-removing", "src", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := os.ReadFile(filepath.Join(reproSrc, "fetcher.js"))
	if err != nil {
		t.Fatal(err)
	}
	return writeProgram(t, map[string]string{"app.js": string(app), "fetcher.js": string(fetcher)})
}

// TestCallGraph_CompletenessInvariant builds every testdata tree, every JS corpus repro, the
// SSRF-0001 path-removing tree and one program per kind of declined site, and holds each to the
// contract. A build that drops one Unresolved append leaves declined ahead of the list and fails.
func TestCallGraph_CompletenessInvariant(t *testing.T) {
	type row struct {
		name     string
		dir      func(t *testing.T) string
		unlisted bool
		want     []string // "callee reason" entries the build must list
	}
	var rows []row
	tops, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range tops {
		if e.IsDir() {
			dir := filepath.Join("testdata", e.Name())
			rows = append(rows, row{name: "testdata/" + e.Name(), dir: func(*testing.T) string { return dir }})
		}
	}
	repros, err := filepath.Glob("../../../corpus/testdata/repros/FERRALON-JS-*/src")
	if err != nil || len(repros) == 0 {
		t.Fatalf("no JS repros: %v", err)
	}
	for _, dir := range repros {
		rows = append(rows, row{name: filepath.Base(filepath.Dir(dir)), dir: func(*testing.T) string { return dir }})
	}
	rows = append(rows, row{name: "SSRF-0001 path-removing", dir: ssrfPathRemoving})
	inline := func(name string, files map[string]string, unlisted bool, want ...string) {
		rows = append(rows, row{name: name, dir: func(t *testing.T) string { return writeProgram(t, files) }, unlisted: unlisted, want: want})
	}
	inline("unknown name", map[string]string{"app.js": "function main() { return missing(1); }\nmodule.exports = { main };\n"}, false,
		"missing "+plugin.PartialReasonDynamicDispatch)
	inline("package call and its load", map[string]string{"app.js": "const fs = require('fs');\nfunction main() { return fs.readFileSync('x'); }\nmodule.exports = { main };\n"}, false,
		"fs.readFileSync "+plugin.PartialReasonUninspectablePackage, "require "+plugin.PartialReasonUninspectablePackage)
	inline("package boundary call", map[string]string{"app.js": "const express = require('express');\nconst app = express();\nfunction h(req, res) { return res; }\napp.get('/x', h);\n"}, false,
		"app.get "+plugin.PartialReasonDynamicDispatch)
	inline("computed require", map[string]string{"app.js": "function load(name) { return require(name); }\nmodule.exports = { load };\n"}, false,
		"require "+plugin.PartialReasonComputedRequireSpecifier)
	inline("computed import", map[string]string{"app.mjs": "export async function load(name) { return import(name); }\n"}, false,
		"import "+plugin.PartialReasonDynamicImportSpecifier)
	inline("prefix load", map[string]string{
		"app.js":        "function load(lang) { return require('./locales/' + lang); }\nmodule.exports = { load };\n",
		"locales/en.js": "module.exports = {};\n",
	}, false, "require "+plugin.PartialReasonComputedRequireSpecifier)
	inline("native load", map[string]string{"app.js": "const m = { exports: {} };\nprocess.dlopen(m, './addon.node');\nmodule.exports = m.exports;\n"}, false,
		"dlopen "+plugin.PartialReasonUnresolvedModule)
	inline("unread relative module", map[string]string{"app.js": "const gen = require('./generated');\nmodule.exports = gen;\n"}, false,
		"require "+plugin.PartialReasonUnresolvedModule)
	inline("eval: its body is never listed", map[string]string{"app.js": "function main(s) { return eval(s); }\nmodule.exports = { main };\n"}, true,
		"eval "+plugin.PartialReasonEvaluatedCode)
	inline("ambiguous name", map[string]string{"app.js": "function f(a) { return a; }\nfunction f(a, b) { return b; }\nfunction main() { return f(1, 2, 3); }\nmodule.exports = { main };\n"}, false,
		"f "+plugin.PartialReasonDynamicDispatch)
	// Calls whose callee is not a name or a chain (opaque.go): Eric's six forms on #208, then the
	// other shapes the scanner meets.
	dd := plugin.PartialReasonDynamicDispatch
	sink := "function sink(x) { return x; }\n"
	exp := "module.exports = { run };\n"
	inline("call on a call", map[string]string{"app.js": sink + "function get() { return sink; }\nfunction run() { return get()(1); }\n" + exp}, false, "get() "+dd)
	inline("computed member call", map[string]string{"app.js": sink + "const t = { s: sink };\nfunction run(k) { return t[k](1); }\n" + exp}, false, "t[k] "+dd)
	inline("index call", map[string]string{"app.js": sink + "const hs = [sink];\nfunction run() { return hs[0](1); }\n" + exp}, false, "hs[0] "+dd)
	inline("comma callee", map[string]string{"app.js": sink + "function run() { return (0, sink)(1); }\n" + exp}, false, "(0, sink) "+dd)
	inline("optional call", map[string]string{"app.js": "function g(x) { return x; }\nfunction run() { return g?.(1); }\n" + exp}, false, "g "+dd)
	inline("tagged template", map[string]string{"app.js": sink + "function run(v) { return sink`a${v}b`; }\n" + exp}, false, "sink "+dd)
	inline("optional call on an index", map[string]string{"app.js": sink + "const t = { s: sink };\nfunction run(k) { return t[k]?.(1); }\n" + exp}, false, "t[k] "+dd)
	inline("non-null call", map[string]string{"app.ts": sink + "export function run(f?: (x: number) => void) { return f!(1); }\n"}, false, "f "+dd)
	inline("new without arguments", map[string]string{"app.js": "function C() { this.x = 1; }\nfunction run() { return new C; }\n" + exp}, false, "new C "+dd)
	inline("super call", map[string]string{"app.js": "class A { constructor(x) { this.x = x; } }\nclass B extends A { constructor() { super(1); } }\nmodule.exports = { B };\n"}, false, "super "+dd)
	inline("call in a parameter default", map[string]string{"app.js": sink + "function run(a = sink(1)) { return a; }\n" + exp}, false, "sink "+dd)
	inline("call in a class heritage clause", map[string]string{"app.js": "function mix(B) { return B; }\nclass A {}\nclass C extends mix(A) {}\nmodule.exports = { C };\n"}, false, "mix "+dd)
	inline("bare decorator", map[string]string{"app.ts": "function sealed(c: any) { return c; }\n@sealed\nexport class C {}\n"}, false, "@sealed "+dd)
	rows = append(rows, row{name: "unreadable source", unlisted: true, dir: func(t *testing.T) string {
		dir := writeProgram(t, map[string]string{"b.js": "module.exports = function b() {};\n"})
		mkfifo(t, dir, "a.js")
		return dir
	}})

	for _, rw := range rows {
		t.Run(rw.name, func(t *testing.T) {
			b, err := buildCallGraph(rw.dir(t))
			if err != nil {
				if strings.HasPrefix(rw.name, "testdata/") && strings.Contains(err.Error(), "no .js/.ts") {
					return // a manifest-only tree holds no sources
				}
				t.Fatalf("buildCallGraph: %v", err)
			}
			if v := completenessViolations(b); len(v) > 0 {
				t.Errorf("contract broken: %s", strings.Join(v, "; "))
			}
			if !b.unlisted && len(b.res.Unresolved) != b.declined {
				t.Errorf("len(Unresolved)=%d, declined=%d, and unlisted_sites is not set", len(b.res.Unresolved), b.declined)
			}
			// Every row pins unlisted, a row with no listed entries too ("unreadable source").
			if b.unlisted != rw.unlisted {
				t.Errorf("unlisted = %v, want %v", b.unlisted, rw.unlisted)
			}
			if rw.want == nil {
				return
			}
			got := map[string]bool{}
			for _, u := range b.res.Unresolved {
				got[u.Callee+" "+u.Reason] = true
			}
			for _, w := range rw.want {
				if !got[w] {
					t.Errorf("no entry %q; got %+v", w, b.res.Unresolved)
				}
			}
		})
	}
}

// TestPickFunc_Candidates: a declined pick lists every declaration the name can denote, whatever
// its arity, and a unique pick lists none.
func TestPickFunc_Candidates(t *testing.T) {
	f := func(arity int) funcDecl { return funcDecl{module: "m", name: "f", arity: arity} }
	id := func(arity int) string { return funcSCIP("m", nil, "f", arity) }
	cases := []struct {
		name   string
		decls  []funcDecl
		arity  int
		target string
		want   []string
	}{
		{"unique match is an edge", []funcDecl{f(1), f(2)}, 1, id(1), nil},
		{"two matches list every declaration", []funcDecl{f(1), f(1), f(2)}, 1, "", []string{id(1), id(2)}},
		{"no arity match lists every declaration", []funcDecl{f(1), f(2)}, 0, "", []string{id(1), id(2)}},
		{"an arity-free reference to two declarations lists both", []funcDecl{f(1), f(3)}, -1, "", []string{id(1), id(3)}},
	}
	rs := &resolver{prog: &program{}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := rs.pickFunc("m", tc.decls, tc.arity, provenance{Algo: algoLocal})
			if r.Target != tc.target || !slices.Equal(r.Candidates, tc.want) {
				t.Errorf("pickFunc = target %q candidates %v; want %q %v", r.Target, r.Candidates, tc.target, tc.want)
			}
			if tc.target == "" && r.Reason != plugin.PartialReasonDynamicDispatch {
				t.Errorf("reason = %q, want dynamic_dispatch", r.Reason)
			}
		})
	}
}

// TestCallGraph_UnresolvedTargets: a site lists Targets only when its candidate set is complete
// and bounded, and then lists all of it; a receiver, package or boundary miss omits Targets.
func TestCallGraph_UnresolvedTargets(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		callee string
		want   []string // nil: Targets must be omitted
	}{
		{
			name: "local name with two declarations matching the arity",
			files: map[string]string{"app.js": `function f(a) { return a; }
function f(a, b) { return b; }
function f(c) { return c; }
function main() { return f(1); }
module.exports = { main };
`},
			callee: "f",
			want:   []string{funcSCIP("app", nil, "f", 1), funcSCIP("app", nil, "f", 2)},
		},
		{
			name: "imported name with no arity match",
			files: map[string]string{
				"lib.js": "function g(a) { return a; }\nfunction g(a, b) { return b; }\nmodule.exports = { g };\n",
				"app.js": "const { g } = require('./lib');\nfunction main() { return g(); }\nmodule.exports = { main };\n",
			},
			callee: "g",
			want:   []string{funcSCIP("lib", nil, "g", 1), funcSCIP("lib", nil, "g", 2)},
		},
		{
			name: "method of a tracked instance with no arity match",
			files: map[string]string{"app.js": `class Jar {
  put(a) { return a; }
  put(a, b) { return b; }
}
const j = new Jar();
function main() { return j.put(); }
module.exports = { main };
`},
			callee: "j.put",
			want:   []string{funcSCIP("app", []string{"Jar"}, "put", 1), funcSCIP("app", []string{"Jar"}, "put", 2)},
		},
		{
			name:   "untracked receiver",
			files:  map[string]string{"app.js": "function main(o) { return o.go(1); }\nmodule.exports = { main };\n"},
			callee: "o.go",
		},
		{
			name:   "package call",
			files:  map[string]string{"app.js": "const fs = require('fs');\nfunction main() { return fs.readFileSync('x'); }\nmodule.exports = { main };\n"},
			callee: "fs.readFileSync",
		},
		{
			name:   "call entering a package boundary",
			files:  map[string]string{"app.js": "const express = require('express');\nconst app = express();\nfunction h(req, res) { return res; }\napp.get('/x', h);\n"},
			callee: "app.get",
		},
		{
			name:   "this-call to a method the class does not declare",
			files:  map[string]string{"app.js": "class A { run() { return this.missing(1); } }\nmodule.exports = { A };\n"},
			callee: "this.missing",
		},
		// Eric's blocker-1 repro on #208: the computed call is listed unbounded beside the
		// bounded f, so run→sink is not refuted.
		{
			name:   "computed call beside a bounded name",
			files:  map[string]string{"app.js": ericRepro1},
			callee: "t[k]",
		},
		{
			name:   "the bounded name beside a computed call",
			files:  map[string]string{"app.js": ericRepro1},
			callee: "f",
			want:   []string{funcSCIP("app", nil, "f", 1), funcSCIP("app", nil, "f", 2)},
		},
		// Eric's blocker-2 repros: a local or a parameter rebinds the name, so the declarations
		// the resolver reads do not bound the call.
		{
			name:   "a local const shadows the name",
			files:  map[string]string{"app.js": "function sink(x) { return x; }\nfunction f() {}\nfunction run() { const f = sink; return f(1); }\nmodule.exports = { run };\n"},
			callee: "f",
		},
		{
			name:   "a parameter shadows the name",
			files:  map[string]string{"app.js": "function sink(x) { return x; }\nfunction f() {}\nfunction run(f) { return f(1); }\nrun(sink);\nmodule.exports = { run };\n"},
			callee: "f",
		},
		{
			name:   "no shadow: the declaration still bounds the call",
			files:  map[string]string{"app.js": "function sink(x) { return x; }\nfunction f() {}\nfunction run() { return f(1); }\nmodule.exports = { run };\n"},
			callee: "f",
			want:   []string{funcSCIP("app", nil, "f", 0)},
		},
		{
			name:   "this-call a subclass overrides",
			files:  map[string]string{"app.js": "class C {\n  m() { return 0; }\n  run() { return this.m(1); }\n}\nclass D extends C {\n  m(x) { return x; }\n}\nmodule.exports = { C, D };\n"},
			callee: "this.m",
		},
		{
			name:   "leaf of a longer chain",
			files:  map[string]string{"app.js": "function c() {}\nfunction run(o) { return o.b.c(1, 2); }\nmodule.exports = { run };\n"},
			callee: "o.b.c",
		},
		{
			name: "leaf of a chain read off an import",
			files: map[string]string{
				"lib.js": "module.exports = { b: { c: function (x) { return x; } } };\n",
				"app.js": "const lib = require('./lib');\nfunction c() {}\nfunction run() { return lib.b.c(1, 2); }\nmodule.exports = { run };\n",
			},
			callee: "lib.b.c",
		},
		{
			name:   "leaf of a chain read off a call",
			files:  map[string]string{"app.js": "function json() {}\nfunction run(res) { return res.status(404).json(1); }\nmodule.exports = { run };\n"},
			callee: "json",
		},
		{
			name:   "optional call bounded by its one declaration",
			files:  map[string]string{"app.js": "function g(x) { return x; }\nfunction run() { return g?.(1); }\nmodule.exports = { run };\n"},
			callee: "g",
			want:   []string{funcSCIP("app", nil, "g", 1)},
		},
		{
			name:   "call in a parameter default",
			files:  map[string]string{"app.js": "function sink(x) { return x; }\nfunction run(a = sink(1)) { return a; }\nmodule.exports = { run };\n"},
			callee: "sink",
			want:   []string{funcSCIP("app", nil, "sink", 1)},
		},
		{
			name:   "parameter default calling another parameter",
			files:  map[string]string{"app.js": "function f() {}\nfunction run(f, a = f(1)) { return a; }\nmodule.exports = { run };\n"},
			callee: "f",
		},
		{
			name:   "optional call on a parameter",
			files:  map[string]string{"app.js": "function g(x) { return x; }\nfunction run(g) { return g?.(1); }\nmodule.exports = { run };\n"},
			callee: "g",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			var site *plugin.UnresolvedCall
			for i := range res.Unresolved {
				if res.Unresolved[i].Callee == tc.callee {
					site = &res.Unresolved[i]
				}
			}
			if site == nil {
				t.Fatalf("no Unresolved entry for %s; got %+v", tc.callee, res.Unresolved)
			}
			var got []string
			for _, s := range site.Targets {
				got = append(got, s.SCIP)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Targets = %v, want %v", got, tc.want)
			}
		})
	}
}

// ericRepro1 is Eric's blocker-1 repro on #208: f's two declarations bound one site, and t[k]
// can run sink, which only the computed call reaches.
const ericRepro1 = `function sink(x) { return x; }
function f(a) {}
function f(a, b) {}
const t = { s: sink };
function run(k) { f(); return t[k](1); }
module.exports = { run };
`

// TestCallGraph_EscapedModuleInit: every module's top-level frame is escaped, since a load the
// lane cannot see may run it.
func TestCallGraph_EscapedModuleInit(t *testing.T) {
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, map[string]string{
		"app.js": "function helper(x) { return x; }\nfunction main() { return helper(1); }\nmodule.exports = { main };\n",
		"lib.js": "module.exports = {};\n",
	})})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range res.Escaped {
		got[e.SCIP] = true
	}
	for _, m := range []string{"app", "lib"} {
		if !got[moduleInitSCIP(m)] {
			t.Errorf("%s is not escaped; got %v", moduleInitSCIP(m), res.Escaped)
		}
	}
	if got[funcSCIP("app", nil, "helper", 1)] {
		t.Error("helper, only ever called directly, is escaped")
	}
}

// TestCallGraph_SSRF0001Unresolved records what the three SSRF-0001 trees put on the wire. The
// handler dispatch tegron cannot see is listed without Targets, nothing is unlisted, and
// fetchUrl is escaped on every tree: #106 counts every export as an escape root, including the
// path-removing tree's, where no in-tree module loads ./fetcher any more.
func TestCallGraph_SSRF0001Unresolved(t *testing.T) {
	trees := []struct {
		name string
		dir  func(t *testing.T) string
	}{
		{"vulnerable", func(*testing.T) string { return reproSrc }},
		{"patched", func(*testing.T) string { return "../../../corpus/testdata/repros/FERRALON-JS-SSRF-0001-patched/src" }},
		{"path-removing", ssrfPathRemoving},
	}
	fetchURL := funcSCIP("fetcher", nil, "fetchUrl", 1)
	for _, tr := range trees {
		t.Run(tr.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: tr.dir(t)})
			if err != nil {
				t.Fatal(err)
			}
			escaped := slices.ContainsFunc(res.Escaped, func(s plugin.Symbol) bool { return s.SCIP == fetchURL })
			unlisted := hasReason(res.Partiality, plugin.PartialReasonUnlistedSites)
			bounded := 0
			for _, u := range res.Unresolved {
				if len(u.Targets) > 0 {
					bounded++
				}
			}
			t.Logf("unresolved=%d bounded=%d unlisted_sites=%v fetchUrl_escaped=%v reasons=%v", len(res.Unresolved), bounded, unlisted, escaped, res.Partiality.Reasons)
			if unlisted {
				t.Error("unlisted_sites is set; every declined site of this tree is listable")
			}
			if !escaped {
				t.Errorf("fetchUrl is not escaped; got %v", res.Escaped)
			}
			if !slices.ContainsFunc(res.Unresolved, func(u plugin.UnresolvedCall) bool {
				return u.Callee == "handler" && u.Arity == 2 && u.Targets == nil
			}) {
				t.Errorf("the handler dispatch is not listed unbounded; got %+v", res.Unresolved)
			}
		})
	}
}

// TestCalleeAsWritten renders the callee the way the source spells it.
func TestCalleeAsWritten(t *testing.T) {
	cases := []struct {
		cs   callSite
		want string
	}{
		{callSite{calleeName: "f"}, "f"},
		{callSite{calleeName: "parse", head: "JSON5", chain: []string{"JSON5", "parse"}}, "JSON5.parse"},
		{callSite{calleeName: "c", head: "a", chain: []string{"a", "b", "c"}}, "a.b.c"},
		{callSite{calleeName: "m", head: "o"}, "o.m"},
	}
	for _, tc := range cases {
		if got := calleeAsWritten(tc.cs); got != tc.want {
			t.Errorf("calleeAsWritten(%+v) = %q, want %q", tc.cs, got, tc.want)
		}
	}
}

// TestCompletenessViolations_CatchesADroppedEntry: the contract check itself fails a build whose
// list is one short, and one that hides an unlisted site.
func TestCompletenessViolations_CatchesADroppedEntry(t *testing.T) {
	b, err := buildCallGraph(writeProgram(t, map[string]string{"app.js": "function main() { return missing(1); }\nmodule.exports = { main };\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if v := completenessViolations(b); len(v) != 0 {
		t.Fatalf("clean build flagged: %v", v)
	}
	short := b
	short.res.Unresolved = nil
	if len(completenessViolations(short)) == 0 {
		t.Error("a build missing its only entry passed")
	}
	hidden := b
	hidden.unlisted = true
	if len(completenessViolations(hidden)) == 0 {
		t.Error("an unlisted site without unlisted_sites passed")
	}
}

// TestCallGraph_DependencyCodeDeclaresUnlisted: Unresolved and Escaped list first-party code
// only, so a graph with dependency code read into it declares unlisted_sites once a site
// anywhere is declined, and an unconnected call in that code draws no edge. A site dependency
// code declines declares it with nothing first-party declined, and a first-party site declined
// beside dependency code that declines nothing declares it too: the site may land on a
// dependency frame Escaped omits. Dependency code that declines nothing, read beside
// first-party code that declines nothing, hides no site. With the package
// unread, the graph is the first-party one.
func TestCallGraph_DependencyCodeDeclaresUnlisted(t *testing.T) {
	dep := &depPkg{path: "node_modules/dep", name: "dep", version: "1.0.0", files: map[string]string{
		"package.json": `{"name":"dep","version":"1.0.0"}`,
		"index.js":     "function hook() { return 1; }\nexports.run = function run() { hook?.(); };\n",
	}}
	f := newDepFixture(t, map[string]string{"index.js": "require('dep').run();\n"}, dep)
	head := withDeps(t, f.dir, f.memStore())
	if !hasReason(head.Partiality, plugin.PartialReasonUnlistedSites) {
		t.Errorf("dependency code read without unlisted_sites: %+v", head.Partiality)
	}
	for _, e := range head.Edges {
		if strings.Contains(e.Callee.SCIP, "hook") {
			t.Errorf("an optional call in dependency code drew an edge: %s -> %s", e.Caller.SCIP, e.Callee.SCIP)
		}
	}
	if absent := withDeps(t, f.dir, artifactcache.NewDeclaredAbsentStore()); hasReason(absent.Partiality, plugin.PartialReasonUnlistedSites) {
		t.Errorf("control: no dependency code read, yet unlisted_sites: %+v", absent.Partiality)
	}
	idle := newDepFixture(t, map[string]string{"index.js": guardIdle}, dep)
	if cg := withDeps(t, idle.dir, idle.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonUnlistedSites) {
		t.Errorf("a site declined in dependency code alone, without unlisted_sites: %+v", cg.Partiality)
	}
	plain := &depPkg{path: "node_modules/dep", name: "dep", version: "1.0.0", files: map[string]string{
		"package.json": `{"name":"dep","version":"1.0.0"}`,
		"index.js":     "exports.run = function run() {};\n",
	}}
	quiet := newDepFixture(t, map[string]string{"index.js": guardIdle}, plain)
	if cg := withDeps(t, quiet.dir, quiet.memStore()); !cg.Partiality.Complete {
		t.Errorf("control: nothing declined anywhere, yet partial: %+v", cg.Partiality)
	}
	hidden := newDepFixture(t, map[string]string{"index.js": "function main() { return missing(1); }\nmodule.exports = { main };\n"}, plain)
	if cg := withDeps(t, hidden.dir, hidden.memStore()); !hasReason(cg.Partiality, plugin.PartialReasonUnlistedSites) {
		t.Errorf("a first-party site declined beside dependency frames Escaped omits, without unlisted_sites: %+v", cg.Partiality)
	}
}
