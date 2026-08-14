package jsanalysis

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- C3(b): same-name fixture — the edge must land on the IMPORTED target ---

// TestC3_SameNameLandsOnImportedTarget builds two modules that each export fetch(1);
// the caller imports fetch from ONE of them. Import-scoped resolution must land the edge
// on the imported module and NOT on the coincidental same-name/same-arity declaration in
// the other module. Under the OLD global (name,arity) resolver this was ambiguous (two
// candidates) and yielded NO edge; a broken new resolver yields the WRONG edge — so the
// assertion names the expected target rather than merely asserting an edge exists.
func TestC3_SameNameLandsOnImportedTarget(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"caller.js": `
const { fetch } = require('./client_a');
function run() {
    return fetch(url);
}
`,
		"client_a.js": `
function fetch(u) { return u; }
module.exports = { fetch };
`,
		"client_b.js": `
function fetch(u) { return u; }
module.exports = { fetch };
`,
	})
	res, prov, err := callGraphInternal(dir)
	if err != nil {
		t.Fatalf("callGraphInternal: %v", err)
	}
	run := funcSCIP("caller", nil, "run", 0)
	wantCallee := funcSCIP("client_a", nil, "fetch", 1)
	wrongCallee := funcSCIP("client_b", nil, "fetch", 1)

	if !hasEdge(res.Edges, run, wantCallee) {
		t.Errorf("expected edge run -> client_a.fetch (the IMPORTED target); edges=%+v", res.Edges)
	}
	if hasEdge(res.Edges, run, wrongCallee) {
		t.Errorf("resolver landed the edge on the WRONG same-name target client_b.fetch; edges=%+v", res.Edges)
	}
	// The imported edge must be attributed (cjs).
	for e, p := range prov {
		if e.Caller.SCIP == run && e.Callee.SCIP == wantCallee && p.Algo != algoCJS {
			t.Errorf("imported edge attributed to %q, want cjs", p.Algo)
		}
	}
}

// --- C3(c): computed require(var) — NO edge, declared partiality ---

// TestC3_ComputedRequireNoEdgeDeclaredPartial asserts a runtime-computed require target
// produces NO edge and a declared computed_require_specifier partiality — §3.1: never
// infer safety, never fabricate a target.
func TestC3_ComputedRequireNoEdgeDeclaredPartial(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"loader.js": `
const plugins = {};
function load(name) {
    const spec = plugins[name];
    return require(spec);
}
function register(name) { return name; }
`,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	// No edge may be fabricated out of the computed require.
	load := funcSCIP("loader", nil, "load", 1)
	for _, e := range res.Edges {
		if e.Caller.SCIP == load {
			t.Errorf("computed require fabricated an edge from load: %+v", e)
		}
	}
	if res.Partiality.Complete {
		t.Fatal("computed require must declare partiality, got Complete")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonComputedRequireSpecifier) {
		t.Errorf("computed require must carry computed_require_specifier; got %v", res.Partiality.Reasons)
	}
}

// --- C5: provenance on every edge + three distinct partiality reasons ---

// TestC5_ThreeDistinctPartialityReasons builds a module with one dynamic import(), one
// computed require(var), and one bare specifier into an uninspectable package that is
// then CALLED. The result must declare THREE DISTINCT reasons — not one blanket
// dynamic_dispatch — so a reviewer can tell which limit applies to which construct.
func TestC5_ThreeDistinctPartialityReasons(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"c5.js": `
import { debounce } from 'lodash';
const cfg = require(configPath);
const lazy = import('./' + variant);

function run() {
    return debounce(handler);
}
`,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if len(res.Edges) != 0 {
		t.Errorf("no first-party edge expected in the C5 fixture; got %+v", res.Edges)
	}
	want := []string{
		plugin.PartialReasonComputedRequireSpecifier,
		plugin.PartialReasonDynamicImportSpecifier,
		plugin.PartialReasonUninspectablePackage,
	}
	got := append([]string(nil), res.Partiality.Reasons...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("C5 reasons = %v, want three distinct %v", res.Partiality.Reasons, want)
	}
}

// TestC5_EveryEdgeHasProvenance asserts (over the SSRF repro) that every emitted edge has
// a non-empty producer algorithm, via the package-internal provenance side table — the
// wire CallEdge stays frozen.
func TestC5_EveryEdgeHasProvenance(t *testing.T) {
	dir := "../../../corpus/testdata/repros/TEGRON-JS-SSRF-0001-vulnerable/src"
	res, prov, err := callGraphInternal(dir)
	if err != nil {
		t.Fatalf("callGraphInternal: %v", err)
	}
	if len(res.Edges) == 0 {
		t.Fatal("expected edges in the SSRF repro")
	}
	for _, e := range res.Edges {
		if prov[e].Algo == "" {
			t.Errorf("edge %s => %s has no provenance algorithm", e.Caller.SCIP, e.Callee.SCIP)
		}
	}
}

// --- C1: conditional exports / imports resolution ---

// TestC1_ExportsTable is the table-driven exports/imports resolver test over hand-built
// package.json fields, including the unexported-subpath NEGATIVE and the condition-flip
// control.
func TestC1_ExportsTable(t *testing.T) {
	obj := func(v string) interface{} {
		var out interface{}
		mustJSON(t, v, &out)
		return out
	}
	cases := []struct {
		name       string
		field      interface{}
		subpath    string
		conditions []string
		wantTarget string
		wantConds  []string
		wantOK     bool
	}{
		{
			name:    "exports string resolves dot",
			field:   obj(`"./index.js"`),
			subpath: ".", conditions: []string{"import", "default"},
			wantTarget: "./index.js", wantOK: true,
		},
		{
			name:    "exports string does NOT expose an unexported subpath (negative)",
			field:   obj(`"./index.js"`),
			subpath: "./secret", conditions: []string{"import", "default"},
			wantOK: false,
		},
		{
			name:    "conditional object selects import",
			field:   obj(`{"import":"./a.mjs","require":"./a.cjs","default":"./a.js"}`),
			subpath: ".", conditions: []string{"import", "default"},
			wantTarget: "./a.mjs", wantConds: []string{"import"}, wantOK: true,
		},
		{
			name:    "condition flip selects require (control)",
			field:   obj(`{"import":"./a.mjs","require":"./a.cjs","default":"./a.js"}`),
			subpath: ".", conditions: []string{"require", "default"},
			wantTarget: "./a.cjs", wantConds: []string{"require"}, wantOK: true,
		},
		{
			name:    "subpath pattern ./* expands",
			field:   obj(`{"./features/*":"./src/features/*.js"}`),
			subpath: "./features/login", conditions: []string{"default"},
			wantTarget: "./src/features/login.js", wantOK: true,
		},
		{
			name:    "declared exports map hides an unexported subpath (negative)",
			field:   obj(`{".":"./index.js","./public":"./src/public.js"}`),
			subpath: "./private", conditions: []string{"default"},
			wantOK: false,
		},
		{
			name:    "imports entry #internal resolves",
			field:   obj(`{"#internal":"./src/internal.js"}`),
			subpath: "#internal", conditions: []string{"default"},
			wantTarget: "./src/internal.js", wantOK: true,
		},
		{
			name:    "nested condition object under subpath",
			field:   obj(`{".":{"node":{"import":"./node.mjs"},"default":"./browser.js"}}`),
			subpath: ".", conditions: []string{"import", "node", "default"},
			wantTarget: "./node.mjs", wantConds: []string{"node", "import"}, wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, conds, ok := resolveExportsField(tc.field, tc.subpath, tc.conditions)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v, want %v (target=%q)", ok, tc.wantOK, target)
			}
			if !ok {
				return
			}
			if target != tc.wantTarget {
				t.Errorf("target=%q, want %q", target, tc.wantTarget)
			}
			if tc.wantConds != nil && !reflect.DeepEqual(conds, tc.wantConds) {
				t.Errorf("conditions=%v, want %v", conds, tc.wantConds)
			}
		})
	}
}

// TestC1_ImportsLiveResolvesFirstParty exercises the LIVE resolver: a module importing a
// `#internal` specifier resolves through the package.json imports map to a first-party
// module and emits an attributed edge (algoImports) with the condition set recorded.
func TestC1_ImportsLiveResolvesFirstParty(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"package.json": `{"name":"app","imports":{"#util":"./util.js"}}`,
		"main.js": `
const { helper } = require('#util');
function run() { return helper(x); }
`,
		"util.js": `
function helper(v) { return v; }
module.exports = { helper };
`,
	})
	_, prov, err := callGraphInternal(dir)
	if err != nil {
		t.Fatalf("callGraphInternal: %v", err)
	}
	run := funcSCIP("main", nil, "run", 0)
	helper := funcSCIP("util", nil, "helper", 1)
	found := false
	for e, p := range prov {
		if e.Caller.SCIP == run && e.Callee.SCIP == helper {
			found = true
			if p.Algo != algoImports {
				t.Errorf("#util edge attributed to %q, want imports", p.Algo)
			}
		}
	}
	if !found {
		t.Errorf("expected run -> util.helper via #util imports map")
	}
}

// --- C2: tsconfig paths/baseUrl/extends per workspace member ---

// TestC2_WorkspaceMembersResolveOwnPaths asserts two members declaring the SAME alias to
// DIFFERENT targets each resolve to their own target, and that member A does NOT resolve
// through member B's mapping (the cross-member negative a merged-config resolver fails).
func TestC2_WorkspaceMembersResolveOwnPaths(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"packages/a/tsconfig.json": `{"compilerOptions":{"baseUrl":".","paths":{"@shared/*":["shared/*"]}}}`,
		"packages/a/src/a.ts": `
import { shared } from '@shared/util';
function run() { return shared(); }
`,
		"packages/a/shared/util.ts": `export function shared() { return 1; }`,
		"packages/b/tsconfig.json":  `{"compilerOptions":{"baseUrl":".","paths":{"@shared/*":["lib/*"]}}}`,
		"packages/b/src/b.ts": `
import { shared } from '@shared/util';
function run() { return shared(); }
`,
		"packages/b/lib/util.ts": `export function shared() { return 2; }`,
	})
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	rs := prog.resolver()

	aRes := rs.ResolveCall("packages/a/src/a", "shared", 0)
	if aRes.Kind != resolveFirstParty {
		t.Fatalf("member A alias did not resolve first-party: %+v", aRes)
	}
	if aRes.Module != "packages/a/shared/util" {
		t.Errorf("member A resolved to %q, want packages/a/shared/util", aRes.Module)
	}
	if aRes.Prov.Algo != algoPathsAlias || aRes.Prov.Tsconfig != "packages/a/tsconfig.json" {
		t.Errorf("member A provenance = %+v, want paths_alias governed by packages/a/tsconfig.json", aRes.Prov)
	}

	bRes := rs.ResolveCall("packages/b/src/b", "shared", 0)
	if bRes.Module != "packages/b/lib/util" {
		t.Errorf("member B resolved to %q, want packages/b/lib/util (its own target)", bRes.Module)
	}
	if bRes.Prov.Tsconfig != "packages/b/tsconfig.json" {
		t.Errorf("member B governed by %q, want packages/b/tsconfig.json", bRes.Prov.Tsconfig)
	}

	// Cross-member negative: A must NOT resolve through B's lib target.
	if aRes.Module == "packages/b/lib/util" {
		t.Error("member A resolved through member B's mapping (config merge leak)")
	}
}

// TestC2_ExtendsChain asserts a member whose tsconfig extends a base tsconfig resolves an
// alias declared in the base — the extends chain is followed.
func TestC2_ExtendsChain(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"tsconfig.base.json": `{"compilerOptions":{"baseUrl":".","paths":{"@core/*":["core/*"]}}}`,
		"tsconfig.json":      `{"extends":"./tsconfig.base.json"}`,
		"app.ts": `
import { core } from '@core/lib';
function run() { return core(); }
`,
		"core/lib.ts": `export function core() { return 1; }`,
	})
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	res := prog.resolver().ResolveCall("app", "core", 0)
	if res.Kind != resolveFirstParty || res.Module != "core/lib" {
		t.Fatalf("extends-chain alias did not resolve to core/lib: %+v", res)
	}
	if res.Prov.Algo != algoPathsAlias {
		t.Errorf("extends-chain edge attributed to %q, want paths_alias", res.Prov.Algo)
	}
}

// --- C4: module-mode / extension precedence matrix ---

// TestC4_ModuleModeMatrix asserts the {no type, module, commonjs} × {.js,.mjs,.cjs,.ts}
// mode matrix, including cells that DIFFER from the extension's default (precedence is
// actually evaluated, not just the extension read).
func TestC4_ModuleModeMatrix(t *testing.T) {
	cases := []struct {
		pkgType string
		ext     string
		want    string
	}{
		{"", ".js", "cjs"},
		{"module", ".js", "esm"},    // differs from .js default (cjs) — type wins
		{"commonjs", ".js", "cjs"},  //
		{"", ".mjs", "esm"},         //
		{"module", ".mjs", "esm"},   //
		{"commonjs", ".mjs", "esm"}, // extension wins over type (differs from commonjs)
		{"", ".cjs", "cjs"},         //
		{"module", ".cjs", "cjs"},   // extension wins over type (differs from module)
		{"commonjs", ".cjs", "cjs"},
		{"", ".ts", "cjs"},
		{"module", ".ts", "esm"}, // differs from .ts default (cjs)
		{"commonjs", ".ts", "cjs"},
	}
	differsFromExtDefault := 0
	extDefault := map[string]string{".js": "cjs", ".mjs": "esm", ".cjs": "cjs", ".ts": "cjs"}
	for _, tc := range cases {
		got := determineModuleMode(tc.pkgType, tc.ext, "")
		if got != tc.want {
			t.Errorf("mode(type=%q ext=%q) = %q, want %q", tc.pkgType, tc.ext, got, tc.want)
		}
		if got != extDefault[tc.ext] {
			differsFromExtDefault++
		}
	}
	if differsFromExtDefault == 0 {
		t.Error("no matrix cell differs from the extension default — precedence is not being tested")
	}
	// tsconfig module setting drives .ts mode when present.
	if determineModuleMode("", ".ts", "commonjs") != "cjs" {
		t.Error(".ts under tsconfig module=commonjs should be cjs")
	}
	if determineModuleMode("", ".ts", "esnext") != "esm" {
		t.Error(".ts under tsconfig module=esnext should be esm")
	}
}

func mustJSON(t *testing.T, s string, v interface{}) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("bad test JSON %q: %v", s, err)
	}
}
