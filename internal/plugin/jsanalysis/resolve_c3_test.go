package jsanalysis

import (
	"sort"
	"testing"
)

// edgeSpec is one expected edge described by its endpoints' constituent parts, so the
// expected SCIP is built by the SAME emitter (funcSCIP) the graph uses — a typo-proof,
// self-consistent baseline.
type edgeSpec struct {
	callerModule    string
	callerEnclosing []string
	callerName      string
	callerArity     int
	calleeModule    string
	calleeEnclosing []string
	calleeName      string
	calleeArity     int
}

func (e edgeSpec) caller() string {
	return funcSCIP(e.callerModule, e.callerEnclosing, e.callerName, e.callerArity)
}
func (e edgeSpec) callee() string {
	return funcSCIP(e.calleeModule, e.calleeEnclosing, e.calleeName, e.calleeArity)
}

// c3Case is one baseline fixture's expected edges and roots (findings/callgraph-baseline.md).
type c3Case struct {
	fixture string
	edges   []edgeSpec
	roots   []string // caller-style SCIPs
}

// c3Baseline is the frozen C3 control: 17 edges / 10 roots across 9 JS/TS fixtures,
// captured BEFORE the rewrite. A post-rewrite re-run must reproduce it EXACTLY — every
// edge preserved (or a removal explained), and every ADDED edge rule-attributed. There
// are no additions or removals expected: import-scoped resolution reproduces the same
// first-party edges the sound global resolver produced on this corpus.
var c3Baseline = []c3Case{
	{
		fixture: "CVE-2022-24999-tool-unavailable",
		edges: []edgeSpec{
			{"app", nil, "handleSearch", 2, "app", nil, "parseQuery", 1},
			{"app", nil, "parseQuery", 1, "qs", nil, "parse", 1},
		},
		roots: []string{funcSCIP("app", nil, "handleSearch", 2)},
	},
	{
		fixture: "CVE-2022-46175-outofrange",
		edges: []edgeSpec{
			{"app", nil, "handleConfig", 2, "app", nil, "loadConfig", 1},
			{"app", nil, "loadConfig", 1, "json5", nil, "parse", 1},
		},
		roots: []string{funcSCIP("app", nil, "handleConfig", 2)},
	},
	{
		fixture: "CVE-2022-46175-reachable-direct",
		edges: []edgeSpec{
			{"app", nil, "handleConfig", 2, "app", nil, "loadConfig", 1},
			{"app", nil, "loadConfig", 1, "json5", nil, "parse", 1},
		},
		roots: []string{funcSCIP("app", nil, "handleConfig", 2)},
	},
	{
		fixture: "CVE-2023-26136-reachable-transitive",
		edges: []edgeSpec{
			{"app", nil, "handleLogin", 2, "app", nil, "storeSession", 1},
			{"app", nil, "storeSession", 1, "cookie", []string{"CookieJar"}, "setCookie", 2},
		},
		roots: []string{funcSCIP("app", nil, "handleLogin", 2)},
	},
	{
		fixture: "CVE-2024-29041-installed-unreachable",
		edges:   nil,
		roots: []string{
			funcSCIP("app", nil, "handleEcho", 2),
			funcSCIP("app", nil, "handleHealth", 2),
		},
	},
	{
		fixture: "TEGRON-JS-NEXTRCE-0001-fixed",
		edges: []edgeSpec{
			{"server", nil, "handleRender", 2, "server", nil, "render", 1},
			{"server", nil, "render", 1, "require", nil, "requirePage", 2},
		},
		roots: []string{funcSCIP("server", nil, "handleRender", 2)},
	},
	{
		fixture: "TEGRON-JS-NEXTRCE-0001-vulnerable",
		edges: []edgeSpec{
			{"require", nil, "requireModule", 1, "require", nil, "resolvePath", 1},
			{"server", nil, "handleRender", 2, "server", nil, "render", 1},
			{"server", nil, "render", 1, "require", nil, "requireModule", 1},
		},
		roots: []string{funcSCIP("server", nil, "handleRender", 2)},
	},
	{
		fixture: "TEGRON-JS-SSRF-0001-patched",
		edges: []edgeSpec{
			{"app", nil, "handle", 1, "fetcher", nil, "fetchUrl", 1},
			{"app", nil, "handleFetch", 2, "app", nil, "handle", 1},
		},
		roots: []string{funcSCIP("app", nil, "handleFetch", 2)},
	},
	{
		fixture: "TEGRON-JS-SSRF-0001-vulnerable",
		edges: []edgeSpec{
			{"app", nil, "handle", 1, "fetcher", nil, "fetchUrl", 1},
			{"app", nil, "handleFetch", 2, "app", nil, "handle", 1},
		},
		roots: []string{funcSCIP("app", nil, "handleFetch", 2)},
	},
}

// TestC3_BaselineDiffPreservedWithProvenance is the C3(a) gate: re-run the import-scoped
// call graph over every baseline fixture and diff against the frozen 17-edge/10-root
// control. It asserts NO baseline edge silently vanishes, NO unexpected edge is added,
// every root is preserved, and — the precision bar made structural — EVERY emitted edge
// carries a non-empty provenance algorithm (C5 tie-in): an edge exists only via a named
// rule, never a fabricated target.
func TestC3_BaselineDiffPreservedWithProvenance(t *testing.T) {
	totalEdges, totalRoots := 0, 0
	for _, tc := range c3Baseline {
		dir := "../../../corpus/testdata/repros/" + tc.fixture + "/src"
		res, prov, err := callGraphInternal(dir)
		if err != nil {
			t.Fatalf("%s: callGraphInternal: %v", tc.fixture, err)
		}

		got := map[string]bool{}
		for _, e := range res.Edges {
			got[e.Caller.SCIP+" => "+e.Callee.SCIP] = true
			// C5: every edge must trace to a named rule.
			if prov[e].Algo == "" {
				t.Errorf("%s: edge %s => %s has EMPTY provenance algo (fabricated target?)", tc.fixture, e.Caller.SCIP, e.Callee.SCIP)
			}
		}
		want := map[string]bool{}
		for _, e := range tc.edges {
			want[e.caller()+" => "+e.callee()] = true
		}
		for k := range want {
			if !got[k] {
				t.Errorf("%s: baseline edge SILENTLY VANISHED: %s", tc.fixture, k)
			}
		}
		for k := range got {
			if !want[k] {
				t.Errorf("%s: UNEXPECTED edge added without baseline entry: %s", tc.fixture, k)
			}
		}
		if len(res.Edges) != len(tc.edges) {
			t.Errorf("%s: edge count = %d, want %d", tc.fixture, len(res.Edges), len(tc.edges))
		}

		gotRoots := map[string]bool{}
		for _, r := range res.Roots {
			gotRoots[r.SCIP] = true
		}
		for _, r := range tc.roots {
			if !gotRoots[r] {
				t.Errorf("%s: baseline root missing: %s (got %v)", tc.fixture, r, res.Roots)
			}
		}
		if len(res.Roots) != len(tc.roots) {
			t.Errorf("%s: root count = %d, want %d (%v)", tc.fixture, len(res.Roots), len(tc.roots), res.Roots)
		}

		totalEdges += len(res.Edges)
		totalRoots += len(res.Roots)
	}
	// The corpus totals the researcher captured: 17 edges, 10 roots.
	if totalEdges != 17 {
		t.Errorf("total edges across corpus = %d, want 17 (baseline control)", totalEdges)
	}
	if totalRoots != 10 {
		t.Errorf("total roots across corpus = %d, want 10 (baseline control)", totalRoots)
	}
}

// TestC3_ProvenanceAlgosAttributeEveryEdge records WHICH rule each baseline edge is
// attributed to, so the diff is not merely "present" but "attributed to a named rule".
// Same-module calls resolve via algoLocal; imported-name calls via cjs/esm; the method
// call on an imported class (setCookie) via cjs.
func TestC3_ProvenanceAlgosAttributeEveryEdge(t *testing.T) {
	dir := "../../../corpus/testdata/repros/CVE-2023-26136-reachable-transitive/src"
	_, prov, err := callGraphInternal(dir)
	if err != nil {
		t.Fatalf("callGraphInternal: %v", err)
	}
	seen := map[resolveAlgo]bool{}
	for _, p := range prov {
		seen[p.Algo] = true
	}
	// handleLogin->storeSession is same-module (local); storeSession->CookieJar.setCookie
	// is a method on a require()'d class (cjs).
	if !seen[algoLocal] {
		t.Errorf("expected a same-module (local) attribution in %s; got %v", dir, sortedAlgos(seen))
	}
	if !seen[algoCJS] {
		t.Errorf("expected a cjs attribution for the imported CookieJar method; got %v", sortedAlgos(seen))
	}
}

func sortedAlgos(seen map[resolveAlgo]bool) []string {
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, string(a))
	}
	sort.Strings(out)
	return out
}
