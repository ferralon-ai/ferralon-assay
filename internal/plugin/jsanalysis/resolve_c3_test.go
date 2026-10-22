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
	// boundary lists the edges into package-boundary nodes (boundary.go), as caller and
	// boundary id; they are diffed apart from the first-party control.
	boundary [][2]string
}

// c3Baseline is the C3 control: 38 edges / 37 roots across 9 JS/TS fixtures. A re-run
// must reproduce it EXACTLY — every edge preserved (or a removal explained), and every
// ADDED edge rule-attributed. Besides the import-scoped first-party edges, it carries
// each module's top-level frame as a root (with edges to what top-level code calls),
// inline handler frames passed to get/createServer, and calls nested in callback
// arguments (fetchUrl → resolveTarget inside a Promise executor).
var c3Baseline = []c3Case{
	{
		fixture: "CVE-2022-24999-tool-unavailable",
		edges: []edgeSpec{
			{"app", nil, "handleSearch", 2, "app", nil, "parseQuery", 1},
			{"app", nil, "parseQuery", 1, "qs", nil, "parse", 1},
			{"app", nil, moduleInitFunc, 0, "app", nil, "makeApp", 0},
			{"app", nil, "makeApp", 0, "app", nil, anonHandlerFunc(29, 46), 2},
		},
		roots: []string{
			funcSCIP("app", nil, "handleSearch", 2),
			funcSCIP("app", nil, moduleInitFunc, 0),
			funcSCIP("qs", nil, moduleInitFunc, 0),
			funcSCIP("app", nil, anonHandlerFunc(29, 46), 2),
			funcSCIP("qs", nil, "parse", 1), // escape root (exported or class member)
		},
	},
	{
		fixture: "CVE-2022-46175-outofrange",
		edges: []edgeSpec{
			{"app", nil, "handleConfig", 2, "app", nil, "loadConfig", 1},
			{"app", nil, "loadConfig", 1, "json5", nil, "parse", 1},
			{"app", nil, moduleInitFunc, 0, "app", nil, "makeApp", 0},
			{"app", nil, "makeApp", 0, "app", nil, anonHandlerFunc(22, 46), 2},
		},
		roots: []string{
			funcSCIP("app", nil, "handleConfig", 2),
			funcSCIP("app", nil, moduleInitFunc, 0),
			funcSCIP("json5", nil, moduleInitFunc, 0),
			funcSCIP("app", nil, anonHandlerFunc(22, 46), 2),
			funcSCIP("json5", nil, "parse", 1), // escape root (exported or class member)
		},
	},
	{
		fixture: "CVE-2022-46175-reachable-direct",
		edges: []edgeSpec{
			{"app", nil, "handleConfig", 2, "app", nil, "loadConfig", 1},
			{"app", nil, "loadConfig", 1, "json5", nil, "parse", 1},
			{"app", nil, moduleInitFunc, 0, "app", nil, "makeApp", 0},
			{"app", nil, "makeApp", 0, "app", nil, anonHandlerFunc(22, 46), 2},
		},
		roots: []string{
			funcSCIP("app", nil, "handleConfig", 2),
			funcSCIP("app", nil, moduleInitFunc, 0),
			funcSCIP("json5", nil, moduleInitFunc, 0),
			funcSCIP("app", nil, anonHandlerFunc(22, 46), 2),
			funcSCIP("json5", nil, "parse", 1), // escape root (exported or class member)
		},
	},
	{
		fixture: "CVE-2023-26136-reachable-transitive",
		edges: []edgeSpec{
			{"app", nil, "handleLogin", 2, "app", nil, "storeSession", 1},
			{"app", nil, "storeSession", 1, "cookie", []string{"CookieJar"}, "setCookie", 2},
			{"app", nil, moduleInitFunc, 0, "app", nil, "makeApp", 0},
			{"app", nil, "makeApp", 0, "app", nil, anonHandlerFunc(24, 46), 2},
		},
		roots: []string{
			funcSCIP("app", nil, "handleLogin", 2),
			funcSCIP("app", nil, moduleInitFunc, 0),
			funcSCIP("cookie", nil, moduleInitFunc, 0),
			funcSCIP("app", nil, anonHandlerFunc(24, 46), 2),
			funcSCIP("cookie", []string{"CookieJar"}, "setCookie", 2), // escape root (exported or class member)
		},
	},
	{
		fixture: "CVE-2024-29041-installed-unreachable",
		edges:   nil,
		boundary: [][2]string{
			{funcSCIP("app", nil, moduleInitFunc, 0), "npm:express#<call>"},
			{funcSCIP("app", nil, moduleInitFunc, 0), "npm:express#<call>.use"},
			{funcSCIP("app", nil, moduleInitFunc, 0), "npm:express#json"},
			{funcSCIP("app", nil, moduleInitFunc, 0), "npm:express#<call>.get"},
			{funcSCIP("app", nil, moduleInitFunc, 0), "npm:express#<call>.post"},
			{funcSCIP("app", nil, moduleInitFunc, 0), "npm:express#<call>.listen"},
			{funcSCIP("app", nil, "handleHealth", 2), "npm:express#response.send"},
			{funcSCIP("app", nil, "handleEcho", 2), "npm:express#response.send"},
		},
		roots: []string{
			funcSCIP("app", nil, "handleEcho", 2),
			funcSCIP("app", nil, "handleHealth", 2),
			funcSCIP("app", nil, moduleInitFunc, 0),
		},
	},
	{
		fixture: "FERRALON-JS-NEXTRCE-0001-fixed",
		edges: []edgeSpec{
			{"server", nil, "handleRender", 2, "server", nil, "render", 1},
			{"server", nil, "render", 1, "require", nil, "requirePage", 2},
			{"require", nil, "requirePage", 2, "require", nil, "getPagePath", 2},
			{"server", nil, moduleInitFunc, 0, "server", nil, "makeApp", 0},
			{"server", nil, "makeApp", 0, "server", nil, anonHandlerFunc(22, 46), 2},
		},
		roots: []string{
			funcSCIP("server", nil, "handleRender", 2),
			funcSCIP("server", nil, moduleInitFunc, 0),
			funcSCIP("require", nil, moduleInitFunc, 0),
			funcSCIP("server", nil, anonHandlerFunc(22, 46), 2),
			funcSCIP("require", nil, "requirePage", 2), // escape root (exported or class member)
		},
	},
	{
		fixture: "FERRALON-JS-NEXTRCE-0001-vulnerable",
		edges: []edgeSpec{
			{"require", nil, "requireModule", 1, "require", nil, "resolvePath", 1},
			{"server", nil, "handleRender", 2, "server", nil, "render", 1},
			{"server", nil, "render", 1, "require", nil, "requireModule", 1},
			{"server", nil, moduleInitFunc, 0, "server", nil, "makeApp", 0},
			{"server", nil, "makeApp", 0, "server", nil, anonHandlerFunc(30, 46), 2},
		},
		roots: []string{
			funcSCIP("server", nil, "handleRender", 2),
			funcSCIP("server", nil, moduleInitFunc, 0),
			funcSCIP("require", nil, moduleInitFunc, 0),
			funcSCIP("server", nil, anonHandlerFunc(30, 46), 2),
			funcSCIP("require", nil, "requireModule", 1), // escape root (exported or class member)
		},
	},
	{
		fixture: "FERRALON-JS-SSRF-0001-patched",
		edges: []edgeSpec{
			{"app", nil, "handle", 1, "fetcher", nil, "fetchUrl", 1},
			{"app", nil, "handleFetch", 2, "app", nil, "handle", 1},
			{"fetcher", nil, "fetchUrl", 1, "fetcher", nil, "resolveTarget", 1},
			{"fetcher", nil, "fetchUrl", 1, "fetcher", nil, anonHandlerFunc(54, 42), 1},
			{"app", nil, moduleInitFunc, 0, "app", nil, "makeApp", 0},
			{"app", nil, "makeApp", 0, "app", nil, anonHandlerFunc(25, 46), 2},
		},
		roots: []string{
			funcSCIP("app", nil, "handleFetch", 2),
			funcSCIP("app", nil, moduleInitFunc, 0),
			funcSCIP("fetcher", nil, moduleInitFunc, 0),
			funcSCIP("app", nil, anonHandlerFunc(25, 46), 2),
			funcSCIP("fetcher", nil, anonHandlerFunc(54, 42), 1),
			funcSCIP("fetcher", nil, "fetchUrl", 1), // escape root (exported or class member)
		},
	},
	{
		fixture: "FERRALON-JS-SSRF-0001-vulnerable",
		edges: []edgeSpec{
			{"app", nil, "handle", 1, "fetcher", nil, "fetchUrl", 1},
			{"app", nil, "handleFetch", 2, "app", nil, "handle", 1},
			{"fetcher", nil, "fetchUrl", 1, "fetcher", nil, "resolveTarget", 1},
			{"fetcher", nil, "fetchUrl", 1, "fetcher", nil, anonHandlerFunc(51, 42), 1},
			{"app", nil, moduleInitFunc, 0, "app", nil, "makeApp", 0},
			{"app", nil, "makeApp", 0, "app", nil, anonHandlerFunc(25, 46), 2},
		},
		roots: []string{
			funcSCIP("app", nil, "handleFetch", 2),
			funcSCIP("app", nil, moduleInitFunc, 0),
			funcSCIP("fetcher", nil, moduleInitFunc, 0),
			funcSCIP("app", nil, anonHandlerFunc(25, 46), 2),
			funcSCIP("fetcher", nil, anonHandlerFunc(51, 42), 1),
			funcSCIP("fetcher", nil, "fetchUrl", 1), // escape root (exported or class member)
		},
	},
}

// TestC3_BaselineDiffPreservedWithProvenance is the C3(a) gate: re-run the import-scoped
// call graph over every baseline fixture and diff against the 38-edge/45-root control. It asserts NO baseline edge silently vanishes, NO unexpected edge is added,
// every root is preserved, and — the precision bar made structural — EVERY emitted edge
// carries a non-empty provenance algorithm (C5 tie-in): an edge exists only via a named
// rule, never a fabricated target.
func TestC3_BaselineDiffPreservedWithProvenance(t *testing.T) {
	totalEdges, totalRoots, totalBoundary := 0, 0, 0
	for _, tc := range c3Baseline {
		dir := "../../../corpus/testdata/repros/" + tc.fixture + "/src"
		res, prov, err := callGraphInternal(dir)
		if err != nil {
			t.Fatalf("%s: callGraphInternal: %v", tc.fixture, err)
		}

		got := map[string]bool{}
		firstParty := 0
		for _, e := range res.Edges {
			got[e.Caller.SCIP+" => "+e.Callee.SCIP] = true
			if !isBoundaryID(e.Callee.SCIP) {
				firstParty++
			}
			// C5: every edge must trace to a named rule.
			if prov[e].Algo == "" {
				t.Errorf("%s: edge %s => %s has EMPTY provenance algo (fabricated target?)", tc.fixture, e.Caller.SCIP, e.Callee.SCIP)
			}
		}
		want := map[string]bool{}
		for _, e := range tc.edges {
			want[e.caller()+" => "+e.callee()] = true
		}
		for _, b := range tc.boundary {
			want[b[0]+" => "+b[1]] = true
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
		if firstParty != len(tc.edges) {
			t.Errorf("%s: first-party edge count = %d, want %d", tc.fixture, firstParty, len(tc.edges))
		}
		if b := len(res.Edges) - firstParty; b != len(tc.boundary) {
			t.Errorf("%s: boundary edge count = %d, want %d", tc.fixture, b, len(tc.boundary))
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

		totalEdges += firstParty
		totalBoundary += len(res.Edges) - firstParty
		totalRoots += len(res.Roots)
	}
	if totalEdges != 38 {
		t.Errorf("total first-party edges across corpus = %d, want 38 (baseline control)", totalEdges)
	}
	if totalBoundary != 8 {
		t.Errorf("total boundary edges across corpus = %d, want 8", totalBoundary)
	}
	if totalRoots != 45 {
		t.Errorf("total roots across corpus = %d, want 45 (baseline control plus 8 escape roots)", totalRoots)
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
