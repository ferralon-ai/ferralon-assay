package javaanalysis

import (
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// springIndexFixture is the REAL index.scip emitted by scip-java 0.10.3 over the
// TEGRON-JAVA-SPRING-SSRF-0001 repro (committed verbatim, 30262 bytes). It is the
// authoritative parser fixture: a hand-crafted sample previously masked the fact
// that scip-java emits NAME-only definition ranges and no enclosing_range/
// enclosing_symbol, so the parser must derive enclosing methods positionally. The
// repro shape it indexes: a @RestController route (FetchController#fetch) calls an
// @Autowired interface method (UrlService#fetch) whose SymbolInformation carries
// an is_implementation relationship to the concrete UrlServiceImpl#fetch (the SSRF
// sink) — the dynamic-dispatch hop pure-Go lexical analysis cannot resolve.
const springIndexFixture = "testdata/real-scip-java-spring.index.scip"

// canonical plugin SCIP ids for the three methods (arity form, local coordinate)
// — the id space scipindex.canonicalizeSCIP rewrites scip-java symbols into, and
// the same space the pure-Go emitter and the resolved advisory sink use.
const (
	canonIface = "scip-java maven . . com/example/web/UrlService#fetch()."
	canonImpl  = "scip-java maven . . com/example/web/UrlServiceImpl#fetch()."
	canonCtrl  = "scip-java maven . . com/example/web/FetchController#fetch()."
)

// TestReadSCIPIndex_ResolvesInterfaceToImplEdge is the CORE Increment-3 regression
// guard, run against the REAL scip-java index (not a hand-crafted fixture). It
// asserts the reader produces (1) the call-site→enclosing-method edge
// (FetchController#fetch → UrlService#fetch — proving positional enclosing-method
// attribution works on scip-java's name-only definition ranges) and (2) the
// resolved interface→impl dispatch edge (UrlService#fetch → UrlServiceImpl#fetch,
// from the is_implementation relationship), so a directed path connects the
// @RestController ingress to the concrete SSRF sink — exactly the CandidatePair
// ingredient lexical analysis declares Partial(dynamic_dispatch) on. A parser that
// passes on synthetic data but extracts zero edges from real output (the original
// bug) now fails here.
func TestReadSCIPIndex_ResolvesInterfaceToImplEdge(t *testing.T) {
	data, err := os.ReadFile(springIndexFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := readSCIPIndex(data)
	if err != nil {
		t.Fatalf("readSCIPIndex: %v", err)
	}

	// The real index must yield a non-empty resolved graph — the EDGES=0 symptom
	// of the original bug fails this immediately.
	if len(g.edges) == 0 {
		t.Fatalf("real scip-java index parsed to ZERO edges (the original bug); want a resolved graph")
	}

	has := func(caller, callee string) bool {
		for _, e := range g.edges {
			if e.Caller.SCIP == caller && e.Callee.SCIP == callee {
				return true
			}
		}
		return false
	}

	// (1) call-site reference attributed to its ENCLOSING method: the svc.fetch(...)
	// call inside FetchController.fetch is a reference to UrlService#fetch, so the
	// edge is FetchController#fetch → UrlService#fetch.
	if !has(canonCtrl, canonIface) {
		t.Errorf("missing call-site→enclosing-method edge %q → %q; edges=%+v", canonCtrl, canonIface, g.edges)
	}
	// (2) the resolved dynamic dispatch from SymbolInformation.relationships
	// (is_implementation): interface method → concrete impl method.
	if !has(canonIface, canonImpl) {
		t.Errorf("missing resolved interface→impl dispatch edge %q → %q; edges=%+v", canonIface, canonImpl, g.edges)
	}

	// The @GetMapping route method must surface as an http_route ingress in the
	// canonical id space.
	gotIngress := false
	for _, in := range g.ingresses {
		if in.Symbol.SCIP == canonCtrl && in.Kind == "http_route" {
			gotIngress = true
		}
	}
	if !gotIngress {
		t.Errorf("expected http_route ingress for %q; got %+v", canonCtrl, g.ingresses)
	}

	// End-to-end reachability: the impl sink must be reachable from the ingress
	// over the resolved edges — the property firstPartyReachPaths turns into a
	// CandidatePair. This is the WHOLE point of the container-backed graph, and it
	// confirms canonicalization connects the resolved edge into the sink id space.
	if !reverseReachable(g.edges, map[string]bool{canonCtrl: true}, canonImpl) {
		t.Fatalf("impl sink %q NOT reachable from ingress %q over resolved edges; edges=%+v", canonImpl, canonCtrl, g.edges)
	}
}

// TestReadSCIPIndex_CanonicalizationConnectsToPureGoSink is the FULL-chain check:
// the impl-fetch id the SCIP reader resolves (real index → readSCIPIndex →
// canonicalizeSCIP) must be byte-identical to the canonical id the pure-Go emitter
// produces for the same method. If canonicalization drifted, the resolved edge
// would exist but never connect ingress→sink and reachability would silently fail
// — so we pin the id equality the pipeline's SCIP-equality reachability relies on.
func TestReadSCIPIndex_CanonicalizationConnectsToPureGoSink(t *testing.T) {
	// The pure-Go emitter's id for com.example.web.UrlServiceImpl#fetch().
	pureGoSink := scipSymbol("com.example.web", []string{"UrlServiceImpl"}, methodDescriptor("fetch", 0))
	if pureGoSink != canonImpl {
		t.Fatalf("pure-Go emitter sink id %q != canonical impl id %q (canonicalization/emitter drift)", pureGoSink, canonImpl)
	}

	data, err := os.ReadFile(springIndexFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := readSCIPIndex(data)
	if err != nil {
		t.Fatalf("readSCIPIndex: %v", err)
	}
	// The resolved sink id must appear as a node in the SCIP-resolved graph, id-
	// equal to the pure-Go sink — the CandidatePair (ingress→sink) the pipeline forms.
	sinkIsNode := false
	for _, e := range g.edges {
		if e.Caller.SCIP == pureGoSink || e.Callee.SCIP == pureGoSink {
			sinkIsNode = true
		}
	}
	if !sinkIsNode {
		t.Fatalf("pure-Go sink id %q is not a node in the SCIP-resolved graph; canonicalization does not connect to the sink", pureGoSink)
	}
	if !reverseReachable(g.edges, map[string]bool{canonCtrl: true}, pureGoSink) {
		t.Fatalf("CandidatePair broken: pure-Go sink %q NOT reachable from ingress %q over the resolved graph", pureGoSink, canonCtrl)
	}
}

// TestReadSCIPIndex_Malformed asserts a truncated index is a tool failure (error),
// not a silent empty success — the caller maps this to Partial(tool_failure),
// never a fabricated edge (inv.5).
func TestReadSCIPIndex_Malformed(t *testing.T) {
	if _, err := readSCIPIndex([]byte{0x12, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("expected error on truncated SCIP index, got nil")
	}
}

// TestCanonicalizeSCIP asserts scip-java symbols are rewritten into the plugin's
// canonical (arity-based, local-coordinate) id space so resolved edges are id-
// equal to the pure-Go call graph and the resolved sink.
func TestCanonicalizeSCIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"scip-java maven com.example/spring-ssrf 0.0.1 com/example/web/UrlServiceImpl#fetch().", canonImpl},
		{"scip-java maven com.example/spring-ssrf 0.0.1 com/example/web/UrlService#fetch().", canonIface},
		// a one-arg erased descriptor maps to arity 1.
		{"scip-java maven g/a 1 p/T#m(java.lang.String).", "scip-java maven . . p/T#m(1)."},
	}
	for _, c := range cases {
		if got := canonicalizeSCIP(c.in); got != c.want {
			t.Errorf("canonicalizeSCIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSCIPResolveGate_Unset asserts the Prove gate is closed when the analyzer
// image env is unset: scipJavaResolve returns gated=false WITHOUT invoking docker,
// so Assess stays byte-identical pure-Go.
func TestSCIPResolveGate_Unset(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "")
	_, gated, ok := scipJavaResolve(t.Context(), reproSrc)
	if gated || ok {
		t.Fatalf("env unset: gated=%v ok=%v, want both false (pure-Go only)", gated, ok)
	}
}

// TestSCIPResolveGate_SetNoDocker asserts that when the gate IS set but the
// docker binary is absent/unrunnable, scipJavaResolve reports gated=true ok=false
// — the caller's signal to keep the lexical graph and declare
// Partial(tool_failure), never a fabricated edge.
func TestSCIPResolveGate_SetNoDocker(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "tegron-java-analyzer@sha256:deadbeef")
	t.Setenv(scipDockerBinEnv, "tegron-no-such-docker-binary-xyz")
	_, gated, ok := scipJavaResolve(t.Context(), reproSrc)
	if !gated {
		t.Fatalf("env set: gated=%v, want true", gated)
	}
	if ok {
		t.Fatalf("no docker: ok=%v, want false (tool_failure fallback)", ok)
	}
}

// TestCallGraph_GateUnset_ByteIdentical asserts CallGraph with the gate UNSET is
// the pure-Go lexical result (Algorithm source-lexical) — the free Assess image
// is unchanged by Increment 3.
func TestCallGraph_GateUnset_ByteIdentical(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "")
	cg, err := CallGraph(t.Context(), plugin.CallGraphRequest{BuildDir: reproSrc})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if cg.Algorithm != "source-lexical" {
		t.Errorf("gate unset: Algorithm=%q, want source-lexical (pure-Go)", cg.Algorithm)
	}
}

// TestCallGraph_GateSetNoDocker_ToolFailure asserts CallGraph with the gate SET
// but docker absent keeps the lexical edges and declares Partial(tool_failure) —
// honest degradation, never a fabricated edge.
func TestCallGraph_GateSetNoDocker_ToolFailure(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "tegron-java-analyzer@sha256:deadbeef")
	t.Setenv(scipDockerBinEnv, "tegron-no-such-docker-binary-xyz")
	cg, err := CallGraph(t.Context(), plugin.CallGraphRequest{BuildDir: reproSrc})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if cg.Partiality.Complete {
		t.Errorf("gate set, docker absent: Partiality=Complete, want Partial(tool_failure)")
	}
	found := false
	for _, r := range cg.Partiality.Reasons {
		if r == plugin.PartialReasonToolFailure {
			found = true
		}
	}
	if !found {
		t.Errorf("gate set, docker absent: reasons=%v, want tool_failure", cg.Partiality.Reasons)
	}
}
