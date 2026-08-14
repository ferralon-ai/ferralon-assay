package plugin

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// TestStubPluginConforms is the conformance assert at the value level: StubPlugin
// must satisfy LanguagePlugin (the package-level var enforces this at compile time;
// this test documents the intent and reports the language tag).
func TestStubPluginConforms(t *testing.T) {
	var p LanguagePlugin = StubPlugin{}
	if got := p.Language(); got != "go" {
		t.Fatalf("Language() = %q, want %q", got, "go")
	}
}

// TestStubLiveOpsCompleteShapes asserts the five live ops return Complete=true with
// the documented canned payload shapes (one Symbol, one ReachPath, one Ingress, a
// small CallGraph).
func TestStubLiveOpsCompleteShapes(t *testing.T) {
	ctx := context.Background()
	p := StubPlugin{}

	idx, err := p.IndexSymbols(ctx, IndexSymbolsRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	if !idx.Partiality.Complete {
		t.Errorf("IndexSymbols partiality = %+v, want Complete", idx.Partiality)
	}
	if len(idx.Symbols) != 1 {
		t.Errorf("IndexSymbols symbols = %d, want 1", len(idx.Symbols))
	}

	res, err := p.ResolveDependencySymbols(ctx, ResolveSymbolsRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if !res.Partiality.Complete || len(res.Resolved) != 1 {
		t.Errorf("ResolveDependencySymbols = %+v / %d resolved", res.Partiality, len(res.Resolved))
	}

	cg, err := p.CallGraph(ctx, CallGraphRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !cg.Partiality.Complete || len(cg.Edges) == 0 || len(cg.Roots) == 0 {
		t.Errorf("CallGraph = %+v / %d edges / %d roots", cg.Partiality, len(cg.Edges), len(cg.Roots))
	}

	ing, err := p.FindIngresses(ctx, FindIngressesRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if !ing.Partiality.Complete || len(ing.Ingresses) != 1 {
		t.Errorf("FindIngresses = %+v / %d", ing.Partiality, len(ing.Ingresses))
	}

	reach, err := p.Reachability(ctx, ReachabilityRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if !reach.Partiality.Complete || len(reach.Paths) != 1 {
		t.Errorf("Reachability = %+v / %d paths", reach.Partiality, len(reach.Paths))
	}
}

// TestStubUnsupportedOps asserts the three Phase-1 contract stubs return declared
// partiality: Complete=false with the PartialReasonUnsupported reason code.
func TestStubUnsupportedOps(t *testing.T) {
	ctx := context.Background()
	p := StubPlugin{}

	taint, err := p.ComputeTaint(ctx, ComputeTaintRequest{})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	assertUnsupported(t, "ComputeTaint", taint.Partiality)

	harness, err := p.GenerateHarness(ctx, GenerateHarnessRequest{})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	assertUnsupported(t, "GenerateHarness", harness.Partiality)

	mani, err := p.BuildManifest(ctx, BuildManifestRequest{})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	assertUnsupported(t, "BuildManifest", mani.Partiality)

	ver, err := p.ResolveDependencyVersions(ctx, ResolveVersionsRequest{})
	if err != nil {
		t.Fatalf("ResolveDependencyVersions: %v", err)
	}
	assertUnsupported(t, "ResolveDependencyVersions", ver.Partiality)
}

func assertUnsupported(t *testing.T, op string, p Partiality) {
	t.Helper()
	if p.Complete {
		t.Errorf("%s: Complete=true, want false (Unsupported)", op)
	}
	if len(p.Reasons) != 1 || p.Reasons[0] != PartialReasonUnsupported {
		t.Errorf("%s: reasons = %v, want [%s]", op, p.Reasons, PartialReasonUnsupported)
	}
}

// TestUnsupportedConstructor asserts Unsupported() ⇒ Complete=false with the
// canonical unsupported reason code.
func TestUnsupportedConstructor(t *testing.T) {
	p := Unsupported()
	if p.Complete {
		t.Errorf("Unsupported().Complete = true, want false")
	}
	if len(p.Reasons) != 1 || p.Reasons[0] != PartialReasonUnsupported {
		t.Errorf("Unsupported().Reasons = %v, want [%s]", p.Reasons, PartialReasonUnsupported)
	}
}

// TestPartialityConstructors covers Complete() and Partial().
func TestPartialityConstructors(t *testing.T) {
	if c := Complete(); !c.Complete || len(c.Reasons) != 0 {
		t.Errorf("Complete() = %+v, want {Complete:true}", c)
	}
	p := Partial(PartialReasonReflection, PartialReasonCgo)
	if p.Complete {
		t.Errorf("Partial().Complete = true, want false")
	}
	if !reflect.DeepEqual(p.Reasons, []string{PartialReasonReflection, PartialReasonCgo}) {
		t.Errorf("Partial().Reasons = %v", p.Reasons)
	}
}

// TestStubPartialVariant asserts the partial-variant StubPlugin flips the live
// results' Complete to false, so L3's seam test can exercise CandidatePair.Partial=true.
func TestStubPartialVariant(t *testing.T) {
	ctx := context.Background()
	p := StubPlugin{Partial: true}

	reach, err := p.Reachability(ctx, ReachabilityRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if reach.Partiality.Complete {
		t.Errorf("partial-variant Reachability Complete=true, want false")
	}
	if len(reach.Partiality.Reasons) == 0 {
		t.Errorf("partial-variant Reachability has no reasons")
	}

	// The partial variant still returns a payload (a reachable-but-partial path).
	if len(reach.Paths) != 1 {
		t.Errorf("partial-variant Reachability paths = %d, want 1", len(reach.Paths))
	}

	// Other live ops also flip.
	res, _ := p.ResolveDependencySymbols(ctx, ResolveSymbolsRequest{})
	if res.Partiality.Complete {
		t.Errorf("partial-variant ResolveDependencySymbols Complete=true, want false")
	}
}

// TestRequestJSONRoundTrip asserts a Request survives encoding/json round-trip
// unchanged (wire-protocol stability).
func TestRequestJSONRoundTrip(t *testing.T) {
	orig := Request{
		Protocol: ProtocolVersion,
		Op:       OpReachability,
		Reachability: &ReachabilityRequest{
			BuildDir: "/repo",
			VulnID:   "GO-2021-0001",
			Symbols:  []string{"scip:foo", "scip:bar"},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Request
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Errorf("Request round-trip mismatch:\n orig = %+v\n back = %+v", orig, back)
	}
}

// TestResponseJSONRoundTrip asserts a Response carrying a live payload survives the
// encoding/json round-trip unchanged.
func TestResponseJSONRoundTrip(t *testing.T) {
	orig := Response{
		Protocol: ProtocolVersion,
		Reachability: &ReachabilityResult{
			Partiality: Partial(PartialReasonReflection),
			Paths: []ReachPath{
				{
					Sink:    Symbol{Kind: SymbolKindFunction, Package: "example.com/dep", Name: "sink", SCIP: "scip:sink"},
					Ingress: Symbol{Kind: SymbolKindFunction, Package: "example.com/app", Name: "main", SCIP: "scip:main"},
					Trace: []Symbol{
						{Kind: SymbolKindFunction, Package: "example.com/app", Name: "main", SCIP: "scip:main"},
						{Kind: SymbolKindFunction, Package: "example.com/dep", Name: "sink", SCIP: "scip:sink"},
					},
				},
			},
		},
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Response
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(orig, back) {
		t.Errorf("Response round-trip mismatch:\n orig = %+v\n back = %+v", orig, back)
	}
}
