// internal/pipeline/plugin_seam_test.go
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestPluginSeam_SymbolMappingResolvesViaPlugin proves that when a LanguagePlugin is
// injected, symbol_mapping writes the plugin-resolved symbol as the real
// vulnerable_symbol artifact type (not the hardcoded stub symbol).
func TestPluginSeam_SymbolMappingResolvesViaPlugin(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-1"}
	c.Request.Vulnerability = assessment.VulnRef{ID: "GO-2021-0001", Source: "osv"}

	stage := symbolMapping{plugin: plugin.StubPlugin{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}

	syms, err := store.Query(c.ID, artifact.TypeVulnerableSymbol)
	if err != nil || len(syms) != 1 {
		t.Fatalf("want 1 vulnerable_symbol artifact, got %d (err=%v)", len(syms), err)
	}
	var got struct {
		Resolved []plugin.Symbol `json:"resolved"`
	}
	if err := json.Unmarshal(syms[0].Payload, &got); err != nil {
		t.Fatalf("decode resolved symbols: %v", err)
	}
	if len(got.Resolved) != 1 || got.Resolved[0].SCIP != "scip:vuln#Vulnerable" {
		t.Fatalf("want stub-resolved symbol, got %+v", got.Resolved)
	}
}

// TestPluginSeam_ReachabilityEmitsCompletePair proves the reachability_ingress stage,
// driven by the (complete) StubPlugin, writes a CandidatePair whose refs resolve and
// whose Partial=false.
func TestPluginSeam_ReachabilityEmitsCompletePair(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-2"}
	c.Request.Vulnerability = assessment.VulnRef{ID: "GO-2021-0001", Source: "osv"}

	// Upstream symbol_mapping (also plugin-driven) anchors the sink.
	if err := (symbolMapping{plugin: plugin.StubPlugin{}}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("symbol_mapping: %v", err)
	}
	if err := (reachabilityIngress{plugin: plugin.StubPlugin{}}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("reachability_ingress: %v", err)
	}

	pairs, err := store.Query(c.ID, artifact.TypeCandidatePair)
	if err != nil || len(pairs) != 1 {
		t.Fatalf("want 1 candidate_pair, got %d (err=%v)", len(pairs), err)
	}
	var pair artifact.CandidatePair
	if err := json.Unmarshal(pairs[0].Payload, &pair); err != nil {
		t.Fatalf("decode candidate_pair: %v", err)
	}
	if pair.Partial {
		t.Fatalf("complete stub must yield Partial=false, got true")
	}
	if pair.SchemaVersion != artifact.CandidatePairSchemaVersion {
		t.Fatalf("schema version = %q", pair.SchemaVersion)
	}
	// Refs must resolve to stored artifacts.
	for _, r := range []artifact.Ref{pair.Sink, pair.Path} {
		if r.ID == "" {
			t.Fatalf("ref has empty ID: %+v", r)
		}
		if _, err := store.Get(r.ID); err != nil {
			t.Fatalf("ref %s does not resolve: %v", r.ID, err)
		}
	}
	if pair.Ingress == nil {
		t.Fatal("complete stub path has a known ingress, want non-nil Ingress leg")
	}
	if _, err := store.Get(pair.Ingress.ID); err != nil {
		t.Fatalf("ingress ref does not resolve: %v", err)
	}
}

// TestPluginSeam_PartialVariantSetsPartialTrue proves the StubPlugin partial variant
// maps declared partiality onto CandidatePair.Partial=true.
func TestPluginSeam_PartialVariantSetsPartialTrue(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-3"}

	if err := (symbolMapping{plugin: plugin.StubPlugin{Partial: true}}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("symbol_mapping: %v", err)
	}
	if err := (reachabilityIngress{plugin: plugin.StubPlugin{Partial: true}}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("reachability_ingress: %v", err)
	}

	pairs, _ := store.Query(c.ID, artifact.TypeCandidatePair)
	if len(pairs) != 1 {
		t.Fatalf("want 1 candidate_pair, got %d", len(pairs))
	}
	var pair artifact.CandidatePair
	if err := json.Unmarshal(pairs[0].Payload, &pair); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !pair.Partial {
		t.Fatalf("partial stub must yield Partial=true, got false")
	}
}

// resolveSpyPlugin wraps StubPlugin and records the ResolveSymbolsRequest for inspection.
// It returns only the Symbol whose DisplayName matches one of the requested AdvisorySymbols,
// so tests can assert that forwarding the advisory symbols actually drives the filtered result.
type resolveSpyPlugin struct {
	plugin.StubPlugin
	capturedReq plugin.ResolveSymbolsRequest
}

func (p *resolveSpyPlugin) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	p.capturedReq = req
	// Return only symbols whose DisplayName appears in req.AdvisorySymbols so the test can
	// distinguish "filter applied" from "filter bypassed".
	var resolved []plugin.Symbol
	for _, sym := range []plugin.Symbol{
		{SCIP: "scip:vuln#Vulnerable", DisplayName: "archive/zip.(*Reader).Open", Package: "archive/zip"},
		{SCIP: "scip:other#Unrelated", DisplayName: "other.Fn", Package: "other"},
	} {
		for _, want := range req.AdvisorySymbols {
			if sym.DisplayName == want {
				resolved = append(resolved, sym)
			}
		}
	}
	return plugin.SymbolResolutionResult{Partiality: plugin.Complete(), Resolved: resolved}, nil
}

// TestPluginSeam_SymbolMappingForwardsAdvisoryFields proves that symbolMapping.Run reads the
// normalized advisory artifact and forwards its PURL and AdvisorySymbols to
// ResolveDependencySymbols, so the matcher can filter to the advisory's vulnerable symbols.
// Previously the call omitted those fields, causing the filter to be bypassed.
func TestPluginSeam_SymbolMappingForwardsAdvisoryFields(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-fwd"}
	c.Request.Vulnerability = assessment.VulnRef{ID: "GO-2021-0264", Source: "osv"}

	// Seed the normalized advisory artifact as advisoryIntake would produce it.
	advisory := struct {
		VulnID          string   `json:"vuln_id"`
		Source          string   `json:"source"`
		PURL            string   `json:"purl"`
		AdvisorySymbols []string `json:"advisory_symbols"`
	}{
		VulnID:          "GO-2021-0264",
		Source:          "osv",
		PURL:            "pkg:golang/stdlib",
		AdvisorySymbols: []string{"archive/zip.(*Reader).Open"},
	}
	if _, err := PutArtifact(store, c, "advisory_intake", artifact.TypeNormalizedAdvisory, "test advisory", advisory); err != nil {
		t.Fatalf("seed advisory: %v", err)
	}

	spy := &resolveSpyPlugin{}
	stage := symbolMapping{plugin: spy}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Assert forwarding: the fields must reach the plugin.
	if spy.capturedReq.PURL != "pkg:golang/stdlib" {
		t.Errorf("PURL not forwarded: got %q, want %q", spy.capturedReq.PURL, "pkg:golang/stdlib")
	}
	if len(spy.capturedReq.AdvisorySymbols) != 1 || spy.capturedReq.AdvisorySymbols[0] != "archive/zip.(*Reader).Open" {
		t.Errorf("AdvisorySymbols not forwarded: got %v", spy.capturedReq.AdvisorySymbols)
	}

	// Assert filtering: only the matching symbol must appear in the artifact.
	syms, err := store.Query(c.ID, artifact.TypeVulnerableSymbol)
	if err != nil || len(syms) != 1 {
		t.Fatalf("want 1 vulnerable_symbol artifact, got %d (err=%v)", len(syms), err)
	}
	var got struct {
		Resolved []plugin.Symbol `json:"resolved"`
	}
	if err := json.Unmarshal(syms[0].Payload, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Resolved) != 1 || got.Resolved[0].SCIP != "scip:vuln#Vulnerable" {
		t.Errorf("want exactly the advisory-matched symbol, got %+v", got.Resolved)
	}
}

// TestPluginSeam_NilPluginKeepsStubBehavior proves both stages keep their exact current
// stub output when no plugin is injected.
func TestPluginSeam_NilPluginKeepsStubBehavior(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-4"}

	if err := (symbolMapping{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("symbol_mapping: %v", err)
	}
	if err := (reachabilityIngress{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("reachability_ingress: %v", err)
	}

	syms, _ := store.Query(c.ID, artifact.TypeVulnerableSymbol)
	if len(syms) != 1 {
		t.Fatalf("want 1 vulnerable_symbol, got %d", len(syms))
	}
	var sym struct {
		Symbol string `json:"symbol"`
	}
	if err := json.Unmarshal(syms[0].Payload, &sym); err != nil {
		t.Fatalf("decode stub symbol: %v", err)
	}
	if sym.Symbol != "example.com/x/pkg.Vulnerable" {
		t.Fatalf("nil-plugin must keep stub symbol byte-for-byte, got %q", sym.Symbol)
	}

	pairs, _ := store.Query(c.ID, artifact.TypeCandidatePair)
	if len(pairs) != 1 {
		t.Fatalf("want 1 candidate_pair, got %d", len(pairs))
	}
	var pair artifact.CandidatePair
	if err := json.Unmarshal(pairs[0].Payload, &pair); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !pair.Partial {
		t.Fatalf("nil-plugin stub must keep Partial=true, got false")
	}
}
