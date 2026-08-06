// internal/pipeline/stages_taint_test.go
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReachabilityEmitsTaintDiscovery exercises the live-plugin seam: with a plugin injected and a
// resolved sink present, reachability_ingress emits exactly one TypeTaint discovery artifact wrapping
// the plugin's verbatim TaintResult. StubPlugin.ComputeTaint returns Unsupported() by design, so the
// persisted result is declared-partial (Complete=false) — that is correct and must be preserved.
func TestReachabilityEmitsTaintDiscovery(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-taint"}

	// Seed the upstream artifacts runWithPlugin reads: inventory build dir + resolved vulnerable symbol.
	if _, err := PutArtifact(store, c, "codebase_inventory", artifact.TypeInventory, "inventory", struct {
		BuildDir string `json:"build_dir"`
	}{BuildDir: "/does/not/matter"}); err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	res := plugin.SymbolResolutionResult{
		Partiality: plugin.Complete(),
		Resolved:   []plugin.Symbol{{SCIP: "scip:vuln#Vulnerable", DisplayName: "example.com/dep.Vulnerable", Package: "example.com/dep"}},
	}
	if _, err := PutArtifact(store, c, "symbol_mapping", artifact.TypeVulnerableSymbol, "vulnerable symbol (resolved)", res); err != nil {
		t.Fatalf("seed symbol: %v", err)
	}

	stage := reachabilityIngress{plugin: plugin.StubPlugin{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}

	taints, err := store.Query(c.ID, artifact.TypeTaint)
	if err != nil {
		t.Fatalf("query taint: %v", err)
	}
	if len(taints) != 1 {
		t.Fatalf("want exactly 1 taint artifact, got %d", len(taints))
	}
	var td taintDiscovery
	if err := json.Unmarshal(taints[0].Payload, &td); err != nil {
		t.Fatalf("decode taintDiscovery: %v", err)
	}
	if td.SchemaVersion != "tegron.taint.v1" {
		t.Fatalf("schema_version = %q, want tegron.taint.v1", td.SchemaVersion)
	}
	if td.Sink == "" {
		t.Fatal("taint sink must be the resolved sink SCIP, got empty")
	}
	// Path-presence taint is partial by construction; StubPlugin returns Unsupported() ⇒ Complete=false.
	if td.Result.Partiality.Complete {
		t.Fatal("taint discovery must stay declared-partial (Complete=false), not be upgraded to Complete")
	}
}

// TestReachabilityStubPathEmitsNoTaint confirms the nil/stub default path (no plugin injected) writes
// no taint artifact — the taint call lives only in the s.plugin != nil branch.
func TestReachabilityStubPathEmitsNoTaint(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-no-taint"}

	stage := reachabilityIngress{} // plugin == nil → default/stub path
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}
	if taints, _ := store.Query(c.ID, artifact.TypeTaint); len(taints) != 0 {
		t.Fatalf("default/stub path must emit no taint artifact, got %d", len(taints))
	}
}
