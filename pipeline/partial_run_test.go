package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// partialRunStubPlugin is firstPartyStubPlugin whose Reachability declares reasons.
type partialRunStubPlugin struct {
	firstPartyStubPlugin
	reasons []string
}

func (p partialRunStubPlugin) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if len(p.reasons) == 0 {
		return plugin.ReachabilityResult{Partiality: plugin.Complete()}, nil
	}
	return plugin.ReachabilityResult{Partiality: plugin.Partial(p.reasons...)}, nil
}

// TestOwnAdvisoryOnPartialRun: the first-party call-graph fallback forms no candidate for the
// scanned project's own advisory when the project states no version of itself and the lane answered
// from a partial run. Each condition is necessary: the same advisory on a run over the whole build,
// on a project whose version is known, or on a dependency keeps its candidate.
func TestOwnAdvisoryOnPartialRun(t *testing.T) {
	const sym = "scip-go gomod example.com/app . example.com/app/fetchHandler()."
	unversioned := []string{plugin.PartialReasonToolFailure, plugin.PartialReasonPartialRunUnversioned}
	cases := []struct {
		name     string
		inv      map[string]any
		reasons  []string
		wantHeld bool
	}{
		{name: "own advisory, no version, partial run", inv: map[string]any{"root": true}, reasons: unversioned, wantHeld: true},
		{name: "own advisory, no version, whole build", inv: map[string]any{"root": true}},
		{name: "own advisory, no version, another tool failure", inv: map[string]any{"root": true}, reasons: []string{plugin.PartialReasonToolFailure}},
		{name: "own advisory, version known, partial run", inv: map[string]any{"root": true, "resolved_version": "1.4.0"}, reasons: unversioned},
		{name: "a dependency's advisory, no version, partial run", inv: map[string]any{}, reasons: unversioned},
		{name: "no inventory, partial run", reasons: unversioned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := partialRunStubPlugin{
				firstPartyStubPlugin: firstPartyStubPlugin{sink: sym, ingress: sym, ingressIsKnown: true},
				reasons:              tc.reasons,
			}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-own"}
			c.Request.Vulnerability = assessment.VulnRef{ID: "GHSA-own", Source: "osv"}
			if tc.inv != nil {
				putJSON(t, store, c.ID, artifact.TypeInventory, tc.inv)
			}
			if err := (symbolMapping{plugin: p}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("symbol_mapping: %v", err)
			}
			if err := (reachabilityIngress{plugin: p}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("reachability_ingress: %v", err)
			}
			pairs, err := store.Query(c.ID, artifact.TypeCandidatePair)
			if err != nil {
				t.Fatalf("query candidate_pair: %v", err)
			}
			wantPairs := 1
			if tc.wantHeld {
				wantPairs = 0
			}
			if len(pairs) != wantPairs {
				t.Fatalf("candidate pairs = %d, want %d", len(pairs), wantPairs)
			}
			if got := OwnAdvisoryHeldForPartialRun(store, c.ID); got != tc.wantHeld {
				t.Fatalf("OwnAdvisoryHeldForPartialRun = %v, want %v", got, tc.wantHeld)
			}
		})
	}
}
