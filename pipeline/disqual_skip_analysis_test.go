package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// countingPlugin records every S4/S5 plugin op it is asked to run.
type countingPlugin struct {
	plugin.StubPlugin
	calls *int
}

func (p countingPlugin) ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	*p.calls++
	return plugin.SymbolResolutionResult{Partiality: plugin.Complete()}, nil
}

func (p countingPlugin) CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	*p.calls++
	return plugin.CallGraphResult{Partiality: plugin.Complete()}, nil
}

func (p countingPlugin) FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	*p.calls++
	return plugin.IngressResult{Partiality: plugin.Complete()}, nil
}

func (p countingPlugin) Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	*p.calls++
	return plugin.ReachabilityResult{Partiality: plugin.Complete()}, nil
}

// TestSkipDisqualifiedAnalysis pins that symbol_mapping and reachability_ingress do no plugin work
// for an advisory disqualification_discovery settled — and only then, and only when opted in.
func TestSkipDisqualifiedAnalysis(t *testing.T) {
	tests := []struct {
		name         string
		discovery    *DisqualResult
		skip         bool
		wantCalls    bool
		wantArtifact bool
	}{
		{name: "disqualified, opted in", discovery: &DisqualResult{Disqualified: true, Reason: ReasonVersionNotInRange}, skip: true, wantCalls: false, wantArtifact: false},
		{name: "disqualified, default", discovery: &DisqualResult{Disqualified: true, Reason: ReasonVersionNotInRange}, skip: false, wantCalls: true, wantArtifact: true},
		{name: "proceeds, opted in", discovery: &DisqualResult{Disqualified: false}, skip: true, wantCalls: true, wantArtifact: true},
		{name: "no discovery artifact, opted in", discovery: nil, skip: true, wantCalls: true, wantArtifact: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-skip"}
			c.Request.Vulnerability = assessment.VulnRef{ID: "GO-2099-0001", Source: "osv"}
			if tt.discovery != nil {
				if _, err := PutArtifact(store, c, "disqualification_discovery", artifact.TypeDiscovery, "seeded", *tt.discovery); err != nil {
					t.Fatal(err)
				}
			}
			var calls int
			p := countingPlugin{calls: &calls}
			cfg := &AssessConfig{}
			WithPlugin(p)(cfg)
			WithSkipDisqualifiedAnalysis(tt.skip)(cfg)
			stages := []Stage{
				symbolMapping{plugin: cfg.Plugin, skipDisqualified: cfg.SkipDisqualifiedAnalysis},
				reachabilityIngress{plugin: cfg.Plugin, skipDisqualified: cfg.SkipDisqualifiedAnalysis},
			}
			for _, s := range stages {
				if err := s.Run(context.Background(), c, store); err != nil {
					t.Fatalf("%s: %v", s.Name(), err)
				}
			}
			if got := calls > 0; got != tt.wantCalls {
				t.Errorf("plugin calls = %d, want calls: %v", calls, tt.wantCalls)
			}
			for _, typ := range []artifact.Type{artifact.TypeVulnerableSymbol, artifact.TypeReachability} {
				arts, err := store.Query(c.ID, typ)
				if err != nil {
					t.Fatal(err)
				}
				if got := len(arts) > 0; got != tt.wantArtifact {
					t.Errorf("%s artifact present = %v, want %v", typ, got, tt.wantArtifact)
				}
			}
		})
	}
}

// TestAssessStagesThreadsSkipDisqualified pins that the option reaches both analysis stages through
// the public assembly seam, and that the default leaves it off.
func TestAssessStagesThreadsSkipDisqualified(t *testing.T) {
	for _, skip := range []bool{false, true} {
		var opts []AssessOption
		if skip {
			opts = append(opts, WithSkipDisqualifiedAnalysis(true))
		}
		for _, s := range AssessStages(opts...) {
			switch st := s.(type) {
			case symbolMapping:
				if st.skipDisqualified != skip {
					t.Errorf("symbol_mapping skipDisqualified = %v, want %v", st.skipDisqualified, skip)
				}
			case reachabilityIngress:
				if st.skipDisqualified != skip {
					t.Errorf("reachability_ingress skipDisqualified = %v, want %v", st.skipDisqualified, skip)
				}
			}
		}
	}
}
