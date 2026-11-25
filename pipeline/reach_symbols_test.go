package pipeline

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// multiSinkPlugin resolves an advisory symbol to several sinks: one first-party, two in a
// dependency, one listed twice. Only the last dependency sink is reachable over the call graph.
type multiSinkPlugin struct {
	firstPartyStubPlugin
	seen *plugin.ReachabilityRequest
}

const (
	msLocal   = "scip-go gomod example.com/app . example.com/app/decode()."
	msDepA    = "scip-go gomod example.com/lib v1.0.0 example.com/lib/Unmarshal()."
	msDepB    = "scip-go gomod example.com/lib v1.0.0 example.com/lib/Decode()."
	msIngress = "scip-go gomod example.com/app . example.com/app/main()."
)

func (p multiSinkPlugin) ResolveDependencySymbols(context.Context, plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{
		Partiality: plugin.Complete(),
		Resolved:   []plugin.Symbol{{SCIP: msLocal}, {SCIP: msDepA}, {SCIP: msDepB}, {SCIP: msDepA}},
		Origins: map[string]string{
			msDepA: "pkg:golang/example.com/lib",
			msDepB: "pkg:golang/example.com/lib",
		},
	}, nil
}

func (p multiSinkPlugin) Reachability(_ context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	*p.seen = req
	return plugin.ReachabilityResult{Partiality: plugin.Complete()}, nil
}

func (p multiSinkPlugin) CallGraph(context.Context, plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Algorithm:  "vta",
		Edges:      []plugin.CallEdge{{Caller: plugin.Symbol{SCIP: msIngress}, Callee: plugin.Symbol{SCIP: msDepB}}},
		Roots:      []plugin.Symbol{{SCIP: msIngress}},
	}, nil
}

// TestReachability_AskedAboutEveryResolvedSink: the lane is asked about every resolved sink,
// dependency sinks first and deduplicated, and the call-graph fallback searches all of them, not
// only the first one resolved.
func TestReachability_AskedAboutEveryResolvedSink(t *testing.T) {
	var seen plugin.ReachabilityRequest
	_, pairs := runFirstPartyReach(t, multiSinkPlugin{seen: &seen})

	if want := []string{msDepA, msDepB, msLocal}; !reflect.DeepEqual(seen.Symbols, want) {
		t.Errorf("ReachabilityRequest.Symbols = %q, want %q", seen.Symbols, want)
	}
	if len(pairs) != 1 {
		t.Fatalf("got %d candidate pairs, want 1: the reachable sink is the third resolved", len(pairs))
	}
}

// strictSeenPlugin records the strict mode each analysis request carries.
type strictSeenPlugin struct {
	multiSinkPlugin
	graph *bool
}

func (p strictSeenPlugin) CallGraph(ctx context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	*p.graph = req.Strict
	return p.multiSinkPlugin.CallGraph(ctx, req)
}

// TestReachability_StrictReachesLane: WithStrict reaches the lane on the call-graph and
// reachability requests reachability_ingress sends, so a lane declares a limit in place of an
// assumption; without it neither request asks for strict mode.
func TestReachability_StrictReachesLane(t *testing.T) {
	for _, strict := range []bool{false, true} {
		var seen plugin.ReachabilityRequest
		var graph bool
		p := strictSeenPlugin{multiSinkPlugin: multiSinkPlugin{seen: &seen}, graph: &graph}
		var stage reachabilityIngress
		for _, s := range AssessStages(WithPlugin(p), WithStrict(strict)) {
			if r, ok := s.(reachabilityIngress); ok {
				stage = r
			}
		}
		if stage.strict != strict {
			t.Fatalf("WithStrict(%v): stage strict = %v", strict, stage.strict)
		}
		store := artifact.NewMemStore()
		c := &assessment.Assessment{ID: "case-strict"}
		c.Request.Vulnerability = assessment.VulnRef{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}
		if err := (symbolMapping{plugin: p}).Run(context.Background(), c, store); err != nil {
			t.Fatalf("symbol_mapping: %v", err)
		}
		if err := stage.Run(context.Background(), c, store); err != nil {
			t.Fatalf("reachability_ingress: %v", err)
		}
		if seen.Strict != strict || graph != strict {
			t.Errorf("WithStrict(%v): reachability request strict = %v, call graph request strict = %v", strict, seen.Strict, graph)
		}
	}
}
