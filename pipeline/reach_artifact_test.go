package pipeline

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// unresolvedFirstPartyStub returns firstPartyStubPlugin's call graph with declined sites and
// escaped symbols listed, as a dynamic-language lane does.
type unresolvedFirstPartyStub struct{ firstPartyStubPlugin }

func (p unresolvedFirstPartyStub) CallGraph(ctx context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	cg, err := p.firstPartyStubPlugin.CallGraph(ctx, req)
	cg.Partiality = plugin.Partial(plugin.PartialReasonDynamicDispatch)
	for _, callee := range []string{"getattr(mod, name)", "h", "registry.get(k)"} {
		cg.Unresolved = append(cg.Unresolved, plugin.UnresolvedCall{Caller: plugin.Symbol{SCIP: p.ingress}, Callee: callee, Arity: 1, Reason: plugin.PartialReasonDynamicDispatch})
	}
	cg.Escaped = []plugin.Symbol{{SCIP: p.sink}, {SCIP: p.ingress}}
	return cg, err
}

// TestReachabilityArtifact_CallGraphLegCountsDeclinedSites: the reachability artifact keeps the
// call graph's partiality, edges and roots and reduces its declined sites and escaped symbols to
// counts, and a reader decoding the leg as a plugin.CallGraphResult reads the same graph.
func TestReachabilityArtifact_CallGraphLegCountsDeclinedSites(t *testing.T) {
	p := unresolvedFirstPartyStub{firstPartyStubPlugin{
		sink:           "scip-go gomod tegron.corpus/app . tegron.corpus/app/fetchHandler().",
		ingress:        "scip-go gomod tegron.corpus/app . tegron.corpus/app/main().",
		ingressIsKnown: true,
	}}
	store, pairs := runFirstPartyReach(t, p)
	if len(pairs) != 1 {
		t.Fatalf("want one candidate pair, got %d", len(pairs))
	}
	arts, err := store.Query("case-fp", artifact.TypeReachability)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no reachability artifact persisted: %v", err)
	}

	var raw struct {
		CallGraph map[string]json.RawMessage `json:"call_graph"`
	}
	if err := json.Unmarshal(arts[0].Payload, &raw); err != nil {
		t.Fatalf("decode reachability: %v", err)
	}
	for _, k := range []string{"unresolved", "escaped"} {
		if _, ok := raw.CallGraph[k]; ok {
			t.Errorf("call_graph.%s persisted; the artifact carries counts only", k)
		}
	}
	for k, want := range map[string]string{"unresolved_count": "3", "escaped_count": "2"} {
		if got := string(raw.CallGraph[k]); got != want {
			t.Errorf("call_graph.%s = %s, want %s", k, got, want)
		}
	}

	var read struct {
		CallGraph plugin.CallGraphResult `json:"call_graph"`
	}
	if err := json.Unmarshal(arts[0].Payload, &read); err != nil {
		t.Fatalf("decode call_graph as CallGraphResult: %v", err)
	}
	want, _ := p.CallGraph(context.Background(), plugin.CallGraphRequest{})
	want.Unresolved, want.Escaped = nil, nil
	if !reflect.DeepEqual(read.CallGraph, want) {
		t.Errorf("call_graph read back = %+v, want %+v", read.CallGraph, want)
	}
}
