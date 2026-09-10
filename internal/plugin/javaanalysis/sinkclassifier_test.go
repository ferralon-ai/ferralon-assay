package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestH3_SinkClassifierHook proves the H3 seam: with no classifier registered
// firstPartyPaths adds no reasons (byte-identical), and a registered classifier's
// reasons surface for the requested sink regardless of reachability.
func TestH3_SinkClassifierHook(t *testing.T) {
	cg := plugin.CallGraphResult{
		Edges: []plugin.CallEdge{{Caller: sym("ingress"), Callee: sym("sink")}},
		Roots: []plugin.Symbol{sym("ingress")},
	}
	ing := plugin.IngressResult{Ingresses: []plugin.Ingress{{Kind: "http_route", Symbol: sym("ingress")}}}

	// These sinks are classified purely by id, so a minimal empty program suffices.
	prog := &program{}

	// Default: empty registry → no extra reasons.
	_, reasons := firstPartyPaths(prog, cg, ing, []string{"sink"})
	if reasons[plugin.PartialReasonRepositorySynthesized] {
		t.Fatal("empty classifier registry leaked a reason")
	}

	// Register a classifier FACTORY that flags one specific sink id.
	orig := len(sinkClassifiers)
	defer func() { sinkClassifiers = sinkClassifiers[:orig] }()
	registerSinkClassifier(func(_ *program) func(string) []string {
		return func(id string) []string {
			if id == "sink" {
				return []string{plugin.PartialReasonRepositorySynthesized}
			}
			return nil
		}
	})

	_, reasons = firstPartyPaths(prog, cg, ing, []string{"sink"})
	if !reasons[plugin.PartialReasonRepositorySynthesized] {
		t.Error("registered classifier reason did not surface")
	}
	// A sink the classifier does not recognize gets no extra reason.
	_, reasons = firstPartyPaths(prog, cg, ing, []string{"other"})
	if reasons[plugin.PartialReasonRepositorySynthesized] {
		t.Error("classifier reason surfaced for an unrecognized sink")
	}
}
