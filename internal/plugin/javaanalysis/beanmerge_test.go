package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestMergeBeanResolvedEdges_NoOp proves the H2 seam is byte-identical to today when
// no overlay supplies bean data: same edges, same partiality (dynamic_dispatch kept).
func TestMergeBeanResolvedEdges_NoOp(t *testing.T) {
	lexical := plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
		Edges:      []plugin.CallEdge{{Caller: sym("a"), Callee: sym("b")}},
		Roots:      []plugin.Symbol{sym("r")},
	}
	unresolved := map[unresolvedCall]bool{{caller: "a", calleeName: "svc", calleeArity: 1}: true}

	got := mergeBeanResolvedEdges(lexical, nil, unresolved, nil)
	if len(got.Edges) != 1 || got.Edges[0].Callee.SCIP != "b" {
		t.Errorf("edges changed in no-op: %+v", got.Edges)
	}
	if len(got.Partiality.Reasons) != 1 || got.Partiality.Reasons[0] != plugin.PartialReasonDynamicDispatch {
		t.Errorf("partiality changed in no-op: %+v", got.Partiality)
	}
}

// TestMergeBeanResolvedEdges_RetiresWhenResidualEmpty proves that supplying a bean
// edge plus the resolved key retires dynamic_dispatch (the sole unresolved key was
// resolved) and unions the edge.
func TestMergeBeanResolvedEdges_RetiresWhenResidualEmpty(t *testing.T) {
	key := unresolvedCall{caller: "a", calleeName: "svc", calleeArity: 1}
	lexical := plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Edges:      []plugin.CallEdge{{Caller: sym("a"), Callee: sym("b")}},
	}
	got := mergeBeanResolvedEdges(lexical,
		[]plugin.CallEdge{{Caller: sym("a"), Callee: sym("impl")}},
		map[unresolvedCall]bool{key: true},
		map[unresolvedCall]bool{key: true})

	if got.Partiality.Complete != true {
		t.Errorf("dynamic_dispatch not retired: %+v", got.Partiality)
	}
	if len(got.Edges) != 2 {
		t.Errorf("bean edge not unioned: %+v", got.Edges)
	}
}

// TestMergeBeanResolvedEdges_KeepsWhenResidual proves an unresolved key the overlay
// did NOT resolve keeps dynamic_dispatch honest, and a coexisting read failure reason
// is preserved.
func TestMergeBeanResolvedEdges_KeepsWhenResidual(t *testing.T) {
	resolved := unresolvedCall{caller: "a", calleeName: "svc", calleeArity: 1}
	residual := unresolvedCall{caller: "c", calleeName: "other", calleeArity: 0}
	lexical := plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch, plugin.PartialReasonToolFailure),
		Edges:      []plugin.CallEdge{{Caller: sym("a"), Callee: sym("b")}},
	}
	got := mergeBeanResolvedEdges(lexical,
		[]plugin.CallEdge{{Caller: sym("a"), Callee: sym("impl")}},
		map[unresolvedCall]bool{resolved: true, residual: true},
		map[unresolvedCall]bool{resolved: true})

	hasDispatch, hasTool := false, false
	for _, r := range got.Partiality.Reasons {
		if r == plugin.PartialReasonDynamicDispatch {
			hasDispatch = true
		}
		if r == plugin.PartialReasonToolFailure {
			hasTool = true
		}
	}
	if !hasDispatch {
		t.Error("dynamic_dispatch wrongly retired while a residual key remained")
	}
	if !hasTool {
		t.Error("tool_failure reason was dropped")
	}
}
