package plugin

import (
	"context"
	"encoding/json"
	"iter"
	"slices"
)

// CallGraphView reads a call graph that may be shared between callers. Nothing it returns aliases
// the graph: scalars and Symbols are values, and every slice is a copy or yielded element by
// element. The zero value is an empty graph.
type CallGraphView struct {
	cg *CallGraphResult
	// enc is cg's JSON encoding when the view was handed one, so marshalling the view does not
	// re-encode the graph.
	enc []byte
}

// NewCallGraphView is a view over cg. The view reads cg's slices in place, so cg must be the
// caller's own, unshared result.
func NewCallGraphView(cg CallGraphResult) CallGraphView {
	return CallGraphView{cg: &cg}
}

// SharedCallGraph is p's call graph for req through a read-only view. A plugin from Memoize decodes
// the graph once and every caller's view shares that decode; any other plugin's CallGraph answer is
// wrapped as is.
func SharedCallGraph(ctx context.Context, p LanguagePlugin, req CallGraphRequest) (CallGraphView, error) {
	if s, ok := p.(callGraphSharer); ok {
		return s.sharedCallGraph(ctx, req)
	}
	cg, err := p.CallGraph(ctx, req)
	if err != nil {
		return CallGraphView{}, err
	}
	return NewCallGraphView(cg), nil
}

// callGraphSharer is implemented only inside this package, so a shared decode is never handed out
// through a type outside it.
type callGraphSharer interface {
	sharedCallGraph(ctx context.Context, req CallGraphRequest) (CallGraphView, error)
}

// Partiality is a copy of the graph's partiality.
func (v CallGraphView) Partiality() Partiality {
	if v.cg == nil {
		return Partiality{}
	}
	p := v.cg.Partiality
	p.Reasons = slices.Clone(p.Reasons)
	p.Scoped = slices.Clone(p.Scoped)
	for i := range p.Scoped {
		p.Scoped[i].Targets = slices.Clone(p.Scoped[i].Targets)
	}
	return p
}

// EdgeCount is the number of edges in the graph.
func (v CallGraphView) EdgeCount() int {
	if v.cg == nil {
		return 0
	}
	return len(v.cg.Edges)
}

// Edges yields each edge in order.
func (v CallGraphView) Edges() iter.Seq[CallEdge] {
	return func(yield func(CallEdge) bool) {
		if v.cg == nil {
			return
		}
		for _, e := range v.cg.Edges {
			if !yield(e) {
				return
			}
		}
	}
}

// Roots yields each root in order.
func (v CallGraphView) Roots() iter.Seq[Symbol] {
	return func(yield func(Symbol) bool) {
		if v.cg == nil {
			return
		}
		for _, r := range v.cg.Roots {
			if !yield(r) {
				return
			}
		}
	}
}

// MarshalJSON encodes the graph exactly as json.Marshal encodes its CallGraphResult; the zero view
// encodes as an empty CallGraphResult.
func (v CallGraphView) MarshalJSON() ([]byte, error) {
	return v.AppendJSON(nil)
}

// AppendJSON appends the graph's MarshalJSON encoding to dst. A view over a memoized graph appends
// the encoding the memo already holds, so a caller assembling a larger document need not re-encode
// the graph, nor have encoding/json re-validate it as it does a Marshaler's output.
func (v CallGraphView) AppendJSON(dst []byte) ([]byte, error) {
	if v.enc != nil {
		return append(dst, v.enc...), nil
	}
	var cg CallGraphResult
	if v.cg != nil {
		cg = *v.cg
	}
	b, err := json.Marshal(cg)
	if err != nil {
		return nil, err
	}
	return append(dst, b...), nil
}
