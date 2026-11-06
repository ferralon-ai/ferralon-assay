package plugin

import (
	"context"
	"encoding/json"
	"iter"
	"slices"
	"sync"
)

// CallGraphView reads a call graph that may be shared between callers. Nothing it returns aliases
// the graph: scalars and Symbols are values, and every slice is a copy or yielded element by
// element. The zero value is an empty graph.
type CallGraphView struct {
	cg *CallGraphResult
	// enc is cg's JSON encoding when the view was handed one, so marshalling the view does not
	// re-encode the graph.
	enc []byte
	// rev is cg's reverse-edge index, built on first use and shared by every view of cg.
	rev *reverseIndex
	// counted, when set, holds cg's CountedCallGraph encoding for every view sharing cg, so it is
	// encoded at most once.
	counted *countedEncoding
}

// CountedCallGraph is a call graph with its Unresolved and Escaped lists reduced to counts: what a
// persisted copy of the graph carries. Decoded as a CallGraphResult it gives the same partiality,
// algorithm, edges and roots, and no Unresolved list, which the contract reads as every declared
// reason unattributable: more conservative than the graph, never less.
type CountedCallGraph struct {
	Partiality      Partiality `json:"partiality"`
	Algorithm       string     `json:"algorithm"`
	Edges           []CallEdge `json:"edges"`
	Roots           []Symbol   `json:"roots"`
	UnresolvedCount int        `json:"unresolved_count,omitempty"`
	EscapedCount    int        `json:"escaped_count,omitempty"`
}

type countedEncoding struct {
	once sync.Once
	b    []byte
	err  error
}

// NewCallGraphView is a view over cg. The view reads cg's slices in place, so cg must be the
// caller's own, unshared result.
func NewCallGraphView(cg CallGraphResult) CallGraphView {
	return CallGraphView{cg: &cg, rev: &reverseIndex{}}
}

// reverseIndex is a graph's edges keyed by callee SCIP id, for walking back from a sink.
type reverseIndex struct {
	once sync.Once
	// sym is each SCIP id's Symbol: the last root naming it, else the last edge endpoint naming it.
	sym     map[string]Symbol
	roots   map[string]struct{}
	callers map[string][]string
}

// buildReverseIndex fills r from cg. It is a variable so tests can count builds.
var buildReverseIndex = func(r *reverseIndex, cg *CallGraphResult) {
	r.sym = make(map[string]Symbol)
	r.roots = make(map[string]struct{})
	if cg == nil {
		return
	}
	r.callers = make(map[string][]string, len(cg.Edges))
	for _, e := range cg.Edges {
		r.sym[e.Caller.SCIP] = e.Caller
		r.sym[e.Callee.SCIP] = e.Callee
		r.callers[e.Callee.SCIP] = append(r.callers[e.Callee.SCIP], e.Caller.SCIP)
	}
	for _, root := range cg.Roots {
		r.sym[root.SCIP] = root
		r.roots[root.SCIP] = struct{}{}
	}
}

func (v CallGraphView) index() *reverseIndex {
	r := v.rev
	if r == nil {
		r = &reverseIndex{}
	}
	r.once.Do(func() { buildReverseIndex(r, v.cg) })
	return r
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

// Callers yields the SCIP id of the caller of each edge into scip, in edge order.
func (v CallGraphView) Callers(scip string) iter.Seq[string] {
	callers := v.index().callers[scip]
	return func(yield func(string) bool) {
		for _, c := range callers {
			if !yield(c) {
				return
			}
		}
	}
}

// IsRoot reports whether a root has SCIP id scip.
func (v CallGraphView) IsRoot(scip string) bool {
	_, ok := v.index().roots[scip]
	return ok
}

// Symbol is the Symbol the graph gives SCIP id scip, or the zero Symbol if none does. Where
// several carry the id, the last root wins, else the last edge endpoint.
func (v CallGraphView) Symbol(scip string) Symbol {
	return v.index().sym[scip]
}

// FromEncoding reports whether the graph is json.Unmarshal of exactly the bytes AppendJSON
// appends, as a memoized graph's shared decode is. Decoding those bytes then yields a value equal
// to the graph. A view that wraps a caller's result need not round-trip that way: encoding can
// lose the difference between a nil and an empty slice.
func (v CallGraphView) FromEncoding() bool { return v.enc != nil }

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

// AppendCountedJSON appends the json.Marshal encoding of the graph's CountedCallGraph to dst. A
// view over a memoized graph encodes it once for every view of that graph.
func (v CallGraphView) AppendCountedJSON(dst []byte) ([]byte, error) {
	if v.counted == nil {
		b, err := v.countedJSON()
		if err != nil {
			return nil, err
		}
		return append(dst, b...), nil
	}
	v.counted.once.Do(func() { v.counted.b, v.counted.err = v.countedJSON() })
	if v.counted.err != nil {
		return nil, v.counted.err
	}
	return append(dst, v.counted.b...), nil
}

func (v CallGraphView) countedJSON() ([]byte, error) {
	var cg CallGraphResult
	if v.cg != nil {
		cg = *v.cg
	}
	return json.Marshal(CountedCallGraph{
		Partiality:      cg.Partiality,
		Algorithm:       cg.Algorithm,
		Edges:           cg.Edges,
		Roots:           cg.Roots,
		UnresolvedCount: len(cg.Unresolved),
		EscapedCount:    len(cg.Escaped),
	})
}
