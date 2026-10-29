package pipeline

import (
	"encoding/json"
	"iter"
	"slices"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ReachabilityRecord reads the legs of an assessment's TypeReachability artifact. The resolved
// payload embeds the whole call graph, and an assessment has several readers of it; through a
// store that keeps views (artifact.Viewer) they share one scan of the payload and one decode of
// the graph.
//
// Each leg reads exactly as decoding the payload into a struct holding only that leg would: absent
// is the zero value, and an error is that decode's error. Every leg but CallGraph is decoded fresh
// on each call, so what a caller gets is its own.
type ReachabilityRecord struct {
	legs struct {
		Reachability  json.RawMessage `json:"reachability"`
		CallGraph     json.RawMessage `json:"call_graph"`
		ToolchainScan json.RawMessage `json:"toolchain_scan"`
		Reachable     json.RawMessage `json:"reachable"`
	}
	err error

	cgOnce sync.Once
	cg     plugin.CallGraphResult
	cgErr  error
}

// Reachability returns the record of caseID's reachability artifact, or false when there is none.
func Reachability(store artifact.Store, caseID string) (*ReachabilityRecord, bool, error) {
	v, ok, err := artifact.View(store, caseID, artifact.TypeReachability, "pipeline.reachability", func(payload []byte) any {
		r := &ReachabilityRecord{}
		r.err = json.Unmarshal(payload, &r.legs)
		return r
	})
	if err != nil || !ok {
		return nil, false, err
	}
	return v.(*ReachabilityRecord), true, nil
}

// Result is the reachability stage's result.
func (r *ReachabilityRecord) Result() (plugin.ReachabilityResult, error) {
	var res plugin.ReachabilityResult
	err := r.leg(r.legs.Reachability, &res)
	return res, err
}

// CallGraph is the call graph the stage ran on. It is decoded once and shared by every caller,
// behind a view that hands out only copies.
func (r *ReachabilityRecord) CallGraph() (CallGraphView, error) {
	r.cgOnce.Do(func() {
		r.cgErr = r.leg(r.legs.CallGraph, &r.cg)
		r.legs.CallGraph = nil
	})
	if r.cgErr != nil {
		return CallGraphView{}, r.cgErr
	}
	return CallGraphView{cg: &r.cg}, nil
}

// CallGraphView reads a shared call graph. Nothing it returns aliases the graph. The zero value is
// an empty graph.
type CallGraphView struct{ cg *plugin.CallGraphResult }

// Partiality is a copy of the graph's partiality.
func (v CallGraphView) Partiality() plugin.Partiality {
	if v.cg == nil {
		return plugin.Partiality{}
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

// Edges yields a copy of each edge in order.
func (v CallGraphView) Edges() iter.Seq[plugin.CallEdge] {
	return func(yield func(plugin.CallEdge) bool) {
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

// ToolchainScan is the toolchain the analysis ran under.
func (r *ReachabilityRecord) ToolchainScan() (ToolchainScan, error) {
	var ts ToolchainScan
	err := r.leg(r.legs.ToolchainScan, &ts)
	return ts, err
}

// StubReachable is the reachable flag of the stub stage's payload, which carries nothing else.
func (r *ReachabilityRecord) StubReachable() (bool, error) {
	var reachable bool
	err := r.leg(r.legs.Reachable, &reachable)
	return reachable, err
}

func (r *ReachabilityRecord) leg(raw json.RawMessage, v any) error {
	if r.err != nil {
		return r.err
	}
	if raw == nil {
		return nil
	}
	return json.Unmarshal(raw, v)
}
