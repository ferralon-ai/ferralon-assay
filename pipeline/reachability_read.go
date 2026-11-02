package pipeline

import (
	"encoding/json"
	"iter"
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
//
// The resolved stage seeds the record into a store that takes seeds (artifact.Seeder), built from
// the values it encoded the payload from, so readers share the run's one decode of the graph.
type ReachabilityRecord struct {
	legs struct {
		Reachability  json.RawMessage `json:"reachability"`
		CallGraph     json.RawMessage `json:"call_graph"`
		ToolchainScan json.RawMessage `json:"toolchain_scan"`
		Reachable     json.RawMessage `json:"reachable"`
	}
	err error

	cgOnce sync.Once
	cg     plugin.CallGraphView
	cgErr  error
}

// reachabilityViewKey keys the ReachabilityRecord view of a reachability artifact.
const reachabilityViewKey = "pipeline.reachability"

// Reachability returns the record of caseID's reachability artifact, or false when there is none.
func Reachability(store artifact.Store, caseID string) (*ReachabilityRecord, bool, error) {
	v, ok, err := artifact.View(store, caseID, artifact.TypeReachability, reachabilityViewKey, func(payload []byte) any {
		r := &ReachabilityRecord{}
		r.err = json.Unmarshal(payload, &r.legs)
		return r
	})
	if err != nil || !ok {
		return nil, false, err
	}
	return v.(*ReachabilityRecord), true, nil
}

// seededReachability is the record that decoding a resolved payload gives, built from what the
// payload was encoded from: reach and ts are exactly the payload's reachability and toolchain_scan
// values, owned by the record, and cg is the graph whose encoding is its call_graph value. cg must
// be FromEncoding, so decoding that value would give an equal graph.
func seededReachability(reach, ts []byte, cg plugin.CallGraphView) *ReachabilityRecord {
	r := &ReachabilityRecord{}
	r.legs.Reachability = reach
	r.legs.ToolchainScan = ts
	r.cgOnce.Do(func() { r.cg = cg })
	return r
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
		var cg plugin.CallGraphResult
		r.cgErr = r.leg(r.legs.CallGraph, &cg)
		r.cg = plugin.NewCallGraphView(cg)
		r.legs.CallGraph = nil
	})
	if r.cgErr != nil {
		return CallGraphView{}, r.cgErr
	}
	return CallGraphView{v: r.cg}, nil
}

// CallGraphView reads a shared call graph. Nothing it returns aliases the graph. The zero value is
// an empty graph.
type CallGraphView struct{ v plugin.CallGraphView }

// Partiality is a copy of the graph's partiality.
func (v CallGraphView) Partiality() plugin.Partiality { return v.v.Partiality() }

// EdgeCount is the number of edges in the graph.
func (v CallGraphView) EdgeCount() int { return v.v.EdgeCount() }

// Edges yields a copy of each edge in order.
func (v CallGraphView) Edges() iter.Seq[plugin.CallEdge] { return v.v.Edges() }

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
