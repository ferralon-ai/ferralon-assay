package depreach

import (
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Confidence grades how decidable a call site was when the edge was produced — the
// three distinguishable states criterion C3 requires. A statically-decidable site is
// Resolved; a virtual/interface site narrowed to a candidate set is Conservative; a
// site whose receiver leaves the loaded assembly set is Boundary (the open-world
// residual). It mirrors the CHA three-state and drives whether a frontier carries a
// completeness hazard.
type Confidence int

const (
	// ConfResolved is a single statically-decided target (call/newobj, or a callvirt
	// whose owner is sealed/exactly known).
	ConfResolved Confidence = iota
	// ConfConservative is a virtual/interface dispatch resolved to a candidate set
	// over the loaded hierarchy — sound but over-approximate.
	ConfConservative
	// ConfBoundary is an unresolved site: the declared owner is outside the loaded
	// assembly set, so no target is known (open-world hazard).
	ConfBoundary
)

func (c Confidence) String() string {
	switch c {
	case ConfResolved:
		return "resolved"
	case ConfConservative:
		return "conservative"
	case ConfBoundary:
		return "boundary"
	default:
		return "unknown"
	}
}

// EdgeOrigin locates the call site an edge was produced from, for provenance grading
// (barrier 4). It is carried on the backing edge only, never on the public projection.
type EdgeOrigin struct {
	Assembly string         // name of the assembly whose IL produced the edge
	Method   assembly.Token // the caller MethodDef token
	ILOffset uint32         // the call instruction's IL offset
}

// BackingEdge is the lane-local, provenance-carrying call-graph edge (the C4
// reconciliation: lane-local because PLAN-300's cross-lane provenance schema is not
// open). It records the producer and origin alongside the resolved endpoints; the
// public plugin.CallEdge is a compact projection that drops all of it. Keeping
// provenance here means the frozen public type is not inflated (barrier-4 scope).
type BackingEdge struct {
	From       plugin.Symbol     // caller (canonical, comparable identity)
	To         plugin.Symbol     // callee
	Kind       assembly.EdgeKind // the IL call-site kind (call/callvirt/newobj/...)
	Producer   string            // which pass emitted it ("cha", "il-callsite", ...)
	Origin     EdgeOrigin        // call-site location
	Confidence Confidence        // C3 decidability grade

	// ⚑SM declared partiality: the edge is attributed through a generated async/iterator
	// state machine (its MoveNext), so it reads through code the developer did not write.
	// Recorded here — never a silent collapse, never an invented `<…>d__N` symbol — and,
	// like all provenance, dropped by Compact(). Partial is false for an ordinary edge.
	Partial       bool
	PartialReason string
}

// Compact projects a BackingEdge to the public, compact plugin.CallEdge, carrying only
// the caller/callee identities. Producer, Origin, and Confidence are intentionally
// dropped — the public edge stays compact; provenance lives on the backing artifact.
func (e BackingEdge) Compact() plugin.CallEdge {
	return plugin.CallEdge{Caller: e.From, Callee: e.To}
}
