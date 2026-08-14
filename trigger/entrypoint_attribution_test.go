package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// Regression — per-advisory entry-point attribution.
//
// These tests pin the demo-go-svc shape that exposed the collapse: one module, two
// attacker-facing routes whose handlers are BOTH net/http handlers, so FindIngresses
// reports each twice (a bare "handler" ingress and the registered "http_route" ingress)
// and sorts the set by kind-then-symbol. The DoS handler (expandHandler) sorts before the
// SSRF handler (fetchHandler) — 'e' < 'f' — so a positional "first attacker-controllable
// ingress" pick hands BOTH advisories expandHandler. Each finding's entry point must come
// from THAT advisory's own reaching ingress instead.
const (
	ssrfHandler = "scip-go gomod example.com/m . example.com/m/fetchHandler()."
	dosHandler  = "scip-go gomod example.com/m . example.com/m/expandHandler()."
	ssrfSink    = "scip-go gomod net/http . net/http/Get()."
	dosSink     = "scip-go gomod example.com/m . example.com/m/expand#makeslice()."
)

// twoRouteIngressMap is the shared, kind-then-symbol-sorted ingress map both advisories
// see — expandHandler ahead of fetchHandler, each present as both a handler and a route.
func twoRouteIngressMap() plugin.IngressResult {
	return plugin.IngressResult{Ingresses: []plugin.Ingress{
		{Kind: "handler", Symbol: plugin.Symbol{SCIP: dosHandler}},
		{Kind: "handler", Symbol: plugin.Symbol{SCIP: ssrfHandler}},
		{Kind: "http_route", Symbol: plugin.Symbol{SCIP: dosHandler}, Selector: "/expand"},
		{Kind: "http_route", Symbol: plugin.Symbol{SCIP: ssrfHandler}, Selector: "/preview"},
	}}
}

// seedTwoRouteCandidate stores the shared ingress map plus ONE advisory's resolved reach
// path (its own ingress→sink trace), the artifacts reachabilityEvidence reads.
func seedTwoRouteCandidate(t *testing.T, store artifact.Store, aid, ingress, sink string) {
	t.Helper()
	putJSON(t, store, aid, artifact.TypeIngressMap, twoRouteIngressMap())
	putJSON(t, store, aid, artifact.TypeReachability, struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
	}{Reachability: plugin.ReachabilityResult{Paths: []plugin.ReachPath{
		{Sink: plugin.Symbol{SCIP: sink}, Ingress: plugin.Symbol{SCIP: ingress}, Trace: []plugin.Symbol{{SCIP: ingress}, {SCIP: sink}}},
	}}})
}

// TestEntryPointAttribution_TwoRoutesDistinct is the headline regression: two advisories
// with distinct sinks behind distinct routes, sharing one ingress map, must each resolve
// to their OWN reaching ingress — SSRF→/preview, DoS→/expand — never collapsing onto the
// positionally-first ingress. This is the test that would have caught the collapse.
func TestEntryPointAttribution_TwoRoutesDistinct(t *testing.T) {
	ssrf := artifact.NewMemStore()
	seedTwoRouteCandidate(t, ssrf, "ssrf", ssrfHandler, ssrfSink)
	dos := artifact.NewMemStore()
	seedTwoRouteCandidate(t, dos, "dos", dosHandler, dosSink)

	gS, eS, _ := reachabilityEvidence(ssrf, "ssrf")
	gD, eD, _ := reachabilityEvidence(dos, "dos")

	if eS == nil || eS.Symbol != "/preview" || eS.Kind != "http_route" {
		t.Errorf("SSRF entry = %+v, want http_route /preview (fetchHandler's route)", eS)
	}
	if eD == nil || eD.Symbol != "/expand" || eD.Kind != "http_route" {
		t.Errorf("DoS entry = %+v, want http_route /expand (expandHandler's route)", eD)
	}
	if eS != nil && eD != nil && eS.Symbol == eD.Symbol {
		t.Errorf("entry points collapsed onto %q for both advisories (the mis-attribution this pins against)", eS.Symbol)
	}
	if gS != report.GradeAttackerTainted || gD != report.GradeAttackerTainted {
		t.Errorf("grades = %q/%q, want attacker_tainted for both (an attacker route lies on each trace)", gS, gD)
	}
}

// TestEntryPointFor_NoPositionalBorrowAmongMultiple is the inv.5 / AC4 honesty guard:
// when a candidate records NO reaching ingress and several ingresses exist, the entry
// point is left unknown (nil) rather than borrowed from the positionally-first
// attacker-controllable ingress in the shared map — borrowing is the exact mechanism that
// mis-attributed SSRF to expandHandler.
func TestEntryPointFor_NoPositionalBorrowAmongMultiple(t *testing.T) {
	if got := entryPointFor("", twoRouteIngressMap().Ingresses); got != nil {
		t.Errorf("entryPointFor(no reaching ingress, multiple ingresses) = %+v, want nil (no positional borrow)", got)
	}
}

// TestEntryPointFor_SingleIngressUnambiguous proves the guard does not over-fire: a lone
// ingress (the stub / single-route shape) is unambiguous, so it stays the entry point.
func TestEntryPointFor_SingleIngressUnambiguous(t *testing.T) {
	only := []plugin.Ingress{{Kind: "http_route", Selector: "GET /"}}
	if got := entryPointFor("", only); got == nil || got.Symbol != "GET /" || got.Kind != "http_route" {
		t.Errorf("entryPointFor(single ingress) = %+v, want the lone GET / ingress", got)
	}
}
