package trigger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// prioritySignals is a hand-written signals 1.x fixture: CVE-2021-38561 has EPSS only, CVE-2025-8110
// is KEV-listed with EPSS, and CVE-2024-55947 carries a stamped not-listed KEV observation.
func prioritySignals(t *testing.T) *intel.Signals {
	t.Helper()
	s, err := intel.Parse(strings.NewReader(`{"signals_version": "1.0.0", "record_count": 3,
	  "signals_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
	  "records": [
	    {"identifier": "CVE-2021-38561", "epss": {"score": 0.0123, "percentile": 0.456, "as_of": "2026-10-18"}},
	    {"identifier": "CVE-2025-8110", "epss": {"score": 0.91, "percentile": 0.99, "as_of": "2026-10-19"},
	     "kev": {"listed": true, "date_added": "2025-07-28", "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
	    {"identifier": "CVE-2024-55947", "kev": {"listed": false, "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPriorityForResolvesViaCVEAlias proves the EPSS lookup fires through a GO-id advisory's CVE
// alias (the plumbing from AdvisoryFacts.Aliases all the way to report.Priority), with the value's
// own stamp.
func TestPriorityForResolvesViaCVEAlias(t *testing.T) {
	p := priorityFor(report.Advisory{ID: "GO-2021-0113", Source: "osv", Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"}}, prioritySignals(t))
	want := report.Priority{EPSSScore: 0.0123, EPSSPercentile: 0.456, EPSSAsOf: "2026-10-18"}
	if p == nil || *p != want {
		t.Fatalf("priority = %+v, want %+v (EPSS via the CVE alias, no KEV fields)", p, want)
	}
}

// TestPriorityForCarriesEachValuesStamp: every value comes with its own stamp, and a stamped
// not-listed KEV observation is carried as one.
func TestPriorityForCarriesEachValuesStamp(t *testing.T) {
	sig := prioritySignals(t)
	got := priorityFor(report.Advisory{ID: "CVE-2025-8110", Source: "osv", Aliases: []string{"GO-2025-3900"}}, sig)
	want := report.Priority{
		EPSSScore: 0.91, EPSSPercentile: 0.99, EPSSAsOf: "2026-10-19",
		KEVListed: true, KEVDateAdded: "2025-07-28", KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z",
	}
	if got == nil || *got != want {
		t.Errorf("CVE-2025-8110 priority = %+v, want %+v", got, want)
	}
	got = priorityFor(report.Advisory{ID: "CVE-2024-55947", Source: "osv"}, sig)
	want = report.Priority{KEVCatalogVersion: "2026.10.19", KEVDateReleased: "2026-10-19T18:00:00Z"}
	if got == nil || *got != want {
		t.Errorf("CVE-2024-55947 priority = %+v, want the stamped not-listed observation %+v", got, want)
	}
}

// TestPriorityForNoSignalIsNil: a synthetic advisory with no id in the signals file, and any
// advisory in a run with no signals at all, carries no Priority.
func TestPriorityForNoSignalIsNil(t *testing.T) {
	if p := priorityFor(report.Advisory{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}, prioritySignals(t)); p != nil {
		t.Errorf("expected nil priority for an id the signals file lacks, got %+v", p)
	}
	if p := priorityFor(report.Advisory{ID: "CVE-2025-8110", Source: "osv"}, nil); p != nil {
		t.Errorf("expected nil priority with no signals, got %+v", p)
	}
}

// putJSON stores one artifact of type typ under assessmentID with a JSON payload.
func putJSON(t *testing.T, store artifact.Store, assessmentID string, typ artifact.Type, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", typ, err)
	}
	if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: typ, Payload: b}); err != nil {
		t.Fatalf("put %s: %v", typ, err)
	}
}

// TestReachabilityEvidenceAttackerTainted proves the strongest grade requires BOTH an
// attacker-controllable ingress AND taint path-presence to the sink (inv. 5: still a
// candidate, never exploitable).
func TestReachabilityEvidenceAttackerTainted(t *testing.T) {
	store := artifact.NewMemStore()
	const aid = "a1"
	putJSON(t, store, aid, artifact.TypeIngressMap, plugin.IngressResult{
		Ingresses: []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: "ing"}, Selector: "GET /fetch"}},
	})
	putJSON(t, store, aid, artifact.TypeTaint, struct {
		Result plugin.TaintResult `json:"result"`
	}{Result: plugin.TaintResult{Paths: []plugin.ReachPath{{Sink: plugin.Symbol{SCIP: "sink"}, Ingress: plugin.Symbol{SCIP: "ing"}, Trace: []plugin.Symbol{{SCIP: "ing"}, {SCIP: "mid"}, {SCIP: "sink"}}}}}})

	grade, entry, frames := reachabilityEvidence(store, aid)
	if grade != report.GradeAttackerTainted {
		t.Errorf("grade = %q, want attacker_tainted", grade)
	}
	if entry == nil || !entry.AttackerControllable || entry.Symbol != "GET /fetch" || entry.Kind != "http_route" {
		t.Errorf("entry = %+v, want attacker-controllable http_route GET /fetch", entry)
	}
	if len(frames) != 3 || frames[0].Symbol != "ing" || frames[2].Symbol != "sink" {
		t.Errorf("frames = %+v, want ingress→sink trace of 3", frames)
	}
}

// TestReachabilityEvidenceAttackerOnReachPath proves that when the only path-presence
// evidence is the reachability trace (no separate taint artifact), an attacker-
// controllable ingress lying ON that trace still earns attacker_tainted — the call
// path is itself the ingress→sink path-presence at the taint op's precision.
func TestReachabilityEvidenceAttackerOnReachPath(t *testing.T) {
	store := artifact.NewMemStore()
	const aid = "a2"
	putJSON(t, store, aid, artifact.TypeIngressMap, plugin.IngressResult{
		Ingresses: []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: "ing"}, Selector: "GET /x"}},
	})
	putJSON(t, store, aid, artifact.TypeReachability, struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
	}{Reachability: plugin.ReachabilityResult{Paths: []plugin.ReachPath{{Sink: plugin.Symbol{SCIP: "sink"}, Ingress: plugin.Symbol{SCIP: "ing"}, Trace: []plugin.Symbol{{SCIP: "ing"}, {SCIP: "sink"}}}}}})

	grade, entry, frames := reachabilityEvidence(store, aid)
	if grade != report.GradeAttackerTainted {
		t.Errorf("grade = %q, want attacker_tainted (attacker ingress on the reach path)", grade)
	}
	if entry == nil || !entry.AttackerControllable || frames == nil {
		t.Errorf("expected attacker-controllable entry + frames, got entry=%+v frames=%+v", entry, frames)
	}
}

// TestReachabilityEvidenceNonAttackerIngress proves that taint to a sink behind a
// non-attacker-controllable entry (e.g. a CLI main) does NOT earn the stronger grade.
func TestReachabilityEvidenceNonAttackerIngress(t *testing.T) {
	store := artifact.NewMemStore()
	const aid = "a3"
	putJSON(t, store, aid, artifact.TypeIngressMap, plugin.IngressResult{
		Ingresses: []plugin.Ingress{{Kind: "main", Symbol: plugin.Symbol{SCIP: "main.main"}}},
	})
	putJSON(t, store, aid, artifact.TypeTaint, struct {
		Result plugin.TaintResult `json:"result"`
	}{Result: plugin.TaintResult{Paths: []plugin.ReachPath{{Sink: plugin.Symbol{SCIP: "sink"}, Ingress: plugin.Symbol{SCIP: "main.main"}, Trace: []plugin.Symbol{{SCIP: "main.main"}, {SCIP: "sink"}}}}}})

	if grade, _, _ := reachabilityEvidence(store, aid); grade != report.GradeControlFlowOnly {
		t.Errorf("grade = %q, want control_flow_only for a non-attacker-controllable ingress", grade)
	}
}
