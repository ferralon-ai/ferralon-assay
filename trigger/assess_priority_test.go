package trigger

import (
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestPriorityForResolvesViaCVEAlias proves the offline EPSS lookup fires through a
// GO-id advisory's CVE alias (the plumbing from AdvisoryFacts.Aliases all the way to
// report.Priority). GO-2021-0113 aliases CVE-2021-38561, which is in the pinned EPSS
// snapshot.
func TestPriorityForResolvesViaCVEAlias(t *testing.T) {
	p := priorityFor(report.Advisory{ID: "GO-2021-0113", Source: "osv", Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"}})
	if p == nil {
		t.Fatal("expected EPSS priority via the CVE alias, got nil")
	}
	if p.EPSSScore <= 0 || p.EPSSPercentile <= 0 {
		t.Errorf("expected a positive EPSS score/percentile, got %+v", p)
	}
	if p.Snapshot == "" {
		t.Error("expected the snapshot date stamped for provenance")
	}
}

// TestPriorityForNoCVEisNil proves a synthetic advisory with no CVE id/alias carries
// no likelihood signal (correct: EPSS/KEV are CVE-keyed).
func TestPriorityForNoCVEisNil(t *testing.T) {
	if p := priorityFor(report.Advisory{ID: "FERRALON-APP-SSRF-0001", Source: "osv"}); p != nil {
		t.Errorf("expected nil priority for a non-CVE advisory, got %+v", p)
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
