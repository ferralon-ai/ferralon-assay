package trigger

import (
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// seedMaliciousPresence records the affirmative TypeMaliciousPresence artifact the maliciousPresence
// stage emits only on a decisive match, so a Report finding can be built for the affirmative arm.
func seedMaliciousPresence(t *testing.T, store *artifact.MemStore, assessmentID, matchedVersion string) {
	t.Helper()
	payload, err := json.Marshal(pipeline.MaliciousPresenceResult{Present: true, MatchedVersion: matchedVersion})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{
		AssessmentID: assessmentID, Type: artifact.TypeMaliciousPresence, ProducedBy: "test", Payload: payload,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// seedCandidate records a reachable candidate pair so a co-present reachability finding exists,
// letting a test prove the malicious-present arm outranks it.
func seedCandidate(t *testing.T, store *artifact.MemStore, assessmentID string) {
	t.Helper()
	reach, _ := json.Marshal(struct {
		Reachable bool `json:"reachable"`
	}{Reachable: true})
	reachRef, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: artifact.TypeReachability, ProducedBy: "test", Payload: reach})
	if err != nil {
		t.Fatalf("Put reachability: %v", err)
	}
	ingress, _ := json.Marshal(struct {
		Entrypoint string `json:"entrypoint"`
	}{Entrypoint: "GET /"})
	ingressRef, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: artifact.TypeIngressMap, ProducedBy: "test", Payload: ingress})
	if err != nil {
		t.Fatalf("Put ingress: %v", err)
	}
	pair, _ := json.Marshal(artifact.CandidatePair{
		SchemaVersion: artifact.CandidatePairSchemaVersion,
		Ingress:       &ingressRef,
		Path:          reachRef,
		Partial:       true,
	})
	if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: artifact.TypeCandidatePair, ProducedBy: "test", Payload: pair}); err != nil {
		t.Fatalf("Put candidate pair: %v", err)
	}
}

// A decisive malicious-present match projects to VerdictMaliciousPresent, carries the matched
// version in its detail, and carries NO not-exploitability basis (an affirmative has no refutation
// grounds — Report.Validate enforces this shape for every non-refutation verdict).
func TestFinding_MaliciousPresent_EmitsAffirmativeVerdict(t *testing.T) {
	store := artifact.NewMemStore()
	seedMaliciousPresence(t, store, "a1", "1.0.1")

	f := finding(store, "a1", report.Advisory{ID: "MAL-2024-1", Source: "test"}, nil)

	if f.Verdict != report.VerdictMaliciousPresent {
		t.Fatalf("verdict = %q, want %q", f.Verdict, report.VerdictMaliciousPresent)
	}
	if f.Evidence.Basis != verdict.BasisNone {
		t.Errorf("basis = %q, want none: a malicious-present affirmative has no refutation grounds", f.Evidence.Basis)
	}
	if f.Evidence.Detail == "" {
		t.Error("detail is empty — a malicious-present finding must state the matched version")
	}
	// The finding must satisfy the Report structural guard (inv.5).
	r := report.Report{SchemaVersion: report.SchemaVersion, Advisories: []report.AdvisoryFinding{f}}
	if err := r.Validate(); err != nil {
		t.Errorf("Report.Validate rejected a malicious-present finding: %v", err)
	}
}

// The malicious-present arm is ordered FIRST in finding(): a decisive presence proof outranks a
// co-present reachable candidate. Without the ordering the candidate arm would win and understate a
// decisive fact as a hedged candidate.
func TestFinding_MaliciousPresent_WinsOverCoPresentCandidate(t *testing.T) {
	store := artifact.NewMemStore()
	seedCandidate(t, store, "a1")
	seedMaliciousPresence(t, store, "a1", "2.3.4")

	// Guard: the candidate really is present, so the test proves ordering, not its absence.
	if !hasCandidate(store, "a1") {
		t.Fatal("precondition failed: seeded candidate is not visible to hasCandidate")
	}

	f := finding(store, "a1", report.Advisory{ID: "MAL-2024-2", Source: "test"}, nil)
	if f.Verdict != report.VerdictMaliciousPresent {
		t.Fatalf("verdict = %q, want %q (malicious-present must win over a co-present candidate)", f.Verdict, report.VerdictMaliciousPresent)
	}
}

// A store with no malicious-present artifact flows through the existing switch unchanged: a lone
// candidate stays a reachable_candidate. The new arm adds exactly one affirmative signal and
// changes nothing else.
func TestFinding_NoMaliciousPresence_CandidatePathUnchanged(t *testing.T) {
	store := artifact.NewMemStore()
	seedCandidate(t, store, "a1")

	f := finding(store, "a1", report.Advisory{ID: "CVE-2023-1", Source: "test"}, nil)
	if f.Verdict != report.VerdictReachableCandidate {
		t.Fatalf("verdict = %q, want %q (non-malicious path must be unchanged)", f.Verdict, report.VerdictReachableCandidate)
	}
}
