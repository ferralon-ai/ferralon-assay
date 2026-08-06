// stages_public_poc_summary_test.go
//
// Row 3 (v3 poc_summary), producer side: the advisory_intake stage widens the public_poc artifact
// from {available} to {available, summary}, carrying the corpus PoC trigger SHAPE (facts.PocSummary)
// so the Service-side seed can adapt a known shape. Absent summary ⇒ omitempty (free-tier path).
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// pocSummarySource is a stub AdvisorySource returning fixed facts for any id — enough to drive the
// advisory_intake public_poc write without the in-memory AdvisoryTable.
type pocSummarySource struct{ facts AdvisoryFacts }

func (s pocSummarySource) Lookup(string) (AdvisoryFacts, bool) { return s.facts, true }

func runIntakePublicPoC(t *testing.T, facts AdvisoryFacts) (available bool, summary string) {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-poc", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-TEST-0001", Source: "corpus"},
	}}
	if err := (advisoryIntake{src: pocSummarySource{facts: facts}}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypePublicPoC)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no public_poc artifact written (err=%v)", err)
	}
	var poc struct {
		Available bool   `json:"available"`
		Summary   string `json:"summary"`
	}
	if err := json.Unmarshal(arts[0].Payload, &poc); err != nil {
		t.Fatalf("decode public_poc: %v", err)
	}
	return poc.Available, poc.Summary
}

// A corpus that declares poc_signal + poc_summary is written through to the public_poc artifact:
// availability AND the trigger-shape summary both land.
func TestAdvisoryIntake_PublicPoCCarriesSummary(t *testing.T) {
	const shape = "duplicate -t- extension singleton in a BCP-47 Accept-Language tag"
	avail, summary := runIntakePublicPoC(t, AdvisoryFacts{PocSignal: true, PocSummary: shape})
	if !avail {
		t.Fatal("public_poc.available must be true when PocSignal is set")
	}
	if summary != shape {
		t.Fatalf("public_poc.summary = %q, want the corpus PocSummary %q", summary, shape)
	}
}

// A corpus silent on poc_summary (today's free-tier shape): availability may still be set, but the
// summary is empty (omitempty) — no shape to adapt, unchanged behavior.
func TestAdvisoryIntake_PublicPoCNoSummaryOmitted(t *testing.T) {
	avail, summary := runIntakePublicPoC(t, AdvisoryFacts{PocSignal: true})
	if !avail {
		t.Fatal("public_poc.available must be true when PocSignal is set")
	}
	if summary != "" {
		t.Fatalf("public_poc.summary = %q, want empty when the corpus declares none", summary)
	}
}
