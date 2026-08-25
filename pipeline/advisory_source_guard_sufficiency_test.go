// advisory_source_guard_sufficiency_test.go
//
// B-guardsuff (cycle 2026-08-24 corpus-scaffold): the advisory-declared guard_sufficiency variants
// decode onto AdvisoryFacts and — like B3's trigger_condition — are PROJECTED onto the
// normalized_advisory artifact so the candidate-scoped annotation consumer
// (trigger.advisoryGuardSufficiency, read only after a candidate forms) can read them. The projection
// crosses the Prove→Assess boundary as DECLARED advisory data (advisory_guards grade), never as a Prove
// verdict. These pin two properties at the projection boundary:
//
//  1. Declared guard-sufficiency variants round-trip onto the artifact verbatim.
//  2. An ABSENT guard_sufficiency emits NO key (omitempty), so absence stays absence on the wire — never
//     a serialized empty array a reader could mistake for a declared-empty sufficiency set
//     (honest-absent, inv.5).
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

func TestGuardSufficiency_ProjectedForCandidateAnnotation(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{
		Module:        "example.com/x",
		VersionScheme: "gomod",
		Symbols:       []string{"pkg.Vuln"},
		GuardSymbols:  []string{"IsSymlink", "hasSymlinkInPath"},
		GuardSufficiency: []GuardVariant{
			{Symbol: "IsSymlink", Version: "0.13.3", ForBypass: "CVE-2025-8110", Sufficient: false},
			{Symbol: "hasSymlinkInPath", Version: "0.13.4", ForBypass: "CVE-2025-8110", Sufficient: true},
		},
	}}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-guardsuff", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-2025-8110", Source: "corpus"},
	}}
	stages := AssessStages(WithAdvisorySource(src))
	if err := stages[0].Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake run: %v", err)
	}
	arts, err := store.Query(c.ID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no normalized_advisory artifact written (err=%v)", err)
	}

	var got struct {
		GuardSufficiency []struct {
			Symbol     string `json:"symbol"`
			Version    string `json:"version"`
			ForBypass  string `json:"for_bypass"`
			Sufficient bool   `json:"sufficient"`
		} `json:"guard_sufficiency"`
	}
	if err := json.Unmarshal(arts[0].Payload, &got); err != nil {
		t.Fatalf("decode normalized_advisory: %v", err)
	}
	if len(got.GuardSufficiency) != 2 {
		t.Fatalf("guard_sufficiency = %+v, want 2 declared variants projected", got.GuardSufficiency)
	}
	if got.GuardSufficiency[0].Symbol != "IsSymlink" || got.GuardSufficiency[0].Sufficient {
		t.Errorf("variant 0 = %+v, want IsSymlink sufficient:false (the present-but-insufficient guard)", got.GuardSufficiency[0])
	}
	if got.GuardSufficiency[1].Symbol != "hasSymlinkInPath" || !got.GuardSufficiency[1].Sufficient {
		t.Errorf("variant 1 = %+v, want hasSymlinkInPath sufficient:true", got.GuardSufficiency[1])
	}
	if got.GuardSufficiency[1].ForBypass != "CVE-2025-8110" {
		t.Errorf("for_bypass = %q, want %q", got.GuardSufficiency[1].ForBypass, "CVE-2025-8110")
	}
}

func TestGuardSufficiency_AbsentOmittedFromProjection(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{
		Module:        "example.com/x",
		VersionScheme: "gomod",
		Symbols:       []string{"pkg.Vuln"},
		// GuardSufficiency intentionally unset.
	}}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-guardsuff-absent", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-X", Source: "corpus"},
	}}
	stages := AssessStages(WithAdvisorySource(src))
	if err := stages[0].Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake run: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeNormalizedAdvisory)
	if len(arts) == 0 {
		t.Fatal("no normalized_advisory artifact written")
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(arts[0].Payload, &keys); err != nil {
		t.Fatalf("decode normalized_advisory: %v", err)
	}
	if _, present := keys["guard_sufficiency"]; present {
		t.Error("guard_sufficiency projected for an advisory that declared none — absent must stay absent (honest-absent, inv.5), never a serialized empty array")
	}
}
