// advisory_source_preconditions_test.go
//
// B3 (cycle 2026-08-24 corpus-scaffold): the advisory-declared exploit preconditions
// (trigger_condition / prerequisite) decode onto AdvisoryFacts and — unlike A2's store-only
// symbol_provenance — are PROJECTED onto the normalized_advisory artifact so the candidate-scoped
// PoE qualifier consumer (trigger.advisoryPreconditions, read only after a candidate forms) can read
// them. These pin two properties at the projection boundary:
//
//  1. A declared precondition round-trips onto the artifact verbatim.
//  2. An ABSENT precondition emits NO key (omitempty), so absence stays absence on the wire — never a
//     serialized "" a reader could mistake for a declared-empty precondition (honest-absent, inv.5).
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

func TestExploitPreconditions_ProjectedForCandidateQualifier(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{
		Module:           "example.com/x",
		VersionScheme:    "gomod",
		Symbols:          []string{"pkg.Vuln"},
		TriggerCondition: "a malicious HTTP/2 client rapidly resets requests",
		Prerequisite:     "HTTP/2 enabled",
	}}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-precond", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-PRECOND", Source: "corpus"},
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
		TriggerCondition string `json:"trigger_condition"`
		Prerequisite     string `json:"prerequisite"`
	}
	if err := json.Unmarshal(arts[0].Payload, &got); err != nil {
		t.Fatalf("decode normalized_advisory: %v", err)
	}
	if got.TriggerCondition != "a malicious HTTP/2 client rapidly resets requests" {
		t.Errorf("trigger_condition = %q, want the declared condition (B3 projects it for the candidate-qualifier consumer)", got.TriggerCondition)
	}
	if got.Prerequisite != "HTTP/2 enabled" {
		t.Errorf("prerequisite = %q, want %q", got.Prerequisite, "HTTP/2 enabled")
	}
}

func TestExploitPreconditions_AbsentOmittedFromProjection(t *testing.T) {
	src := selectionStubSource{facts: AdvisoryFacts{
		Module:        "example.com/x",
		VersionScheme: "gomod",
		Symbols:       []string{"pkg.Vuln"},
		// TriggerCondition / Prerequisite intentionally unset.
	}}

	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-precond-absent", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-PRECOND", Source: "corpus"},
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
	for _, k := range []string{"trigger_condition", "prerequisite"} {
		if _, present := keys[k]; present {
			t.Errorf("%s projected for an advisory that declared none — absent must stay absent (honest-absent, inv.5), never a serialized empty", k)
		}
	}
}
