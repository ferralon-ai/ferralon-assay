package pipeline

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestAdvisoryTargetConditionalSymbols_Intake carries the built-in set's target-conditional symbols
// through the normalized advisory, and none for an advisory that declares none.
func TestAdvisoryTargetConditionalSymbols_Intake(t *testing.T) {
	for _, id := range []string{"CVE-2024-21907", "FERRALON-JAVA-DEP-0001"} {
		t.Run(id, func(t *testing.T) {
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-" + id, Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: id, Source: "corpus"},
			}}
			if err := (advisoryIntake{}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			got, want := AdvisoryTargetConditionalSymbols(store, c.ID), AdvisoryTable[id].TargetConditionalSymbols
			if !slices.Equal(got, want) {
				t.Fatalf("target-conditional symbols = %v, want %v", got, want)
			}
		})
	}
}
