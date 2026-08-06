package pipeline

import "testing"

// TestSBOMStages_OnlyS1S2 proves SBOMStages returns exactly the two SBOM-producing
// stages — advisory_intake (S1) then codebase_inventory (S2) — and none of the S3–S6
// analysis stages. This is the cheap dependency-resolution slice the PR-inherit
// head-SBOM resolver runs.
func TestSBOMStages_OnlyS1S2(t *testing.T) {
	stages := SBOMStages()
	want := []string{"advisory_intake", "codebase_inventory"}
	if len(stages) != len(want) {
		t.Fatalf("SBOMStages() returned %d stages, want %d", len(stages), len(want))
	}
	for i, name := range want {
		if got := stages[i].Name(); got != name {
			t.Fatalf("stage %d = %q, want %q", i, got, name)
		}
	}
}
