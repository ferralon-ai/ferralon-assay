package projection_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// fixtureReasonedNotExploitable returns a well-formed reasoned_not_exploitable PoE.
func fixtureReasonedNotExploitable() verdict.PoE {
	return verdict.PoE{
		SchemaVersion:    verdict.SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000001",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        verdict.DirectionNotExploitable,
		Strength:         verdict.StrengthReasoned,
		ReasonedGrounds:  "no reachable call path from any ingress to the vulnerable symbol",
		Confidence:       verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{verdict.FlagStaticTaintPathComplete}),
		CompletionStatus: verdict.CompletionCompleted,
		Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
	}
}

// fixtureReasonedExploitable returns a well-formed reasoned_exploitable PoE.
func fixtureReasonedExploitable() verdict.PoE {
	return verdict.PoE{
		SchemaVersion:    verdict.SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000002",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        verdict.DirectionExploitable,
		Strength:         verdict.StrengthReasoned,
		ReasonedGrounds:  "taint path reaches sink via user-controlled input at handler boundary",
		Confidence:       verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{verdict.FlagStaticTaintPathComplete, verdict.FlagPublicPoCReplayed}),
		CompletionStatus: verdict.CompletionStoppedBudget,
		Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
	}
}

// fixtureProvenExploitable returns a well-formed proven exploitable PoE.
func fixtureProvenExploitable() verdict.PoE {
	return verdict.PoE{
		SchemaVersion:    verdict.SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000003",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        verdict.DirectionExploitable,
		Strength:         verdict.StrengthProven,
		Confidence:       verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{verdict.FlagCanaryTriggered}),
		CompletionStatus: verdict.CompletionCompleted,
		Reproducer:       &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000cc", Type: artifact.Type("reproducer")},
		Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
	}
}

// fixtureProvenNotExploitable returns a well-formed proven not_exploitable PoE (PoNE).
func fixtureProvenNotExploitable() verdict.PoE {
	pos := &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000c1", Type: artifact.Type("proof_report")}
	neg := &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000c2", Type: artifact.Type("proof_report")}
	return verdict.PoE{
		SchemaVersion:    verdict.SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000004",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        verdict.DirectionNotExploitable,
		Strength:         verdict.StrengthProven,
		Confidence:       verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{verdict.FlagCanaryTriggered}),
		CompletionStatus: verdict.CompletionCompleted,
		PatchValidation: &verdict.PatchValidationRef{
			PositiveTrace: pos,
			NegativeTrace: neg,
			FixSource:     "advisory:v0.3.7",
		},
		Episodes: []string{"01890000-0000-7000-8000-0000000000bb"},
	}
}

// --- SARIF tests ---

func TestSARIF_ProvenExploitable_IsError(t *testing.T) {
	log, err := projection.ProjectSARIF(fixtureProvenExploitable())
	if err != nil {
		t.Fatalf("ProjectSARIF: %v", err)
	}
	result := log.Runs[0].Results[0]
	if result.Level != "error" {
		t.Fatalf("proven exploitable: want level=error, got %q", result.Level)
	}
	if result.Kind != "fail" {
		t.Fatalf("proven exploitable: want kind=fail, got %q", result.Kind)
	}
}

func TestSARIF_ReasonedExploitable_IsWarning_NotError(t *testing.T) {
	// inv.5 honesty: a reasoned lean MUST NOT map to "error".
	// "error" in SARIF implies a confirmed finding; "warning" signals a hypothesis.
	log, err := projection.ProjectSARIF(fixtureReasonedExploitable())
	if err != nil {
		t.Fatalf("ProjectSARIF: %v", err)
	}
	result := log.Runs[0].Results[0]
	if result.Level == "error" {
		t.Fatalf("reasoned_exploitable MUST NOT project as SARIF level=error (inv.5 honesty violation)")
	}
	if result.Level != "warning" {
		t.Fatalf("reasoned_exploitable: want level=warning, got %q", result.Level)
	}
	if result.Kind != "open" {
		t.Fatalf("reasoned_exploitable: want kind=open, got %q", result.Kind)
	}
}

func TestSARIF_ProvenNotExploitable_IsNote(t *testing.T) {
	log, err := projection.ProjectSARIF(fixtureProvenNotExploitable())
	if err != nil {
		t.Fatalf("ProjectSARIF: %v", err)
	}
	result := log.Runs[0].Results[0]
	if result.Level != "note" {
		t.Fatalf("proven not_exploitable: want level=note, got %q", result.Level)
	}
}

func TestSARIF_ReasonedNotExploitable_IsNone(t *testing.T) {
	log, err := projection.ProjectSARIF(fixtureReasonedNotExploitable())
	if err != nil {
		t.Fatalf("ProjectSARIF: %v", err)
	}
	result := log.Runs[0].Results[0]
	if result.Level != "none" {
		t.Fatalf("reasoned not_exploitable: want level=none, got %q", result.Level)
	}
}

func TestSARIF_RuleIDContainsLabel(t *testing.T) {
	cases := []struct {
		name    string
		poe     verdict.PoE
		wantSub string
	}{
		{"proven_exploitable", fixtureProvenExploitable(), "exploitable"},
		{"reasoned_exploitable", fixtureReasonedExploitable(), "reasoned_exploitable"},
		{"proven_not_exploitable", fixtureProvenNotExploitable(), "not_exploitable"},
		{"reasoned_not_exploitable", fixtureReasonedNotExploitable(), "reasoned_not_exploitable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log, err := projection.ProjectSARIF(tc.poe)
			if err != nil {
				t.Fatalf("ProjectSARIF: %v", err)
			}
			ruleID := log.Runs[0].Results[0].RuleID
			if !strings.Contains(ruleID, tc.wantSub) {
				t.Fatalf("ruleId %q does not contain %q", ruleID, tc.wantSub)
			}
		})
	}
}

func TestSARIF_RoundTrip_ValidJSON(t *testing.T) {
	b, err := projection.MarshalSARIF(fixtureReasonedNotExploitable())
	if err != nil {
		t.Fatalf("MarshalSARIF: %v", err)
	}
	// Must be valid JSON and have $schema / version fields.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if raw["$schema"] == nil {
		t.Fatal("SARIF output missing $schema field")
	}
	if raw["version"] == nil {
		t.Fatal("SARIF output missing version field")
	}
	if raw["version"] != projection.SARIFVersion {
		t.Fatalf("SARIF version = %v, want %q", raw["version"], projection.SARIFVersion)
	}
}

func TestSARIF_TegronProperties_IncludeLabel(t *testing.T) {
	log, err := projection.ProjectSARIF(fixtureReasonedExploitable())
	if err != nil {
		t.Fatalf("ProjectSARIF: %v", err)
	}
	result := log.Runs[0].Results[0]
	if result.Properties == nil || result.Properties.Tegron == nil {
		t.Fatal("SARIF result missing tegron properties")
	}
	label, ok := result.Properties.Tegron["verdict_label"]
	if !ok {
		t.Fatal("tegron properties missing verdict_label")
	}
	if label != "reasoned_exploitable" {
		t.Fatalf("verdict_label = %v, want %q", label, "reasoned_exploitable")
	}
}

// TestSARIF_Inv5_ReasonedNeverProven is the explicit inv.5 honesty invariant test.
// A reasoned verdict must NEVER project as SARIF level "error" (proven-finding tier).
func TestSARIF_Inv5_ReasonedNeverProven(t *testing.T) {
	reasonedPOEs := []verdict.PoE{
		fixtureReasonedExploitable(),
		fixtureReasonedNotExploitable(),
	}
	for _, p := range reasonedPOEs {
		log, err := projection.ProjectSARIF(p)
		if err != nil {
			t.Fatalf("ProjectSARIF(%s): %v", p.Label(), err)
		}
		for _, result := range log.Runs[0].Results {
			if result.Level == "error" {
				t.Errorf("inv.5 VIOLATION: reasoned verdict %q projected as SARIF level=error (proven-finding tier)", p.Label())
			}
		}
	}
}

func TestSARIF_EmptyDirection_ReturnsError(t *testing.T) {
	p := fixtureReasonedNotExploitable()
	p.Direction = ""
	if _, err := projection.ProjectSARIF(p); err == nil {
		t.Fatal("expected error for empty Direction, got nil")
	}
}
