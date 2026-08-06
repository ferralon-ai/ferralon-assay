package verdict

import (
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

func TestPoEProofReportRefRoundTrips(t *testing.T) {
	ref := artifact.Ref{ID: "rep-1", Type: artifact.Type("proof_report")}
	poe := PoE{
		SchemaVersion:   SchemaVersion,
		AssessmentID:    "case-1",
		CaseID:          "matter-1",
		Direction:       DirectionNotExploitable,
		Strength:        StrengthReasoned,
		ReasonedGrounds: "no engine",
		Confidence:      ConfidenceFromFlags(nil),
		ProofReport:     &ref,
	}
	if err := poe.Validate(); err != nil {
		t.Fatalf("adding a ProofReport ref must not affect Validate: %v", err)
	}
	b, _ := json.Marshal(poe)
	var got PoE
	json.Unmarshal(b, &got)
	if got.ProofReport == nil || got.ProofReport.ID != "rep-1" {
		t.Fatalf("ProofReport ref lost in round-trip: %+v", got.ProofReport)
	}
}

func TestLabel(t *testing.T) {
	cases := []struct {
		name string
		dir  Direction
		str  Strength
		want string
	}{
		{"proven_exploitable", DirectionExploitable, StrengthProven, "exploitable"},
		{"proven_not_exploitable", DirectionNotExploitable, StrengthProven, "not_exploitable"},
		{"reasoned_exploitable", DirectionExploitable, StrengthReasoned, "reasoned_exploitable"},
		{"reasoned_not_exploitable", DirectionNotExploitable, StrengthReasoned, "reasoned_not_exploitable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := PoE{Direction: tc.dir, Strength: tc.str}
			if got := p.Label(); got != tc.want {
				t.Fatalf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSchemaVersionConst(t *testing.T) {
	if SchemaVersion != "tegron.poe.v1" {
		t.Fatalf("SchemaVersion = %q, want %q", SchemaVersion, "tegron.poe.v1")
	}
}

// helper: a minimal well-formed reasoned_not_exploitable PoE.
func wellFormedReasonedNotExploitable() PoE {
	return PoE{
		SchemaVersion:    SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000001",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        DirectionNotExploitable,
		Strength:         StrengthReasoned,
		Conditions:       nil,
		ReasonedGrounds:  "no reachable call path from any ingress to the vulnerable symbol",
		Confidence:       ConfidenceFromFlags([]EvidenceFlag{FlagStaticTaintPathComplete}),
		CompletionStatus: CompletionCompleted,
		Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
	}
}

func TestValidate_RejectsReasonedWithoutGrounds(t *testing.T) {
	p := wellFormedReasonedNotExploitable()
	p.ReasonedGrounds = ""
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for reasoned verdict with empty ReasonedGrounds, got nil")
	}
}

func TestValidate_RejectsProvenWithoutProofFlag(t *testing.T) {
	p := PoE{
		SchemaVersion:    SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000002",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        DirectionNotExploitable,
		Strength:         StrengthProven,
		Confidence:       CalibratedConfidence{Score: 0.4, EvidenceFlags: []EvidenceFlag{FlagStaticTaintPathComplete}},
		CompletionStatus: CompletionCompleted,
		Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for proven verdict without a proof flag, got nil")
	}
}

func TestValidate_RejectsExploitableProvenWithoutReproducer(t *testing.T) {
	p := PoE{
		SchemaVersion:    SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000003",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        DirectionExploitable,
		Strength:         StrengthProven,
		Confidence:       ConfidenceFromFlags([]EvidenceFlag{FlagCanaryTriggered}),
		CompletionStatus: CompletionCompleted,
		Reproducer:       nil, // RFC 0001 inv. 5: missing execution proof.
		Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for exploitable+proven without a Reproducer ref, got nil")
	}
}

func TestValidate_AcceptsWellFormedReasonedNotExploitable(t *testing.T) {
	p := wellFormedReasonedNotExploitable()
	if err := p.Validate(); err != nil {
		t.Fatalf("expected well-formed reasoned_not_exploitable to validate, got %v", err)
	}
}

func TestValidate_AcceptsWellFormedExploitableProven(t *testing.T) {
	p := PoE{
		SchemaVersion:    SchemaVersion,
		ArtifactID:       "01890000-0000-7000-8000-000000000004",
		AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
		CaseID:           "01890000-0000-7000-8000-0000000000a0",
		Direction:        DirectionExploitable,
		Strength:         StrengthProven,
		Confidence:       ConfidenceFromFlags([]EvidenceFlag{FlagCanaryTriggered}),
		CompletionStatus: CompletionCompleted,
		Reproducer:       &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000cc", Type: artifact.Type("reproducer")},
		Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected well-formed exploitable+proven to validate, got %v", err)
	}
}

// TestValidate_ProvenNotExploitableRequiresPatchValidation covers the RFC 0010 two-trace guard
// added to Validate(): a proven not_exploitable verdict MUST carry a PatchValidation with both
// trace refs; missing or partial is rejected, complete is accepted.
func TestValidate_ProvenNotExploitableRequiresPatchValidation(t *testing.T) {
	base := func() PoE {
		return PoE{
			SchemaVersion:    SchemaVersion,
			AssessmentID:     "01890000-0000-7000-8000-0000000000aa",
			CaseID:           "01890000-0000-7000-8000-0000000000a0",
			Direction:        DirectionNotExploitable,
			Strength:         StrengthProven,
			Confidence:       ConfidenceFromFlags([]EvidenceFlag{FlagCanaryTriggered}),
			CompletionStatus: CompletionCompleted,
			Episodes:         []string{"01890000-0000-7000-8000-0000000000bb"},
		}
	}
	pos := &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000c1", Type: artifact.Type("proof_report")}
	neg := &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000c2", Type: artifact.Type("proof_report")}

	cases := []struct {
		name    string
		pv      *PatchValidationRef
		wantErr bool
	}{
		{"missing", nil, true},
		{"positive_only", &PatchValidationRef{PositiveTrace: pos, FixSource: "advisory:v0.3.7"}, true},
		{"negative_only", &PatchValidationRef{NegativeTrace: neg, FixSource: "advisory:v0.3.7"}, true},
		{"both", &PatchValidationRef{PositiveTrace: pos, NegativeTrace: neg, FixSource: "advisory:v0.3.7"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			p.PatchValidation = tc.pv
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected %s to validate, got %v", tc.name, err)
			}
		})
	}
}

// TestValidate_NonExploitableBasisOnlyOnReasonedNotExploitable enforces the inverted inv.5
// structural guard: a grounded NonExploitableBasis (a disqualification refutation) is a REASONED
// claim and may appear ONLY on a reasoned not_exploitable verdict. Attaching it to a proven verdict
// (a refutation masquerading as a proof — exactly the re-scan-only basis RFC 0010 rejects) or to an
// exploitable verdict is rejected.
func TestValidate_NonExploitableBasisOnlyOnReasonedNotExploitable(t *testing.T) {
	t.Run("reasoned_not_exploitable_accepts", func(t *testing.T) {
		p := wellFormedReasonedNotExploitable()
		p.NonExploitableBasis = BasisVersionNotAffected
		if err := p.Validate(); err != nil {
			t.Fatalf("grounded reasoned not_exploitable must validate, got %v", err)
		}
	})
	t.Run("proven_not_exploitable_rejects", func(t *testing.T) {
		// A proven not_exploitable (two-trace PoNE) must NOT also carry a disqualification basis.
		pos := &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000c1", Type: artifact.Type("proof_report")}
		neg := &artifact.Ref{ID: "01890000-0000-7000-8000-0000000000c2", Type: artifact.Type("proof_report")}
		p := PoE{
			SchemaVersion:       SchemaVersion,
			AssessmentID:        "01890000-0000-7000-8000-0000000000aa",
			CaseID:              "01890000-0000-7000-8000-0000000000a0",
			Direction:           DirectionNotExploitable,
			Strength:            StrengthProven,
			Confidence:          ConfidenceFromFlags([]EvidenceFlag{FlagCanaryTriggered}),
			CompletionStatus:    CompletionCompleted,
			PatchValidation:     &PatchValidationRef{PositiveTrace: pos, NegativeTrace: neg, FixSource: "advisory:v0.3.7"},
			NonExploitableBasis: BasisVersionNotAffected,
			Episodes:            []string{"01890000-0000-7000-8000-0000000000bb"},
		}
		if err := p.Validate(); err == nil {
			t.Fatal("inverted inv.5: a disqualification basis on a PROVEN verdict must be rejected")
		}
	})
	t.Run("exploitable_rejects", func(t *testing.T) {
		p := PoE{
			SchemaVersion:       SchemaVersion,
			AssessmentID:        "01890000-0000-7000-8000-0000000000aa",
			CaseID:              "01890000-0000-7000-8000-0000000000a0",
			Direction:           DirectionExploitable,
			Strength:            StrengthReasoned,
			ReasonedGrounds:     "lean",
			CompletionStatus:    CompletionCompleted,
			NonExploitableBasis: BasisSymbolAbsent,
			Episodes:            []string{"01890000-0000-7000-8000-0000000000bb"},
		}
		if err := p.Validate(); err == nil {
			t.Fatal("a non_exploitable_basis on an EXPLOITABLE verdict must be rejected")
		}
	})
}

func TestConfidenceFromFlags(t *testing.T) {
	const eps = 1e-9
	cases := []struct {
		name  string
		flags []EvidenceFlag
		want  float64
	}{
		{"empty", nil, 0.1},
		{"empty_slice", []EvidenceFlag{}, 0.1},
		{"one_non_proof", []EvidenceFlag{FlagStaticTaintPathComplete}, 0.4},
		{"two_non_proof", []EvidenceFlag{FlagStaticTaintPathComplete, FlagPublicPoCReplayed}, 0.7},
		{"one_proof_canary", []EvidenceFlag{FlagCanaryTriggered}, 0.9},
		{"one_proof_syscall", []EvidenceFlag{FlagSyscallConsistent}, 0.9},
		{"proof_plus_non_proof_floor", []EvidenceFlag{FlagStaticTaintPathComplete, FlagCanaryTriggered}, 0.9},
		{"proof_dominates_many_non_proof", []EvidenceFlag{FlagStaticTaintPathComplete, FlagPublicPoCReplayed, FlagCanaryTriggered}, 0.9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ConfidenceFromFlags(tc.flags)
			if got.Score < tc.want-eps || got.Score > tc.want+eps {
				t.Fatalf("Score = %v, want %v", got.Score, tc.want)
			}
			if len(got.EvidenceFlags) != len(tc.flags) {
				t.Fatalf("EvidenceFlags len = %d, want %d", len(got.EvidenceFlags), len(tc.flags))
			}
		})
	}
}

func TestConfidenceFromFlags_CapsAt099(t *testing.T) {
	// Four non-proof copies would give 0.1 + 4*0.3 = 1.3; must cap at 0.99.
	flags := []EvidenceFlag{
		FlagStaticTaintPathComplete,
		FlagPublicPoCReplayed,
		FlagStaticTaintPathComplete,
		FlagPublicPoCReplayed,
	}
	got := ConfidenceFromFlags(flags)
	if got.Score != 0.99 {
		t.Fatalf("Score = %v, want 0.99 (cap)", got.Score)
	}
}

func TestConfidenceFromFlags_Deterministic(t *testing.T) {
	flags := []EvidenceFlag{FlagStaticTaintPathComplete, FlagCanaryTriggered}
	first := ConfidenceFromFlags(flags)
	for i := 0; i < 5; i++ {
		if got := ConfidenceFromFlags(flags); got.Score != first.Score {
			t.Fatalf("non-deterministic: run %d Score = %v, first = %v", i, got.Score, first.Score)
		}
	}
}
