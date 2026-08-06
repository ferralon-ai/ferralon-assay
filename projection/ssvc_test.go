package projection_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

func TestSSVC_ProvenExploitable_ActDecision(t *testing.T) {
	// proven exploitable with FlagPublicPoCReplayed → Exploitation=active → Act
	p := fixtureProvenExploitable()
	// Add public PoC flag to drive Exploitation=active
	p.Confidence = verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{
		verdict.FlagCanaryTriggered,
		verdict.FlagPublicPoCReplayed,
	})
	d, err := projection.ProjectSSVC(p)
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.Exploitation != projection.SSVCExploitationActive {
		t.Fatalf("exploitation = %q, want %q", d.DecisionPoints.Exploitation, projection.SSVCExploitationActive)
	}
	if d.Decision != projection.SSVCDecisionTrackAct {
		t.Fatalf("decision = %q, want %q (act for active exploitation)", d.Decision, projection.SSVCDecisionTrackAct)
	}
}

func TestSSVC_ProvenExploitable_NoPublicPoC_AttendDecision(t *testing.T) {
	// proven exploitable without public PoC → Exploitation=poc, TechImpact=total → Attend
	d, err := projection.ProjectSSVC(fixtureProvenExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.Exploitation != projection.SSVCExploitationPoC {
		t.Fatalf("exploitation = %q, want %q", d.DecisionPoints.Exploitation, projection.SSVCExploitationPoC)
	}
	if d.Decision != projection.SSVCDecisionTrackAttend {
		t.Fatalf("decision = %q, want %q (attend for poc + total impact)", d.Decision, projection.SSVCDecisionTrackAttend)
	}
}

func TestSSVC_ReasonedExploitable_PoCDecision(t *testing.T) {
	// reasoned exploitable without public PoC → poc → Attend (conservative)
	d, err := projection.ProjectSSVC(fixtureReasonedExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	// fixtureReasonedExploitable has FlagPublicPoCReplayed → active → Act
	if d.DecisionPoints.Exploitation != projection.SSVCExploitationActive {
		t.Fatalf("exploitation = %q, want %q (public poc replayed flag present)", d.DecisionPoints.Exploitation, projection.SSVCExploitationActive)
	}
}

func TestSSVC_NotExploitable_TrackDecision(t *testing.T) {
	d, err := projection.ProjectSSVC(fixtureReasonedNotExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.Exploitation != projection.SSVCExploitationNone {
		t.Fatalf("not_exploitable: exploitation = %q, want %q", d.DecisionPoints.Exploitation, projection.SSVCExploitationNone)
	}
	if d.Decision != projection.SSVCDecisionTrackTrack {
		t.Fatalf("not_exploitable: decision = %q, want %q", d.Decision, projection.SSVCDecisionTrackTrack)
	}
}

func TestSSVC_Automatable_NoConditions_Yes(t *testing.T) {
	p := fixtureProvenExploitable()
	p.Conditions = nil
	d, err := projection.ProjectSSVC(p)
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.Automatable != projection.SSVCAutomatableYes {
		t.Fatalf("exploitable with no conditions: automatable = %q, want %q",
			d.DecisionPoints.Automatable, projection.SSVCAutomatableYes)
	}
}

func TestSSVC_Automatable_WithConditions_No(t *testing.T) {
	p := fixtureProvenExploitable()
	p.Conditions = []verdict.Condition{{Predicate: "authenticated_session"}}
	d, err := projection.ProjectSSVC(p)
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.Automatable != projection.SSVCAutomatableNo {
		t.Fatalf("exploitable with conditions: automatable = %q, want %q",
			d.DecisionPoints.Automatable, projection.SSVCAutomatableNo)
	}
}

func TestSSVC_TechnicalImpact_Exploitable_Total(t *testing.T) {
	d, err := projection.ProjectSSVC(fixtureProvenExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.TechnicalImpact != projection.SSVCTechnicalImpactTotal {
		t.Fatalf("exploitable: technical_impact = %q, want %q",
			d.DecisionPoints.TechnicalImpact, projection.SSVCTechnicalImpactTotal)
	}
}

func TestSSVC_TechnicalImpact_NotExploitable_Partial(t *testing.T) {
	d, err := projection.ProjectSSVC(fixtureReasonedNotExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.TechnicalImpact != projection.SSVCTechnicalImpactPartial {
		t.Fatalf("not_exploitable: technical_impact = %q, want %q",
			d.DecisionPoints.TechnicalImpact, projection.SSVCTechnicalImpactPartial)
	}
}

func TestSSVC_VectorString_Format(t *testing.T) {
	d, err := projection.ProjectSSVC(fixtureProvenExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	// Must start with SSVCv2/ and end with /
	if !strings.HasPrefix(d.Vector, "SSVCv2/") {
		t.Fatalf("vector %q must start with SSVCv2/", d.Vector)
	}
	if !strings.HasSuffix(d.Vector, "/") {
		t.Fatalf("vector %q must end with /", d.Vector)
	}
}

func TestSSVC_RoundTrip_ValidJSON(t *testing.T) {
	b, err := projection.MarshalSSVC(fixtureProvenExploitable())
	if err != nil {
		t.Fatalf("MarshalSSVC: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if raw["schema_version"] != projection.SSVCSchemaVersion {
		t.Fatalf("schema_version = %v, want %q", raw["schema_version"], projection.SSVCSchemaVersion)
	}
	if raw["decision_points"] == nil {
		t.Fatal("SSVC output missing decision_points")
	}
}

func TestSSVC_SourceTracksVerdictLabel(t *testing.T) {
	d, err := projection.ProjectSSVC(fixtureReasonedExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.Source.VerdictLabel != "reasoned_exploitable" {
		t.Fatalf("source.verdict_label = %q, want %q", d.Source.VerdictLabel, "reasoned_exploitable")
	}
	if d.Source.VerdictStrength != string(verdict.StrengthReasoned) {
		t.Fatalf("source.verdict_strength = %q, want %q", d.Source.VerdictStrength, verdict.StrengthReasoned)
	}
}

// TestSSVC_Inv5_ReasonedNotDowngradedToNone asserts that a reasoned_exploitable verdict
// is NOT mapped to Exploitation=none (which would suppress it entirely, violating honesty).
func TestSSVC_Inv5_ReasonedNotDowngradedToNone(t *testing.T) {
	d, err := projection.ProjectSSVC(fixtureReasonedExploitable())
	if err != nil {
		t.Fatalf("ProjectSSVC: %v", err)
	}
	if d.DecisionPoints.Exploitation == projection.SSVCExploitationNone {
		t.Fatal("inv.5 honesty: reasoned_exploitable MUST NOT project as Exploitation=none")
	}
}

func TestSSVC_EmptyDirection_ReturnsError(t *testing.T) {
	p := fixtureReasonedNotExploitable()
	p.Direction = ""
	if _, err := projection.ProjectSSVC(p); err == nil {
		t.Fatal("expected error for empty Direction, got nil")
	}
}

func TestSSVC_AllFourVerdicts_ProduceValidDecision(t *testing.T) {
	cases := []struct {
		name string
		poe  verdict.PoE
	}{
		{"proven_exploitable", fixtureProvenExploitable()},
		{"reasoned_exploitable", fixtureReasonedExploitable()},
		{"proven_not_exploitable", fixtureProvenNotExploitable()},
		{"reasoned_not_exploitable", fixtureReasonedNotExploitable()},
	}
	validDecisions := map[string]bool{
		projection.SSVCDecisionTrackAct:       true,
		projection.SSVCDecisionTrackAttend:    true,
		projection.SSVCDecisionTrackTrack:     true,
		projection.SSVCDecisionTrackTrackStar: true,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := projection.ProjectSSVC(tc.poe)
			if err != nil {
				t.Fatalf("ProjectSSVC: %v", err)
			}
			if !validDecisions[d.Decision] {
				t.Fatalf("decision %q is not a valid SSVC deployer decision", d.Decision)
			}
		})
	}
}
