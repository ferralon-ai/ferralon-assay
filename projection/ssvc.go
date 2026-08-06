// internal/projection/ssvc.go
//
// SSVC (Stakeholder-Specific Vulnerability Categorization) projection of a Tegron PoE.
//
// SSVC v2.0 decision tree reference: https://certcc.github.io/SSVC/
//
// Decision points emitted:
//   - Exploitation    — how exploits are available in the wild
//   - Automatable     — whether the attack can be scripted end-to-end
//   - TechnicalImpact — what an attacker can do once exploitation succeeds
//   - MissionWellbeingImpact — combined safety/wellbeing impact (operator tree)
//
// Mapping from PoE fields:
//
//	Exploitation:
//	  proven exploitable + FlagPublicPoCReplayed → "active"  (public PoC was used)
//	  proven exploitable                         → "poc"     (Tegron reproducer = PoC-equivalent)
//	  reasoned exploitable                       → "poc"     (substantiated lean)
//	  not_exploitable (proven or reasoned)       → "none"
//
//	Automatable:
//	  Conditions is empty && exploitable         → "yes"     (no required preconditions)
//	  Conditions non-empty || not_exploitable    → "no"
//
//	TechnicalImpact:
//	  exploitable (any strength)                 → "total"   (conservative; Tegron cannot narrow)
//	  not_exploitable (any strength)             → "partial" (minimum meaningful impact)
//	  Note: "total" is the conservative default for exploitable verdicts because
//	  Tegron does not yet classify impact scope — choosing "partial" would be under-reporting.
//
//	MissionWellbeingImpact:
//	  always "high" for exploitable, "low" for not_exploitable
//	  (conservative operator assumption; caller may override)
//
// The SSVC decision is emitted as a JSON structure plus a compact vector string
// following the SSVC vector notation: SSVCv2/<dp1>:<v1>/<dp2>:<v2>/.../<timestamp>/
package projection

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// SSVCSchemaVersion is the SSVC spec version this projection targets.
const SSVCSchemaVersion = "SSVCv2"

// SSVC decision-point values per the SSVC v2.0 spec.
const (
	SSVCExploitationNone   = "none"
	SSVCExploitationPoC    = "poc"
	SSVCExploitationActive = "active"

	SSVCAutomatableNo  = "no"
	SSVCAutomatableYes = "yes"

	SSVCTechnicalImpactPartial = "partial"
	SSVCTechnicalImpactTotal   = "total"

	SSVCMissionImpactLow  = "low"
	SSVCMissionImpactHigh = "high"

	// SSVCDecisionTrack is the output decision (operator/deployer track).
	SSVCDecisionTrackAct       = "act"
	SSVCDecisionTrackAttend    = "attend"
	SSVCDecisionTrackTrack     = "track"
	SSVCDecisionTrackTrackStar = "track*"
)

// SSVCDecision is the full SSVC decision output for one PoE.
type SSVCDecision struct {
	SchemaVersion  string          `json:"schema_version"`
	AssessmentID   string          `json:"assessment_id"`
	CaseID         string          `json:"case_id"`
	DecisionPoints SSVCDecisionPts `json:"decision_points"`
	Decision       string          `json:"decision"`
	Vector         string          `json:"vector"`
	Timestamp      string          `json:"timestamp"`
	// Source records which PoE label and evidence flags drove the decision.
	Source SSVCSource `json:"source"`
}

// SSVCDecisionPts holds the enumerated values for each SSVC decision point.
type SSVCDecisionPts struct {
	Exploitation    string `json:"exploitation"`
	Automatable     string `json:"automatable"`
	TechnicalImpact string `json:"technical_impact"`
	MissionImpact   string `json:"mission_wellbeing_impact"`
}

// SSVCSource documents the PoE inputs that drove each decision-point value.
type SSVCSource struct {
	VerdictLabel    string   `json:"verdict_label"`
	VerdictStrength string   `json:"verdict_strength"`
	ConfidenceScore float64  `json:"confidence_score"`
	EvidenceFlags   []string `json:"evidence_flags"`
	ConditionCount  int      `json:"condition_count"`
}

// ProjectSSVC converts a PoE into an SSVC decision.
//
// The projection is READ-ONLY and conservative: it never downgrades an exploitable
// verdict to "none" and never upgrades a reasoned verdict to "proven" level.
func ProjectSSVC(p verdict.PoE) (*SSVCDecision, error) {
	if p.Direction == "" {
		return nil, fmt.Errorf("projection/ssvc: PoE has no direction")
	}
	if p.Strength == "" {
		return nil, fmt.Errorf("projection/ssvc: PoE has no strength")
	}

	dp := ssvcDecisionPoints(p)
	decision := ssvcOutcome(dp)
	vector := ssvcVector(dp, decision)

	flags := make([]string, 0, len(p.Confidence.EvidenceFlags))
	for _, f := range p.Confidence.EvidenceFlags {
		flags = append(flags, string(f))
	}

	return &SSVCDecision{
		SchemaVersion:  SSVCSchemaVersion,
		AssessmentID:   p.AssessmentID,
		CaseID:         p.CaseID,
		DecisionPoints: dp,
		Decision:       decision,
		Vector:         vector,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Source: SSVCSource{
			VerdictLabel:    p.Label(),
			VerdictStrength: string(p.Strength),
			ConfidenceScore: p.Confidence.Score,
			EvidenceFlags:   flags,
			ConditionCount:  len(p.Conditions),
		},
	}, nil
}

// MarshalSSVC is a convenience wrapper that projects and JSON-encodes in one call.
func MarshalSSVC(p verdict.PoE) ([]byte, error) {
	d, err := ProjectSSVC(p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// ssvcDecisionPoints derives the four decision-point values from a PoE.
func ssvcDecisionPoints(p verdict.PoE) SSVCDecisionPts {
	exploitation := ssvcExploitation(p)
	automatable := ssvcAutomatable(p)
	techImpact := ssvcTechnicalImpact(p)
	missionImpact := ssvcMissionImpact(p)
	return SSVCDecisionPts{
		Exploitation:    exploitation,
		Automatable:     automatable,
		TechnicalImpact: techImpact,
		MissionImpact:   missionImpact,
	}
}

func ssvcExploitation(p verdict.PoE) string {
	if p.Direction == verdict.DirectionNotExploitable {
		return SSVCExploitationNone
	}
	// exploitable direction (proven or reasoned)
	for _, f := range p.Confidence.EvidenceFlags {
		if f == verdict.FlagPublicPoCReplayed {
			return SSVCExploitationActive
		}
	}
	// proven or reasoned exploitable without a public PoC → PoC-equivalent
	return SSVCExploitationPoC
}

func ssvcAutomatable(p verdict.PoE) string {
	if p.Direction == verdict.DirectionNotExploitable {
		return SSVCAutomatableNo
	}
	// exploitable: if there are preconditions (auth, file mode, etc.) the attack is
	// NOT unconditionally automatable. No conditions → automatable.
	if len(p.Conditions) == 0 {
		return SSVCAutomatableYes
	}
	return SSVCAutomatableNo
}

func ssvcTechnicalImpact(p verdict.PoE) string {
	if p.Direction == verdict.DirectionExploitable {
		// Conservative: Tegron does not classify impact scope; "total" avoids under-reporting.
		return SSVCTechnicalImpactTotal
	}
	return SSVCTechnicalImpactPartial
}

func ssvcMissionImpact(p verdict.PoE) string {
	if p.Direction == verdict.DirectionExploitable {
		return SSVCMissionImpactHigh
	}
	return SSVCMissionImpactLow
}

// ssvcOutcome derives the SSVC operator/deployer outcome from the decision points.
// Follows the SSVC v2 deployer tree logic (simplified for Tegron's current decision-point set):
//
//	Exploitation=active                    → Act
//	Exploitation=poc && TechImpact=total   → Attend
//	Exploitation=poc && TechImpact=partial → Track*
//	Exploitation=none                      → Track
func ssvcOutcome(dp SSVCDecisionPts) string {
	switch dp.Exploitation {
	case SSVCExploitationActive:
		return SSVCDecisionTrackAct
	case SSVCExploitationPoC:
		if dp.TechnicalImpact == SSVCTechnicalImpactTotal {
			return SSVCDecisionTrackAttend
		}
		return SSVCDecisionTrackTrackStar
	default:
		return SSVCDecisionTrackTrack
	}
}

// ssvcVector encodes a compact SSVC vector string.
// Format: SSVCv2/E:<exploitation>/A:<automatable>/T:<technical_impact>/M:<mission_impact>/<decision>/<timestamp>/
func ssvcVector(dp SSVCDecisionPts, decision string) string {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	return fmt.Sprintf("SSVCv2/E:%s/A:%s/T:%s/M:%s/%s/%s/",
		dp.Exploitation, dp.Automatable, dp.TechnicalImpact, dp.MissionImpact,
		decision, ts)
}
