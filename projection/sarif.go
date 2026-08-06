// internal/projection/sarif.go
//
// SARIF 2.1.0 projection of a Tegron PoE verdict.
//
// Mapping rationale (inv.5 honesty rule):
//   - proven   exploitable       → level "error"   (confirmed exploit fire)
//   - reasoned exploitable       → level "warning"  (defended lean, not proof)
//   - proven   not_exploitable   → level "note"     (confirmed safe by two-trace)
//   - reasoned not_exploitable   → level "none"     (lean toward safe, unconfirmed)
//
// A reasoned lean MUST NOT emit as "error" — that would silently claim proof status.
// The level "warning" for reasoned_exploitable explicitly signals that this is a
// substantiated hypothesis that owes sandbox confirmation, not a proven finding.
package projection

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// SARIFVersion is the OASIS SARIF schema version this projection targets.
const SARIFVersion = "2.1.0"

// SARIFSchemaURI is the canonical $schema URI for SARIF 2.1.0.
const SARIFSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// sarifLevel maps a PoE verdict to a SARIF result level.
// The mapping is honest: reasoned leans never become "error" (which implies
// a proven finding in SARIF tooling). See package-level comment for the table.
func sarifLevel(p verdict.PoE) string {
	switch {
	case p.Direction == verdict.DirectionExploitable && p.Strength == verdict.StrengthProven:
		return "error"
	case p.Direction == verdict.DirectionExploitable && p.Strength == verdict.StrengthReasoned:
		return "warning"
	case p.Direction == verdict.DirectionNotExploitable && p.Strength == verdict.StrengthProven:
		return "note"
	default: // reasoned_not_exploitable
		return "none"
	}
}

// sarifKind maps a PoE verdict to a SARIF result kind.
// "fail" is reserved for confirmed findings; reasoned leans use "open" to signal
// they require follow-up.
func sarifKind(p verdict.PoE) string {
	if p.Strength == verdict.StrengthProven {
		return "fail"
	}
	return "open"
}

// --- SARIF 2.1.0 struct shapes (minimal subset; sufficient for round-trip validation) ---

// SARIFLog is the top-level SARIF 2.1.0 log object.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun is a single analysis run.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Results     []SARIFResult     `json:"results"`
}

// SARIFInvocation describes how the analysis run itself went, as distinct from what
// it found. It is the SARIF-native slot for "the tool could not do part of its job":
// a consumer that reads only Results cannot tell an empty result set produced by a
// clean codebase from one produced by an analysis that never ran.
type SARIFInvocation struct {
	// ExecutionSuccessful is SARIF's required completeness signal for the run.
	ExecutionSuccessful bool `json:"executionSuccessful"`
	// ToolExecutionNotifications carry conditions the tool hit while running — here,
	// each disclosed limit on what the pass could establish.
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

// SARIFNotification is one condition encountered during the run (not a finding about
// the code).
type SARIFNotification struct {
	Level   string       `json:"level,omitempty"`
	Message SARIFMessage `json:"message"`
}

// SARIFTool identifies the tool that produced the run.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver is the primary analysis tool.
type SARIFDriver struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	InformationURI  string `json:"informationUri,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
}

// SARIFResult is a single result in the run.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Kind      string          `json:"kind,omitempty"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	// Rank is the SARIF 2.1.0 "rank" property (0.0–100.0): a numeric score that
	// code-scanning tools may use to order results for triage. Set from the EPSS
	// percentile when intel is available (EPSSPercentile * 100). Omitted (−1 sentinel
	// serialized as omitempty) when no intel snapshot matched this finding.
	// A positive rank is ONLY a likelihood-of-wild-exploitation signal from public
	// feeds — never a claim about this codebase (inv. 5).
	Rank       *float64         `json:"rank,omitempty"`
	Properties *SARIFProperties `json:"properties,omitempty"`
}

// SARIFMessage is a localizable result message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation is a result location (optional; filled when a vulnerable symbol ref exists).
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation points to a file at a specific region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation is a file location.
type SARIFArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}

// SARIFRegion is a region within an artifact. Code scanning uses it to anchor the
// alert; a dependency finding has no precise line, so the projection emits startLine 1
// (the honest "somewhere in the manifest" anchor).
type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// SARIFProperties carries scanner-specific extension fields under the "scanner" key.
type SARIFProperties struct {
	Tegron map[string]any `json:"scanner,omitempty"`
}

// ProjectSARIF converts a PoE into a SARIF 2.1.0 log.
//
// The projection is READ-ONLY: it never alters direction, strength, or confidence.
// It is honest: reasoned verdicts project as "warning" or "none", never as "error".
func ProjectSARIF(p verdict.PoE) (*SARIFLog, error) {
	if p.Direction == "" {
		return nil, fmt.Errorf("projection/sarif: PoE has no direction")
	}
	if p.Strength == "" {
		return nil, fmt.Errorf("projection/sarif: PoE has no strength")
	}

	msg := sarifMessage(p)

	props := map[string]any{
		"verdict_label":     p.Label(),
		"verdict_direction": string(p.Direction),
		"verdict_strength":  string(p.Strength),
		"confidence_score":  p.Confidence.Score,
		"completion_status": string(p.CompletionStatus),
		"assessment_id":     p.AssessmentID,
		"case_id":           p.CaseID,
		"projected_at":      time.Now().UTC().Format(time.RFC3339),
	}
	if len(p.Conditions) > 0 {
		conds := make([]string, 0, len(p.Conditions))
		for _, c := range p.Conditions {
			conds = append(conds, c.Predicate)
		}
		props["conditions"] = conds
	}
	if p.ReasonedGrounds != "" {
		props["reasoned_grounds"] = p.ReasonedGrounds
	}
	if p.Objection != nil {
		props["objection_attack_class"] = p.Objection.AttackClass
		props["objection_rationale"] = p.Objection.Rationale
	}

	result := SARIFResult{
		RuleID: brand.Name + "/" + p.Label(),
		Level:  sarifLevel(p),
		Kind:   sarifKind(p),
		Message: SARIFMessage{
			Text: msg,
		},
		Properties: &SARIFProperties{Tegron: props},
	}

	log := &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           brand.Name,
						InformationURI: brand.RepoURL,
					},
				},
				Results: []SARIFResult{result},
			},
		},
	}
	return log, nil
}

// MarshalSARIF is a convenience wrapper that projects and JSON-encodes in one call.
func MarshalSARIF(p verdict.PoE) ([]byte, error) {
	log, err := ProjectSARIF(p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(log)
}

// sarifMessage builds an honest, human-readable result message.
func sarifMessage(p verdict.PoE) string {
	switch p.Label() {
	case "exploitable":
		return fmt.Sprintf(
			"%s has proven this vulnerability exploitable (confidence %.2f). "+
				"A sandbox reproducer fired and is referenced in the PoE (assessment %s).",
			brand.Name, p.Confidence.Score, p.AssessmentID)
	case "reasoned_exploitable":
		return fmt.Sprintf(
			"%s has a reasoned (unproven) lean toward exploitability (confidence %.2f). "+
				"This is a substantiated hypothesis — sandbox confirmation is pending. "+
				"Grounds: %s (assessment %s).",
			brand.Name, p.Confidence.Score, p.ReasonedGrounds, p.AssessmentID)
	case "not_exploitable":
		return fmt.Sprintf(
			"%s has proven this vulnerability not exploitable (two-trace patch validation; "+
				"confidence %.2f, assessment %s).",
			brand.Name, p.Confidence.Score, p.AssessmentID)
	default: // reasoned_not_exploitable
		return fmt.Sprintf(
			"%s leans toward not exploitable (reasoned, unproven; confidence %.2f). "+
				"Grounds: %s (assessment %s).",
			brand.Name, p.Confidence.Score, p.ReasonedGrounds, p.AssessmentID)
	}
}
