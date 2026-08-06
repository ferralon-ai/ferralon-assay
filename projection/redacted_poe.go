// internal/projection/redacted_poe.go
//
// RedactedPoE projection — a safe-to-share outside-org view of a Tegron PoE.
//
// # Security posture: default-deny allowlist
//
// This projection is a SECURITY boundary. Fields are included ONLY if they appear
// in the explicit allowlist below. A newly-added PoE field is silently excluded
// until it is consciously evaluated and added to the allowlist. This is the
// opposite of a blocklist approach (where new fields would leak by default).
//
// # Permitted (allowlisted) fields
//
//   - SchemaVersion           — protocol version; no internal identifier
//   - Direction               — verdict direction (exploitable / not_exploitable)
//   - Strength                — verdict strength (proven / reasoned)
//   - CompletionStatus        — why analysis ended (completed / stopped_budget / …)
//   - ConfidenceScore         — the scalar score; evidence flags are stripped (they
//     may name internal call-graph nodes or repo paths)
//   - VulnID                  — CVE/GHSA/OSV id passed by the caller (external ref)
//   - EffectSummary            — a human-readable effect-only description of the
//     vulnerability's impact if exploited; never a file
//     path, symbol name, or other source identifier
//   - Conditions              — predicate strings; included because they are already
//     public preconditions (e.g. "authenticated_session")
//
// # Excluded fields (with rationale)
//
//   - ArtifactID, AssessmentID, CaseID — org-internal identifiers; EXCLUDED
//   - ReasonedGrounds          — may contain internal symbol/path references; EXCLUDED
//   - EvidenceFlags            — may name internal nodes; EXCLUDED
//   - VulnerableSymbol, CallPath, Ingress, Feasibility — artifact refs to internal
//     analysis results; EXCLUDED
//   - Reproducer, Observability, ProofReport — artifact refs to sandbox outputs with
//     build-dir and repo context; EXCLUDED
//   - Episodes                 — internal episode IDs; EXCLUDED
//   - Objection                — internal adversarial-review record; EXCLUDED
//   - PatchValidation          — carries FixSource which may embed repo refs; EXCLUDED
//
// # Inv.5 honesty (RFC 0001)
//
// The projection is READ-ONLY: it never upgrades Strength from reasoned to proven,
// and never changes Direction. A reasoned verdict redacts as reasoned.
package projection

import (
	"encoding/json"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// RedactedPoESchemaVersion is the schema version of RedactedPoE payloads.
const RedactedPoESchemaVersion = "tegron.projection_redacted_poe.v1"

// RedactedPoE is a safe-to-share outside-org view of a Tegron PoE.
//
// Only allowlisted fields are present; all source-identifying details are
// stripped. The allowlist is the security boundary — default-deny.
type RedactedPoE struct {
	// SchemaVersion identifies the payload schema. Allows consumers to version-check.
	SchemaVersion string `json:"schema_version"`

	// VulnID is the CVE / GHSA / OSV identifier passed by the caller. Empty
	// when the caller did not provide one.
	VulnID string `json:"vuln_id,omitempty"`

	// Direction is the verdict direction: "exploitable" or "not_exploitable".
	Direction verdict.Direction `json:"direction"`

	// Strength is how the verdict is known: "proven" or "reasoned".
	// A reasoned verdict is a defended hypothesis; proven requires ground-truth
	// execution evidence. This field is preserved verbatim (inv.5 honesty).
	Strength verdict.Strength `json:"strength"`

	// CompletionStatus records why analysis ended, orthogonal to the verdict.
	CompletionStatus verdict.CompletionStatus `json:"completion_status"`

	// ConfidenceScore is the scalar confidence value [0, 1]. The evidence flags
	// that produced it are stripped (they may name internal call-graph nodes).
	ConfidenceScore float64 `json:"confidence_score"`

	// Conditions are the precondition predicates on this verdict (e.g.
	// "authenticated_session"). These are effect-level preconditions already
	// visible to the target's users; they contain no source identifiers.
	Conditions []RedactedCondition `json:"conditions,omitempty"`

	// EffectSummary is a human-readable, effect-only description of what an
	// attacker can do if the vulnerability is exploited. Populated from the
	// caller-supplied summary; empty when not provided.
	EffectSummary string `json:"effect_summary,omitempty"`
}

// RedactedCondition is a redacted form of verdict.Condition. Only the Predicate
// string (a public-facing precondition label) is retained.
type RedactedCondition struct {
	Predicate string `json:"predicate"`
}

// RedactedPoEOptions carries the optional caller-supplied context for the
// redacted projection.
type RedactedPoEOptions struct {
	// VulnID is the CVE / GHSA / OSV identifier (e.g. "CVE-2024-1234").
	// Defaults to empty string (omitted from output) when not provided.
	VulnID string

	// EffectSummary is a human-readable, effect-only description of the
	// vulnerability impact. Must not contain file paths, symbol names, or
	// repo identifiers — callers are responsible for this constraint.
	EffectSummary string
}

// ProjectRedactedPoE produces a redacted, outside-org-safe projection of a PoE.
//
// The projection is READ-ONLY and inv.5-honest: it never upgrades Strength from
// reasoned to proven, and never changes Direction. The redaction is a security
// boundary implemented as a default-deny allowlist — only the fields listed in
// RedactedPoE are included.
func ProjectRedactedPoE(p verdict.PoE, opts RedactedPoEOptions) (*RedactedPoE, error) {
	if p.Direction == "" {
		return nil, fmt.Errorf("projection/redacted_poe: PoE has no direction")
	}
	if p.Strength == "" {
		return nil, fmt.Errorf("projection/redacted_poe: PoE has no strength")
	}

	// Build the conditions list from the allowlisted Predicate field only.
	var conds []RedactedCondition
	for _, c := range p.Conditions {
		conds = append(conds, RedactedCondition{Predicate: c.Predicate})
	}

	return &RedactedPoE{
		SchemaVersion:    RedactedPoESchemaVersion,
		VulnID:           opts.VulnID,
		Direction:        p.Direction, // copied verbatim (inv.5: no upgrade)
		Strength:         p.Strength,  // copied verbatim (inv.5: no upgrade)
		CompletionStatus: p.CompletionStatus,
		ConfidenceScore:  p.Confidence.Score, // scalar only; flags stripped
		Conditions:       conds,
		EffectSummary:    opts.EffectSummary,
	}, nil
}

// MarshalRedactedPoE is a convenience wrapper that projects and JSON-encodes in
// one call.
func MarshalRedactedPoE(p verdict.PoE, opts RedactedPoEOptions) ([]byte, error) {
	r, err := ProjectRedactedPoE(p, opts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
