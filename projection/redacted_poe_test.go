package projection_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// fixturePoEWithSensitiveFields returns a proven-exploitable PoE that carries
// every category of sensitive / source-identifying field:
//
//   - internal IDs (ArtifactID, AssessmentID, CaseID, Episodes)
//   - source-level evidence refs (VulnerableSymbol, CallPath, Ingress, Feasibility)
//   - sandbox/build refs (Reproducer, Observability, ProofReport)
//   - internal reasoning text (ReasonedGrounds is empty for proven, but filled for
//     the reasoned variant below)
//   - evidence flags that may name internal nodes
//   - Objection (internal adversarial-review record)
func fixturePoEWithSensitiveFields() verdict.PoE {
	symbolRef := &artifact.Ref{ID: "aef00000-0000-7000-8000-000000000001", Type: artifact.TypeVulnerableSymbol}
	pathRef := &artifact.Ref{ID: "aef00000-0000-7000-8000-000000000002", Type: artifact.TypeReachability}
	ingressRef := &artifact.Ref{ID: "aef00000-0000-7000-8000-000000000003", Type: artifact.TypeIngressMap}
	// These four Ref types are produced by the proof path, which declares its own half of
	// the taxonomy; this library does not, so they are spelled as the literal wire values.
	feasRef := &artifact.Ref{ID: "aef00000-0000-7000-8000-000000000004", Type: artifact.Type("feasibility")}
	reproRef := &artifact.Ref{ID: "aef00000-0000-7000-8000-000000000005", Type: artifact.Type("reproducer")}
	obsRef := &artifact.Ref{ID: "aef00000-0000-7000-8000-000000000006", Type: artifact.Type("observability")}
	proofRef := &artifact.Ref{ID: "aef00000-0000-7000-8000-000000000007", Type: artifact.Type("proof_report")}

	return verdict.PoE{
		SchemaVersion:    verdict.SchemaVersion,
		ArtifactID:       "aef00000-0000-7000-8000-000000000010", // sensitive: internal ID
		AssessmentID:     "aef00000-0000-7000-8000-0000000000aa", // sensitive: internal ID
		CaseID:           "aef00000-0000-7000-8000-0000000000cc", // sensitive: internal ID
		Direction:        verdict.DirectionExploitable,
		Strength:         verdict.StrengthProven,
		Confidence:       verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{verdict.FlagCanaryTriggered}),
		CompletionStatus: verdict.CompletionCompleted,
		// evidence refs — all sensitive
		VulnerableSymbol: symbolRef,
		CallPath:         pathRef,
		Ingress:          ingressRef,
		Feasibility:      feasRef,
		Reproducer:       reproRef,
		Observability:    obsRef,
		ProofReport:      proofRef,
		// internal episode IDs
		Episodes: []string{"aef00000-0000-7000-8000-0000000000e1", "aef00000-0000-7000-8000-0000000000e2"},
		// adversarial-review record — internal
		Objection: &verdict.Objection{
			AttackClass: "memory_corruption",
			Rationale:   "internal review note: heap overflow in /src/internal/parser.c line 42",
		},
		Conditions: []verdict.Condition{
			{Predicate: "authenticated_session"},
		},
	}
}

// fixtureReasonedPoEWithSensitiveFields is like fixturePoEWithSensitiveFields but
// reasoned, so ReasonedGrounds is populated (another potential leak vector).
func fixtureReasonedPoEWithSensitiveFields() verdict.PoE {
	p := verdict.PoE{
		SchemaVersion:    verdict.SchemaVersion,
		ArtifactID:       "aef00000-0000-7000-8000-000000000020",
		AssessmentID:     "aef00000-0000-7000-8000-0000000000ab",
		CaseID:           "aef00000-0000-7000-8000-0000000000cd",
		Direction:        verdict.DirectionExploitable,
		Strength:         verdict.StrengthReasoned,
		ReasonedGrounds:  "taint path: /repo/internal/handlers/upload.go:Handler -> sink at /repo/vendor/lib/parse.go:ParseInput",
		Confidence:       verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{verdict.FlagStaticTaintPathComplete}),
		CompletionStatus: verdict.CompletionStoppedCapability,
		Episodes:         []string{"aef00000-0000-7000-8000-0000000000e3"},
		Conditions:       []verdict.Condition{{Predicate: "unauthenticated"}},
	}
	return p
}

// sensitiveStrings lists every value that must never appear anywhere in the
// RedactedPoE JSON output. These are the denylist: source-identifying strings
// that this projection is designed to strip.
var sensitiveStrings = []string{
	// internal artifact IDs from the fixture
	"aef00000-0000-7000-8000-000000000010", // ArtifactID
	"aef00000-0000-7000-8000-0000000000aa", // AssessmentID
	"aef00000-0000-7000-8000-0000000000cc", // CaseID
	"aef00000-0000-7000-8000-000000000001", // VulnerableSymbol ref ID
	"aef00000-0000-7000-8000-000000000002", // CallPath ref ID
	"aef00000-0000-7000-8000-000000000003", // Ingress ref ID
	"aef00000-0000-7000-8000-000000000004", // Feasibility ref ID
	"aef00000-0000-7000-8000-000000000005", // Reproducer ref ID
	"aef00000-0000-7000-8000-000000000006", // Observability ref ID
	"aef00000-0000-7000-8000-000000000007", // ProofReport ref ID
	"aef00000-0000-7000-8000-0000000000e1", // Episode[0]
	"aef00000-0000-7000-8000-0000000000e2", // Episode[1]
	// Objection fields
	"memory_corruption",
	"internal review note",
	"/src/internal/parser.c",
	// artifact type strings that appear in the refs
	"vulnerable_symbol",
	"reachability",
	"ingress_map",
	"feasibility",
	"reproducer",
	"observability",
	"proof_report",
}

// sensitiveSreasonedStrings lists values from the reasoned fixture that must
// never appear in redacted output.
var sensitiveReasonedStrings = []string{
	"aef00000-0000-7000-8000-000000000020", // ArtifactID
	"aef00000-0000-7000-8000-0000000000ab", // AssessmentID
	"aef00000-0000-7000-8000-0000000000cd", // CaseID
	"aef00000-0000-7000-8000-0000000000e3", // Episode
	// ReasonedGrounds contains internal paths — must be excluded
	"/repo/internal/handlers/upload.go",
	"/repo/vendor/lib/parse.go",
	"taint path:",
}

// TestRedactedPoE_DefaultDeny_NoSensitiveFieldsInOutput is the primary security
// assertion: every sensitive string from the fixture must be absent from the
// JSON output. This catches any new PoE field that leaks by omission from the
// allowlist.
func TestRedactedPoE_DefaultDeny_NoSensitiveFieldsInOutput(t *testing.T) {
	p := fixturePoEWithSensitiveFields()
	b, err := projection.MarshalRedactedPoE(p, projection.RedactedPoEOptions{
		VulnID:        "CVE-2024-9999",
		EffectSummary: "Remote code execution via crafted HTTP multipart upload.",
	})
	if err != nil {
		t.Fatalf("MarshalRedactedPoE: %v", err)
	}
	out := string(b)
	for _, sensitive := range sensitiveStrings {
		if strings.Contains(out, sensitive) {
			t.Errorf("REDACTION LEAK: sensitive string %q found in redacted output", sensitive)
		}
	}
}

// TestRedactedPoE_ReasonedGrounds_Excluded asserts that the internal
// ReasonedGrounds field (which may contain source paths) is excluded even for
// reasoned verdicts.
func TestRedactedPoE_ReasonedGrounds_Excluded(t *testing.T) {
	p := fixtureReasonedPoEWithSensitiveFields()
	b, err := projection.MarshalRedactedPoE(p, projection.RedactedPoEOptions{})
	if err != nil {
		t.Fatalf("MarshalRedactedPoE: %v", err)
	}
	out := string(b)
	for _, sensitive := range sensitiveReasonedStrings {
		if strings.Contains(out, sensitive) {
			t.Errorf("REDACTION LEAK: sensitive string %q found in redacted output", sensitive)
		}
	}
}

// TestRedactedPoE_AllowlistedFields_Present asserts that the permitted fields ARE
// present in the output (allowlist-positive check).
func TestRedactedPoE_AllowlistedFields_Present(t *testing.T) {
	p := fixturePoEWithSensitiveFields()
	opts := projection.RedactedPoEOptions{
		VulnID:        "CVE-2024-9999",
		EffectSummary: "Remote code execution via crafted HTTP multipart upload.",
	}
	r, err := projection.ProjectRedactedPoE(p, opts)
	if err != nil {
		t.Fatalf("ProjectRedactedPoE: %v", err)
	}

	if r.SchemaVersion != projection.RedactedPoESchemaVersion {
		t.Errorf("schema_version = %q, want %q", r.SchemaVersion, projection.RedactedPoESchemaVersion)
	}
	if r.VulnID != "CVE-2024-9999" {
		t.Errorf("vuln_id = %q, want %q", r.VulnID, "CVE-2024-9999")
	}
	if r.Direction != verdict.DirectionExploitable {
		t.Errorf("direction = %q, want %q", r.Direction, verdict.DirectionExploitable)
	}
	if r.Strength != verdict.StrengthProven {
		t.Errorf("strength = %q, want %q", r.Strength, verdict.StrengthProven)
	}
	if r.CompletionStatus != verdict.CompletionCompleted {
		t.Errorf("completion_status = %q, want %q", r.CompletionStatus, verdict.CompletionCompleted)
	}
	if r.ConfidenceScore <= 0 {
		t.Errorf("confidence_score = %f, want > 0", r.ConfidenceScore)
	}
	if r.EffectSummary != opts.EffectSummary {
		t.Errorf("effect_summary = %q, want %q", r.EffectSummary, opts.EffectSummary)
	}
	if len(r.Conditions) != 1 || r.Conditions[0].Predicate != "authenticated_session" {
		t.Errorf("conditions = %v, want [{authenticated_session}]", r.Conditions)
	}
}

// TestRedactedPoE_Inv5_StrengthPreservedVerbatim is the explicit inv.5 honesty
// assertion: the redacted projection must not upgrade strength from reasoned to
// proven under any circumstances.
func TestRedactedPoE_Inv5_StrengthPreservedVerbatim(t *testing.T) {
	cases := []struct {
		name         string
		poe          verdict.PoE
		wantStrength verdict.Strength
	}{
		{
			name:         "proven_strength_preserved",
			poe:          fixturePoEWithSensitiveFields(),
			wantStrength: verdict.StrengthProven,
		},
		{
			name:         "reasoned_strength_not_upgraded",
			poe:          fixtureReasonedPoEWithSensitiveFields(),
			wantStrength: verdict.StrengthReasoned,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := projection.ProjectRedactedPoE(tc.poe, projection.RedactedPoEOptions{})
			if err != nil {
				t.Fatalf("ProjectRedactedPoE: %v", err)
			}
			if r.Strength != tc.wantStrength {
				t.Errorf("inv.5 VIOLATION: strength = %q, want %q (must not be upgraded)", r.Strength, tc.wantStrength)
			}
			if r.Direction != tc.poe.Direction {
				t.Errorf("inv.5 VIOLATION: direction = %q, want %q (must not be altered)", r.Direction, tc.poe.Direction)
			}
		})
	}
}

// TestRedactedPoE_Inv5_ReasonedNeverProven tests the bright-line inv.5 constraint:
// a reasoned verdict, no matter how high its confidence score, must never project
// as "proven" strength.
func TestRedactedPoE_Inv5_ReasonedNeverProven(t *testing.T) {
	// High-confidence reasoned PoE — still must project as reasoned, never proven.
	p := fixtureReasonedPoEWithSensitiveFields()
	p.Confidence = verdict.ConfidenceFromFlags([]verdict.EvidenceFlag{
		verdict.FlagStaticTaintPathComplete,
		verdict.FlagPublicPoCReplayed,
	})
	r, err := projection.ProjectRedactedPoE(p, projection.RedactedPoEOptions{})
	if err != nil {
		t.Fatalf("ProjectRedactedPoE: %v", err)
	}
	if r.Strength == verdict.StrengthProven {
		t.Errorf("inv.5 VIOLATION: high-confidence reasoned verdict projected as proven — " +
			"the reasoned/proven bright line must never be crossed by confidence accumulation")
	}
}

// TestRedactedPoE_EmptyDirection_ReturnsError verifies input validation.
func TestRedactedPoE_EmptyDirection_ReturnsError(t *testing.T) {
	p := fixturePoEWithSensitiveFields()
	p.Direction = ""
	if _, err := projection.ProjectRedactedPoE(p, projection.RedactedPoEOptions{}); err == nil {
		t.Fatal("expected error for empty Direction, got nil")
	}
}

// TestRedactedPoE_EmptyStrength_ReturnsError verifies input validation.
func TestRedactedPoE_EmptyStrength_ReturnsError(t *testing.T) {
	p := fixturePoEWithSensitiveFields()
	p.Strength = ""
	if _, err := projection.ProjectRedactedPoE(p, projection.RedactedPoEOptions{}); err == nil {
		t.Fatal("expected error for empty Strength, got nil")
	}
}

// TestRedactedPoE_NoConditions_OmittedFromJSON asserts that the conditions field
// is omitted (not null) when no conditions are present.
func TestRedactedPoE_NoConditions_OmittedFromJSON(t *testing.T) {
	p := fixturePoEWithSensitiveFields()
	p.Conditions = nil
	b, err := projection.MarshalRedactedPoE(p, projection.RedactedPoEOptions{})
	if err != nil {
		t.Fatalf("MarshalRedactedPoE: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := raw["conditions"]; ok {
		t.Error("conditions field should be omitted when empty, not present as null or []")
	}
}

// TestRedactedPoE_JSON_SchemaVersionPresent verifies the JSON round-trip sets the
// schema version.
func TestRedactedPoE_JSON_SchemaVersionPresent(t *testing.T) {
	b, err := projection.MarshalRedactedPoE(fixturePoEWithSensitiveFields(), projection.RedactedPoEOptions{
		VulnID: "CVE-2024-9999",
	})
	if err != nil {
		t.Fatalf("MarshalRedactedPoE: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if got := raw["schema_version"]; got != projection.RedactedPoESchemaVersion {
		t.Errorf("schema_version = %v, want %q", got, projection.RedactedPoESchemaVersion)
	}
}

// TestRedactedPoE_AllFourVerdictClasses smoke-tests that all four verdict classes
// produce a valid, non-nil redacted projection.
func TestRedactedPoE_AllFourVerdictClasses(t *testing.T) {
	cases := []struct {
		name string
		poe  verdict.PoE
	}{
		{"proven_exploitable", fixtureProvenExploitable()},
		{"reasoned_exploitable", fixtureReasonedExploitable()},
		{"proven_not_exploitable", fixtureProvenNotExploitable()},
		{"reasoned_not_exploitable", fixtureReasonedNotExploitable()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := projection.ProjectRedactedPoE(tc.poe, projection.RedactedPoEOptions{
				VulnID: "CVE-2024-1234",
			})
			if err != nil {
				t.Fatalf("ProjectRedactedPoE(%s): %v", tc.name, err)
			}
			if r == nil {
				t.Fatal("got nil RedactedPoE")
			}
			if r.Direction != tc.poe.Direction {
				t.Errorf("direction = %q, want %q", r.Direction, tc.poe.Direction)
			}
			if r.Strength != tc.poe.Strength {
				t.Errorf("strength = %q, want %q", r.Strength, tc.poe.Strength)
			}
		})
	}
}
