// vex.go
//
// OpenVEX wire vocabulary — the document shapes and status/justification
// constants shared by every VEX projector in this package.
//
// Format choice: OpenVEX (https://openvex.dev / github.com/openvex/spec).
// Rationale: OpenVEX is the lighter-weight, git-native VEX format; it has a
// published JSON schema, clean status enum, and is widely consumed by scanners
// (Grype, Trivy). CSAF-VEX is richer but requires a full CSAF 2.0 document
// structure that is disproportionate to a single finding.
//
// This file declares vocabulary only — no projector. The projector this module
// ships is ProjectReportVEX (report_vex.go), which maps FROM the neutral scan
// report.Report. The PoE-driven projector lives service-side, because a PoE
// carries a proof-tier verdict this module cannot produce (RFC 0001 inv. 5).
//
// Status honesty (inv. 5), enforced by whichever projector fills these shapes:
// "affected" is reserved for a PROVEN exploitable verdict. A reachable
// candidate or a reasoned lean is "under_investigation" — the only OpenVEX
// status that asserts nothing.
package projection

// OpenVEXSchemaVersion is the OpenVEX context/schema version this projection targets.
const OpenVEXSchemaVersion = "https://openvex.dev/ns/v0.2.0"

// VEXStatus values per the OpenVEX spec.
const (
	VEXStatusAffected           = "affected"
	VEXStatusNotAffected        = "not_affected"
	VEXStatusUnderInvestigation = "under_investigation"
	VEXStatusFixed              = "fixed"
)

// VEXJustification values per OpenVEX §3.2 (not_affected justifications).
const (
	VEXJustNotPresent        = "vulnerable_code_not_present"
	VEXJustNotReachable      = "vulnerable_code_not_reachable"
	VEXJustInlineMitigations = "inline_mitigations_already_exist"
)

// --- OpenVEX struct shapes ---

// VEXDocument is the top-level OpenVEX document.
type VEXDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []VEXStatement `json:"statements"`
}

// VEXStatement is a single VEX statement about one (product, vuln) pair.
type VEXStatement struct {
	Vulnerability VEXVulnerability `json:"vulnerability"`
	Products      []VEXProduct     `json:"products"`
	Status        string           `json:"status"`
	// Justification is set only for not_affected statements (OpenVEX §3.2).
	Justification string `json:"justification,omitempty"`
	// ImpactStatement is free text elaborating the status (used for reasoned leans).
	ImpactStatement string `json:"impact_statement,omitempty"`
	// ActionStatement is set for affected (per OpenVEX spec).
	ActionStatement string `json:"action_statement,omitempty"`
	// Timestamp is statement-level (if different from document-level).
	Timestamp string `json:"timestamp,omitempty"`
	// Extensions carries scanner-specific metadata.
	Extensions *VEXExtensions `json:"scanner_extensions,omitempty"`
}

// VEXVulnerability identifies the vulnerability.
type VEXVulnerability struct {
	// ID is the CVE / GHSA / OSV identifier.
	ID string `json:"@id"`
	// Aliases is an optional list of alternate IDs.
	Aliases []string `json:"aliases,omitempty"`
}

// VEXProduct identifies the affected product.
type VEXProduct struct {
	// ID is the PURL or other product identifier.
	ID string `json:"@id"`
}

// VEXExtensions carries verdict details not captured by the OpenVEX schema.
// The report-driven projector leaves it nil; it is populated by the PoE-driven
// projector, whose verdict carries assessment and case identifiers.
type VEXExtensions struct {
	VerdictLabel     string  `json:"verdict_label"`
	VerdictStrength  string  `json:"verdict_strength"`
	VerdictDirection string  `json:"verdict_direction"`
	ConfidenceScore  float64 `json:"confidence_score"`
	CompletionStatus string  `json:"completion_status"`
	AssessmentID     string  `json:"assessment_id"`
	CaseID           string  `json:"case_id"`
	ReasonedGrounds  string  `json:"reasoned_grounds,omitempty"`
}
