// Package artifact defines the content-addressed common currency of the pipeline.
// Every stage output is stored as an Artifact, discovered by its Type, and referenced
// by later stages through a Ref.
package artifact

import "time"

// Type is the semantic artifact type — the discovery key. It is a plain string: a Type
// carries no behavior and is never validated against the Registry on write, so a consumer
// may declare and store types of its own without registering them here.
type Type string

// Artifact-type constants. One per pipeline output.
const (
	TypeNormalizedAdvisory Type = "normalized_advisory"
	TypeInventory          Type = "inventory" // SBOM
	TypePublicPoC          Type = "public_poc"
	TypeDisqualification   Type = "disqualification"
	TypeDiscovery          Type = "discovery"
	TypeVulnerableSymbol   Type = "vulnerable_symbol" // symbol resolution
	TypeReachability       Type = "reachability"
	TypeIngressMap         Type = "ingress_map"
	TypeCandidatePair      Type = "candidate_pair"
	TypeTaint              Type = "taint"                   // pre-execution taint path-presence
	TypeHarness            Type = "harness"                 // deterministic scaffolding around a sink; NEVER proof
	TypePoE                Type = "proof_of_exploitability" // apex
	TypeExposureFootprint  Type = "exposure_footprint"      // deterministic exposure report
	// TypeMaliciousPresence is the decisive OSS "affected" signal: a known-malicious package
	// resolved to a version the advisory enumerates as affected. It is emitted ONLY on an
	// affirmative presence match; absence/version-not-listed/unresolvable emit nothing (fail-open).
	TypeMaliciousPresence Type = "malicious_presence"
	// Standard projections — generated from a PoE, read-only views.
	TypeProjectionSARIF       Type = "projection_sarif"        // SARIF 2.1.0 projection of a PoE
	TypeProjectionVEX         Type = "projection_vex"          // OpenVEX projection of a PoE
	TypeProjectionSSVC        Type = "projection_ssvc"         // SSVC decision projection of a PoE
	TypeProjectionRedactedPoE Type = "projection_redacted_poe" // redacted PoE for outside-org sharing
)

// ExposureFootprintPayload is the payload of a TypeExposureFootprint artifact.
// All fields are raw ground-truth counts derived from already-produced deterministic stage
// results. NO composite scoring formula is included — tier-placement weighting is a GTM/product
// decision outside the engine.
//
// dep_count uses -1 (not 0) when the value is unknown (e.g. BuildManifest unsupported in Phase 1)
// to distinguish "unknown" from "zero dependencies" — a zero would be misleading.
type ExposureFootprintPayload struct {
	SchemaVersion string `json:"schema_version"` // = "tegron.exposure_footprint.v1"
	AssessmentID  string `json:"assessment_id"`  // UUIDv7 of the producing Assessment
	CaseID        string `json:"case_id"`        // parent Case id

	// Ingress surface
	IngressCount int      `json:"ingress_count"` // number of framework-idiomatic entry points found
	IngressKinds []string `json:"ingress_kinds"` // distinct Ingress.Kind values (e.g. ["http_route","main"])

	// Reachability surface
	ReachablePathCount int `json:"reachable_path_count"` // number of (ingress, sink, path) traces

	// Symbol surface
	VulnerableSymbolCount int `json:"vulnerable_symbol_count"` // resolved vulnerable symbols
	SymbolCount           int `json:"symbol_count"`            // total indexed symbols (-1 = unknown)

	// Dependency / repo surface
	DepCount  int `json:"dep_count"`  // direct dep count from go.mod (-1 = unknown)
	RepoCount int `json:"repo_count"` // number of repos in the assessed subject

	// Partiality
	PartialityFlags []string `json:"partiality_flags,omitempty"` // reason codes from any partial plugin ops
}

// ExposureFootprintSchemaVersion is the schema version stamped on every ExposureFootprintPayload.
const ExposureFootprintSchemaVersion = "tegron.exposure_footprint.v1"

// Ref is an artifact reference. The evidence chain is built from these.
type Ref struct {
	ID   string `json:"id"` // UUIDv7 of the referenced artifact
	Type Type   `json:"type"`
}

// Artifact is the content-addressed common currency of the pipeline.
type Artifact struct {
	ID           string    `json:"id"`            // UUIDv7
	AssessmentID string    `json:"assessment_id"` // UUIDv7 of owning Assessment
	Type         Type      `json:"type"`
	ContentHash  string    `json:"content_hash"` // "sha256:<hex>" of Payload
	Descriptor   string    `json:"descriptor"`   // semantic descriptor for discovery
	ProducedBy   string    `json:"produced_by"`  // stage name
	Payload      []byte    `json:"payload"`      // inline JSON
	CreatedAt    time.Time `json:"created_at"`
}

// Ref returns an artifact reference to this Artifact.
func (a *Artifact) Ref() Ref { return Ref{ID: a.ID, Type: a.Type} }
