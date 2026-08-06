// Package assessment defines the neutral inputs and the durable record of one Assess pass:
// what codebase, at what revision, against which advisory. It carries no tier, tenancy, or
// billing concept.
package assessment

import "time"

// Status is the coarse pipeline status surfaced to clients.
type Status string

// StatusQueued through StatusFailed enumerate the Status lifecycle a single Assess pass
// moves through, in order; StatusFailed can follow any of the others. A caller that adds
// stages of its own may declare additional Status values.
const (
	StatusQueued    Status = "queued"
	StatusInventory Status = "inventory"
	StatusAnalysis  Status = "analysis"
	StatusComplete  Status = "complete"
	StatusFailed    Status = "failed"
)

// VulnRef identifies the vulnerability under assessment. Source names where the advisory
// was read from, not a judgement about it.
type VulnRef struct {
	ID     string `json:"id"`     // e.g. "GO-2021-0001" / "CVE-..."
	Source string `json:"source"` // "osv" | "nvd" | "ghsa"
}

// Acquisition tells checkout how to materialize the codebase. Zero value
// (Mode == "") means "clone Repo@Revision" — the pre-existing behavior.
type Acquisition struct {
	Mode string `json:"mode,omitempty"` // "" (clone) | "vendored_repro" | "pinned_ref"
	Path string `json:"path,omitempty"` // local path when Mode=="vendored_repro"
}

// CodebaseRef identifies the codebase under assessment.
type CodebaseRef struct {
	Repo        string      `json:"repo"`
	Revision    string      `json:"revision"`
	Acquisition Acquisition `json:"acquisition,omitempty"` // zero value = clone (additive, keeps old payloads valid)
}

// ExecutionContext describes how the codebase runs.
type ExecutionContext struct {
	Kind string `json:"kind"` // "compose" | "image" | "cluster"
}

// OwnershipProof carries the credential used to FETCH the codebase under assessment. It is a
// transport credential, not an authorization decision and not an identity: the engine passes
// Token to the checkout seam and never inspects, stores, or reasons about it.
type OwnershipProof struct {
	Token string `json:"token"`
}

// Request is the client-supplied input that opens an Assessment.
type Request struct {
	Vulnerability  VulnRef          `json:"vulnerability"`
	Codebase       CodebaseRef      `json:"codebase"`
	Execution      ExecutionContext `json:"execution"`
	OwnershipProof OwnershipProof   `json:"ownership_proof"`
}

// SubjectSnapshot is the resolved-subject snapshot captured on an Assessment at launch: the
// single codebase that was actually assessed plus the vulnerability it was assessed against.
// URL/Ref are the requested coordinates; ResolvedCommit is the concrete commit checkout pinned
// the assessment to.
type SubjectSnapshot struct {
	URL            string  `json:"url"`
	Ref            string  `json:"ref"`
	ResolvedCommit string  `json:"resolved_commit"`
	Vulnerability  VulnRef `json:"vulnerability"`
	// PredecessorCommit is the concrete commit SHA a comparison build was checked out at,
	// pinned the same way as ResolvedCommit. Empty when there is no comparison build and for
	// codebases materialized from a local path rather than a git tree.
	PredecessorCommit string `json:"predecessor_commit,omitempty"`
}

// Assessment is the durable, recallable record of one assessment pass.
type Assessment struct {
	ID        string    `json:"id"` // UUIDv7; also the client's job handle
	Status    Status    `json:"status"`
	Request   Request   `json:"request"`
	VerdictID string    `json:"verdict_id"` // artifact ID of the verdict when complete; "" otherwise
	Episodes  []string  `json:"episodes"`   // Episode IDs recorded during the run
	CreatedAt time.Time `json:"created_at"`
	// Subject is the resolved-subject snapshot captured at launch.
	Subject SubjectSnapshot `json:"subject"`
	// OwnershipProof is the cached credential persisted on the record. Request keeps the
	// inbound wire copy; this is the durable, recallable cache on the Assessment.
	OwnershipProof OwnershipProof `json:"ownership_proof"`
}
