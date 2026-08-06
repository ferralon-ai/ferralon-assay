// Package verdict defines the Proof of Exploitability (PoE) vocabulary: the closed set of
// types an Assess pass concludes with — direction, strength, evidence, and the invariants
// that keep a "proven" claim backed by a ground-truth observation rather than accumulated
// confidence.
//
// # Why this vocabulary is published
//
// These types ship in the open deliberately. Ferralon's claim is that a vulnerability
// finding can be proven rather than argued, and a claim like that is only worth something
// if you can read the terms it is made in. So the terms are here in full: what a verdict
// is allowed to say, which evidence classes are allowed to back it, and the rule that
// "proven" requires a ground-truth execution observation and nothing softer. Validate is
// where that rule is enforced, and it is short enough to read in one sitting.
//
// The vocabulary is deliberately wider than what this module constructs. Fixing the whole
// grammar up front — every direction, strength and evidence class a finding can carry —
// keeps a verdict's shape stable as the analysis behind it deepens, rather than
// renegotiating the contract each time a new stage lands. Several of these terms are
// declared here and reserved for implementation.
//
// What the package defines is the shape of the claim — the fields, the closed enums, the
// invariants, and the adversarial review that can downgrade a verdict (see Objection). It
// does not describe how evidence is obtained: no detonation harness, no sandbox and no
// reproducer synthesis is part of this module.
//
// A vocabulary with no engine behind it cannot assert anything, which is what makes it safe
// to read. Nothing outside this package's own tests constructs a PoE, and no code in this
// module emits either proof flag — projection consumes a PoE it is handed, and the analysis
// here stops at reachability. What these types give a reader is the standard Ferralon holds
// itself to before calling something proven, which is the part worth checking.
package verdict

import (
	"errors"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// SchemaVersion is the versioned PoE schema identifier (RFC 0003).
const SchemaVersion = "tegron.poe.v1"

// Direction is which way the evidence points (RFC 0003).
type Direction string

const (
	// DirectionExploitable means the evidence points to the codebase being vulnerable to
	// the advisory under assessment.
	DirectionExploitable Direction = "exploitable"
	// DirectionNotExploitable means the evidence points to the codebase not being
	// vulnerable to the advisory under assessment.
	DirectionNotExploitable Direction = "not_exploitable"
)

// Strength is how the verdict is known. The proven/reasoned wall is the product's
// bright line: crossing it requires a ground-truth observation, never accumulated
// confidence (RFC 0003).
type Strength string

const (
	// StrengthProven means the verdict is backed by a ground-truth execution
	// observation — never by accumulated confidence. See Validate for the flags a
	// proven verdict requires.
	StrengthProven Strength = "proven"
	// StrengthReasoned means the verdict is a defended lean rather than a ground-truth
	// observation; ReasonedGrounds must state why (see Validate).
	StrengthReasoned Strength = "reasoned"
)

// NonExploitableBasis records WHAT grounds a `reasoned not_exploitable` verdict — the
// distinction between a grounded refutation and a bare "the pipeline found nothing" lean.
// It NEVER sets or implies `proven`: a refutation that is not a ground-truth sandbox
// observation (RFC 0010 rejects re-scan-only as proof of a working patch) is a reasoned
// lean, not a proof. The two-trace PoNE (RFC 0010) is the only `proven not_exploitable`
// path and carries PatchValidation instead; this field is empty there.
type NonExploitableBasis string

const (
	// BasisNone is the default: a bare reasoned not-exploitable lean with no grounded
	// refutation behind it (the stub/no-attributed-signal path). A model asserting
	// "not exploitable" with no disqualification or refutation evidence lands here.
	BasisNone NonExploitableBasis = ""
	// BasisVersionNotAffected: the resolved dependency version is provably outside the
	// advisory's affected range (disqualification_discovery, RFC 0006).
	BasisVersionNotAffected NonExploitableBasis = "version_not_in_affected_range"
	// BasisSymbolAbsent: the vulnerable symbol is provably absent from the built artifact
	// (disqualification_discovery / absence-elision, RFC 0006).
	BasisSymbolAbsent NonExploitableBasis = "vulnerable_symbol_absent"
)

// CompletionStatus records why analysis ended, orthogonal to the verdict (RFC 0003).
type CompletionStatus string

const (
	// CompletionCompleted means analysis ran to its normal conclusion.
	CompletionCompleted CompletionStatus = "completed"
	// CompletionStoppedBudget means analysis stopped because it exhausted its time or
	// resource budget before reaching a conclusion.
	CompletionStoppedBudget CompletionStatus = "stopped_budget"
	// CompletionStoppedCapability means analysis stopped because the codebase or advisory
	// exceeded what the available plugins can evaluate.
	CompletionStoppedCapability CompletionStatus = "stopped_capability"
	// CompletionEnvUnavailable means analysis stopped because a required execution
	// environment was unavailable.
	CompletionEnvUnavailable CompletionStatus = "environment_unavailable"
)

// EvidenceFlag is a concrete, machine-checkable observed fact (RFC 0003). The two
// proof flags (canary/syscall) are the only flags that gate the proven rung.
type EvidenceFlag string

const (
	// FlagStaticTaintPathComplete records that static analysis found a complete taint
	// path from an untrusted ingress to the vulnerable symbol.
	FlagStaticTaintPathComplete EvidenceFlag = "static_taint_path_complete"
	// FlagPublicPoCReplayed records that a public proof-of-concept for the advisory was
	// replayed against the codebase.
	FlagPublicPoCReplayed EvidenceFlag = "public_poc_replayed"
	// FlagCanaryTriggered is a proof flag: it records that a canary planted in the
	// codebase's execution fired. It is one of the two flags that can gate a proven
	// verdict — see proofFlags.
	FlagCanaryTriggered EvidenceFlag = "canary_triggered" // proof flag
	// FlagSyscallConsistent is a proof flag: it records that observed syscall behavior is
	// consistent with the advisory's vulnerability class. It is one of the two flags that
	// can gate a proven verdict — see proofFlags.
	FlagSyscallConsistent EvidenceFlag = "syscall_consistent_with_class" // proof flag
)

// Condition is a precondition predicate in the verdict's envelope (RFC 0003).
type Condition struct {
	Predicate string `json:"predicate"` // e.g. "authenticated_session"
}

// CalibratedConfidence carries the computed score and the flags it was derived from.
// The score is COMPUTED from the flags, never narrated (RFC 0003).
type CalibratedConfidence struct {
	Score         float64        `json:"score"`
	EvidenceFlags []EvidenceFlag `json:"evidence_flags"`
}

// PoE is the apex artifact (RFC 0003). The Payload of a TypePoE artifact is this,
// JSON-encoded. The evidence chain is carried by reference (*artifact.Ref), never
// embedded (RFC 0003/0011).
type PoE struct {
	SchemaVersion    string               `json:"schema_version"` // = SchemaVersion
	ArtifactID       string               `json:"artifact_id"`
	AssessmentID     string               `json:"assessment_id"` // the per-pass Assessment id (RFC 0003)
	CaseID           string               `json:"case_id"`       // the durable matter id; set by the pipeline at emission (RFC 0003)
	Direction        Direction            `json:"direction"`
	Strength         Strength             `json:"strength"`
	Conditions       []Condition          `json:"conditions"`
	ReasonedGrounds  string               `json:"reasoned_grounds,omitempty"` // required iff Strength==reasoned
	Confidence       CalibratedConfidence `json:"confidence"`
	CompletionStatus CompletionStatus     `json:"completion_status"`
	// Evidence chain — artifact refs, not embedded (RFC 0003/0011).
	VulnerableSymbol *artifact.Ref `json:"vulnerable_symbol,omitempty"`
	CallPath         *artifact.Ref `json:"call_path,omitempty"`
	Ingress          *artifact.Ref `json:"ingress,omitempty"`
	Feasibility      *artifact.Ref `json:"feasibility,omitempty"`
	Reproducer       *artifact.Ref `json:"reproducer,omitempty"` // required iff exploitable && proven
	Observability    *artifact.Ref `json:"observability,omitempty"`
	ProofReport      *artifact.Ref `json:"proof_report,omitempty"` // the ProofReport that backs this verdict (§6.2)
	Episodes         []string      `json:"episodes"`               // Episode IDs that produced this
	// Objection records a sustained adversarial-review downgrade (RFC 0010). nil unless a
	// downgrade applied; additive optional field, so existing PoE JSON stays valid.
	Objection *Objection `json:"objection,omitempty"`
	// PatchValidation is the two-trace negative-control reference backing a `proven
	// not_exploitable` PoNE verdict (RFC 0010). nil for every other verdict class; required
	// (with both trace refs) when Strength==proven && Direction==not_exploitable.
	PatchValidation *PatchValidationRef `json:"patch_validation,omitempty"`
	// NonExploitableBasis records the grounded refutation behind a `reasoned not_exploitable`
	// verdict (a disqualification: version-not-affected or symbol-absent), distinguishing it
	// from a bare skeleton lean. Empty for every other verdict class — including a `proven`
	// PoNE (which is backed by PatchValidation) and a bare reasoned lean (BasisNone). This is
	// a grounded REASONED claim, never a proof: it cannot and must not raise Strength.
	NonExploitableBasis NonExploitableBasis `json:"non_exploitable_basis,omitempty"`
}

// PatchValidationRef carries the two ProofReport refs that back a PoNE `proven
// not_exploitable` verdict by reference (RFC 0003 evidence-by-ref), never embedded.
type PatchValidationRef struct {
	PositiveTrace *artifact.Ref `json:"positive_trace"` // ProofReport: canary FIRED pre-patch
	NegativeTrace *artifact.Ref `json:"negative_trace"` // ProofReport: canary DARK post-patch
	FixSource     string        `json:"fix_source"`     // "advisory:<ver>" | "client:<rev>"
}

// Label returns the four-name convenience label from the (direction, strength) grid.
//
//	proven   + exploitable     -> "exploitable"
//	proven   + not_exploitable -> "not_exploitable"
//	reasoned + exploitable     -> "reasoned_exploitable"
//	reasoned + not_exploitable -> "reasoned_not_exploitable"
func (p PoE) Label() string {
	if p.Strength == StrengthReasoned {
		return "reasoned_" + string(p.Direction)
	}
	return string(p.Direction)
}

// proofFlags are the only flags that gate the proven rung (RFC 0003). A proven
// verdict requires at least one ground-truth side-effect flag by construction.
var proofFlags = map[EvidenceFlag]bool{
	FlagCanaryTriggered:   true,
	FlagSyscallConsistent: true,
}

// hasProofFlag reports whether flags contain at least one proof flag.
func hasProofFlag(flags []EvidenceFlag) bool {
	for _, f := range flags {
		if proofFlags[f] {
			return true
		}
	}
	return false
}

// Validate enforces the PoE invariants and returns an error describing the first
// violation found. It encodes RFC 0001 invariant 5 — no proven verdict without
// execution proof:
//
//   - Strength==reasoned requires non-empty ReasonedGrounds (a reasoned verdict is a
//     defended lean; it must state its grounds).
//   - Strength==proven requires at least one proof flag (FlagCanaryTriggered or
//     FlagSyscallConsistent) AND a non-empty Confidence.EvidenceFlags set — a proven
//     verdict cannot exist without a ground-truth side-effect observation.
//   - Direction==exploitable && Strength==proven requires a non-nil Reproducer ref —
//     an exploitable proof must carry the runnable demonstration a client can fire.
//   - Direction==not_exploitable && Strength==proven requires a PatchValidation with both
//     trace refs — a proven not-exploitable claim must carry its two-trace negative control
//     (RFC 0010). This tightens, never loosens: it adds a structural obligation.
func (p PoE) Validate() error {
	switch p.Strength {
	case StrengthReasoned:
		if p.ReasonedGrounds == "" {
			return errors.New("verdict: reasoned strength requires non-empty ReasonedGrounds")
		}
	case StrengthProven:
		if len(p.Confidence.EvidenceFlags) == 0 {
			return errors.New("verdict: proven strength requires non-empty Confidence.EvidenceFlags")
		}
		if !hasProofFlag(p.Confidence.EvidenceFlags) {
			return fmt.Errorf("verdict: proven strength requires a proof flag (%q or %q)",
				FlagCanaryTriggered, FlagSyscallConsistent)
		}
		if p.Direction == DirectionExploitable && p.Reproducer == nil {
			return errors.New("verdict: exploitable+proven requires a non-nil Reproducer ref (RFC 0001 inv. 5)")
		}
		if p.Direction == DirectionNotExploitable {
			if p.PatchValidation == nil ||
				p.PatchValidation.PositiveTrace == nil ||
				p.PatchValidation.NegativeTrace == nil {
				return errors.New("verdict: not_exploitable+proven requires PatchValidation with both positive and negative trace refs (RFC 0010 two-trace)")
			}
		}
	default:
		return fmt.Errorf("verdict: unknown strength %q", p.Strength)
	}
	// A grounded non-exploitability basis is a REASONED refutation, never a proof: it may
	// appear ONLY on a reasoned not_exploitable verdict. Setting it on a proven verdict would
	// be the inverted inv.5 violation (a disqualification masquerading as a proof of a working
	// patch — exactly the re-scan-only basis RFC 0010 rejects), and on an exploitable verdict
	// it is incoherent. Reject both structurally.
	if p.NonExploitableBasis != BasisNone {
		if p.Strength != StrengthReasoned || p.Direction != DirectionNotExploitable {
			return fmt.Errorf("verdict: non_exploitable_basis %q is only valid on a reasoned not_exploitable verdict (inv.5: a grounded refutation is reasoned, never proven)", p.NonExploitableBasis)
		}
	}
	return nil
}
