// Package report defines the neutral scan Report — the canonical output contract
// of the ferralon-assay OSS tool. It is the document every downstream Phase-2/3
// component (StateStore, projectors, triggers, the CLI) reads or renders.
//
// # Tier-grammar boundary (invariant 5)
//
// The Report carries ONLY the deterministic verdict set the OSS tool is allowed
// to emit (inv. 5 — no proven verdict without executable proof):
//
//   - VerdictDisqualified     — provably out of scope (version not in affected range).
//   - VerdictNotExploitable   — provably safe with grounds (vulnerable symbol absent /
//     not reachable). A grounded REASONED refutation, never a proof.
//   - VerdictReachableCandidate — a reachable code path was found. Framed as a
//     *candidate*, never as "vulnerable" / "exploitable". Turning a candidate into a
//     proven verdict takes a ground-truth execution observation, which this tool
//     does not make.
//   - VerdictUndetermined     — the advisory applies and the scan established NOTHING
//     about it. The absence of a verdict, stated explicitly.
//   - VerdictMaliciousPresent — a known-malicious package (OSV MAL advisory) resolved
//     to a listed affected version. The one decisive OSS "affected": deterministic
//     presence proof, not a reachability lean, so it does not cross inv. 5.
//
// The Report MUST NOT carry `exploitable` or `reasoned_*` verdicts — those are
// Service-tier concepts. There is no model in the runner that could produce them,
// so the boundary is structural. AdvisoryFinding.Verdict is constrained to the
// values above by construction; see Verdict.Valid.
//
// # Role
//
// The Report is a neutral output PROJECTION of one deterministic Assess pass — it
// is NOT an Assessment (the Case/Assessment lifecycle stays Service-side). It is
// its own type, deliberately decoupled from the pipeline carrier types: a Report
// is built from S1–S6 output but does not embed pipeline internals.
//
// # Serialization
//
// The Report round-trips cleanly to and from JSON (Report → JSON → Report is
// lossless). It is the on-disk `report.json` the StateStore commits to the orphan
// ref and the source of truth the OpenVEX / SARIF / inlined-HTML projectors render.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// SchemaVersion is the versioned identifier of the Report schema. It is written
// into every Report so future readers can detect and migrate older documents.
// Bump it on any breaking change to the field set or semantics.
//
// v3 is the per-value-stamped Priority: every EPSS/KEV value carries its own stamp
// (epss_as_of; kev_catalog_version + kev_date_released), each field is present exactly
// when it has a value (a sourced EPSS score or percentile of 0 included), a stamped
// KEV observation without kev_listed means "not in that catalog", and the signals file
// is named once as provenance.intel.signals_digest. upgradeV2 records how v2 differs.
const SchemaVersion = "tegron.report.v3"

// SchemaVersionV2 is the schema before per-value priority stamps. Documents carrying
// it are still read and are upgraded on read by Upgrade; nothing produces it any more.
const SchemaVersionV2 = "tegron.report.v2"

// SchemaVersionV1 is the schema before first-class undetermined rows. Documents
// carrying it are still read (a StateStore written before the v2 bump holds one) and
// are upgraded on read by Upgrade; nothing produces it any more.
const SchemaVersionV1 = "tegron.report.v1"

// Verdict is the per-advisory deterministic verdict an OSS scan may assign. It is
// the constrained subset of the full (direction × strength) verdict grammar that
// invariant 5 permits the runner to emit. The full grammar lives in package
// verdict; the OSS Report deliberately exposes only these five values so a
// downstream reader cannot encounter `exploitable` or `reasoned_*` in OSS state.
type Verdict string

const (
	// VerdictDisqualified — the advisory does not apply to this codebase because the
	// resolved dependency version is provably outside the advisory's affected range
	// (disqualification_discovery). The strongest deterministic "safe".
	VerdictDisqualified Verdict = "disqualified"

	// VerdictNotExploitable — the advisory applies to a present dependency, but the
	// vulnerable code is provably absent from the built artifact or provably not
	// reachable. A grounded reasoned refutation (see EvidenceSummary.Basis); NEVER a
	// proof of a working patch (that is the Service-tier two-trace PoNE, inv. 5).
	VerdictNotExploitable Verdict = "not_exploitable"

	// VerdictReachableCandidate — a reachable path to the vulnerable symbol was found.
	// This is "declared-partial": a CANDIDATE for exploitability, never a claim of it.
	// This tool stops here; turning a candidate into `exploitable` requires observing
	// the path execute, which the runner does not do.
	VerdictReachableCandidate Verdict = "reachable_candidate"

	// VerdictUndetermined — the advisory applies to this codebase and the scan
	// established NOTHING about it: not that it is out of range, not that the vulnerable
	// code is absent, not that a path reaches it. It is the explicit absence of a
	// verdict, and it is a CLAIM ABOUT THE SCAN, never about the codebase.
	//
	// It exists because the other three are all assertions, and a scan that establishes
	// nothing has no honest way to pick one — the pressure to pick anyway is what
	// produced a real defect: Go toolchain advisories emitted
	// not_exploitable/vulnerable_symbol_absent, projected into customers' OpenVEX as
	// not_affected, on a fact the scanner never established.
	//
	// A reader must treat it as "not assessed, never safe": it is NOT a weaker
	// not_exploitable, and it must never be counted as a clean result. UndeterminedReason
	// carries the machine-readable reason; Evidence.Basis MUST be empty (there are no
	// refutation grounds to state — Validate enforces it).
	VerdictUndetermined Verdict = "undetermined"

	// VerdictMaliciousPresent — the codebase resolved a KNOWN-MALICIOUS package (an OSV MAL
	// advisory) to a version the advisory enumerates as affected. It is the ONE decisive OSS
	// "affected": unlike reachable_candidate (a lean) it rests on deterministic proof that the
	// bad artifact is installed — exact-version membership, no reachability inference — so its
	// OpenVEX projection is honestly "affected" without crossing inv. 5 (no execution claim is
	// laundered; this is the deterministic-no-execution mirror of VerdictDisqualified, pointed
	// the other way). It is affirmative-only: the presence stage emits it or nothing, and it
	// never mints a not-affected, so disqualify's first_party trust gate stays untouched.
	VerdictMaliciousPresent Verdict = "malicious_package_present"
)

// Valid reports whether v is one of the five permitted deterministic verdicts.
// It is the structural guard for inv. 5: any value outside this set (notably the
// Service-tier `exploitable` / `reasoned_*`) is rejected.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictDisqualified, VerdictNotExploitable, VerdictReachableCandidate, VerdictUndetermined, VerdictMaliciousPresent:
		return true
	default:
		return false
	}
}

// Package identifies one resolved dependency in the SBOM by ecosystem coordinates.
// The triple {Ecosystem, Name, Version} is exactly what CVE-watch later feeds to
// OSV.dev `querybatch`, so it is modeled cleanly and serializably with no embedded
// analysis state.
type Package struct {
	// Ecosystem is the OSV.dev / PURL ecosystem name (e.g. "Go", "Maven", "npm").
	// It matches the OSV `package.ecosystem` field so the SBOM feeds querybatch
	// directly.
	Ecosystem string `json:"ecosystem"`
	// Name is the package name within the ecosystem (e.g. "golang.org/x/text",
	// "com.example:widget", "lodash").
	Name string `json:"name"`
	// Version is the exact resolved version (e.g. "v0.3.7", "1.2.3"). The resolved
	// version, not a constraint — disqualification compares it against advisory ranges.
	Version string `json:"version"`
	// PURL is the optional package URL (pkg:golang/golang.org/x/text@v0.3.7) when the
	// analyzer resolved one. Used as the OpenVEX/SARIF product identifier; omitted
	// when unavailable.
	PURL string `json:"purl,omitempty"`
	// Direct distinguishes a direct dependency — one the scanned module itself declares —
	// from a transitive one pulled in through the graph (§4.1.2 "direct/transitive
	// relationship"). It mirrors plugin.DependencyNode.Direct and, like it, is NOT
	// omitempty: false (transitive) is load-bearing and must serialize, or a transitive
	// package would be byte-indistinguishable from a direct one. A stored v2 document
	// written before this field decodes to false and is regenerated as direct/transitive
	// on its next baseline run.
	Direct bool `json:"direct"`
	// Root marks the scanned project itself: an advisory against the repository's own package
	// (grafana's advisory in the grafana repository), whose vulnerable code is first-party.
	Root bool `json:"root,omitempty"`
	// PartialReason discloses a limit on THIS package's own resolution using the open
	// plugin Partiality reason vocabulary (e.g. an integrity digest that could not be
	// acquired in a no-acquisition scan, a version range that could not be pinned). It is
	// the §4.1 "declared partiality for unresolved conditions" at package scope: a field
	// that could not be established is declared here rather than emitted as an empty value
	// masquerading as "nothing to resolve". Empty means the package resolved cleanly. It
	// is DISCLOSURE, never a verdict (inv. 5) — no finding depends on it. When several
	// limits apply to one package the primary code rides here and the full set stays in
	// the inventory node; a graph-level limit (a whole ecosystem unresolved) is a
	// scan-level PartialityNote, not this field.
	PartialReason string `json:"partial_reason,omitempty"`
	// Replace is the module path a replace directive substitutes for this package (Go), so the
	// build compiles that module's code under Name. Empty when not replaced or replaced by a
	// directory.
	Replace string `json:"replace,omitempty"`
}

// Label is the package as a finding row names it: name@version for a resolved package. A
// version the inventory observed without resolving it (PartialReason source_unpinned) is
// shown as an observation, never as name@version, and a package with no version is its name.
func (p Package) Label() string {
	switch {
	case p.Version == "":
		return p.Name
	case p.PinUnresolved():
		return fmt.Sprintf("%s (pinned %s, not resolved)", p.Name, p.Version)
	default:
		return p.Name + "@" + p.Version
	}
}

// PinUnresolved reports whether Version is an inventory observation rather than a resolved
// version (PartialReason source_unpinned). Such a version must never be presented as
// name@version, in a label or in an identifier.
func (p Package) PinUnresolved() bool {
	return p.Version != "" && strings.HasPrefix(p.PartialReason, plugin.PartialReasonSourceUnpinned)
}

// Key is this package's stable identity for Relationship endpoints: its PURL when the
// analyzer resolved one, else the ecosystem-scoped coordinate triple. The report SBOM is
// package-granularity — distinct plugin.DependencyNode instances of one PURL collapse to
// one report package — so relationships are expressed over these keys, not over the
// inventory's per-instance node IDs (which do not ride the report). Deterministic: two
// packages with equal identity produce equal keys.
func (p Package) Key() string {
	if p.PURL != "" {
		return p.PURL
	}
	return p.Ecosystem + ":" + p.Name + "@" + p.Version
}

// SBOM is the resolved dependency set of the scanned codebase. It is the input to
// CVE-watch (OSV.dev querybatch over Packages) and is content-addressed in state:
// an unchanged SBOM serializes byte-identically so the StateStore writes zero new
// git objects.
type SBOM struct {
	// Packages is the resolved dependency set. Order is stable (callers sort before
	// constructing) so the serialized form is deterministic for content addressing.
	Packages []Package `json:"packages"`
	// Relationships is the parent→child dependency-edge set over Packages (§4.1.2
	// "parent edges"; §8 DoD checkbox 2 "and dependency relationships"). Each endpoint is
	// a Package.Key(); a whole-graph SBOM keyed off plugin.DependencyInventory carries the
	// edges the inventory resolved. Explicitly ordered (sorted by (Parent, Child)) and
	// de-duplicated by the builder, never map-ordered, so an unchanged SBOM serializes
	// byte-identically and the StateStore writes zero new git objects. omitempty: a lane
	// whose resolver expresses no edges (or none yet) omits the field rather than emitting
	// an empty array — absent edges are declared by a scan-level PartialityNote, not by [].
	Relationships []Relationship `json:"relationships,omitempty"`
	// GoBuildList names the resolver output the Go packages were taken from when they are the
	// build's whole module list with replace targets recorded (plugin.DependencyInventory.BuildList).
	// Empty for an SBOM resolved any other way, or written before replace targets were recorded.
	GoBuildList string `json:"go_build_list,omitempty"`
	// GoMainModule is the path of the module GoBuildList was resolved for; set with it.
	GoMainModule string `json:"go_main_module,omitempty"`
}

// Relationship is one parent→child dependency edge in the SBOM (§4.1.2). Endpoints are
// Package.Key() values, not inventory node IDs: the report SBOM is package-granularity, so
// an edge relates two package identities. It carries no analysis state — a relationship is
// structural, never a verdict (inv. 5).
type Relationship struct {
	// Parent is the Package.Key() of the depending package (the one that pulls the child in).
	Parent string `json:"parent"`
	// Child is the Package.Key() of the depended-on package.
	Child string `json:"child"`
}

// ReachabilityGrade refines a reachable_candidate by the STRENGTH of the
// deterministic reachability evidence found on the path. It is NOT a verdict and
// never asserts exploitability (inv. 5): every graded finding remains a
// reachable_candidate. The grade only distinguishes how much attacker-controllable
// signal the deterministic analysis found — evidence strength, not a claim. Turning
// the stronger grade into a proven `exploitable` still requires an execution observation.
type ReachabilityGrade string

const (
	// GradeControlFlowOnly — the vulnerable symbol is callable (a control-flow path
	// exists) but the deterministic analysis found no attacker-controllable data
	// flowing along that path to it. The weaker candidate signal.
	GradeControlFlowOnly ReachabilityGrade = "control_flow_only"
	// GradeAttackerTainted — an attacker-controllable ingress reaches the vulnerable
	// symbol AND tainted data flows along the path to it (taint path-presence). The
	// strongest deterministic candidate signal; still a candidate, never exploitable.
	GradeAttackerTainted ReachabilityGrade = "attacker_tainted"
)

// Valid reports whether g is a permitted grade. The empty grade is valid (a
// candidate need not be graded; non-candidates must leave it empty).
func (g ReachabilityGrade) Valid() bool {
	switch g {
	case "", GradeControlFlowOnly, GradeAttackerTainted:
		return true
	default:
		return false
	}
}

// SymbolConfidence qualifies a reachable_candidate by the CONFIDENCE in how the
// vulnerable-symbol set that resolved was DERIVED — the corpus's record-scoped
// symbol_provenance tag, read as a strength signal (RFC §4.1). It is orthogonal to
// ReachabilityGrade: grade is how much attacker-controllable signal the path carries;
// SymbolConfidence is how the symbol identity itself was obtained.
//
// It is a STRENGTH signal on an ALREADY-FORMED candidate, NEVER a verdict and NEVER an
// admission/refute input (inv. 5): a lower confidence never gates a symbol out of
// reachability, never disqualifies, and never flips a verdict — it only qualifies how the
// candidate was reached. A stronger confidence never asserts exploitability. Empty ⇒ no
// derivation signal (absent OR unrecognized provenance): the candidate is reported exactly
// as it is today, at no confidence penalty — absent is unknown derivation, not low
// confidence (honest-absent).
type SymbolConfidence string

const (
	// SymbolConfidenceHigh — the resolved symbols were authoritatively declared
	// (symbol_provenance "osv-declared" / "curated").
	SymbolConfidenceHigh SymbolConfidence = "high"
	// SymbolConfidenceModerate — the resolved symbols were heuristically extracted
	// (symbol_provenance "diff-lexed"). A LOWER confidence label; still a full candidate,
	// walked and graded identically, never gated out.
	SymbolConfidenceModerate SymbolConfidence = "moderate"
)

// symbol_provenance "cna-declared" (symbols the assigning CNA declared, with no measured
// completeness rate) maps to no SymbolConfidence: the candidate carries an empty label, like
// absent provenance.

// Valid reports whether c is a permitted confidence label. Empty is valid (a candidate need
// not carry a derivation signal; non-candidates must leave it empty).
func (c SymbolConfidence) Valid() bool {
	switch c {
	case "", SymbolConfidenceHigh, SymbolConfidenceModerate:
		return true
	default:
		return false
	}
}

// ExploitPreconditions carries the advisory-declared preconditions for the exploit
// mechanism to fire — the corpus's record-scoped trigger_condition / prerequisite text
// (RFC §4.2, the Proof-of-Exploitability qualifier axis). It DESCRIBES a
// reachable_candidate; it never scores it. Populated only on a reachable_candidate, only
// after the candidate has formed, so it is structurally incapable of reaching admission,
// disqualification, or refute (inv.5).
//
// It is presence-only context, NEVER a met/unmet evaluation: the OSS Assess tier does not
// and cannot decide whether a free-text precondition holds in the customer build — that is
// a runtime question only the Prove tier settles, exactly as MitigatingGuards surfaces
// guard PRESENCE without asserting sufficiency. Because unmet is never computed, a
// present-but-unmet precondition can never refute or weaken a verdict; it only records that
// exploitation is CONDITIONAL. Absent ⇒ nil ⇒ the candidate is reported exactly as today
// (absent = unconditional, the conservative reading, never "not exploitable" — honest-absent).
//
// A non-nil value MUST carry at least one non-empty field: conditionality is never asserted
// from emptiness (validate() rejects a non-nil-but-empty block).
type ExploitPreconditions struct {
	// TriggerCondition is the advisory-declared condition under which the trigger fires
	// (e.g. "a malicious HTTP/2 client rapidly resets requests"). Empty when undeclared.
	TriggerCondition string `json:"trigger_condition,omitempty"`
	// Prerequisite is the advisory-declared mechanism precondition (e.g. a required
	// configuration or attacker capability). Empty when undeclared.
	Prerequisite string `json:"prerequisite,omitempty"`
}

// Empty reports whether p declares no precondition at all — the state that must resolve to
// a nil *ExploitPreconditions (no annotation), never a non-nil-but-empty block.
func (p ExploitPreconditions) Empty() bool {
	return p.TriggerCondition == "" && p.Prerequisite == ""
}

// GuardSufficiencyLabel classifies one on-path guard by whether the advisory DECLARES it
// sufficient to close its bypass (corpus guard_sufficiency). It is an advisory-DECLARED,
// Prove-adjudicated claim surfaced as candidate context — the Assess tier NEVER verifies it
// (whether the guard actually closes the hole is a runtime question only the Prove tier
// settles, exactly as MitigatingGuards surfaces guard PRESENCE without asserting sufficiency).
type GuardSufficiencyLabel string

const (
	// GuardSufficiencySufficient — the advisory declares this guard variant sufficient to
	// close its bypass. Still only a DECLARED claim; Assess does not confirm it.
	GuardSufficiencySufficient GuardSufficiencyLabel = "sufficient"
	// GuardSufficiencyInsufficient — the advisory declares this guard variant insufficient
	// (e.g. gogs IsSymlink@0.13.3, a leaf-only check the bypass still defeats). A LOWER
	// descriptive label; it never weakens or flips the candidate verdict.
	GuardSufficiencyInsufficient GuardSufficiencyLabel = "insufficient"
)

// Valid reports whether l is a recognized sufficiency label. Unlike SymbolConfidence, empty
// is NOT valid: a GuardSufficiencyNote exists only to carry a declared label, so an empty one
// is a malformed annotation (validate() rejects it), never a no-signal state — absence is
// expressed by omitting the note entirely, not by an empty label.
func (l GuardSufficiencyLabel) Valid() bool {
	switch l {
	case GuardSufficiencySufficient, GuardSufficiencyInsufficient:
		return true
	default:
		return false
	}
}

// SufficiencyLabel maps the advisory's declared sufficiency bool onto its descriptive label.
func SufficiencyLabel(sufficient bool) GuardSufficiencyLabel {
	if sufficient {
		return GuardSufficiencySufficient
	}
	return GuardSufficiencyInsufficient
}

// GuardSufficiencyNote annotates ONE guard already surfaced on the candidate path
// (EvidenceSummary.MitigatingGuards) with the advisory's DECLARED sufficiency against a named
// bypass (RFC §4.2, B-guardsuff). It is DESCRIPTIVE, presence-only context: it records what the
// advisory declares about an on-path guard, never a met/unmet evaluation and never a strength
// score. It can only ADD context to an already-formed reachable_candidate — never gate
// admission, never refute, never flip a verdict. A note is emitted only for a guard that
// guardsOnPath already reported, so it never widens the guard set.
type GuardSufficiencyNote struct {
	// Symbol is the guard function/method (matches a MitigatingGuards entry).
	Symbol string `json:"symbol"`
	// ForBypass names the bypass the sufficiency claim is scoped to (advisory-declared).
	ForBypass string `json:"for_bypass,omitempty"`
	// Sufficiency is the advisory's declared classification for this guard against ForBypass.
	Sufficiency GuardSufficiencyLabel `json:"sufficiency"`
}

// CallFrame is one node on a reachability path: a symbol with an optional source
// location so a reader can jump straight to the code. Neutral evidence — it records
// where a path runs, never that the path is exploitable.
type CallFrame struct {
	// Symbol is the function / method at this frame (e.g. "pkg.VulnFunc").
	Symbol string `json:"symbol"`
	// File is the source file holding Symbol, when the analyzer resolved one.
	File string `json:"file,omitempty"`
	// Line is the 1-based line of Symbol within File, when known.
	Line int `json:"line,omitempty"`
}

// EntryPoint is the ingress at the head of a candidate path — where untrusted input
// can enter the program. AttackerControllable records whether the deterministic
// ingress analysis classed this entry as attacker-reachable (e.g. an HTTP route) vs
// an internal/dev-only entry (e.g. a CLI flag or test main). It is evidence about
// the path's head, not a verdict about the finding.
type EntryPoint struct {
	// Symbol is the entrypoint function (e.g. "net/http.HandlerFunc", "main.main").
	Symbol string `json:"symbol"`
	// Kind classifies the ingress: "http_route" | "rpc" | "cli" | "test" |
	// "unknown". Drives the attacker-controllability read and the display.
	Kind string `json:"kind,omitempty"`
	// AttackerControllable is true when this ingress can carry untrusted, externally
	// supplied input (e.g. an HTTP route), false for internal/dev-only entries.
	AttackerControllable bool `json:"attacker_controllable"`
}

// AdvisoryBound is one affected range of an advisory that records no version the version axis can
// compare against. Type is the OSV range type ("GIT" bounds are commits); any field may be empty.
type AdvisoryBound struct {
	Type         string `json:"type,omitempty"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// EvidenceSummary is a compact, neutral grounds statement for one advisory's
// verdict — what made it disqualified / not-reachable / a candidate. It carries
// the structured basis plus a short human-readable line; it does NOT embed full
// evidence chains (those are Service-tier artifacts). This keeps the Report a thin
// projection safe to store and render.
type EvidenceSummary struct {
	// Basis is the structured grounds for a not_exploitable / disqualified verdict,
	// reusing the OSS verdict grammar (verdict.NonExploitableBasis):
	// "version_not_in_affected_range", "vulnerable_symbol_absent" or, for a not_exploitable
	// resting on reachability, "vulnerable_symbol_unreachable". Empty for a
	// reachable_candidate (which has no refutation basis — its grounds are the path) and
	// for an undetermined finding (which has no grounds at all).
	Basis verdict.NonExploitableBasis `json:"basis,omitempty"`
	// Detail is a one-line, neutral, human-readable summary of the grounds (e.g.
	// "resolved v0.3.7 is below the first affected version v0.3.8" or "a path from an
	// HTTP handler reaches the advisory symbol"). Neutral phrasing only — never
	// asserts exploitability.
	Detail string `json:"detail,omitempty"`
	// Assumptions are the caller's declarations a not_exploitable verdict holds only under, each one
	// checkable line (a library-entrypoints declaration that took a package out of the entry points).
	// Empty means the verdict rests on the scan's evidence alone. Set only on a not_exploitable.
	Assumptions []string `json:"assumptions,omitempty"`
	// ReachablePath, for a reachable_candidate, names the entrypoint→symbol path that
	// made it a candidate (compact, e.g. "net/http.Handler → pkg.VulnFunc"). Empty
	// for disqualified / not_exploitable. Framed as a candidate path, never a proof.
	ReachablePath string `json:"reachable_path,omitempty"`
	// Grade refines a reachable_candidate by reachability-evidence strength (see
	// ReachabilityGrade). Empty for disqualified / not_exploitable. Never a verdict.
	Grade ReachabilityGrade `json:"reachability_grade,omitempty"`
	// EntryPoint is the ingress at the head of the candidate path, when discovery
	// resolved one. Nil unless the finding is a graded candidate.
	EntryPoint *EntryPoint `json:"entry_point,omitempty"`
	// CallPath is the structured ingress→symbol frames behind ReachablePath, when the
	// analyzer resolved them. ReachablePath stays the compact human form; CallPath is
	// the jump-to-source detail. Empty for non-candidates.
	CallPath []CallFrame `json:"call_path,omitempty"`
	// MitigatingGuards names the advisory-declared guard/validation functions found on
	// the candidate path (called by a path frame). It is MITIGATING EVIDENCE about the
	// candidate, never a verdict (inv.5): a guard's PRESENCE narrows attention, but the
	// candidate stays reachable_candidate because presence ≠ sufficiency — whether the
	// guard actually closes the hole is a runtime question only the Prove tier settles.
	// Empty when the advisory declares no guards or none were found on the path.
	MitigatingGuards []string `json:"mitigating_guards,omitempty"`
	// AdvisoryBounds is what the advisory's affected ranges record when none of them is a range
	// the version axis can check (undetermined_reason advisory_range_absent): each range's type and
	// its introduced, fixed and last_affected events. Disclosure only; nothing
	// reads it to decide a verdict. Set only on an advisory_range_absent finding.
	AdvisoryBounds []AdvisoryBound `json:"advisory_bounds,omitempty"`
	// SymbolConfidence qualifies a reachable_candidate by the confidence in how the
	// vulnerable-symbol set was DERIVED (corpus symbol_provenance). STRENGTH signal only,
	// never a verdict (inv.5, RFC §4.1): it is read only AFTER a candidate forms, so it can
	// neither gate admission nor refute. Empty ⇒ no derivation signal (absent or unrecognized
	// provenance) ⇒ candidate reported exactly as today. Populated only on a
	// reachable_candidate — validate() rejects it on any other verdict.
	SymbolConfidence SymbolConfidence `json:"symbol_confidence,omitempty"`
	// ExploitPreconditions surfaces the advisory-declared exploit preconditions
	// (trigger_condition / prerequisite) as PoE qualifier context on a reachable_candidate
	// (RFC §4.2). DESCRIPTIVE only — presence, never a met/unmet evaluation and never a
	// strength score: it enriches the evidence, it does not select or weaken the verdict.
	// Nil ⇒ no declared precondition (absent = unconditional, reported exactly as today —
	// honest-absent). Populated only on a reachable_candidate, and only with at least one
	// non-empty field — validate() rejects it on any other verdict and rejects an empty block.
	ExploitPreconditions *ExploitPreconditions `json:"exploit_preconditions,omitempty"`
	// GuardSufficiency annotates the MitigatingGuards on a reachable_candidate with the
	// advisory's DECLARED sufficiency (corpus guard_sufficiency) against each guard's bypass
	// (RFC §4.2, B-guardsuff). DESCRIPTIVE, presence-only: it surfaces a Prove-tier claim as
	// candidate context — it never evaluates whether a guard actually closes the hole (a runtime
	// question only the Prove tier settles) and never scores the candidate. It enriches the
	// evidence, it does not select or weaken the verdict. Each note annotates a guard already in
	// MitigatingGuards, so it never widens the guard set. Empty ⇒ no declared sufficiency for any
	// on-path guard ⇒ the candidate is reported exactly as today (honest-absent, inv.5).
	// Populated only on a reachable_candidate — validate() rejects it on any other verdict.
	GuardSufficiency []GuardSufficiencyNote `json:"guard_sufficiency,omitempty"`
}

// Priority is the EPSS/KEV prioritization context attached to a finding from the signals file the
// run was given (package intel). It is exploitation-LIKELIHOOD context from public feeds — NEVER an
// exploitability verdict for this codebase (inv. 5). EPSS is FIRST.org's probability the CVE is
// exploited in the wild; KEVListed means CISA records active exploitation of the CVE somewhere.
// Neither asserts the finding is exploitable here — they only rank attention, and nothing that
// decides a verdict reads them.
//
// EVERY VALUE CARRIES ITS OWN STAMP, because the values are point-in-time captures of differing
// age and there is no report-wide "as of" date: the EPSS fields come with EPSSAsOf, the model date
// they are from; the KEV fields come with KEVCatalogVersion and KEVDateReleased, the CISA catalog
// they were read from. A value is never set without its stamp (Validate enforces it), so a reader
// can always say how old each one is. Which signals file the values came from is recorded once, as
// Provenance.Intel.SignalsDigest.
//
// A nil Priority means the run had no signals, the file had no stamped value for the advisory's id
// or aliases, or the join to its record was refused. It never means "not exploited".
type Priority struct {
	// EPSSScore is FIRST.org's 0..1 probability the CVE is exploited in the wild in the 30 days
	// after EPSSAsOf. Set only with EPSSAsOf. Not omitempty: 0 is a real score, so it serializes
	// whenever EPSSAsOf does (MarshalJSON); a Priority with no EPSS value omits it.
	EPSSScore float64 `json:"epss_score"`
	// EPSSPercentile is the score's percentile rank among all CVEs scored by the same model run
	// (0..1). Not omitempty: 0 is a real percentile, so it serializes whenever HasPercentile is set
	// (MarshalJSON); a percentile the signals file did not source is omitted.
	EPSSPercentile float64 `json:"epss_percentile"`
	// HasPercentile is whether the signals file sourced EPSSPercentile, zero included. It is not a
	// field of its own on the wire: epss_percentile's presence carries it both ways.
	HasPercentile bool `json:"-"`
	// EPSSAsOf is the EPSS model date (YYYY-MM-DD) the score and percentile come from. Set iff the
	// finding carries an EPSS value.
	EPSSAsOf string `json:"epss_as_of,omitempty"`
	// KEVListed is true when the CVE was in the CISA Known Exploited Vulnerabilities catalog named
	// by KEVCatalogVersion. With the catalog stamp set and KEVListed false (omitted on the wire), the
	// CVE was NOT in that catalog as of KEVDateReleased — which says nothing about the catalog today.
	KEVListed bool `json:"kev_listed,omitempty"`
	// KEVDateAdded is the date CISA added the CVE to KEV (YYYY-MM-DD); set only when KEVListed and
	// the signals file stated it.
	KEVDateAdded string `json:"kev_date_added,omitempty"`
	// KEVCatalogVersion is CISA's version string for the catalog the KEV observation was read
	// from. Set iff the finding carries a KEV observation, together with KEVDateReleased.
	KEVCatalogVersion string `json:"kev_catalog_version,omitempty"`
	// KEVDateReleased is CISA's release timestamp for that catalog version.
	KEVDateReleased string `json:"kev_date_released,omitempty"`
}

// MarshalJSON writes epss_score whenever the Priority carries an EPSS value, so a genuine score of 0
// is never read as an as-of with no score, and omits it from a block with no EPSS value at all (a
// KEV-only observation). It writes epss_percentile whenever the signals file sourced one, so a
// genuine percentile of 0 is never read as an unsourced one. A value with no stamp is written too
// (Validate refuses it), and so is a nonzero percentile without HasPercentile: the encoder never
// hides a value it was given.
func (p Priority) MarshalJSON() ([]byte, error) {
	type plain Priority // the same fields without this method
	w := struct {
		EPSSScore      *float64 `json:"epss_score,omitempty"`
		EPSSPercentile *float64 `json:"epss_percentile,omitempty"`
		plain
	}{plain: plain(p)}
	if p.EPSSAsOf != "" || p.EPSSScore != 0 {
		w.EPSSScore = &p.EPSSScore
	}
	if p.HasPercentile || p.EPSSPercentile != 0 {
		w.EPSSPercentile = &p.EPSSPercentile
	}
	return json.Marshal(w)
}

// UnmarshalJSON reads a priority block, setting HasPercentile exactly when epss_percentile is
// present, so a sourced percentile of 0 reads back as sourced.
func (p *Priority) UnmarshalJSON(b []byte) error {
	type plain Priority // the same fields without this method
	w := struct {
		EPSSPercentile *float64 `json:"epss_percentile"`
		*plain
	}{plain: (*plain)(p)}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	if w.EPSSPercentile != nil {
		p.EPSSPercentile, p.HasPercentile = *w.EPSSPercentile, true
	}
	return nil
}

// HasEPSS reports whether the Priority carries a (stamped) EPSS value.
func (p *Priority) HasEPSS() bool { return p != nil && p.EPSSAsOf != "" }

// HasEPSSPercentile reports whether the Priority carries a (stamped) EPSS percentile: one the
// signals file sourced, zero included, or any nonzero one.
func (p *Priority) HasEPSSPercentile() bool {
	return p.HasEPSS() && (p.HasPercentile || p.EPSSPercentile != 0)
}

// HasKEV reports whether the Priority carries a (stamped) KEV observation, listed or not.
func (p *Priority) HasKEV() bool { return p != nil && p.KEVCatalogVersion != "" }

// validate enforces that no priority value is set without its stamp, and that an empty Priority is
// nil rather than present-and-empty.
func (p *Priority) validate() error {
	if p.EPSSAsOf == "" && (p.EPSSScore != 0 || p.EPSSPercentile != 0 || p.HasPercentile) {
		return fmt.Errorf("an EPSS value without its epss_as_of stamp")
	}
	if (p.KEVCatalogVersion == "") != (p.KEVDateReleased == "") {
		return fmt.Errorf("half a KEV catalog stamp (kev_catalog_version and kev_date_released go together)")
	}
	if p.KEVCatalogVersion == "" && (p.KEVListed || p.KEVDateAdded != "") {
		return fmt.Errorf("a KEV value without its kev_catalog_version / kev_date_released stamp")
	}
	if p.KEVDateAdded != "" && !p.KEVListed {
		return fmt.Errorf("kev_date_added on a CVE that is not kev_listed")
	}
	if p.EPSSAsOf == "" && p.KEVCatalogVersion == "" {
		return fmt.Errorf("an empty priority block (no signal must be a nil priority)")
	}
	return nil
}

// Advisory identifies a vulnerability the scan evaluated. It is a self-contained
// identifier (id + source) so the Report does not couple to the assessment carrier;
// it mirrors the shape of assessment.VulnRef without importing the lifecycle package.
type Advisory struct {
	// ID is the advisory identifier (e.g. "GO-2021-0001", "CVE-2024-1234").
	ID string `json:"id"`
	// Source is the advisory database the ID came from ("osv" | "nvd" | "ghsa").
	Source string `json:"source"`
	// Aliases are alternate identifiers for the same advisory (e.g. a CVE alias for a
	// GHSA id). Optional; lets a reader correlate across databases.
	Aliases []string `json:"aliases,omitempty"`
}

// AdvisoryFinding is one advisory the scan evaluated, paired with its deterministic
// verdict and the grounds behind it.
type AdvisoryFinding struct {
	// Advisory identifies the vulnerability evaluated (CVE / GHSA / OSV id + source).
	Advisory Advisory `json:"advisory"`
	// Package names the dependency the advisory was evaluated against (the member of
	// SBOM.Packages this finding concerns). Optional when the advisory is codebase-wide.
	Package *Package `json:"package,omitempty"`
	// Verdict is the per-advisory deterministic verdict. It MUST satisfy Verdict.Valid
	// (inv. 5): one of disqualified / not_exploitable / reachable_candidate / undetermined /
	// malicious_package_present.
	Verdict Verdict `json:"verdict"`
	// UndeterminedReason is the machine-readable reason the scan established no verdict.
	// Set IFF Verdict is VerdictUndetermined (Validate enforces both directions): a bare
	// "we do not know" with no reason is the silent-suppression failure this verdict
	// exists to end.
	//
	// It draws on the SAME OPEN vocabulary as PartialityNote.Reason — the two describe
	// one fact at two scopes (the limit, and the advisories it hit), so they must name it
	// with one word. A reader that meets an unrecognized code must disclose it honestly
	// rather than drop the row.
	//
	// It sits beside Verdict rather than inside Evidence deliberately: it qualifies the
	// verdict (why there is none), where EvidenceSummary states grounds FOR one, and an
	// undetermined finding has no grounds to state.
	UndeterminedReason string `json:"undetermined_reason,omitempty"`
	// Evidence is the compact grounds behind the verdict (see EvidenceSummary).
	Evidence EvidenceSummary `json:"evidence"`
	// Priority is the EPSS/KEV prioritization context for this advisory, from the signals
	// file the run was given, each value carrying its own stamp (see Priority). Nil when
	// the run had no signals or the file had no stamped value for the advisory's id or
	// aliases — never "not exploited". Exploitation-likelihood context only — never an
	// exploitability claim for this codebase.
	Priority *Priority `json:"priority,omitempty"`
}

// Provenance records how and when the Report was produced — enough to make it
// reproducible and to drive StateStore CAS merges (latest per-advisory verdict
// wins by Timestamp).
type Provenance struct {
	// CommitSHA is the resolved commit of the scanned codebase.
	CommitSHA string `json:"commit_sha"`
	// AnalyzerVersion is the ferralon-assay tool version that produced the Report. Lets
	// future readers reason about analyzer-driven verdict changes.
	AnalyzerVersion string `json:"analyzer_version"`
	// CapabilityManifestVersion cites the capability.Manifest CONTENT version this scan's
	// evidence was produced under (which analyzer support surface was in force). Additive and
	// omitempty; population is Phase-4 (each lane stamps a real version in its PLAN-4x0), so this
	// cycle it stays empty. Kept a plain string so report needs no capability import.
	CapabilityManifestVersion string `json:"capability_manifest_version,omitempty"`
	// AdvisoryCursor is the advisory-corpus position this scan evaluated against. It
	// is the CVE-watch cursor: a later run compares OSV.dev querybatch results to the
	// stored cursor to decide heartbeat vs earnest run.
	AdvisoryCursor string `json:"advisory_cursor"`
	// Timestamp is when the Report was produced (UTC). It is the tiebreaker for the
	// StateStore CAS merge: when two runs evaluate the same advisory, the later
	// Timestamp's verdict wins.
	Timestamp time.Time `json:"timestamp"`
	// Intel records WHERE this pass got its advisory work set and its advisory facts.
	// Nil on a Report built without it (additive; a reader that predates the field is
	// unaffected). See IntelProvenance.
	Intel *IntelProvenance `json:"intel,omitempty"`
}

// IntelProvenance records the intel inputs a scan pass actually used: which set of
// advisory ids it evaluated, how many, and where the FACTS about them came from.
//
// It exists because the two are independently variable and neither is visible in the
// findings. A Report with zero findings is the same shape whether the pass evaluated a
// wide work set and refuted all of it, or evaluated a narrow one; and a pass that
// resolved its facts from a stale corpus is the same shape as one that resolved them
// from a fresh one. Without this block, "why did this go red with no code change?" — or
// green — has no answer.
//
// The command line fills the whole block. trigger.Run* sets only SignalsDigest, the one input it
// holds: how the work set was chosen and where the facts came from are known to the entrypoint that
// resolved them, so on a library run the other fields are zero, meaning not recorded.
//
// It is DISCLOSURE, never a verdict (inv. 5). No finding's verdict, grounds, or count
// depends on it; it narrows what the verdicts above cover, exactly as PartialityNote
// does.
type IntelProvenance struct {
	// WorkSetSource names how the set of evaluated advisory ids was chosen — one of the
	// WorkSet* constants. The vocabulary is OPEN: a reader that meets an unrecognized
	// value must surface it rather than drop it.
	WorkSetSource string `json:"work_set_source"`
	// WorkSetSize is how many advisory ids that source produced for this pass.
	WorkSetSize int `json:"work_set_size"`
	// FactSource names the AdvisorySource chain the pass resolved facts through — one of
	// the FactSource* constants.
	FactSource string `json:"fact_source"`
	// CorpusDigest is the corpus_digest of the filesystem advisory corpus the pass read,
	// when one was configured. It is the handle that makes a verdict change attributable
	// to an intel change rather than a code change. Empty when no corpus was used.
	CorpusDigest string `json:"corpus_digest,omitempty"`
	// CorpusRecords is how many records that corpus accounted for. Empty when no corpus
	// was used. It is deliberately NOT the number of ids evaluated: without a declared
	// policy a corpus is a fact lookup, and with one the work set holds only the corpus
	// advisories that match the repository's dependencies — reading "72 records" as "72
	// CVEs evaluated" overstates the scan either way.
	CorpusRecords int `json:"corpus_records,omitempty"`
	// CorpusPolicy is the advisory policy the run declared its corpus was selected by (e.g.
	// "published-7d"). Empty when no policy was declared. WorkSetSource says whether the
	// policy actually defined the work set.
	CorpusPolicy string `json:"corpus_policy,omitempty"`
	// CorpusManifest is the provenance block the corpus manifest itself carries: the policy and
	// corpus snapshot that produced the record set the pass read. Nil when the corpus carries none
	// (a bundle file, or a manifest published without the block). It is reported as the producer
	// wrote it and is not checked against CorpusPolicy or CorpusDigest.
	CorpusManifest *CorpusManifestProvenance `json:"corpus_manifest,omitempty"`
	// CorpusSigner is the signer the corpus release was verified against before the pass read it:
	// the Action's bundle route checks the release's bundles.json with cosign for this exact
	// certificate identity and OIDC issuer, then pins the bundle to that bundles.json. Nil when no
	// signature was verified for the corpus the pass read (no corpus, a corpus directory, or a
	// bundle handed over without one). It records what was verified, not who should have signed.
	CorpusSigner *CorpusSigner `json:"corpus_signer,omitempty"`
	// SignalsDigest is the signals_digest of the EPSS/KEV signals file the pass ranked its findings
	// with: the value the loader recomputed from the file's payload, not the file's unverified
	// claim. trigger.Run* records it from the request's Signals, so a library run and the command
	// line name the file alike. Each priority value carries its own age stamp; this names the file.
	// When set, the file ranked every row in the Report, so a row with no Priority is one the file
	// holds no usable signal for (no record, or a refused join).
	//
	// A Report read back from the state ref is not always one run's work, so Priority rows can appear
	// WITHOUT a digest: statestore.Merge, on a conflicting write, unions rows from two runs and leaves
	// the digest empty when any row, ranked or not, came from a Report that named a different file (or
	// none) than the one whose provenance the merge kept; and a Report written before this field
	// existed has rows and no digest. So empty with Priority rows means the file is not known; empty
	// with no Priority rows means no file is named: no signals were recorded, or the rows came from
	// runs that did not share one.
	SignalsDigest string `json:"signals_digest,omitempty"`
}

// CorpusSigner names the keyless signer a corpus release's signature verified against. Both fields
// are always set on a non-nil value.
type CorpusSigner struct {
	// Identity is the signing certificate's identity (its SAN), e.g. a service account email.
	Identity string `json:"identity"`
	// Issuer is the OIDC issuer that certified Identity.
	Issuer string `json:"issuer"`
}

// CorpusManifestProvenance mirrors a policy manifest's `provenance` block. It is audit metadata
// about the corpus as a whole, distinct from the per-advisory trust tier a corpus document carries,
// and like the rest of IntelProvenance it never feeds a verdict.
type CorpusManifestProvenance struct {
	// GeneratedAt is when the producer generated the manifest, as the producer wrote it.
	GeneratedAt string `json:"generated_at,omitempty"`
	// Generator names the producing tool.
	Generator string `json:"generator,omitempty"`
	// PolicyID is the policy that selected the record set (e.g. "published-7d", "full").
	PolicyID string `json:"policy_id,omitempty"`
	// PolicyQuery is the human-readable form of that policy's selection predicate.
	PolicyQuery string `json:"policy_query,omitempty"`
	// SourceCorpusDigest is the digest of the full corpus the selection ran over.
	SourceCorpusDigest string `json:"source_corpus_digest,omitempty"`
	// SelectionIndexDigest is the digest of the selection index the selection read.
	SelectionIndexDigest string `json:"selection_index_digest,omitempty"`
}

// The WorkSetSource vocabulary. It is open — these are the values in use today.
const (
	// WorkSetBuiltinLanguageSet is the compiled-in, language-scoped list of advisory ids
	// (cmd/ferralon-assay/acquire.go). Fixed per language, identical on every repository.
	WorkSetBuiltinLanguageSet = "builtin_language_set"
	// WorkSetOSVQuery is an SBOM-driven work set resolved by querying OSV.dev for the
	// advisories that affect the repository's real dependencies.
	WorkSetOSVQuery = "osv_query"
)

// The FactSource vocabulary. It is open — these are the values in use today.
const (
	// FactSourceBuiltinTable is the compiled-in AdvisoryTable alone: no corpus configured.
	FactSourceBuiltinTable = "builtin_table"
	// FactSourceCorpusThenBuiltinTable is the chained source — a filesystem advisory
	// corpus consulted first, the built-in table behind it. The corpus SUPPLEMENTS the
	// table; facts are never merged across the two.
	FactSourceCorpusThenBuiltinTable = "corpus_then_builtin_table"
)

// PartialityNote discloses one limit on what this scan pass could establish about
// the codebase — e.g. a dependency ecosystem whose installed versions could not be
// pinned because the repository commits no lockfile or manifest.
//
// It is deliberately SCAN-LEVEL, not per-finding: the case it exists to disclose is
// precisely the one with ZERO findings. A codebase whose dependencies could not be
// resolved emits a Report that would otherwise be byte-indistinguishable from a
// genuinely clean scan, and a reader could reasonably conclude those dependencies
// were assessed when they were not. Surfacing the limit is the "not assessed, never
// safe" doctrine at the output boundary.
//
// A note is DISCLOSURE, never a verdict (inv. 5): it asserts nothing about
// exploitability, and no finding's Verdict, grounds, or count depends on one. It
// narrows what the verdicts above cover; it never changes them.
type PartialityNote struct {
	// Reason is the canonical machine-readable code the analyzer declared for the
	// limit (the plugin Partiality reason vocabulary, e.g. "no_manifest"). The
	// vocabulary is OPEN — a reader that meets an unrecognized code must disclose it
	// honestly rather than drop it, since dropping it restores the silent-clean-scan
	// failure this type exists to prevent.
	Reason string `json:"reason"`
	// Ecosystem scopes the limit to one dependency ecosystem, using the same
	// vocabulary as Package.Ecosystem ("Go", "npm", "PyPI", "Maven", "NuGet"). Empty
	// when the limit is scan-wide rather than ecosystem-scoped.
	Ecosystem string `json:"ecosystem,omitempty"`
	// Detail names the specific thing the limit applies to — the analysis step that did
	// not complete and the advisory it was evaluating, for a "tool_failure". Reason
	// stays the closed machine-readable code; Detail carries the free-text specifics a
	// reader needs to act ("which tool failed?"), so a consumer matching on Reason is
	// unaffected by it. Empty when the reason code says everything there is to say.
	//
	// It is part of the note's identity for de-duplication: two failures of different
	// steps are two disclosures, not one.
	Detail string `json:"detail,omitempty"`
	// Package and Path locate a limit the analyzer bounded to one package: the package whose code
	// holds the blind spot (a PURL without a version; empty for first-party code or a scan-wide
	// limit) and the location inside it. Disclosure only, and part of the note's identity.
	Package string `json:"package,omitempty"`
	Path    string `json:"path,omitempty"`
	// Class sorts the limit into the quiet methodology arm (inherent_limit) or the loud
	// arm the headline qualifier fires on (did_not_run). Builder.AddPartiality stamps it
	// from Reason when a producer leaves it unset, so every note in a built Report
	// carries one. Additive and omitted when empty (§11): a reader predating it sees the
	// note exactly as before, and a reader that meets an empty or unrecognized value
	// resolves it through EffectiveClass, which defaults to the LOUD arm.
	//
	// It is disclosure volume, never a verdict — no finding, count or grounds depends
	// on it.
	Class PartialityClass `json:"class,omitempty"`
	// Advisories are advisory ids WITHHELD from Report.Advisories under this limit —
	// evaluated, no verdict established, and therefore absent from advisories[] entirely.
	// Sorted, de-duplicated.
	//
	// It is NOT where this analyzer names an advisory it did not assess — that is Detail
	// above, which carries identities under a limit whose advisories were never withheld
	// in the v1 sense (they were never in advisories[] to begin with). The two do not
	// overlap: Advisories is the upgrade path for a stored v1 document, Detail is the
	// live disclosure.
	//
	// EMPTY IS THE SHAPE THIS ANALYZER NOW PRODUCES. Withholding was the v1 emission for
	// an advisory the scan could not adjudicate, because v1's verdict set had no cell for
	// it; v2 has VerdictUndetermined, so such an advisory is a first-class row and the
	// limit above it names only the limit. Upgrade converts a stored v1 list into rows and
	// empties it.
	//
	// An empty list means the limit narrowed coverage but suppressed no verdict — and a
	// reader must not read it as "nothing was withheld under any limit", only as "nothing
	// was withheld under THIS one". The field is retained rather than removed because a
	// future withholding shape may need it again, and because a stored v1 document still
	// carries ids here until it is upgraded.
	Advisories []string `json:"advisories,omitempty"`
}

// Reason codes for the two shapes of "the advisory applies to the Go toolchain and we could not
// adjudicate it". They are values of ONE open vocabulary read at two scopes:
// PartialityNote.Reason (the limit, scan-level) and AdvisoryFinding.UndeterminedReason (the
// advisories that limit hit, per-finding). The same run emits both, naming the same fact once
// each way; they must never diverge.
const (
	// ReasonGoToolchainUnresolved: no subject Go toolchain fact could be resolved at all — no
	// subject declaration, no CI observation, and no go.mod version directive. Nothing was
	// established about the version the subject builds with, so neither the version axis nor
	// stdlib reachability says anything about it.
	ReasonGoToolchainUnresolved = "go_toolchain_unresolved"
	// ReasonUnspecifiedLimit is produced only by Upgrade, and only over a document this analyzer
	// did not write: a tegron.report.v1 note that withheld advisories under a limit whose own
	// `reason` was empty. It says exactly that — the limit named itself nothing — and no more.
	//
	// It exists because the two honest-looking alternatives are both worse. Dropping the ids
	// would silently un-name the advisories, which is the failure `undetermined` exists to end.
	// Copying the empty reason onto the rows would produce a report that fails its own Validate
	// (an unexplained non-verdict is silent suppression), so the document would decode and then
	// blow up somewhere downstream instead of at the boundary. A synthesized code keeps the
	// advisory nameable AND keeps the reason honest: "we do not know which limit" is a different
	// fact from either go_toolchain_* code, and it is labelled as a different fact.
	//
	// Builder.AddPartiality drops a note with an empty Reason, so this cannot arise from a
	// document this analyzer produced.
	ReasonUnspecifiedLimit = "unspecified_limit"
	// ReasonGoToolchainNotScanned: a subject toolchain fact EXISTS, and the version axis
	// consumed it without reaching a disqualification — but stdlib reachability was not run
	// against that toolchain, so the empty path set is a fact about the scanner's Go, not the
	// subject's. An absent symbol under a different toolchain is not evidence the symbol is
	// absent under the subject's.
	ReasonGoToolchainNotScanned = "go_toolchain_not_scanned"
	// ReasonAnalysisDidNotRun is the general form of the same fact, for every ecosystem: a step
	// the refutation would have to rest on did not happen on THIS run, so the absence of a
	// reachable path is a fact about the analysis rather than about the codebase.
	//
	// It is the code an analyzer that cannot yet resolve a dependency's versions or symbols lands
	// its findings on. A `not_exploitable` basis asserts that no path in what this codebase builds
	// reaches the vulnerable symbol; an analysis that never searched has
	// asserted it on evidence it does not have, which is a false negative — the one outcome this
	// scanner may never produce.
	//
	// The two go_toolchain_* codes above are the SPECIFIC cases of this and keep their own names:
	// they say which fact was missing, and a reader can act on them. This one says only that a
	// step did not run, and the scan-level PartialityNote list names which step.
	ReasonAnalysisDidNotRun = "analysis_did_not_run"
	// ReasonPackageVersionUnresolved: the advisory reached the verdict without a package whose
	// installed version was resolved, so nothing establishes which code the build carries.
	ReasonPackageVersionUnresolved = "package_version_unresolved"
	// ReasonAdvisorySymbolAbsent: the advisory names no vulnerable symbol and no analyzer refuted
	// the package as a whole, so there was nothing to search for.
	ReasonAdvisorySymbolAbsent = "advisory_symbol_absent"
	// ReasonVulnerableSymbolUnresolved: the advisory names vulnerable symbols, but not every one was
	// located inside the affected package and searched by the reachability analysis, and no
	// analyzer refuted the package as a whole.
	ReasonVulnerableSymbolUnresolved = "vulnerable_symbol_unresolved"
	// ReasonAdvisorySymbolsUnvetted: every advisory symbol was located inside the affected package
	// and searched, and none was reached, but the advisory's symbol set is not one an absence may
	// rest on: its symbol_provenance is not osv-declared or curated (diff-lexed, cna-declared,
	// unrecognized, or untagged outside a first-party record), so the vulnerable code may lie in a
	// function the set does not list.
	ReasonAdvisorySymbolsUnvetted = "advisory_symbols_unvetted"
	// ReasonAdvisoryUnknownToAnalyzer: the analyzer that searches for this advisory's symbols
	// reported nothing about the advisory at all. It may not know the advisory, or may never have
	// analyzed the affected module. Its silence is not a search that came back empty.
	ReasonAdvisoryUnknownToAnalyzer = "advisory_unknown_to_analyzer"
	// ReasonRefutationWithheld: the analysis ran and found no path to the advisory's vulnerable
	// code, but code that search did not cover may reach it (files the build left out, methods it
	// never started from, importers of a library package, calls made through reflection), so the
	// refutation was withheld. The scan-level PartialityNote list names which.
	ReasonRefutationWithheld = "refutation_withheld"
	// ReasonAdvisoryRangeAbsent: a path reaches the advisory's vulnerable code, but the advisory
	// records no affected version range the version axis can bound, so it was admitted at every installed
	// version and nothing establishes that this version is affected. The path stays on the finding
	// as evidence.
	ReasonAdvisoryRangeAbsent = "advisory_range_absent"
	// ReasonBuildContextNotCompared: the PR-inherit diff compared the dependency set but NOT the
	// build context (detected project/language/target/runtime/project root). §8 checkbox 12's
	// build-context clause is unimplemented — PLAN-004's WorkspacePlan exists at checkout time but
	// is not persisted into report.SBOM, the object the diff compares, so a change confined to the
	// build context is not detected and could inherit a stale Report silently. Carried as an
	// inherent_limit (quiet methodology arm) on the inherited fast path so the gap is disclosed
	// without asserting anything about this run's verdicts. A follow-on that persists build context
	// into the compared state closes it.
	ReasonBuildContextNotCompared = "build_context_not_compared"
	// ReasonScanCutShort: the scan stopped before this advisory's assessment finished, at its time
	// limit or because the runner stopped it. Nothing the advisory's analysis produced is kept, so
	// the row says nothing about the codebase. As a scan-level note it names the cause, how many
	// advisories were not assessed, and how to give the scan more time.
	ReasonScanCutShort = "scan_cut_short"
)

// BaselineRef points at a prior baseline Report this Report inherits from or is
// diffed against (PR-adjacent inherit / fast-path). It is a reference, never an
// embedded Report — the baseline lives in the StateStore and is fetched by ref.
type BaselineRef struct {
	// CommitSHA is the commit of the baseline Report (the prior main-line scan).
	CommitSHA string `json:"commit_sha"`
	// StateRef is the git ref where the baseline Report tree lives (default
	// "refs/assay/state"; a platform fallback may override the namespace).
	StateRef string `json:"state_ref,omitempty"`
	// BlobSHA is the content-addressed git blob SHA of the baseline report.json, when
	// known. Lets a reader fetch exactly the baseline bytes that were inherited.
	BlobSHA string `json:"blob_sha,omitempty"`
}

// Report is the neutral scan result emitted by one deterministic Assess pass. It
// is the canonical `report.json` the StateStore persists and the source of truth
// the OpenVEX / SARIF / inlined-HTML projectors render. It round-trips losslessly
// to JSON.
//
// A Report is an output projection, not a lifecycle entity: it deliberately does
// NOT carry Case/Assessment state, which is Service-side and paid. It carries only
// the SBOM, the evaluated advisories with deterministic verdicts, provenance, and
// an optional inherited-baseline pointer.
type Report struct {
	// SchemaVersion is the schema identifier; equals the SchemaVersion constant for a
	// freshly built Report. Readers check it before interpreting the rest.
	SchemaVersion string `json:"schema_version"`
	// Subject identifies what was scanned (repo + resolved commit). Neutral coordinates;
	// no account/tenant identity.
	Subject Subject `json:"subject"`
	// SBOM is the resolved dependency set (the CVE-watch input).
	SBOM SBOM `json:"sbom"`
	// Advisories are the advisories evaluated this pass, each with its deterministic
	// verdict. Order is stable for content addressing.
	Advisories []AdvisoryFinding `json:"advisories"`
	// Partiality discloses what this pass could NOT establish (see PartialityNote).
	// Empty on a fully-resolved scan — silence is the clean-scan signal, so a reader
	// may treat a non-empty list as "the verdicts above cover less than the whole
	// codebase". Additive and omitted when empty (§11 of the contract), so a reader
	// that predates the field is unaffected.
	Partiality []PartialityNote `json:"partiality,omitempty"`
	// Provenance records SHA / analyzer version / advisory cursor / timestamp.
	Provenance Provenance `json:"provenance"`
	// Baseline points at the prior baseline Report this one inherits from / diffs
	// against. Nil for a fresh baseline run.
	Baseline *BaselineRef `json:"baseline,omitempty"`
	// BuildGraph records where a JVM scan's dependency graph came from and, when it could not be
	// had, the typed cause. Set on every Java and Kotlin scan; nil for every other language.
	BuildGraph *BuildGraph `json:"build_graph,omitempty"`
	// LibraryEntrypoints are the sets of the build's packages the scan treated as callable by code
	// outside the build, one per ecosystem, and whether each was inferred or declared. A lane
	// resolves one only to judge a refutation such a caller may contradict. Sorted by ecosystem.
	LibraryEntrypoints []plugin.ResolvedLibraryEntrypoints `json:"library_entrypoints,omitempty"`
	// DependencyCode records whether a JS scan read its dependencies' code and, when a fetch
	// failed and the scan fell back to reading none, the cause. Set on every JavaScript scan;
	// nil for every other language.
	DependencyCode *DependencyCode `json:"dependency_code,omitempty"`
}

// AddPartiality records notes on a built Report, classified, de-duplicated and sorted as
// Builder.AddPartiality and Build would have them.
func (r *Report) AddPartiality(notes ...PartialityNote) {
	b := Builder{partiality: append([]PartialityNote(nil), r.Partiality...)}
	b.AddPartiality(notes...)
	r.Partiality = dedupPartiality(b.partiality)
}

// Dependency code sources.
const (
	// DependencyCodeSourceFetch is a scan that fetches each lock-pinned package and reads its
	// integrity-verified code.
	DependencyCodeSourceFetch = "fetch"
	// DependencyCodeSourceOffline is a scan that reads only an operator-seeded dependency cache.
	DependencyCodeSourceOffline = "offline"
	// DependencyCodeSourceOff is a scan the caller ran with dependency code switched off.
	DependencyCodeSourceOff = "off"
)

// PartialReasonDependencyCodeUnavailable is the scan-level reason a JS scan carries when a fetch
// failed and it read no dependency code. It is plugin.PartialReasonToolFailure narrowed the way
// the JVM lane narrows it to build_graph_absent: the step that did not run is the dependency
// code read, whatever stopped it (the registry, a credential, the deadline).
const PartialReasonDependencyCodeUnavailable = plugin.PartialReasonToolFailure + ":dependency_code_unavailable"

// DependencyCode is the provenance of the dependency code a JS scan read.
type DependencyCode struct {
	// Source is one of the DependencyCodeSource constants.
	Source string `json:"source"`
	// Cause is why a fetch-mode scan read no dependency code. Nil when it read what it fetched,
	// and for "offline" and "off".
	Cause *DependencyCodeCause `json:"cause,omitempty"`
}

// DependencyCodeCause is why a fetch fell back to reading no dependency code.
type DependencyCodeCause struct {
	// Kind is inventory_failed, or the reason the first failed package, in PURL order, was not
	// fetched: registry_unavailable (throttled, server error, timeout or dropped connection),
	// registry_unreachable (name resolution or connect failure), not_served (the registry
	// answered that it does not serve the tarball), fetch_failed, policy_refused, cancelled,
	// integrity_mismatch or npmrc_malformed.
	Kind string `json:"kind"`
	// Detail names that package and, where there is one, the policy or fetch-failure code or the
	// npm configuration file and line. It never carries a URL, a host or a credential.
	Detail string `json:"detail,omitempty"`
}

// Build graph sources.
const (
	// BuildGraphSourceTool is a graph the scan resolved by running the repository's own Maven or
	// Gradle.
	BuildGraphSourceTool = "build_tool"
	// BuildGraphSourceFile is a graph the caller resolved ahead of the scan and handed in.
	BuildGraphSourceFile = "build_tool_file"
	// BuildGraphSourceOff is a scan the caller ran with the build graph switched off: it has no
	// JVM dependency inventory, and says so.
	BuildGraphSourceOff = "off"
)

// BuildGraph is the provenance of a JVM scan's dependency graph.
type BuildGraph struct {
	// Source is one of the BuildGraphSource constants.
	Source string `json:"source"`
	// Cause is why the graph could not be had. Nil when the scan read a graph, and for "off".
	// A scan with a Cause exits non-zero once its Report is published.
	Cause *BuildGraphCause `json:"cause,omitempty"`
}

// BuildGraphCause is a typed build graph failure.
type BuildGraphCause struct {
	// Kind is one of toolchain_absent, jdk_mismatch, credentials, tool_failed or
	// graph_rejected.
	Kind string `json:"kind"`
	// Detail narrows Kind: the wanted and found JDK (jdk_mismatch, as want/have), the repository
	// (credentials), the failed step (tool_failed) or the failed check (graph_rejected).
	Detail string `json:"detail,omitempty"`
}

// Subject identifies the scanned codebase by neutral coordinates. It carries no
// account or tenant identity — the OSS tool runs in the customer's own tenancy.
type Subject struct {
	// Repo is the repository locator (URL or path) that was scanned.
	Repo string `json:"repo"`
	// Revision is the requested revision (branch / tag / ref) the scan targeted.
	Revision string `json:"revision,omitempty"`
	// ResolvedCommit is the concrete commit the scan was pinned to.
	ResolvedCommit string `json:"resolved_commit"`
}

// Validate enforces the Report invariants and returns the first violation found.
// It is the structural guard for inv. 5 and basic completeness:
//
//   - SchemaVersion must be set (a Report with no schema version is uninterpretable).
//   - Every AdvisoryFinding.Verdict must satisfy Verdict.Valid — no `exploitable` /
//     `reasoned_*` may appear in an OSS Report.
//   - A reachable_candidate must NOT carry a not-exploitability Basis (a candidate
//     has no refutation grounds); a disqualified / not_exploitable finding SHOULD
//     carry grounds (Basis or Detail) but an empty grounds is tolerated rather than
//     rejected, so a minimally-populated Report still validates.
//   - An undetermined finding must NOT carry a Basis (it has no grounds at all) and
//     MUST carry an UndeterminedReason; no other verdict may carry one.
//   - The reachability basis (vulnerable_symbol_unreachable) is valid only on a
//     not_exploitable: a disqualification rests on the version or symbol axis, never on
//     a path search.
func (r Report) Validate() error {
	if r.SchemaVersion == "" {
		return fmt.Errorf("report: SchemaVersion is required")
	}
	for i := range r.Advisories {
		f := r.Advisories[i]
		if !f.Verdict.Valid() {
			return fmt.Errorf("report: advisory %q has non-deterministic verdict %q (inv. 5: OSS may emit only disqualified / not_exploitable / reachable_candidate / undetermined)",
				f.Advisory.ID, f.Verdict)
		}
		if f.Verdict == VerdictReachableCandidate && f.Evidence.Basis != verdict.BasisNone {
			return fmt.Errorf("report: advisory %q is a reachable_candidate but carries a not-exploitability basis %q (a candidate has no refutation grounds)",
				f.Advisory.ID, f.Evidence.Basis)
		}
		// The undetermined/basis invariant mirrors the candidate/basis one above and is the
		// structural reason the new verdict cannot decay into a refutation: a basis is what
		// makes not_exploitable a CLAIM, so an undetermined finding carrying one would be the
		// original defect wearing a new label.
		if f.Verdict == VerdictUndetermined && f.Evidence.Basis != verdict.BasisNone {
			return fmt.Errorf("report: advisory %q is undetermined but carries a not-exploitability basis %q (an undetermined finding establishes nothing, so it has no grounds)",
				f.Advisory.ID, f.Evidence.Basis)
		}
		if f.Evidence.Basis == verdict.BasisSymbolUnreachable && f.Verdict != VerdictNotExploitable {
			return fmt.Errorf("report: advisory %q carries basis %q but verdict is %q (a reachability refutation grounds only a not_exploitable)",
				f.Advisory.ID, f.Evidence.Basis, f.Verdict)
		}
		if f.Verdict == VerdictUndetermined && f.UndeterminedReason == "" {
			return fmt.Errorf("report: advisory %q is undetermined but carries no undetermined_reason (an unexplained non-verdict is silent suppression)",
				f.Advisory.ID)
		}
		if len(f.Evidence.AdvisoryBounds) > 0 && f.UndeterminedReason != ReasonAdvisoryRangeAbsent {
			return fmt.Errorf("report: advisory %q carries advisory_bounds but its undetermined_reason is %q (only a range-absent finding records partial bounds)",
				f.Advisory.ID, f.UndeterminedReason)
		}
		if f.UndeterminedReason != "" && f.Verdict != VerdictUndetermined {
			return fmt.Errorf("report: advisory %q carries undetermined_reason %q but verdict is %q (a reason explains only an absent verdict)",
				f.Advisory.ID, f.UndeterminedReason, f.Verdict)
		}
		if !f.Evidence.Grade.Valid() {
			return fmt.Errorf("report: advisory %q has invalid reachability grade %q", f.Advisory.ID, f.Evidence.Grade)
		}
		if f.Evidence.Grade != "" && f.Verdict != VerdictReachableCandidate {
			return fmt.Errorf("report: advisory %q carries reachability grade %q but verdict is %q (a grade refines only a reachable_candidate, never asserts exploitability)",
				f.Advisory.ID, f.Evidence.Grade, f.Verdict)
		}
		if !f.Evidence.SymbolConfidence.Valid() {
			return fmt.Errorf("report: advisory %q has invalid symbol confidence %q", f.Advisory.ID, f.Evidence.SymbolConfidence)
		}
		// Structural honest-absent gate (inv.5, RFC §4.1): a derivation-confidence signal may
		// qualify ONLY a reachable_candidate. Forbidding it on every other verdict is what makes
		// provenance-as-confidence incapable of ever annotating — let alone driving — a
		// disqualification, a not_exploitable, or an undetermined finding.
		if f.Evidence.SymbolConfidence != "" && f.Verdict != VerdictReachableCandidate {
			return fmt.Errorf("report: advisory %q carries symbol confidence %q but verdict is %q (a derivation-confidence signal qualifies only a reachable_candidate, never an admission or refutation)",
				f.Advisory.ID, f.Evidence.SymbolConfidence, f.Verdict)
		}
		// A declaration only ever lets a refutation stand, so only a not_exploitable rests on one.
		if len(f.Evidence.Assumptions) > 0 && f.Verdict != VerdictNotExploitable {
			return fmt.Errorf("report: advisory %q carries assumptions but verdict is %q (an assumption qualifies only a not_exploitable)",
				f.Advisory.ID, f.Verdict)
		}
		// Structural honest-absent gate (inv.5, RFC §4.2): the exploit-precondition qualifier may
		// describe ONLY a reachable_candidate. Forbidding it on every other verdict is what makes a
		// declared precondition incapable of ever annotating — let alone refuting — a
		// disqualification, a not_exploitable, or an undetermined finding.
		if f.Evidence.ExploitPreconditions != nil && f.Verdict != VerdictReachableCandidate {
			return fmt.Errorf("report: advisory %q carries exploit preconditions but verdict is %q (a precondition qualifier describes only a reachable_candidate, never an admission or refutation)",
				f.Advisory.ID, f.Verdict)
		}
		// Conditionality is never asserted from emptiness: a non-nil block that declares no
		// precondition would be a claim ("this candidate is conditional") resting on nothing.
		if f.Evidence.ExploitPreconditions != nil && f.Evidence.ExploitPreconditions.Empty() {
			return fmt.Errorf("report: advisory %q carries a non-nil but empty exploit-precondition block (absent must resolve to no annotation, never an empty conditionality claim)",
				f.Advisory.ID)
		}
		// Structural honest-absent gate (inv.5, RFC §4.2, B-guardsuff): a declared-sufficiency
		// annotation may qualify ONLY a reachable_candidate — it annotates that candidate's on-path
		// guards. Forbidding it on every other verdict is what makes guard_sufficiency incapable of
		// ever annotating — let alone driving — a disqualification, a not_exploitable, or an
		// undetermined finding. This is the structural wall against the presence→sufficiency
		// laundering a guard-driven PoNE verdict would be.
		if len(f.Evidence.GuardSufficiency) > 0 && f.Verdict != VerdictReachableCandidate {
			return fmt.Errorf("report: advisory %q carries guard-sufficiency annotations but verdict is %q (a declared-sufficiency label describes only a reachable_candidate, never an admission or refutation)",
				f.Advisory.ID, f.Verdict)
		}
		// Each note must carry a real guard and a recognized label: an empty symbol or an
		// unrecognized/empty sufficiency label is a malformed annotation, never a no-signal state
		// (absence is expressed by omitting the note). This mirrors the non-nil-but-empty rejection
		// above — an annotation resting on nothing is a claim resting on nothing.
		for _, n := range f.Evidence.GuardSufficiency {
			if n.Symbol == "" || !n.Sufficiency.Valid() {
				return fmt.Errorf("report: advisory %q carries a malformed guard-sufficiency note (symbol %q, sufficiency %q) — a note must name an on-path guard and a recognized label",
					f.Advisory.ID, n.Symbol, n.Sufficiency)
			}
		}
		// Every priority value carries its own stamp (see Priority). An unstamped value would
		// read as current when it is a capture of unknown age.
		if f.Priority != nil {
			if err := f.Priority.validate(); err != nil {
				return fmt.Errorf("report: advisory %q carries %v", f.Advisory.ID, err)
			}
		}
	}
	// SBOM relationships are referential: every edge endpoint must name a package present
	// in this SBOM. A dangling edge is a resolver defect — it would let a PR-diff or a
	// projection dereference a parent/child that is not in the package set — so it is a
	// structural violation, not a tolerated partial. (An SBOM with zero relationships is
	// valid: a lane may express no edges yet.)
	if len(r.SBOM.Relationships) > 0 {
		present := make(map[string]struct{}, len(r.SBOM.Packages))
		for i := range r.SBOM.Packages {
			present[r.SBOM.Packages[i].Key()] = struct{}{}
		}
		for _, rel := range r.SBOM.Relationships {
			if _, ok := present[rel.Parent]; !ok {
				return fmt.Errorf("report: SBOM relationship parent %q references no package in the SBOM (dangling edge)", rel.Parent)
			}
			if _, ok := present[rel.Child]; !ok {
				return fmt.Errorf("report: SBOM relationship child %q references no package in the SBOM (dangling edge)", rel.Child)
			}
		}
	}
	return nil
}
