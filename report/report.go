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
	"fmt"
	"time"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// SchemaVersion is the versioned identifier of the Report schema. It is written
// into every Report so future readers can detect and migrate older documents.
// Bump it on any breaking change to the field set or semantics.
const SchemaVersion = "tegron.report.v2"

// SchemaVersionV1 is the predecessor schema. Documents carrying it are still read
// (a StateStore written before the bump holds one) and are upgraded on read by
// Upgrade; nothing produces it any more.
const SchemaVersionV1 = "tegron.report.v1"

// Verdict is the per-advisory deterministic verdict an OSS scan may assign. It is
// the constrained subset of the full (direction × strength) verdict grammar that
// invariant 5 permits the runner to emit. The full grammar lives in package
// verdict; the OSS Report deliberately exposes only these four values so a
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
}

// SBOM is the resolved dependency set of the scanned codebase. It is the input to
// CVE-watch (OSV.dev querybatch over Packages) and is content-addressed in state:
// an unchanged SBOM serializes byte-identically so the StateStore writes zero new
// git objects.
type SBOM struct {
	// Packages is the resolved dependency set. Order is stable (callers sort before
	// constructing) so the serialized form is deterministic for content addressing.
	Packages []Package `json:"packages"`
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

// EvidenceSummary is a compact, neutral grounds statement for one advisory's
// verdict — what made it disqualified / not-reachable / a candidate. It carries
// the structured basis plus a short human-readable line; it does NOT embed full
// evidence chains (those are Service-tier artifacts). This keeps the Report a thin
// projection safe to store and render.
type EvidenceSummary struct {
	// Basis is the structured grounds for a not_exploitable / disqualified verdict,
	// reusing the OSS verdict grammar (verdict.NonExploitableBasis):
	// "version_not_in_affected_range" or "vulnerable_symbol_absent". Empty for a
	// reachable_candidate (which has no refutation basis — its grounds are the path) and
	// for an undetermined finding (which has no grounds at all).
	Basis verdict.NonExploitableBasis `json:"basis,omitempty"`
	// Detail is a one-line, neutral, human-readable summary of the grounds (e.g.
	// "resolved v0.3.7 is below the first affected version v0.3.8" or "a path from an
	// HTTP handler reaches the advisory symbol"). Neutral phrasing only — never
	// asserts exploitability.
	Detail string `json:"detail,omitempty"`
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
}

// Priority is the deterministic, offline prioritization signal attached to a
// finding from the pinned EPSS/KEV snapshot (package intel). It is exploitation-
// LIKELIHOOD context from public feeds — NEVER an exploitability verdict for this
// codebase (inv. 5). EPSS is FIRST.org's probability the CVE is exploited in the
// wild; KEVListed means CISA records active exploitation of the CVE somewhere.
// Neither asserts the finding is exploitable here — they only rank attention.
type Priority struct {
	// EPSSScore is FIRST.org's 0..1 probability the CVE is exploited in the wild.
	EPSSScore float64 `json:"epss_score"`
	// EPSSPercentile is the CVE's percentile rank among all scored CVEs (0..1).
	EPSSPercentile float64 `json:"epss_percentile"`
	// KEVListed is true when the CVE is in CISA's Known Exploited Vulnerabilities catalog.
	KEVListed bool `json:"kev_listed"`
	// KEVDateAdded is the date CISA added the CVE to KEV (YYYY-MM-DD); set iff KEVListed.
	KEVDateAdded string `json:"kev_date_added,omitempty"`
	// Snapshot is the pinned intel snapshot date the score/flag came from — provenance
	// for reproducibility (a later snapshot may rank the same finding differently).
	Snapshot string `json:"snapshot,omitempty"`
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
	// (inv. 5): one of disqualified / not_exploitable / reachable_candidate / undetermined.
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
	// Priority is the offline EPSS/KEV prioritization signal for this advisory, from
	// the pinned intel snapshot. Nil when no CVE record matched. Exploitation-
	// likelihood context only — never an exploitability claim for this codebase.
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
	// was used. It is deliberately NOT the number of ids evaluated: a corpus is a fact
	// lookup, not a work list, and conflating the two is what made "72 records" read as
	// "72 CVEs evaluated".
	CorpusRecords int `json:"corpus_records,omitempty"`
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
	// its findings on. `not_exploitable / vulnerable_symbol_absent` asserts that the vulnerable
	// symbol is not present in what this codebase builds; an analysis that never searched has
	// asserted it on evidence it does not have, which is a false negative — the one outcome this
	// scanner may never produce.
	//
	// The two go_toolchain_* codes above are the SPECIFIC cases of this and keep their own names:
	// they say which fact was missing, and a reader can act on them. This one says only that a
	// step did not run, and the scan-level PartialityNote list names which step.
	ReasonAnalysisDidNotRun = "analysis_did_not_run"
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
		if f.Verdict == VerdictUndetermined && f.UndeterminedReason == "" {
			return fmt.Errorf("report: advisory %q is undetermined but carries no undetermined_reason (an unexplained non-verdict is silent suppression)",
				f.Advisory.ID)
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
	}
	return nil
}
