// ferralon-assay/pipeline/stages.go
//
// The deterministic Assess stages S1–S6 (advisory_intake, codebase_inventory,
// disqualification_discovery, symbol_mapping, reachability_ingress, exposure_footprint) and the
// stage-assembly seam AssessStages. The Prove stages S7–S10 (live_confirmation,
// sandbox_observability, adversarial_review, verdict_emission) and the typed With… options that
// inject the model / sandbox / dispatch / recall seams live Service-side in the Service pipeline
// package, which composes its Prove stages onto AssessStages.
//
// Cross-boundary seam: a handful of free helpers and frozen artifact shapes are exported
// (PutArtifact, InventoryBuildDir, HarnessArtifact, DisqualResult + reason constants, AdvisoryTable,
// AdvisoryFacts) because the Prove stages build on the same artifact contracts. They are neutral
// plumbing, not proof.
package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/vulnclass"
)

// AssessConfig holds the free-stage seams an AssessStages caller may inject. It is the OSS half of
// the former stageConfig; the Prove options (model/sandbox/dispatch/recall/fuzz/critic) live in the
// Service prove package, which builds its own stages and appends them after AssessStages.
type AssessConfig struct {
	Plugin   plugin.LanguagePlugin
	Checkout checkout.Checkout
	Source   AdvisorySource
	// SubjectGoVersion/CIGoVersion carry the two candidate subject-toolchain sources into
	// codebase_inventory (ADR 0014 tiers 1–2), and TrustCIGoVersion is the caller's assertion that
	// the second describes the subject. See WithSubjectToolchain.
	SubjectGoVersion string
	CIGoVersion      string
	TrustCIGoVersion bool
	// SubjectToolchainReachability opts reachability_ingress into running the Go analysis under the
	// SUBJECT's toolchain (ADR 0014 M4). Off by default. See WithSubjectToolchainReachability.
	SubjectToolchainReachability bool
}

// AssessOption customizes the free-stage set built by AssessStages.
type AssessOption func(*AssessConfig)

// WithPlugin injects a LanguagePlugin into the symbol_mapping and reachability_ingress stages (and
// the codebase_inventory manifest/version reads). When absent, those stages keep their skeleton stub
// behavior (no real analysis) — so existing tests and the default path are unchanged.
func WithPlugin(p plugin.LanguagePlugin) AssessOption {
	return func(c *AssessConfig) { c.Plugin = p }
}

// WithCheckout injects a Checkout into the codebase_inventory stage. When absent, that stage uses a
// hermetic FakeCheckout (no network, no git) — so the default path stays hermetic.
func WithCheckout(co checkout.Checkout) AssessOption {
	return func(c *AssessConfig) { c.Checkout = co }
}

// WithAdvisorySource injects the AdvisorySource the S1 stages (advisory_intake, codebase_inventory)
// read advisory facts through. When absent (nil), those stages fall back to defaultAdvisorySource() —
// the process-wide default (tableSource unless SetDefaultAdvisorySource installed a corpus) — so the
// default path is byte-identical to today.
func WithAdvisorySource(src AdvisorySource) AssessOption {
	return func(c *AssessConfig) { c.Source = src }
}

// WithSubjectToolchain injects the two candidate EXACT sources of the subject's Go toolchain that
// the pipeline cannot read off the tree (ADR 0014 §2.2 tiers 1–2): declared is the subject's own
// statement of the toolchain it builds with, observed is `go env GOVERSION` sampled on the CI runner
// BEFORE the Action installed the scanner's own Go. Either may be empty; absent both, the fact falls
// back to the subject's go.mod floors and then to unresolved, so every non-Action caller is
// unchanged.
//
// trustObserved is a required third argument rather than a separate option because the observation
// alone does not carry its own provenance. `go env GOVERSION` on a runner answers "what Go is
// installed here", which is a statement about the SUBJECT only in a same-job topology where the
// caller provisioned its build toolchain before invoking the scan; in a dedicated scan job the same
// command returns the hosted runner image's preinstalled Go, unrelated to a build pinned elsewhere.
// Nothing observable distinguishes the two, so only the caller can assert it — and until they do,
// observed does not participate in resolution at all (not even as a floor: an unrelated Go is not a
// lower bound on the subject's toolchain).
//
// Never pass the SCANNER's toolchain here. That value is a property of the analysis environment, and
// mistaking it for a statement about the subject is precisely the defect ADR 0014 exists to close.
func WithSubjectToolchain(declared, observed string, trustObserved bool) AssessOption {
	return func(c *AssessConfig) {
		c.SubjectGoVersion, c.CIGoVersion, c.TrustCIGoVersion = declared, observed, trustObserved
	}
}

// WithSubjectToolchainReachability opts the Go reachability analysis into running under the
// SUBJECT's Go toolchain instead of the analyzer's, when — and only when — the subject's toolchain
// resolved to an EXACT bound (ADR 0014 M4). It is OFF by default and ships that way for one release
// (ruling 3), because it is the step that makes findings appear on scans that are green today: a
// subject on an older toolchain has stdlib symbols the analyzer's newer toolchain does not flag.
//
// What the option buys when on is not a louder scan, it is a licensed one. With it off, an empty
// path set for a stdlib advisory is evidence about the ANALYZER's Go, so no verdict may rest on it
// and the advisory is withheld and disclosed (M2). With it on and the subject's toolchain actually
// executed, the same empty path set is evidence about the SUBJECT, and the ordinary verdict rules
// apply. The option alone is never enough — a non-exact bound, or a toolchain that could not be
// fetched, still yields the disclosed partial (see ReachabilityResult.ScanToolchain).
func WithSubjectToolchainReachability(enabled bool) AssessOption {
	return func(c *AssessConfig) { c.SubjectToolchainReachability = enabled }
}

// AssessStages returns the deterministic Assess stages S1–S6 in pipeline order, applying any
// options. The Service composes the full S1–S10 pipeline as append(AssessStages(opts...),
// prove.ProveStages(...)...).
func AssessStages(opts ...AssessOption) []Stage {
	cfg := &AssessConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return []Stage{
		advisoryIntake{src: cfg.Source},
		codebaseInventory{checkout: cfg.Checkout, plugin: cfg.Plugin, src: cfg.Source, subjectGoVersion: cfg.SubjectGoVersion, ciGoVersion: cfg.CIGoVersion, trustCIGoVersion: cfg.TrustCIGoVersion},
		maliciousPresence{},
		disqualificationDiscovery{},
		symbolMapping{plugin: cfg.Plugin},
		reachabilityIngress{plugin: cfg.Plugin, subjectToolchain: cfg.SubjectToolchainReachability},
		exposureFootprintStage{},
	}
}

// SBOMStages returns ONLY the SBOM-producing stages — S1 advisory_intake + S2
// codebase_inventory — in pipeline order, applying any options. It is the cheap
// dependency-resolution slice the PR-inherit head-SBOM resolver runs (no S3–S6): S1
// normalizes the advisory module/PURL, S2 resolves the on-disk version, and the
// resolver reads back the package from those two artifacts.
func SBOMStages(opts ...AssessOption) []Stage {
	cfg := &AssessConfig{}
	for _, o := range opts {
		o(cfg)
	}
	return []Stage{
		advisoryIntake{src: cfg.Source},
		codebaseInventory{checkout: cfg.Checkout, plugin: cfg.Plugin, src: cfg.Source, subjectGoVersion: cfg.SubjectGoVersion, ciGoVersion: cfg.CIGoVersion, trustCIGoVersion: cfg.TrustCIGoVersion},
	}
}

// The individual free stage constructors below let callers (notably the Service prove-side
// integration tests that span the boundary) build and run a single S1–S6 stage in isolation.
// The design sanctions OSS exposing "the Stage interface, the S1–S6 stages, and a stage-assembly
// seam"; these are that exposure.

// NewAdvisoryIntake returns the S1 advisory_intake stage.
func NewAdvisoryIntake() Stage { return advisoryIntake{} }

// NewCodebaseInventory returns the S2 codebase_inventory stage with the given seams (nil ok).
func NewCodebaseInventory(co checkout.Checkout, p plugin.LanguagePlugin) Stage {
	return codebaseInventory{checkout: co, plugin: p}
}

// NewDisqualificationDiscovery returns the S3 disqualification_discovery stage.
func NewDisqualificationDiscovery() Stage { return disqualificationDiscovery{} }

// NewSymbolMapping returns the S4 symbol_mapping stage with the given plugin (nil ok).
func NewSymbolMapping(p plugin.LanguagePlugin) Stage { return symbolMapping{plugin: p} }

// NewReachabilityIngress returns the S5 reachability_ingress stage with the given plugin (nil ok).
func NewReachabilityIngress(p plugin.LanguagePlugin) Stage { return reachabilityIngress{plugin: p} }

// NewExposureFootprint returns the S6 exposure_footprint stage.
func NewExposureFootprint() Stage { return exposureFootprintStage{} }

// PutArtifact marshals v to JSON and Puts an artifact of the given type, joined to the assessment
// and attributed to the producing stage. It returns the stored artifact's Ref. Exported so the
// Service Prove stages write artifacts through the same contract.
func PutArtifact(store artifact.Store, c *assessment.Assessment, producedBy string, t artifact.Type, descriptor string, v any) (artifact.Ref, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return artifact.Ref{}, err
	}
	return store.Put(&artifact.Artifact{
		AssessmentID: c.ID,
		Type:         t,
		Descriptor:   descriptor,
		ProducedBy:   producedBy,
		Payload:      payload,
	})
}

// --- Stage 1: advisory_intake -------------------------------------------------

// src is the AdvisorySource this stage reads advisory facts through (the U8a intake seam). A nil
// src falls back to defaultAdvisorySource() — the in-memory AdvisoryTable — so the default path is
// byte-identical to the historical inline AdvisoryTable[id] lookup.
type advisoryIntake struct{ src AdvisorySource }

func (advisoryIntake) Name() string              { return "advisory_intake" }
func (advisoryIntake) Status() assessment.Status { return assessment.StatusInventory }

// AdvisoryFacts are the normalized, pinned facts for one corpus advisory. They are offline,
// osv-verified facts (per the fixtures' rationale), NOT a live OSV fetch. Downstream stages read
// these by name from the normalized-advisory artifact.
type AdvisoryFacts struct {
	// Module is the affected module path (e.g. golang.org/x/text). Empty for stdlib
	// advisories (archive/zip), whose version is the Go toolchain, not a module version —
	// so no module-version disqualification applies and the version-range axis fails open.
	Module string
	// Aliases are the advisory's alternate identifiers (CVE / GHSA ids), exactly as OSV
	// records them. They are the keys the offline EPSS/KEV prioritization snapshot
	// (package intel) is looked up by — EPSS and KEV are CVE-keyed, so a GO-/GHSA-keyed
	// advisory only carries a likelihood signal through its CVE alias. Advisory-only
	// context; aliases NEVER decide a verdict (inv. 5).
	Aliases []string
	// UpperExclusive is the single clean "affects < X" semver bound, or "" when the advisory
	// has no single upper-exclusive range the disqualification predicate can use soundly.
	UpperExclusive string
	// FixedVersion is the first patched release (informational; equals UpperExclusive here).
	FixedVersion string
	// VersionScheme selects the comparator the disqualification axis uses: "" / "gomod" → Go
	// semver (v-prefixed); "maven" → Maven version ordering; "npm" → node-semver ordering
	// (non-v-prefixed, prerelease rules). Set "maven" for Java, "npm" for JS/TS advisories.
	VersionScheme string
	// Coordinate is the dependency identity the plugin's version resolver reads the declared
	// version for ("groupId:artifactId" for Maven, the npm package name for JS). Empty for Go.
	Coordinate string
	// PURL is the package URL the live symbol resolver consumes.
	PURL string
	// Symbols are the advisory's vulnerable symbols the live symbol resolver consumes.
	Symbols []string
	// SymbolProvenance is the corpus's RECORD-SCOPED derivation tag for Symbols — a single scalar
	// per record naming how the whole set was obtained (open set: "osv-declared" | "curated" |
	// "diff-lexed"; "reasoning" reserved). STORE-ONLY (A2): it is decoded and carried, but NO
	// consumer reads it — it feeds no admission, reachability, or refute path this cycle. Absent →
	// "" → UNKNOWN derivation, which is NOT low-confidence and NOT untrusted: a symbol with no
	// provenance tag resolves and is walked exactly as one with it (honest-absent, inv.5). A future
	// provenance-as-confidence consumer is a separate (B) change, gated on review. Carries no verdict.
	//
	// omitempty (like SymbolsTyped, unlike the other facts fields): symbol_provenance is a
	// PUBLISHED/enrichment-corpus tag. The built-in AdvisoryTable floor fixtures are Tegron's own
	// curated entries and carry none, so "" is the permanent state for every floor entry, not a field
	// the corpus fell behind on. Serializing it as ""/present on ~40 fixtures would be misrepresentative
	// noise, and the round-trip guard (TestAdvisoryCorpus_Valid) legitimately does not apply to a tag
	// the floor never populates. When the published feed carries it, a non-empty value round-trips.
	SymbolProvenance string `json:",omitempty"`
	// GuardSymbols are advisory-declared mitigation functions (e.g. a path/symlink
	// validator) whose PRESENCE on the resolved ingress→sink path is reported as
	// candidate-tier evidence. Membership-based and explicit (mirrors the sanitizer
	// allow-list philosophy): a guard's presence is mitigating EVIDENCE, never a
	// verdict (inv.5) — guard presence ≠ guard sufficiency, which only the Prove tier
	// can adjudicate. Empty for advisories with no declared guard.
	GuardSymbols []string
	// CWEs are the advisory's CWE ids (e.g. "CWE-918"). They drive class recognition
	// (vulnclass.ClassifyAdvisory) which shapes live-confirmation framing and selects the proof
	// route. Advisory-only: CWEs NEVER decide a verdict and never touch the proven gate (inv.5).
	CWEs []string
	// Summary is a short free-text advisory summary, the keyword fallback for class recognition
	// when no recognized CWE is present. Advisory-only (inv.5).
	Summary string

	// --- normalized_advisory.v2 additions (Tranche-B contract spine) ---------
	// These fields are ADDITIVE and zero-value-safe: an advisory that declares none
	// leaves them empty, and every downstream consumer treats the zero value as
	// Undetermined / OPEN (SOUNDNESS: unknown is never "not affected", inv.5). The
	// consumers that read them are wired in later slices (U2/U3/U5/U9); this slice
	// adds only the shape.

	// AffectedRanges is the multi-range OSV-shaped affected set, in VersionScheme
	// order. It is the richer successor to the single-string UpperExclusive (kept for
	// back-compat): an advisory may declare disjoint ranges and per-range fix sources
	// (branch-aware backports). Empty ⇒ the version axis falls back to UpperExclusive
	// (or fails open when both are empty).
	AffectedRanges []Range
	// Provenance records where this fact was read from and how far it may be trusted.
	// TrustTier gates refute eligibility: low-trust facts (byo/third_party) MAY narrow
	// toward candidate but MAY NEVER refute — no laundering a false negative through an
	// untrusted source. Zero value ⇒ untrusted ⇒ never refutes.
	Provenance Provenance
	// Lineage names the deterministic known-vulnerable predecessor (IncompleteFixOf)
	// and the completing fix (RefixedBy) for incomplete-patch advisories. Advisory-only
	// framing for the two-trace PoNE predecessor baseline; never decides a verdict.
	Lineage Lineage
	// SinkKind is the RFC-0005 proof-route selector. It carries EITHER a literal
	// vulnclass.Class string (native back-compat) OR Intel's stable sink taxonomy
	// (e.g. "memory_corruption", "resource_exhaustion", "code_execution") — Intel keeps its
	// own vocabulary; classFromSinkKind (advisory_source.go) owns the Intel→vulnclass
	// mapping, fanning "code_execution" out by CWEs. Empty ⇒ route derived from CWE/summary
	// as today; ambiguous/unrecognized ⇒ same fail-open (2026-07-15 sink_kind reconcile).
	SinkKind string
	// TriggerCondition and Prerequisite are advisory-declared preconditions (RFC-0005
	// mechanism fields) framing what must hold for the sink to bite. Advisory-only.
	TriggerCondition string
	Prerequisite     string
	// ConfigKey is the core.config predicate operand — a config key plus the value that
	// makes the codebase unsafe. Zero value ⇒ predicate stays Undetermined (fail open).
	ConfigKey ConfigOperand
	// FeatureFlag is the core.feature_enabled predicate operand — the flag whose enabled
	// state is a precondition. Empty ⇒ Undetermined.
	FeatureFlag string
	// GadgetClasses is the java.gadget_on_classpath predicate operand — FQ gadget
	// class/library names. Empty ⇒ Undetermined (never refute on a partial classpath).
	GadgetClasses []string
	// GuardSufficiency classifies named guard variants against a specific bypass
	// (evidence-framing only — Assess NEVER refutes on sufficiency; Prove adjudicates).
	GuardSufficiency []GuardVariant
	// PocSignal is the corpus poc_signal: whether a public proof-of-concept exists. It
	// populates the S1 public_poc artifact's Available flag. Zero value false ⇒ no PoC
	// (unchanged behavior when the corpus is silent). Advisory-only capability-cost
	// signal; never decides a verdict (inv.5).
	PocSignal bool

	// --- ferralon.normalized_advisory.v3 additions -----------------------------
	// Additive and zero-value-safe (an advisory that declares none leaves them empty).
	// Every consumer reads the zero value as Undetermined/OPEN (inv.5). None can carry a
	// verdict — there is no field a severity/exploitability decision could land in.

	// Withdrawn marks an OSV-withdrawn (retracted) advisory. A withdrawn advisory is
	// disqualified for live routing: the route resolution point forces ClassUnknown so
	// RouteForClass yields no proof route (B2 §3, T1). Zero value false ⇒ live advisory.
	Withdrawn bool
	// Trigger is the per-CVE reach descriptor. When populated, PoE class-framing
	// interpolates the CVE's real Route/Param/MalformedToken instead of the per-class
	// constant (row 1). Zero value ⇒ the per-class constant framing (today's behavior).
	// Advisory framing only — it shapes WHAT the model proposes, never a verdict (inv.5).
	Trigger TriggerRoute
	// Fix is the upstream-fix hint (upstream commit / guard shape / failed-fix class).
	// A synthesis hint consumed downstream; never an oracle bypass (DecideTwoTrace stays
	// the sole sufficiency authority, inv.5). Zero value ⇒ no hint.
	Fix FixHint
	// PocSummary is a short free-text summary of the public PoC's SHAPE (clinical
	// register: shape, never a runnable payload). Advisory-only. Empty ⇒ no summary.
	PocSummary string

	// AffectedPackages is the additive v3 multi-package set (cycle
	// 2026-07-23-affected-block-multipkg). It carries EVERY package the advisory affects,
	// each with its own identity/version/symbol axes, so codebase_inventory's select-by-target
	// can pick the package the assessed codebase actually depends on — a target on a SECONDARY
	// package resolves instead of falling OPEN. The set INCLUDES the primary (the scalar
	// per-package block above equals one element), so selection is one uniform match loop.
	// Empty ⇒ v2/single-package behavior (fail-open, inv.5). Advisory-only framing.
	AffectedPackages []AffectedPackage

	// --- ferralon.normalized_advisory.v4 additions -----------------------------
	// SymbolsTyped is the §4.4.2/.3 typed-symbol axis: the canonical comparable plugin.Symbol
	// identity, coexisting with the bare Symbols []string above. DECLARED-AWAITING-EMIT
	// (anvil-q15): the cve-enrichment producer does not emit typed symbols yet, so this is nil on
	// every current advisory — nil means "producer has not emitted," NOT "no symbols" (Symbols
	// still carries the strings). No consumer may read nil SymbolsTyped as an empty symbol set.
	// Carries no verdict; advisory-only framing (inv.5).
	//
	// omitempty (unlike the other facts fields): the built-in AdvisoryTable corpus never carries
	// typed symbols — they are emitted by the separate cve-enrichment producer for the PUBLISHED
	// feed only — so a nil here is the permanent declared-awaiting-emit state for every table entry,
	// not a field the corpus "fell behind on." Serializing it as null on ~40 built-in fixtures would
	// be misrepresentative noise; the round-trip guard (TestAdvisoryCorpus_Valid) legitimately does
	// not apply to a producer-only axis. When the producer emits, a non-nil value round-trips.
	SymbolsTyped []plugin.Symbol `json:",omitempty"`

	// MaliciousPackage marks an OSV malicious-package (MAL) advisory and carries the enumerated
	// affected version set. Declared=false (the zero) ⇒ not a malicious package ⇒ the presence path
	// never fires and every existing stage runs unchanged (inv.5). Declared=true with an empty
	// AffectedVersions ⇒ un-decidable ⇒ OPEN. This is the ONLY axis that can drive a decisive OSS
	// "affected" (VerdictMaliciousPresent); it is exact-string membership, never a comparator.
	MaliciousPackage MaliciousPackageFacts
}

// MaliciousPackageFacts is the normalized malicious-package marker. Declared is load-bearing and
// distinct from a non-empty version set: it distinguishes "declared malicious, empty version set →
// OPEN" from "not malicious". AffectedVersions is the OSV versions[] set for exact-string membership
// (no semver comparator — MAL versions are enumerated, and the harm is "this exact bad artifact is
// installed"). Zero value ⇒ not malicious ⇒ today's exact behavior.
type MaliciousPackageFacts struct {
	Declared         bool
	AffectedVersions []string
}

// AffectedPackage is one package of a multi-package advisory's affected set — the per-package
// identity + version + symbol axes that differ package-to-package. It mirrors the scalar
// per-package fields of AdvisoryFacts (Module/Coordinate/PURL/VersionScheme/UpperExclusive/
// FixedVersion/AffectedRanges/Symbols); advisory-level facts (CWEs, sink kind, trigger, …) are
// shared and stay on AdvisoryFacts, never duplicated here. All fields zero-value-safe.
type AffectedPackage struct {
	Module         string
	Coordinate     string
	PURL           string
	VersionScheme  string
	UpperExclusive string
	FixedVersion   string
	AffectedRanges []Range
	Symbols        []string
}

// Presence is the §4.4.6 absent-vs-none tri-state for a pointer-backed advisory operand. It closes
// the gap where toFacts collapsed a NIL wire operand (the advisory is SILENT about the constraint)
// and an EMPTY-STRUCT wire operand (the advisory affirmatively DECLARES the constraint has no
// values) to one indistinguishable zero struct — the wire already carries the distinction in the
// *docTrigger/*docFix/*docConfigKey pointers, but the projection erased it.
//
// It is a REPRESENTATION-ONLY marker this cycle (PLAN-024): the distinction becomes readable, but no
// consumer branches on it yet. Consumers still treat absent AND declared_empty as OPEN/Undetermined
// via the value-based Zero() methods (both are value-zero); PLAN-220 is what exploits declared_empty
// as an affirmative "declared none." The marker carries `json:"-"` so it never reaches the wire and
// the advisory fixtures stay byte-identical (no regen). Zero value = PresenceAbsent, so an operand
// left unset by the built-in AdvisoryTable path reads as "silent," unchanged.
type Presence uint8

const (
	// PresenceAbsent: the wire operand pointer was nil — the advisory is silent about this
	// constraint. The zero value, so an unset operand is "absent" with no explicit stamp.
	PresenceAbsent Presence = iota
	// PresenceDeclaredEmpty: the wire operand was present (non-nil) but projected to a zero value
	// — the advisory affirmatively declares the constraint carries no operand values.
	PresenceDeclaredEmpty
	// PresenceDeclaredValues: the wire operand was present and carries at least one value.
	PresenceDeclaredValues
)

func (p Presence) String() string {
	switch p {
	case PresenceAbsent:
		return "absent"
	case PresenceDeclaredEmpty:
		return "declared_empty"
	case PresenceDeclaredValues:
		return "declared_values"
	default:
		return "unknown"
	}
}

// presenceFromZero maps an operand's value-zero-ness onto the DECLARED half of the tri-state (the
// caller has already established the wire operand was non-nil; nil is stamped PresenceAbsent
// separately). A projected operand that is value-zero — including one whose only declared field was
// an unrecognized closed-set member dropped fail-open — reads as declared_empty; anything carrying a
// value reads as declared_values.
//
// KNOWN LIMITATION (PLAN-220): this reads the POST-fail-open Zero(), so an operand whose sole declared
// field was an unrecognized value (dropped to zero at decode) is labeled declared_empty rather than
// declared_values. Latent this cycle — no consumer reads Presence yet. When PLAN-220 wires consumers,
// it decides whether a wire-present-but-all-dropped operand should be distinguished from a genuinely
// empty one; doing so needs the pre-drop wire shape, not the projected zero.
func presenceFromZero(zero bool) Presence {
	if zero {
		return PresenceDeclaredEmpty
	}
	return PresenceDeclaredValues
}

// TriggerRoute is the advisory-declared per-CVE reach descriptor: the ingress kind, the ingress
// route path, the tainted parameter on that route, and the clinical SHAPE of the malformed value
// (never a weaponized payload — memory clinical-register-terminology). It frames the reach path the
// PoE class-framing interpolates per-CVE; it is context, never a verdict (inv.5).
type TriggerRoute struct {
	IngressKind    string // closed set: "" | http | grpc | cli | library (ingressKindRecognized)
	Route          string // literal ingress path, e.g. "/fetch"
	Param          string // tainted query/body key placed on the route
	MalformedToken string // clinical SHAPE of the value on that key
	// Declared is the §4.4.6 absent-vs-none marker (representation-only, json:"-"): absent when the
	// wire `trigger` operand was nil, declared_empty/declared_values when it was present. No consumer
	// branches on it this cycle — Zero() stays value-based so behavior is preserved.
	Declared Presence `json:"-"`
}

// Zero reports whether the descriptor carries no reach information (all VALUE fields empty), so the
// per-class constant framing is used unchanged. It deliberately ignores Declared: a declared_empty
// trigger is value-zero and must still report Zero()==true so no consumer branch flips (inv.5,
// §4.4.6 behavior-preserving — the Presence distinction is representable, not yet acted on).
func (t TriggerRoute) Zero() bool {
	return t.IngressKind == "" && t.Route == "" && t.Param == "" && t.MalformedToken == ""
}

// FixHint is the advisory-declared upstream-fix hint. FailedFixClass is a closed set
// (failedFixClassRecognized). It is a synthesis hint, never a sufficiency oracle (inv.5).
type FixHint struct {
	UpstreamCommit string // upstream commit that fixed the vuln
	GuardShape     string // shape of the guard the fix introduced
	FailedFixClass string // closed set: "" | naive-dep-bump-insufficient | guard-keyed-away-from-sink
	// Declared is the §4.4.6 absent-vs-none marker (representation-only, json:"-"): absent when the
	// wire `fix` operand was nil, declared_empty/declared_values when present. Zero() ignores it.
	Declared Presence `json:"-"`
}

// Zero reports whether the hint carries no fix intelligence (all VALUE fields empty), so the
// synthesis prompt omits the hint block and the predecessor baseline falls back to the
// version-derived anchor. It ignores Declared (see TriggerRoute.Zero): a declared_empty hint is
// value-zero and must still report Zero()==true so no consumer branch flips (§4.4.6).
func (f FixHint) Zero() bool {
	return f.UpstreamCommit == "" && f.GuardShape == "" && f.FailedFixClass == ""
}

// resolveVulnClass picks the proof-route vuln class for an advisory (advisory framing only, inv.5 —
// it selects a proof SHAPE, never a verdict). Precedence:
//
//  1. Withdrawn (T1, B2 §3): an OSV-withdrawn advisory is retracted upstream → force ClassUnknown so
//     RouteForClass yields NO live route. The withdrawn state supersedes a declared sink_kind.
//  2. Declared sink_kind (row 2, spec 02): a recognized sink_kind supersedes the CWE/keyword
//     classifier guess — the corpus knows the sink precisely; the classifier only guesses. sink_kind
//     is either a literal vulnclass.Class (native back-compat) or Intel's own sink taxonomy, mapped
//     via classFromSinkKind (advisory_source.go); "code_execution" resolves only when facts.CWEs
//     pin exactly one fan-out class (2026-07-15 sink_kind reconcile).
//  3. Fail open (BINDING zero-regressions invariant): an empty, unrecognized, OR AMBIGUOUS sink_kind
//     (e.g. "code_execution" whose cwe[] don't pin one class) leaves the ClassifyAdvisory result
//     standing — never overriding a correct classifier hit with a wrong or guessed mapped class.
//
// Both classFramingBlock and RouteForClass read the stamped vuln_class, so this single resolution
// point propagates to framing AND route selection.
func resolveVulnClass(facts AdvisoryFacts) vulnclass.Class {
	if facts.Withdrawn {
		return vulnclass.ClassUnknown
	}
	classified := vulnclass.ClassifyAdvisory(vulnclass.AdvisoryClass{CWEs: facts.CWEs, Summary: facts.Summary})
	if k, ok := classFromSinkKind(facts.SinkKind, facts.CWEs); ok {
		return k
	}
	return classified
}

// advisoryTrigger is the JSON shape of the per-CVE reach descriptor stamped onto the
// normalized_advisory artifact (the channel the Service-side PoE class-framing reads it back through,
// mirroring how vuln_class is stamped and re-read). Field names match docTrigger's wire tags so the
// descriptor round-trips byte-for-byte through the artifact. Advisory framing only (inv.5).
type advisoryTrigger struct {
	IngressKind    string `json:"ingress_kind,omitempty"`
	Route          string `json:"route,omitempty"`
	Param          string `json:"param,omitempty"`
	MalformedToken string `json:"malformed_token,omitempty"`
}

// Range is one OSV-shaped affected interval, expressed in the advisory's declared
// VersionScheme. A backport is emitted as SEPARATE ranges (e.g. the 1.20.x branch fixed
// at 1.20.10 AND mainline fixed at 1.21.3), each with its own FixedVersion — never one
// conflated bound. All fields are zero-value-safe.
type Range struct {
	Introduced   string // inclusive lower bound; "" = unbounded below
	Fixed        string // exclusive upper bound: the release fixing THIS range
	LastAffected string // inclusive upper bound; set instead of Fixed when no fix release exists
	FixedVersion string // per-range fix source for the branch-aware two-trace PoNE predecessor
}

// TrustTier gates refute eligibility for a fact. Only first_party facts may drive a
// KnownFalse (refute) branch; byo/third_party may narrow toward candidate but never
// refute. The zero value ("") is untrusted and never refutes (fail open).
type TrustTier string

const (
	// TrustByO marks a fact sourced from the codebase's own bring-your-own advisory
	// input. It may narrow toward candidate but never refute.
	TrustByO TrustTier = "byo"
	// TrustThirdParty marks a fact sourced from an external, non-authoritative feed.
	// It may narrow toward candidate but never refute.
	TrustThirdParty TrustTier = "third_party"
	// TrustFirstParty marks a fact sourced from an authoritative first-party corpus.
	// It is the only tier that may drive a KnownFalse (refute) branch.
	TrustFirstParty TrustTier = "first_party"
)

// Provenance records the source and trust of one advisory fact. Trusted-or-nulled: a
// fact whose provenance is unknown carries the zero TrustTier and can never refute.
//
// §4.4.4 (source provenance AND confidence) is discharged by this triple, NOT by a separate
// synthesized per-fact confidence score — and that absence is deliberate, not a gap:
//
//   - Provenance = Source + InputDigest + TrustTier. Source names where the fact was read from,
//     InputDigest pins the exact bytes, and TrustTier is the CONFIDENCE-IN-SOURCE axis (byo /
//     third_party / first_party) that gates refute eligibility. Together they answer "how far may
//     this fact be trusted," which is the confidence half of §4.4.4.
//   - There is NO per-fact `Confidence` field, on purpose. Upstream advisories do not carry a
//     confidence number, so any value here would be SYNTHESIZED by this reader — and a manufactured
//     confidence score is a verdict-like judgment (a graded assertion about how true the fact is),
//     exactly what the evidence-only record must never hold (§3 non-negotiable). TrustTier grades the
//     SOURCE, which the source itself supplies; it never grades the fact's truth.
//   - Per-SYMBOL attribution certainty — "is this the right vulnerable symbol" — is a distinct axis
//     and is the §4.4.8 attribution-review concern (see AttributionStatus and
//     attribution_status_model.md), not a field on this base record. An attribution's status IS its
//     per-symbol confidence signal, kept out of the evidence record and in the review workflow.
type Provenance struct {
	Source      string    // corpus feed id
	InputDigest string    // digest of the corpus artifact this fact was read from
	TrustTier   TrustTier // gates refute eligibility; the confidence-in-source axis (§4.4.4)
}

// Lineage names the incomplete-patch predecessor/successor CVEs for the two-trace PoNE
// predecessor baseline. Advisory-only framing; never decides a verdict.
type Lineage struct {
	IncompleteFixOf string // CVE this advisory re-opens (deterministic known-vulnerable predecessor)
	RefixedBy       string // CVE that completes the fix, if any
}

// ConfigOperand is the core.config predicate's advisory half: a config key plus the
// value that makes the codebase unsafe.
type ConfigOperand struct {
	Key         string
	UnsafeValue string
	// Declared is the §4.4.6 absent-vs-none marker (representation-only, json:"-"): absent when the
	// wire `config_key` operand was nil, declared_empty/declared_values when present. Zero() ignores it.
	Declared Presence `json:"-"`
}

// Zero reports whether the operand carries no config predicate (both VALUE fields empty). Like
// TriggerRoute.Zero it ignores Declared: a declared_empty config_key is value-zero and must still
// report Zero()==true so the predicate stays Undetermined/OPEN for every existing consumer (§4.4.6).
func (c ConfigOperand) Zero() bool {
	return c.Key == "" && c.UnsafeValue == ""
}

// AttributionStatus is the §4.4.8 review state of a symbol attribution — whether the advisory's
// claim that a given symbol is the vulnerable one has been reviewed, and with what outcome. It is a
// closed string enum (attributionStatusRecognized), fail-open like TrustTier: an unrecognized value
// drops to the zero. This cycle (PLAN-024) establishes the TYPE and the state model
// (attribution_status_model.md) ONLY; it is NOT yet wired onto the bare `symbols []string` axis —
// per-symbol population rides on typed symbols (anvil-q15) + PLAN-220.
//
// An attribution's status IS its per-symbol confidence signal (the §4.4.4 tie-in): it is the axis a
// synthesized per-fact confidence score would otherwise usurp, kept HONEST by living in a review
// workflow with named states and evidence-driven transitions rather than a manufactured number.
type AttributionStatus string

const (
	// AttributionUnreviewed: the attribution has not been reviewed. The zero-value default — an
	// as-ingested attribution is unreviewed until a review moves it, and fail-open decode lands here.
	AttributionUnreviewed AttributionStatus = "unreviewed"
	// AttributionConfirmed: review established this symbol IS the vulnerable one for this advisory.
	AttributionConfirmed AttributionStatus = "confirmed"
	// AttributionAmbiguous: review found the symbol identity underdetermined — the advisory's symbol
	// could resolve to more than one candidate (overload/rename/relocation) and evidence does not
	// yet single one out. Distinct from disputed: no counter-claim, just insufficient resolution.
	AttributionAmbiguous AttributionStatus = "ambiguous"
	// AttributionDisputed: review surfaced positive counter-evidence that this symbol is NOT the
	// vulnerable one (e.g. the named symbol never reaches the sink). A standing contradiction, not
	// mere under-resolution.
	AttributionDisputed AttributionStatus = "disputed"
)

// GuardVariant classifies a named guard variant against a specific bypass, for the
// guard_sufficiency evidence framing. Assess never refutes on it (Prove adjudicates
// sufficiency); it only upgrades the evidence label.
type GuardVariant struct {
	Symbol, Version, ForBypass string
	Sufficient                 bool
}

// AdvisoryTable pins the corpus advisories. This is honest for the corpus (the advisories are real
// and verified against osv.dev per the fixtures) and stays offline. An unknown VulnID yields zero
// facts → every structured field stays empty → the disqualification predicate fails open
// (SOUNDNESS: unknown is never "not affected"). Exported because the Prove path reads the
// FixedVersion for a known-vulnerable predecessor.
var AdvisoryTable = map[string]AdvisoryFacts{
	"GO-2021-0113": {
		Module:         "golang.org/x/text",
		Aliases:        []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"},
		UpperExclusive: "v0.3.7",
		FixedVersion:   "v0.3.7",
		PURL:           "pkg:golang/golang.org/x/text",
		Symbols:        []string{"golang.org/x/text/language.Parse"},
		CWEs:           []string{"CWE-125"},
		Summary:        "out-of-bounds read panic in language.Parse on a malformed BCP-47 tag",
	},
	"GO-2022-0322": {
		Module:         "github.com/prometheus/client_golang",
		Aliases:        []string{"CVE-2022-21698", "GHSA-cg3q-j54f-5p7p"},
		UpperExclusive: "v1.11.1",
		FixedVersion:   "v1.11.1",
		PURL:           "pkg:golang/github.com/prometheus/client_golang",
		Symbols: []string{
			"github.com/prometheus/client_golang/prometheus/promhttp.Handler",
			"github.com/prometheus/client_golang/prometheus/promhttp.HandlerFor",
		},
		CWEs:    []string{"CWE-770"},
		Summary: "uncontrolled resource consumption: unbounded cardinality of metric labels enables memory exhaustion",
	},
	"CVE-2024-45337": {
		Module:         "golang.org/x/crypto",
		Aliases:        []string{"GHSA-v778-237x-gjrc", "GO-2024-3321"},
		UpperExclusive: "v0.31.0",
		FixedVersion:   "v0.31.0",
		PURL:           "pkg:golang/golang.org/x/crypto",
		Symbols:        []string{"golang.org/x/crypto/ssh.NewServerConn"},
		CWEs:           []string{"CWE-285"},
		Summary:        "authorization bypass: an SSH server that misuses ServerConfig.PublicKeyCallback may treat a public key that was offered but never used to complete authentication as if it had authenticated the session",
	},
	"FERRALON-APP-SSRF-0001": {
		PURL:    "pkg:golang/tegron/corpus/ssrf",
		Symbols: []string{"main.fetchHandler"},
		CWEs:    []string{"CWE-918"},
		Summary: "server-side request forgery: fetchHandler forwards an attacker-controlled url parameter to http.Get with no allowlist",
	},
	"FERRALON-APP-DOS-0001": {
		PURL:    "pkg:golang/tegron/corpus/dos",
		Symbols: []string{"main.expandHandler"},
		CWEs:    []string{"CWE-400"},
		Summary: "uncontrolled resource consumption: expandHandler allocates a slice sized by an attacker-controlled count with no upper bound, faulting the process",
	},
	// Grafana CVE-2024-9264 (SQL Expressions → DuckDB RCE/LFI). First-party
	// application sink: the vulnerable feature reaches an exec sink that hands
	// attacker SQL to the DuckDB engine binary. The fix (PR #94942, "disable sql
	// expressions") DELETES the go-duck dependency and the exec sink and redirects
	// the route to an inert stub — a structural symbol/path removal, so the fixed
	// tree resolves nothing → reachable_candidate → not_exploitable. Module is
	// empty (first-party, no go.mod require to version-resolve); PURL names the app
	// so symbol resolution scopes there, and the /api/ds/query http_route handler
	// is the recognized ingress (ADR 0005 first-party reachability). No version
	// keying — this is a reachability firing, not a version-axis case.
	"TEGRON-GO-GRAFANA-DUCKDB-0001": {
		Aliases: []string{"CVE-2024-9264", "GHSA-q99m-qcv4-fpm7"},
		PURL:    "pkg:golang/github.com/grafana/grafana",
		Symbols: []string{"main.runDuckQuery"},
		CWEs:    []string{"CWE-94", "CWE-78"},
		Summary: "code injection / OS command execution: the SQL Expressions feature reaches runDuckQuery, which executes attacker-controlled SQL through the DuckDB engine binary (DuckDB file functions enable LFI/RCE); the upstream fix removes the go-duck dependency and the exec sink outright",
	},
	"GO-2021-0264": {
		Aliases: []string{"CVE-2021-41772"},
		PURL:    "pkg:golang/stdlib",
		Symbols: []string{"archive/zip.(*Reader).Open"},
	},
	// --- Go stdlib/toolchain (go-toolchain scheme, U7) -----------------------------------------
	// These advisories fix at TOOLCHAIN releases (go1.20.10, go1.21.3 …), NOT module semver, so
	// they carry the "go-toolchain" VersionScheme EXPLICITLY: there is no module PURL for the
	// toolchain itself (schemeFromPURL maps pkg:golang → gomod and must stay that way, so it can
	// never derive this scheme). Each is a branch-aware BACKPORT — the fix landed on two release
	// branches — expressed as TWO disjoint AffectedRanges; U2's versionOutsideRanges reasons over
	// the whole set (a version disqualifies only when it is at/past the fix on EVERY branch).
	//
	// CVE-2023-39325 (HTTP/2 rapid reset) is the required anchor: fixed go1.20.10 on the 1.20.x
	// branch AND go1.21.3 on mainline (GO-2023-2102 / GHSA-4374-p667-p6c8). Module is empty
	// (stdlib is the toolchain, not a go.mod require).
	"CVE-2023-39325": {
		Aliases:       []string{"GO-2023-2102", "GHSA-4374-p667-p6c8"},
		VersionScheme: "go-toolchain",
		PURL:          "pkg:golang/stdlib",
		AffectedRanges: []Range{
			{Fixed: "go1.20.10", FixedVersion: "go1.20.10"},
			{Introduced: "go1.21.0", Fixed: "go1.21.3", FixedVersion: "go1.21.3"},
		},
		Symbols: []string{"net/http.(*http2Server).ServeConn"},
		CWEs:    []string{"CWE-400"},
		Summary: "uncontrolled resource consumption (HTTP/2 rapid reset): a client that rapidly opens and resets streams forces the net/http HTTP/2 server to spawn unbounded handler goroutines; fixed on both the go1.20.x and go1.21.x branches",
	},
	// CVE-2023-45283 (path/filepath, Windows \??\ device-path bypass): fixed go1.20.11 and
	// go1.21.4 (GO-2023-2185). A second backport pair.
	"CVE-2023-45283": {
		Aliases:       []string{"GO-2023-2185"},
		VersionScheme: "go-toolchain",
		PURL:          "pkg:golang/stdlib",
		AffectedRanges: []Range{
			{Fixed: "go1.20.11", FixedVersion: "go1.20.11"},
			{Introduced: "go1.21.0", Fixed: "go1.21.4", FixedVersion: "go1.21.4"},
		},
		Symbols: []string{"path/filepath.IsLocal", "path/filepath.Clean"},
		CWEs:    []string{"CWE-22"},
		Summary: "improper path traversal: on Windows path/filepath does not treat a \\??\\ device-path prefix as special, so IsLocal reports an escaping path as local; fixed on both the go1.20.x and go1.21.x branches",
	},
	// CVE-2024-24790 (net/netip, IPv4-mapped IPv6 Is* methods): fixed go1.21.11 and go1.22.4
	// (GO-2024-2887). A backport across the 1.21.x and 1.22.x branches.
	"CVE-2024-24790": {
		Aliases:       []string{"GO-2024-2887"},
		VersionScheme: "go-toolchain",
		PURL:          "pkg:golang/stdlib",
		AffectedRanges: []Range{
			{Fixed: "go1.21.11", FixedVersion: "go1.21.11"},
			{Introduced: "go1.22.0", Fixed: "go1.22.4", FixedVersion: "go1.22.4"},
		},
		Symbols: []string{"net/netip.Addr.IsPrivate", "net/netip.Addr.IsLoopback"},
		CWEs:    []string{"CWE-125"},
		Summary: "incorrect address classification: net/netip Is* methods (IsPrivate, IsLoopback, …) return false for IPv4-mapped IPv6 addresses that should classify by their IPv4 form, defeating allow/deny checks; fixed on both the go1.21.x and go1.22.x branches",
	},
	// The gogs incomplete-fix chain is TWO advisories, and they are split — not merged under one
	// id — so that every per-CVE fact lands on the CVE it is actually true of. A merged entry has
	// one slot for two different answers, so no per-CVE fact on it can be right.
	//
	// Both are first-party application sinks: the advisory affects the gogs.io/gogs application
	// itself, not a dependency, so Module is empty (no go.mod require to version-resolve — the
	// version axis fails open and every checkpoint proceeds to reachability). PURL names the
	// precise sink package (gogs.io/gogs/internal/db) so symbol resolution scopes to it; the
	// macaron route handlers reaching it are recognized ingresses (ADR 0005 first-party
	// reachability). The sink is the same symbol in both: (*Repository).UpdateRepoFile.
	//
	// Facts resolved against api.osv.dev, and the guard attribution read off the real gogs
	// sources at each release tag (internal/db/repo_editor.go):
	//
	//   CVE-2024-55947 — PREDECESSOR, published 2024-12-23, aliases GHSA-qf5v-rp47-55gg /
	//     GO-2024-3356, fixed 0.13.1. A ../ traversal through the file-update API; v0.13.1
	//     closes it by extending the isRepositoryGitPath .git guard to that route's call sites.
	//   CVE-2025-8110 — SUCCESSOR, published 2025-12-10, aliases GHSA-mq8m-42gh-wq7r /
	//     GO-2025-4225, last_affected 0.13.3. A committed in-repo symlink escapes the working
	//     tree, bypassing the v0.13.1 traversal fix. v0.13.3's osutil.IsSymlink check is
	//     LEAF-ONLY — it inspects the final path component, so a symlink at an INTERIOR
	//     component still escapes; v0.13.4's hasSymlinkInPath walks the whole path hierarchy
	//     and closes it (upstream commit 553707f).
	//
	// Lineage joins them keyed from the predecessor: 55947 RefixedBy 8110, and 8110
	// IncompleteFixOf 55947. IncompleteFixOf on the predecessor stays empty (honest-empty — it
	// re-opens nothing), matching the log4shell shape.
	//
	// SOUNDNESS (inv.5): NEITHER entry may carry AffectedRanges/UpperExclusive/FixedVersion. The
	// fix versions above are real, but they are not a version AXIS — with no resolvable
	// first-party version there is nothing to compare them against, and declaring them would make
	// the entry version-disqualifiable, refuting a live finding on a version the scan never
	// established. They live in GuardSufficiency instead, which is Prove-side evidence framing
	// that Assess never refutes on.
	//
	// Each entry carries ONLY its own OSV aliases. Merging them was customer-visible wrong:
	// internal/intel/data/kev.json lists only CVE-2025-8110, and trigger's priorityFor joins on
	// ID + Aliases, so the successor sitting in the predecessor's alias array reported
	// KEVListed against CVE-2024-55947 — which CISA does not list. The GO- ids are load-bearing,
	// not decoration: they are the key govulncheck reports dependency findings under
	// (reachcandidate.govulnMatchID, which takes the FIRST GO- alias — with one GO- id per entry
	// that is now unambiguous, where the merged entry could only ever key one of the two).
	"CVE-2024-55947": {
		Aliases: []string{"GHSA-qf5v-rp47-55gg", "GO-2024-3356"},
		PURL:    "pkg:golang/gogs.io/gogs/internal/db",
		Symbols: []string{"UpdateRepoFile"},
		// GuardSymbols are the advisory-declared mitigations whose PRESENCE on the
		// ingress→sink path the candidate tier reports as evidence — never as a verdict
		// (inv.5). This CVE's guard is the .git path check alone.
		GuardSymbols: []string{"isRepositoryGitPath"},
		GuardSufficiency: []GuardVariant{
			{Symbol: "isRepositoryGitPath", Version: "0.13.1", ForBypass: "CVE-2024-55947", Sufficient: true},
		},
		CWEs:    []string{"CWE-22"},
		Lineage: Lineage{RefixedBy: "CVE-2025-8110"},
		Summary: "path traversal / arbitrary file write: the repository file-update API reaches UpdateRepoFile with an attacker-controlled tree path that escapes the repository directory; fixed in v0.13.1 by extending the .git path guard to that route",
	},
	"CVE-2025-8110": {
		Aliases: []string{"GHSA-mq8m-42gh-wq7r", "GO-2025-4225"},
		PURL:    "pkg:golang/gogs.io/gogs/internal/db",
		Symbols: []string{"UpdateRepoFile"},
		// Presence ≠ sufficiency, and this CVE is the proof of it: v0.13.3 CARRIES IsSymlink
		// and is still vulnerable, because the check is leaf-only. Assess reports guard
		// presence as evidence; only runtime Prove adjudicates which guard closes the hole.
		GuardSymbols: []string{"IsSymlink", "hasSymlinkInPath"},
		GuardSufficiency: []GuardVariant{
			{Symbol: "IsSymlink", Version: "0.13.3", ForBypass: "CVE-2025-8110", Sufficient: false},
			{Symbol: "hasSymlinkInPath", Version: "0.13.4", ForBypass: "CVE-2025-8110", Sufficient: true},
		},
		CWEs:    []string{"CWE-22"},
		Lineage: Lineage{IncompleteFixOf: "CVE-2024-55947"},
		Summary: "arbitrary file write via symlink: a committed in-repo symlink at an interior path component is followed by UpdateRepoFile, escaping the working tree; bypasses the v0.13.1 traversal fix and v0.13.3's leaf-only symlink check, and is closed by the full-hierarchy walk added in v0.13.4",
	},
	"TEGRON-JAVA-SSRF-0001": {
		PURL:    "pkg:maven/com.example.web/ssrf",
		Symbols: []string{"UrlFetcher.fetch"},
		CWEs:    []string{"CWE-918"},
		Summary: "server-side request forgery: a servlet forwards an attacker-controlled target through UrlFetcher.fetch to an outbound HTTP request with no allowlist",
	},
	"TEGRON-JAVA-SPRING-SSRF-0001": {
		PURL:    "pkg:maven/com.example.web/spring-ssrf",
		Symbols: []string{"UrlServiceImpl.fetch"},
		CWEs:    []string{"CWE-918"},
		Summary: "server-side request forgery: a Spring @RestController reaches UrlServiceImpl.fetch through an @Autowired interface field; the sink issues an outbound request with no allowlist",
	},
	"TEGRON-JAVA-SSRF-0002": {
		Coordinate:     "com.example.net:urlkit",
		UpperExclusive: "2.1.0",
		FixedVersion:   "2.1.0",
		VersionScheme:  "maven",
		PURL:           "pkg:maven/com.example.net/urlkit",
		Symbols:        []string{"App.fetch"},
		CWEs:           []string{"CWE-918"},
		Summary:        "server-side request forgery: com.example.net:urlkit reaches an outbound HTTP GET to a caller-supplied URL with no allowlist; fixed in 2.1.0. In the unreachable repro the sink App.fetch is present but dead — never called from an ingress — so the case is not_exploitable at the reach axis.",
	},
	"TEGRON-JAVA-SSRF-0003": {
		Coordinate:    "com.example.svc:iface-fetch",
		VersionScheme: "maven",
		PURL:          "pkg:maven/com.example.svc/iface-fetch",
		AffectedRanges: []Range{
			{Introduced: "1.0.0", Fixed: "1.3.0", FixedVersion: "1.3.0"},
		},
		Symbols: []string{"SomeServiceImpl.fetch"},
		CWEs:    []string{"CWE-918"},
		Summary: "server-side request forgery: com.example.svc:iface-fetch reaches SomeServiceImpl.fetch through an @Autowired SomeService interface field; the sink issues an outbound request with no allowlist. Fixed in 1.3.0 (affects [1.0.0, 1.3.0)). The tool-unavailable repro is undetermined under the analyzer-gated-but-absent overlay and not_exploitable ungated.",
	},
	"TEGRON-JS-SSRF-0001": {
		PURL:    "pkg:npm/tegron-corpus-ssrf",
		Symbols: []string{"fetchUrl"},
		CWEs:    []string{"CWE-918"},
		Summary: "server-side request forgery: an Express route forwards an attacker-controlled target through fetchUrl to an outbound HTTP request with no allowlist",
	},
	"TEGRON-JS-NEXTRCE-0001": {
		Aliases: []string{"GHSA-5vj8-3v2h-h38v"},
		PURL:    "pkg:npm/next",
		Symbols: []string{"requireModule"},
		CWEs:    []string{"CWE-94"},
		Summary: "module-resolution RCE: the catch-all page route reaches requireModule, which require()s an attacker-controlled path with no bundles-directory containment (Next.js < 5.1.0)",
	},
	"TEGRON-JAVA-DEP-0001": {
		Coordinate:     "com.example.lib:widget",
		UpperExclusive: "1.4.0",
		FixedVersion:   "1.4.0",
		VersionScheme:  "maven",
		PURL:           "pkg:maven/com.example.lib/widget",
		Summary:        "deserialization flaw in com.example.lib:widget fixed in 1.4.0",
	},
	"TEGRON-JS-DEP-0001": {
		Coordinate:     "left-pad",
		UpperExclusive: "1.4.0",
		FixedVersion:   "1.4.0",
		VersionScheme:  "npm",
		PURL:           "pkg:npm/left-pad",
		Summary:        "prototype pollution in left-pad fixed in 1.4.0",
	},
	// PyPI / NuGet DEP fixtures carry NO explicit VersionScheme: the scheme is derived from
	// the corpus PURL (pkg:pypi→pypi, pkg:nuget→nuget) by advisoryIntake.Run (§3), which is
	// how the U8 corpus feed will light up the pypi/nuget comparators versionOutsideRange
	// already dispatches. Version-axis fixtures only (like the Java/JS DEP entries above): no
	// live repro, no symbols — they exercise the derived-scheme disqualification path.
	"TEGRON-PY-DEP-0001": {
		Coordinate:     "flask",
		UpperExclusive: "2.3.2",
		FixedVersion:   "2.3.2",
		PURL:           "pkg:pypi/flask",
		Summary:        "reflected header injection in flask fixed in 2.3.2",
	},
	"TEGRON-NET-DEP-0001": {
		Coordinate:     "Newtonsoft.Json",
		UpperExclusive: "13.0.1",
		FixedVersion:   "13.0.1",
		PURL:           "pkg:nuget/Newtonsoft.Json",
		Summary:        "insecure default deserialization in Newtonsoft.Json fixed in 13.0.1",
	},
	"TEGRON-NET-REACH-0001": {
		Aliases:        []string{"CVE-2021-32840"},
		UpperExclusive: "1.3.3",
		FixedVersion:   "1.3.3",
		VersionScheme:  "nuget",
		Coordinate:     "SharpZipLib",
		PURL:           "pkg:nuget/SharpZipLib",
		Symbols:        []string{"ICSharpCode.SharpZipLib.Zip.FastZip.ExtractZip"},
		CWEs:           []string{"CWE-22"},
		Summary:        "path traversal (Zip-Slip) on archive extraction: ICSharpCode.SharpZipLib before 1.3.3 does not validate archive entry paths, so FastZip.ExtractZip writes files outside the destination directory, enabling arbitrary file write and possible remote code execution. GHSA-m22m-h4rf-pwq3 / CVE-2021-32840, fixed in 1.3.3.",
		AffectedRanges: []Range{{Fixed: "1.3.3", FixedVersion: "1.3.3"}},
		Provenance:     Provenance{Source: "GHSA-m22m-h4rf-pwq3", InputDigest: "provisional-symbol-spelling: authored before the .NET symbol profile was fixed; re-normalisation pending. The Symbols spelling above is NOT canonical yet. NOTE the identity split: Coordinate/PURL are keyed by the NuGet PACKAGE ID (SharpZipLib) so versions.go matches the .csproj PackageReference; Symbols are keyed by the CLR NAMESPACE path (ICSharpCode.SharpZipLib.*)."},
	},
	// First-party pypi advisory with a KNOWN scheme (pkg:pypi → pypi) but NO version-range
	// fix — an open/unbounded affected range, like the gogs symlink CVE. schemeFromPURL
	// derives a comparator, but with no upper bound the version axis has nothing to soundly
	// prove outside, so it MUST stay OPEN. Deriving a scheme selects a comparator; it never
	// manufactures a bound. Guards inv.5 (§3): a known scheme must never disqualify an
	// unbounded advisory.
	"TEGRON-PY-FIRSTPARTY-0001": {
		PURL:    "pkg:pypi/tegron-corpus-app",
		Symbols: []string{"app.handler"},
		CWEs:    []string{"CWE-22"},
		Summary: "first-party path traversal with no version-range fix (open/unbounded affected range)",
	},
	// Apache Airflow Experimental REST API removal (PR #41434, shipped in Airflow 3.0.0).
	// The experimental API shipped with no access control by default (CVE-2020-13927 family);
	// the definitive fix DELETES the endpoints wholesale. First-party application sink: the
	// advisory affects apache-airflow itself, not a dependency, so there is no version-range
	// fix — Module/Coordinate/UpperExclusive stay empty (the version axis fails open and every
	// checkpoint proceeds to reachability), gogs-shaped. PURL names the sink's module so symbol
	// resolution scopes to it; the @api_experimental.route Flask-blueprint handler reaching it
	// is a recognized http_route ingress. At the fix commit BOTH the sink module (get_code.py)
	// and the decorated handler are removed — symbol-removal AND path-removal — so the sink no
	// longer resolves and no ingress→sink path exists: reachable_candidate → not_exploitable.
	"TEGRON-PY-AIRFLOW-EXPAPI-0001": {
		Aliases: []string{"CVE-2020-13927"},
		PURL:    "pkg:pypi/apache-airflow",
		Symbols: []string{"airflow.api.common.experimental.get_code.get_code"},
		CWEs:    []string{"CWE-306"},
		Summary: "missing authentication: the experimental REST API exposes an unauthenticated get_code sink that reads arbitrary DAG source off disk; the experimental API has no access control by default and was removed wholesale in Airflow 3.0.0",
	},
	// --- demo-relevant real Go advisories (broad-corpus membership) -----------------------------
	// Four real vuln.go.dev records evaluated on every Go scan (they surface reachable in
	// demo-go-svc, whose go.mod pins x/crypto v0.30.0, x/net v0.32.0, and nanoauth at the
	// introduced pseudo-version). Each carries its GO- alias, because govulncheck keys its findings
	// by the GO- id and never by the CVE/GHSA primary — govulnMatchID resolves the alias so
	// reachability can match, and v-prefixed versions. CWEs are transcribed from the CVE
	// Program CNA record (vuln.go.dev's OSV JSON assigns no CWE — as it also omits CVE-2024-45337's
	// CWE-285 above; the corpus convention sources CWE from the CVE record). Advisory-only: CWEs
	// and Lineage NEVER decide a verdict (inv.5).
	"CVE-2026-46595": {
		Module:         "golang.org/x/crypto",
		Aliases:        []string{"GHSA-x527-x647-q7gg", "GO-2026-5023"},
		UpperExclusive: "v0.52.0",
		FixedVersion:   "v0.52.0",
		PURL:           "pkg:golang/golang.org/x/crypto",
		Symbols:        []string{"golang.org/x/crypto/ssh.NewServerConn"},
		CWEs:           []string{"CWE-863"},
		// Incomplete-fix follow-on to CVE-2024-45337: the 45337 fix skipped source-address
		// validation when a non-public-key callback is configured (golang-announce / GO-2026-5023).
		Lineage: Lineage{IncompleteFixOf: "CVE-2024-45337"},
		Summary: "authorization bypass (incomplete fix of CVE-2024-45337): when an SSH server's ServerConfig uses a non-public-key callback, the source-address validation added by the CVE-2024-45337 fix is skipped, re-opening the authorization bypass",
	},
	"CVE-2026-39831": {
		Module:         "golang.org/x/crypto",
		Aliases:        []string{"GHSA-89gr-r52h-f8rx", "GO-2026-5019"},
		UpperExclusive: "v0.52.0",
		FixedVersion:   "v0.52.0",
		PURL:           "pkg:golang/golang.org/x/crypto",
		Symbols: []string{
			"golang.org/x/crypto/ssh.NewServerConn",
			"golang.org/x/crypto/ssh.CertChecker.Authenticate",
			"golang.org/x/crypto/ssh.CertChecker.CheckCert",
			"golang.org/x/crypto/ssh.CertChecker.CheckHostKey",
			"golang.org/x/crypto/ssh.Certificate.Verify",
			"golang.org/x/crypto/ssh.Dial",
			"golang.org/x/crypto/ssh.NewClientConn",
		},
		CWEs:    []string{"CWE-290"},
		Summary: "authentication bypass: the Verify() method for FIDO/U2F security-key types (sk-ecdsa-sha2-nistp256@openssh.com, sk-ssh-ed25519@openssh.com) does not check the User Presence flag, so signatures generated without a physical touch are accepted, allowing unattended use of a hardware security key",
	},
	"CVE-2026-39821": {
		Module:         "golang.org/x/net",
		Aliases:        []string{"GO-2026-5026"},
		UpperExclusive: "v0.55.0",
		FixedVersion:   "v0.55.0",
		PURL:           "pkg:golang/golang.org/x/net",
		Symbols: []string{
			"golang.org/x/net/idna.Profile.ToASCII",
			"golang.org/x/net/idna.Profile.ToUnicode",
			"golang.org/x/net/idna.ToASCII",
			"golang.org/x/net/idna.ToUnicode",
		},
		CWEs:    []string{"CWE-1289"},
		Summary: "privilege escalation via IDNA confusion: idna.ToASCII/ToUnicode incorrectly accept a Punycode-encoded label that decodes to an ASCII-only label (e.g. ToUnicode(\"xn--example-.com\") returns \"example.com\" instead of an error), so a hostname allow/deny check on the ASCII form can be bypassed after conversion to Unicode",
	},
	// nanoauth is a first-party-shaped dependency advisory whose affected set is an OSV-shaped
	// introduced+fixed range of Go PSEUDO-versions. versionOutsideRange rejects pseudo-versions as
	// prerelease, so the version axis fails OPEN (it can never disqualify) — correct and intended:
	// nanoauth "applies" and its verdict is reachability/symbol-presence-decided, not version-decided.
	// The range is expressed via AffectedRanges (mirroring the go-toolchain entries' shape), NOT a
	// single UpperExclusive, because it has a real lower bound.
	"CVE-2020-36569": {
		Module:  "github.com/nanobox-io/golang-nanoauth",
		Aliases: []string{"GHSA-hrm3-3xm6-x33h", "GO-2020-0004"},
		PURL:    "pkg:golang/github.com/nanobox-io/golang-nanoauth",
		AffectedRanges: []Range{
			{
				Introduced:   "v0.0.0-20160722212129-ac0cc4484ad4",
				Fixed:        "v0.0.0-20200131131040-063a3fb69896",
				FixedVersion: "v0.0.0-20200131131040-063a3fb69896",
			},
		},
		Symbols: []string{
			"github.com/nanobox-io/golang-nanoauth.Auth.ListenAndServe",
			"github.com/nanobox-io/golang-nanoauth.Auth.ListenAndServeTLS",
			"github.com/nanobox-io/golang-nanoauth.Auth.ServeHTTP",
			"github.com/nanobox-io/golang-nanoauth.ListenAndServe",
			"github.com/nanobox-io/golang-nanoauth.ListenAndServeTLS",
		},
		CWEs:    []string{"CWE-305", "CWE-287"},
		Summary: "authentication bypass: authentication is globally bypassed in golang-nanoauth between the introduced and fixed pseudo-versions when ListenAndServe is called with an empty token; a timing side-channel may also allow token recovery",
	},

	// --- real public dependency advisories for Maven / npm / PyPI / NuGet ----------------------
	//
	// Twelve real, currently-published advisories, three per non-Go ecosystem. They are the DEFAULT
	// advisory floor for Java, JS, Python and .NET, exactly as the real Go advisories above are for
	// Go, and they are what makes a default scan of those repositories complete.
	//
	// Until 2026-08-05 the only Maven/npm/PyPI/NuGet entries in this table were the TEGRON-* house
	// canaries below, which are gated off the default surface because they carry no CVE. That left
	// the default floor for four of the five supported languages EMPTY, and scanWorkSet halts a run
	// whose work set resolves to zero — so a default Java, JS, Python or .NET scan could not
	// complete at all.
	//
	// The OSV work-set widening does not close that gap, which is the thing prose kept asserting
	// and nobody measured. admitByFacts admits only ids this table can already resolve, so with no
	// non-Go facts it admits nothing. Measured 2026-08-05 against api.osv.dev: a jackson-databind
	// tree got 55 real GHSA ids back and admitted 0; a requests/pyyaml tree 8 and 0; a
	// Newtonsoft.Json tree 1 and 0. All four still halted. The floor was the missing piece.
	//
	// These twelve were already AUTHORED, as on-disk fixtures under corpus/testdata/advisories/,
	// and never wired into the table — the work was done and left unconnected. Promoting them
	// verbatim is why each carries real Symbols: the reachability axis has something to resolve, so
	// a finding is decided by version AND reachability rather than refuted on an advisory that
	// declared no symbol to be absent.
	//
	// RANGES RE-VERIFIED against api.osv.dev on 2026-08-05, every entry, against the CVE record and
	// its GHSA/PYSEC aliases. Three fixtures disagreed with the published affected set and are
	// corrected here; see each entry. CWEs are left as authored — they never decide a verdict
	// (inv.5) — and the places where the OSV record assigns a different id are recorded in the
	// cycle deposit rather than silently reconciled.
	"CVE-2019-14540": {
		Coordinate:    "com.fasterxml.jackson.core:jackson-databind",
		Aliases:       []string{"GHSA-h822-r4r5-v8jg"},
		VersionScheme: "maven",
		PURL:          "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
		// CORRECTED 2026-08-05. The authored fixture carried ONLY the [2.9.0, 2.9.10) branch, so a
		// repository on 2.8.0 — genuinely affected, and covered by the published advisory — was
		// provably outside the recorded set and would have been refuted not_exploitable. A false
		// negative is the one outcome this scanner may never produce, so the other two branches
		// published by GHSA-h822-r4r5-v8jg are restored.
		AffectedRanges: []Range{
			{Fixed: "2.6.7.3", FixedVersion: "2.6.7.3"},
			{Introduced: "2.7.0", Fixed: "2.8.11.5", FixedVersion: "2.8.11.5"},
			{Introduced: "2.9.0", Fixed: "2.9.10", FixedVersion: "2.9.10"},
		},
		Symbols: []string{
			"com.fasterxml.jackson.databind.ObjectMapper.readValue",
			"com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping",
		},
		CWEs:    []string{"CWE-502"},
		Summary: "deserialization of untrusted data: jackson-databind polymorphic typing did not block the com.zaxxer.hikari.HikariConfig gadget, so an attacker-controlled type in a readValue payload reaches a JNDI lookup",
	},
	"CVE-2020-36518": {
		Coordinate:    "com.fasterxml.jackson.core:jackson-databind",
		Aliases:       []string{"GHSA-57j2-w4cx-62h2"},
		VersionScheme: "maven",
		PURL:          "pkg:maven/com.fasterxml.jackson.core/jackson-databind",
		AffectedRanges: []Range{
			{Fixed: "2.12.6.1", FixedVersion: "2.12.6.1"},
			{Introduced: "2.13.0", Fixed: "2.13.2.1", FixedVersion: "2.13.2.1"},
		},
		Symbols: []string{"com.fasterxml.jackson.databind.ObjectMapper.readValue"},
		CWEs:    []string{"CWE-787"},
		Summary: "denial of service: jackson-databind recursively parses deeply nested JSON with no depth limit, raising a Java StackOverflowError; fixed on both the 2.12.x and 2.13.x branches",
	},
	"CVE-2024-22243": {
		Coordinate:    "org.springframework:spring-web",
		Aliases:       []string{"GHSA-ccgv-vj62-xf9h"},
		VersionScheme: "maven",
		PURL:          "pkg:maven/org.springframework/spring-web",
		AffectedRanges: []Range{
			{Introduced: "5.3.0", Fixed: "5.3.32", FixedVersion: "5.3.32"},
			{Introduced: "6.0.0", Fixed: "6.0.17", FixedVersion: "6.0.17"},
			{Introduced: "6.1.0", Fixed: "6.1.4", FixedVersion: "6.1.4"},
		},
		Symbols: []string{
			"org.springframework.web.util.UriComponentsBuilder.build",
			"org.springframework.web.util.UriComponentsBuilder.getHost",
		},
		CWEs:    []string{"CWE-601"},
		Summary: "open redirect / SSRF: UriComponentsBuilder parses the userinfo segment of an externally provided URL so a host check on the parsed result can be made to disagree with where the request is actually sent",
	},
	"CVE-2022-46175": {
		Coordinate:    "json5",
		Aliases:       []string{"GHSA-9c47-m6qq-7p4h"},
		VersionScheme: "npm",
		PURL:          "pkg:npm/json5",
		AffectedRanges: []Range{
			{Fixed: "1.0.2", FixedVersion: "1.0.2"},
			{Introduced: "2.0.0", Fixed: "2.2.2", FixedVersion: "2.2.2"},
		},
		Symbols: []string{"json5.parse"},
		CWEs:    []string{"CWE-1321"},
		Summary: "prototype pollution: JSON5.parse does not restrict a __proto__ key, so parsing crafted input pollutes the prototype of the returned object",
	},
	"CVE-2023-26136": {
		Coordinate:     "tough-cookie",
		Aliases:        []string{"GHSA-72xf-g2v4-qvf3"},
		UpperExclusive: "4.1.3",
		FixedVersion:   "4.1.3",
		VersionScheme:  "npm",
		PURL:           "pkg:npm/tough-cookie",
		Symbols:        []string{"MemoryCookieStore.putCookie", "CookieJar.setCookie"},
		CWEs:           []string{"CWE-1321"},
		Summary:        "prototype pollution: tough-cookie's cookie memstore index is a plain object, so a crafted __proto__ domain/path reaches Object.prototype",
	},
	"CVE-2024-29041": {
		Coordinate:    "express",
		Aliases:       []string{"GHSA-rv95-896h-c2vc"},
		VersionScheme: "npm",
		PURL:          "pkg:npm/express",
		// The published set also carries a [5.0.0-alpha.1, 5.0.0-beta.3) prerelease branch. It is
		// NOT recorded here: the npm comparator rejects prerelease bounds, and one unparseable
		// range makes versionOutsideRanges fail OPEN across the whole set (it disqualifies only on
		// provably-outside EVERY range), which would delete the version axis for the 4.x users this
		// advisory is actually about. A 5.x prerelease version fails open on its own account, so no
		// affected release is refuted by the omission — verified 2026-08-05.
		UpperExclusive: "4.19.2",
		FixedVersion:   "4.19.2",
		Symbols:        []string{"express.response.location", "express.response.redirect"},
		CWEs:           []string{"CWE-601"},
		Summary:        "open redirect: Express passes a user-provided URL through encodeurl after allow-list validation, so a malformed URL can be normalized into an off-site redirect",
	},
	"CVE-2024-22195": {
		// PyPI and NuGet entries below carry an EXPLICIT VersionScheme, as the authored fixtures
		// did; schemeFromPURL would derive the same value from the PURL type.
		Coordinate:     "jinja2",
		Aliases:        []string{"GHSA-h5c8-rqwp-cp95", "GHSA-h75v-3vvj-5mfj"},
		UpperExclusive: "3.1.3",
		FixedVersion:   "3.1.3",
		VersionScheme:  "pypi",
		PURL:           "pkg:pypi/jinja2",
		Symbols:        []string{"jinja2.filters.do_xmlattr"},
		CWEs:           []string{"CWE-79"},
		Summary:        "cross-site scripting: the Jinja2 xmlattr filter accepts attribute keys containing spaces, allowing HTML attribute injection when user input is passed as keys",
	},
	"CVE-2024-23334": {
		Coordinate:    "aiohttp",
		Aliases:       []string{"GHSA-5h86-8mv2-jq9f"},
		VersionScheme: "pypi",
		PURL:          "pkg:pypi/aiohttp",
		// CORRECTED 2026-08-05: the authored fixture bounded this below at zero; the published set
		// is introduced at 1.0.5. Widening below the real introduction over-reports rather than
		// under-reports, so nothing unsound shipped, but the recorded range must be the published
		// one or the citation does not check out.
		AffectedRanges: []Range{{Introduced: "1.0.5", Fixed: "3.9.2", FixedVersion: "3.9.2"}},
		Symbols: []string{
			"aiohttp.web_urldispatcher.StaticResource._handle",
			"aiohttp.web.UrlDispatcher.add_static",
		},
		CWEs:    []string{"CWE-22"},
		Summary: "path traversal: aiohttp.web.static(follow_symlinks=True) serves files outside the static root when the request path traverses a symlink",
	},
	"CVE-2024-3772": {
		Coordinate:    "pydantic",
		Aliases:       []string{"GHSA-mr82-8j83-vxmv"},
		VersionScheme: "pypi",
		PURL:          "pkg:pypi/pydantic",
		AffectedRanges: []Range{
			{Fixed: "1.10.13", FixedVersion: "1.10.13"},
			{Introduced: "2.0.0", Fixed: "2.4.0", FixedVersion: "2.4.0"},
		},
		CWEs:    []string{"CWE-1333"},
		Summary: "regular expression denial of service: pydantic email validation regex is vulnerable to catastrophic backtracking on a crafted address",
	},
	"CVE-2019-0820": {
		Coordinate:    "System.Text.RegularExpressions",
		Aliases:       []string{"GHSA-cmhx-cq75-c4mj"},
		VersionScheme: "nuget",
		PURL:          "pkg:nuget/System.Text.RegularExpressions",
		// CORRECTED 2026-08-05: introduced at 4.3.0 per GHSA-cmhx-cq75-c4mj, not at zero.
		AffectedRanges: []Range{{Introduced: "4.3.0", Fixed: "4.3.1", FixedVersion: "4.3.1"}},
		CWEs:           []string{"CWE-1333"},
		Summary:        "regular expression denial of service in System.Text.RegularExpressions (.NET Core) timeout handling, fixed in 4.3.1",
	},
	"CVE-2020-5234": {
		Coordinate:    "MessagePack",
		Aliases:       []string{"GHSA-7q36-4xx7-xcxf"},
		VersionScheme: "nuget",
		PURL:          "pkg:nuget/MessagePack",
		AffectedRanges: []Range{
			{Fixed: "1.9.11", FixedVersion: "1.9.11"},
			{Introduced: "2.0.0", Fixed: "2.1.90", FixedVersion: "2.1.90"},
		},
		Symbols: []string{
			"MessagePack.MessagePackSerializer.Typeless.Deserialize",
			"MessagePack.MessagePackSerializer.Deserialize",
		},
		CWEs:    []string{"CWE-502"},
		Summary: "deserialization of untrusted data: MessagePack Typeless deserialization of attacker-controlled input enables hostile type instantiation",
	},
	"CVE-2024-21907": {
		Coordinate:     "Newtonsoft.Json",
		Aliases:        []string{"GHSA-5crp-9r3c-p9vr"},
		UpperExclusive: "13.0.1",
		FixedVersion:   "13.0.1",
		VersionScheme:  "nuget",
		PURL:           "pkg:nuget/Newtonsoft.Json",
		Symbols: []string{
			"Newtonsoft.Json.JsonConvert.DeserializeObject",
			"Newtonsoft.Json.JsonConvert.SerializeObject",
		},
		CWEs:    []string{"CWE-400"},
		Summary: "uncontrolled resource consumption: Newtonsoft.Json parses arbitrarily deeply nested JSON with no default MaxDepth, enabling a StackOverflow/CPU denial of service",
	},
}

func (s advisoryIntake) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	vulnID := c.Request.Vulnerability.ID
	src := s.src
	if src == nil {
		src = defaultAdvisorySource()
	}
	facts, _ := src.Lookup(vulnID) // miss → zero facts → fail-open downstream (bool intentionally discarded)

	// Resolve the version comparator scheme (§3): an explicit VersionScheme wins, otherwise
	// derive it from the corpus PURL (pkg:pypi→pypi, pkg:nuget→nuget, pkg:maven→maven,
	// pkg:npm→npm, pkg:golang→gomod). This SELECTS a comparator only — it never concludes;
	// an unknown/absent PURL leaves the scheme "" so the default semver path runs and fails
	// open on any uncertainty (inv.5). No path here fabricates a not-affected.
	scheme := facts.VersionScheme
	if scheme == "" {
		scheme = schemeFromPURL(facts.PURL)
	}

	// Carry the advisory's full affected set into the artifact. A backport/split-fix advisory
	// declares disjoint AffectedRanges (each OSV-shaped Range's Fixed is the per-branch
	// upper-exclusive bound); the version axis reasons over all of them (versionOutsideRanges).
	// When the advisory declares no structured ranges, fall back to the legacy single
	// UpperExclusive bound so today's behavior is preserved (an empty Fixed carries through as an
	// empty upper, which fails the version axis OPEN downstream, inv.5).
	ranges := buildAffectedRanges(facts.AffectedRanges, facts.UpperExclusive, scheme)

	// v3 multi-package set (cycle 2026-07-23-affected-block-multipkg, wiring R1): emit the FULL
	// affected_packages[] onto the normalized-advisory artifact so the downstream extractors can
	// pick the element codebase_inventory selected against the target. Each element carries its OWN
	// version scheme (an explicit per-package VersionScheme wins, else derived from the element's
	// PURL) and its own ranges/symbols. Advisory-level fields are NOT repeated — they live top-level.
	// Empty for a v2/single-package advisory (facts.AffectedPackages nil) → the array is omitted and
	// every extractor falls to the scalar block (today's exact behavior, inv.5).
	var affectedPackages []advisoryAffectedPackage
	for _, p := range facts.AffectedPackages {
		pkgScheme := p.VersionScheme
		if pkgScheme == "" {
			pkgScheme = schemeFromPURL(p.PURL)
		}
		affectedPackages = append(affectedPackages, advisoryAffectedPackage{
			Module:         p.Module,
			Coordinate:     p.Coordinate,
			PURL:           p.PURL,
			AffectedRanges: buildAffectedRanges(p.AffectedRanges, p.UpperExclusive, pkgScheme),
			Symbols:        p.Symbols,
		})
	}
	// Recognize the vulnerability class from CWE + summary (vulnclass.ClassifyAdvisory). Advisory-
	// only (inv.5): shapes live-confirmation framing and selects the proof route, but NEVER decides
	// a verdict and never touches the proven gate. An unrecognized advisory yields ClassUnknown.
	vulnClass := resolveVulnClass(facts)
	// v3 trigger descriptor (row 1): stamp the per-CVE reach descriptor onto the artifact so the
	// Service-side PoE class-framing can interpolate it per-CVE. Omitted when zero (constant framing
	// fallback) and when withdrawn (no live route). Advisory framing only — never a verdict (inv.5).
	var advTrigger *advisoryTrigger
	if !facts.Withdrawn && !facts.Trigger.Zero() {
		advTrigger = &advisoryTrigger{
			IngressKind:    facts.Trigger.IngressKind,
			Route:          facts.Trigger.Route,
			Param:          facts.Trigger.Param,
			MalformedToken: facts.Trigger.MalformedToken,
		}
	}
	// Carry the malicious-package marker onto the artifact so the maliciousPresence stage can read
	// the enumerated affected set back. Emitted IFF the advisory DECLARED the marker — a nil marker
	// (v2/non-MAL advisory) is omitted, so no presence path exists (inv.5 fail-open). An
	// empty-but-declared set carries through as an empty array, which the stage reads as un-decidable
	// → OPEN.
	var advMalicious *advisoryMaliciousPackage
	if facts.MaliciousPackage.Declared {
		advMalicious = &advisoryMaliciousPackage{AffectedVersions: facts.MaliciousPackage.AffectedVersions}
	}
	// B-guardsuff: project the advisory's DECLARED guard_sufficiency onto the artifact so the Assess
	// tier can annotate an on-path guard with its declared sufficiency (candidate context only). This is
	// the one Prove→Assess projection the consumer needs, and it crosses as DECLARED ADVISORY DATA — the
	// same grade as advisory_guards above — never as a Prove sufficiency verdict. Absent ⇒ nil ⇒ omitted
	// (honest-absent, inv.5): a candidate-scoped descriptive label, structurally incapable of a verdict.
	var advGuardSuff []advisoryGuardVariant
	for _, g := range facts.GuardSufficiency {
		advGuardSuff = append(advGuardSuff, advisoryGuardVariant{
			Symbol:     g.Symbol,
			Version:    g.Version,
			ForBypass:  g.ForBypass,
			Sufficient: g.Sufficient,
		})
	}
	advisory := struct {
		VulnID           string                    `json:"vuln_id"`
		Source           string                    `json:"source"`
		Module           string                    `json:"module,omitempty"`
		Aliases          []string                  `json:"aliases,omitempty"`
		AffectedRanges   []affectedRange           `json:"affected_ranges,omitempty"`
		FixedVersion     string                    `json:"fixed_version,omitempty"`
		PURL             string                    `json:"purl,omitempty"`
		AdvisorySymbols  []string                  `json:"advisory_symbols,omitempty"`
		SymbolProvenance string                    `json:"symbol_provenance,omitempty"` // B1: record-scoped derivation tag, read as a candidate-only STRENGTH signal (never admission/refute)
		AdvisoryGuards   []string                  `json:"advisory_guards,omitempty"`
		CWEs             []string                  `json:"cwes,omitempty"`
		VulnClass        string                    `json:"vuln_class,omitempty"`        // "" ⇒ class not assessed (honest)
		TrustTier        string                    `json:"trust_tier,omitempty"`        // gates refute eligibility (inv.5); "" ⇒ untrusted
		Trigger          *advisoryTrigger          `json:"trigger,omitempty"`           // v3 per-CVE reach descriptor (row 1)
		TriggerCondition string                    `json:"trigger_condition,omitempty"` // B3: advisory-declared exploit precondition, read as candidate-only PoE qualifier context (never admission/refute)
		Prerequisite     string                    `json:"prerequisite,omitempty"`      // B3: advisory-declared mechanism precondition, read alongside TriggerCondition
		AffectedPackages []advisoryAffectedPackage `json:"affected_packages,omitempty"`
		MaliciousPackage *advisoryMaliciousPackage `json:"malicious_package,omitempty"` // MAL presence-verdict marker
		GuardSufficiency []advisoryGuardVariant    `json:"guard_sufficiency,omitempty"` // B-guardsuff: advisory-DECLARED guard sufficiency, read as a candidate-only descriptive annotation on on-path guards (never admission/refute)
	}{
		VulnID:           vulnID,
		Source:           c.Request.Vulnerability.Source,
		Module:           facts.Module,
		Aliases:          facts.Aliases,
		AffectedRanges:   ranges,
		FixedVersion:     facts.FixedVersion,
		PURL:             facts.PURL,
		AdvisorySymbols:  facts.Symbols,
		SymbolProvenance: facts.SymbolProvenance,
		AdvisoryGuards:   facts.GuardSymbols,
		CWEs:             facts.CWEs,
		VulnClass:        string(vulnClass),
		TrustTier:        string(facts.Provenance.TrustTier),
		Trigger:          advTrigger,
		TriggerCondition: facts.TriggerCondition,
		Prerequisite:     facts.Prerequisite,
		AffectedPackages: affectedPackages,
		MaliciousPackage: advMalicious,
		GuardSufficiency: advGuardSuff,
	}
	if _, err := PutArtifact(store, c, s.Name(), artifact.TypeNormalizedAdvisory, "normalized advisory", advisory); err != nil {
		return err
	}
	// public_poc availability comes from the corpus poc_signal (AdvisoryFacts.PocSignal),
	// feeding the downstream public_poc_adaptation instrument. Zero value false ⇒ no PoC,
	// unchanged behavior when the corpus is silent. Advisory-only capability-cost signal;
	// never decides a verdict (inv.5).
	//
	// Summary (v3, row 3) carries the public PoC's clinical trigger SHAPE (from the corpus
	// poc_summary) — a VALUE-level description the model ADAPTS from, never a weaponized payload
	// (memory clinical-register-terminology). Empty when the corpus declares no summary
	// (free-tier path: PocSignal alone still routes to adaptation). Advisory framing only (inv.5).
	poc := struct {
		Available bool   `json:"available"`
		Summary   string `json:"summary,omitempty"`
	}{Available: facts.PocSignal, Summary: facts.PocSummary}
	descriptor := "public PoC (none declared)"
	if poc.Available {
		descriptor = "public PoC (available)"
	}
	if _, err := PutArtifact(store, c, s.Name(), artifact.TypePublicPoC, descriptor, poc); err != nil {
		return err
	}
	return nil
}

// --- Stage 2: codebase_inventory ----------------------------------------------

type codebaseInventory struct {
	checkout checkout.Checkout
	plugin   plugin.LanguagePlugin
	// src is the AdvisorySource this stage reads advisory facts through (U8a intake seam). A nil
	// src falls back to defaultAdvisorySource() — the in-memory AdvisoryTable — so the default path
	// is byte-identical to the historical inline AdvisoryTable[id] lookup.
	src AdvisorySource
	// subjectGoVersion/ciGoVersion are the two candidate EXACT subject-toolchain sources this stage
	// cannot discover from the tree on disk (ADR 0014 tiers 1–2): the subject's own declaration and
	// the Go the CI runner already had before the Action installed the scanner's. Both empty is the
	// normal non-Action case and simply leaves the fact to the go.mod floors.
	//
	// trustCIGoVersion is the caller's assertion that ciGoVersion describes the SUBJECT. Absent it,
	// the observation is discarded rather than demoted — see resolveToolchainFact.
	subjectGoVersion string
	ciGoVersion      string
	trustCIGoVersion bool
}

func (codebaseInventory) Name() string              { return "codebase_inventory" }
func (codebaseInventory) Status() assessment.Status { return assessment.StatusInventory }

// resolveDependencyVersion reads the version the assessed codebase declares for one advisory
// package: the go.mod require version for a Go module, or the plugin's resolved dependency version
// for a managed-ecosystem coordinate. It returns "" when the codebase does not depend on the
// package (the go.mod/manifest has no such entry) or the version cannot be pinned — the caller
// reads "" as "this package is not (resolvably) present." partiality carries the plugin resolver's
// disclosure reasons when a coordinate was found but its version could not be fully pinned. This is
// the SAME resolution the scalar path always ran; select-by-target just iterates it over candidates.
//
// A "go-toolchain" scheme package (the Go stdlib/toolchain entry: empty module, coordinate
// "stdlib") is not a plugin-resolvable dependency coordinate: the version it is adjudicated against
// is the SUBJECT'S TOOLCHAIN, resolved once per run into the bounded ToolchainFact (ADR 0014), not
// a version any manifest or plugin resolver can report. So it takes the toolchain fact directly and
// returns before the plugin branch — which also means a Go plugin that errors on the non-go.mod
// "stdlib" coordinate can never abort Run (the PR #219 guard, preserved).
//
// Bound is what licenses this. goToolchainVersionOutsideRange is monotone non-decreasing in its
// version argument, so for a floor f on the true toolchain t (t >= f), outside(f, u) implies
// outside(t, u): both "exact" and "minimum" may feed the version axis, because the only conclusion
// it can draw is "provably past the fix", and a floor past the fix proves the real toolchain is
// past it. An unresolved fact yields "" and the axis fails OPEN, unchanged (inv.5).
//
// This is the ONLY production writer of a go-toolchain-shaped resolved_version. Before it, the
// U7 comparator had no reachable input and the axis was dark for exactly the advisory class whose
// verdict depends on the toolchain (ADR 0014 §0). There is no "separate comparator path off the
// AdvisoryTable" — the AdvisoryTable supplies the affected RANGE, never a version.
func (s codebaseInventory) resolveDependencyVersion(ctx context.Context, buildDir, language, module, coordinate, scheme string, toolchain ToolchainFact) (version string, partiality []string, err error) {
	if scheme == "go-toolchain" {
		switch toolchain.Bound {
		case ToolchainBoundExact, ToolchainBoundMinimum:
			return toolchain.Version, nil, nil
		default:
			return "", nil, nil
		}
	}
	switch {
	case module != "":
		// A Go module coordinate resolves off go.mod with no plugin involved, so this branch
		// carried no partiality at all — every Go scan disclosed nothing. Distinguish the two
		// ways the version comes back empty: an unreadable/unparseable go.mod means the
		// version could not be established (disclose no_manifest), whereas a go.mod that
		// parses and simply does not require the module means the codebase genuinely does not
		// depend on it (honest absence — no disclosure, so a true not_exploitable stays
		// unqualified).
		v, manifestRead := moduleVersionFromGoMod(buildDir, module)
		if !manifestRead {
			return "", []string{plugin.PartialReasonNoManifest}, nil
		}
		return v, nil, nil
	case coordinate != "" && s.plugin != nil && s.plugin.Language() == language:
		vr, err := s.plugin.ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{
			BuildDir:   buildDir,
			Coordinate: coordinate,
		})
		if err != nil {
			return "", nil, err
		}
		v := ""
		if vr.Found && vr.Match.Resolved {
			v = vr.Match.Version
		}
		// Persist WHY the resolution was incomplete (e.g. "no_manifest"): a degraded resolve leaves
		// the version empty, which downstream is indistinguishable from "this codebase has no such
		// dependency". Carrying the reason is what makes an unresolvable scan distinguishable from a
		// clean one at the customer surface — the flags are disclosure only and gate no verdict.
		var flags []string
		if !vr.Partiality.Complete {
			flags = append(flags, vr.Partiality.Reasons...)
		}
		return v, flags, nil
	}
	// A managed-ecosystem coordinate with no language-matched analyzer available (the
	// tegron-plugin-<lang> binary is not on PATH, so acquire selected nothing, or the
	// detected tree language does not match the advisory's ecosystem). The version cannot
	// be established, and returning it bare reads downstream as "not installed" — which
	// disqualifies the advisory on a version comparison that never happened. Disclose the
	// absence instead; the verdict is untouched.
	if coordinate != "" {
		return "", []string{plugin.PartialReasonNoPlugin}, nil
	}
	return "", nil, nil
}
func (s codebaseInventory) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	buildDir, language := "", ""
	var plan checkout.WorkspacePlan
	acq := c.Request.Codebase.Acquisition
	switch {
	case acq.Mode == "vendored_repro":
		p, err := checkout.ResolveVendored(acq.Path)
		if err != nil {
			return err
		}
		plan = p
	case s.checkout != nil:
		// Thread the per-fire ownership token onto the context so GitCheckout can authenticate a
		// PRIVATE-repo clone on the credential-fenced fire VM. It rides in-flight only;
		// an empty token (public repo / hermetic FakeCheckout / local ambient-cred dev) is a no-op
		// and takes today's bare-clone path unchanged.
		fctx := checkout.WithCredential(ctx, checkout.NewCredential(c.Request.OwnershipProof.Token))
		p, err := s.checkout.Fetch(fctx, c.Request.Codebase.Repo, c.Request.Codebase.Revision)
		if err != nil {
			return err
		}
		plan = p
	}
	// Project the plan's single project into the scalar build_dir/language that S3–S6 already read.
	// The plan holds exactly one project today (PLAN-004); PLAN-400 enumerates true monorepos and the
	// per-project fan-out reads plan.Projects. An empty plan means no acquisition ran (nil checkout,
	// non-vendored mode) — the historical no-op path, which leaves buildDir/language empty.
	if len(plan.Projects) > 0 {
		prim := plan.Primary()
		buildDir, language = prim.Root, prim.Language
	}

	// Pin the concrete commit SHA the assessment was checked out at (T1 reproducibility anchor):
	// the requested Revision is a branch/tag/ref; rev-parse resolves it to the exact commit so a
	// third party knows precisely which source was assessed. The orchestrator persists this Subject
	// mutation after the stage, so it reaches verdict-emission (firepersist projects it into
	// proof_verdicts.subject_repo_ref). Fails soft to "" for the vendored_repro path (not a git
	// tree); only an explicit ResolvedCommit on the request (OSS --commit) takes precedence.
	if buildDir != "" && c.Subject.ResolvedCommit == "" {
		if sha, err := checkout.ResolveHead(ctx, buildDir); err != nil {
			return err
		} else if sha != "" {
			c.Subject.ResolvedCommit = sha
		}
	}

	module, goVersion, buildCommand, toolchainDirective := "", "", "", ""
	if s.plugin != nil && buildDir != "" && s.plugin.Language() == language {
		mani, err := s.plugin.BuildManifest(ctx, plugin.BuildManifestRequest{BuildDir: buildDir})
		if err != nil {
			return err
		}
		module = mani.ProjectRoot
		goVersion = mani.Runtime.Version
		buildCommand = mani.Resolver.Command
		toolchainDirective = mani.Runtime.Toolchain
	}

	// The subject's Go toolchain as ONE resolved fact carrying its own strength (ADR 0014). This is
	// the single resolution site: the raw go_version above stays exactly what it was (the verbatim
	// `go` directive, read by nobody) and the fact is derived beside it, never instead of it. It is
	// resolved BEFORE dependency-version resolution because the version axis consumes it: for a
	// go-toolchain-scheme advisory this fact IS resolved_version.
	//
	// Go-only by construction. Both floors are go.mod directives and both exact tiers are statements
	// about a Go build environment, so resolving this for a JS/Java/Python/.NET subject would label
	// the RUNNER's Go as the subject's — the same category error the fact exists to close. (The prior
	// BuildManifestResult.GoVersion overload — jsanalysis stuffing a node engine range into a Go-named
	// field — is gone: PLAN-000's ecosystem-neutral rework carries it in Runtime{Name:"node"} instead.)
	toolchain := ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}
	if language == "go" {
		toolchain = resolveToolchainFact(toolchainInputs{
			subjectDeclared:    s.subjectGoVersion,
			ciObserved:         s.ciGoVersion,
			trustCIObserved:    s.trustCIGoVersion,
			toolchainDirective: toolchainDirective,
			goDirective:        goVersion,
		})
	}

	src := s.src
	if src == nil {
		src = defaultAdvisorySource()
	}
	facts, _ := src.Lookup(c.Request.Vulnerability.ID) // miss → zero facts → fail-open (bool intentionally discarded)
	resolvedVersion := ""
	var partialityFlags []string
	// selectedModule/selectedCoordinate name the v3 affected_packages[] element the target actually
	// depends on (the select-by-target pick). They are the join key the downstream extractors use to
	// read the SELECTED element's ranges/symbols/identity off the normalized-advisory artifact. Both
	// empty ⇒ no element selected: the scalar-primary path ran (a v2 advisory, or a v3 advisory whose
	// packages the target does not depend on → OPEN).
	var selectedModule, selectedCoordinate string
	if buildDir != "" {
		// v3 select-by-target: iterate the advisory's full affected set (producer-sorted,
		// deterministic) and pick the FIRST package the assessed codebase actually depends on. This
		// is the whole point of the multi-package block — a target on a SECONDARY package resolves
		// into real version/symbol analysis instead of falling OPEN against an unmatched primary.
		for _, pkg := range facts.AffectedPackages {
			v, flags, err := s.resolveDependencyVersion(ctx, buildDir, language, pkg.Module, pkg.Coordinate, pkg.VersionScheme, toolchain)
			if err != nil {
				return err
			}
			if v != "" {
				resolvedVersion, partialityFlags = v, flags
				selectedModule, selectedCoordinate = pkg.Module, pkg.Coordinate
				break
			}
		}
		// Fail-open (inv.5, load-bearing): no array element matched THIS target (or the advisory is
		// v2/single-package: AffectedPackages is empty) → fall back to the scalar primary. This is
		// byte-identical to the pre-v3 resolution, so a v2 advisory and a v3-no-match target both get
		// today's exact behavior (typically OPEN). Selection NEVER fabricates a not-affected.
		if selectedModule == "" && selectedCoordinate == "" {
			v, flags, err := s.resolveDependencyVersion(ctx, buildDir, language, facts.Module, facts.Coordinate, facts.VersionScheme, toolchain)
			if err != nil {
				return err
			}
			resolvedVersion, partialityFlags = v, flags
		}
	}

	inv := struct {
		Repo     string `json:"repo"`
		Revision string `json:"revision"`
		BuildDir string `json:"build_dir"`
		Language string `json:"language,omitempty"`
		// WorkspacePlan is the full enumeration of detected projects (one today; PLAN-400 makes it
		// hold true monorepos). It is PERSISTED but not yet read by any downstream stage — the scalar
		// build_dir/language above remain the primary-project projection S3–S6 consume. Landing the
		// field now (the PLAN-000 pattern) makes the contract real end-to-end; PLAN-400 wires the
		// per-project readers. Not dead code: it is the on-disk half of the WorkspacePlan contract.
		WorkspacePlan   checkout.WorkspacePlan `json:"workspace_plan"`
		ResolvedVersion string                 `json:"resolved_version,omitempty"`
		Module          string                 `json:"module,omitempty"`
		GoVersion       string                 `json:"go_version,omitempty"`
		BuildCommand    string                 `json:"build_command,omitempty"`
		PartialityFlags []string               `json:"partiality_flags,omitempty"`
		// Toolchain is the subject's Go toolchain resolved to one bounded fact (ADR 0014). Always
		// emitted, including as {"bound":"none","source":"unresolved"} — an explicit "we looked and
		// established nothing" is a disclosure, and a silently absent field is how the version axis
		// stayed dark. Read back by Toolchain() (the version axis, and the scan-level disclosure
		// trigger/assess.go emits for a toolchain advisory it could not adjudicate).
		Toolchain ToolchainFact `json:"toolchain"`
		// SelectedModule/SelectedCoordinate name the v3 affected_packages[] element select-by-target
		// picked (the package the target depends on). They are the join key extractSelectedPackage
		// uses to read the selected element off the normalized-advisory artifact. Both empty ⇒ scalar
		// primary path (v2 advisory or v3-no-match) → extractors read the top-level scalar block.
		SelectedModule     string `json:"selected_module,omitempty"`
		SelectedCoordinate string `json:"selected_coordinate,omitempty"`
	}{
		Repo:               c.Request.Codebase.Repo,
		Revision:           c.Request.Codebase.Revision,
		BuildDir:           buildDir,
		Language:           language,
		WorkspacePlan:      plan,
		ResolvedVersion:    resolvedVersion,
		Module:             module,
		GoVersion:          goVersion,
		BuildCommand:       buildCommand,
		PartialityFlags:    partialityFlags,
		Toolchain:          toolchain,
		SelectedModule:     selectedModule,
		SelectedCoordinate: selectedCoordinate,
	}
	_, err := PutArtifact(store, c, s.Name(), artifact.TypeInventory, "codebase inventory", inv)
	return err
}

// moduleVersionFromGoMod parses buildDir/go.mod and returns the resolved version of the given
// module path (the version on its require directive). Offline read of the pinned dependency
// version.
//
// manifestRead separates the two reasons the version can come back empty, which the caller must
// tell apart: false means go.mod was absent or unparseable, so NOTHING about the dependency set
// was established; true with an empty version means go.mod was read cleanly and does not require
// the module, which is a real fact about the codebase.
func moduleVersionFromGoMod(buildDir, module string) (version string, manifestRead bool) {
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return "", false
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return "", false
	}
	for _, r := range mf.Require {
		if r.Mod.Path == module {
			return r.Mod.Version, true
		}
	}
	return "", true
}

// InventoryBuildDir returns the BuildDir recorded by codebase_inventory, or "" if none. S4/S5 read
// it back from the inventory artifact; the Prove stages reuse it too. "" is a valid value.
func InventoryBuildDir(store artifact.Store, caseID string) (string, error) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil {
		return "", err
	}
	if len(arts) == 0 {
		return "", nil
	}
	var inv struct {
		BuildDir string `json:"build_dir"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return "", err
	}
	return inv.BuildDir, nil
}

// --- Stage 2b: malicious_presence ---------------------------------------------

// maliciousPresence is the decisive OSS "affected" stage. It fires ONLY on an affirmative match: a
// malicious-package (MAL) advisory whose enumerated affected set contains the version the codebase
// resolved. It reads two already-produced artifacts — the normalized-advisory malicious_package
// marker and the codebase-inventory resolved_version — and NEVER re-Lookups.
//
// It is inserted after codebase_inventory (it needs resolved_version) and before
// disqualification_discovery. It emits the affirmative TypeMaliciousPresence artifact or NOTHING;
// it can never mint a not-affected. Every non-match case (not malicious, unresolvable version,
// version-not-listed) falls through to the existing reconcile path unchanged (inv.5 fail-open):
//
//   - not declared malicious ⇒ no-op ⇒ every existing stage runs as today.
//   - declared + resolved_version == "" (unresolvable/absent) ⇒ no match ⇒ OPEN, never clear.
//   - declared + resolved_version NOT in the enumerated set ⇒ no affirmative ⇒ existing fail-open.
//   - declared + resolved_version IN the set (EXACT string equality, no comparator) ⇒ affirmative.
//
// Exact string equality is deliberate: MAL versions are enumerated, not ranged, and any spelling
// drift between the resolved-version and corpus-version fails toward NO match ⇒ OPEN (safe), never a
// fabricated clear. An empty enumerated set (declared but no versions) is un-decidable ⇒ no match ⇒
// OPEN.
type maliciousPresence struct{}

func (maliciousPresence) Name() string              { return "malicious_presence" }
func (maliciousPresence) Status() assessment.Status { return assessment.StatusInventory }

// MaliciousPresenceResult is the affirmative payload (schema tegron.malicious_presence.v1). It is
// only ever written with Present=true; the stage emits no artifact at all for a non-match. Present
// is carried explicitly so a reader keys on the value, not on mere artifact existence.
type MaliciousPresenceResult struct {
	Present        bool   `json:"present"`
	MatchedVersion string `json:"matched_version"`
}

func (s maliciousPresence) Run(_ context.Context, c *assessment.Assessment, store artifact.Store) error {
	versions, declared := extractMaliciousAffectedVersions(store, c.ID)
	if !declared {
		return nil // not a malicious-package advisory → no presence path (inv.5)
	}
	resolved, ok := extractResolvedVersion(store, c.ID)
	if !ok {
		return nil // resolved_version == "" (unresolvable/absent) → no match → OPEN
	}
	for _, v := range versions {
		if v == resolved { // exact string membership — no semver comparator
			res := MaliciousPresenceResult{Present: true, MatchedVersion: resolved}
			_, err := PutArtifact(store, c, s.Name(), artifact.TypeMaliciousPresence, "malicious package present at listed version", res)
			return err
		}
	}
	return nil // version not in the enumerated set (or empty set) → no affirmative → OPEN
}

// extractMaliciousAffectedVersions reads the malicious-package marker off the normalized-advisory
// artifact. declared reports whether the advisory carried the marker at all (the object was present),
// distinct from an empty version set — the same load-bearing distinction as MaliciousPackageFacts.
// Declared. Any miss/malformed ⇒ (nil, false) ⇒ no presence path (inv.5 fail-open).
func extractMaliciousAffectedVersions(store artifact.Store, caseID string) (versions []string, declared bool) {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil, false
	}
	var adv struct {
		MaliciousPackage *struct {
			AffectedVersions []string `json:"affected_versions"`
		} `json:"malicious_package"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil || adv.MaliciousPackage == nil {
		return nil, false
	}
	return adv.MaliciousPackage.AffectedVersions, true
}

// --- Stage 3: disqualification_discovery --------------------------------------

type disqualificationDiscovery struct{}

func (disqualificationDiscovery) Name() string              { return "disqualification_discovery" }
func (disqualificationDiscovery) Status() assessment.Status { return assessment.StatusInventory }

// DisqualResult is the typed discovery payload (schema tegron.discovery.v1). Reason carries the
// machine-readable basis for proceeding or disqualifying. Exported so verdict_emission (Prove) can
// read the recorded reason code.
type DisqualResult struct {
	Disqualified bool   `json:"disqualified"`
	Reason       string `json:"reason"`
}

// Reason codes recorded in the discovery artifact.
const (
	ReasonVersionNotInRange = "version_not_in_affected_range"
	ReasonSymbolAbsent      = "vulnerable_symbol_absent"
	ReasonInsufficient      = "insufficient_evidence_to_disqualify"

	// Intake disqualification reason codes (M0). These short-circuit advisories that are
	// un-adjudicable BY DESIGN — nothing in the resolved codebase the analysis could ever
	// reach — BEFORE the pipeline spends cycles on symbol mapping / call-graph (S4+). They
	// are DISTINCT from the version/symbol axes above, which record provably-not-affected
	// verdicts; these record "not adjudicable here at all". Like every disqualification axis
	// they fail OPEN on any uncertainty (inv.5): only a PROVABLE mismatch/absence disqualifies.
	ReasonAdvisoryEcosystemMismatch = "advisory_ecosystem_mismatch"
	ReasonNoManifestEntry           = "no_manifest_entry"
)

// affectedRange is the single, unambiguous structured constraint this stage understands: an
// upper-exclusive semver bound (the "affects < X" form).
type affectedRange struct {
	UpperExclusive string `json:"upper_exclusive"`
	Scheme         string `json:"scheme,omitempty"`
}

// advisoryAffectedPackage is one element of the normalized-advisory artifact's affected_packages[]
// (v3 multi-package, cycle 2026-07-23-affected-block-multipkg). It carries the per-package identity
// (Module/Coordinate/PURL) plus the package's own upper-exclusive range set and symbols, each range
// already scheme-tagged so extractAffectedRange consumes the selected element verbatim. Advisory-
// level fields are shared and stay top-level on the artifact. Only fields the downstream select join
// + extractors read are carried; the whole element is omitted for a v2/single-package advisory.
type advisoryAffectedPackage struct {
	Module         string          `json:"module,omitempty"`
	Coordinate     string          `json:"coordinate,omitempty"`
	PURL           string          `json:"purl,omitempty"`
	AffectedRanges []affectedRange `json:"affected_ranges,omitempty"`
	Symbols        []string        `json:"symbols,omitempty"`
}

// advisoryMaliciousPackage is the normalized-advisory artifact's malicious-package marker — what the
// maliciousPresence stage reads back (stages read facts off the artifact, never re-Lookup). Present
// on the artifact IFF the advisory declared the marker (facts.MaliciousPackage.Declared).
type advisoryMaliciousPackage struct {
	AffectedVersions []string `json:"affected_versions,omitempty"`
}

// advisoryGuardVariant is one element of the normalized-advisory artifact's guard_sufficiency[]
// (B-guardsuff, cycle 2026-08-24-corpus-scaffold). It carries the advisory's DECLARED sufficiency
// classification of a named guard variant against a specific bypass — projected onto the artifact so
// the Assess tier can annotate an on-path guard with it as candidate context. It is DECLARED ADVISORY
// DATA at the same grade as advisory_guards, NOT a Prove verdict: Assess never adjudicates sufficiency
// (whether the guard actually closes the hole is a runtime question only the Prove tier settles). The
// whole array is omitted when the advisory declares none (honest-absent, inv.5).
type advisoryGuardVariant struct {
	Symbol     string `json:"symbol,omitempty"`
	Version    string `json:"version,omitempty"`
	ForBypass  string `json:"for_bypass,omitempty"`
	Sufficient bool   `json:"sufficient,omitempty"`
}

// buildAffectedRanges projects an advisory's OSV-shaped Range set (or the legacy single
// UpperExclusive bound) into the stage's upper-exclusive affectedRange form under one version
// scheme. A multi-range advisory yields one entry per range (each range's Fixed is its
// upper-exclusive bound); a legacy single-bound advisory yields one entry; an advisory with no
// structured bound yields nil (the version axis then fails OPEN downstream, inv.5). Shared by the
// scalar-primary emit and the per-element affected_packages[] emit so both project identically.
func buildAffectedRanges(ranges []Range, upperExclusive, scheme string) []affectedRange {
	if len(ranges) > 0 {
		out := make([]affectedRange, 0, len(ranges))
		for _, r := range ranges {
			out = append(out, affectedRange{UpperExclusive: r.Fixed, Scheme: scheme})
		}
		return out
	}
	if upperExclusive != "" {
		return []affectedRange{{UpperExclusive: upperExclusive, Scheme: scheme}}
	}
	return nil
}

// intakeDisqualify decides whether the advisory is un-adjudicable BY DESIGN against the
// resolved codebase, from intake facts alone (advisory ecosystem + resolved manifest), BEFORE
// any symbol/call-graph work. Two guards:
//
//   - Guard 1 (ecosystem mismatch): the advisory's package ecosystem provably differs from the
//     codebase's — an npm advisory against a Java project, a native/generic advisory against a
//     managed-package build. There is no package of the advisory's ecosystem to reach.
//   - Guard 2 (no manifest entry): the advisory names a DEPENDENCY coordinate the resolved
//     manifest provably lacks. No dependency edge exists to reach across. First-party/app-level
//     sinks carry NO dependency coordinate (coordinate==""), so this guard never fires on them —
//     they are handled by first-party reachability downstream, never disqualified here.
//
// Every uncertainty fails OPEN to analysis (inv.5): an empty/ambiguous ecosystem, an unreadable
// manifest, or an empty coordinate proceeds — it NEVER fabricates a disqualification. Ecosystem
// tokens are compared in one namespace (see languageEcosystem / purlEcosystem); manifestKnown is
// false whenever the manifest could not be read, so absence is only "provable" against a manifest
// actually parsed.
func intakeDisqualify(advEco, codeEco, coordinate string, manifestHasCoord, manifestKnown bool) (bool, string) {
	if advEco != "" && codeEco != "" && advEco != codeEco {
		return true, ReasonAdvisoryEcosystemMismatch
	}
	if coordinate != "" && manifestKnown && !manifestHasCoord {
		return true, ReasonNoManifestEntry
	}
	return false, ReasonInsufficient
}

// extractAdvisoryEcosystem reads the normalized advisory's PURL and returns its ecosystem token
// (PURL-type namespace: "golang" | "maven" | "npm" | …), or "" when there is no parseable PURL —
// the intake ecosystem axis then fails open (inv.5).
func extractAdvisoryEcosystem(store artifact.Store, caseID string) string {
	// v3: the intake ecosystem guard must compare the SELECTED package's ecosystem, so a target on a
	// secondary package is judged against the package it actually depends on. No selection (or a
	// selected element with no PURL) → scalar PURL (unchanged).
	if sel, ok := extractSelectedPackage(store, caseID); ok && sel.PURL != "" {
		return purlEcosystem(sel.PURL)
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return ""
	}
	var adv struct {
		PURL string `json:"purl"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return ""
	}
	return purlEcosystem(adv.PURL)
}

// purlEcosystem extracts the type token from a package URL "pkg:<type>/<namespace>/<name>@<ver>".
// It returns "" for an empty or malformed pkg: URL, failing the ecosystem axis open (inv.5).
func purlEcosystem(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return ""
	}
	return strings.ToLower(rest[:i])
}

// extractCodebaseEcosystem reads the inventory's detected language and maps it into the PURL-type
// namespace so it compares against the advisory ecosystem, or "" when the language is
// unknown/undetected (hermetic stub, failed checkout) — failing the ecosystem axis open (inv.5).
func extractCodebaseEcosystem(store artifact.Store, caseID string) string {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return ""
	}
	var inv struct {
		Language string `json:"language"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return ""
	}
	return languageEcosystem(inv.Language)
}

// languageEcosystem maps a pipeline language tag onto the PURL type its packages carry, so the
// codebase and advisory ecosystems compare in one namespace. Unknown/empty → "" (fail open).
func languageEcosystem(language string) string {
	switch language {
	case "go":
		return "golang"
	case "java":
		return "maven"
	case "javascript", "js":
		return "npm"
	default:
		return ""
	}
}

// schemeFromPURL maps a package URL's type token onto the VersionScheme its packages order
// versions under, so the corpus PURL selects the comparator versionOutsideRange already
// dispatches (maven | npm | pypi | nuget), or the default v-semver path for Go and unknowns.
// It is a SPEC, not a judgment (§3): setting a scheme only SELECTS a comparator, it never
// concludes. Every comparator returns (outside, ok) and fails OPEN on any uncertainty
// (inv.5), and an unknown/absent PURL type yields "" → the default semver path, which itself
// fails open on an unparseable bound. So a mis-set or unknown scheme can never fabricate a
// not-affected. "golang" → "gomod" is the default path (gomod is not branched in
// versionOutsideRange), identical to the prior "" behavior for Go advisories.
func schemeFromPURL(purl string) string {
	switch purlEcosystem(purl) {
	case "maven":
		return "maven"
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "nuget":
		return "nuget"
	case "golang":
		return "gomod"
	default:
		return ""
	}
}

// extractAdvisoryModule reads the normalized advisory's dependency coordinate (the Go module path;
// "" for first-party/app-level advisories and for ecosystems that carry no module coordinate). The
// bool reports presence.
func extractAdvisoryModule(store artifact.Store, caseID string) (string, bool) {
	// v3: the intake no-manifest-entry guard must test the SELECTED package's module, not the scalar
	// primary's — else a target on a secondary package would be disqualified because the primary
	// module is absent from go.mod (a false not-affected). No selection → scalar module (unchanged).
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return sel.Module, sel.Module != ""
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", false
	}
	var adv struct {
		Module string `json:"module"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return "", false
	}
	if adv.Module == "" {
		return "", false
	}
	return adv.Module, true
}

// goModRequires is the Go concrete manifest-membership oracle for the intake no-manifest-entry
// guard: it reports whether buildDir/go.mod declares module (as the root module or a require), and
// whether the manifest was readable at all. manifestKnown=false — no build dir, or an absent /
// unparseable go.mod — forces the caller to fail OPEN, because absence is only PROVABLE against a
// manifest actually parsed (inv.5). Other ecosystems have no S3-side manifest reader yet and so
// carry no coordinate through this guard (they fail open); wiring a plugin oracle is a follow-up.
func goModRequires(buildDir, module string) (present bool, manifestKnown bool) {
	if buildDir == "" || module == "" {
		return false, false
	}
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return false, false
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return false, false
	}
	if mf.Module != nil && mf.Module.Mod.Path == module {
		return true, true
	}
	for _, r := range mf.Require {
		if r.Mod.Path == module {
			return true, true
		}
	}
	return false, true
}

// disqualify records a not-affected determination ONLY when provably not-affected; every
// uncertainty fails OPEN to analysis. rngs is the advisory's full affected set (one or more
// disjoint ranges — e.g. a branch-aware backport); the version axis disqualifies only when the
// resolved version is provably outside EVERY range (versionOutsideRanges), never on a subset.
func disqualify(rngs []affectedRange, rangeKnown bool, ver string, verKnown bool, symbol string, symbolKnown bool, trust TrustTier) (bool, string) {
	// inv.5 refute-gate: a not-affected refute may be driven ONLY by a first-party fact. Any other
	// tier (byo / third_party / zero / unrecognized) suppresses BOTH refute reasons and fails OPEN —
	// no laundering a false negative through a low-trust advisory source. This gate can only ever
	// REMOVE refutes: when trust is first_party the behavior below is identical to before.
	if trust != TrustFirstParty {
		return false, ReasonInsufficient
	}
	if symbolKnown && symbol == "absent" {
		return true, ReasonSymbolAbsent
	}
	if rangeKnown && verKnown {
		if outside, ok := versionOutsideRanges(ver, rngs); ok && outside {
			return true, ReasonVersionNotInRange
		}
	}
	return false, ReasonInsufficient
}

// VersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper, under the given comparator scheme ("" / "gomod" | "maven" | "npm").
// It is the exported seam external callers use to
// share the disqualification axis's exact version semantics: ok=false means the
// version or bound is invalid/prerelease/unparseable and the predicate must fail
// OPEN (inv.5), never fabricate a not-affected. Single-sources versionOutsideRange.
func VersionOutsideRange(ver, upperExclusive, scheme string) (outside bool, ok bool) {
	return versionOutsideRange(ver, affectedRange{UpperExclusive: upperExclusive, Scheme: scheme})
}

// versionOutsideRanges reports whether ver is provably outside the ENTIRE affected set — a
// disjoint union of ranges (e.g. a branch-aware backport: the 1.20.x branch fixed at 1.20.10 AND
// mainline fixed at 1.21.3 are TWO ranges, not one bound). ver is disqualifiable (provably
// not-affected) ONLY when it is provably outside EVERY range. SOUNDNESS (inv.5): if any range is
// ambiguous/unparseable/uncertain the whole set fails OPEN (ok=false) — a disjoint set never
// fabricates a not-affected. A version provably INSIDE any one range is definitively still affected
// (ok=true, outside=false), regardless of the other ranges. An empty set is not a proof of anything
// (ok=false).
func versionOutsideRanges(ver string, rngs []affectedRange) (outside bool, ok bool) {
	if len(rngs) == 0 {
		return false, false
	}
	for _, rng := range rngs {
		out, rok := versionOutsideRange(ver, rng)
		if !rok {
			return false, false // uncertainty in any range ⇒ OPEN
		}
		if !out {
			return false, true // provably inside this range ⇒ still affected
		}
	}
	return true, true // provably outside every range
}

// versionOutsideRange reports whether ver is provably outside the affected set affects<upper.
func versionOutsideRange(ver string, rng affectedRange) (outside bool, ok bool) {
	if rng.Scheme == "maven" {
		return mavenVersionOutsideRange(ver, rng.UpperExclusive)
	}
	if rng.Scheme == "npm" {
		return npmDisqualifyOutside(ver, rng.UpperExclusive)
	}
	if rng.Scheme == "pypi" {
		return pypiVersionOutsideRange(ver, rng.UpperExclusive)
	}
	if rng.Scheme == "nuget" {
		return nugetVersionOutsideRange(ver, rng.UpperExclusive)
	}
	// "go-toolchain": Go stdlib/toolchain RELEASE versions (go1.21.3), DISTINCT from the default
	// gomod path below (module semver via golang.org/x/mod/semver, which requires a leading "v"
	// and rejects go1.x). The token is unambiguous — it never collides with gomod, whose scheme
	// is "golang"/"gomod"/"" — and advisories carry it EXPLICITLY (there is no module PURL for the
	// toolchain, so schemeFromPURL never derives it). See go_toolchain_version.go.
	if rng.Scheme == "go-toolchain" {
		return goToolchainVersionOutsideRange(ver, rng.UpperExclusive)
	}
	upper := rng.UpperExclusive
	if !semver.IsValid(ver) || !semver.IsValid(upper) {
		return false, false
	}
	if semver.Prerelease(ver) != "" || semver.Prerelease(upper) != "" {
		return false, false
	}
	return semver.Compare(ver, upper) >= 0, true
}

// extractAffectedRange reads the advisory's full affected set (one or more disjoint ranges) from
// the normalized-advisory artifact. rangeKnown is false — the version axis then fails OPEN (inv.5) —
// when there is no artifact, no range, or ANY range lacks a usable upper-exclusive bound: a set with
// one unexpressable range cannot soundly prove outside-EVERY-range, so the whole set is withheld
// rather than disqualifying on the expressable subset (which would risk a fabricated not-affected).
// extractSelectedPackage joins the codebase_inventory selection back to the normalized-advisory
// affected_packages[] set (v3 wiring R1, cycle 2026-07-23-affected-block-multipkg): it reads the
// selected_module/selected_coordinate the inventory stage recorded, then returns the matching
// affected_packages[] element off the stage-1 normalized-advisory artifact. ok=false whenever there
// is no selection (a v2 advisory, or a v3 advisory whose packages the target does not depend on) OR
// the selected identity matches no array element — in every such case the caller falls to the
// top-level scalar block, which is today's exact behavior (inv.5 fail-open). The select stage only
// ever records an identity present in the array, so a match is the normal case; a miss degrades to
// scalar rather than fabricating anything.
func extractSelectedPackage(store artifact.Store, caseID string) (advisoryAffectedPackage, bool) {
	invArts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(invArts) == 0 {
		return advisoryAffectedPackage{}, false
	}
	var inv struct {
		SelectedModule     string `json:"selected_module"`
		SelectedCoordinate string `json:"selected_coordinate"`
	}
	if err := json.Unmarshal(invArts[0].Payload, &inv); err != nil {
		return advisoryAffectedPackage{}, false
	}
	if inv.SelectedModule == "" && inv.SelectedCoordinate == "" {
		return advisoryAffectedPackage{}, false
	}
	advArts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(advArts) == 0 {
		return advisoryAffectedPackage{}, false
	}
	var adv struct {
		AffectedPackages []advisoryAffectedPackage `json:"affected_packages"`
	}
	if err := json.Unmarshal(advArts[0].Payload, &adv); err != nil {
		return advisoryAffectedPackage{}, false
	}
	for _, p := range adv.AffectedPackages {
		if inv.SelectedModule != "" && p.Module == inv.SelectedModule {
			return p, true
		}
		if inv.SelectedCoordinate != "" && p.Coordinate == inv.SelectedCoordinate {
			return p, true
		}
	}
	return advisoryAffectedPackage{}, false
}

func extractAffectedRange(store artifact.Store, caseID string) ([]affectedRange, bool) {
	// v3: when select-by-target chose a package, the version axis must reason over THAT package's
	// ranges (paired with the version the inventory resolved for it) — not the scalar primary's.
	// A selected element with no usable range withholds the whole set (fails the axis OPEN), exactly
	// as the scalar path does below. No selection → scalar path unchanged (inv.5).
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return validAffectedRanges(sel.AffectedRanges)
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil, false
	}
	var adv struct {
		AffectedRanges []affectedRange `json:"affected_ranges"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return nil, false
	}
	return validAffectedRanges(adv.AffectedRanges)
}

// validAffectedRanges returns the range set only when it is wholly usable: non-empty and every entry
// carries an upper-exclusive bound. A set with one unexpressable range cannot soundly prove
// outside-EVERY-range, so the whole set is withheld (rangeKnown=false → the version axis fails OPEN,
// inv.5) rather than disqualifying on the expressable subset (which would risk a fabricated
// not-affected).
func validAffectedRanges(rngs []affectedRange) ([]affectedRange, bool) {
	if len(rngs) == 0 {
		return nil, false
	}
	for _, r := range rngs {
		if r.UpperExclusive == "" {
			return nil, false
		}
	}
	return rngs, true
}

// ResolvedVersion returns the dependency version the inventory stage resolved for the assessed
// codebase, or ok=false when none was resolved (no inventory artifact, or an empty version). It
// is the exported seam the Prove path (service) uses to place the assessed codebase on a release
// branch when selecting a branch-correct fix baseline from a multi-range (backport) advisory.
func ResolvedVersion(store artifact.Store, caseID string) (string, bool) {
	return extractResolvedVersion(store, caseID)
}

// Toolchain returns the subject's Go toolchain as the bounded fact codebase_inventory resolved
// (ADR 0014 §2.1). ok is false when there is no inventory artifact at all; a run that looked and
// established nothing returns ok=true with {Bound: none, Source: unresolved} — "we could not tell"
// is a fact, and collapsing it into the same ok=false as "no run happened" is what let the version
// axis stay dark. Consumers MUST branch on Bound, never on a non-empty Version: exact licenses a
// reachability refutation, minimum licenses only a disqualification (see ToolchainFact).
func Toolchain(store artifact.Store, caseID string) (ToolchainFact, bool) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return ToolchainFact{}, false
	}
	var inv struct {
		Toolchain ToolchainFact `json:"toolchain"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return ToolchainFact{}, false
	}
	if inv.Toolchain.Bound == "" {
		// An inventory artifact written before the field existed, or by a non-Go path that omitted
		// it. Normalize to the explicit unresolved fact rather than an ambiguous zero value.
		return ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}, true
	}
	return inv.Toolchain, true
}

// SubjectToolchainScanned reports whether reachability for this case actually ran under the
// SUBJECT's Go toolchain (ADR 0014 M4). It is the licence a stdlib refutation-by-absence needs: only
// when it is true is an empty path set evidence about the subject rather than about the analyzer.
//
// It is false in every other state, and deliberately conflates none of them — flag off, floor-only
// or unresolved bound, a toolchain that could not be fetched, a build the subject's toolchain could
// not complete, a stub/skeleton run with no analyzer at all. Each of those is a scan under the
// analyzer's toolchain, and they are all the same thing to a verdict: not established. A reader that
// wants to tell them apart reads the ToolchainScan block itself.
func SubjectToolchainScanned(store artifact.Store, caseID string) bool {
	arts, err := store.Query(caseID, artifact.TypeReachability)
	if err != nil || len(arts) == 0 {
		return false
	}
	var payload struct {
		ToolchainScan ToolchainScan `json:"toolchain_scan"`
	}
	if err := json.Unmarshal(arts[0].Payload, &payload); err != nil {
		return false
	}
	return payload.ToolchainScan.Subject
}

// ToolchainSubject reports whether the advisory under assessment is keyed to the Go
// TOOLCHAIN/STDLIB itself rather than to a dependency the codebase requires — i.e. whether both
// analysis axes for it turn on the subject's Go toolchain rather than on a module version.
//
// It answers off the element select-by-target actually adjudicated (the selected affected_packages[]
// element, else the scalar block), because a multi-package advisory can be BOTH: CVE-2023-39325
// affects golang.org/x/net AND the stdlib, and a target that requires x/net is adjudicated as an
// x/net module case with a genuinely resolved module version — not a toolchain case.
//
// Two recognizers, because the corpus carries the fact two ways: an explicit "go-toolchain" version
// scheme (the U7 comparator's own token) and the stdlib PURL (which schemeFromPURL maps to gomod, so
// a stdlib advisory with no explicit scheme — GO-2021-0264 — is invisible to the scheme test alone).
func ToolchainSubject(store artifact.Store, caseID string) bool {
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return toolchainSubject(sel.PURL, sel.AffectedRanges)
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return false
	}
	var adv struct {
		PURL           string          `json:"purl"`
		AffectedRanges []affectedRange `json:"affected_ranges"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return false
	}
	return toolchainSubject(adv.PURL, adv.AffectedRanges)
}

// goStdlibPURLName is the package-URL NAME the corpus gives the Go standard library, under the
// "golang" type and no namespace. The stdlib is not a module, so this PURL never names a go.mod
// require — it names the toolchain.
const goStdlibPURLName = "stdlib"

// isGoStdlibPURL reports whether purl names the Go standard library, across every spelling the PURL
// grammar permits for the same package: a pinned version ("@go1.20"), qualifiers ("?os=linux"), a
// subpath ("#net/http"), and a non-lowercased type or name (the grammar makes the type
// case-insensitive and requires the golang name to be lowercase, so an uppercase spelling is a
// non-conformant rendering of the SAME package, never a different one).
//
// It replaces an exact string comparison against "pkg:golang/stdlib", which was wrong in both
// directions and harmful in both. A MISS on a versioned or qualified spelling from the corpus feed
// restores the unestablished not_exploitable (ToolchainSubject is what withheldNote keys on) AND
// stops advisoryFromArtifacts suppressing the SBOM coordinate, putting a nonexistent
// golang.org/x/net@go1.x.y into the SBOM and the OpenVEX product id. An OVER-match would withhold a
// genuinely resolved module finding. So the name is compared as a whole PURL name segment: a
// namespaced "pkg:golang/example.com/stdlib" and a longer "pkg:golang/stdlib-helper" are both
// modules, not the standard library, and neither matches.
func isGoStdlibPURL(purl string) bool {
	if purlEcosystem(purl) != "golang" {
		return false
	}
	name := purl[len("pkg:"):]
	name = name[strings.IndexByte(name, '/')+1:]
	// Trim the optional trailing components in the order the grammar appends them, so a separator
	// appearing inside a later component can never be mistaken for an earlier one.
	for _, sep := range []byte{'#', '?', '@'} {
		if i := strings.IndexByte(name, sep); i >= 0 {
			name = name[:i]
		}
	}
	return strings.EqualFold(name, goStdlibPURLName)
}

func toolchainSubject(purl string, rngs []affectedRange) bool {
	if isGoStdlibPURL(purl) {
		return true
	}
	for _, r := range rngs {
		if r.Scheme == "go-toolchain" {
			return true
		}
	}
	return false
}

func extractResolvedVersion(store artifact.Store, caseID string) (string, bool) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return "", false
	}
	var inv struct {
		ResolvedVersion string `json:"resolved_version"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return "", false
	}
	if inv.ResolvedVersion == "" {
		return "", false
	}
	return inv.ResolvedVersion, true
}

func extractSymbolSignal(store artifact.Store, caseID string) (string, bool) {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", false
	}
	var adv struct {
		VulnerableSymbolPresence string `json:"vulnerable_symbol_presence"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return "", false
	}
	if adv.VulnerableSymbolPresence == "" {
		return "", false
	}
	return adv.VulnerableSymbolPresence, true
}

// extractAdvisoryTrust reads the advisory's declared TrustTier from the normalized-advisory
// artifact. It returns (zero, false) on ANY miss/malformed/empty/UNRECOGNIZED value — only the
// three known enum strings map to their tier. SOUNDNESS (inv.5): an unknown or absent provenance
// is untrusted and NEVER first_party, so it can never unlock a refute (never defaults trust up).
func extractAdvisoryTrust(store artifact.Store, caseID string) (TrustTier, bool) {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", false
	}
	var adv struct {
		TrustTier string `json:"trust_tier"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return "", false
	}
	switch TrustTier(adv.TrustTier) {
	case TrustByO, TrustThirdParty, TrustFirstParty:
		return TrustTier(adv.TrustTier), true
	default:
		return "", false
	}
}

func (s disqualificationDiscovery) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	// Intake disqualification (M0): short-circuit advisories un-adjudicable BY DESIGN against
	// the resolved codebase — an ecosystem no resolved package matches, or a named dependency
	// the resolved manifest provably lacks — before any symbol/call-graph work. Distinct from
	// the version/symbol axes below; fails OPEN on any uncertainty (inv.5).
	buildDir, err := InventoryBuildDir(store, c.ID)
	if err != nil {
		return err
	}
	advModule, _ := extractAdvisoryModule(store, c.ID)
	manifestHas, manifestKnown := goModRequires(buildDir, advModule)
	if disq, reason := intakeDisqualify(
		extractAdvisoryEcosystem(store, c.ID),
		extractCodebaseEcosystem(store, c.ID),
		advModule, manifestHas, manifestKnown,
	); disq {
		res := DisqualResult{Disqualified: true, Reason: reason}
		_, err := PutArtifact(store, c, s.Name(), artifact.TypeDiscovery, "disqualification discovery (un-adjudicable at intake)", res)
		return err
	}

	rngs, rangeKnown := extractAffectedRange(store, c.ID)
	ver, verKnown := extractResolvedVersion(store, c.ID)
	symbol, symbolKnown := extractSymbolSignal(store, c.ID)
	trust, _ := extractAdvisoryTrust(store, c.ID) // miss/unknown ⇒ zero tier ⇒ refute suppressed (inv.5)

	disqualified, reason := disqualify(rngs, rangeKnown, ver, verKnown, symbol, symbolKnown, trust)
	res := DisqualResult{Disqualified: disqualified, Reason: reason}

	descriptor := "disqualification discovery (proceeds: insufficient evidence)"
	if disqualified {
		descriptor = "disqualification discovery (provably not-affected)"
	}
	_, err = PutArtifact(store, c, s.Name(), artifact.TypeDiscovery, descriptor, res)
	return err
}

// --- Stage 4: symbol_mapping --------------------------------------------------

type symbolMapping struct {
	plugin plugin.LanguagePlugin
}

func (symbolMapping) Name() string              { return "symbol_mapping" }
func (symbolMapping) Status() assessment.Status { return assessment.StatusAnalysis }
func (s symbolMapping) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	if s.plugin != nil {
		buildDir, err := InventoryBuildDir(store, c.ID)
		if err != nil {
			return err
		}
		purl, advisorySymbols := advisoryPURLAndSymbols(store, c.ID)
		res, err := s.plugin.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
			BuildDir:        buildDir,
			VulnID:          c.Request.Vulnerability.ID,
			PURL:            purl,
			AdvisorySymbols: advisorySymbols,
		})
		if err != nil {
			return err
		}
		_, err = PutArtifact(store, c, s.Name(), artifact.TypeVulnerableSymbol, "vulnerable symbol (resolved)", res)
		return err
	}
	sym := struct {
		Symbol string `json:"symbol"`
	}{Symbol: "example.com/x/pkg.Vulnerable"}
	_, err := PutArtifact(store, c, s.Name(), artifact.TypeVulnerableSymbol, "vulnerable symbol (stub)", sym)
	return err
}

func advisoryPURLAndSymbols(store artifact.Store, caseID string) (purl string, symbols []string) {
	// v3: symbol mapping must resolve the SELECTED package's PURL + symbols, so a target on a
	// secondary package looks for THAT package's vulnerable symbols (not the primary's). No selection
	// → scalar PURL/symbols (unchanged).
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return sel.PURL, sel.Symbols
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", nil
	}
	var adv struct {
		PURL            string   `json:"purl"`
		AdvisorySymbols []string `json:"advisory_symbols"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return "", nil
	}
	return adv.PURL, adv.AdvisorySymbols
}

// govulnMatchID returns the id govulncheck keys its findings by — a GO-YYYY-NNNN id — for the
// advisory under assessment: the primary id itself when it is already GO- prefixed (the natively
// GO-keyed advisory, e.g. GO-2021-0113, which govulncheck emits verbatim), else the first GO-
// prefixed entry in the normalized-advisory artifact's aliases (the CVE/GHSA-keyed advisory whose
// GO- alias govulncheck reports, e.g. CVE-2024-45337 → GO-2024-3321), else the primary id as a
// fail-safe. Passing the primary id straight through — as the call site historically did — makes
// parseFindings' `f.OSV == vulnID` filter drop every finding for a CVE/GHSA-keyed advisory
// ("GO-2024-3321" != "CVE-2024-45337"), silently forcing it off the reachable path and, because
// the drop empties findings entirely, bypassing reconcile()'s inv.5 fail-open. The resolver reads
// the aliases advisoryIntake.Run already wrote (from AdvisoryFacts.Aliases); a corpus advisory
// that carries no GO- alias falls back to the primary id (still correct for GO-native ids; a
// genuine corpus gap for a CVE-keyed one, which the corpus must supply).
func govulnMatchID(store artifact.Store, caseID, primary string) string {
	if strings.HasPrefix(primary, "GO-") {
		return primary
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return primary
	}
	var adv struct {
		Aliases []string `json:"aliases"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return primary
	}
	for _, a := range adv.Aliases {
		if strings.HasPrefix(a, "GO-") {
			return a
		}
	}
	return primary
}

// --- Stage 5: reachability_ingress --------------------------------------------

type reachabilityIngress struct {
	plugin plugin.LanguagePlugin
	// subjectToolchain opts this stage into asking the analyzer to run under the subject's Go
	// toolchain (ADR 0014 M4, flag-gated one release). See WithSubjectToolchainReachability.
	subjectToolchain bool
}

func (reachabilityIngress) Name() string              { return "reachability_ingress" }
func (reachabilityIngress) Status() assessment.Status { return assessment.StatusAnalysis }
func (s reachabilityIngress) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	var sinkRef artifact.Ref
	if syms, err := store.Query(c.ID, artifact.TypeVulnerableSymbol); err != nil {
		return err
	} else if len(syms) > 0 {
		sinkRef = syms[0].Ref()
	}

	if s.plugin != nil {
		return s.runWithPlugin(ctx, c, store, sinkRef)
	}

	reach := struct {
		Reachable bool `json:"reachable"`
	}{Reachable: true}
	reachRef, err := PutArtifact(store, c, s.Name(), artifact.TypeReachability, "reachability (stub)", reach)
	if err != nil {
		return err
	}
	ingress := struct {
		Entrypoint string `json:"entrypoint"`
	}{Entrypoint: "GET /"}
	ingressRef, err := PutArtifact(store, c, s.Name(), artifact.TypeIngressMap, "ingress map (stub)", ingress)
	if err != nil {
		return err
	}
	pair := artifact.CandidatePair{
		SchemaVersion: artifact.CandidatePairSchemaVersion,
		Sink:          sinkRef,
		Ingress:       &ingressRef,
		Path:          reachRef,
		Partial:       true,
	}
	if _, err := PutArtifact(store, c, s.Name(), artifact.TypeCandidatePair, "candidate pair (partial)", pair); err != nil {
		return err
	}
	return nil
}

// requestedToolchain returns the subject's Go toolchain this run must execute under, or "" for
// "run under the analyzer's own" — which is every case but one (ADR 0014 M4).
//
// Three gates, and each is load-bearing rather than defensive:
//
//   - The flag. M4 changes the meaning of a green scan, so it ships off for one release (ruling 3).
//   - An inventory fact must exist. No fact means no run resolved one; nothing to request.
//   - The bound must be EXACT. This is the asymmetry the whole ADR turns on: reachability's output
//     is a refutation by ABSENCE, and absence is only evidence about the toolchain the analysis ran
//     on. A floor ("at least go1.20") licenses a disqualification because outside() is monotone, but
//     scanning AT the floor would let a symbol missing from go1.20 be reported absent from a subject
//     that actually builds with go1.24. A consumer that branched on a non-empty Version alone would
//     reintroduce the defect in a new place.
func (s reachabilityIngress) requestedToolchain(store artifact.Store, caseID string) string {
	if !s.subjectToolchain {
		return ""
	}
	fact, ok := Toolchain(store, caseID)
	if !ok || fact.Bound != ToolchainBoundExact {
		return ""
	}
	return fact.Version
}

func (s reachabilityIngress) runWithPlugin(ctx context.Context, c *assessment.Assessment, store artifact.Store, sinkRef artifact.Ref) error {
	buildDir, err := InventoryBuildDir(store, c.ID)
	if err != nil {
		return err
	}
	// govulncheck keys its findings by the advisory's GO-YYYY-NNNN id, so the id we hand
	// Reachability (→ parseFindings' f.OSV == vulnID filter) MUST be that GO- id — not the
	// corpus primary id, which for a CVE/GHSA-keyed advisory (e.g. CVE-2024-45337) never equals
	// govulncheck's GO- id and would silently drop every finding, forcing the advisory off the
	// reachable path AND bypassing the inv.5 fail-open. Resolve the GO- match id from the
	// normalized-advisory artifact's aliases.
	vulnID := govulnMatchID(store, c.ID, c.Request.Vulnerability.ID)

	cg, err := s.plugin.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: buildDir})
	if err != nil {
		return err
	}
	ingresses, err := s.plugin.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: buildDir})
	if err != nil {
		return err
	}
	requestedToolchain := s.requestedToolchain(store, c.ID)
	reach, err := s.plugin.Reachability(ctx, plugin.ReachabilityRequest{
		BuildDir:    buildDir,
		VulnID:      vulnID,
		GoToolchain: requestedToolchain,
	})
	if err != nil {
		return err
	}
	toolchainScan := newToolchainScan(requestedToolchain, reach.ScanToolchain)

	// Resolve the representative reach paths: govulncheck's directly when present, else
	// the first-party call-graph fallback. The fallback's ReachPath carries the
	// advisory-specific reaching ingress + ingress→sink trace (firstPartyReachPaths walks
	// back from THIS advisory's sink), so it is the only per-advisory entry-point signal.
	paths := reach.Paths
	firstParty := false
	if len(paths) == 0 {
		if sink, err := resolvedSinkSCIP(store, c.ID); err != nil {
			return err
		} else if sink != "" {
			if fp := firstPartyReachPaths(cg, ingresses, sink); len(fp) > 0 {
				paths = fp
				firstParty = true
			}
		}
	}

	// Persist the RESOLVED paths (not the raw govulncheck reach) so the report builder
	// reads the advisory-specific reaching ingress + trace. Persisting reach.Paths here —
	// empty for a first-party sink — drops that ingress, which forces the report builder
	// onto a positional pick from the shared, sorted ingress map and collapses every
	// advisory's entry point onto whichever ingress sorts first (the SSRF→expandHandler
	// mis-attribution). The CallGraph leg is unchanged (guard discovery reads it).
	reachOut := reach
	reachOut.Paths = paths
	reachPayload := struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
		CallGraph    plugin.CallGraphResult    `json:"call_graph"`
		// ToolchainScan records which Go toolchain this analysis actually ran under (ADR 0014 M4).
		// It is the fact SubjectToolchainScanned reads back, and the reason a fallback cannot pass
		// itself off as a subject scan.
		ToolchainScan ToolchainScan `json:"toolchain_scan"`
	}{Reachability: reachOut, CallGraph: cg, ToolchainScan: toolchainScan}
	reachRef, err := PutArtifact(store, c, s.Name(), artifact.TypeReachability, "reachability (resolved)", reachPayload)
	if err != nil {
		return err
	}

	ingressRef, err := PutArtifact(store, c, s.Name(), artifact.TypeIngressMap, "ingress map (resolved)", ingresses)
	if err != nil {
		return err
	}

	for _, p := range paths {
		pair := artifact.CandidatePair{
			SchemaVersion: artifact.CandidatePairSchemaVersion,
			Sink:          sinkRef,
			Path:          reachRef,
			Partial:       firstParty || !reach.Partiality.Complete,
		}
		if p.Ingress.SCIP != "" {
			pair.Ingress = &ingressRef
		}
		desc := "candidate pair (resolved)"
		if firstParty {
			desc = "candidate pair (first-party call-graph reachability)"
		}
		if _, err := PutArtifact(store, c, s.Name(), artifact.TypeCandidatePair, desc, pair); err != nil {
			return err
		}
	}

	sink, err := resolvedSinkSCIP(store, c.ID)
	if err != nil {
		return err
	}
	if sink != "" {
		taint, err := s.plugin.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: buildDir, Sinks: []string{sink}})
		if err != nil {
			return err
		}
		td := taintDiscovery{SchemaVersion: "tegron.taint.v1", Sink: sink, Result: taint}
		if _, err := PutArtifact(store, c, s.Name(), artifact.TypeTaint, "taint (discovery, path-presence)", td); err != nil {
			return err
		}

		harness, err := s.plugin.GenerateHarness(ctx, plugin.GenerateHarnessRequest{Sink: sink, Kind: "unit"})
		if err != nil {
			return err
		}
		ha := HarnessArtifact{SchemaVersion: "tegron.harness.v1", Sink: sink, Result: harness}
		if _, err := PutArtifact(store, c, s.Name(), artifact.TypeHarness, "harness (skeleton scaffolding)", ha); err != nil {
			return err
		}
	}
	return nil
}

// firstPartyReachPaths derives (ingress→sink) ReachPaths for a FIRST-PARTY sink by walking the
// static CallGraph backward from the resolved sink toward an entry point. Soundness / inv.5: this
// asserts only STRUCTURAL reachability — a candidate, never a verdict and never proof.
func firstPartyReachPaths(cg plugin.CallGraphResult, ingresses plugin.IngressResult, sink string) []plugin.ReachPath {
	if sink == "" || len(cg.Edges) == 0 {
		return nil
	}

	// The BFS runs over SCIP-id keys, reproducing the pre-Symbol identity exactly: CallEdge
	// endpoints were bare SCIP ids, and the sink parameter is a SCIP id (resolvedSinkSCIP), so
	// keying the graph on .SCIP is the same graph the old string-typed code built. symBySCIP
	// carries the structured Symbol for each node so the ReachPath.Sink/Ingress/Trace fields —
	// now plugin.Symbol — are reconstructed at the return boundary.
	symBySCIP := make(map[string]plugin.Symbol)
	callers := make(map[string][]string, len(cg.Edges))
	for _, e := range cg.Edges {
		symBySCIP[e.Caller.SCIP] = e.Caller
		symBySCIP[e.Callee.SCIP] = e.Callee
		callers[e.Callee.SCIP] = append(callers[e.Callee.SCIP], e.Caller.SCIP)
	}

	ingressSyms := make(map[string]struct{}, len(ingresses.Ingresses))
	for _, in := range ingresses.Ingresses {
		if in.Symbol.SCIP != "" {
			symBySCIP[in.Symbol.SCIP] = in.Symbol
			ingressSyms[in.Symbol.SCIP] = struct{}{}
		}
	}
	roots := make(map[string]struct{}, len(cg.Roots))
	for _, r := range cg.Roots {
		symBySCIP[r.SCIP] = r
		roots[r.SCIP] = struct{}{}
	}

	type node struct {
		sym  string
		path []string
	}
	visited := map[string]struct{}{sink: {}}
	queue := []node{{sym: sink, path: []string{sink}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		_, isIngress := ingressSyms[cur.sym]
		_, isRoot := roots[cur.sym]
		if isIngress || isRoot {
			trace := make([]plugin.Symbol, len(cur.path))
			for i := range cur.path {
				trace[i] = symBySCIP[cur.path[len(cur.path)-1-i]]
			}
			var ingress plugin.Symbol
			if isIngress {
				ingress = symBySCIP[cur.sym]
			}
			return []plugin.ReachPath{{Sink: symBySCIP[sink], Ingress: ingress, Trace: trace}}
		}

		for _, caller := range callers[cur.sym] {
			if _, seen := visited[caller]; seen {
				continue
			}
			visited[caller] = struct{}{}
			queue = append(queue, node{sym: caller, path: append(append([]string{}, cur.path...), caller)})
		}
	}
	return nil
}

// HarnessArtifact is the FROZEN persisted shape of a TypeHarness artifact (schema
// tegron.harness.v1): a self-describing wrapper around the plugin's verbatim HarnessResult plus the
// sink it was generated for. inv.5: HarnessResult.Skeleton is always true at this stage. Exported
// because the Prove path reads it to assemble a directed-fuzz target.
type HarnessArtifact struct {
	SchemaVersion string               `json:"schema_version"`
	Sink          string               `json:"sink"`
	Result        plugin.HarnessResult `json:"result"`
}

// taintDiscovery is the FROZEN persisted shape of a TypeTaint artifact (schema tegron.taint.v1).
type taintDiscovery struct {
	SchemaVersion string             `json:"schema_version"`
	Sink          string             `json:"sink"`
	Result        plugin.TaintResult `json:"result"`
}

// resolvedSinkSCIP reads the upstream vulnerable-symbol artifact and returns the first resolved SCIP
// id, or "" if no symbol resolved (inv.7).
func resolvedSinkSCIP(store artifact.Store, caseID string) (string, error) {
	arts, err := store.Query(caseID, artifact.TypeVulnerableSymbol)
	if err != nil {
		return "", err
	}
	if len(arts) == 0 {
		return "", nil
	}
	var res plugin.SymbolResolutionResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil {
		return "", err
	}
	if len(res.Resolved) == 0 {
		return "", nil
	}
	return res.Resolved[0].SCIP, nil
}

// --- Exposure footprint (deterministic boundary artifact, F1/F4) ---------------

type exposureFootprintStage struct{}

func (exposureFootprintStage) Name() string              { return "exposure_footprint" }
func (exposureFootprintStage) Status() assessment.Status { return assessment.StatusAnalysis }

func (s exposureFootprintStage) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	// CaseID is left unset: the parent matter is a service-side concept the engine does not
	// know about. The JSON key stays in the schema so no bundle consumer sees a shape change.
	payload := artifact.ExposureFootprintPayload{
		SchemaVersion: artifact.ExposureFootprintSchemaVersion,
		AssessmentID:  c.ID,
	}

	if arts, err := store.Query(c.ID, artifact.TypeIngressMap); err != nil {
		return err
	} else if len(arts) > 0 {
		var ir plugin.IngressResult
		if err := json.Unmarshal(arts[0].Payload, &ir); err == nil {
			payload.IngressCount = len(ir.Ingresses)
			seen := make(map[string]struct{})
			for _, ing := range ir.Ingresses {
				if _, ok := seen[ing.Kind]; !ok {
					seen[ing.Kind] = struct{}{}
					payload.IngressKinds = append(payload.IngressKinds, ing.Kind)
				}
			}
			if ir.Partiality.Reasons != nil {
				payload.PartialityFlags = append(payload.PartialityFlags, ir.Partiality.Reasons...)
			}
		}
	}

	if arts, err := store.Query(c.ID, artifact.TypeReachability); err != nil {
		return err
	} else if len(arts) > 0 {
		var full struct {
			Reachability plugin.ReachabilityResult `json:"reachability"`
		}
		// Partiality is harvested whether or not any path was found, and BEFORE the
		// path-count branch. Harvesting it only on len(Paths) > 0 dropped the disclosure
		// on precisely the case it exists for: a reachability pass that resolved nothing
		// because it could not see the code produces zero paths, and without the reason
		// codes it is indistinguishable from a pass that looked and found nothing.
		unmarshalled := json.Unmarshal(arts[0].Payload, &full) == nil
		if unmarshalled && full.Reachability.Partiality.Reasons != nil {
			payload.PartialityFlags = append(payload.PartialityFlags, full.Reachability.Partiality.Reasons...)
		}
		if unmarshalled && len(full.Reachability.Paths) > 0 {
			payload.ReachablePathCount = len(full.Reachability.Paths)
		} else {
			var stub struct {
				Reachable bool `json:"reachable"`
			}
			if json.Unmarshal(arts[0].Payload, &stub) == nil && stub.Reachable {
				payload.ReachablePathCount = 1
			}
		}
	}

	if arts, err := store.Query(c.ID, artifact.TypeVulnerableSymbol); err != nil {
		return err
	} else if len(arts) > 0 {
		var res plugin.SymbolResolutionResult
		if err := json.Unmarshal(arts[0].Payload, &res); err == nil {
			payload.VulnerableSymbolCount = len(res.Resolved)
			if res.Partiality.Reasons != nil {
				payload.PartialityFlags = append(payload.PartialityFlags, res.Partiality.Reasons...)
			}
		}
	}

	// Dependency-version resolution is the fourth partiality axis (alongside ingress,
	// reachability and vulnerable-symbol above): the inventory stage records why it
	// could not pin an installed version. Harvesting it here keeps the footprint an
	// honest account of what the pass could not establish.
	if arts, err := store.Query(c.ID, artifact.TypeInventory); err != nil {
		return err
	} else if len(arts) > 0 {
		var inv struct {
			PartialityFlags []string `json:"partiality_flags"`
		}
		if err := json.Unmarshal(arts[0].Payload, &inv); err == nil {
			payload.PartialityFlags = append(payload.PartialityFlags, inv.PartialityFlags...)
		}
	}

	payload.SymbolCount = -1
	payload.DepCount = exposureFootprintDepCount(store, c.ID)
	payload.RepoCount = 1

	_, err := PutArtifact(store, c, s.Name(), artifact.TypeExposureFootprint, "exposure footprint (deterministic)", payload)
	return err
}

func exposureFootprintDepCount(store artifact.Store, caseID string) int {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return -1
	}
	var inv struct {
		BuildDir string `json:"build_dir"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil || inv.BuildDir == "" {
		return -1
	}
	data, err := os.ReadFile(filepath.Join(inv.BuildDir, "go.mod"))
	if err != nil {
		return -1
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return -1
	}
	count := 0
	for _, r := range mf.Require {
		if !r.Indirect {
			count++
		}
	}
	return count
}
