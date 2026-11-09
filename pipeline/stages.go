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
// (PutArtifact, InventoryBuildDir, HarnessArtifact, DisqualResult + reason constants,
// AdvisoryFacts) because the Prove stages build on the same artifact contracts. They are neutral
// plumbing, not proof.

package pipeline

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	gover "go/version"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/checkout/gomodtree"
	"github.com/ferralon-ai/ferralon-assay/internal/gomod"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/vulnclass"
)

// AssessConfig holds the free-stage seams an AssessStages caller may inject. It is the OSS half of
// the stage configuration; the Prove options (model/sandbox/dispatch/recall/fuzz/critic) live in the
// Service prove package, which builds its own stages and appends them after AssessStages.
type AssessConfig struct {
	Plugin   plugin.LanguagePlugin
	Checkout checkout.Checkout
	Source   AdvisorySource
	// SubjectGoVersion/CIGoVersion carry the two candidate subject-toolchain sources into
	// codebase_inventory, where both are exact and outrank the go.mod floors, and TrustCIGoVersion
	// is the caller's assertion that the second describes the subject. See WithSubjectToolchain.
	SubjectGoVersion string
	CIGoVersion      string
	TrustCIGoVersion bool
	// SubjectGoWork is the caller's statement of the GOWORK the subject's Go build runs under. See
	// WithSubjectGoWork.
	SubjectGoWork string
	// SubjectToolchainReachability opts reachability_ingress into running the Go analysis under the
	// SUBJECT's toolchain when that toolchain resolved to an exact version. Off by default. See
	// WithSubjectToolchainReachability.
	SubjectToolchainReachability bool
	// SkipDisqualifiedAnalysis lets symbol_mapping and reachability_ingress return without calling
	// the plugin when disqualification_discovery already settled the advisory. Off by default. See
	// WithSkipDisqualifiedAnalysis.
	SkipDisqualifiedAnalysis bool
	// DependencyAcquisition fills the dependency cache for a JS build. nil leaves the stage out.
	// See WithDependencyAcquisition.
	DependencyAcquisition *dependencyAcquirer
	// LibraryEntrypoints is the caller's statement of which of the build's packages code outside
	// the build may import; nil is auto. See WithLibraryEntrypoints.
	LibraryEntrypoints *plugin.LibraryEntrypoints
	// InventoryMemo is the scan's memo of codebase_inventory's checkout-constant reads; nil repeats
	// them per advisory. See WithInventoryMemo.
	InventoryMemo *InventoryMemo
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
// the process-wide default SetDefaultAdvisorySource installed, which resolves nothing when unset.
func WithAdvisorySource(src AdvisorySource) AssessOption {
	return func(c *AssessConfig) { c.Source = src }
}

// AdvisorySourceOf returns the AdvisorySource a run assessed with opts reads advisory facts through:
// the one WithAdvisorySource injected, else the process-wide default — the source S1 reads.
func AdvisorySourceOf(opts ...AssessOption) AdvisorySource {
	var cfg AssessConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.Source != nil {
		return cfg.Source
	}
	return defaultAdvisorySource()
}

// WithSubjectToolchain injects the two candidate EXACT sources of the subject's Go toolchain that
// the pipeline cannot read off the tree, both ranked above its go.mod floors: declared is the
// subject's own statement of the toolchain it builds with, observed is `go env GOVERSION` sampled
// on the CI runner BEFORE the Action installed the scanner's own Go. Either may be empty; absent
// both, the fact falls back to the subject's go.mod floors and then to unresolved, so every
// non-Action caller is unchanged.
//
// trustObserved is a required third argument rather than a separate option because the observation
// alone does not carry its own provenance. `go env GOVERSION` on a runner answers "what Go is
// installed here", which is a statement about the SUBJECT only in a same-job topology where the
// caller provisioned its build toolchain before invoking the scan; in a dedicated scan job the same
// command returns the hosted runner image's preinstalled Go, unrelated to a build pinned elsewhere.
// Nothing observable distinguishes the two, so only the caller can assert it — and until they do,
// observed does not participate in resolution at all (not even as a floor: an unrelated Go is not a
// lower bound on the subject's toolchain). The same assertion admits the toolchain the analyzer
// resolves for the build directory when the go.mod directives do not bound it, an ambient value of
// the same kind (ToolchainSourceBuildResolved).
//
// Never pass the SCANNER's toolchain here. That value is a property of the analysis environment, and
// mistaking it for a statement about the subject yields verdicts about the wrong toolchain.
func WithSubjectToolchain(declared, observed string, trustObserved bool) AssessOption {
	return func(c *AssessConfig) {
		c.SubjectGoVersion, c.CIGoVersion, c.TrustCIGoVersion = declared, observed, trustObserved
	}
}

// WithSubjectGoWork states the GOWORK the subject's Go build runs under: "off", or the path of its
// go.work, relative to the checkout root unless absolute. Unstated, the build runs under the go.work
// the go command finds from the module, searched no higher than its repository. Never pass the
// scanner's own GOWORK: it describes the analysis environment, not the subject. A stated go.work
// that does not exist, does not parse or does not use the module withholds every verdict.
func WithSubjectGoWork(declared string) AssessOption {
	return func(c *AssessConfig) { c.SubjectGoWork = declared }
}

// WithSubjectToolchainReachability opts the Go reachability analysis into running under the
// SUBJECT's Go toolchain instead of the analyzer's, when — and only when — the subject's toolchain
// resolved to an EXACT bound. It is OFF by default and ships that way for one release
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

// WithLibraryEntrypoints hands reachability_ingress the caller's statement of which of the build's
// packages code outside the build may import. A lane that withholds a refutation such an importer
// may contradict resolves its entry points from it, and a refutation that holds only because a
// declaration left a package out carries that declaration as an assumption.
func WithLibraryEntrypoints(e plugin.LibraryEntrypoints) AssessOption {
	return func(c *AssessConfig) { c.LibraryEntrypoints = &e }
}

// WithSkipDisqualifiedAnalysis lets S4 symbol_mapping and S5 reachability_ingress skip their plugin
// work for an advisory S3 disqualified, leaving no vulnerable_symbol / reachability / ingress_map /
// candidate_pair artifact behind. It is only sound for a caller whose verdict for a disqualified
// advisory reads nothing those stages write — Assay's report builder settles a disqualified row on
// the discovery artifact alone. A caller that consults the S4/S5 artifacts after a disqualification
// (a Prove tier weighing a static refutation against it) must leave it off, which is the default.
func WithSkipDisqualifiedAnalysis(enabled bool) AssessOption {
	return func(c *AssessConfig) { c.SkipDisqualifiedAnalysis = enabled }
}

// AssessStages returns the deterministic Assess stages S1–S6 in pipeline order, applying any
// options. The Service composes the full S1–S10 pipeline as append(AssessStages(opts...),
// prove.ProveStages(...)...).
func AssessStages(opts ...AssessOption) []Stage {
	cfg := &AssessConfig{}
	for _, o := range opts {
		o(cfg)
	}
	stages := []Stage{
		advisoryIntake{src: cfg.Source},
		codebaseInventory{checkout: cfg.Checkout, plugin: cfg.Plugin, src: cfg.Source, subjectGoVersion: cfg.SubjectGoVersion, ciGoVersion: cfg.CIGoVersion, trustCIGoVersion: cfg.TrustCIGoVersion, subjectGoWork: cfg.SubjectGoWork, memo: cfg.InventoryMemo},
		maliciousPresence{},
		disqualificationDiscovery{},
	}
	if cfg.DependencyAcquisition != nil {
		stages = append(stages, dependencyAcquisition{acq: cfg.DependencyAcquisition, plugin: cfg.Plugin})
	}
	return append(stages,
		symbolMapping{plugin: cfg.Plugin, skipDisqualified: cfg.SkipDisqualifiedAnalysis, deps: cfg.DependencyAcquisition},
		reachabilityIngress{plugin: cfg.Plugin, subjectToolchain: cfg.SubjectToolchainReachability, skipDisqualified: cfg.SkipDisqualifiedAnalysis, deps: cfg.DependencyAcquisition, libraryEntrypoints: cfg.LibraryEntrypoints},
		exposureFootprintStage{},
	)
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
		codebaseInventory{checkout: cfg.Checkout, plugin: cfg.Plugin, src: cfg.Source, subjectGoVersion: cfg.SubjectGoVersion, ciGoVersion: cfg.CIGoVersion, trustCIGoVersion: cfg.TrustCIGoVersion, subjectGoWork: cfg.SubjectGoWork, memo: cfg.InventoryMemo},
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
	return putPayload(store, c, producedBy, t, descriptor, payload)
}

// putPayload is PutArtifact for a payload that is already encoded.
func putPayload(store artifact.Store, c *assessment.Assessment, producedBy string, t artifact.Type, descriptor string, payload []byte) (artifact.Ref, error) {
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
// src falls back to defaultAdvisorySource(), the process-wide default.
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
	// "cna-declared" | "diff-lexed"; "reasoning" reserved). It feeds no admission or reachability
	// path: a symbol resolves and is walked the same under every tag, and absent → "" → UNKNOWN
	// derivation. Two consumers read it: the candidate's SymbolConfidence label, and the
	// not_exploitable grounds, where only an osv-declared or curated set (or an untagged set a house
	// canary carries, BuiltIn) may ground on the listed symbols' absence. Carries no verdict.
	//
	// omitempty (like SymbolsTyped, unlike the other facts fields): a record with no symbols has no
	// derivation to tag, and an absent tag reads as unknown derivation.
	SymbolProvenance string `json:",omitempty"`
	// TargetConditionalSymbols are the Symbols that some build target of the package does not
	// compile (an async entry on a framework target without async, an XmlNode entry on one without
	// System.Xml). Absence of any other symbol never refutes. One of these may be absent only from a
	// package the lane read in full; every other symbol must still resolve and be searched.
	TargetConditionalSymbols []string `json:",omitempty"`
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
	// BuiltIn marks a fact compiled into the scanner: only the house-canary source sets it, and it
	// has no JSON form, so no corpus document can claim it. It is what vouches for an untagged symbol
	// set: the canaries' symbols are written in this module.
	BuiltIn bool `json:"-"`
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

	// DroppedPackages holds the package URL of each affected_packages element that failed
	// validation and is absent from AffectedPackages ("" when the element had none). The
	// not_exploitable gate counts each as another package, so a malformed element cannot narrow
	// the advisory to the one package that was searched.
	DroppedPackages []string `json:"-"`

	// --- ferralon.normalized_advisory.v4 additions -----------------------------
	// SymbolsTyped is the §4.4.2/.3 typed-symbol axis: the canonical comparable plugin.Symbol
	// identity, coexisting with the bare Symbols []string above. DECLARED-AWAITING-EMIT
	// (anvil-q15): the cve-enrichment producer does not emit typed symbols yet, so this is nil on
	// every current advisory — nil means "producer has not emitted," NOT "no symbols" (Symbols
	// still carries the strings). No consumer may read nil SymbolsTyped as an empty symbol set.
	// Carries no verdict; advisory-only framing (inv.5).
	//
	// omitempty (unlike the other facts fields): typed symbols are emitted only by the separate
	// cve-enrichment producer for the PUBLISHED feed, so nil is the declared-awaiting-emit state for
	// every other record, and serializing it as null would be noise. When the producer emits, a
	// non-nil value round-trips.
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
// left unset by a map-backed source reads as "silent," unchanged.
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
	Type         string `json:",omitempty"` // OSV range type (SEMVER | ECOSYSTEM | GIT); "" when the source states none
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

func (s advisoryIntake) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	vulnID := c.Request.Vulnerability.ID
	src := s.src
	if src == nil {
		src = defaultAdvisorySource()
	}
	// The start of an assessment is the corpus freshness boundary: a long-lived process picks up a
	// rewritten corpus here, never mid-Lookup. A failed reload keeps the last good corpus serving, so
	// it is logged, not returned.
	if r, ok := src.(CorpusRefresher); ok {
		if err := r.Refresh(); err != nil {
			log.Printf("pipeline: advisory_intake: advisory corpus refresh: %v", err)
		}
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
			AffectedRanges: withDisagreeingLegacyRanges(buildAffectedRanges(p.AffectedRanges, p.UpperExclusive, pkgScheme), p, facts, scheme),
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
		Coordinate       string                    `json:"coordinate,omitempty"`
		Aliases          []string                  `json:"aliases,omitempty"`
		AffectedRanges   []affectedRange           `json:"affected_ranges,omitempty"`
		FixedVersion     string                    `json:"fixed_version,omitempty"`
		PURL             string                    `json:"purl,omitempty"`
		AdvisorySymbols  []string                  `json:"advisory_symbols,omitempty"`
		Conditional      []string                  `json:"target_conditional_symbols,omitempty"`
		SymbolProvenance string                    `json:"symbol_provenance,omitempty"` // B1: record-scoped derivation tag: a candidate STRENGTH signal, and the gate on symbol-absence grounds (never admission)
		AdvisoryGuards   []string                  `json:"advisory_guards,omitempty"`
		CWEs             []string                  `json:"cwes,omitempty"`
		VulnClass        string                    `json:"vuln_class,omitempty"`        // "" ⇒ class not assessed (honest)
		TrustTier        string                    `json:"trust_tier,omitempty"`        // gates refute eligibility (inv.5); "" ⇒ untrusted
		BuiltIn          bool                      `json:"built_in,omitempty"`          // a house canary answered (AdvisoryFacts.BuiltIn)
		Trigger          *advisoryTrigger          `json:"trigger,omitempty"`           // v3 per-CVE reach descriptor (row 1)
		TriggerCondition string                    `json:"trigger_condition,omitempty"` // B3: advisory-declared exploit precondition, read as candidate-only PoE qualifier context (never admission/refute)
		Prerequisite     string                    `json:"prerequisite,omitempty"`      // B3: advisory-declared mechanism precondition, read alongside TriggerCondition
		AffectedPackages []advisoryAffectedPackage `json:"affected_packages,omitempty"`
		DroppedPackages  []string                  `json:"dropped_affected_packages,omitempty"`
		MaliciousPackage *advisoryMaliciousPackage `json:"malicious_package,omitempty"` // MAL presence-verdict marker
		GuardSufficiency []advisoryGuardVariant    `json:"guard_sufficiency,omitempty"` // B-guardsuff: advisory-DECLARED guard sufficiency, read as a candidate-only descriptive annotation on on-path guards (never admission/refute)
	}{
		VulnID:           vulnID,
		Source:           c.Request.Vulnerability.Source,
		Module:           facts.Module,
		Coordinate:       facts.Coordinate,
		Aliases:          facts.Aliases,
		AffectedRanges:   ranges,
		FixedVersion:     facts.FixedVersion,
		PURL:             facts.PURL,
		AdvisorySymbols:  facts.Symbols,
		Conditional:      facts.TargetConditionalSymbols,
		SymbolProvenance: facts.SymbolProvenance,
		AdvisoryGuards:   facts.GuardSymbols,
		CWEs:             facts.CWEs,
		VulnClass:        string(vulnClass),
		TrustTier:        string(facts.Provenance.TrustTier),
		BuiltIn:          facts.BuiltIn,
		Trigger:          advTrigger,
		TriggerCondition: facts.TriggerCondition,
		Prerequisite:     facts.Prerequisite,
		AffectedPackages: affectedPackages,
		DroppedPackages:  facts.DroppedPackages,
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
	// memo carries the scan's checkout-constant reads across advisories; nil recomputes them.
	memo *InventoryMemo
	// src is the AdvisorySource this stage reads advisory facts through (U8a intake seam). A nil
	// src falls back to defaultAdvisorySource(), the process-wide default.
	src AdvisorySource
	// subjectGoVersion/ciGoVersion are the two candidate EXACT subject-toolchain sources this stage
	// cannot discover from the tree on disk, both ranked above the go.mod floors: the subject's own
	// declaration and the Go the CI runner already had before the Action installed the scanner's.
	// Both empty is the normal non-Action case and simply leaves the fact to the go.mod floors.
	//
	// trustCIGoVersion is the caller's assertion that ciGoVersion describes the SUBJECT. Absent it,
	// the observation is discarded rather than demoted — see resolveToolchainFact.
	subjectGoVersion string
	ciGoVersion      string
	trustCIGoVersion bool
	// subjectGoWork is the caller's statement of the GOWORK the subject's build runs under: "off", a
	// go.work path relative to the checkout root, or "" to take the go.work the go command finds.
	// See ResolveGoWorkspace.
	subjectGoWork string
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
// is the SUBJECT'S TOOLCHAIN, resolved once per run into the bounded ToolchainFact, not
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
// verdict depends on the toolchain. The advisory supplies the affected RANGE, never a version.
func (s codebaseInventory) resolveDependencyVersion(ctx context.Context, buildDir string, goWork GoWorkspace, language, module, coordinate, scheme string, toolchain ToolchainFact) (dep depVersions, partiality []string, err error) {
	if scheme == "go-toolchain" {
		switch toolchain.Bound {
		case ToolchainBoundExact, ToolchainBoundMinimum:
			return singleVersion(toolchain.Version), nil, nil
		default:
			return depVersions{}, nil, nil
		}
	}
	switch {
	case module != "":
		// A Go module coordinate resolves off go.mod with no plugin involved, so this branch
		// carried no partiality at all — every Go scan disclosed nothing. Distinguish the three
		// ways the version comes back empty: an unreadable/unparseable go.mod means the
		// version could not be established (disclose no_manifest); a module the go.mod requires
		// but replaces with a local directory or another module is declared with no version
		// that describes it (disclose source_unpinned and keep it declared, so the version axis
		// stays open); and a go.mod that parses and simply does not require the module means the
		// codebase genuinely does not depend on it (honest absence — no disclosure, so a true
		// not_exploitable stays unqualified).
		v, pinned, manifestRead := moduleVersionFromBuild(ctx, buildDir, goWork, module)
		if !manifestRead {
			return depVersions{}, []string{plugin.PartialReasonNoManifest}, nil
		}
		if !pinned {
			return depVersions{Found: true}, []string{plugin.PartialReasonSourceUnpinned}, nil
		}
		return singleVersion(v), nil, nil
	case coordinate != "" && s.plugin != nil && s.plugin.Language() == language:
		vr, err := s.plugin.ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{
			BuildDir:   buildDir,
			Coordinate: coordinate,
		})
		if err != nil {
			return depVersions{}, nil, err
		}
		dep := depVersionsOf(vr)
		// Persist WHY the resolution was incomplete (e.g. "no_manifest"): a degraded resolve leaves
		// the version empty, which downstream is indistinguishable from "this codebase has no such
		// dependency". Carrying the reason is what makes an unresolvable scan distinguishable from a
		// clean one at the customer surface. They hold a refutation only while the version resolved
		// anyway; an unresolved version is its own undetermined reason (trigger withoutVersionLimits).
		var flags []string
		if !vr.Partiality.Complete {
			flags = append(flags, vr.Partiality.Reasons...)
		}
		return dep, flags, nil
	}
	// A managed-ecosystem coordinate with no language-matched analyzer available (the
	// assay-plugin-<lang> binary is not on PATH, so acquire selected nothing, or the
	// detected tree language does not match the advisory's ecosystem). The version cannot
	// be established, and returning it bare reads downstream as "not installed" — which
	// disqualifies the advisory on a version comparison that never happened. Disclose the
	// absence instead; the verdict is untouched.
	if coordinate != "" {
		return depVersions{}, []string{plugin.PartialReasonNoPlugin}, nil
	}
	return depVersions{}, nil, nil
}

// depVersions is what a codebase carries of one dependency. A multi-project build can declare it
// at a different version per module, and a nested install can sit beside a top-level one, so the
// version axis needs every version, not the first one a resolver happened to read.
type depVersions struct {
	// Version is the representative the inventory records as resolved_version.
	Version string
	// Versions is every distinct resolved version, Version first.
	Versions []string
	// Complete reports that Versions covers every declaration: the resolver enumerated them all and
	// resolved each. Only a complete set can show every version is outside an affected range.
	Complete bool
	// Found reports that the codebase declares the dependency at all, resolved or not.
	Found bool
	// Presence is the first resolved copy, which maliciousPresence matches against. It stands
	// without agreement, so it is never read by the not-affected path.
	Presence string
	// Annotations are the assumptions the resolver's answer rests on (plugin.Annotation). They
	// qualify the answer without making it partial, so they gate nothing here.
	Annotations []plugin.Annotation
}

// singleVersion is a dependency whose source can carry one version only (a go.mod require, the
// subject's toolchain). An empty v is an honest absence.
func singleVersion(v string) depVersions {
	if v == "" {
		return depVersions{}
	}
	return depVersions{Version: v, Versions: []string{v}, Complete: true, Found: true, Presence: v}
}

// depVersionsOf reads a plugin resolution. The set is complete only when the plugin asserts
// MatchesComplete over a complete scan and every copy it lists is resolved; Match may still be
// unresolved, as it is when the copies disagree.
func depVersionsOf(vr plugin.DependencyVersionResult) depVersions {
	dep := depVersions{Found: vr.Found, Annotations: vr.Annotations}
	if vr.Found && vr.Match.Resolved {
		dep.Version = vr.Match.Version
		dep.Versions = []string{dep.Version}
	}
	dep.Presence = dep.Version
	if vr.Presence != nil && vr.Presence.Resolved {
		dep.Presence = vr.Presence.Version
	}
	dep.Complete = vr.MatchesComplete && vr.Partiality.Complete && len(vr.Matches) > 0
	for _, m := range vr.Matches {
		if !m.Resolved {
			dep.Complete = false
			continue
		}
		if !slices.Contains(dep.Versions, m.Version) {
			dep.Versions = append(dep.Versions, m.Version)
		}
	}
	return dep
}

// presentPackage is an affected package the codebase carries besides the selected one. The version
// axis must clear it too: a patched first package does not clear an affected second one.
type presentPackage struct {
	Module     string   `json:"module,omitempty"`
	Coordinate string   `json:"coordinate,omitempty"`
	Versions   []string `json:"versions,omitempty"`
	Complete   bool     `json:"complete"`
}

// PackageKey is one dependency identity an advisory's facts name: the key codebase_inventory
// resolves a version by. Ecosystem is the PURL type ("golang", "maven", "npm", "pypi", "nuget"), or
// "" when the package carries no parseable PURL.
type PackageKey struct {
	Ecosystem string
	Name      string
}

// AffectedPackageKeys returns every dependency identity the advisory could apply to a codebase
// through, deduplicated, in declaration order: each affected_packages[] element, then the scalar
// primary. The name is exactly what resolveDependencyVersion looks the package up by — the Go module
// path (go.mod require), "stdlib" for a go-toolchain package (the subject's toolchain), else the
// ecosystem coordinate (the plugin's dependency coordinate). A package with none of the three names
// no dependency, and an advisory that yields no keys at all carries no coordinates to match.
//
// It decides applicability by IDENTITY only. The version axis is evaluated per advisory by the
// disqualification stage once the advisory is in the work set.
func AffectedPackageKeys(f AdvisoryFacts) []PackageKey {
	var keys []PackageKey
	seen := make(map[PackageKey]struct{})
	add := func(module, coordinate, purl, scheme string) {
		if scheme == "" {
			scheme = schemeFromPURL(purl)
		}
		var k PackageKey
		switch {
		case scheme == "go-toolchain" || isGoStdlibPURL(purl):
			k = PackageKey{Ecosystem: "golang", Name: goStdlibPURLName}
		case module != "":
			k = PackageKey{Ecosystem: "golang", Name: module}
		case coordinate != "":
			k = PackageKey{Ecosystem: purlEcosystem(purl), Name: coordinate}
		default:
			return
		}
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for _, p := range f.AffectedPackages {
		add(p.Module, p.Coordinate, p.PURL, p.VersionScheme)
	}
	add(f.Module, f.Coordinate, f.PURL, f.VersionScheme)
	return keys
}

func (s codebaseInventory) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	buildDir, language := "", ""
	var plan checkout.WorkspacePlan
	acq := c.Request.Codebase.Acquisition
	switch {
	case acq.Mode == "vendored_repro":
		p, err := s.memo.resolveVendored(acq.Path)
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

	// checkoutRoot is the directory the codebase was actually checked out into. It is captured here,
	// before any later module-root reassignment could move buildDir off the checkout root (a nested
	// Go module, TEG-062, absent on this module today), so a downstream reader that needs the real
	// checked-out tree — e.g. the Prove sandbox_observability stage's Dockerfile lookup, F39/TEG-064 —
	// can still reach it. Equal to buildDir for every non-nested tree, which is every tree here.
	checkoutRoot := buildDir

	// Pin the concrete commit SHA the assessment was checked out at (T1 reproducibility anchor):
	// the requested Revision is a branch/tag/ref; rev-parse resolves it to the exact commit so a
	// third party knows precisely which source was assessed. The orchestrator persists this Subject
	// mutation after the stage, so it reaches verdict-emission (firepersist projects it into
	// proof_verdicts.subject_repo_ref). Fails soft to "" for the vendored_repro path (not a git
	// tree); only an explicit ResolvedCommit on the request (OSS --commit) takes precedence.
	if buildDir != "" && c.Subject.ResolvedCommit == "" {
		if sha, err := s.memo.resolveHead(ctx, buildDir); err != nil {
			return err
		} else if sha != "" {
			c.Subject.ResolvedCommit = sha
		}
	}

	// A Go module need not live at the checkout root: a monorepo may nest it under
	// target/, src/, or a cmd/service subdirectory. checkout.FindGoModuleRoot re-runs the same
	// bounded search DetectLanguage used to accept this tree, and everything from here on
	// (BuildManifest, the toolchain fact, dependency-version resolution, and the persisted
	// inv.BuildDir every later stage reads back) must operate on the MODULE root, not the
	// checkout root — go.mod-relative reads and Go tooling invocations only work from there.
	// This intentionally runs AFTER ResolveHead above: ResolveHead needs the actual git checkout
	// root (where .git lives) to pin ResolvedCommit, and reassigning buildDir first would silently
	// lose that anchor for a nested module.
	if language == checkout.LangGo {
		if root, ok := s.memo.goModuleRoot(buildDir); ok {
			buildDir = root
		}
	}

	// The go.work the build runs under, resolved once here and recorded for every later reader, so the
	// analyzer loads the same workspace ownership, presence and the version axis read. A workspace
	// that cannot be established fails the stage: no fact about the build may rest on a guess at it.
	var goWork GoWorkspace
	if language == checkout.LangGo && buildDir != "" {
		ws, err := s.memo.goWorkspace(ctx, buildDir, checkoutRoot, s.subjectGoWork)
		if err != nil {
			return fmt.Errorf("resolve the build's go.work: %w", err)
		}
		goWork = ws
	}

	module, goVersion, buildCommand, toolchainDirective, buildToolchain := "", "", "", "", ""
	if s.plugin != nil && buildDir != "" && s.plugin.Language() == language {
		mani, err := s.plugin.BuildManifest(ctx, plugin.BuildManifestRequest{BuildDir: buildDir, GoWork: goWork.File})
		if err != nil {
			return err
		}
		module = mani.ProjectRoot
		if rt, ok := mani.PrimaryRuntime(); ok {
			goVersion = rt.Version
			toolchainDirective = rt.Toolchain
			buildToolchain = rt.Resolved
		}
		if rs, ok := mani.PrimaryResolver(); ok {
			buildCommand = rs.Command
		}
	}

	// The subject's Go toolchain as ONE resolved fact carrying its own strength. This is
	// the single resolution site: the raw go_version above stays exactly what it was (the verbatim
	// `go` directive, read by nobody) and the fact is derived beside it, never instead of it. It is
	// resolved BEFORE dependency-version resolution because the version axis consumes it: for a
	// go-toolchain-scheme advisory this fact IS resolved_version.
	//
	// Go-only by construction. The floor is a go.mod directive and the exact tiers are statements
	// about a Go build environment, so resolving this for a JS/Java/Python/.NET subject would label
	// the RUNNER's Go as the subject's — the same category error the fact exists to close. Other
	// ecosystems' runtime versions (e.g. a node engine range) live in RuntimeSpec{Name:"node"}, not here.
	toolchain := ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}
	goFloor := ""
	if language == "go" {
		goDirective := goVersion
		if goWork.File != "" {
			// A workspace build runs under the go.work's go and toolchain lines and ignores its
			// modules' own toolchain lines, so those are what bound its toolchain and its floor.
			goDirective, toolchainDirective = goWork.Directives()
		}
		cands := ToolchainCandidates{
			SubjectDeclared:    s.subjectGoVersion,
			CIObserved:         s.ciGoVersion,
			TrustCIObserved:    s.trustCIGoVersion,
			BuildResolved:      buildToolchain,
			ToolchainDirective: toolchainDirective,
			GoDirective:        goDirective,
			BazelWorkspace:     s.memo.bazelWorkspaceAbove(buildDir),
		}
		toolchain = ResolveToolchain(cands)
		if !cands.BazelWorkspace {
			goFloor = goLineFloor(toolchainInputs{toolchainDirective: cands.ToolchainDirective, goDirective: cands.GoDirective})
		}
	}

	src := s.src
	if src == nil {
		src = defaultAdvisorySource()
	}
	facts, _ := src.Lookup(c.Request.Vulnerability.ID) // miss → zero facts → fail-open (bool intentionally discarded)
	var (
		resolved        depVersions
		alsoPresent     []presentPackage
		partialityFlags []string
		// annotations is every assumption a resolution of any affected package rested on: an
		// install command the lane assumed inactive qualifies every version it read in the scan.
		annotations []plugin.Annotation
	)
	// presenceVersion is the version maliciousPresence matches against: the package selection
	// below run over each package's first resolved copy rather than its agreed Match. It is
	// never read by the not-affected path.
	presenceVersion := ""
	// selectedModule/selectedCoordinate name the v3 affected_packages[] element the target actually
	// depends on (the select-by-target pick). They are the join key the downstream extractors use to
	// read the SELECTED element's ranges/symbols/identity off the normalized-advisory artifact. Both
	// empty ⇒ no element selected: the scalar-primary path ran (a v2 advisory, or a v3 advisory whose
	// packages the target does not depend on → OPEN).
	var selectedModule, selectedCoordinate string
	// isRoot records that the adjudicated package is the scanned project itself (its manifest's own
	// identity), so its vulnerable code is first-party and its version is the project's.
	isRoot := false
	if buildDir != "" {
		root, hasRoot := s.memo.readRootPackage(ctx, buildDir, language)
		resolve := func(module, coordinate, purl, scheme string) (depVersions, []string, bool, error) {
			if v, ok := root.Matches(buildDir, goWork, module, coordinate, purl); hasRoot && ok {
				dep := singleVersion(v)
				dep.Found = true
				return dep, nil, true, nil
			}
			dep, flags, err := s.resolveDependencyVersion(ctx, buildDir, goWork, language, module, coordinate, scheme, toolchain)
			for _, a := range dep.Annotations {
				if !slices.Contains(annotations, a) {
					annotations = append(annotations, a)
				}
			}
			return dep, flags, false, err
		}
		presenceSelected := false
		// v3 select-by-target: iterate the advisory's full affected set (producer-sorted,
		// deterministic) and pick the FIRST package the assessed codebase actually depends on. This
		// is the whole point of the multi-package block — a target on a SECONDARY package resolves
		// into real version/symbol analysis instead of falling OPEN against an unmatched primary.
		// Every other package is resolved too and recorded when the codebase declares it, since the
		// version axis must clear each one; one that cannot be resolved after the selection is
		// recorded as present with no versions, which keeps the axis open.
		selected := false
		for _, pkg := range facts.AffectedPackages {
			dep, flags, rootPkg, err := resolve(pkg.Module, pkg.Coordinate, pkg.PURL, pkg.VersionScheme)
			if err != nil {
				if !selected {
					return err
				}
				alsoPresent = append(alsoPresent, presentPackage{Module: pkg.Module, Coordinate: pkg.Coordinate})
				continue
			}
			if !presenceSelected && (dep.Presence != "" || rootPkg) {
				presenceVersion, presenceSelected = dep.Presence, true
			}
			// A package the target declares ends the selection even when its version is unresolved:
			// moving on would adjudicate the advisory on another package's ranges while this one
			// may sit inside its own. It is selected with no version, so the version axis stays open.
			// The presence scan goes on past it to the first package with a resolved copy.
			switch {
			case !selected && (dep.Version != "" || dep.Found || rootPkg):
				resolved, partialityFlags, isRoot = dep, flags, rootPkg
				selectedModule, selectedCoordinate = pkg.Module, pkg.Coordinate
				selected = true
			case dep.Found:
				alsoPresent = append(alsoPresent, presentPackage{
					Module: pkg.Module, Coordinate: pkg.Coordinate, Versions: dep.Versions, Complete: dep.Complete,
				})
			}
		}
		// Fail-open (inv.5, load-bearing): no array element matched THIS target (or the advisory is
		// v2/single-package: AffectedPackages is empty) → fall back to the scalar primary. This is
		// byte-identical to the pre-v3 resolution, so a v2 advisory and a v3-no-match target both get
		// today's exact behavior (typically OPEN). Selection NEVER fabricates a not-affected.
		// The presence scan falls back the same way when no array element had a resolved copy.
		// That presence-only lookup is best effort: an error there leaves presence empty rather
		// than failing a stage that has already selected its package.
		if !selected || !presenceSelected {
			dep, flags, rootPkg, err := resolve(facts.Module, facts.Coordinate, facts.PURL, facts.VersionScheme)
			if err != nil && !selected {
				return err
			}
			if !selected {
				resolved, partialityFlags, isRoot = dep, flags, rootPkg
			}
			if !presenceSelected {
				presenceVersion = dep.Presence
			}
		}
	}
	// Non-Go no-manifest-entry oracle (manifest_membership.go): only consulted when nothing
	// resolved and the package is not the project itself, since either is present by
	// construction. A root package need not list itself, and may match with no version.
	var membership *manifestMembership
	if buildDir != "" && resolved.Version == "" && !isRoot {
		membership = resolveManifestMembership(ctx, s.plugin, buildDir, language, AffectedPackageKeys(facts))
	}

	inv := struct {
		Repo     string `json:"repo"`
		Revision string `json:"revision"`
		BuildDir string `json:"build_dir"`
		// CheckoutRoot is the directory the codebase was actually checked out into, captured BEFORE
		// a nested Go module (TEG-062) reassigns BuildDir to the module root. Equal to BuildDir for
		// every non-Go and non-nested-Go tree. Read back by InventoryCheckoutRoot (F39, TEG-064).
		CheckoutRoot string `json:"checkout_root,omitempty"`
		// GoWork is the go.work the Go build runs under, read back by InventoryGoWorkspace.
		GoWork   GoWorkspace `json:"go_work"`
		Language string      `json:"language,omitempty"`
		// WorkspacePlan is the full enumeration of detected projects (one today; PLAN-400 makes it
		// hold true monorepos). It is PERSISTED but not yet read by any downstream stage — the scalar
		// build_dir/language above remain the primary-project projection S3–S6 consume. Landing the
		// field now (the PLAN-000 pattern) makes the contract real end-to-end; PLAN-400 wires the
		// per-project readers. Not dead code: it is the on-disk half of the WorkspacePlan contract.
		WorkspacePlan   checkout.WorkspacePlan `json:"workspace_plan"`
		ResolvedVersion string                 `json:"resolved_version,omitempty"`
		// ResolvedVersions is every distinct version the codebase carries of the adjudicated
		// package; VersionsComplete reports that it covers every declaration. AlsoPresent is each
		// other affected package the codebase declares. Read back by extractVersionAxis.
		ResolvedVersions []string         `json:"resolved_versions,omitempty"`
		VersionsComplete bool             `json:"versions_complete,omitempty"`
		AlsoPresent      []presentPackage `json:"also_present,omitempty"`
		// PresenceVersion is the version maliciousPresence matches against (presenceVersion
		// above). Read back by extractPresenceVersion only.
		PresenceVersion string   `json:"presence_version,omitempty"`
		Module          string   `json:"module,omitempty"`
		GoVersion       string   `json:"go_version,omitempty"`
		BuildCommand    string   `json:"build_command,omitempty"`
		PartialityFlags []string `json:"partiality_flags,omitempty"`
		// Annotations are the assumptions the resolved versions rest on. Unlike PartialityFlags
		// they leave the resolution complete; trigger discloses them on every verdict they qualify.
		Annotations []plugin.Annotation `json:"annotations,omitempty"`
		// Toolchain is the subject's Go toolchain resolved to one bounded fact. Always
		// emitted, including as {"bound":"none","source":"unresolved"} — an explicit "we looked and
		// established nothing" is a disclosure, and a silently absent field is how the version axis
		// stayed dark. Read back by Toolchain() (the version axis, and the scan-level disclosure
		// trigger/assess.go emits for a toolchain advisory it could not adjudicate).
		Toolchain ToolchainFact `json:"toolchain"`
		// GoFloor is the go.mod `go` line when it binds (goLineFloor): no build of the subject runs a
		// Go below it. Read back by toolchainFloor for the reachability request.
		GoFloor string `json:"go_floor,omitempty"`
		// SelectedModule/SelectedCoordinate name the v3 affected_packages[] element select-by-target
		// picked (the package the target depends on). They are the join key extractSelectedPackage
		// uses to read the selected element off the normalized-advisory artifact. Both empty ⇒ scalar
		// primary path (v2 advisory or v3-no-match) → extractors read the top-level scalar block.
		SelectedModule     string `json:"selected_module,omitempty"`
		SelectedCoordinate string `json:"selected_coordinate,omitempty"`
		// Root is true when the adjudicated package is the scanned project itself. Read back by
		// RootSubject.
		Root bool `json:"root,omitempty"`
		// ManifestMembership is the PyPI/npm manifest-membership fact the intake no-manifest-entry
		// guard reads back (intakeManifestMembership). Absent ⇒ no fact ⇒ the guard fails open.
		ManifestMembership *manifestMembership `json:"manifest_membership,omitempty"`
	}{
		Repo:               c.Request.Codebase.Repo,
		Revision:           c.Request.Codebase.Revision,
		BuildDir:           buildDir,
		CheckoutRoot:       checkoutRoot,
		GoWork:             goWork,
		Language:           language,
		WorkspacePlan:      plan,
		ResolvedVersion:    resolved.Version,
		ResolvedVersions:   resolved.Versions,
		VersionsComplete:   resolved.Complete,
		AlsoPresent:        alsoPresent,
		PresenceVersion:    presenceVersion,
		Module:             module,
		GoVersion:          goVersion,
		BuildCommand:       buildCommand,
		PartialityFlags:    partialityFlags,
		Annotations:        annotations,
		Toolchain:          toolchain,
		GoFloor:            goFloor,
		SelectedModule:     selectedModule,
		SelectedCoordinate: selectedCoordinate,
		Root:               isRoot,
		ManifestMembership: membership,
	}
	_, err := PutArtifact(store, c, s.Name(), artifact.TypeInventory, "codebase inventory", inv)
	return err
}

// BazelWorkspaceAbove reports whether a Bazel workspace marker file sits in moduleRoot or any
// directory above it up to the git top-level of moduleRoot, inclusive, and never above it; it is false
// when that top-level cannot be determined. Bazel (rules_go) takes its Go SDK from the workspace, not
// from go.mod, so the go line is no floor on the release a Bazel build compiles with.
func BazelWorkspaceAbove(moduleRoot string) bool {
	found, _ := bazelWorkspaceAbove(moduleRoot)
	return found
}

// bazelWorkspaceAbove is BazelWorkspaceAbove, also reporting whether the git top-level it searches
// to could be determined; found is false when it could not.
func bazelWorkspaceAbove(moduleRoot string) (found, determined bool) {
	if moduleRoot == "" {
		return false, true
	}
	top, err := gitOutput(context.Background(), moduleRoot, "rev-parse", "--show-toplevel")
	if err != nil || top == "" {
		return false, false
	}
	top, err = filepath.EvalSymlinks(top)
	if err != nil {
		return false, false
	}
	dir, err := filepath.EvalSymlinks(filepath.Clean(moduleRoot))
	if err != nil {
		return false, false
	}
	for {
		for _, marker := range []string{"MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"} {
			if fi, err := os.Stat(filepath.Join(dir, marker)); err == nil && !fi.IsDir() {
				return true, true
			}
		}
		if dir == top {
			return false, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false, true
		}
		dir = parent
	}
}

// moduleVersionFromGoMod parses buildDir/go.mod and returns the version the build selects for
// module: its require version, or the version a same-module replace directive substitutes.
//
// manifestRead separates the reasons the version can come back empty: false means go.mod was
// absent or unparseable, so nothing about the dependency set was established; true with an
// empty version and pinned true means go.mod does not require the module, a real fact about the
// codebase. pinned false means the module is required but replaced by a local directory or by
// another module, so the build compiles code no upstream version describes.
func moduleVersionFromGoMod(buildDir, module string) (version string, pinned, manifestRead bool) {
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return "", false, false
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return "", false, false
	}
	for _, r := range mf.Require {
		if r.Mod.Path != module {
			continue
		}
		t, ok := gomod.Replacement(mf, module, r.Mod.Version)
		switch {
		case !ok:
			return r.Mod.Version, true, true
		case t.Filesystem || t.Path != module:
			return "", false, true
		default:
			return t.Version, true, true
		}
	}
	return "", true, true
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

// InventoryGoWorkspace returns the go.work codebase_inventory resolved for the Go build; the zero
// workspace (GOWORK=off) when none was recorded.
func InventoryGoWorkspace(store artifact.Store, caseID string) (GoWorkspace, error) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return GoWorkspace{}, err
	}
	var inv struct {
		GoWork GoWorkspace `json:"go_work"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return GoWorkspace{}, err
	}
	return inv.GoWork, nil
}

// InventoryCheckoutRoot returns the checkout root recorded by codebase_inventory — the directory
// the codebase was actually checked out into, which for a nested Go module (TEG-062) differs from
// InventoryBuildDir (the discovered module root). "" if none was recorded: a record written before
// this field existed, or a case where BuildDir was never set either — an honest absence, not an
// error (read-time only, no migration; F39, TEG-064).
func InventoryCheckoutRoot(store artifact.Store, caseID string) (string, error) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil {
		return "", err
	}
	if len(arts) == 0 {
		return "", nil
	}
	var inv struct {
		CheckoutRoot string `json:"checkout_root"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return "", err
	}
	return inv.CheckoutRoot, nil
}

// --- Stage 2b: malicious_presence ---------------------------------------------

// maliciousPresence is the decisive OSS "affected" stage. It fires ONLY on an affirmative match: a
// malicious-package (MAL) advisory whose enumerated affected set contains the version the codebase
// resolved. It reads two already-produced artifacts — the normalized-advisory malicious_package
// marker and the codebase-inventory presence_version — and NEVER re-Lookups.
//
// It is inserted after codebase_inventory (it needs presence_version) and before
// disqualification_discovery. It emits the affirmative TypeMaliciousPresence artifact or NOTHING;
// it can never mint a not-affected. Every non-match case (not malicious, unresolvable version,
// version-not-listed) falls through to the existing reconcile path unchanged (inv.5 fail-open):
//
//   - not declared malicious ⇒ no-op ⇒ every existing stage runs as today.
//   - declared + presence_version == "" (unresolvable/absent) ⇒ no match ⇒ OPEN, never clear.
//   - declared + presence_version NOT in the enumerated set ⇒ no affirmative ⇒ existing fail-open.
//   - declared + presence_version IN the set (EXACT string equality, no comparator) ⇒ affirmative.
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
	presence, ok := extractPresenceVersion(store, c.ID)
	axis, axisOK := extractVersionAxis(store, c.ID)
	if !ok && !axisOK {
		return nil // no resolved copy (unresolvable/absent) → no match → OPEN
	}
	// Any version the codebase carries at a listed version is present; the set need not be complete
	// to affirm one. The first resolved copy leads, then every agreed-on or listed copy.
	candidates := axis.Versions
	if ok {
		candidates = append([]string{presence}, candidates...)
	}
	for _, resolved := range candidates {
		if slices.Contains(versions, resolved) { // exact string membership — no semver comparator
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
// upper-exclusive semver bound (the "affects < X" form), floored by an inclusive LowerInclusive
// bound when the range was introduced above zero. LastAffected is the inclusive upper bound a range
// carries when it has no upper-exclusive one. versionOutsideRange is the one reading of all of
// them.
type affectedRange struct {
	UpperExclusive string `json:"upper_exclusive"`
	Scheme         string `json:"scheme,omitempty"`
	LowerInclusive string `json:"lower_inclusive,omitempty"` // an introduced bound above zero
	LastAffected   string `json:"last_affected,omitempty"`
	Type           string `json:"type,omitempty"`
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
			ar := affectedRange{UpperExclusive: r.Fixed, Scheme: scheme, LastAffected: r.LastAffected, Type: r.Type}
			// OSV writes an unbounded start as "0"; some feeds spell it "0.0.0".
			if r.Introduced != "0" && r.Introduced != "0.0.0" {
				ar.LowerInclusive = r.Introduced
			}
			out = append(out, ar)
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
	case "kotlin":
		return "maven" // Kotlin/JVM artifacts are Maven-keyed in OSV regardless of source language (A2).
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
// guard: it reports whether buildDir/go.mod declares module (as the root module, a package path
// inside it, or a require), or a module the go.work in force uses declares it the same way, and
// whether that was readable at all. A module none of them declares is decided by the regime:
//   - under a go.work, the build list the go command computes: presence when it holds the module,
//     absence when it does not;
//   - outside one, goModBuilds: a replace is presence; from go 1.17 the missing require is absence;
//     below 1.17 or with no go directive, vendor/modules.txt and go.sum's module-zip hashes decide.
//
// manifestKnown=false — no build dir; an absent / unparseable go.mod or go.work; a build list the
// go command could not compute; or, below go 1.17 outside a workspace, a missing or unparseable
// go.sum or an unparseable vendor/modules.txt — forces the caller to fail OPEN, because absence is
// only PROVABLE against a manifest actually parsed (inv.5). PyPI and npm use the plugin oracle in
// manifest_membership.go.
//
// Those manifests are the whole build only when no other module of the checkout can build against
// module, so a module none of them declares is unknown, not absent, when:
//   - the build runs under ws (its effective GOWORK is on and names ws.File) and the go command's
//     build list for it cannot be computed. A computed list is decisive, since the go command
//     computes it over the whole workspace graph, members below go 1.17 included;
//   - the build runs with GOWORK=off and a go.work sits in buildDir: the walk leaves the modules it
//     uses out, and nothing here reads what their builds draw on;
//   - nested reports a module outside buildDir's module graph that may require it (gomodtree.Tree's
//     MayRequire: one whose go.mod names it, declares go below 1.17 or does not parse), or a walk that
//     could not read the whole tree. This holds under a workspace too.
//
// nested is called only when no manifest declares module.
func goModRequires(ctx context.Context, buildDir string, ws GoWorkspace, module string, nested func() gomodtree.Tree) (present bool, manifestKnown bool) {
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
	var root string
	if mf.Module != nil {
		root = mf.Module.Mod.Path
		if goPathOwner(buildDir, ws, root, module) != goOwnedElsewhere {
			return true, true
		}
	}
	declares := func(mf *modfile.File) bool {
		for _, r := range mf.Require {
			if r.Mod.Path == module || strings.HasPrefix(module, r.Mod.Path+"/") {
				return true
			}
		}
		return false
	}
	if declares(mf) {
		return true, true
	}
	uses, _, ok := ws.uses()
	if !ok {
		return false, false
	}
	for _, use := range uses {
		data, err := os.ReadFile(filepath.Join(use, "go.mod"))
		if err != nil {
			return false, false
		}
		wm, err := modfile.Parse("go.mod", data, nil)
		if err != nil || wm.Module == nil {
			return false, false
		}
		if p := wm.Module.Mod.Path; p != root && (module == p || strings.HasPrefix(module, p+"/")) || declares(wm) {
			return true, true
		}
	}
	if ws.File != "" {
		// Under a go.work no go.mod states what is in the build: a dependency the workspace selects at
		// a higher version can bring in a module none of them lists. Only the build list decides.
		mods, err := workspaceBuildList(ctx, buildDir, ws)
		if err != nil {
			return false, false
		}
		for _, m := range mods {
			if !m.Main && (module == m.Path || strings.HasPrefix(module, m.Path+"/")) {
				return true, true
			}
		}
	} else if fi, err := os.Stat(filepath.Join(buildDir, "go.work")); err == nil && !fi.IsDir() {
		return false, false
	} else if present, known := goModBuilds(buildDir, mf, module); present || !known {
		return present, known
	}
	if nested().MayRequire(module) {
		return false, false
	}
	return false, true
}

// goModBuilds answers membership outside a workspace for a module buildDir/go.mod does not require.
// A replace of module is presence at any go version. From go 1.17 go.mod lists every module that
// provides a package to the build, so a missing require is absence. Below that, or with no go
// directive, go.mod omits indirect dependencies, and the build list is what the build verifies:
// a module vendor/modules.txt lists, or one go.sum holds a module-zip (non-/go.mod) h1: line for,
// is present, and one in neither is absent. A go.sum missing or unparseable there, or a
// vendor/modules.txt that does not parse, leaves it unknown.
func goModBuilds(buildDir string, mf *modfile.File, module string) (present bool, manifestKnown bool) {
	for _, r := range mf.Replace {
		if module == r.Old.Path || strings.HasPrefix(module, r.Old.Path+"/") {
			return true, true
		}
	}
	if mf.Go != nil && goVersionAtLeast(mf.Go.Version, "1.17") {
		return false, true
	}
	if present, ok := goVendorHas(filepath.Join(buildDir, "vendor", "modules.txt"), module); present || !ok {
		return present, ok
	}
	return goSumHas(filepath.Join(buildDir, "go.sum"), module)
}

// goVersionAtLeast reports whether the go directive version v is at least min; an unparseable v
// reads as below it, which sends the caller to the go.sum check and its own fail-open.
func goVersionAtLeast(v, min string) bool {
	return gover.IsValid("go"+v) && gover.Compare("go"+v, "go"+min) >= 0
}

// goVendorHas reports whether the vendor/modules.txt at file lists module, or a module its path
// sits under; ok is false when the file exists but cannot be read or a module line in it does not
// parse. A missing file lists nothing.
func goVendorHas(file, module string) (present, ok bool) {
	data, err := os.ReadFile(file)
	if err != nil {
		return false, os.IsNotExist(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "#") || strings.HasPrefix(line, "##") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "#" {
			return false, false
		}
		if f[1] == module || strings.HasPrefix(module, f[1]+"/") {
			present = true
		}
	}
	return present, true
}

// goSumHas reports whether the go.sum at file holds a module-zip (non-/go.mod) h1: line for module
// or for a module its path sits under, at any version; ok is false when the file is missing or does
// not parse.
func goSumHas(file, module string) (present, ok bool) {
	data, err := os.ReadFile(file)
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 || !strings.HasPrefix(f[2], "h1:") {
			return false, false
		}
		if strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		if f[0] == module || strings.HasPrefix(module, f[0]+"/") {
			present = true
		}
	}
	return present, true
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

// disqualifyEvery is disqualify over every version the codebase carries. The version axis refutes
// only when the set is complete and each version, of the selected package and of every other
// affected package present, is provably outside its own ranges; the symbol axis and the trust gate
// are disqualify's, unchanged.
func disqualifyEvery(rngs []affectedRange, rangeKnown bool, axis versionAxis, axisKnown bool, others []presentRanges, symbol string, symbolKnown bool, trust TrustTier) (bool, string) {
	if disq, reason := disqualify(rngs, rangeKnown, "", false, symbol, symbolKnown, trust); disq || trust != TrustFirstParty {
		return disq, reason
	}
	if !axisKnown || !everyVersionOutside(axis.Versions, axis.Complete, rngs, rangeKnown, trust) {
		return false, ReasonInsufficient
	}
	for _, o := range others {
		if !everyVersionOutside(o.Versions, o.Complete, o.Ranges, o.RangeKnown, trust) {
			return false, ReasonInsufficient
		}
	}
	return true, ReasonVersionNotInRange
}

func everyVersionOutside(vers []string, complete bool, rngs []affectedRange, rangeKnown bool, trust TrustTier) bool {
	if !complete || len(vers) == 0 {
		return false
	}
	for _, v := range vers {
		if disq, _ := disqualify(rngs, rangeKnown, v, true, "", false, trust); !disq {
			return false
		}
	}
	return true
}

// VersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper, under the given comparator scheme ("" / "gomod" | "maven" | "npm").
// It is the exported seam external callers use to
// share the disqualification axis's exact version semantics: ok=false means the
// version or bound is invalid, a prerelease the scheme cannot order, or unparseable,
// and the predicate must fail OPEN (inv.5), never fabricate a not-affected.
// Single-sources versionOutsideRange.
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

// versionOutsideUpper reports whether ver is provably at or past rng's upper-exclusive bound
// (affects<upper). It reads only UpperExclusive and Scheme; versionOutsideRange adds the other bounds.
func versionOutsideUpper(ver string, rng affectedRange) (outside bool, ok bool) {
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
// when there is no artifact, no range, or ANY range carries no bound at all: a set with
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
	return affectedPackageNamed(adv.AffectedPackages, inv.SelectedModule, inv.SelectedCoordinate)
}

// affectedPackageNamed returns the advisory's entry for a package, merged across every element that
// names it. An advisory may list one package in several affected[] entries, and a version in any of
// their ranges is affected, so the ranges are unioned; judging the first entry alone would refute a
// version only a later entry covers. An entry with no ranges, or no symbols, leaves that field
// unknown for the whole package rather than letting the other entries narrow it.
func affectedPackageNamed(pkgs []advisoryAffectedPackage, module, coordinate string) (advisoryAffectedPackage, bool) {
	var (
		out                     advisoryAffectedPackage
		found, rangeless, blind bool
	)
	for _, p := range pkgs {
		if !(module != "" && p.Module == module) && !(coordinate != "" && p.Coordinate == coordinate) {
			continue
		}
		rangeless = rangeless || len(p.AffectedRanges) == 0
		blind = blind || len(p.Symbols) == 0
		if !found {
			out, found = p, true
			out.AffectedRanges = slices.Clone(p.AffectedRanges)
			out.Symbols = slices.Clone(p.Symbols)
			continue
		}
		out.AffectedRanges = append(out.AffectedRanges, p.AffectedRanges...)
		for _, sym := range p.Symbols {
			if !slices.Contains(out.Symbols, sym) {
				out.Symbols = append(out.Symbols, sym)
			}
		}
	}
	if rangeless {
		out.AffectedRanges = nil
	}
	if blind {
		out.Symbols = nil
	}
	return out, found
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
// carries at least one bound (upper-exclusive, last_affected or introduced). A set with one boundless
// range cannot soundly prove outside-EVERY-range, so the whole set is withheld (rangeKnown=false → the
// version axis fails OPEN, inv.5) rather than disqualifying on the expressable subset (which would
// risk a fabricated not-affected).
func validAffectedRanges(rngs []affectedRange) ([]affectedRange, bool) {
	if len(rngs) == 0 {
		return nil, false
	}
	for _, r := range rngs {
		if r.UpperExclusive == "" && r.LastAffected == "" && r.LowerInclusive == "" {
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

// RootSubject reports whether codebase_inventory adjudicated the advisory against the scanned
// project itself rather than a dependency: the project's own manifest identity is the advisory's
// package, so the vulnerable code is first-party.
func RootSubject(store artifact.Store, caseID string) bool {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return false
	}
	var inv struct {
		Root bool `json:"root"`
	}
	return json.Unmarshal(arts[0].Payload, &inv) == nil && inv.Root
}

// Toolchain returns the subject's Go toolchain as the bounded fact codebase_inventory resolved.
// ok is false when there is no inventory artifact at all; a run that looked and
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
// SUBJECT's Go toolchain. It is the licence a stdlib refutation-by-absence needs: only
// when it is true is an empty path set evidence about the subject rather than about the analyzer.
//
// It is false in every other state, and deliberately conflates none of them — flag off, floor-only
// or unresolved bound, a toolchain that could not be fetched, a build the subject's toolchain could
// not complete, a stub/skeleton run with no analyzer at all. Each of those is a scan under the
// analyzer's toolchain, and they are all the same thing to a verdict: not established. A reader that
// wants to tell them apart reads the ToolchainScan block itself.
func SubjectToolchainScanned(store artifact.Store, caseID string) bool {
	rec, ok, err := Reachability(store, caseID)
	if err != nil || !ok {
		return false
	}
	ts, err := rec.ToolchainScan()
	if err != nil {
		return false
	}
	return ts.Subject
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

// versionAxis is the version-axis input codebase_inventory recorded for the adjudicated package.
type versionAxis struct {
	Versions []string
	Complete bool
}

// presentRanges is another present affected package joined to its own ranges.
type presentRanges struct {
	presentPackage
	Ranges     []affectedRange
	RangeKnown bool
}

// extractVersionAxis reads every version codebase_inventory resolved for the adjudicated package.
// The set stands without a resolved_version, which is empty when the copies disagree. An inventory
// that recorded a resolved_version with no set yields that version alone, never complete.
func extractVersionAxis(store artifact.Store, caseID string) (versionAxis, bool) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return versionAxis{}, false
	}
	var inv struct {
		ResolvedVersion  string   `json:"resolved_version"`
		ResolvedVersions []string `json:"resolved_versions"`
		VersionsComplete bool     `json:"versions_complete"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return versionAxis{}, false
	}
	switch {
	case len(inv.ResolvedVersions) > 0:
		return versionAxis{Versions: inv.ResolvedVersions, Complete: inv.VersionsComplete}, true
	case inv.ResolvedVersion != "":
		return versionAxis{Versions: []string{inv.ResolvedVersion}}, true
	}
	return versionAxis{}, false
}

// extractAlsoPresent joins each other affected package the inventory recorded to its ranges on the
// normalized advisory. A package the advisory no longer names keeps no ranges, which keeps the axis open.
// The toolchain package's ranges lose their lower bounds when the toolchain version is only a floor,
// as rangesForToolchainFloor says.
func extractAlsoPresent(store artifact.Store, caseID string) []presentRanges {
	invArts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(invArts) == 0 {
		return nil
	}
	var inv struct {
		AlsoPresent []presentPackage `json:"also_present"`
	}
	if err := json.Unmarshal(invArts[0].Payload, &inv); err != nil || len(inv.AlsoPresent) == 0 {
		return nil
	}
	var adv struct {
		AffectedPackages []advisoryAffectedPackage `json:"affected_packages"`
	}
	if advArts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory); err == nil && len(advArts) > 0 {
		_ = json.Unmarshal(advArts[0].Payload, &adv) // a miss leaves every package rangeless: OPEN
	}
	out := make([]presentRanges, 0, len(inv.AlsoPresent))
	for _, p := range inv.AlsoPresent {
		pr := presentRanges{presentPackage: p}
		if a, ok := affectedPackageNamed(adv.AffectedPackages, p.Module, p.Coordinate); ok {
			pr.Ranges, pr.RangeKnown = validAffectedRanges(a.AffectedRanges)
			if toolchainSubject(a.PURL, pr.Ranges) {
				pr.Ranges = rangesForToolchainFloor(store, caseID, pr.Ranges)
			}
		}
		out = append(out, pr)
	}
	return out
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

// extractPresenceVersion returns the inventory's presence_version, falling back to
// resolved_version for a record that carries none. ok is false when both are empty.
func extractPresenceVersion(store artifact.Store, caseID string) (string, bool) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return "", false
	}
	var inv struct {
		ResolvedVersion string `json:"resolved_version"`
		PresenceVersion string `json:"presence_version"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return "", false
	}
	if inv.PresenceVersion != "" {
		return inv.PresenceVersion, true
	}
	return inv.ResolvedVersion, inv.ResolvedVersion != ""
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
	goWork, err := InventoryGoWorkspace(store, c.ID)
	if err != nil {
		return err
	}
	advModule, _ := extractAdvisoryModule(store, c.ID)
	coordinate, manifestHas, manifestKnown := intakeManifestMembership(ctx, store, c.ID, buildDir, goWork, advModule)
	if disq, reason := intakeDisqualify(
		extractAdvisoryEcosystem(store, c.ID),
		extractCodebaseEcosystem(store, c.ID),
		coordinate, manifestHas, manifestKnown,
	); disq {
		res := DisqualResult{Disqualified: true, Reason: reason}
		_, err := PutArtifact(store, c, s.Name(), artifact.TypeDiscovery, "disqualification discovery (un-adjudicable at intake)", res)
		return err
	}

	rngs, rangeKnown := extractAffectedRange(store, c.ID)
	rngs = rangesForFloorVersion(store, c.ID, rngs)
	axis, axisKnown := extractVersionAxis(store, c.ID)
	symbol, symbolKnown := extractSymbolSignal(store, c.ID)
	trust, _ := extractAdvisoryTrust(store, c.ID) // miss/unknown ⇒ zero tier ⇒ refute suppressed (inv.5)

	disqualified, reason := disqualifyEvery(rngs, rangeKnown, axis, axisKnown, extractAlsoPresent(store, c.ID), symbol, symbolKnown, trust)
	res := DisqualResult{Disqualified: disqualified, Reason: reason}

	descriptor := "disqualification discovery (proceeds: insufficient evidence)"
	if disqualified {
		descriptor = "disqualification discovery (provably not-affected)"
	}
	_, err = PutArtifact(store, c, s.Name(), artifact.TypeDiscovery, descriptor, res)
	return err
}

// settledByDisqualification reports whether S3 recorded the advisory as disqualified. An absent or
// undecodable discovery artifact reads as not disqualified, so the analysis stages still run.
func settledByDisqualification(store artifact.Store, assessmentID string) (bool, error) {
	arts, err := store.Query(assessmentID, artifact.TypeDiscovery)
	if err != nil || len(arts) == 0 {
		return false, err
	}
	var res DisqualResult
	if json.Unmarshal(arts[0].Payload, &res) != nil {
		return false, nil
	}
	return res.Disqualified, nil
}

// --- Stage 4: symbol_mapping --------------------------------------------------

type symbolMapping struct {
	plugin           plugin.LanguagePlugin
	skipDisqualified bool
	deps             *dependencyAcquirer
}

func (symbolMapping) Name() string              { return "symbol_mapping" }
func (symbolMapping) Status() assessment.Status { return assessment.StatusAnalysis }
func (s symbolMapping) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	if s.skipDisqualified {
		if settled, err := settledByDisqualification(store, c.ID); err != nil || settled {
			return err
		}
	}
	if s.plugin != nil {
		buildDir, err := InventoryBuildDir(store, c.ID)
		if err != nil {
			return err
		}
		goWork, err := InventoryGoWorkspace(store, c.ID)
		if err != nil {
			return err
		}
		purl, advisorySymbols := advisoryPURLAndSymbols(store, c.ID)
		req := plugin.ResolveSymbolsRequest{
			BuildDir:        buildDir,
			GoWork:          goWork.File,
			VulnID:          c.Request.Vulnerability.ID,
			PURL:            purl,
			AdvisorySymbols: advisorySymbols,
		}
		if dc := s.deps.cacheFor(store, c.ID); dc != "" {
			req.DependencyCache = dc
			req.Package = admittedPackagePURL(store, c.ID)
			if req.Package == "" {
				req.PackageVersions = affectedInstalledVersions(store, c.ID)
			}
		}
		res, err := s.plugin.ResolveDependencySymbols(ctx, req)
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
	// toolchain when it resolved to an exact version (flag-gated, off by default). See
	// WithSubjectToolchainReachability.
	subjectToolchain bool
	skipDisqualified bool
	deps             *dependencyAcquirer
	// libraryEntrypoints is handed to the plugin as is; nil is auto.
	libraryEntrypoints *plugin.LibraryEntrypoints
}

func (reachabilityIngress) Name() string              { return "reachability_ingress" }
func (reachabilityIngress) Status() assessment.Status { return assessment.StatusAnalysis }
func (s reachabilityIngress) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	if s.skipDisqualified {
		if settled, err := settledByDisqualification(store, c.ID); err != nil || settled {
			return err
		}
	}
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
// "run under the analyzer's own" — which is every case but one: the flag is on and the subject's
// toolchain resolved EXACT from a source that observed the subject.
//
// Four gates, and each is load-bearing rather than defensive:
//
//   - The flag. Running under the subject's toolchain changes the meaning of a green scan, so it
//     ships off by default for one release.
//   - An inventory fact must exist. No fact means no run resolved one; nothing to request.
//   - The bound must be EXACT. This is the asymmetry the whole design turns on: reachability's output
//     is a refutation by ABSENCE, and absence is only evidence about the toolchain the analysis ran
//     on. A floor ("at least go1.20") licenses a disqualification because outside() is monotone, but
//     scanning AT the floor would let a symbol missing from go1.20 be reported absent from a subject
//     that actually builds with go1.24. A consumer that branched on a non-empty Version alone would
//     reintroduce the defect in a new place.
//   - The source must not be build_resolved. That value is the analyzer's own go command resolving
//     the build directory, which in a dedicated scan job is the runner's Go; requested, it would
//     establish the build's Go release from the analyzer's, and the lane would exclude release-tagged
//     files on that say-so.
func (s reachabilityIngress) requestedToolchain(store artifact.Store, caseID string) string {
	if !s.subjectToolchain {
		return ""
	}
	fact, ok := Toolchain(store, caseID)
	if !ok || fact.Bound != ToolchainBoundExact || fact.Source == ToolchainSourceBuildResolved {
		return ""
	}
	return fact.Version
}

// toolchainFloor returns the subject's binding go line (goLineFloor) as codebase_inventory recorded
// it, or "" when it recorded none. It only ever narrows the files the analyzer reads as compiled, so
// unlike requestedToolchain it needs neither the flag nor an exact fact.
func (s reachabilityIngress) toolchainFloor(store artifact.Store, caseID string) string {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return ""
	}
	var inv struct {
		GoFloor string `json:"go_floor"`
	}
	if json.Unmarshal(arts[0].Payload, &inv) != nil {
		return ""
	}
	return inv.GoFloor
}

// entrypointsFor is the run's library-entrypoints statement with its paths based at the checkout
// root, which for a nested module lies above the build directory. A record with no checkout root
// leaves Base empty, so the lane reads the paths from the build directory.
func (s reachabilityIngress) entrypointsFor(store artifact.Store, caseID string) (*plugin.LibraryEntrypoints, error) {
	if s.libraryEntrypoints == nil {
		return nil, nil
	}
	root, err := InventoryCheckoutRoot(store, caseID)
	if err != nil {
		return nil, err
	}
	e := *s.libraryEntrypoints
	e.Base = root
	return &e, nil
}

// reachAttribution is what countedReachPaths attributes a Go reach path by: the names of the
// selected affected package, every other affected package the build carries joined to its ranges,
// the scanned project's module path, and the advisory's trust tier.
type reachAttribution struct {
	selected []string
	others   []presentRanges
	project  string
	trust    TrustTier
}

// readReachAttribution reads the reachAttribution for a Go assessment. The selected package is the
// selected affected_packages[] element, else the advisory's module. ok is false for another
// language or when neither names a package, and every path then counts.
func readReachAttribution(store artifact.Store, caseID string) (reachAttribution, bool) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return reachAttribution{}, false
	}
	var inv struct {
		Language string `json:"language"`
		Module   string `json:"module"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil || inv.Language != "go" {
		return reachAttribution{}, false
	}
	sel, ok := extractSelectedPackage(store, caseID)
	if !ok {
		module, ok := extractAdvisoryModule(store, caseID)
		if !ok {
			return reachAttribution{}, false
		}
		sel = advisoryAffectedPackage{Module: module}
	}
	a := reachAttribution{project: inv.Module, others: extractAlsoPresent(store, caseID)}
	for _, n := range []string{sel.Module, sel.Coordinate} {
		if n != "" {
			a.selected = append(a.selected, n)
		}
	}
	a.trust, _ = extractAdvisoryTrust(store, caseID)
	return a, true
}

// countedReachPaths returns the reach paths that count toward the selected package. A path is
// attributed by its sink's import path to the affected package owning the longest name that is the
// import path or a prefix of it at a "/" boundary; stdlib owns an import path whose first element
// has no dot, and the selected package wins a tie. A sink with no import path, one inside the
// scanned project, or one no affected package owns is unattributed and counts as the selected
// package's. A path is dropped only when its owner is another affected package whose every version
// in the build is provably outside that package's ranges (everyVersionOutside). The kept paths are
// ordered the selected package's own, then unattributed, then other packages', each group in its
// input order.
func countedReachPaths(paths []plugin.ReachPath, a reachAttribution) []plugin.ReachPath {
	var own, unattributed, other []plugin.ReachPath
	for _, p := range paths {
		o, owner := a.owner(p.Sink.Package)
		switch {
		case owner == ownerSelected:
			own = append(own, p)
		case owner == ownerNone:
			unattributed = append(unattributed, p)
		case everyVersionOutside(o.Versions, o.Complete, o.Ranges, o.RangeKnown, a.trust):
		default:
			other = append(other, p)
		}
	}
	return slices.Concat(own, unattributed, other)
}

// pathOwner is which package a reach path's sink is attributed to.
type pathOwner int

const (
	ownerNone pathOwner = iota
	ownerSelected
	ownerOther
)

// owner attributes an import path. For ownerOther it also returns that package.
func (a reachAttribution) owner(pkg string) (presentRanges, pathOwner) {
	if pkg == "" || a.project != "" && (pkg == a.project || strings.HasPrefix(pkg, a.project+"/")) {
		return presentRanges{}, ownerNone
	}
	best, owner := 0, ownerNone
	for _, n := range a.selected {
		if l := ownedLength(n, pkg); l > best {
			best, owner = l, ownerSelected
		}
	}
	var other presentRanges
	for _, o := range a.others {
		if l := max(ownedLength(o.Module, pkg), ownedLength(o.Coordinate, pkg)); l > best {
			best, owner, other = l, ownerOther, o
		}
	}
	return other, owner
}

// ownedLength is the length of the match by which the package named name owns import path pkg,
// or 0 when it does not own it.
func ownedLength(name, pkg string) int {
	switch {
	case name == "":
		return 0
	case name == goStdlibPURLName:
		if first, _, _ := strings.Cut(pkg, "/"); !strings.Contains(first, ".") {
			return len(first)
		}
		return 0
	case pkg == name || strings.HasPrefix(pkg, name+"/"):
		return len(name)
	}
	return 0
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
	goWork, err := InventoryGoWorkspace(store, c.ID)
	if err != nil {
		return err
	}

	depCache := s.deps.cacheFor(store, c.ID)
	cg, err := plugin.SharedCallGraph(ctx, s.plugin, plugin.CallGraphRequest{BuildDir: buildDir, GoWork: goWork.File, DependencyCache: depCache})
	if err != nil {
		return err
	}
	ingresses, err := s.plugin.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: buildDir, GoWork: goWork.File})
	if err != nil {
		return err
	}
	sinks, err := resolvedSinks(store, c.ID)
	if err != nil {
		return err
	}
	requestedToolchain := s.requestedToolchain(store, c.ID)
	entrypoints, err := s.entrypointsFor(store, c.ID)
	if err != nil {
		return err
	}
	reach, err := s.plugin.Reachability(ctx, plugin.ReachabilityRequest{
		BuildDir:           buildDir,
		GoWork:             goWork.File,
		VulnID:             vulnID,
		Symbols:            sinks,
		GoToolchain:        requestedToolchain,
		GoToolchainFloor:   s.toolchainFloor(store, c.ID),
		Package:            admittedPackagePURL(store, c.ID),
		DependencyCache:    depCache,
		LibraryEntrypoints: entrypoints,
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
		for _, sink := range sinks {
			paths = append(paths, firstPartyReachPaths(cg, ingresses, sink)...)
		}
		firstParty = len(paths) > 0
	}

	// Persist the RESOLVED paths (not the raw govulncheck reach) so the report builder
	// reads the advisory-specific reaching ingress + trace. Persisting reach.Paths here —
	// empty for a first-party sink — drops that ingress, which forces the report builder
	// onto a positional pick from the shared, sorted ingress map and collapses every
	// advisory's entry point onto whichever ingress sorts first (the SSRF→expandHandler
	// mis-attribution). The CallGraph leg is unchanged (guard discovery reads it).
	// Candidate pairs are written for the counted paths only. When none count, the reachability
	// artifact keeps every path, so the record never reads as an absence of paths.
	counted := paths
	if a, ok := readReachAttribution(store, c.ID); ok {
		counted = countedReachPaths(paths, a)
	}
	reachOut := reach
	reachOut.Paths = counted
	if len(counted) == 0 {
		reachOut.Paths = paths
	}
	reachRef, err := putReachability(store, c, s.Name(), reachOut, cg, toolchainScan)
	if err != nil {
		return err
	}

	ingressRef, err := PutArtifact(store, c, s.Name(), artifact.TypeIngressMap, "ingress map (resolved)", ingresses)
	if err != nil {
		return err
	}

	for _, p := range counted {
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
		taint, err := s.plugin.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: buildDir, GoWork: goWork.File, Sinks: []string{sink}, DependencyCache: depCache})
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

// reachabilityPayload is the resolved reachability artifact's payload, byte for byte what json.Marshal
// makes of
//
//	struct {
//		Reachability  plugin.ReachabilityResult `json:"reachability"`
//		CallGraph     plugin.CountedCallGraph   `json:"call_graph"`
//		ToolchainScan ToolchainScan             `json:"toolchain_scan"`
//	}
//
// except that the call graph is appended from the view's counted encoding rather than re-encoded for
// every advisory. The leg carries the declined sites and escaped symbols as counts: every
// candidate's artifact holds a copy, and a dynamic-language monorepo lists a site per dynamic
// call. ToolchainScan records which Go toolchain this analysis actually ran under. It is the fact
// SubjectToolchainScanned reads back, and the reason a fallback cannot pass itself off as a
// subject scan.
func reachabilityPayload(reach plugin.ReachabilityResult, cg plugin.CallGraphView, ts ToolchainScan) ([]byte, error) {
	b, _, _, err := encodeReachability(reach, cg, ts)
	return b, err
}

// encodeReachability is reachabilityPayload that also returns the payload's reachability and
// toolchain_scan values, which share no memory with the payload.
func encodeReachability(reach plugin.ReachabilityResult, cg plugin.CallGraphView, ts ToolchainScan) (payload, reachLeg, tsLeg []byte, err error) {
	r, err := json.Marshal(reach)
	if err != nil {
		return nil, nil, nil, err
	}
	t, err := json.Marshal(ts)
	if err != nil {
		return nil, nil, nil, err
	}
	b := append([]byte(`{"reachability":`), r...)
	b = append(b, `,"call_graph":`...)
	if b, err = cg.AppendCountedJSON(b); err != nil {
		return nil, nil, nil, err
	}
	b = append(b, `,"toolchain_scan":`...)
	b = append(b, t...)
	return append(b, '}'), r, t, nil
}

// putReachability stores the resolved reachability artifact. When the store takes seeds and cg is
// the decode of its own encoding, it also seeds the artifact's ReachabilityRecord from the values
// the payload was encoded from, so readers neither split the payload nor decode the run's graph
// again for every case. The seed holds the full in-memory graph, Unresolved and Escaped lists
// included, while the payload carries their counts; a record's readers see only the partiality,
// edges and roots, which both carry alike.
func putReachability(store artifact.Store, c *assessment.Assessment, producedBy string, reach plugin.ReachabilityResult, cg plugin.CallGraphView, ts ToolchainScan) (artifact.Ref, error) {
	payload, reachLeg, tsLeg, err := encodeReachability(reach, cg, ts)
	if err != nil {
		return artifact.Ref{}, err
	}
	ref, err := putPayload(store, c, producedBy, artifact.TypeReachability, "reachability (resolved)", payload)
	if err != nil {
		return ref, err
	}
	if seeder, ok := store.(artifact.Seeder); ok && cg.FromEncoding() {
		seeder.Seed(ref.ID, reachabilityViewKey, seededReachability(reachLeg, tsLeg, cg))
	}
	return ref, nil
}

// firstPartyReachPaths derives (ingress→sink) ReachPaths for a FIRST-PARTY sink by walking the
// static CallGraph backward from the resolved sink toward an entry point. Soundness / inv.5: this
// asserts only STRUCTURAL reachability — a candidate, never a verdict and never proof.
func firstPartyReachPaths(cg plugin.CallGraphView, ingresses plugin.IngressResult, sink string) []plugin.ReachPath {
	if sink == "" || cg.EdgeCount() == 0 {
		return nil
	}

	// The BFS runs over SCIP-id keys, reproducing the pre-Symbol identity exactly: CallEdge
	// endpoints were bare SCIP ids, and the sink parameter is a SCIP id (resolvedSinkSCIP), so
	// keying the graph on .SCIP is the same graph the old string-typed code built. The structured
	// Symbol for each node reconstructs the ReachPath.Sink/Ingress/Trace fields — now
	// plugin.Symbol — at the return boundary. The graph's reverse-edge index is built once per
	// graph, not per sink; only the ingresses are overlaid here. A root's Symbol beats an
	// ingress's, which beats an edge endpoint's.
	ingressSyms := make(map[string]plugin.Symbol, len(ingresses.Ingresses))
	for _, in := range ingresses.Ingresses {
		if in.Symbol.SCIP != "" {
			ingressSyms[in.Symbol.SCIP] = in.Symbol
		}
	}
	symOf := func(id string) plugin.Symbol {
		if !cg.IsRoot(id) {
			if s, ok := ingressSyms[id]; ok {
				return s
			}
		}
		return cg.Symbol(id)
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
		if isIngress || cg.IsRoot(cur.sym) {
			trace := make([]plugin.Symbol, len(cur.path))
			for i := range cur.path {
				trace[i] = symOf(cur.path[len(cur.path)-1-i])
			}
			var ingress plugin.Symbol
			if isIngress {
				ingress = symOf(cur.sym)
			}
			return []plugin.ReachPath{{Sink: symOf(sink), Ingress: ingress, Trace: trace}}
		}

		for caller := range cg.Callers(cur.sym) {
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

// resolvedSinks returns every resolved sink SCIP id from the upstream vulnerable-symbol artifact,
// deduplicated, or nil when none resolved (inv.7). Sinks the lane placed in a dependency (an
// Origin) come first, then first-party ones, each in resolution order. Reachability must be asked
// about all of them: a lane only declares what it could not search for the sinks it was given.
func resolvedSinks(store artifact.Store, caseID string) ([]string, error) {
	res, err := VulnerableSymbols(store, caseID)
	if err != nil {
		return nil, err
	}
	var deps, firstParty []string
	seen := make(map[string]struct{}, len(res.Resolved))
	for _, sym := range res.Resolved {
		if sym.SCIP == "" {
			continue
		}
		if _, dup := seen[sym.SCIP]; dup {
			continue
		}
		seen[sym.SCIP] = struct{}{}
		if _, ok := res.Origins[sym.SCIP]; ok {
			deps = append(deps, sym.SCIP)
		} else {
			firstParty = append(firstParty, sym.SCIP)
		}
	}
	return append(deps, firstParty...), nil
}

// VulnerableSymbols reads the symbol-mapping stage's resolution. A missing artifact, or the
// pluginless stub payload, yields an empty result.
func VulnerableSymbols(store artifact.Store, caseID string) (plugin.SymbolResolutionResult, error) {
	arts, err := store.Query(caseID, artifact.TypeVulnerableSymbol)
	if err != nil {
		return plugin.SymbolResolutionResult{}, err
	}
	if len(arts) == 0 {
		return plugin.SymbolResolutionResult{}, nil
	}
	var res plugin.SymbolResolutionResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil {
		return plugin.SymbolResolutionResult{}, err
	}
	return res, nil
}

// AdvisorySymbols returns the vulnerable symbols the advisory names for the package under
// assessment (the selected package's when the advisory targets a secondary one).
func AdvisorySymbols(store artifact.Store, caseID string) []string {
	_, symbols := advisoryPURLAndSymbols(store, caseID)
	return symbols
}

// AdvisoryTargetConditionalSymbols returns the advisory symbols that some build target of the
// package does not compile (AdvisoryFacts.TargetConditionalSymbols).
func AdvisoryTargetConditionalSymbols(store artifact.Store, caseID string) []string {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil
	}
	var adv struct {
		Conditional []string `json:"target_conditional_symbols"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return nil
	}
	return adv.Conditional
}

// AdvisoryPackage returns the name and package URL of the package the advisory was assessed
// against: the selected package's when the advisory targets a secondary one, else the advisory's
// primary. The name is the Go module path, or the ecosystem's own coordinate everywhere else.
func AdvisoryPackage(store artifact.Store, caseID string) (name, purl string) {
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return cmp.Or(sel.Module, sel.Coordinate), sel.PURL
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", ""
	}
	var adv struct {
		Module     string `json:"module"`
		Coordinate string `json:"coordinate"`
		PURL       string `json:"purl"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return "", ""
	}
	return cmp.Or(adv.Module, adv.Coordinate), adv.PURL
}

// AdvisoryPackagePURLs returns the package URL of every package the advisory names: its primary's
// when it has one, then each affected_packages[] element's, in declaration order. An element without
// one yields "".
func AdvisoryPackagePURLs(store artifact.Store, caseID string) []string {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil
	}
	var adv struct {
		PURL             string                    `json:"purl"`
		AffectedPackages []advisoryAffectedPackage `json:"affected_packages"`
		DroppedPackages  []string                  `json:"dropped_affected_packages"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return nil
	}
	var purls []string
	if adv.PURL != "" {
		purls = append(purls, adv.PURL)
	}
	for _, p := range adv.AffectedPackages {
		purls = append(purls, p.PURL)
	}
	return append(purls, adv.DroppedPackages...)
}

// AdvisoryListsAffectedPackages reports whether the advisory carries an affected_packages[] set. Only
// that set enumerates every package the advisory affects; a record with only the scalar purl may
// affect packages it does not name.
func AdvisoryListsAffectedPackages(store artifact.Store, caseID string) bool {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return false
	}
	var adv struct {
		AffectedPackages []advisoryAffectedPackage `json:"affected_packages"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return false
	}
	return len(adv.AffectedPackages) > 0
}

// AdvisoryPURL returns the package URL the advisory was assessed against: the selected package's
// when the advisory targets a secondary one, else the advisory's primary.
func AdvisoryPURL(store artifact.Store, caseID string) string {
	purl, _ := advisoryPURLAndSymbols(store, caseID)
	return purl
}

// admittedPackagePURL returns the assessed package's PURL pinned to the inventory-resolved
// version, or "" when either is unknown or the assessed package is the scanned project itself
// (RootSubject), whose own code always loads. Any version or qualifier the advisory PURL carries
// is replaced: the resolved version is the one installed in the build.
func admittedPackagePURL(store artifact.Store, caseID string) string {
	if RootSubject(store, caseID) {
		return ""
	}
	purl := AdvisoryPURL(store, caseID)
	version, ok := ResolvedVersion(store, caseID)
	if purl == "" || !ok {
		return ""
	}
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	if at := strings.LastIndexByte(purl, '@'); at > strings.LastIndexByte(purl, '/') {
		purl = purl[:at]
	}
	return purl + "@" + version
}

// affectedInstalledVersions returns the assessed package's installed versions that are not provably
// outside the advisory's affected ranges, for when the copies disagree and the inventory resolved no
// single version. It is nil when one version was resolved, when the package is the scanned project
// itself, or when the inventory lists no versions. A version the ranges cannot place is kept.
func affectedInstalledVersions(store artifact.Store, caseID string) []string {
	if RootSubject(store, caseID) {
		return nil
	}
	if _, ok := ResolvedVersion(store, caseID); ok {
		return nil
	}
	axis, ok := extractVersionAxis(store, caseID)
	if !ok {
		return nil
	}
	rngs, rangeKnown := extractAffectedRange(store, caseID)
	var out []string
	for _, v := range axis.Versions {
		if rangeKnown {
			if outside, ok := versionOutsideRanges(v, rngs); ok && outside {
				continue
			}
		}
		out = append(out, v)
	}
	return out
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
			payload.ScopedPartiality = appendScoped(payload.ScopedPartiality, ir.Partiality.Scoped)
		}
	}

	if rec, ok, err := Reachability(store, c.ID); err != nil {
		return err
	} else if ok {
		// Partiality is harvested whether or not any path was found, and BEFORE the
		// path-count branch. Harvesting it only on len(Paths) > 0 dropped the disclosure
		// on precisely the case it exists for: a reachability pass that resolved nothing
		// because it could not see the code produces zero paths, and without the reason
		// codes it is indistinguishable from a pass that looked and found nothing.
		//
		// The call graph's limits are harvested beside reachability's: a lane may declare a
		// step that did not run only on its graph, and that limit must hold the verdict
		// whether or not the graph has edges.
		reach, reachErr := rec.Result()
		cg, cgErr := rec.CallGraph()
		unmarshalled := reachErr == nil && cgErr == nil
		if unmarshalled {
			cgPartiality := cg.Partiality()
			payload.PartialityFlags = append(payload.PartialityFlags, reach.Partiality.Reasons...)
			payload.PartialityFlags = append(payload.PartialityFlags, cgPartiality.Reasons...)
			payload.ScopedPartiality = appendScoped(payload.ScopedPartiality, reach.Partiality.Scoped)
			payload.ScopedPartiality = appendScoped(payload.ScopedPartiality, cgPartiality.Scoped)
		}
		if unmarshalled && len(reach.Paths) > 0 {
			payload.ReachablePathCount = len(reach.Paths)
		} else if reachable, err := rec.StubReachable(); err == nil && reachable {
			payload.ReachablePathCount = 1
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
			payload.ScopedPartiality = appendScoped(payload.ScopedPartiality, res.Partiality.Scoped)
		}
	}

	// Dependency-version resolution is a partiality axis too (alongside ingress, call
	// graph, reachability and vulnerable-symbol above): the inventory stage records why it
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

// appendScoped copies a plugin's scoped limits into the footprint's form.
func appendScoped(dst []artifact.ScopedPartialityFlag, scoped []plugin.ScopedReason) []artifact.ScopedPartialityFlag {
	for _, r := range scoped {
		dst = append(dst, artifact.ScopedPartialityFlag{Reason: r.Reason, Package: r.Package, Path: r.Path, Targets: r.Targets})
	}
	return dst
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
