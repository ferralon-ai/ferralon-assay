// advisory_source.go
//
// The AdvisorySource seam: the single point S1 reads normalized advisory facts through. Before
// this seam, the two S1 read sites did a bare `AdvisoryTable[id]` map lookup (stages.go); they now
// route through AdvisorySource.Lookup so the fact origin can be swapped — from the in-memory
// AdvisoryTable to a digest-pinned artifact corpus, and eventually to a live published feed —
// WITHOUT changing S1's logic or its fail-open posture.
//
// SOUNDNESS (inv.5): the seam is trusted-or-nulled. Every failure mode — unknown id, unreadable
// artifact, malformed document, shape-validation failure, digest mismatch — collapses to
// (zero AdvisoryFacts, false), which downstream reads exactly as today's map miss: no facts →
// fail OPEN → proceed to analysis, NEVER refute, NEVER a fabricated not-affected. A source never
// returns a partial or laundered fact.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/vulnclass"
)

// AdvisorySource resolves normalized advisory facts by vuln id. It is the single seam S1 reads
// advisories through, replacing the inline AdvisoryTable[id] lookups.
type AdvisorySource interface {
	// Lookup returns the pinned facts for vulnID. found=false yields the ZERO AdvisoryFacts
	// (fail-open downstream, byte-identical to today's map miss). Every failure mode — unknown
	// id, unreadable artifact, shape-validation failure, digest mismatch — collapses to
	// (zero, false). A source NEVER returns a partial or laundered fact.
	Lookup(vulnID string) (AdvisoryFacts, bool)
}

// defaultAdvisorySourceVar backs defaultAdvisorySource(). It is nil until an entrypoint installs a
// source via SetDefaultAdvisorySource; nil ⇒ tableSource{}, so an unset process is byte-identical to
// the historical inline AdvisoryTable[id] lookups.
//
// CONCURRENCY CONTRACT — set-before-spawn. SetDefaultAdvisorySource is called at most ONCE, at process
// boot from main(), BEFORE any pipeline goroutine (the worker pool / orchestrator) is started — the
// same precedent as the AnalyzerVersion package var in ferralon-assay/trigger/assess.go. It is therefore
// not guarded by a mutex: the single write happens-before every subsequent read. Do NOT call it after
// the pipeline is serving.
var defaultAdvisorySourceVar AdvisorySource

// SetDefaultAdvisorySource installs the process-wide default AdvisorySource that defaultAdvisorySource()
// resolves through — and therefore BOTH S1 stages' nil-src fallback AND LookupAdvisoryFacts (the
// Prove-side read point). This is the SWAP POINT, runtime-selectable: an entrypoint that has
// materialized a filesystem corpus calls SetDefaultAdvisorySource(NewArtifactSource(dir)) at boot to
// route every seam read through the digest-pinned corpus instead of the built-in AdvisoryTable.
// Passing tableSource{} (or leaving it unset) keeps the built-in default.
//
// Set-before-spawn only (see defaultAdvisorySourceVar's concurrency contract).
func SetDefaultAdvisorySource(src AdvisorySource) { defaultAdvisorySourceVar = src }

// defaultAdvisorySource is the AdvisorySource an S1 stage reads through when it is constructed without
// an explicit source (the production path), and the source LookupAdvisoryFacts reads through. It
// returns the process-wide default installed by SetDefaultAdvisorySource, falling back to tableSource{}
// — the bare AdvisoryTable map read — when unset, so an unset process stays byte-identical to the
// historical inline AdvisoryTable[id] lookups.
func defaultAdvisorySource() AdvisorySource {
	if defaultAdvisorySourceVar != nil {
		return defaultAdvisorySourceVar
	}
	return tableSource{}
}

// LookupAdvisoryFacts resolves advisory facts for vulnID through the default AdvisorySource seam —
// the SAME seam S1 reads through — returning the zero AdvisoryFacts on any miss/failure (fail open,
// byte-identical to a map miss). It is the exported read point for Service-side consumers (e.g.
// fixSourceFor) that must go through the seam rather than indexing AdvisoryTable directly: closing
// a seam-bypass, so those consumers automatically follow the source flip and see the
// v3 enrichment fields (e.g. Fix) a live corpus carries.
func LookupAdvisoryFacts(vulnID string) AdvisoryFacts {
	facts, _ := defaultAdvisorySource().Lookup(vulnID)
	return facts
}

// tableSource wraps the in-memory AdvisoryTable. It is the default and fallback: its Lookup is
// the exact map read the two S1 sites did inline, so wiring it changes no behavior.
type tableSource struct{}

// NewTableSource returns the built-in AdvisoryTable as an AdvisorySource. It is the exported handle
// on the compiled-in default so an entrypoint can put the table EXPLICITLY at the tail of a chain
// (NewChainSource) rather than having a corpus replace it wholesale.
func NewTableSource() AdvisorySource { return tableSource{} }

func (tableSource) Lookup(vulnID string) (AdvisoryFacts, bool) {
	facts, ok := AdvisoryTable[vulnID]
	if !ok {
		return AdvisoryFacts{}, false
	}
	// The curated AdvisoryTable is this module's own offline, osv-verified first-party corpus. Stamp
	// that provenance when the entry left it zero (fill-only; never overwrite a declared tier) so
	// legitimate refutes stay eligible under the inv.5 trust-gate. `facts` is a copy of the map
	// value, so this never mutates the table. Every other field is byte-identical to the bare
	// map read.
	if facts.Provenance.TrustTier == "" {
		facts.Provenance.TrustTier = TrustFirstParty
	}
	return facts, true
}

// chainSource resolves an advisory through an ordered list of sources. It exists so a corpus can
// SUPPLEMENT the built-in AdvisoryTable instead of REPLACING it: before the chain, installing a
// filesystem corpus swapped the table out entirely, so every id the corpus did not carry resolved to
// zero facts and failed open. Measured against the 2026-07-23 published corpus, that silently emptied
// the whole 16-id scan work set.
//
// THE PARTIAL-FACT RULE: FIRST HIT WINS, WHOLE FACTS ONLY. NO MERGING, EVER.
//
// The chain returns the FIRST source's fact verbatim and stops. It never reads a second source to
// "top up" empty fields on the first source's fact. This is the load-bearing rule, not a convenience:
//
//   - Every source already guarantees whole-fact-or-nothing. artifactSource.toFacts returns
//     (zero, false) on ANY shape-validation failure, and tableSource returns a whole map value. So
//     ok=true from a source means "this producer asserted this entire fact", and there is no such
//     thing as a partial fact to top up in the first place.
//   - A merged fact is one NO producer ever asserted and NO digest pins. Its version axis could come
//     from the corpus while its symbol axis came from a years-old table entry, and the disqualification
//     stages would weigh the blend as a single coherent advisory. That is exactly the laundering the
//     seam's soundness note (inv.5) forbids.
//   - Provenance.TrustTier gates whether facts may drive a refute. Merging would let one source's
//     trust tier vouch for another source's fields.
//
// FAIL-OPEN IS PRESERVED EXACTLY. A nil source is skipped, never dereferenced; an empty chain, and a
// chain whose every source misses, return (zero, false) — byte-identical to today's map miss. The
// chain introduces no error path and no (zero, true).
type chainSource struct{ sources []AdvisorySource }

// NewChainSource returns an AdvisorySource that tries each source in order and returns the first
// WHOLE fact any of them resolves (see chainSource for the no-merging rule). Nil entries are skipped,
// so a caller may pass a source it built conditionally without a nil check.
func NewChainSource(sources ...AdvisorySource) AdvisorySource {
	return chainSource{sources: sources}
}

func (c chainSource) Lookup(vulnID string) (AdvisoryFacts, bool) {
	for _, s := range c.sources {
		if s == nil {
			continue
		}
		if facts, ok := s.Lookup(vulnID); ok {
			return facts, true
		}
	}
	return AdvisoryFacts{}, false
}

// Refresh forwards the freshness check to every member that implements CorpusRefresher and joins their
// errors. Members that cannot refresh (the built-in table) are skipped.
func (c chainSource) Refresh() error {
	var errs []error
	for _, s := range c.sources {
		if r, ok := s.(CorpusRefresher); ok {
			if err := r.Refresh(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// normalizedAdvisorySchemaVersion is the schema id an on-disk advisory document must declare to be
// accepted. It is the cross-repo wire tag between this reader and the advisory-corpus producer,
// which is a separate codebase: every field of the shape below is one the producer's projection
// emits. A document declaring any other version fails shape-validation → fail open.
const normalizedAdvisorySchemaVersion = "ferralon.normalized_advisory.v2"

// normalizedAdvisorySchemaVersionV3 is the additive wire-major successor to v2. v3 adds
// enrichment fields (trigger/fix/poc_summary/config_key/…) that are every one omitempty + zero-safe,
// so a v2 document still decodes correctly and simply leaves the new fields at their zero value =
// Undetermined/OPEN (inv.5 fail-open, unchanged). The reader recognizes the SET {v2, v3} rather than a
// single const (schemaVersionRecognized), which keeps the corpus rollout non-breaking: old and new
// documents coexist during migration. Rides the ferralon. base (feed is a Ferralon platform feature).
const normalizedAdvisorySchemaVersionV3 = "ferralon.normalized_advisory.v3"

// normalizedAdvisorySchemaVersionV4 is the additive successor to v3. It adds the typed-symbol axis
// (§4.4.2/.3): `symbols_typed []plugin.Symbol`, the canonical comparable PLAN-000 identity, coexisting
// with the existing bare `symbols []string` (mirrors the affected_packages[] additive precedent). It is
// omitempty + zero-safe, so v2/v3 documents decode unchanged with it nil. DECLARED-AWAITING-EMIT: the
// cve-enrichment producer (a separate repo) does not emit typed symbols today, so the field is nil on
// every current document — nil means "producer has not emitted typed symbols," NOT "the advisory has no
// symbols" (the bare `symbols` axis is unaffected). Producer ownership is escalated to Eric (anvil-q15).
const normalizedAdvisorySchemaVersionV4 = "ferralon.normalized_advisory.v4"

// schemaVersionRecognized is the closed set of accepted wire tags. It replaces the exact-match gate
// (d.SchemaVersion != normalizedAdvisorySchemaVersion) so v2, v3, and v4 documents all validate. A tag
// outside the set fails shape-validation → fail open (never a laundered fact). New wire majors are
// added here, never as a silent prefix match.
func schemaVersionRecognized(v string) bool {
	switch v {
	case normalizedAdvisorySchemaVersion, normalizedAdvisorySchemaVersionV3, normalizedAdvisorySchemaVersionV4:
		return true
	default:
		return false
	}
}

// artifactSource is a digest-pinned advisory reader. It reads one normalized_advisory.v2 JSON
// document per advisory from root, locating each via a manifest that carries a per-artifact
// "sha256:<hex>" digest. On Lookup it finds the advisory, reads its bytes, VERIFIES the digest,
// decodes, and SHAPE-VALIDATES; it returns (facts, true) only if every step passes. Any failure
// returns (zero, false) — fail open, never refute, never a laundered fact.
//
// MANIFEST LIFECYCLE — load once, index once, refresh at scan boundaries:
//   - The first Lookup/Validate/Describe/Refresh reads, validates, and indexes manifest.json by
//     identifier, recording the file's identity (os.Stat: same file, size, mtime) as it was read.
//   - Lookup never touches the manifest again: it reads the served manifestState through an atomic
//     pointer, lock-free, so concurrent Lookups cost one map read.
//   - Refresh (CorpusRefresher) is the freshness check. advisory_intake calls it at the start of every
//     assessment. It stats the manifest; an unchanged identity costs nothing more. A changed identity
//     is re-read and re-validated, and the new state is swapped in atomically. A reload that fails
//     while a good manifest is served KEEPS serving the last good manifest and returns the error;
//     that failed identity is not retried until the file changes again.
//
// Per-advisory documents are read and digest-verified against the SERVED manifest on every Lookup, so
// between a corpus rewrite and the next Refresh a rewritten document fails its digest and misses (fail
// open) rather than resolving against the wrong pin.
type artifactSource struct {
	root string

	// readFile reads the manifest; nil means os.ReadFile. Tests set it to count manifest reads.
	readFile func(string) ([]byte, error)

	state atomic.Pointer[manifestState] // the served load outcome; nil until the first load

	mu         sync.Mutex  // serializes loads and refreshes
	refreshErr error       // guarded by mu: the last failed reload while a good manifest is served
	failedInfo os.FileInfo // guarded by mu: the identity that failed to reload
}

// manifestState is one immutable load outcome. err != nil means no usable manifest (index nil).
// info is the manifest's identity when it was read; nil when it could not be stat'd.
type manifestState struct {
	man   advisoryManifest
	index map[string]advisoryManifestEntry
	err   error
	info  os.FileInfo
}

// CorpusRefresher is implemented by an AdvisorySource whose backing corpus can change under a
// long-lived process. Refresh is a cheap freshness check meant for coarse boundaries (the pipeline calls
// it at the start of each assessment), never per Lookup. It reloads the corpus index only when the
// corpus changed. A non-nil error means the source could not load the changed corpus; a source that
// already served a good corpus keeps serving it, so the error is for logging and health, never a
// reason to abort a run (inv.5).
type CorpusRefresher interface {
	Refresh() error
}

// NewArtifactSource constructs a digest-pinned filesystem AdvisorySource rooted at root. It is cheap
// and does no I/O; the first Lookup/Validate/Describe loads the manifest. An entrypoint hands it
// to SetDefaultAdvisorySource (process-wide) and/or WithAdvisorySource (per-run). The returned value
// also satisfies CorpusValidator, CorpusDescriber, and CorpusRefresher, so the entrypoint can preflight
// the corpus at boot, record its identity, and pick up a rewritten manifest at the next assessment.
func NewArtifactSource(root string) AdvisorySource { return &artifactSource{root: root} }

// CorpusValidator is implemented by an AdvisorySource that supports a STARTUP-ONLY preflight of its
// backing corpus. An entrypoint type-asserts the source it built to this interface and calls Validate()
// once, before serving; a source with no on-disk corpus to preflight (e.g. tableSource) does not
// implement it.
//
// SOUNDNESS SPLIT (inv.5): Validate is SEPARATE from Lookup. Lookup keeps its per-advisory fail-open
// (zero, false) on EVERY failure mode — a broken corpus never turns a per-advisory miss into an error
// mid-run, never a fabricated not-affected. Validate is the opt-in, boot-time gate an entrypoint uses
// to HARD-FAIL a WHOLLY-unusable corpus (missing dir / unreadable / invalid manifest) loudly, before
// analysis. The two never interact: Validate surfaces the real error loadManifest deliberately swallows.
type CorpusValidator interface {
	Validate() error
}

// CorpusInfo identifies the corpus a run resolved facts through: the manifest's outer integrity
// handle and how many records it accounted for. It exists so an entrypoint can RECORD what intel the
// run actually used — without it, "why did this go red with no code change?" has no answer, and a
// stale or truncated corpus is indistinguishable from a fresh one in the Report.
type CorpusInfo struct {
	Digest  string
	Records int
	// Manifest is the manifest's own provenance block: which policy selected the record set, from
	// which corpus snapshot, and when. Zero when the corpus carries none (a bundle, or a manifest
	// published without the block).
	Manifest ManifestProvenance
}

// CorpusDescriber is implemented by an AdvisorySource backed by an on-disk corpus. Describe reports
// the corpus identity for provenance recording ONLY — it never participates in a Lookup and cannot
// change a verdict. ok=false when the corpus cannot be read at all, the same fail-open shape
// loadManifest uses.
type CorpusDescriber interface {
	Describe() (CorpusInfo, bool)
}

// AdvisoryEnumerator is implemented by an AdvisorySource that can enumerate the full identifier set
// it carries. It is OPTIONAL and deliberately NOT part of the one-method AdvisorySource seam:
// tableSource/chainSource do not implement it, and Lookup's fail-open contract is unaffected. An
// entrypoint type-asserts to it (the same pattern as CorpusValidator/CorpusDescriber) to derive the
// scan work set from the corpus itself: both corpus readers (artifactSource, bundleSource) implement
// it, so the policy a corpus was built from defines what a scan evaluates.
// KnownIDs returns the identifiers sorted ascending; an unusable corpus yields an empty slice, never
// an error (enumeration is provenance/work-set metadata, never a Lookup path).
type AdvisoryEnumerator interface {
	KnownIDs() []string
}

func (s *artifactSource) Describe() (CorpusInfo, bool) {
	man, ok := s.loadManifest()
	if !ok {
		return CorpusInfo{}, false
	}
	info := CorpusInfo{Digest: man.CorpusDigest, Records: len(man.Records)}
	if man.Provenance != nil {
		info.Manifest = *man.Provenance
	}
	return info, true
}

// The types below ARE the corpus contract: directory layout, field tables, and closed-set
// vocabularies are all declared here, and this file is the source of truth a producer conforms to.

// advisoryManifest is the on-disk manifest: the producer's corpus-manifest encoding, extended
// with the per-record relative `path` the reader needs to locate each document under root. `records` is
// sorted ascending by identifier and is byte-deterministic across regenerations. RecordCount must
// equal len(Records); a mismatch marks the manifest invalid (loadManifest fails it before any
// Lookup runs). CorpusDigest is the outer integrity handle the published feed is pinned by (not
// verified per-lookup here — the per-record Digest is the load-bearing pin verified on every
// Lookup). Provenance is the manifest-level audit block (see ManifestProvenance); nil when absent.
type advisoryManifest struct {
	ManifestVersion string                  `json:"manifest_version"`
	SchemaVersion   string                  `json:"schema_version"`
	RecordCount     int                     `json:"record_count"`
	Records         []advisoryManifestEntry `json:"records"`
	CorpusDigest    string                  `json:"corpus_digest"`
	Provenance      *ManifestProvenance     `json:"provenance,omitempty"`
}

// ManifestProvenance is a policy manifest's `provenance` block: which policy selected the manifest's
// record set, the corpus snapshot it was selected from, and which producer generated it when. It is
// audit metadata only. Like manifest_version it is carried through and never validated, and nothing
// reads it into a Lookup, a work set, or a verdict.
//
// It is a different object from docProv, the per-advisory `provenance` block inside each corpus
// document, whose trust_tier gates refute eligibility. The two share a JSON key at different levels
// and have opposite verdict-sensitivity.
type ManifestProvenance struct {
	GeneratedAt          string `json:"generated_at,omitempty"`           // RFC 3339 as written by the producer; not parsed
	Generator            string `json:"generator,omitempty"`              // producing tool, e.g. "ferralon-intel/enrichment"
	PolicyID             string `json:"policy_id,omitempty"`              // e.g. "published-7d", "full"
	PolicyQuery          string `json:"policy_query,omitempty"`           // human-readable selection predicate
	SourceCorpusDigest   string `json:"source_corpus_digest,omitempty"`   // digest of the full corpus the selection ran over
	SelectionIndexDigest string `json:"selection_index_digest,omitempty"` // digest of the selection index the selection read
}

// UnmarshalJSON decodes the block best-effort and never fails: an unvalidated audit field must not be
// able to make a usable corpus unreadable. A member of the wrong type stays zero while the well-typed
// members alongside it still decode, and a block that is not an object decodes to the zero value.
func (p *ManifestProvenance) UnmarshalJSON(b []byte) error {
	type plain ManifestProvenance
	var v plain
	_ = json.Unmarshal(b, &v)
	*p = ManifestProvenance(v)
	return nil
}

// advisoryManifestEntry pins one advisory by its content digest. Path is relative to root, forward-
// slash-separated, and may include date-partitioned subdirectories (e.g. "2021/12/CVE-2021-44228.json")
// — see safeRelPath.
type advisoryManifestEntry struct {
	Identifier   string `json:"identifier"`
	Path         string `json:"path"`          // path relative to root; forward slashes; subdirs allowed
	OutputDigest string `json:"output_digest"` // per-artifact "sha256:<hex>" over the file bytes
}

// advisoryDoc is the on-disk normalized_advisory.v2 wire shape for one advisory. It is a distinct
// type from AdvisoryFacts on purpose: the wire schema is explicit and every field is shape-
// validated at the seam before any fact reaches S1. Fields not carried here map to the zero value
// on AdvisoryFacts, which downstream treats as Undetermined / OPEN.
type advisoryDoc struct {
	SchemaVersion  string   `json:"schema_version"`
	VulnID         string   `json:"vuln_id"`
	Module         string   `json:"module,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`
	UpperExclusive string   `json:"upper_exclusive,omitempty"`
	FixedVersion   string   `json:"fixed_version,omitempty"`
	VersionScheme  string   `json:"version_scheme,omitempty"`
	Coordinate     string   `json:"coordinate,omitempty"`
	PURL           string   `json:"purl,omitempty"`
	Symbols        []string `json:"symbols,omitempty"`
	GuardSymbols   []string `json:"guard_symbols,omitempty"`
	CWEs           []string `json:"cwes,omitempty"`
	// Summary is the free-text advisory narrative, the keyword fallback for class recognition. The
	// enrichment producer projects it under `root_cause`, NOT `summary` — decoding the wrong key left
	// the field empty on every record. Maps onto AdvisoryFacts.Summary.
	Summary string `json:"root_cause,omitempty"`
	// SummaryCompat is the `summary` spelling of the same narrative. The published corpus emits
	// `summary` on every record and `root_cause` on none, while the enrichment records use
	// `root_cause` — the two spellings coexist in the wild. Both are decoded and toFacts prefers
	// `root_cause`; carrying only one spelling left Summary empty across a whole corpus and killed the
	// free-text keyword fallback for class recognition. Neither key can carry a verdict.
	SummaryCompat  string        `json:"summary,omitempty"`
	SinkKind       string        `json:"sink_kind,omitempty"`
	PocSignal      *docPocSignal `json:"poc_signal,omitempty"`
	AffectedRanges []docRange    `json:"affected_ranges,omitempty"`
	Provenance     *docProv      `json:"provenance,omitempty"`
	Lineage        *docLineage   `json:"lineage,omitempty"`

	// --- ferralon.normalized_advisory.v3 additive block -----------------------------------------
	// Every field is omitempty + zero-safe: an absent field decodes to the zero value, which every
	// downstream consumer reads as Undetermined/OPEN (inv.5 fail-open, preserved). None of these can
	// carry a verdict — there is no field a severity/CVSS/exploitability decision could land in.
	Withdrawn        bool              `json:"withdrawn,omitempty"`         // OSV withdrawn: retracted advisory → never a live route
	Trigger          *docTrigger       `json:"trigger,omitempty"`           // per-CVE reach descriptor
	Fix              *docFix           `json:"fix,omitempty"`               // upstream-fix hint; consumed Prove-side
	PocSummary       string            `json:"poc_summary,omitempty"`       // PoC shape summary; consumed Prove-side
	TriggerCondition string            `json:"trigger_condition,omitempty"` // mechanism precondition
	Prerequisite     string            `json:"prerequisite,omitempty"`      // mechanism precondition
	ConfigKey        *docConfigKey     `json:"config_key,omitempty"`        // core.config predicate operand
	FeatureFlag      string            `json:"feature_flag,omitempty"`      // core.feature_enabled predicate operand
	GadgetClasses    []string          `json:"gadget_classes,omitempty"`    // java.gadget_on_classpath predicate operand
	GuardSufficiency []docGuardVariant `json:"guard_sufficiency,omitempty"` // Prove-side evidence-label upgrade only

	// MaliciousPackage marks an OSV malicious-package (MAL) advisory and carries the ENUMERATED
	// affected version set. Object presence (non-nil) IS the marker: "this advisory is a malicious
	// package; the presence-verdict model applies; there is no reachability/symbol/detonation."
	// Absent (a v2 doc or any non-MAL advisory) ⇒ nil ⇒ the presence path never fires (inv.5
	// fail-open). It carries NO bounds — a MAL record enumerates versions[], never a range — so it
	// cannot feed the range/version axis; it is exact-string membership only (see toFacts / the
	// maliciousPresence stage). Same additive omitempty posture as trigger/fix/config_key.
	MaliciousPackage *docMaliciousPackage `json:"malicious_package,omitempty"`

	// AffectedPackages is the additive v3 multi-package set. It lists EVERY package the advisory affects — each with its own identity/version/symbol
	// axes — so the reader's stage-2 select-by-target can pick the package the assessed codebase
	// actually depends on (a target on a SECONDARY package resolves instead of falling OPEN). The
	// array is COMPLETE and INCLUDES the primary: the scalar top-level per-package block equals
	// AffectedPackages[k] for exactly one k (the producer's selectPrimaryAffected pick), so the reader
	// has ONE uniform match path. Absent (v2 doc) → empty → today's exact scalar-only
	// behavior (inv.5 fail-open). Advisory-level fields (aliases/cwes/sink_kind/trigger/…) are NOT
	// repeated per element — they are shared across every package and stay top-level.
	AffectedPackages []docAffectedPackage `json:"affected_packages,omitempty"`

	// --- ferralon.normalized_advisory.v4 additive block -----------------------------------------
	// SymbolsTyped is the §4.4.2/.3 typed-symbol axis: the canonical comparable plugin.Symbol identity
	// (Kind/Package/Enclosing/Name/Descriptor/SCIP), coexisting with the bare `symbols []string` above.
	// omitempty + zero-safe: absent (every v2/v3 document, and every v4 document until the producer emits)
	// → nil. DECLARED-AWAITING-EMIT (anvil-q15): nil means "producer has not emitted typed symbols," NOT
	// "no symbols" — the bare `symbols` axis carries the strings today. Carries no verdict.
	SymbolsTyped []plugin.Symbol `json:"symbols_typed,omitempty"`

	// SymbolProvenance is the corpus's RECORD-SCOPED derivation tag for the `symbols` set — how those
	// symbols were obtained. It is a SINGLE scalar per record (one value covers the whole `symbols`
	// array, not one tag per symbol). OPEN SET, decoded verbatim: the emitted vocabulary is
	// "osv-declared" | "curated" | "diff-lexed" (with "reasoning" reserved-not-emitted), but an
	// unrecognized value passes through UNTOUCHED — never rejected, never coerced to zero — so a
	// future producer tier needs no consumer change. STORE-ONLY (A2, cycle 2026-08-24 corpus-scaffold):
	// decoded onto AdvisoryFacts and read by NOTHING — it must not enter any admission, reachability,
	// or refute path. Absent → "" → UNKNOWN derivation, NOT low confidence and NOT "untrusted": a
	// symbol with no provenance tag resolves and is walked exactly as today (honest-absent, inv.5).
	// Carries no verdict.
	SymbolProvenance string `json:"symbol_provenance,omitempty"`
}

// docAffectedPackage is one entry of the additive v3 affected_packages[] set. It mirrors the
// per-package scalar fields of advisoryDoc exactly (identity + version + symbol axes), reusing
// docRange, so a selected element lifts into AdvisoryFacts with no new mapping. Advisory-level
// fields are NOT repeated here.
type docAffectedPackage struct {
	Module         string     `json:"module,omitempty"`
	Coordinate     string     `json:"coordinate,omitempty"`
	PURL           string     `json:"purl,omitempty"`
	VersionScheme  string     `json:"version_scheme,omitempty"`
	UpperExclusive string     `json:"upper_exclusive,omitempty"`
	FixedVersion   string     `json:"fixed_version,omitempty"`
	AffectedRanges []docRange `json:"affected_ranges,omitempty"`
	Symbols        []string   `json:"symbols,omitempty"`
}

// docTrigger is the v3 per-CVE reach descriptor. IngressKind is a closed set
// (ingressKindRecognized); Route/Param/MalformedToken frame the reach path. MalformedToken is the
// clinical SHAPE that trips the sink, described at the level of the value's form, and is NEVER a
// weaponized payload string.
type docTrigger struct {
	IngressKind    string `json:"ingress_kind"`              // closed set: http|grpc|cli|library
	Route          string `json:"route,omitempty"`           // literal ingress path, e.g. "/fetch"
	Param          string `json:"param,omitempty"`           // tainted query/body key placed on the route
	MalformedToken string `json:"malformed_token,omitempty"` // clinical SHAPE of the value on that key
}

// docFix is the v3 upstream-fix hint. FailedFixClass is a closed set (failedFixClassRecognized).
// Consumed by patch synthesis; carried here as part of the v3 wire.
type docFix struct {
	UpstreamCommit string `json:"upstream_commit,omitempty"`
	GuardShape     string `json:"guard_shape,omitempty"`
	FailedFixClass string `json:"failed_fix_class,omitempty"` // closed set (failedFixClassRecognized)
}

// docMaliciousPackage is the malicious-package marker's wire shape. AffectedVersions is the OSV
// versions[] set copied verbatim, for exact-string membership (no comparator). An empty/absent set
// inside a present object ⇒ un-decidable ⇒ OPEN both directions (mirror of the empty-set rule in
// versionOutsideRanges). Maps onto AdvisoryFacts.MaliciousPackage (MaliciousPackageFacts).
type docMaliciousPackage struct {
	AffectedVersions []string `json:"affected_versions,omitempty"`
}

// docConfigKey is the core.config predicate operand: a config key plus the value that makes the
// codebase unsafe. Maps onto AdvisoryFacts.ConfigKey (ConfigOperand).
type docConfigKey struct {
	Key         string `json:"key,omitempty"`
	UnsafeValue string `json:"unsafe_value,omitempty"`
}

// docGuardVariant classifies a named guard variant against a specific bypass. Maps onto
// AdvisoryFacts.GuardSufficiency (GuardVariant). Prove-side evidence-label upgrade ONLY — Assess
// never refutes on sufficiency.
type docGuardVariant struct {
	Symbol     string `json:"symbol,omitempty"`
	Version    string `json:"version,omitempty"`
	ForBypass  string `json:"for_bypass,omitempty"`
	Sufficient bool   `json:"sufficient,omitempty"`
}

// docPocSignal is the poc_signal operand. The engine consumes only Available
// (→ AdvisoryFacts.PocSignal); any other key is producer attribution the reader does not read.
//
// TWO WIRE ENCODINGS EXIST AND BOTH ARE ACCEPTED (see UnmarshalJSON):
//
//   - the OBJECT {available, references, source} — the attribution-carrying shape the enrichment
//     records emit;
//   - a BARE BOOL — which is what the published corpus emits and what its own field reference
//     declares.
//
// Pinning the reader to exactly one of them is a whole-corpus outage in either direction, because a
// type mismatch fails json.Unmarshal on the WHOLE DOCUMENT, not just the field. Object-only decoding
// rejected 67 of the 72 published records outright (measured against a real corpus); bool-only
// decoding is the mirror-image failure, hit on the other side at a feed swap. A union decoder is
// the only encoding that cannot regress either producer.
type docPocSignal struct {
	Available bool `json:"available"`
}

// UnmarshalJSON accepts the bare-bool and the object encoding of poc_signal, and FAILS OPEN AT THE
// FIELD (Available stays false, no error) on any third encoding.
//
// Field-level fail-open is deliberate and matches this file's existing precedent for operand-shaped
// fields (an unrecognized ingress_kind / failed_fix_class drops to "" rather than rejecting the
// document). poc_signal cannot carry a verdict: it is a positive-signal flag whose zero means "no
// public-exploit signal", which is identical to the key being absent — so a garbled encoding narrows
// nothing and launders nothing. Rejecting the whole document over it would discard a complete,
// digest-verified advisory because of one unreadable evidence flag, which is how the object-only
// decoder emptied the entire published corpus.
func (p *docPocSignal) UnmarshalJSON(b []byte) error {
	var flag bool
	if err := json.Unmarshal(b, &flag); err == nil {
		p.Available = flag
		return nil
	}
	var obj struct {
		Available bool `json:"available"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil // fail open at the field: unknown encoding → Available stays false
	}
	p.Available = obj.Available
	return nil
}

type docRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

type docProv struct {
	Source      string `json:"source,omitempty"`
	InputDigest string `json:"input_digest,omitempty"`
	TrustTier   string `json:"trust_tier,omitempty"`
}

type docLineage struct {
	IncompleteFixOf string `json:"incomplete_fix_of,omitempty"`
	RefixedBy       string `json:"refixed_by,omitempty"`
}

func (s *artifactSource) Lookup(vulnID string) (AdvisoryFacts, bool) {
	st := s.current()
	if st.err != nil {
		return AdvisoryFacts{}, false
	}
	entry, ok := st.index[vulnID]
	if !ok {
		return AdvisoryFacts{}, false
	}
	return s.resolveEntry(entry, vulnID)
}

// resolveEntry reads, digest-verifies, decodes, and shape-validates the one document a manifest
// entry pins. It is Lookup's per-document half, shared with lookupEach so the single-id and bulk
// paths apply the identical checks.
func (s *artifactSource) resolveEntry(entry advisoryManifestEntry, vulnID string) (AdvisoryFacts, bool) {
	if entry.Path == "" || entry.OutputDigest == "" || !safeRelPath(entry.Path) {
		return AdvisoryFacts{}, false
	}
	data, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(entry.Path)))
	if err != nil {
		return AdvisoryFacts{}, false
	}
	// Digest pin: a tampered or stale-regen file cannot silently poison S1. Mismatch → reject to
	// Undetermined (fail open), never pass the bytes through.
	if !digestMatches(data, entry.OutputDigest) {
		return AdvisoryFacts{}, false
	}
	var doc advisoryDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return AdvisoryFacts{}, false
	}
	return doc.toFacts(vulnID)
}

// KnownIDs returns the manifest's identifier set, sorted ascending (implements AdvisoryEnumerator).
// An unusable manifest yields an empty slice, never an error — the same fail-open shape as Lookup.
// The manifest's records are already producer-sorted, but the order is re-established here rather
// than trusted, since the enumerator contract promises it.
func (s *artifactSource) KnownIDs() []string {
	st := s.current()
	if st.err != nil {
		return nil
	}
	ids := make([]string, 0, len(st.man.Records))
	for _, r := range st.man.Records {
		ids = append(ids, r.Identifier)
	}
	sort.Strings(ids)
	return ids
}

// lookupEach resolves every id against ONE snapshot of the served manifest index, calling fn with
// exactly what Lookup(id) would return against that snapshot. A Refresh that swaps the index mid-batch
// does not split the batch across two manifests.
func (s *artifactSource) lookupEach(ids []string, fn func(id string, facts AdvisoryFacts, ok bool)) {
	st := s.current()
	for _, id := range ids {
		entry, found := st.index[id]
		if st.err != nil || !found {
			fn(id, AdvisoryFacts{}, false)
			continue
		}
		facts, ok := s.resolveEntry(entry, id)
		fn(id, facts, ok)
	}
}

// bulkLookup is implemented by a source whose per-id Lookup carries a fixed cost that a batch can
// pay once. It is unexported: LookupEach is the only caller, and every other source is served by
// plain Lookup.
type bulkLookup interface {
	lookupEach(ids []string, fn func(id string, facts AdvisoryFacts, ok bool))
}

// LookupEach resolves every id in ids through src and calls fn once per id, in order, with exactly
// what src.Lookup(id) would return. It exists for work-set admission, which asks a corpus about
// every id it carries: a source that can amortize its index load across the batch does so, and the
// result is the same as calling Lookup in a loop.
func LookupEach(src AdvisorySource, ids []string, fn func(id string, facts AdvisoryFacts, ok bool)) {
	if b, ok := src.(bulkLookup); ok {
		b.lookupEach(ids, fn)
		return
	}
	for _, id := range ids {
		facts, ok := src.Lookup(id)
		fn(id, facts, ok)
	}
}

// interface assertions: artifactSource satisfies the core seam plus the optional interfaces.
var (
	_ AdvisorySource     = (*artifactSource)(nil)
	_ CorpusValidator    = (*artifactSource)(nil)
	_ CorpusDescriber    = (*artifactSource)(nil)
	_ AdvisoryEnumerator = (*artifactSource)(nil)
	_ CorpusRefresher    = (*artifactSource)(nil)
	_ bulkLookup         = (*artifactSource)(nil)
)

// current returns the served manifestState, performing the first load if none has happened. On a
// failed load the state carries the descriptive error and a nil index; Lookup/Describe collapse that to
// the fail-open shape, Validate surfaces it verbatim.
func (s *artifactSource) current() *manifestState {
	if st := s.state.Load(); st != nil {
		return st
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.state.Load(); st != nil {
		return st
	}
	st := s.loadState()
	s.state.Store(st)
	return st
}

// loadState stats, then reads and validates, the manifest. The stat comes first, so a file replaced
// between the two is recorded under its older identity and simply reloads again at the next Refresh;
// the reverse order could pair a newer identity with older content and miss the change.
func (s *artifactSource) loadState() *manifestState {
	info, statErr := os.Stat(s.manifestPath())
	if statErr != nil {
		info = nil
	}
	man, index, err := s.readManifest()
	return &manifestState{man: man, index: index, err: err, info: info}
}

// Refresh implements CorpusRefresher: reload the manifest if its identity (same file, size, mtime)
// changed since the served state was read. See artifactSource's lifecycle for the failure rules.
func (s *artifactSource) Refresh() error {
	s.current()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.state.Load()
	path := s.manifestPath()

	info, err := os.Stat(path)
	if err != nil {
		if cur.err != nil {
			return cur.err
		}
		s.refreshErr = fmt.Errorf("advisory manifest %s is no longer readable; serving the last good manifest: %w", path, err)
		return s.refreshErr
	}
	if sameFileIdentity(info, cur.info) {
		s.refreshErr, s.failedInfo = nil, nil
		return cur.err
	}
	if sameFileIdentity(info, s.failedInfo) {
		return s.refreshErr
	}

	next := s.loadState()
	if next.err == nil || cur.err != nil {
		// A good reload replaces whatever was served; with no good manifest to protect, a failed
		// reload replaces the older failure so the error stays current.
		s.state.Store(next)
		s.refreshErr, s.failedInfo = nil, nil
		return next.err
	}
	s.failedInfo = next.info
	s.refreshErr = fmt.Errorf("advisory manifest changed but failed to reload; serving the last good manifest: %w", next.err)
	return s.refreshErr
}

// sameFileIdentity reports whether a and b describe the same unchanged file. A nil side never matches,
// so a manifest that could not be stat'd is always re-checked.
func sameFileIdentity(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func (s *artifactSource) manifestPath() string { return filepath.Join(s.root, "manifest.json") }

// loadManifest returns the served manifest, or ok=false when none could be loaded. record_count must
// equal len(records) and every identifier must be unique; either violation marks the whole manifest
// invalid (every Lookup against it then fails open), since a manifest that cannot account for its
// own record set cannot be trusted to name the right file for any single id.
func (s *artifactSource) loadManifest() (advisoryManifest, bool) {
	st := s.current()
	if st.err != nil {
		return advisoryManifest{}, false
	}
	return st.man, true
}

// readManifest reads and validates the manifest and indexes its records by identifier, returning a
// DESCRIPTIVE error (naming the manifest path and the specific violation) on any failure. Lookup
// collapses the error to (zero, false) (inv.5 — a per-advisory read never surfaces an error); Validate
// surfaces it verbatim for the startup preflight. Both read the same served state, so the fail-open
// Lookup path and the loud Validate path can never diverge.
func (s *artifactSource) readManifest() (advisoryManifest, map[string]advisoryManifestEntry, error) {
	path := s.manifestPath()
	readFile := s.readFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	data, err := readFile(path)
	if err != nil {
		return advisoryManifest{}, nil, fmt.Errorf("read advisory manifest %s: %w", path, err)
	}
	var man advisoryManifest
	if err := json.Unmarshal(data, &man); err != nil {
		return advisoryManifest{}, nil, fmt.Errorf("parse advisory manifest %s: %w", path, err)
	}
	if man.RecordCount != len(man.Records) {
		return advisoryManifest{}, nil, fmt.Errorf("advisory manifest %s: record_count %d != len(records) %d", path, man.RecordCount, len(man.Records))
	}
	index := make(map[string]advisoryManifestEntry, len(man.Records))
	for _, r := range man.Records {
		if _, dup := index[r.Identifier]; dup {
			return advisoryManifest{}, nil, fmt.Errorf("advisory manifest %s: duplicate identifier %q", path, r.Identifier)
		}
		index[r.Identifier] = r
	}
	return man, index, nil
}

// Validate is the STARTUP-ONLY corpus preflight (decisions.md #1): it returns a descriptive error when
// the corpus is WHOLLY unusable — root/manifest missing, manifest unreadable, or manifest invalid
// (record_count≠len, duplicate identifier). An entrypoint calls it once at boot and HARD-FAILS the
// process on error, so a broken orchestrator-materialized corpus is loud, never silently degraded to
// stale built-in intel.
//
// It reads the same served state as Lookup, so it can never accept a manifest Lookup would choke on, nor
// reject one Lookup would accept. After a failed Refresh it still reports on the manifest being served
// (the last good one); the reload failure is Refresh's error. It does NOT read or validate individual advisory documents: a single
// malformed / digest-mismatched advisory is a per-advisory fail-open concern (inv.5), NOT a
// corpus-unusable one — Validate gates the manifest, Lookup gates each document.
//
// inv.5 SPLIT: Validate never runs inside Lookup and never changes Lookup's per-advisory (zero, false).
func (s *artifactSource) Validate() error {
	return s.current().err
}

// toFacts shape-validates the decoded document and maps it to AdvisoryFacts. It returns
// (zero, false) on ANY validation failure — a malformed advisory contributes nothing, and nothing
// fails open (inv.5). It NEVER returns a partial fact.
func (d advisoryDoc) toFacts(wantID string) (AdvisoryFacts, bool) {
	// Required envelope. The schema gate recognizes the closed set {v2, v3} (schemaVersionRecognized),
	// not a single const, so v2 and v3 documents both validate and a v2 doc leaves the v3 fields zero.
	if !schemaVersionRecognized(d.SchemaVersion) {
		return AdvisoryFacts{}, false
	}
	if d.VulnID == "" || d.VulnID != wantID {
		return AdvisoryFacts{}, false
	}
	if !schemeRecognized(d.VersionScheme) {
		return AdvisoryFacts{}, false
	}

	var ranges []Range
	for _, r := range d.AffectedRanges {
		// A range must carry at least one bound; a boundless entry is garbled → fail open.
		if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
			return AdvisoryFacts{}, false
		}
		ranges = append(ranges, Range{
			Introduced:   r.Introduced,
			Fixed:        r.Fixed,
			LastAffected: r.LastAffected,
			FixedVersion: r.FixedVersion,
		})
	}

	var prov Provenance
	if d.Provenance != nil {
		if !trustTierRecognized(d.Provenance.TrustTier) {
			return AdvisoryFacts{}, false
		}
		prov = Provenance{
			Source:      d.Provenance.Source,
			InputDigest: d.Provenance.InputDigest,
			TrustTier:   TrustTier(d.Provenance.TrustTier),
		}
	}

	var lineage Lineage
	if d.Lineage != nil {
		lineage = Lineage{IncompleteFixOf: d.Lineage.IncompleteFixOf, RefixedBy: d.Lineage.RefixedBy}
	}

	// v3 additive block. Each closed-set enum is validated fail-open: an unrecognized IngressKind /
	// FailedFixClass drops to "" (the zero, constant-fallback) exactly the way schemeRecognized /
	// trustTierRecognized gate — never rejecting the whole document, never a silent wrong operand.
	// §4.4.6 absent-vs-none: the pointer nil/non-nil already carries the distinction on the wire;
	// stamp it onto the projection so it is no longer collapsed. nil → PresenceAbsent (the zero, set
	// by leaving the operand untouched); non-nil zero-valued → declared_empty; non-nil with values →
	// declared_values. Representation-only — Zero() stays value-based, so no consumer branch flips.
	var trigger TriggerRoute
	if d.Trigger != nil {
		ingress := d.Trigger.IngressKind
		if !ingressKindRecognized(ingress) {
			ingress = "" // fail open: unrecognized ingress kind → zero → per-class constant fallback
		}
		trigger = TriggerRoute{
			IngressKind:    ingress,
			Route:          d.Trigger.Route,
			Param:          d.Trigger.Param,
			MalformedToken: d.Trigger.MalformedToken,
		}
		trigger.Declared = presenceFromZero(trigger.Zero())
	}
	var fix FixHint
	if d.Fix != nil {
		ffc := d.Fix.FailedFixClass
		if !failedFixClassRecognized(ffc) {
			ffc = "" // fail open: unrecognized failed-fix class → zero
		}
		fix = FixHint{
			UpstreamCommit: d.Fix.UpstreamCommit,
			GuardShape:     d.Fix.GuardShape,
			FailedFixClass: ffc,
		}
		fix.Declared = presenceFromZero(fix.Zero())
	}
	var configKey ConfigOperand
	if d.ConfigKey != nil {
		configKey = ConfigOperand{Key: d.ConfigKey.Key, UnsafeValue: d.ConfigKey.UnsafeValue}
		configKey.Declared = presenceFromZero(configKey.Zero())
	}
	var guardSuff []GuardVariant
	for _, g := range d.GuardSufficiency {
		guardSuff = append(guardSuff, GuardVariant{
			Symbol:     g.Symbol,
			Version:    g.Version,
			ForBypass:  g.ForBypass,
			Sufficient: g.Sufficient,
		})
	}

	// v3 multi-package set. Carry ALL elements through with PER-ELEMENT fail-open validation: an
	// element with an unrecognized version_scheme or a boundless range DROPS that element (continue),
	// never the whole document — the opposite of the scalar path's whole-doc reject. Dropping a
	// garbled element can only remove a select-by-target candidate (a target on it then falls back to
	// the scalar primary → OPEN), never fabricate a not-affected (inv.5). The scalar-primary mapping
	// below is UNCHANGED; the array decodes alongside it.
	var affectedPkgs []AffectedPackage
	for _, p := range d.AffectedPackages {
		if !schemeRecognized(p.VersionScheme) {
			continue // fail open: drop this element, keep the document
		}
		var pranges []Range
		garbled := false
		for _, r := range p.AffectedRanges {
			if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
				garbled = true
				break
			}
			pranges = append(pranges, Range{
				Introduced:   r.Introduced,
				Fixed:        r.Fixed,
				LastAffected: r.LastAffected,
				FixedVersion: r.FixedVersion,
			})
		}
		if garbled {
			continue // boundless range → drop this element, keep the document
		}
		affectedPkgs = append(affectedPkgs, AffectedPackage{
			Module:         goModulePath(p.Module, p.Coordinate, p.VersionScheme),
			Coordinate:     p.Coordinate,
			PURL:           p.PURL,
			VersionScheme:  p.VersionScheme,
			UpperExclusive: p.UpperExclusive,
			FixedVersion:   p.FixedVersion,
			AffectedRanges: pranges,
			Symbols:        p.Symbols,
		})
	}

	// Malicious-package marker. Non-nil object ⇒ Declared=true (the presence-verdict model applies);
	// copy the enumerated versions verbatim, dropping empty strings. ADDITIVE + zero-safe: a nil
	// marker ⇒ Declared=false ⇒ today's exact behavior; a malformed/empty marker only adds a presence
	// path that itself fails open — it NEVER rejects the document and NEVER touches the scalar/version
	// axes. The explicit Declared bool distinguishes "declared malicious, empty set → OPEN" from "not
	// malicious at all".
	var malicious MaliciousPackageFacts
	if d.MaliciousPackage != nil {
		malicious.Declared = true
		for _, v := range d.MaliciousPackage.AffectedVersions {
			if v == "" {
				continue
			}
			malicious.AffectedVersions = append(malicious.AffectedVersions, v)
		}
	}

	// Prefer the `root_cause` spelling; fall back to `summary` (see SummaryCompat). Both name the
	// same free-text narrative, so this is a spelling reconciliation, not a merge across facts.
	summary := d.Summary
	if summary == "" {
		summary = d.SummaryCompat
	}

	return AdvisoryFacts{
		Module:         goModulePath(d.Module, d.Coordinate, d.VersionScheme),
		Aliases:        d.Aliases,
		UpperExclusive: d.UpperExclusive,
		FixedVersion:   d.FixedVersion,
		VersionScheme:  d.VersionScheme,
		Coordinate:     d.Coordinate,
		PURL:           d.PURL,
		Symbols:        d.Symbols,
		// A2 store-only: the record-scoped derivation tag rides alongside Symbols verbatim (open set,
		// no validation — an unrecognized tier passes through). Nothing downstream reads it.
		SymbolProvenance: d.SymbolProvenance,
		GuardSymbols:     d.GuardSymbols,
		CWEs:             d.CWEs,
		Summary:          summary,
		SinkKind:         d.SinkKind,
		PocSignal:        d.PocSignal != nil && d.PocSignal.Available,
		AffectedRanges:   ranges,
		Provenance:       prov,
		Lineage:          lineage,
		// v3 additive fields.
		Withdrawn:        d.Withdrawn,
		Trigger:          trigger,
		Fix:              fix,
		PocSummary:       d.PocSummary,
		TriggerCondition: d.TriggerCondition,
		Prerequisite:     d.Prerequisite,
		ConfigKey:        configKey,
		FeatureFlag:      d.FeatureFlag,
		GadgetClasses:    d.GadgetClasses,
		GuardSufficiency: guardSuff,
		AffectedPackages: affectedPkgs,
		// v4 additive field. Zero-safe passthrough: nil (producer has not emitted) stays nil —
		// never conflated with an empty symbol set (anvil-q15 declared-awaiting-emit).
		SymbolsTyped:     d.SymbolsTyped,
		MaliciousPackage: malicious,
	}, true
}

// goModulePath resolves the Go MODULE PATH for a package block, projecting `coordinate` onto it when
// the document carries no explicit `module`.
//
// In the gomod scheme the two name the same string. The built-in AdvisoryTable puts it in `module`;
// the published corpus puts it in `coordinate` and omits `module` entirely (FIELDS.md: "`coordinate`
// — the package coordinate/name in its ecosystem (e.g. `golang.org/x/crypto`)", alongside a purl of
// `pkg:golang/golang.org/x/crypto`). The engine's whole Go version axis is keyed on Module —
// moduleVersionFromGoMod's go.mod require lookup and the intake no-manifest-entry guard both read it
// — so a corpus record that spells it `coordinate` silently loses its version axis and falls through
// to reachability. Measured on a Go scan: the five corpus-carried work-set ids went from
// `disqualified / version_not_in_affected_range` ("provably not affected") to
// `not_exploitable / vulnerable_symbol_absent`, a weaker and less accurate ground for the same
// non-finding.
//
// SCOPED TO gomod ONLY. maven / npm / pypi / nuget coordinates are genuinely not module paths, and
// the resolvers for those ecosystems read Coordinate on purpose. The projection also cannot fabricate
// a refute: if a record ever carried a sub-package path rather than a module path, the go.mod lookup
// finds no require line, the version stays empty, and the advisory fails OPEN exactly as it does
// today.
func goModulePath(module, coordinate, scheme string) string {
	if module != "" || scheme != "gomod" {
		return module
	}
	return coordinate
}

// digestMatches reports whether sha256(data) equals the expected "sha256:<hex>" string.
func digestMatches(data []byte, expected string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(expected, prefix) {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == strings.TrimPrefix(expected, prefix)
}

// recognizedVersionSchemes is the closed admitted vocabulary: the empty scheme (Go-semver default)
// plus every non-Go comparator versionOutsideRange dispatches on. It is a named list rather than a
// switch so a test can ENUMERATE the dispatch — the dead-axis table
// (disqual_dead_axis_table_test.go) walks it and demands each arm have a live production producer of
// resolved_version. A comment claiming a comparator has an input cannot be tested; a list can.
var recognizedVersionSchemes = []string{"", "gomod", "maven", "npm", "pypi", "nuget", "go-toolchain"}

// schemeRecognized allows the empty scheme (Go-semver default) plus the closed set of non-Go
// comparators. An unrecognized scheme fails open — the safe direction (an advisory we cannot
// place on a known version axis contributes no version-range refute).
func schemeRecognized(scheme string) bool {
	for _, s := range recognizedVersionSchemes {
		if scheme == s {
			return true
		}
	}
	return false
}

// trustTierRecognized allows the empty tier (zero value: untrusted, never refutes) plus the closed
// TrustTier enum. Any other value fails validation → fail open.
func trustTierRecognized(tier string) bool {
	switch TrustTier(tier) {
	case "", TrustByO, TrustThirdParty, TrustFirstParty:
		return true
	default:
		return false
	}
}

// attributionStatusRecognized allows the empty status (zero value, semantically unreviewed) plus the
// closed AttributionStatus enum (§4.4.8). Any other value fails validation → fail open to unreviewed,
// mirroring trustTierRecognized. Wired into per-symbol population by PLAN-220 (this cycle establishes
// the type + validator + state model only); exercised now by TestAttributionStatusRecognized.
func attributionStatusRecognized(status string) bool {
	switch AttributionStatus(status) {
	case "", AttributionUnreviewed, AttributionConfirmed, AttributionAmbiguous, AttributionDisputed:
		return true
	default:
		return false
	}
}

// --- v3 closed-set validators -----------------------------------------------------------------
// All three mirror schemeRecognized/trustTierRecognized: a recognized member (including the empty
// zero) validates; anything else fails open (the operand drops to zero, never a silent wrong route).
// They live together here, next to the existing recognizers, so the whole seam's operand vocabulary
// is validated in one place (any new operand needs a matching recognizer or it fails open silently).

// codeExecutionFanout is the subset of vulnclass classes the corpus's "code_execution" sink_kind
// may disambiguate to, given the advisory's CWEs. The upstream vocabulary stays as it is; the
// mapping into our closed enum lives here. A CWE that recognizes to some OTHER class (e.g. a
// memory-safety CWE riding along on a code_execution advisory) is not a code_execution
// disambiguator and is ignored for this fan-out; it does not count toward "pinned" or "ambiguous".
var codeExecutionFanout = map[vulnclass.Class]bool{
	vulnclass.ClassDeserialize: true, // CWE-502
	vulnclass.ClassTemplateInj: true, // CWE-1336, CWE-94 (SSTI)
	vulnclass.ClassInjection:   true, // CWE-77, CWE-78
}

// intelSinkKindClass maps Intel's stable sink taxonomy (the corpus-native sink_kind vocabulary,
// distinct from vulnclass.Class) to a vulnclass.Class for the 1:1, CWE-independent members. Members
// whose Intel string happens to already equal the vulnclass.Class string (e.g. "ssrf",
// "path_traversal") are handled by the native-enum branch in classFromSinkKind and do not need an
// entry here; this map only carries the members where the two vocabularies diverge.
var intelSinkKindClass = map[string]vulnclass.Class{
	"memory_corruption":   vulnclass.ClassMemorySafety,
	"resource_exhaustion": vulnclass.ClassDoS,
}

// classFromSinkKind resolves a declared sink_kind string to a vulnclass.Class. The recognized
// vocabulary is TWO-LAYERED:
//
//  1. Native back-compat: a value that is already a literal vulnclass.Class string resolves 1:1
//     (our own fixtures, and any corpus that emits the enum directly, e.g. "ssrf",
//     "path_traversal" — which are also Intel-vocabulary-identical strings).
//  2. Intel's stable sink taxonomy: "memory_corruption", "resource_exhaustion" map 1:1 via
//     intelSinkKindClass; "code_execution" FANS OUT by the advisory's cwe[] (deserialization /
//     template_injection / injection) via classFromCodeExecutionCWEs.
//
// Intel keeps its own vocabulary; this projection layer (this function) owns the mapping — the
// corpus never has to speak vulnclass.Class. An empty, unrecognized, or ambiguous value returns
// ok=false (HONEST-ABSENT, BINDING zero-regressions invariant): the caller keeps the CWE/keyword
// classifier result rather than risk overriding a correct classification with a wrong mapped class.
func classFromSinkKind(s string, cwes []string) (vulnclass.Class, bool) {
	switch vulnclass.Class(s) {
	case vulnclass.ClassMemorySafety, vulnclass.ClassInjection, vulnclass.ClassPathTraversal,
		vulnclass.ClassDeserialize, vulnclass.ClassSSRF, vulnclass.ClassAuthBypass,
		vulnclass.ClassDoS, vulnclass.ClassTemplateInj, vulnclass.ClassUnsafeRefl,
		vulnclass.ClassOpenRedirect, vulnclass.ClassPrototypePollution:
		return vulnclass.Class(s), true
	}
	if c, ok := intelSinkKindClass[s]; ok {
		return c, true
	}
	if s == "code_execution" {
		return classFromCodeExecutionCWEs(cwes)
	}
	// Includes "" (ClassUnknown) and any other unrecognized value: fail open, the classifier stands.
	return vulnclass.ClassUnknown, false
}

// classFromCodeExecutionCWEs disambiguates the Intel "code_execution" sink_kind by the advisory's
// cwe[] set, reusing vulnclass's existing CWE→Class table (vulnclass.ClassFromCWE) rather than
// re-encoding CWE numbers here. It collects the DISTINCT set of codeExecutionFanout classes any
// advisory CWE recognizes to; if exactly one distinct class is pinned, that is the resolution. If
// zero CWEs pin a fan-out class, or more than one distinct class is pinned (a genuinely ambiguous
// advisory, e.g. cwe=[CWE-502, CWE-78]), this returns ok=false — HONEST-ABSENT, never a guess.
func classFromCodeExecutionCWEs(cwes []string) (vulnclass.Class, bool) {
	found := make(map[vulnclass.Class]bool, 1)
	for _, raw := range cwes {
		c, ok := vulnclass.ClassFromCWE(raw)
		if !ok || !codeExecutionFanout[c] {
			continue
		}
		found[c] = true
	}
	if len(found) != 1 {
		return vulnclass.ClassUnknown, false
	}
	for c := range found {
		return c, true
	}
	return vulnclass.ClassUnknown, false // unreachable (len(found) == 1 above)
}

// sinkKindRecognized reports whether s is the empty zero or a recognized sink_kind — either the
// native vulnclass.Class vocabulary or Intel's stable sink taxonomy, INCLUDING "code_execution"
// (which is recognized as a vocabulary member even though it resolves conditionally on cwe[] — a
// declared sink_kind of "code_execution" is a real, well-formed corpus value, not garbage; whether it
// PINS a class on a given advisory is what classFromSinkKind's cwe[] fan-out decides). Empty is
// recognized (the zero, no override); any other unrecognized value fails open.
func sinkKindRecognized(s string) bool {
	if s == "" || s == "code_execution" {
		return true
	}
	switch vulnclass.Class(s) {
	case vulnclass.ClassMemorySafety, vulnclass.ClassInjection, vulnclass.ClassPathTraversal,
		vulnclass.ClassDeserialize, vulnclass.ClassSSRF, vulnclass.ClassAuthBypass,
		vulnclass.ClassDoS, vulnclass.ClassTemplateInj, vulnclass.ClassUnsafeRefl,
		vulnclass.ClassOpenRedirect, vulnclass.ClassPrototypePollution:
		return true
	}
	_, ok := intelSinkKindClass[s]
	return ok
}

// ingressKindRecognized allows the empty zero plus the closed ingress-kind set. An
// unrecognized kind fails open — toFacts drops it to "", and framing falls to the per-class constant.
func ingressKindRecognized(kind string) bool {
	switch kind {
	case "", "http", "grpc", "cli", "library":
		return true
	default:
		return false
	}
}

// failedFixClassRecognized allows the empty zero plus the failed-fix taxonomy: the two shapes a
// published fix repeatedly turns out to have when it did not actually close the vulnerability. An
// unrecognized class fails open — toFacts drops it to "".
func failedFixClassRecognized(class string) bool {
	switch class {
	case "", "naive-dep-bump-insufficient", "guard-keyed-away-from-sink":
		return true
	default:
		return false
	}
}

// safeRelPath rejects manifest `path` entries that escape root: absolute paths (either separator
// convention), backslash separators, empty or "." or ".." segments. Forward-slash subdirectories ARE
// allowed — the corpus is date-partitioned (e.g. "2021/12/CVE-2021-44228.json") — which
// is the one thing this extends beyond the flat-basename-only safeRelName it replaces.
func safeRelPath(p string) bool {
	if p == "" || strings.Contains(p, "\\") || filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
