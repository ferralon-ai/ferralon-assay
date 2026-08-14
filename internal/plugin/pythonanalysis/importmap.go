package pythonanalysis

// Distribution → import-package mapping (PLAN-172, §6 Phase 1).
//
// The mapping answers "which import packages does a PyPI distribution contribute, and by
// what provenance" — the identity join PLAN-370 needs to make the call graph import-aware
// and PLAN-270 upgrades from curated to observed. This cycle ships the TYPE plus its
// declared/curated/unknown paths; the observed value is defined here and populated by
// nothing in this cycle (PLAN-270 fills it via a data change, no type change).
//
// The canonical state is a flat, sorted slice of Contributions — never a nested map —
// because provenance, source, and date attach to the individual (distribution → import
// package) fact, not to a distribution as a whole. Forward/reverse lookups are derived
// read-only from that slice; no map is an iteration source on any output or serialization
// path (C6).
//
// LOCATION (D3): lane-local in internal/plugin/pythonanalysis. The mapping is intrinsically
// Python-ecosystem-shaped (dotted import paths, PEP 420 namespaces, PEP 503 names) and both
// consumers (PLAN-270, PLAN-370) edit this same package; the language-agnostic plugin
// contract stays clean. plugin.go is consumed, never edited.

import (
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Provenance records how a single distribution→import-package contribution was obtained.
// The zero value is invalid: every contribution the module produces has a non-zero
// Provenance (C2a). It is a typed string, not a bool, so an observed fact is distinguishable
// from a curated guess with identical names (C2b).
type Provenance string

const (
	// ProvenanceDeclared: read from a first-party project's source layout (checkout.WorkspacePlan
	// roots + module tree — NOT a pyproject `packages` field for our corpus; see DeriveFirstParty).
	ProvenanceDeclared Provenance = "declared"
	// ProvenanceCurated: a checked-in table row with a cited Source + Date (C5).
	ProvenanceCurated Provenance = "curated"
	// ProvenanceObserved: read from the selected artifact's own metadata (top_level.txt/RECORD).
	// DEFINED by this cycle, POPULATED by none of it — PLAN-270 fills it with a data change, no
	// type change (C2). No code in this cycle constructs a ProvenanceObserved contribution.
	ProvenanceObserved Provenance = "observed"
	// ProvenanceUnknown: no declared/curated/observed source. A declared unknown (C4) — never a
	// name-identity guess. ImportPackage is "" and Partiality is set (see DeclaredUnknown).
	ProvenanceUnknown Provenance = "unknown"
)

// knownProvenance is the recognized enum set; the validator rejects any other value.
var knownProvenance = map[Provenance]bool{
	ProvenanceDeclared: true,
	ProvenanceCurated:  true,
	ProvenanceObserved: true,
	ProvenanceUnknown:  true,
}

// Contribution is one (distribution → import package) fact with its provenance. It is the
// atomic, sorted unit. IDENTITY/dedup is by (Distribution, ImportPackage, Provenance) —
// INCLUDING Provenance — so an observed contribution never silently equals or overwrites a
// curated one with identical names (C2b; otherwise PLAN-270's upgrade would be invisible).
type Contribution struct {
	Distribution  string             `json:"distribution"`         // PEP 503-normalized distribution name (left-hand side)
	ImportPackage string             `json:"import_package"`       // dotted import path CONTRIBUTED (e.g. "airflow", "acme.foo"); "" iff Provenance==unknown
	Provenance    Provenance         `json:"provenance"`           // how obtained; never the zero value (C2a)
	Source        string             `json:"source,omitempty"`     // C5: citation for a curated row (required when Provenance==curated)
	Date          string             `json:"date,omitempty"`       // C5: RFC 3339 date the curated row was taken (required when Provenance==curated)
	Partiality    *plugin.Partiality `json:"partiality,omitempty"` // set IFF Provenance==unknown (C4); nil for a resolved contribution
}

// DistImportMap is the many-to-many distribution↔import-package mapping for one resolution.
// The canonical state is the sorted Contributions slice — the ONLY serialization source (C6).
// Forward and Reverse indexes are built on demand from it and are never an iteration source
// on any output or serialization path.
type DistImportMap struct {
	Contributions []Contribution `json:"contributions"` // sorted by (Distribution, ImportPackage, Provenance)
}

// NewDistImportMap assembles a DistImportMap from contributions, canonicalizing them
// (sorted + deduped by the full identity tuple) so the result is deterministic. It does not
// validate — Validate is separate so a test can drive an invalid map through the validator.
func NewDistImportMap(contribs ...Contribution) DistImportMap {
	return DistImportMap{Contributions: canonicalize(contribs)}
}

// canonicalize sorts contributions by the full identity tuple (Distribution, ImportPackage,
// Provenance) and drops exact-tuple duplicates. The sort is total and deterministic, so the
// canonical slice is byte-identical across runs (C6).
func canonicalize(in []Contribution) []Contribution {
	if len(in) == 0 {
		return nil
	}
	out := make([]Contribution, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return lessContribution(out[i], out[j]) })
	deduped := out[:0]
	for i, c := range out {
		if i > 0 && sameIdentity(out[i-1], c) {
			continue
		}
		deduped = append(deduped, c)
	}
	return deduped
}

// lessContribution orders by (Distribution, ImportPackage, Provenance) — the full identity
// tuple — so ordering and dedup key agree.
func lessContribution(a, b Contribution) bool {
	if a.Distribution != b.Distribution {
		return a.Distribution < b.Distribution
	}
	if a.ImportPackage != b.ImportPackage {
		return a.ImportPackage < b.ImportPackage
	}
	return a.Provenance < b.Provenance
}

// sameIdentity reports whether two contributions share the full identity tuple. Source/Date/
// Partiality are NOT part of identity — an observed upgrade of a curated pair differs in
// Provenance, so it is a distinct contribution, never a silent overwrite (C2b).
func sameIdentity(a, b Contribution) bool {
	return a.Distribution == b.Distribution &&
		a.ImportPackage == b.ImportPackage &&
		a.Provenance == b.Provenance
}

// Forward returns the import packages a distribution contributes, sorted and deduped. A
// distribution whose only contribution is Unknown returns an EMPTY slice — never the
// distribution name (the name-identity fallback C4 forbids; the census's load-bearing
// apache-airflow→airflow row proves the map is a real lookup, not strings.ToLower).
//
// The forward index (map[dist][]importPkg) is built on demand for keyed O(1) lookup; it is
// never ranged to produce output or serialized. Unknown contributions (ImportPackage == "")
// are excluded, so an unknown-only distribution yields no entry at all.
func (m DistImportMap) Forward(dist string) []string {
	var pkgs []string
	for _, c := range m.Contributions {
		if c.Distribution != dist {
			continue
		}
		if c.Provenance == ProvenanceUnknown || c.ImportPackage == "" {
			continue
		}
		pkgs = append(pkgs, c.ImportPackage)
	}
	return sortedDedup(pkgs)
}

// Reverse returns the distributions contributing a given import package OR any package under
// it as a PEP 420 namespace root, sorted and deduped. A query q matches a contribution whose
// ImportPackage equals q OR is dotted-prefixed by q ("q."). So Reverse("acme.foo") returns
// the leaf's providers and Reverse("acme") returns EVERY distribution contributing under the
// namespace root (C3b). The prefix rule is what lets the namespace root return both providers
// WITHOUT either distribution owning the bare root as an exclusive entry (C3c): no
// Contribution{ImportPackage:"acme"} exists; "acme" is reachable only as a prefix of the leaves.
//
// Iteration is over the sorted Contributions slice — never a map — so output is deterministic.
func (m DistImportMap) Reverse(importPkg string) []string {
	var dists []string
	for _, c := range m.Contributions {
		if c.ImportPackage == "" {
			continue
		}
		if c.ImportPackage == importPkg || strings.HasPrefix(c.ImportPackage, importPkg+".") {
			dists = append(dists, c.Distribution)
		}
	}
	return sortedDedup(dists)
}

// sortedDedup returns a sorted, duplicate-free copy. A nil/empty input yields a nil slice,
// so Forward on an unknown-only distribution returns EMPTY, never the distribution name.
func sortedDedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	deduped := out[:0]
	for i, s := range out {
		if i > 0 && out[i-1] == s {
			continue
		}
		deduped = append(deduped, s)
	}
	return deduped
}

// DeclaredUnknown builds the C4 declared-unknown contribution for a distribution with no
// declared, curated, or observed source. It yields Provenance==unknown with ImportPackage==""
// and a declared Partiality — an honest, fine-grained "we do not know this distribution's
// import packages", never a name-identity guess (§3.1). The distribution name is PEP
// 503-normalized so it collates with the rest of the map.
//
// TODO(PLAN-371): the Partiality rides plugin.Unsupported() (PartialReasonUnsupported =
// "unsupported_phase1") PROVISIONALLY. PLAN-371 owns the Python partiality vocabulary and will
// add a shared plugin.go reason code naming "distribution provides unknown import packages"
// (proposed PartialReasonImportMappingUnknown = "import_mapping_unknown"); swap this
// provisional ride for it then. This cycle adds NO new PartialReason* constant — not in
// plugin.go (anvil's) and not a lane-local placeholder string (D4). The provisional ride is
// defensible because the entry's own Provenance==unknown already carries the honest distinction;
// the partiality string is not the load-bearing honesty signal here.
func DeclaredUnknown(dist string) Contribution {
	p := plugin.Unsupported()
	return Contribution{
		Distribution:  normalizePyCoordinate(dist),
		ImportPackage: "",
		Provenance:    ProvenanceUnknown,
		Partiality:    &p,
	}
}
