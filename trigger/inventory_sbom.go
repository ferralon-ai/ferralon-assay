package trigger

import (
	"slices"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// sbomFromInventory maps a whole-graph plugin.DependencyInventory (§4.1) to the report.SBOM the scan
// emits, plus the scan-level partiality notes an unresolved inventory MUST declare (C3). It is the
// single inventory→report projection both SBOM producers share, so ResolveSBOM and
// buildBaselineReport key on the inventory identically (C1).
//
// ecosystem is the OSV/PURL ecosystem of the resolved language: it attributes the graph-level
// partiality note and is the fallback ecosystem for a node whose PURL does not name one.
func sbomFromInventory(inv plugin.DependencyInventory, ecosystem string) (report.SBOM, []report.PartialityNote) {
	notes := inventoryPartialityNotes(inv.Partiality, ecosystem)

	pkgs := make([]report.Package, 0, len(inv.Nodes))
	keyByID := make(map[string]string, len(inv.Nodes))
	seen := make(map[string]struct{}, len(inv.Nodes))
	for i := range inv.Nodes {
		n := inv.Nodes[i]
		eco, name := ecosystemAndNameFromPURL(n.PURL, ecosystem)
		p := report.Package{
			Ecosystem: eco,
			Name:      name,
			Version:   n.Version,
			PURL:      n.PURL,
			Direct:    n.Direct,
			Replace:   n.Replace,
		}
		if !n.Partiality.Complete && len(n.Partiality.Reasons) > 0 {
			// A node-level limit (e.g. a version that could not be pinned, a digest not acquired)
			// rides the package as its primary reason code; the full set stays in the inventory node.
			// Empty PartialReason means this package resolved cleanly.
			p.PartialReason = n.Partiality.Reasons[0]
		}
		key := p.Key()
		keyByID[n.ID] = key
		if _, ok := seen[key]; ok {
			// The report SBOM is package-granularity: distinct inventory node instances of one
			// identity collapse to one package. The instance tree with distinct IDs stays in the
			// inventory; edges below are re-expressed over the collapsed keys.
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, p)
	}

	rels := make([]report.Relationship, 0, len(inv.Edges))
	relSeen := make(map[report.Relationship]struct{}, len(inv.Edges))
	for _, e := range inv.Edges {
		parent, pok := keyByID[e.Parent]
		child, cok := keyByID[e.Child]
		if !pok || !cok {
			// An edge whose endpoint is not among Nodes is a resolver defect; dropping it keeps the
			// SBOM referentially valid (report.Validate rejects a dangling edge).
			continue
		}
		r := report.Relationship{Parent: parent, Child: child}
		if _, ok := relSeen[r]; ok {
			continue
		}
		relSeen[r] = struct{}{}
		rels = append(rels, r)
	}

	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].Parent != rels[j].Parent {
			return rels[i].Parent < rels[j].Parent
		}
		return rels[i].Child < rels[j].Child
	})

	if len(pkgs) == 0 {
		pkgs = nil
	}
	if len(rels) == 0 {
		rels = nil
	}
	sbom := report.SBOM{Packages: pkgs, Relationships: rels}
	if ecosystem == "Go" {
		sbom.GoBuildList, sbom.GoMainModule = inv.BuildList, inv.MainModule
	}
	return sbom, notes
}

// inventoryLimitDetail marks a note as the whole-graph inventory's own limit. CVE-watch reads the
// prior Report's notes back by it (inventoryLimits).
const inventoryLimitDetail = "dependency inventory not fully resolved; the SBOM may omit packages for this ecosystem"

// inventoryLimits returns the whole-graph inventory notes among notes.
func inventoryLimits(notes []report.PartialityNote) []report.PartialityNote {
	var out []report.PartialityNote
	for _, n := range notes {
		if n.Detail == inventoryLimitDetail {
			out = append(out, n)
		}
	}
	return out
}

// withInventoryLimits is G0 for the scan-wide inventory: an inventory step that did not run for an
// ecosystem (an ambiguous lockfile left a root's packages out, a resolver failed) means the
// admitted package may also be installed where the analysis never looked, so no
// not_exploitable of that ecosystem stands. Those limits are resolved once per scan, outside
// every assessment's own artifacts, which is why finding() cannot see them and this runs after
// it.
//
// The same holds for a disqualification that rests on the inventory: a version outside the range
// says nothing of a second copy the inventory missed, and a package absent from the manifest may
// be present where it never looked. Those rows become undetermined too. A symbol-axis
// disqualification compares the built artifact and an ecosystem mismatch compares the lane, so
// neither depends on the inventory and both stand.
//
// A package absent from the manifest has no Package to match a limit's ecosystem against, so any
// did-not-run limit demotes it. Any other row with no Package is a Go toolchain row, whose version
// is the toolchain's rather than the inventory's, so it stands.
//
// A limit bounded by Targets (a Go module nested below the build root, whose go.mod lists all it
// builds against) demotes only a row whose packages could be one of them. purls is every package
// the row's advisory affects, beside the row's own Package; with none known, a bounded limit
// demotes as an unbounded one does.
func withInventoryLimits(f report.AdvisoryFinding, limits []report.PartialityNote, purls []string) report.AdvisoryFinding {
	absent := f.Verdict == report.VerdictDisqualified && f.Evidence.Detail == disqualDetail(pipeline.ReasonNoManifestEntry)
	if !(f.Verdict == report.VerdictNotExploitable || restsOnInventory(f)) || (f.Package == nil && !absent) {
		return f
	}
	keys, known := rowKeys(f.Package, purls)
	for _, n := range limits {
		if n.Ecosystem != "" && f.Package != nil && n.Ecosystem != f.Package.Ecosystem {
			continue
		}
		if report.ClassifyPartialityReason(n.Reason) != report.PartialityDidNotRun || !limitCovers(n, keys, known) {
			continue
		}
		f.Verdict = report.VerdictUndetermined
		f.UndeterminedReason = report.ReasonAnalysisDidNotRun
		f.Evidence = report.EvidenceSummary{Detail: report.UndeterminedDetail(report.ReasonAnalysisDidNotRun)}
		return f
	}
	return f
}

// rowKeys returns the packages a row could be about: every one of purls, and the row's own
// package. known is false when purls is empty or any of them is not a package URL.
func rowKeys(pkg *report.Package, purls []string) (keys []pkgKey, known bool) {
	if len(purls) == 0 {
		return nil, false
	}
	for _, p := range purls {
		key, ok := purlKey(p)
		if !ok {
			return nil, false
		}
		keys = append(keys, key)
	}
	if pkg != nil {
		key, ok := purlKey(pkg.PURL)
		if !ok {
			typ, typed := purlTypeFor[pkg.Ecosystem]
			if !typed || pkg.Name == "" {
				return nil, false
			}
			key = pkgKey{typ: typ, name: normalizePackageName(typ, pkg.Name)}
		}
		keys = append(keys, key)
	}
	return keys, true
}

// limitCovers reports whether an inventory limit could hide a row about keys: it could unless it is
// bounded and none of its Targets could be one of them (scopedLimitCounts' rule). A row whose
// packages are not known could be about anything.
func limitCovers(n report.PartialityNote, keys []pkgKey, known bool) bool {
	if len(n.Targets) == 0 || !known {
		return true
	}
	bound := artifact.ScopedPartialityFlag{Targets: n.Targets}
	return slices.ContainsFunc(keys, func(k pkgKey) bool { return scopedLimitCounts(bound, k, true, false) })
}

// inheritedLimits returns the limits of head to apply to a row a Report re-emits from base. A row
// of base was judged under every limit base carries, with its advisory's packages known; re-applying
// a bounded one now, with only the row in hand, could only lose that bound's precision. So a bounded
// limit base carries is left out, and every other limit of head applies as to a fresh row.
func inheritedLimits(head []report.PartialityNote, base *report.Report) []report.PartialityNote {
	var carried []report.PartialityNote
	if base != nil {
		carried = inventoryLimits(base.Partiality)
	}
	var out []report.PartialityNote
	for _, n := range head {
		if len(n.Targets) > 0 && slices.ContainsFunc(carried, func(c report.PartialityNote) bool { return sameLimit(n, c) }) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// sameLimit reports whether a and b declare one limit with one bound.
func sameLimit(a, b report.PartialityNote) bool {
	return a.Reason == b.Reason && a.Ecosystem == b.Ecosystem && a.Detail == b.Detail &&
		a.Package == b.Package && a.Path == b.Path && slices.Equal(a.Targets, b.Targets)
}

// restsOnInventory reports whether f is a disqualification whose grounds are inventory facts.
func restsOnInventory(f report.AdvisoryFinding) bool {
	if f.Verdict != report.VerdictDisqualified {
		return false
	}
	return f.Evidence.Basis == verdict.BasisVersionNotAffected ||
		f.Evidence.Detail == disqualDetail(pipeline.ReasonNoManifestEntry)
}

// inventoryPartialityNotes turns a graph-level Partiality into the scan-level notes that declare an
// unresolved inventory (C3). A Complete inventory declares nothing — a codebase with genuinely zero
// dependencies is silent, and only a resolver that could NOT establish the inventory (Unsupported /
// no_language_plugin / any partial) names the limit. A partial that carries no reason still emits a
// note (unspecified_limit) rather than nothing: silence here is the shrunken-CVE-watch failure §4.1
// exists to prevent.
//
// A reason the inventory also scoped (a Go module nested below the build root, one limit per module)
// stays one note, whose Path names every scoped location, comma-separated, in the inventory's order.
// Its Targets are the union of the scoped limits' Targets: none, so unbounded, when the reason is
// also run-wide or any one of them is unbounded.
func inventoryPartialityNotes(p plugin.Partiality, ecosystem string) []report.PartialityNote {
	if p.Complete {
		return nil
	}
	reasons := append([]string(nil), p.Reasons...)
	paths := map[string][]string{}
	targets := map[string][]string{}
	unbounded := map[string]bool{}
	for _, r := range p.Reasons {
		unbounded[r] = true
	}
	for _, sr := range p.Scoped {
		if !slices.Contains(reasons, sr.Reason) {
			reasons = append(reasons, sr.Reason)
		}
		if sr.Path != "" {
			paths[sr.Reason] = append(paths[sr.Reason], sr.Path)
		}
		if len(sr.Targets) == 0 {
			unbounded[sr.Reason] = true
		}
		targets[sr.Reason] = append(targets[sr.Reason], sr.Targets...)
	}
	if len(reasons) == 0 {
		reasons = []string{report.ReasonUnspecifiedLimit}
	}
	notes := make([]report.PartialityNote, 0, len(reasons))
	for _, r := range reasons {
		n := report.PartialityNote{
			Reason:    r,
			Ecosystem: ecosystem,
			Detail:    inventoryLimitDetail,
			Path:      strings.Join(paths[r], ", "),
		}
		if !unbounded[r] {
			n.Targets = slices.Compact(slices.Sorted(slices.Values(targets[r])))
		}
		notes = append(notes, n)
	}
	return notes
}

// ecosystemAndNameFromPURL extracts the OSV ecosystem and package name from a normalized PURL
// ("pkg:golang/golang.org/x/text@v0.3.7" -> "Go", "golang.org/x/text"). A node with no parseable
// PURL falls back to the resolved-language ecosystem and an empty name — HONEST ABSENCE, never a
// fabricated coordinate.
func ecosystemAndNameFromPURL(purl, fallbackEcosystem string) (ecosystem, name string) {
	if !strings.HasPrefix(purl, "pkg:") {
		return fallbackEcosystem, ""
	}
	body := purl[len("pkg:"):]
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i] // strip qualifiers / subpath
	}
	if i := strings.LastIndex(body, "@"); i >= 0 {
		body = body[:i] // strip version
	}
	slash := strings.IndexByte(body, '/')
	if slash < 0 {
		return fallbackEcosystem, ""
	}
	ptype := body[:slash]
	name = body[slash+1:]
	if ptype == "maven" {
		// OSV addresses Maven packages as "group:artifact", but the PURL path form spells the same
		// coordinate "group/artifact". Left as-is, the SBOM would query OSV under a name that never
		// matches and silently miss advisories. A Maven group contains no '/', so the single
		// separator here is the group↔artifact boundary to rewrite. Go and npm keep their slashes
		// (that IS their OSV name); PyPI and NuGet carry no namespace.
		name = strings.Replace(name, "/", ":", 1)
	}
	return purlTypeToEcosystem(ptype, fallbackEcosystem), name
}

// purlTypeToEcosystem maps a PURL type to the OSV ecosystem name, mirroring ecosystemFor but keyed
// on the PURL type rather than the plugin language. An unrecognized type falls back to the resolved
// language's ecosystem, or the raw type when there is none.
func purlTypeToEcosystem(ptype, fallback string) string {
	switch ptype {
	case "golang":
		return "Go"
	case "maven":
		return "Maven"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "nuget":
		return "NuGet"
	default:
		if fallback != "" {
			return fallback
		}
		return ptype
	}
}
