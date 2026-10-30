package trigger

import (
	"slices"
	"sort"
	"strings"

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
func withInventoryLimits(f report.AdvisoryFinding, limits []report.PartialityNote) report.AdvisoryFinding {
	absent := f.Verdict == report.VerdictDisqualified && f.Evidence.Detail == disqualDetail(pipeline.ReasonNoManifestEntry)
	if !(f.Verdict == report.VerdictNotExploitable || restsOnInventory(f)) || (f.Package == nil && !absent) {
		return f
	}
	for _, n := range limits {
		if n.Ecosystem != "" && f.Package != nil && n.Ecosystem != f.Package.Ecosystem {
			continue
		}
		if report.ClassifyPartialityReason(n.Reason) != report.PartialityDidNotRun {
			continue
		}
		f.Verdict = report.VerdictUndetermined
		f.UndeterminedReason = report.ReasonAnalysisDidNotRun
		f.Evidence = report.EvidenceSummary{Detail: report.UndeterminedDetail(report.ReasonAnalysisDidNotRun)}
		return f
	}
	return f
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
func inventoryPartialityNotes(p plugin.Partiality, ecosystem string) []report.PartialityNote {
	if p.Complete {
		return nil
	}
	reasons := append([]string(nil), p.Reasons...)
	paths := map[string][]string{}
	for _, sr := range p.Scoped {
		if !slices.Contains(reasons, sr.Reason) {
			reasons = append(reasons, sr.Reason)
		}
		if sr.Path != "" {
			paths[sr.Reason] = append(paths[sr.Reason], sr.Path)
		}
	}
	if len(reasons) == 0 {
		reasons = []string{report.ReasonUnspecifiedLimit}
	}
	notes := make([]report.PartialityNote, 0, len(reasons))
	for _, r := range reasons {
		notes = append(notes, report.PartialityNote{
			Reason:    r,
			Ecosystem: ecosystem,
			Detail:    inventoryLimitDetail,
			Path:      strings.Join(paths[r], ", "),
		})
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
