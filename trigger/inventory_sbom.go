package trigger

import (
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
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
	return report.SBOM{Packages: pkgs, Relationships: rels}, notes
}

// inventoryPartialityNotes turns a graph-level Partiality into the scan-level notes that declare an
// unresolved inventory (C3). A Complete inventory declares nothing — a codebase with genuinely zero
// dependencies is silent, and only a resolver that could NOT establish the inventory (Unsupported /
// no_language_plugin / any partial) names the limit. A partial that carries no reason still emits a
// note (unspecified_limit) rather than nothing: silence here is the shrunken-CVE-watch failure §4.1
// exists to prevent.
func inventoryPartialityNotes(p plugin.Partiality, ecosystem string) []report.PartialityNote {
	if p.Complete {
		return nil
	}
	reasons := p.Reasons
	if len(reasons) == 0 {
		reasons = []string{report.ReasonUnspecifiedLimit}
	}
	notes := make([]report.PartialityNote, 0, len(reasons))
	for _, r := range reasons {
		notes = append(notes, report.PartialityNote{
			Reason:    r,
			Ecosystem: ecosystem,
			Detail:    "dependency inventory not fully resolved; the SBOM may omit packages for this ecosystem",
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
	return purlTypeToEcosystem(body[:slash], fallbackEcosystem), body[slash+1:]
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
