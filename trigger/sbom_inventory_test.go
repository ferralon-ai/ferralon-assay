package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// fakeInventoryPlugin is a LanguagePlugin that differs from the hermetic stub in exactly one axis:
// ResolveInventory returns a caller-supplied DependencyInventory. Every other operation keeps
// StubPlugin's behavior, so injecting it changes ONLY the SBOM (which keys on ResolveInventory) and
// never a verdict — the isolation C5 depends on.
type fakeInventoryPlugin struct {
	plugin.StubPlugin
	lang string
	inv  plugin.DependencyInventory
}

func (p fakeInventoryPlugin) Language() string { return p.lang }

func (p fakeInventoryPlugin) ResolveInventory(context.Context, plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return p.inv, nil
}

// twoPackageInventory is a resolved (Complete) inventory: a direct package with one transitive child
// it depends on. Exercises Direct=true/false and a parent→child edge through the projection.
func twoPackageInventory() plugin.DependencyInventory {
	return plugin.DependencyInventory{
		Partiality: plugin.Complete(),
		Nodes: []plugin.DependencyNode{
			{ID: "n_text", PURL: "pkg:golang/golang.org/x/text@v0.3.6", Version: "v0.3.6", Direct: true},
			{ID: "n_net", PURL: "pkg:golang/golang.org/x/net@v0.17.0", Version: "v0.17.0", Direct: false},
		},
		Edges: []plugin.DependencyEdge{{Parent: "n_text", Child: "n_net"}},
	}
}

// lonelyInventory holds a single package that appears in NO advisory corpus used by these tests —
// the control for C1: an inventory-keyed producer surfaces it; an advisory-keyed one cannot.
func lonelyInventory() plugin.DependencyInventory {
	return plugin.DependencyInventory{
		Partiality: plugin.Complete(),
		Nodes: []plugin.DependencyNode{
			{ID: "lonely", PURL: "pkg:golang/example.com/lonely@v1.2.3", Version: "v1.2.3", Direct: true},
		},
	}
}

// TestBaseline_InventoryKeyed_NonAdvisoryPackageReachesSBOM is C1 on the buildBaselineReport
// producer: a dependency that appears in NO advisory in the work set is present in the resulting
// report.SBOM. On main (advisory-keyed) this package could never appear — the producer only emitted
// packages some advisory named.
func TestBaseline_InventoryKeyed_NonAdvisoryPackageReachesSBOM(t *testing.T) {
	rep := runBaselineWith(t, goFixtureModule(t),
		[]assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}}, // about golang.org/x/text, not lonely
		fakeInventoryPlugin{lang: "go", inv: lonelyInventory()})

	if !hasPackageNamed(rep.SBOM.Packages, "example.com/lonely") {
		t.Fatalf("a resolved dependency absent from the advisory corpus did not reach the SBOM: %+v", rep.SBOM.Packages)
	}
}

// TestSBOMFromInventory_UnsupportedVsEmptyHonesty is C3, the load-bearing honesty check, at the
// projection: an inventory that could NOT be resolved (Unsupported) is declared with a scan-level
// partiality note; an inventory that resolved to genuinely zero dependencies is silent. Both produce
// an empty package list and MUST be distinguishable — if one assertion accepted both, the test would
// measure nothing.
func TestSBOMFromInventory_UnsupportedVsEmptyHonesty(t *testing.T) {
	// (i) resolved with packages: no note.
	iSBOM, iNotes := sbomFromInventory(twoPackageInventory(), "Go")
	if len(iSBOM.Packages) != 2 || len(iNotes) != 0 {
		t.Fatalf("(i) resolved: want 2 packages + 0 notes, got %d packages, %d notes", len(iSBOM.Packages), len(iNotes))
	}
	// (ii) unsupported: empty packages, ONE note naming the ecosystem.
	iiSBOM, iiNotes := sbomFromInventory(plugin.DependencyInventory{Partiality: plugin.Unsupported()}, "Go")
	if len(iiSBOM.Packages) != 0 || len(iiNotes) != 1 || iiNotes[0].Ecosystem != "Go" {
		t.Fatalf("(ii) unsupported: want 0 packages + 1 Go note, got %d packages, %+v", len(iiSBOM.Packages), iiNotes)
	}
	// (iii) honestly empty: empty packages, NO note.
	iiiSBOM, iiiNotes := sbomFromInventory(plugin.DependencyInventory{Partiality: plugin.Complete()}, "Go")
	if len(iiiSBOM.Packages) != 0 || len(iiiNotes) != 0 {
		t.Fatalf("(iii) honestly-empty: want 0 packages + 0 notes, got %d packages, %d notes", len(iiiSBOM.Packages), len(iiiNotes))
	}
	// The two empty-package cases MUST differ in disclosure. Mutation control: dropping the note in
	// inventoryPartialityNotes collapses (ii) onto (iii) and trips this.
	if len(iiNotes) == len(iiiNotes) {
		t.Fatal("unsupported and honestly-empty inventories are indistinguishable — the exact honesty bug C3 guards")
	}
}

// TestBaseline_UnsupportedInventoryDeclaresPartiality is C3 end-to-end: the unsupported-inventory
// note reaches the built Report's scan-level partiality, so a mostly-empty Phase-1 SBOM is an honest
// disclosure rather than a silent shrink of the CVE-watch query set.
func TestBaseline_UnsupportedInventoryDeclaresPartiality(t *testing.T) {
	rep := runBaselineWith(t, goFixtureModule(t),
		[]assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
		fakeInventoryPlugin{lang: "go", inv: plugin.DependencyInventory{Partiality: plugin.Unsupported()}})

	if len(rep.SBOM.Packages) != 0 {
		t.Fatalf("unsupported inventory ⇒ empty SBOM, got %+v", rep.SBOM.Packages)
	}
	if !hasPartialityReason(rep.Partiality, plugin.PartialReasonUnsupported) {
		t.Fatalf("unsupported inventory must declare a partiality note, got %+v", rep.Partiality)
	}
}

// TestBaseline_WiderSBOMChangesNoVerdict is C5: a wider SBOM changes no verdict. Two plugins identical
// in every pipeline operation differ ONLY in ResolveInventory; the findings are byte-equal while the
// SBOMs differ, proving the inventory feeds the SBOM and never a verdict.
func TestBaseline_WiderSBOMChangesNoVerdict(t *testing.T) {
	codebase := goFixtureModule(t)
	corpus := []assessment.VulnRef{
		{ID: "GO-2021-0113", Source: "osv"},
		{ID: "GO-2021-0264", Source: "osv"},
	}
	repEmpty := runBaselineWith(t, codebase, corpus,
		fakeInventoryPlugin{lang: "go", inv: plugin.DependencyInventory{Partiality: plugin.Unsupported()}})
	repWide := runBaselineWith(t, codebase, corpus,
		fakeInventoryPlugin{lang: "go", inv: twoPackageInventory()})

	if !equalFindings(repEmpty.Advisories, repWide.Advisories) {
		t.Fatalf("a wider SBOM changed a verdict:\n empty=%+v\n wide=%+v", repEmpty.Advisories, repWide.Advisories)
	}
	if len(repWide.SBOM.Packages) <= len(repEmpty.SBOM.Packages) {
		t.Fatal("the wide plugin must actually widen the SBOM, else the invariance is vacuous")
	}
}

// TestBaseline_RelationshipsAndDirectReachReport is the producer half of C2: the inventory's
// parent→child edge and its direct/transitive distinction round-trip through buildBaselineReport into
// report.SBOM, referentially valid (BuildValidated ran inside RunBaseline).
func TestBaseline_RelationshipsAndDirectReachReport(t *testing.T) {
	rep := runBaselineWith(t, goFixtureModule(t),
		[]assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
		fakeInventoryPlugin{lang: "go", inv: twoPackageInventory()})

	if len(rep.SBOM.Relationships) != 1 {
		t.Fatalf("want 1 relationship from the inventory edge, got %+v", rep.SBOM.Relationships)
	}
	rel := rep.SBOM.Relationships[0]
	if rel.Parent != "pkg:golang/golang.org/x/text@v0.3.6" || rel.Child != "pkg:golang/golang.org/x/net@v0.17.0" {
		t.Fatalf("relationship endpoints wrong: %+v", rel)
	}
	direct, transitive := false, false
	for _, p := range rep.SBOM.Packages {
		if p.Name == "golang.org/x/text" && p.Direct {
			direct = true
		}
		if p.Name == "golang.org/x/net" && !p.Direct {
			transitive = true
		}
	}
	if !direct || !transitive {
		t.Fatalf("direct/transitive distinction lost through the report: %+v", rep.SBOM.Packages)
	}
}

func runBaselineWith(t *testing.T, codebase assessment.CodebaseRef, corpus []assessment.VulnRef, p plugin.LanguagePlugin) *report.Report {
	t.Helper()
	rep, err := RunBaseline(context.Background(), &memStore{}, BaselineRequest{
		Subject:       Subject{Repo: "example.com/app", ResolvedCommit: "sha"},
		Codebase:      codebase,
		Advisories:    corpus,
		AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(p)},
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	return rep
}

func hasPackageNamed(pkgs []report.Package, name string) bool {
	for _, p := range pkgs {
		if p.Name == name {
			return true
		}
	}
	return false
}

func hasPartialityReason(notes []report.PartialityNote, reason string) bool {
	for _, n := range notes {
		if n.Reason == reason {
			return true
		}
	}
	return false
}

// equalFindings compares the verdict-bearing identity of two finding slices: id, verdict, grade and
// undetermined reason. A wider SBOM must leave every one of these unchanged.
func equalFindings(a, b []report.AdvisoryFinding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Advisory.ID != b[i].Advisory.ID ||
			a[i].Verdict != b[i].Verdict ||
			a[i].Evidence.Grade != b[i].Evidence.Grade ||
			a[i].UndeterminedReason != b[i].UndeterminedReason {
			return false
		}
	}
	return true
}
