package trigger

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// This file is the .NET half of the inventory→SBOM projection proof (PLAN-152). It mirrors
// sbom_inventory_test.go (Go-keyed) with lang:"dotnet" and NuGet PURLs, asserting the SINGLE shared
// projection (sbomFromInventory) subsumes .NET: nuget→NuGet ecosystem, PURL-name extraction, Key()-
// joined relationships, and both partiality shapes (node + graph). Helpers fakeInventoryPlugin,
// runBaselineWith, hasPackageNamed live in sbom_inventory_test.go — same package.

// dotnetFixtureModule writes a minimal .NET project to a temp dir whose sole marker is a .csproj, so
// checkout.DetectLanguage classifies it as "dotnet" (the vendored_repro path — no network, no dotnet
// invocation). It is the .NET analogue of goFixtureModule; the injected fakeInventoryPlugin supplies
// the inventory, so the .csproj content is never restored.
func dotnetFixtureModule(t *testing.T) assessment.CodebaseRef {
	t.Helper()
	dir := t.TempDir()
	csproj := `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>` +
		`<ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>`
	if err := os.WriteFile(filepath.Join(dir, "App.csproj"), []byte(csproj), 0o644); err != nil {
		t.Fatalf("write App.csproj: %v", err)
	}
	return assessment.CodebaseRef{
		Repo:        "example.com/app",
		Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
	}
}

// nugetTwoPackageInventory is a resolved (Complete) NuGet inventory: a direct package with one
// transitive child it depends on. NuGet PURLs are lower-cased (nugetPURL), the transitive node carries
// a node-level partiality reason (the portable RID-agnostic "no_runtime_target" the real assets-tier
// resolver emits for a rid-less target), and a parent→child edge exercises the relationship projection.
func nugetTwoPackageInventory() plugin.DependencyInventory {
	return plugin.DependencyInventory{
		Partiality: plugin.Complete(),
		Nodes: []plugin.DependencyNode{
			{ID: "n_json", PURL: "pkg:nuget/newtonsoft.json@13.0.3", Version: "13.0.3", Direct: true},
			{
				ID: "n_bcl", PURL: "pkg:nuget/microsoft.bcl.asyncinterfaces@8.0.0", Version: "8.0.0", Direct: false,
				// A node-level limit (a portable resolution with no RID selection) must ride the package
				// as its PartialReason — mirror of ridPartiality(rid=="") in the real .NET resolver.
				Partiality: plugin.Partial("no_runtime_target"),
			},
		},
		Edges: []plugin.DependencyEdge{{Parent: "n_json", Child: "n_bcl"}},
	}
}

// lonelyNuGetInventory holds a single NuGet package that appears in NO advisory corpus these tests use
// — the control for C1: an inventory-keyed producer surfaces it; an advisory-keyed one never could.
func lonelyNuGetInventory() plugin.DependencyInventory {
	return plugin.DependencyInventory{
		Partiality: plugin.Complete(),
		Nodes: []plugin.DependencyNode{
			{ID: "lonely", PURL: "pkg:nuget/example.only@1.2.3", Version: "1.2.3", Direct: true},
		},
	}
}

// TestSBOMFromInventory_DotNet_NuGetProjection is the .NET projection unit test: a Complete NuGet
// inventory with a direct + transitive package, a parent→child edge, and node-level partiality projects
// to a report.SBOM whose packages are NuGet-ecosystem, PURL-named, correctly direct/transitive, whose
// relationship is Key()-joined (NOT string containment), and whose node partiality rides the package.
func TestSBOMFromInventory_DotNet_NuGetProjection(t *testing.T) {
	sbom, notes := sbomFromInventory(nugetTwoPackageInventory(), ecosystemFor("dotnet"))

	if len(sbom.Packages) != 2 {
		t.Fatalf("want 2 NuGet packages, got %d: %+v", len(sbom.Packages), sbom.Packages)
	}
	if len(notes) != 0 {
		t.Fatalf("a Complete inventory declares no scan-level note, got %+v", notes)
	}

	// (1) every package is NuGet; (2) Name is the PURL name (not the raw PURL); Version + Direct correct.
	var direct, transitive *report.Package
	for i := range sbom.Packages {
		p := &sbom.Packages[i]
		if p.Ecosystem != "NuGet" {
			t.Fatalf("package %q ecosystem = %q, want NuGet (the nuget→NuGet map)", p.Name, p.Ecosystem)
		}
		switch p.Name {
		case "newtonsoft.json":
			direct = p
		case "microsoft.bcl.asyncinterfaces":
			transitive = p
		default:
			t.Fatalf("unexpected package name %q — PURL name extraction wrong (raw PURL leaked?)", p.Name)
		}
	}
	if direct == nil || transitive == nil {
		t.Fatalf("both packages must be present by PURL name: %+v", sbom.Packages)
	}
	if direct.Version != "13.0.3" || !direct.Direct {
		t.Fatalf("direct package wrong: %+v", *direct)
	}
	if transitive.Version != "8.0.0" || transitive.Direct {
		t.Fatalf("transitive package wrong: %+v", *transitive)
	}
	// (4) node-level partiality rides the package PartialReason; the clean node carries none.
	if transitive.PartialReason != "no_runtime_target" {
		t.Fatalf("node-level partiality did not ride the package: %+v", *transitive)
	}
	if direct.PartialReason != "" {
		t.Fatalf("a cleanly-resolved node must carry no PartialReason: %+v", *direct)
	}

	// (3) the parent→child relationship is present, keyed by report.Package.Key() — NOT by string
	// containment or the inventory's per-instance node IDs (n_json/n_bcl never ride the report).
	if len(sbom.Relationships) != 1 {
		t.Fatalf("want 1 relationship from the inventory edge, got %+v", sbom.Relationships)
	}
	rel := sbom.Relationships[0]
	if rel.Parent != direct.Key() || rel.Child != transitive.Key() {
		t.Fatalf("relationship not Key()-joined: rel=%+v parentKey=%q childKey=%q", rel, direct.Key(), transitive.Key())
	}
	// The endpoints are the PURLs (Key() returns PURL when set), never the raw node IDs.
	if rel.Parent == "n_json" || rel.Child == "n_bcl" {
		t.Fatalf("relationship leaked inventory node IDs instead of package keys: %+v", rel)
	}
}

// TestSBOMFromInventory_DotNet_GraphPartialDeclaresNuGetNote is C3 at the .NET projection: a graph-level
// Partial inventory (e.g. only a lockfile resolved, no restore output) yields a scan-level
// PartialityNote attributed to the NuGet ecosystem — the disclosure that keeps a shrunken SBOM honest.
func TestSBOMFromInventory_DotNet_GraphPartialDeclaresNuGetNote(t *testing.T) {
	inv := plugin.DependencyInventory{Partiality: plugin.Partial("no_resolver_output")}
	sbom, notes := sbomFromInventory(inv, ecosystemFor("dotnet"))

	if len(sbom.Packages) != 0 {
		t.Fatalf("an unresolved inventory has no packages, got %+v", sbom.Packages)
	}
	if len(notes) != 1 {
		t.Fatalf("a graph-level partial declares exactly one note, got %+v", notes)
	}
	if notes[0].Ecosystem != "NuGet" {
		t.Fatalf("the note must be attributed to NuGet, got %+v", notes[0])
	}
	if notes[0].Reason != "no_resolver_output" {
		t.Fatalf("the note must carry the graph-level reason, got %+v", notes[0])
	}
}

// TestBaseline_DotNet_InventoryKeyed_NonAdvisoryPackageReachesSBOM is C1 for .NET on the full
// buildBaselineReport producer: a NuGet dependency that appears in NO advisory in the work set still
// reaches the built report.SBOM. It runs the whole S1–S6 baseline over a .csproj codebase detected as
// "dotnet", so the injected .NET plugin's ResolveInventory is actually dispatched through the generic
// substrate (pipeline.ResolveCodebaseInventory keys dispatch on Plugin.Language()=="dotnet"). On an
// advisory-keyed producer this package could never appear — the corpus names a different package.
func TestBaseline_DotNet_InventoryKeyed_NonAdvisoryPackageReachesSBOM(t *testing.T) {
	rep := runBaselineWith(t, dotnetFixtureModule(t),
		[]assessment.VulnRef{{ID: "GHSA-0000-dotnet-other", Source: "osv"}}, // about some other package, not example.only
		fakeInventoryPlugin{lang: "dotnet", inv: lonelyNuGetInventory()})

	if !hasPackageNamed(rep.SBOM.Packages, "example.only") {
		t.Fatalf("a resolved .NET dependency absent from the advisory corpus did not reach the SBOM: %+v", rep.SBOM.Packages)
	}
	for i := range rep.SBOM.Packages {
		if rep.SBOM.Packages[i].Name == "example.only" && rep.SBOM.Packages[i].Ecosystem != "NuGet" {
			t.Fatalf("the .NET package reached the SBOM with the wrong ecosystem: %+v", rep.SBOM.Packages[i])
		}
	}
}
