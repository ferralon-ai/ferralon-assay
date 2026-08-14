package trigger

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	dotnetanalysis "github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// This is the higher-value half of the PLAN-152 proof: it runs the ACTUAL .NET resolver
// (dotnetanalysis.ResolveInventory) over a hermetic project.assets.json fixture and projects its REAL
// output through the shared sbomFromInventory. A hand-built fake asserts what I think the resolver
// emits; this asserts what it actually emits — real PURL format, node IDs, and edge endpoints — so a
// mismatch (a PURL the projection can't parse, an edge whose endpoint is not among Nodes, a node
// partiality dropped) reds here, not in production. No dotnet/MSBuild/NuGet: the fixture is read as
// bytes.

// composeDotNetBuildDir lays the single-transitive capture out into a fresh BuildDir the resolver
// consumes, mirroring the proven layout in inventory_c2_differential_test.go: proj/* (the .csproj) and
// assets/* (obj/project.assets.json) overlaid at the root, so the restore output lands in obj/ beside
// the project file. Read-only copy of checked-in testdata; nothing is executed.
func composeDotNetBuildDir(t *testing.T, capture string) string {
	t.Helper()
	base := filepath.Join("..", "internal", "plugin", "dotnetanalysis", "testdata", "inventory", "capture", capture)
	dst := t.TempDir()
	for _, sub := range []string{"proj", "assets"} {
		src := filepath.Join(base, sub)
		err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			target := filepath.Join(dst, rel)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0o644)
		})
		if err != nil {
			t.Fatalf("compose %s: %v", src, err)
		}
	}
	return dst
}

// TestDotNetRealInventoryProjectsToSBOM runs dotnetanalysis.ResolveInventory over the single-transitive
// fixture (a full net8.0 Microsoft.Extensions.Hosting graph with real transitive edges — chosen because
// it has transitive edges; the C2 suite asserts Microsoft.Extensions.Hosting@8.0.0 is direct) and
// projects the real inventory. It asserts the projected report.SBOM carries the fixture's real NuGet
// coordinates, at least one Key()-joined parent→child relationship, node partiality carried through, and
// passes report.Validate (no dangling edge).
func TestDotNetRealInventoryProjectsToSBOM(t *testing.T) {
	dir := composeDotNetBuildDir(t, "single-transitive")

	inv, err := dotnetanalysis.ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("ResolveInventory: %v", err)
	}
	// The assets tier resolves the whole graph: a Complete inventory with nodes and real edges. If this
	// fixture ever loses its transitive edge the relationship assertion below would vacuously pass, so
	// guard the precondition at the source.
	if !inv.Partiality.Complete {
		t.Fatalf("single-transitive resolves via the assets tier (Complete); got %+v", inv.Partiality)
	}
	if len(inv.Nodes) == 0 || len(inv.Edges) == 0 {
		t.Fatalf("fixture must yield a non-trivial graph: %d nodes, %d edges", len(inv.Nodes), len(inv.Edges))
	}

	// Project the REAL inventory through the shared projection under the .NET ecosystem.
	sbom, notes := sbomFromInventory(inv, ecosystemFor("dotnet"))
	if len(notes) != 0 {
		t.Fatalf("a Complete inventory yields no scan-level note, got %+v", notes)
	}
	if len(sbom.Packages) == 0 {
		t.Fatalf("the real inventory projected to zero packages: %+v", sbom)
	}

	// Every projected package is NuGet. A wrong ecosystem (e.g. the resolver emitting a "pkg:golang/…"
	// PURL, or ecosystemFor("dotnet") not mapping to NuGet) would trip here rather than silently
	// mis-key CVE-watch downstream.
	keys := make(map[string]struct{}, len(sbom.Packages))
	var direct, nodePartial bool
	for i := range sbom.Packages {
		p := sbom.Packages[i]
		if p.Ecosystem != "NuGet" {
			t.Fatalf("projected package %q has ecosystem %q, want NuGet: %+v", p.Name, p.Ecosystem, p)
		}
		keys[p.Key()] = struct{}{}
		if p.Name == "microsoft.extensions.hosting" && p.Version == "8.0.0" && p.Direct {
			direct = true
		}
		if p.PartialReason == "no_runtime_target" {
			// The rid-less (portable) assets target marks each node no_runtime_target; the projection
			// must carry that node-level reason onto the package.
			nodePartial = true
		}
	}
	if !direct {
		t.Fatalf("the fixture's real direct coordinate Microsoft.Extensions.Hosting@8.0.0 did not project as direct NuGet: %+v", sbom.Packages)
	}
	if !nodePartial {
		t.Fatalf("node-level partiality (no_runtime_target) was not carried onto any package: %+v", sbom.Packages)
	}

	// At least one real parent→child relationship, every endpoint Key()-joined to a projected package.
	// A dropped edge (endpoint not among Nodes) would leave zero relationships OR a dangling endpoint;
	// the shared projection drops dangling edges, so a resolver ID mismatch would surface as an empty
	// relationship set here.
	if len(sbom.Relationships) == 0 {
		t.Fatalf("the real transitive graph projected to zero relationships: %+v", sbom)
	}
	for _, rel := range sbom.Relationships {
		if _, ok := keys[rel.Parent]; !ok {
			t.Fatalf("relationship parent %q is not a projected package key (dropped/mismatched node ID)", rel.Parent)
		}
		if _, ok := keys[rel.Child]; !ok {
			t.Fatalf("relationship child %q is not a projected package key (dropped/mismatched node ID)", rel.Child)
		}
	}

	// report.Validate passes over the real projected SBOM: referentially valid, no dangling edge.
	rep := report.NewBuilder(report.Subject{Repo: "example.com/app", ResolvedCommit: "sha"}).
		AddPackages(sbom.Packages...).
		SetRelationships(sbom.Relationships).
		Build()
	if err := rep.Validate(); err != nil {
		t.Fatalf("the real projected SBOM failed report.Validate: %v", err)
	}

	// Non-vacuity: the Validate guard is load-bearing. Injecting a dangling edge into the very same
	// real SBOM must red — proving the pass above certifies referential integrity, not an unenforced
	// check. (Mirrors report.TestSBOMValidateRejectsDanglingRelationship, but on MY resolver's output.)
	broken := report.NewBuilder(report.Subject{Repo: "example.com/app", ResolvedCommit: "sha"}).
		AddPackages(sbom.Packages...).
		SetRelationships(append(append([]report.Relationship(nil), sbom.Relationships...),
			report.Relationship{Parent: sbom.Relationships[0].Parent, Child: "pkg:nuget/does.not.exist@9.9.9"})).
		Build()
	if err := broken.Validate(); err == nil {
		t.Fatal("Validate accepted a dangling edge appended to the real SBOM — the integrity check is not enforced")
	}
}
