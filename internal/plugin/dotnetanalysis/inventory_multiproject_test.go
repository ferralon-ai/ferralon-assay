package dotnetanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- multi-project .sln fixture ----------------------------------------------
//
// A two-project solution: App (net8.0, package Serilog) has a ProjectReference to Lib (net8.0,
// package Newtonsoft.Json). Each project carries its OWN restore output under its own obj/, so a
// correct walker attributes each package to its owning project and never bleeds one project's
// packages into the other. The .sln also declares a solution folder to prove folder entries are
// filtered out of the member list.

const mpSolution = `Microsoft Visual Studio Solution File, Format Version 12.00
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", "src\App\App.csproj", "{11111111-1111-1111-1111-111111111111}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Lib", "src\Lib\Lib.csproj", "{22222222-2222-2222-2222-222222222222}"
EndProject
Project("{2150E333-8FDC-42A3-9474-1A3956D46DE4}") = "solution-items", "solution-items", "{33333333-3333-3333-3333-333333333333}"
EndProject
Global
EndGlobal
`

const mpAppCsproj = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Serilog" Version="2.10.0" /></ItemGroup>
  <ItemGroup><ProjectReference Include="..\Lib\Lib.csproj" /></ItemGroup>
</Project>
`

// App's restore output. Note the Lib/1.0.0 entry of type "project": the core parser skips it, so a
// ProjectReference never becomes a phantom NuGet node.
const mpAppAssets = `{
  "version": 3,
  "targets": {
    "net8.0": {
      "Serilog/2.10.0": { "type": "package" },
      "Lib/1.0.0": { "type": "project" }
    }
  },
  "libraries": {
    "Serilog/2.10.0": { "type": "package", "path": "serilog/2.10.0", "sha512": "c2VyaWxvZ2hhc2g=" },
    "Lib/1.0.0": { "type": "project", "path": "../Lib/Lib.csproj" }
  },
  "projectFileDependencyGroups": { "net8.0": [ "Serilog >= 2.10.0" ] }
}
`

const mpLibCsproj = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup>
</Project>
`

const mpLibAssets = `{
  "version": 3,
  "targets": { "net8.0": { "Newtonsoft.Json/13.0.1": { "type": "package" } } },
  "libraries": { "Newtonsoft.Json/13.0.1": { "type": "package", "path": "newtonsoft.json/13.0.1", "sha512": "bmoxMw==" } },
  "projectFileDependencyGroups": { "net8.0": [ "Newtonsoft.Json >= 13.0.1" ] }
}
`

// mpTree builds the on-disk solution. Callers mutate the returned map for the negative controls.
func mpTree() map[string]string {
	return map[string]string{
		"App.sln":                         mpSolution,
		"src/App/App.csproj":              mpAppCsproj,
		"src/App/obj/project.assets.json": mpAppAssets,
		"src/Lib/Lib.csproj":              mpLibCsproj,
		"src/Lib/obj/project.assets.json": mpLibAssets,
	}
}

const (
	appProj = "src/App/App.csproj"
	libProj = "src/Lib/Lib.csproj"
)

// --- membership + ProjectReference-not-a-node --------------------------------

// The core multi-project assertion set (fixture requirements a–d): per-project membership, the
// ProjectReference as an edge (never a phantom NuGet node), workspace membership, and no
// cross-project mis-attribution.
func TestInventory_Multiproject_Membership(t *testing.T) {
	inv := resolveInv(t, writeTree(t, mpTree()))

	if !inv.Partiality.Complete {
		t.Fatalf("both projects resolve from assets — workspace must be Complete(); got %+v", inv.Partiality)
	}

	// (b) The ProjectReference produced NO node: exactly the two real packages exist, and neither
	// PURL is a project. A phantom "Lib" node would make this 3 nodes / carry a lib PURL.
	if len(inv.Nodes) != 2 {
		t.Fatalf("want exactly 2 package nodes (Serilog, Newtonsoft.Json); got %d: %+v", len(inv.Nodes), inv.Nodes)
	}
	serilog, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == "pkg:nuget/serilog@2.10.0" })
	if !ok {
		t.Fatal("no Serilog node")
	}
	newton, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == "pkg:nuget/newtonsoft.json@13.0.1" })
	if !ok {
		t.Fatal("no Newtonsoft.Json node")
	}

	// (a) per-project Membership.Project — specific expected owning project, not mere presence.
	if serilog.Membership.Project != appProj {
		t.Errorf("Serilog must belong to %s; got %q", appProj, serilog.Membership.Project)
	}
	if newton.Membership.Project != libProj {
		t.Errorf("Newtonsoft.Json must belong to %s; got %q", libProj, newton.Membership.Project)
	}
	// (d) a node in Lib is not mis-attributed to App.
	if newton.Membership.Project == appProj {
		t.Fatal("Newtonsoft.Json (Lib) mis-attributed to App — cross-project bleed")
	}

	// (c) Membership.Workspace == the solution for every node.
	for _, n := range inv.Nodes {
		if n.Membership.Workspace != "App.sln" {
			t.Errorf("node %s: Workspace must be App.sln; got %q", n.ID, n.Membership.Workspace)
		}
	}

	// (b, edge half) the ProjectReference App->Lib is an inter-project edge with project markers,
	// distinct from any package Node.ID.
	wantEdge := plugin.DependencyEdge{Parent: "project::" + appProj, Child: "project::" + libProj}
	var sawProjEdge bool
	for _, e := range inv.Edges {
		if e == wantEdge {
			sawProjEdge = true
		}
	}
	if !sawProjEdge {
		t.Fatalf("want inter-project edge %+v; got edges %+v", wantEdge, inv.Edges)
	}
}

// --- C1 multi-project slice --------------------------------------------------

// C1 (§4.1) membership populated with SPECIFIC expected values across projects — the vacuous-field
// trap is avoided by asserting the exact (Project, Workspace, Target) triple per owning project.
func TestInventory_C1_Multiproject_Membership(t *testing.T) {
	inv := resolveInv(t, writeTree(t, mpTree()))

	want := map[string]plugin.DependencyMembership{
		"pkg:nuget/serilog@2.10.0":         {Project: appProj, Workspace: "App.sln", Target: "net8.0"},
		"pkg:nuget/newtonsoft.json@13.0.1": {Project: libProj, Workspace: "App.sln", Target: "net8.0"},
	}
	for purl, wm := range want {
		n, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == purl })
		if !ok {
			t.Fatalf("no node for %s", purl)
		}
		if n.Membership != wm {
			t.Errorf("%s membership: want %+v; got %+v", purl, wm, n.Membership)
		}
	}
}

// --- C7 multi-project slice --------------------------------------------------

// C7: the (PURL, version, digest, TFM, RID) acquisition key holds per node across projects, or a
// named partiality reason accounts for a missing component.
func TestInventory_C7_Multiproject_AcquisitionKey(t *testing.T) {
	inv := resolveInv(t, writeTree(t, mpTree()))
	graph := inv.Partiality
	for _, n := range inv.Nodes {
		named := func(reason string) bool { return hasReason(n.Partiality, reason) || hasReason(graph, reason) }
		if n.PURL == "" {
			t.Errorf("node %s: PURL must never be empty", n.ID)
		}
		if n.Version == "" && !named(reasonUnresolvedVersionRange) {
			t.Errorf("node %s: empty version needs unresolved_version_range", n.ID)
		}
		if n.Artifact.Digest == "" && !(named(reasonNoLockfile) || named(reasonNoResolverOutput)) {
			t.Errorf("node %s: empty digest needs no_lockfile/no_resolver_output", n.ID)
		}
		if n.Membership.Target == "" {
			t.Errorf("node %s: TFM must be recorded", n.ID)
		}
		if n.Provenance.Target == "" && !named(reasonNoRuntimeTarget) {
			t.Errorf("node %s: empty RID needs no_runtime_target", n.ID)
		}
	}
	// Concretely: both nodes carry a real assets digest across the two projects.
	for _, purl := range []string{"pkg:nuget/serilog@2.10.0", "pkg:nuget/newtonsoft.json@13.0.1"} {
		n, _ := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == purl })
		if n.Artifact.Digest == "" {
			t.Errorf("%s: assets tier must carry a sha512 digest", purl)
		}
	}
}

// --- negative / mutation controls --------------------------------------------

// A project that CANNOT resolve → partial-with-named-reason, distinct from a genuinely-empty
// project; and the App project's nodes are retained (never a silent drop of the whole workspace).
func TestInventory_Multiproject_UnresolvableVsEmpty(t *testing.T) {
	// Case 1 — Lib malformed: workspace is Partial(tool_failure) but App's Serilog survives.
	broken := mpTree()
	delete(broken, "src/Lib/obj/project.assets.json")               // drop restore output
	broken["src/Lib/Lib.csproj"] = `<Project><ItemGroup></Project>` // unparseable → tool_failure
	binv := resolveInv(t, writeTree(t, broken))

	if binv.Partiality.Complete {
		t.Fatal("a project that fails to resolve must make the workspace Partial")
	}
	if !hasReason(binv.Partiality, plugin.PartialReasonToolFailure) {
		t.Fatalf("the failing project must name tool_failure; got %v", binv.Partiality.Reasons)
	}
	if _, ok := nodeByPredicate(binv, func(n plugin.DependencyNode) bool { return n.Membership.Project == appProj }); !ok {
		t.Fatal("App's nodes must be retained — an unresolvable sibling is declared partiality, not a whole-workspace drop")
	}

	// Case 2 — Lib genuinely empty: assets present, zero libraries → Complete, only App's node.
	empty := mpTree()
	empty["src/Lib/obj/project.assets.json"] = `{ "version": 3, "targets": { "net8.0": {} }, "libraries": {}, "projectFileDependencyGroups": { "net8.0": [] } }`
	empty["src/Lib/Lib.csproj"] = `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>`
	einv := resolveInv(t, writeTree(t, empty))

	if !einv.Partiality.Complete {
		t.Fatalf("a genuinely-empty project must keep the workspace Complete(); got %v", einv.Partiality.Reasons)
	}
	// The measurable distinction: unresolvable ≠ empty.
	if binv.Partiality.Complete == einv.Partiality.Complete {
		t.Fatal("unresolvable project and genuinely-empty project must classify differently")
	}
}

// Membership is DERIVED from the walk, not hard-coded: swap the two projects' package manifests and
// the attribution follows the packages to their new owning project.
func TestInventory_Multiproject_MembershipNotHardcoded(t *testing.T) {
	swapped := mpTree()
	// App now carries Newtonsoft.Json; Lib now carries Serilog (manifests + restore output swapped).
	swapped["src/App/App.csproj"] = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup>
  <ItemGroup><ProjectReference Include="..\Lib\Lib.csproj" /></ItemGroup>
</Project>`
	swapped["src/App/obj/project.assets.json"] = mpLibAssets
	swapped["src/Lib/Lib.csproj"] = mpLibCsprojWithSerilog
	swapped["src/Lib/obj/project.assets.json"] = mpAppAssetsSerilogOnly

	inv := resolveInv(t, writeTree(t, swapped))

	serilog, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == "pkg:nuget/serilog@2.10.0" })
	if !ok {
		t.Fatal("no Serilog node after swap")
	}
	if serilog.Membership.Project != libProj {
		t.Errorf("after swap Serilog must belong to %s; got %q (attribution is hard-coded, not derived)", libProj, serilog.Membership.Project)
	}
	newton, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == "pkg:nuget/newtonsoft.json@13.0.1" })
	if !ok {
		t.Fatal("no Newtonsoft.Json node after swap")
	}
	if newton.Membership.Project != appProj {
		t.Errorf("after swap Newtonsoft.Json must belong to %s; got %q", appProj, newton.Membership.Project)
	}
}

// Swap-fixture bodies: Lib carrying Serilog, and a Serilog-only assets file (no ProjectReference
// project entry, since post-swap Lib is the leaf).
const mpLibCsprojWithSerilog = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Serilog" Version="2.10.0" /></ItemGroup>
</Project>
`

const mpAppAssetsSerilogOnly = `{
  "version": 3,
  "targets": { "net8.0": { "Serilog/2.10.0": { "type": "package" } } },
  "libraries": { "Serilog/2.10.0": { "type": "package", "path": "serilog/2.10.0", "sha512": "c2VyaWxvZ2hhc2g=" } },
  "projectFileDependencyGroups": { "net8.0": [ "Serilog >= 2.10.0" ] }
}
`

// --- root Central Package Management (Directory.Packages.props) ---------------
//
// The STANDARD CPM layout: a solution-ROOT Directory.Packages.props pins every version, and each
// subdir project references packages WITHOUT a Version (MSBuild walks up from the project and imports
// the nearest props). No restore output, so resolution falls to the declared-text tier where the CPM
// merge happens — the tier that must discover the ROOT props, an ANCESTOR of each project dir, not
// just a project-local one. There is no per-project Directory.Packages.props here, so a project-dir-only
// lookup resolves NOTHING; a correct upward walk to the solution root resolves both.

const cpmRootSolution = `Microsoft Visual Studio Solution File, Format Version 12.00
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", "src\App\App.csproj", "{11111111-1111-1111-1111-111111111111}"
EndProject
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Lib", "src\Lib\Lib.csproj", "{22222222-2222-2222-2222-222222222222}"
EndProject
Global
EndGlobal
`

// Root props: ManagePackageVersionsCentrally + the two managed versions. This is the ONLY place the
// versions appear — the csprojs below are version-less.
const cpmRootProps = `<Project>
  <PropertyGroup><ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Serilog" Version="2.10.0" />
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>
`

const cpmAppCsproj = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Serilog" /></ItemGroup>
</Project>
`

const cpmLibCsproj = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" /></ItemGroup>
</Project>
`

func cpmRootTree() map[string]string {
	return map[string]string{
		"CpmRoot.sln":              cpmRootSolution,
		"Directory.Packages.props": cpmRootProps,
		"src/App/App.csproj":       cpmAppCsproj,
		"src/Lib/Lib.csproj":       cpmLibCsproj,
	}
}

// A solution-root Directory.Packages.props resolves the versions for subdir projects' version-less
// PackageReferences (scope item 3, standard CPM layout). Regression guard for the project-dir-only
// discovery gap: without the upward walk to the solution root, these versions would be UNRESOLVED.
func TestInventory_Multiproject_RootCPM_ResolvesSubdirVersions(t *testing.T) {
	inv := resolveInv(t, writeTree(t, cpmRootTree()))

	// Declared-text tier (no restore output), so the workspace is Partial — never Complete().
	if inv.Partiality.Complete {
		t.Fatal("declared-text CPM resolution must be Partial, not Complete()")
	}

	want := map[string]struct {
		version string
		project string
	}{
		"serilog":         {"2.10.0", appProj},
		"newtonsoft.json": {"13.0.1", libProj},
	}
	for id, w := range want {
		purl := "pkg:nuget/" + id + "@" + w.version
		n, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == purl })
		if !ok {
			t.Fatalf("%s: version %s from the ROOT Directory.Packages.props did not resolve for the subdir project (project-dir-only lookup missed the ancestor props)", id, w.version)
		}
		if n.Version != w.version {
			t.Errorf("%s: want version %q from root CPM; got %q", id, w.version, n.Version)
		}
		if n.Membership.Project != w.project {
			t.Errorf("%s: want owning project %q; got %q", id, w.project, n.Membership.Project)
		}
		// A resolved CPM version must NOT carry unresolved_version_range.
		if hasReason(n.Partiality, reasonUnresolvedVersionRange) {
			t.Errorf("%s: resolved from root CPM but still flagged unresolved_version_range", id)
		}
	}
}

// Mutation control: DELETE the root Directory.Packages.props → the subdir projects' version-less
// references drop to unresolved (empty version, unresolved_version_range), NEVER a guessed version.
func TestInventory_Multiproject_RootCPM_Mutation_MissingProps(t *testing.T) {
	tree := cpmRootTree()
	delete(tree, "Directory.Packages.props") // remove the only source of the managed versions
	inv := resolveInv(t, writeTree(t, tree))

	for _, id := range []string{"serilog", "newtonsoft.json"} {
		// The guessed version must NOT appear as a node.
		guessed := map[string]string{"serilog": "pkg:nuget/serilog@2.10.0", "newtonsoft.json": "pkg:nuget/newtonsoft.json@13.0.1"}[id]
		if _, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == guessed }); ok {
			t.Fatalf("%s: version was GUESSED after the root props was deleted — soundness failure", id)
		}
		// The reference still surfaces, version-less, named unresolved_version_range.
		unpinned := "pkg:nuget/" + id
		n, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.PURL == unpinned })
		if !ok {
			t.Fatalf("%s: the version-less reference must still surface as an unresolved node", id)
		}
		if n.Version != "" {
			t.Errorf("%s: version must be empty with no props to pin it; got %q", id, n.Version)
		}
		if !hasReason(n.Partiality, reasonUnresolvedVersionRange) {
			t.Errorf("%s: an unpinnable CPM reference must name unresolved_version_range", id)
		}
	}
}
