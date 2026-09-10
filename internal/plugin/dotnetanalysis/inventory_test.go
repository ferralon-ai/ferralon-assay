package dotnetanalysis

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func resolveInv(t *testing.T, dir string) plugin.DependencyInventory {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("ResolveInventory: %v", err)
	}
	return inv
}

func reasonSet(p plugin.Partiality) map[string]bool {
	s := map[string]bool{}
	for _, r := range p.Reasons {
		s[r] = true
	}
	return s
}

// subset reports whether every reason in a is present in b.
func subset(a, b map[string]bool) bool {
	for r := range a {
		if !b[r] {
			return false
		}
	}
	return true
}

func nodeByPredicate(inv plugin.DependencyInventory, pred func(plugin.DependencyNode) bool) (plugin.DependencyNode, bool) {
	for _, n := range inv.Nodes {
		if pred(n) {
			return n, true
		}
	}
	return plugin.DependencyNode{}, false
}

func nodesForTFM(inv plugin.DependencyInventory, tfm string) []plugin.DependencyNode {
	var out []plugin.DependencyNode
	for _, n := range inv.Nodes {
		if n.Membership.Target == tfm {
			out = append(out, n)
		}
	}
	return out
}

// --- shared fixture bodies ---------------------------------------------------

// A single net8.0 project WITH restore output (tier 1). Serilog is direct with a transitive
// Serilog.Sinks.Console; the .csproj also declares Serilog so the delete-assets mutation still
// resolves a node from the lower tier.
const c1AssetsCsproj = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Serilog" Version="2.10.0" /></ItemGroup>
</Project>
`

const c1AssetsJSON = `{
  "version": 3,
  "targets": {
    "net8.0": {
      "Serilog/2.10.0": { "type": "package", "dependencies": { "Serilog.Sinks.Console": "4.0.0" } },
      "Serilog.Sinks.Console/4.0.0": { "type": "package" }
    }
  },
  "libraries": {
    "Serilog/2.10.0": { "type": "package", "path": "serilog/2.10.0", "sha512": "c2VyaWxvZ2hhc2g=" },
    "Serilog.Sinks.Console/4.0.0": { "type": "package", "path": "serilog.sinks.console/4.0.0", "sha512": "Y29uc29sZWhhc2g=" }
  },
  "projectFileDependencyGroups": {
    "net8.0": [ "Serilog >= 2.10.0" ]
  }
}
`

func c1AssetsTree() map[string]string {
	return map[string]string{
		"App.csproj":              c1AssetsCsproj,
		"obj/project.assets.json": c1AssetsJSON,
	}
}

// --- C1 ----------------------------------------------------------------------

// C1: ResolveInventory returns real data, every §4.1 bullet has a populated field OR a
// partiality reason naming it. Graph is Complete() on the tier-1 assets path.
func TestInventory_C1_AssetsCoverage(t *testing.T) {
	inv := resolveInv(t, writeTree(t, c1AssetsTree()))

	if !inv.Partiality.Complete {
		t.Fatalf("tier-1 assets resolution must be Complete(); got %+v", inv.Partiality)
	}
	if len(inv.Nodes) != 2 {
		t.Fatalf("want 2 nodes (Serilog + transitive Console); got %d", len(inv.Nodes))
	}
	if len(inv.Edges) != 1 {
		t.Fatalf("want 1 parent edge Serilog->Console; got %+v", inv.Edges)
	}

	serilog, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.Version == "2.10.0" })
	if !ok {
		t.Fatal("no Serilog@2.10.0 node")
	}
	// §4.1 bullet-by-bullet: a populated field or a partiality reason naming the bullet.
	if serilog.PURL != "pkg:nuget/serilog@2.10.0" {
		t.Errorf("PURL bullet: got %q", serilog.PURL)
	}
	if serilog.Version == "" {
		t.Error("version bullet unpopulated")
	}
	if !serilog.Direct {
		t.Error("direct/transitive bullet: Serilog must be Direct")
	}
	if serilog.Membership.Project == "" {
		t.Error("project membership bullet unpopulated")
	}
	if serilog.Membership.Target != "net8.0" {
		t.Errorf("TFM membership bullet: got %q", serilog.Membership.Target)
	}
	if serilog.Artifact.Identity == "" {
		t.Error("artifact identity bullet unpopulated")
	}
	if serilog.Artifact.Digest != "sha512:c2VyaWxvZ2hhc2g=" {
		t.Errorf("digest bullet: got %q", serilog.Artifact.Digest)
	}
	if serilog.Provenance.Manifest == "" {
		t.Error("manifest provenance bullet unpopulated")
	}
	if serilog.Provenance.Resolver == "" {
		t.Error("resolver provenance bullet unpopulated")
	}
	if serilog.Provenance.Runtime != "net8.0" {
		t.Errorf("runtime provenance bullet: got %q", serilog.Provenance.Runtime)
	}
	// RID bullet: absent → the naming partiality reason (the "OR" branch).
	if serilog.Provenance.Target == "" && !hasReason(serilog.Partiality, reasonNoRuntimeTarget) {
		t.Error("RID bullet: empty Provenance.Target must carry no_runtime_target")
	}

	// Transitive node is Direct=false — the load-bearing negative.
	console, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.Version == "4.0.0" })
	if !ok || console.Direct {
		t.Errorf("Serilog.Sinks.Console must be present and transitive; got %+v ok=%v", console, ok)
	}
}

// C1 negative control: a genuine zero-dependency project (assets present, empty libraries) is
// Complete() with zero nodes — and MUST classify differently from a resolver failure.
func TestInventory_C1_ZeroDepVsToolFailure(t *testing.T) {
	zerodep := resolveInv(t, writeTree(t, map[string]string{
		"App.csproj":              c1AssetsCsproj,
		"obj/project.assets.json": `{ "version": 3, "targets": { "net8.0": {} }, "libraries": {}, "projectFileDependencyGroups": { "net8.0": [] } }`,
	}))
	if !zerodep.Partiality.Complete || len(zerodep.Nodes) != 0 {
		t.Fatalf("genuine zero-dep must be Complete() with zero nodes; got %+v nodes=%d", zerodep.Partiality, len(zerodep.Nodes))
	}

	// A malformed .csproj with no assets/lock: tool_failure, NOT Complete, NOT no_manifest.
	toolfail := resolveInv(t, writeTree(t, map[string]string{
		"App.csproj": `<Project><ItemGroup></Project>`, // ItemGroup closed by </Project> → parse error
	}))
	if toolfail.Partiality.Complete {
		t.Fatal("a resolver failure must never be Complete()")
	}
	if !hasReason(toolfail.Partiality, plugin.PartialReasonToolFailure) {
		t.Fatalf("malformed manifest must carry tool_failure; got %v", toolfail.Partiality.Reasons)
	}
	if hasReason(toolfail.Partiality, plugin.PartialReasonNoManifest) {
		t.Fatal("a malformed manifest is not no_manifest — the two must stay distinct")
	}
	// The measurable distinction the negative control exists to enforce.
	if zerodep.Partiality.Complete == toolfail.Partiality.Complete {
		t.Fatal("zero-dep and tool-failure must be classified differently")
	}
}

// C1 mutation control: deleting project.assets.json flips Complete → Partial with a named
// reason (falls to the lower tier), not merely a smaller graph.
func TestInventory_C1_DeleteAssetsMutation(t *testing.T) {
	withAssets := resolveInv(t, writeTree(t, c1AssetsTree()))
	if !withAssets.Partiality.Complete {
		t.Fatal("precondition: with assets must be Complete()")
	}

	tree := c1AssetsTree()
	delete(tree, "obj/project.assets.json") // the mutation
	without := resolveInv(t, writeTree(t, tree))

	if without.Partiality.Complete {
		t.Fatal("deleting assets must flip Complete → Partial")
	}
	if !hasReason(without.Partiality, reasonNoResolverOutput) {
		t.Fatalf("the flip must name a reason (no_resolver_output); got %v", without.Partiality.Reasons)
	}
	if len(without.Nodes) == 0 {
		t.Fatal("the declared .csproj still resolves Serilog — the change is a named partiality, not an empty graph")
	}
}

// --- C3 ----------------------------------------------------------------------

// C3: one project presented four ways — assets / lockfile-only / declared-text-only / nothing —
// pairwise distinguishable, partiality monotonically non-decreasing, no-input NOT empty-Complete.
func TestInventory_C3_PrecedenceFourWays(t *testing.T) {
	assets := resolveInv(t, writeTree(t, map[string]string{
		"App.csproj":              c1AssetsCsproj,
		"obj/project.assets.json": c1AssetsJSON,
	}))
	lockOnly := resolveInv(t, writeTree(t, map[string]string{
		"App.csproj": c1AssetsCsproj,
		"packages.lock.json": `{ "version": 1, "dependencies": { "net8.0": {
			"Serilog": { "type": "Direct", "resolved": "2.10.0", "contentHash": "c2VyaWxvZ2hhc2g=" } } } }`,
	}))
	// declared text + CPM (version-less PackageReference resolved from Directory.Packages.props).
	textOnly := resolveInv(t, writeTree(t, map[string]string{
		"App.csproj": `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Serilog" /></ItemGroup>
</Project>`,
		"Directory.Packages.props": `<Project><ItemGroup><PackageVersion Include="Serilog" Version="2.10.0" /></ItemGroup></Project>`,
	}))
	nothing := resolveInv(t, writeTree(t, map[string]string{"Program.cs": "class P {}\n"}))

	// Pairwise distinguishable.
	got := []plugin.Partiality{assets.Partiality, lockOnly.Partiality, textOnly.Partiality, nothing.Partiality}
	for i := range got {
		for j := i + 1; j < len(got); j++ {
			if reflect.DeepEqual(got[i], got[j]) {
				t.Fatalf("presentations %d and %d are not distinguishable: %+v", i, j, got[i])
			}
		}
	}

	// Monotonic non-decreasing reason sets down the chain (the C3 invariant).
	sets := []map[string]bool{
		reasonSet(assets.Partiality),
		reasonSet(lockOnly.Partiality),
		reasonSet(textOnly.Partiality),
		reasonSet(nothing.Partiality),
	}
	for i := 0; i+1 < len(sets); i++ {
		if !subset(sets[i], sets[i+1]) {
			t.Fatalf("partiality not monotonic: tier %d reasons %v not ⊆ tier %d reasons %v", i, sets[i], i+1, sets[i+1])
		}
		if len(sets[i]) >= len(sets[i+1]) {
			t.Fatalf("partiality not strictly increasing: tier %d (%d) vs tier %d (%d)", i, len(sets[i]), i+1, len(sets[i+1]))
		}
	}

	// Tier 1 is Complete; the mutation control — the declared-text path must NOT be Complete().
	if !assets.Partiality.Complete {
		t.Error("assets tier must be Complete()")
	}
	if textOnly.Partiality.Complete {
		t.Fatal("declared-text path must be Partial — a Complete() here would go red (mutation control)")
	}

	// No-input is NOT an empty successful inventory (the §3.6 failure mode).
	if nothing.Partiality.Complete {
		t.Fatal("no-input must never be Complete()")
	}
	if len(nothing.Nodes) != 0 {
		t.Fatalf("no-input must have zero nodes; got %d", len(nothing.Nodes))
	}
	if !hasReason(nothing.Partiality, plugin.PartialReasonNoManifest) {
		t.Fatalf("no-input must name no_manifest; got %v", nothing.Partiality.Reasons)
	}
}

// --- C4 ----------------------------------------------------------------------

// C4: a multi-TFM project whose two TFMs resolve DIFFERENT versions of one package yields two
// distinct-version nodes with distinct TFM membership; query-by-TFM is isolated; a RID target is
// recorded and its absence elsewhere carries no_runtime_target.
func TestInventory_C4_MultiTFMAndRID(t *testing.T) {
	inv := resolveInv(t, writeTree(t, map[string]string{
		"App.csproj": `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFrameworks>net8.0;net472</TargetFrameworks></PropertyGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup>
</Project>`,
		"obj/project.assets.json": `{
  "version": 3,
  "targets": {
    "net8.0": { "Newtonsoft.Json/13.0.1": { "type": "package" } },
    "net472": { "Newtonsoft.Json/12.0.3": { "type": "package" } },
    "net8.0/linux-x64": { "Newtonsoft.Json/13.0.1": { "type": "package" } }
  },
  "libraries": {
    "Newtonsoft.Json/13.0.1": { "type": "package", "path": "newtonsoft.json/13.0.1", "sha512": "bmoxMw==" },
    "Newtonsoft.Json/12.0.3": { "type": "package", "path": "newtonsoft.json/12.0.3", "sha512": "bmoxMg==" }
  },
  "projectFileDependencyGroups": {
    "net8.0": [ "Newtonsoft.Json >= 13.0.1" ],
    "net472": [ "Newtonsoft.Json >= 12.0.3" ]
  }
}`,
	}))

	if !inv.Partiality.Complete {
		t.Fatalf("assets tier must be Complete(); got %+v", inv.Partiality)
	}

	net8 := nodesForTFM(inv, "net8.0")
	net472 := nodesForTFM(inv, "net472")
	if len(net472) != 1 {
		t.Fatalf("net472 must resolve exactly one node; got %d", len(net472))
	}
	if net472[0].Version != "12.0.3" {
		t.Errorf("net472 must resolve 12.0.3 (distinct version); got %q", net472[0].Version)
	}
	// Query-by-TFM isolation: net472's set carries no net8.0 version, and vice versa.
	for _, n := range net472 {
		if n.Version == "13.0.1" {
			t.Error("net472 query leaked the net8.0 version 13.0.1 (flattening)")
		}
	}
	var saw8, sawFlattenAcross bool
	for _, n := range net8 {
		if n.Version == "13.0.1" {
			saw8 = true
		}
		if n.Version == "12.0.3" {
			sawFlattenAcross = true
		}
	}
	if !saw8 {
		t.Error("net8.0 must resolve 13.0.1")
	}
	if sawFlattenAcross {
		t.Error("net8.0 query leaked the net472 version 12.0.3 (flattening)")
	}

	// Two distinct-version nodes exist across the TFMs (the shape that detects flattening).
	if net472[0].Version == net8[0].Version {
		t.Fatal("the two TFMs must carry distinct versions of the same package")
	}

	// RID: the linux-x64 target is recorded on the node.
	rid, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.Provenance.Target == "linux-x64" })
	if !ok {
		t.Fatal("the net8.0/linux-x64 RID selection must be recorded on a node")
	}
	if !rid.Partiality.Complete {
		t.Errorf("a RID-specific node must not carry no_runtime_target; got %v", rid.Partiality.Reasons)
	}
	// RID absence elsewhere carries no_runtime_target.
	portable, ok := nodeByPredicate(inv, func(n plugin.DependencyNode) bool { return n.Membership.Target == "net472" })
	if !ok || !hasReason(portable.Partiality, reasonNoRuntimeTarget) {
		t.Errorf("a portable (no-RID) node must carry no_runtime_target; got %+v ok=%v", portable.Partiality, ok)
	}
}

// --- C7 ----------------------------------------------------------------------

// C7: every node forms a (PURL, version, digest, TFM, RID) acquisition key whose every
// component is non-empty OR carries a partiality reason (node- or graph-level) naming the miss.
func TestInventory_C7_AcquisitionKey(t *testing.T) {
	check := func(t *testing.T, inv plugin.DependencyInventory) {
		t.Helper()
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
	}

	// Tier 1: digest present, RID absent → per-node no_runtime_target.
	t.Run("assets", func(t *testing.T) {
		check(t, resolveInv(t, writeTree(t, c1AssetsTree())))
	})
	// Tier 3: digest absent → the graph names no_lockfile.
	t.Run("declared", func(t *testing.T) {
		inv := resolveInv(t, writeTree(t, map[string]string{"App.csproj": c1AssetsCsproj}))
		if len(inv.Nodes) == 0 {
			t.Fatal("declared tier must resolve the Serilog node")
		}
		check(t, inv)
	})
}

// --- C5(c) -------------------------------------------------------------------

// C5(c): the hermetic no-toolchain guard — ResolveInventory over a fixture with PATH emptied
// returns byte-identical output. If resolution degraded, something was shelling out to a
// toolchain that is not there.
func TestInventory_C5_HermeticEmptyPATH(t *testing.T) {
	dir := writeTree(t, c1AssetsTree())
	normal := resolveInv(t, dir)

	t.Setenv("PATH", "")
	hermetic := resolveInv(t, dir)

	if !reflect.DeepEqual(normal, hermetic) {
		t.Fatalf("result changed with PATH emptied — a toolchain was being executed:\n normal=%+v\n hermetic=%+v", normal, hermetic)
	}
	if !hermetic.Partiality.Complete || len(hermetic.Nodes) != 2 {
		t.Fatalf("hermetic run must still fully resolve from checkout files; got %+v nodes=%d", hermetic.Partiality, len(hermetic.Nodes))
	}
}
