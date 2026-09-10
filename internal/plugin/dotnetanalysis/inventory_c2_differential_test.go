package dotnetanalysis

// C2 real-differential test: grade ResolveInventory against captures produced OFFLINE by the
// native NuGet resolver (`dotnet list package --include-transitive --format json`). The captures
// are COLD FIXTURES — this test only READS them; it never executes dotnet/MSBuild/NuGet/restore.
//
// Grading scope: native.json is FLAT — top-level + transitive packages per framework, with NO
// parent edges. So C2 grades the (id, resolvedVersion, framework, direct) multiset only; parent
// edges are NOT graded here (they stay covered by the assets-based edge tests in
// inventory_test.go, e.g. C1). direct=true for topLevelPackages, false for transitivePackages.
//
// Per framework the comparison is set-valued: native lists each package once per framework, so for
// the RID capture (whose assets carry both `net8.0` and `net8.0/linux-x64` scopes) the resolver's
// per-TFM/RID nodes are UNIONED into their bare TFM bucket before comparison.

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- native.json oracle schema ----------------------------------------------

type nativePkg struct {
	ID              string `json:"id"`
	ResolvedVersion string `json:"resolvedVersion"`
}

type nativeFramework struct {
	Framework          string      `json:"framework"`
	TopLevelPackages   []nativePkg `json:"topLevelPackages"`
	TransitivePackages []nativePkg `json:"transitivePackages"`
}

type nativeProject struct {
	Path       string            `json:"path"`
	Frameworks []nativeFramework `json:"frameworks"`
}

type nativeReport struct {
	Projects []nativeProject `json:"projects"`
}

// pkgTuple is one graded package instance within a (project, framework) bucket.
type pkgTuple struct {
	id      string // lower-cased NuGet id
	version string // resolved version
	direct  bool
}

func (p pkgTuple) String() string {
	kind := "transitive"
	if p.direct {
		kind = "direct"
	}
	return p.id + "@" + p.version + " (" + kind + ")"
}

// bucketKey identifies a (project, bare-TFM) comparison bucket. Project is keyed by the .csproj
// basename, which is unique across every capture (App.csproj, Lib.csproj, MultiTfm.csproj).
type bucketKey struct {
	project   string // filepath.Base of the .csproj
	framework string // bare TFM, RID stripped
}

// --- BuildDir composition ----------------------------------------------------

const captureRoot = "testdata/inventory/capture"

// copyDir recursively copies every file under src into dst, preserving the relative layout.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
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
		t.Fatalf("copyDir %s -> %s: %v", src, dst, err)
	}
}

// composeBuildDir lays a capture out into a fresh BuildDir the resolver can consume: proj/* and
// assets/* are overlaid preserving structure (so obj/project.assets.json lands beside each
// .csproj), and a sibling packages.lock.json (present for the lockfile + cpm captures) is placed at
// the BuildDir root — mirroring the capture's own placement.
func composeBuildDir(t *testing.T, capture string) string {
	t.Helper()
	base := filepath.Join(captureRoot, capture)
	dst := t.TempDir()
	copyDir(t, filepath.Join(base, "proj"), dst)
	copyDir(t, filepath.Join(base, "assets"), dst)
	if lock := filepath.Join(base, "packages.lock.json"); fileExists(lock) {
		data, err := os.ReadFile(lock)
		if err != nil {
			t.Fatalf("read %s: %v", lock, err)
		}
		if err := os.WriteFile(filepath.Join(dst, "packages.lock.json"), data, 0o644); err != nil {
			t.Fatalf("write packages.lock.json: %v", err)
		}
	}
	return dst
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// --- side builders -----------------------------------------------------------

// nativeBuckets parses a capture's native.json into per-(project, framework) tuple multisets.
func nativeBuckets(t *testing.T, capture string) map[bucketKey]map[pkgTuple]int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(captureRoot, capture, "native.json"))
	if err != nil {
		t.Fatalf("read native.json: %v", err)
	}
	var rep nativeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("parse native.json: %v", err)
	}
	out := map[bucketKey]map[pkgTuple]int{}
	for _, proj := range rep.Projects {
		pbase := filepath.Base(proj.Path)
		for _, fw := range proj.Frameworks {
			key := bucketKey{project: pbase, framework: fw.Framework}
			set := out[key]
			if set == nil {
				set = map[pkgTuple]int{}
				out[key] = set
			}
			for _, p := range fw.TopLevelPackages {
				set[pkgTuple{id: strings.ToLower(p.ID), version: p.ResolvedVersion, direct: true}]++
			}
			for _, p := range fw.TransitivePackages {
				set[pkgTuple{id: strings.ToLower(p.ID), version: p.ResolvedVersion, direct: false}]++
			}
		}
	}
	return out
}

// invBuckets projects the resolver's inventory into the same per-(project, bare-TFM) buckets.
// Because native lists each package once per framework, buckets are SETS: RID-scoped nodes fold
// into their bare TFM bucket (the union), so a value of >1 would signal a genuine intra-framework
// version collision, which the comparison surfaces.
func invBuckets(t *testing.T, inv plugin.DependencyInventory) map[bucketKey]map[pkgTuple]int {
	t.Helper()
	out := map[bucketKey]map[pkgTuple]int{}
	for _, n := range inv.Nodes {
		project, scope := parseNodeID(t, n.ID)
		tfm, _ := splitTargetKey(scope)
		key := bucketKey{project: filepath.Base(project), framework: tfm}
		set := out[key]
		if set == nil {
			set = map[pkgTuple]int{}
			out[key] = set
		}
		set[pkgTuple{id: purlID(n.PURL), version: n.Version, direct: n.Direct}] = 1 // set semantics
	}
	return out
}

// parseNodeID splits the stable node key "<project>|<TFM>[/<RID>]|<PURL>" (makeNodeID) — none of
// project path, scope, or PURL contains '|'.
func parseNodeID(t *testing.T, id string) (project, scope string) {
	t.Helper()
	parts := strings.Split(id, "|")
	if len(parts) != 3 {
		t.Fatalf("node ID %q is not <project>|<scope>|<purl>", id)
	}
	return parts[0], parts[1]
}

// purlID recovers the lower-cased id from "pkg:nuget/<lower-id>@<version>".
func purlID(purl string) string {
	s := strings.TrimPrefix(purl, "pkg:nuget/")
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	return s
}

// --- differential assertion --------------------------------------------------

// assertBucketsEqual compares inventory vs native per bucket and, on mismatch, prints the symmetric
// difference (missing = in native, absent from inventory; extra = in inventory, absent from native).
func assertBucketsEqual(t *testing.T, want, got map[bucketKey]map[pkgTuple]int) {
	t.Helper()
	keys := map[bucketKey]bool{}
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	for _, k := range sortedBucketKeys(keys) {
		w, g := want[k], got[k]
		if w == nil {
			t.Errorf("[%s | %s] resolver produced a bucket native does not have (%d entries): %s",
				k.project, k.framework, len(g), formatSet(g))
			continue
		}
		if g == nil {
			t.Errorf("[%s | %s] native has a bucket the resolver omitted (%d entries): %s",
				k.project, k.framework, len(w), formatSet(w))
			continue
		}
		var missing, extra []string
		for p, wc := range w {
			if g[p] != wc {
				missing = append(missing, p.String())
			}
		}
		for p, gc := range g {
			if w[p] != gc {
				extra = append(extra, p.String())
			}
		}
		if len(missing) > 0 || len(extra) > 0 {
			sort.Strings(missing)
			sort.Strings(extra)
			t.Errorf("[%s | %s] differential mismatch:\n  missing (native, not in inventory): %v\n  extra (inventory, not in native): %v",
				k.project, k.framework, missing, extra)
		}
	}
}

func sortedBucketKeys(m map[bucketKey]bool) []bucketKey {
	out := make([]bucketKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].project != out[j].project {
			return out[i].project < out[j].project
		}
		return out[i].framework < out[j].framework
	})
	return out
}

func formatSet(s map[pkgTuple]int) string {
	var xs []string
	for p := range s {
		xs = append(xs, p.String())
	}
	sort.Strings(xs)
	return "[" + strings.Join(xs, ", ") + "]"
}

// tuplesFor returns the flat set of tuples the resolver produced for a given (project-basename,
// bare-TFM), for the per-capture must-exhibit assertions.
func tuplesFor(inv plugin.DependencyInventory, t *testing.T, projectBase, tfm string) map[pkgTuple]bool {
	out := map[pkgTuple]bool{}
	for _, n := range inv.Nodes {
		project, scope := parseNodeID(t, n.ID)
		nt, _ := splitTargetKey(scope)
		if filepath.Base(project) == projectBase && nt == tfm {
			out[pkgTuple{id: purlID(n.PURL), version: n.Version, direct: n.Direct}] = true
		}
	}
	return out
}

// --- the C2 table ------------------------------------------------------------

func TestInventory_C2_NativeDifferential(t *testing.T) {
	cases := []struct {
		name    string
		exhibit func(t *testing.T, buildDir string, inv plugin.DependencyInventory)
	}{
		{
			name: "single-transitive",
			exhibit: func(t *testing.T, _ string, inv plugin.DependencyInventory) {
				// One direct host package + a transitive fan-out, all net8.0.
				got := tuplesFor(inv, t, "App.csproj", "net8.0")
				if !got[pkgTuple{"microsoft.extensions.hosting", "8.0.0", true}] {
					t.Error("single-transitive: Microsoft.Extensions.Hosting@8.0.0 must be direct")
				}
			},
		},
		{
			name: "diamond",
			exhibit: func(t *testing.T, _ string, inv plugin.DependencyInventory) {
				// Diamond unification: two direct Azure packages converge on ONE Azure.Core@1.36.0.
				var core []plugin.DependencyNode
				for _, n := range inv.Nodes {
					if n.PURL == "pkg:nuget/azure.core@1.36.0" {
						core = append(core, n)
					}
				}
				if len(core) != 1 {
					t.Fatalf("diamond: want exactly one azure.core@1.36.0 node (unification); got %d", len(core))
				}
				if core[0].Direct {
					t.Error("diamond: azure.core must be transitive (Direct=false)")
				}
				got := tuplesFor(inv, t, "App.csproj", "net8.0")
				if !got[pkgTuple{"azure.identity", "1.10.4", true}] {
					t.Error("diamond: Azure.Identity@1.10.4 must be direct")
				}
				if !got[pkgTuple{"azure.storage.blobs", "12.19.1", true}] {
					t.Error("diamond: Azure.Storage.Blobs@12.19.1 must be direct")
				}
			},
		},
		{
			name: "multi-tfm",
			exhibit: func(t *testing.T, _ string, inv plugin.DependencyInventory) {
				// Per-TFM isolation: the two frameworks carry DIFFERENT package sets.
				net8 := tuplesFor(inv, t, "MultiTfm.csproj", "net8.0")
				netstd := tuplesFor(inv, t, "MultiTfm.csproj", "netstandard2.0")
				if len(net8) == 0 || len(netstd) == 0 {
					t.Fatalf("multi-tfm: both TFMs must resolve; net8.0=%d netstandard2.0=%d", len(net8), len(netstd))
				}
				if setsEqual(net8, netstd) {
					t.Error("multi-tfm: net8.0 and netstandard2.0 sets must DIFFER (no cross-TFM flattening)")
				}
				if !net8[pkgTuple{"system.text.json", "8.0.0", true}] {
					t.Error("multi-tfm net8.0: System.Text.Json@8.0.0 must be direct")
				}
				if !net8[pkgTuple{"system.text.encodings.web", "8.0.0", false}] {
					t.Error("multi-tfm net8.0: System.Text.Encodings.Web@8.0.0 must be transitive")
				}
				if !netstd[pkgTuple{"netstandard.library", "2.0.3", true}] {
					t.Error("multi-tfm netstandard2.0: NETStandard.Library@2.0.3 must be direct")
				}
				if len(netstd) <= len(net8) {
					t.Errorf("multi-tfm: netstandard2.0 polyfill set (%d) should exceed net8.0 (%d)", len(netstd), len(net8))
				}
			},
		},
		{
			name: "lockfile",
			exhibit: func(t *testing.T, buildDir string, inv plugin.DependencyInventory) {
				// The lockfile fixture must actually be present in the BuildDir. NOTE: assets take
				// precedence over the lockfile when both are present (they are here, per the copy
				// recipe), so this capture verifies the resolved (id,version) set matches native with
				// the lockfile in place — not the lockfile-only precedence arm in isolation.
				if !fileExists(filepath.Join(buildDir, "packages.lock.json")) {
					t.Error("lockfile: packages.lock.json must be present in the BuildDir")
				}
				got := tuplesFor(inv, t, "App.csproj", "net8.0")
				if !got[pkgTuple{"serilog.aspnetcore", "8.0.1", true}] {
					t.Error("lockfile: Serilog.AspNetCore@8.0.1 must be direct")
				}
			},
		},
		{
			name: "cpm-solution",
			exhibit: func(t *testing.T, _ string, inv plugin.DependencyInventory) {
				// Two projects resolve independently; CPM version (Serilog 3.1.1) flows from the ROOT
				// Directory.Packages.props into both subdir projects.
				app := tuplesFor(inv, t, "App.csproj", "net8.0")
				lib := tuplesFor(inv, t, "Lib.csproj", "net8.0")
				if !app[pkgTuple{"serilog", "3.1.1", true}] {
					t.Error("cpm-solution App: Serilog@3.1.1 must resolve direct from CPM props")
				}
				if !lib[pkgTuple{"serilog", "3.1.1", true}] {
					t.Error("cpm-solution Lib: Serilog@3.1.1 must resolve direct from CPM props")
				}
				// The App->Lib ProjectReference is an inter-project edge, NOT a NuGet node.
				for _, n := range inv.Nodes {
					if strings.HasPrefix(n.PURL, "pkg:nuget/lib@") {
						t.Errorf("cpm-solution: ProjectReference Lib must not become a NuGet node; got %q", n.ID)
					}
				}
				var interProject bool
				for _, e := range inv.Edges {
					if strings.HasPrefix(e.Parent, "project::") && strings.HasPrefix(e.Child, "project::") &&
						strings.Contains(e.Parent, "App") && strings.Contains(e.Child, "Lib") {
						interProject = true
					}
				}
				if !interProject {
					t.Errorf("cpm-solution: App->Lib must yield a project:: inter-project edge; edges=%+v", inv.Edges)
				}
			},
		},
		{
			name: "rid-selfcontained",
			exhibit: func(t *testing.T, _ string, inv plugin.DependencyInventory) {
				// native.json is per-framework (no RID split). The resolver emits per-TFM/RID nodes;
				// their UNION into the bare net8.0 bucket must equal native's framework set (asserted
				// by the full-set equality above). Here we confirm a RID scope was actually produced.
				var sawRID bool
				for _, n := range inv.Nodes {
					_, scope := parseNodeID(t, n.ID)
					if _, rid := splitTargetKey(scope); rid == "linux-x64" {
						sawRID = true
					}
				}
				if !sawRID {
					t.Error("rid-selfcontained: expected at least one net8.0/linux-x64 RID-scoped node")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buildDir := composeBuildDir(t, tc.name)
			inv := resolveInv(t, buildDir)
			// Full (id, resolvedVersion, framework, direct) multiset equality per (project, framework).
			assertBucketsEqual(t, nativeBuckets(t, tc.name), invBuckets(t, inv))
			// Capture-specific must-exhibit assertions.
			tc.exhibit(t, buildDir, inv)
		})
	}
}

func setsEqual(a, b map[pkgTuple]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
