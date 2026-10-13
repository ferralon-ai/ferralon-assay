package cfamilyanalysis

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func resolveInventory(t *testing.T, files map[string]string) plugin.DependencyInventory {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: writeFiles(t, files)})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func nodeByPURL(t *testing.T, inv plugin.DependencyInventory, purl string) plugin.DependencyNode {
	t.Helper()
	for _, n := range inv.Nodes {
		if n.PURL == purl {
			return n
		}
	}
	t.Fatalf("no node with PURL %s in %+v", purl, inv.Nodes)
	return plugin.DependencyNode{}
}

func purls(inv plugin.DependencyInventory) []string {
	var out []string
	for _, n := range inv.Nodes {
		out = append(out, n.PURL)
	}
	return out
}

// Every way the inventory can come up short declares why, and none of them reads Complete.
func TestResolveInventoryPartiality(t *testing.T) {
	tests := []struct {
		name      string
		files     map[string]string
		wantPart  plugin.Partiality
		wantPURLs []string
	}{
		{
			name:     "no manifest at all",
			files:    map[string]string{"CMakeLists.txt": "project(p C)", "main.c": "int main(void){return 0;}"},
			wantPart: plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:     "conanfile.py alone is not a manifest",
			files:    map[string]string{"conanfile.py": "requires = 'zlib/1.3.1'"},
			wantPart: plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:     "empty conan.lock",
			files:    map[string]string{conanLockFile: `{"version":"0.5","requires":[]}`},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned),
		},
		{
			name:     "zero-byte conan.lock",
			files:    map[string]string{conanLockFile: ""},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned, plugin.PartialReasonToolFailure),
		},
		{
			name:     "unparsable conan.lock",
			files:    map[string]string{conanLockFile: `{"version":"0.5","requires":[`},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned, plugin.PartialReasonToolFailure),
		},
		{
			name:     "unfamiliar conan lockfile format",
			files:    map[string]string{conanLockFile: `{"version":"0.4","graph_lock":{"nodes":{}}}`},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned, plugin.PartialReasonToolFailure),
		},
		{
			name:      "conanfile.txt with literal pins has no lock for its transitive packages",
			files:     map[string]string{conanTxtFile: "[requires]\nzlib/1.2.11\n"},
			wantPart:  plugin.Partial(plugin.PartialReasonSourceUnpinned),
			wantPURLs: []string{"pkg:conan/zlib@1.2.11"},
		},
		{
			name:      "conanfile.txt with only a range pins nothing",
			files:     map[string]string{conanTxtFile: "[requires]\nzlib/[>=1.2 <2]\n"},
			wantPart:  plugin.Partial(plugin.PartialReasonSourceUnpinned),
			wantPURLs: []string{"pkg:conan/zlib"},
		},
		{
			name:     "conanfile.txt with no requires",
			files:    map[string]string{conanTxtFile: "[generators]\nCMakeDeps\n"},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned),
		},
		{
			name:      "vcpkg.json with no overrides pins nothing",
			files:     map[string]string{vcpkgFile: `{"dependencies":["zlib"]}`},
			wantPart:  plugin.Partial(plugin.PartialReasonSourceUnpinned),
			wantPURLs: []string{"pkg:vcpkg/zlib"},
		},
		{
			name:     "unparsable vcpkg.json",
			files:    map[string]string{vcpkgFile: `{"dependencies": [`},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned, plugin.PartialReasonToolFailure),
		},
		{
			name:     "empty vcpkg status",
			files:    map[string]string{vcpkgStatusFile: ""},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned),
		},
		{
			name:     "vcpkg status with every package removed",
			files:    map[string]string{vcpkgStatusFile: "Package: zlib\nVersion: 1.3.1\nArchitecture: x64-linux\nStatus: purge ok not-installed\n"},
			wantPart: plugin.Partial(plugin.PartialReasonSourceUnpinned),
		},
		{
			name:      "vcpkg status entry with no version",
			files:     map[string]string{vcpkgStatusFile: vcpkgStatus + "\nPackage: bzip2\nArchitecture: x64-linux\nStatus: install ok installed\n"},
			wantPart:  plugin.Partial(plugin.PartialReasonSourceUnpinned),
			wantPURLs: []string{"pkg:vcpkg/bzip2", "pkg:vcpkg/libpng@1.6.43?port_version=2", "pkg:vcpkg/vcpkg-cmake@2024-04-23", "pkg:vcpkg/zlib@1.3.1"},
		},
		{
			name:      "conan locked but vcpkg only declared",
			files:     map[string]string{conanLockFile: conanLock, vcpkgFile: `{"dependencies":["curl"]}`},
			wantPart:  plugin.Partial(plugin.PartialReasonSourceUnpinned),
			wantPURLs: []string{"pkg:conan/fmt@10.2.1", "pkg:conan/mylib@2.0?channel=stable&user=corp", "pkg:conan/zlib@1.3.1", "pkg:vcpkg/curl"},
		},
		{
			name:      "conan.lock pins the whole host graph",
			files:     map[string]string{conanLockFile: conanLock},
			wantPart:  plugin.Complete(),
			wantPURLs: []string{"pkg:conan/fmt@10.2.1", "pkg:conan/mylib@2.0?channel=stable&user=corp", "pkg:conan/zlib@1.3.1"},
		},
		{
			name:      "vcpkg status pins the installed tree",
			files:     map[string]string{vcpkgStatusFile: vcpkgStatus},
			wantPart:  plugin.Complete(),
			wantPURLs: []string{"pkg:vcpkg/libpng@1.6.43?port_version=2", "pkg:vcpkg/vcpkg-cmake@2024-04-23", "pkg:vcpkg/zlib@1.3.1"},
		},
		{
			name:      "vcpkg.json asks for a package the status does not have installed",
			files:     map[string]string{vcpkgStatusFile: vcpkgStatus, vcpkgFile: vcpkgJSON},
			wantPart:  plugin.Partial(plugin.PartialReasonSourceUnpinned),
			wantPURLs: []string{"pkg:vcpkg/fmt@10.1.1?port_version=2", "pkg:vcpkg/libpng@1.6.43?port_version=2", "pkg:vcpkg/vcpkg-cmake@2024-04-23", "pkg:vcpkg/zlib@1.3.1", "pkg:vcpkg/curl"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := resolveInventory(t, tt.files)
			if !reflect.DeepEqual(inv.Partiality, tt.wantPart) {
				t.Errorf("Partiality = %+v, want %+v", inv.Partiality, tt.wantPart)
			}
			if !tt.wantPart.Complete && inv.Partiality.Complete {
				t.Error("a short inventory reads Complete")
			}
			got := map[string]bool{}
			for _, p := range purls(inv) {
				got[p] = true
			}
			want := map[string]bool{}
			for _, p := range tt.wantPURLs {
				want[p] = true
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("PURLs = %v, want %v", purls(inv), tt.wantPURLs)
			}
		})
	}
}

// vcpkg's status Depends fields are the inventory's edges, and vcpkg.json marks which installed
// packages are direct.
func TestResolveInventoryVcpkgStatusGraph(t *testing.T) {
	inv := resolveInventory(t, map[string]string{
		vcpkgStatusFile: vcpkgStatus,
		vcpkgFile:       `{"dependencies":["libpng"],"overrides":[{"name":"libpng","version":"1.6.43","port-version":2}]}`,
	})
	if !inv.Partiality.Complete {
		t.Fatalf("Partiality = %+v, want Complete", inv.Partiality)
	}

	locked := plugin.DependencyInventory{Nodes: lockNodes(inv)}
	libpng := nodeByPURL(t, locked, "pkg:vcpkg/libpng@1.6.43?port_version=2")
	wantLibpng := plugin.DependencyNode{
		ID:         vcpkgStatusFile + "|x64-linux|pkg:vcpkg/libpng@1.6.43?port_version=2",
		PURL:       "pkg:vcpkg/libpng@1.6.43?port_version=2",
		Version:    "1.6.43#2",
		Direct:     true,
		Artifact:   plugin.DependencyArtifact{Identity: "libpng:x64-linux"},
		Provenance: plugin.DependencyProvenance{Manifest: vcpkgFile, Lockfile: vcpkgStatusFile, Resolver: "vcpkg installed status", Target: "x64-linux"},
		Partiality: plugin.Complete(),
	}
	if !reflect.DeepEqual(libpng, wantLibpng) {
		t.Errorf("libpng = %+v\nwant     %+v", libpng, wantLibpng)
	}
	zlib := nodeByPURL(t, locked, "pkg:vcpkg/zlib@1.3.1")
	if zlib.Direct {
		t.Error("zlib is only a transitive dependency of libpng, but reads Direct")
	}
	cmake := nodeByPURL(t, locked, "pkg:vcpkg/vcpkg-cmake@2024-04-23")

	wantEdges := []plugin.DependencyEdge{
		{Parent: libpng.ID, Child: cmake.ID},
		{Parent: libpng.ID, Child: zlib.ID},
		{Parent: zlib.ID, Child: cmake.ID},
	}
	if !reflect.DeepEqual(inv.Edges, wantEdges) {
		t.Errorf("Edges = %+v\nwant  %+v", inv.Edges, wantEdges)
	}

	// The declared vcpkg.json override for the same version is its own node, Direct on its own.
	override := nodeByPURL(t, plugin.DependencyInventory{Nodes: nodesFrom(inv, vcpkgFile)}, "pkg:vcpkg/libpng@1.6.43?port_version=2")
	if !override.Direct || override.Provenance.Manifest != vcpkgFile || override.Provenance.Lockfile != "" {
		t.Errorf("override node = %+v", override)
	}
}

func lockNodes(inv plugin.DependencyInventory) []plugin.DependencyNode {
	var out []plugin.DependencyNode
	for _, n := range inv.Nodes {
		if n.Provenance.Lockfile != "" {
			out = append(out, n)
		}
	}
	return out
}

func nodesFrom(inv plugin.DependencyInventory, source string) []plugin.DependencyNode {
	var out []plugin.DependencyNode
	for _, n := range inv.Nodes {
		if n.Provenance.Manifest == source && n.Provenance.Lockfile == "" {
			out = append(out, n)
		}
	}
	return out
}

// A Depends entry for a package vcpkg did not record as installed gets no edge and no node.
func TestResolveInventoryVcpkgEdgeToAbsentPackage(t *testing.T) {
	inv := resolveInventory(t, map[string]string{vcpkgStatusFile: "Package: libpng\nVersion: 1.6.43\nDepends: zlib\nArchitecture: x64-linux\nStatus: install ok installed\n"})
	if len(inv.Edges) != 0 || len(inv.Nodes) != 1 {
		t.Fatalf("Nodes = %+v, Edges = %+v; want one node, no edges", inv.Nodes, inv.Edges)
	}
}

// A conan.lock is the resolved graph; conanfile.txt marks which of its packages the project asks
// for. The lock pins the range conanfile.txt only constrains, so the range is not a node of its own.
func TestResolveInventoryConanDirect(t *testing.T) {
	inv := resolveInventory(t, map[string]string{conanLockFile: conanLock, conanTxtFile: "[requires]\nfmt/[>=10 <11]\n"})
	if !inv.Partiality.Complete {
		t.Fatalf("Partiality = %+v, want Complete", inv.Partiality)
	}
	if len(inv.Nodes) != 3 {
		t.Fatalf("Nodes = %+v, want the three locked packages", inv.Nodes)
	}
	fmtNode := nodeByPURL(t, inv, "pkg:conan/fmt@10.2.1")
	want := plugin.DependencyNode{
		ID:         conanLockFile + "||pkg:conan/fmt@10.2.1",
		PURL:       "pkg:conan/fmt@10.2.1",
		Version:    "10.2.1",
		Direct:     true,
		Artifact:   plugin.DependencyArtifact{Identity: "fmt/10.2.1#15db2a3ea0646365bf05a6f50369ac59%1785754570.436"},
		Provenance: plugin.DependencyProvenance{Manifest: conanTxtFile, Lockfile: conanLockFile, Resolver: "conan lockfile"},
		Partiality: plugin.Complete(),
	}
	if !reflect.DeepEqual(fmtNode, want) {
		t.Errorf("fmt = %+v\nwant  %+v", fmtNode, want)
	}
	if nodeByPURL(t, inv, "pkg:conan/zlib@1.3.1").Direct {
		t.Error("zlib is not declared, but reads Direct")
	}
}

func TestResolveInventoryUnpinnedNodeDeclaresItself(t *testing.T) {
	inv := resolveInventory(t, map[string]string{conanTxtFile: "[requires]\nzlib/[>=1.2 <2]\n"})
	n := nodeByPURL(t, inv, "pkg:conan/zlib")
	if n.Version != "" || !reflect.DeepEqual(n.Partiality, plugin.Partial(plugin.PartialReasonSourceUnpinned)) || !n.Direct {
		t.Errorf("unpinned node = %+v", n)
	}
}

func TestResolveInventoryDeterministic(t *testing.T) {
	files := map[string]string{vcpkgStatusFile: vcpkgStatus, vcpkgFile: vcpkgJSON, conanLockFile: conanLock, conanTxtFile: conanfileTxt}
	dir := writeFiles(t, files)
	first, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(again, first) {
			t.Fatalf("run %d differs:\n%+v\n%+v", i, again, first)
		}
	}
}

func TestResolveInventoryBadBuildDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: missing}); err == nil {
		t.Fatal("missing build dir: want a hard error")
	}
}
