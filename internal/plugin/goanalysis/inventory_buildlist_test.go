package goanalysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The not_exploitable gate reads a Go inventory marked with BuildList as the build's whole module
// list, so these pin what that list is in each build mode.

func nodePURLs(inv plugin.DependencyInventory) []string {
	var purls []string
	for _, n := range inv.Nodes {
		purls = append(purls, n.PURL)
	}
	return purls
}

// A replace by another module keeps the required path as the node's identity and records the
// replacement's path beside it.
func TestResolveInventory_BuildList_ModuleReplace(t *testing.T) {
	newFileProxy(t, []proxyModule{
		{"example.test/dep", "v1.0.0", "module example.test/dep\n\ngo 1.21\n"},
		{"example.test/fork", "v1.1.0", "module example.test/fork\n\ngo 1.21\n"},
	})
	app := t.TempDir()
	writeDir(t, app, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.21\n\nrequire example.test/dep v1.0.0\n\nreplace example.test/dep => example.test/fork v1.1.0\n",
		"main.go": "package main\n\nimport _ \"example.test/dep\"\n\nfunc main() {}\n",
	})

	inv := resolve(t, app)
	if inv.BuildList != plugin.BuildListGoModGraph || inv.MainModule != "example.test/app" || !inv.Partiality.Complete {
		t.Fatalf("build list = %q for %q, partiality %+v; want %q for example.test/app, complete", inv.BuildList, inv.MainModule, inv.Partiality, plugin.BuildListGoModGraph)
	}
	dep, ok := nodeByPathPrefix(inv, "pkg:golang/example.test/dep@")
	if !ok {
		t.Fatalf("replaced module absent: %q", nodePURLs(inv))
	}
	if dep.Version != "v1.1.0" || dep.Replace != "example.test/fork" {
		t.Errorf("dep = %s replace %q, want v1.1.0 replace example.test/fork", dep.Version, dep.Replace)
	}
}

// A vendored module resolves to the same build list as the module without vendor/: `go mod graph`
// reads the module graph, not vendor/modules.txt.
func TestResolveInventory_BuildList_Vendored(t *testing.T) {
	newFileProxy(t, []proxyModule{{"example.test/x", "v1.0.0", "module example.test/x\n\ngo 1.21\n"}})
	t.Setenv("GOFLAGS", "") // the vendored default, -mod=vendor
	files := map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.21\n\nrequire example.test/x v1.0.0\n",
		"main.go": "package main\n\nimport _ \"example.test/x\"\n\nfunc main() {}\n",
	}
	plain := t.TempDir()
	writeDir(t, plain, files)
	vendored := t.TempDir()
	writeDir(t, vendored, files)
	writeDir(t, vendored, map[string]string{
		"vendor/modules.txt":           "# example.test/x v1.0.0\n## explicit; go 1.21\nexample.test/x\n",
		"vendor/example.test/x/lib.go": "package x\n",
	})

	want, got := resolve(t, plain), resolve(t, vendored)
	if got.BuildList != plugin.BuildListGoModGraph || !got.Partiality.Complete {
		t.Fatalf("vendored build list = %q, partiality %+v; want %q, complete", got.BuildList, got.Partiality, plugin.BuildListGoModGraph)
	}
	if !slices.Equal(nodePURLs(got), nodePURLs(want)) || len(got.Nodes) == 0 {
		t.Errorf("vendored nodes = %q, want the module's %q", nodePURLs(got), nodePURLs(want))
	}
}

// A vendored module whose graph cannot be resolved (no proxy, cold cache) declares a tool failure,
// so the list is not read as complete.
func TestResolveInventory_BuildList_VendoredOffline(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOMODCACHE", writableTempDir(t))
	app := t.TempDir()
	writeDir(t, app, map[string]string{
		"go.mod":                       "module example.test/app\n\ngo 1.21\n\nrequire example.test/x v1.0.0\n",
		"main.go":                      "package main\n\nimport _ \"example.test/x\"\n\nfunc main() {}\n",
		"vendor/modules.txt":           "# example.test/x v1.0.0\n## explicit; go 1.21\nexample.test/x\n",
		"vendor/example.test/x/lib.go": "package x\n",
	})

	inv := resolve(t, app)
	if inv.Partiality.Complete || !invHasReason(inv.Partiality, plugin.PartialReasonToolFailure) || inv.BuildList != "" {
		t.Errorf("partiality = %+v, build list %q; want tool_failure, no build list", inv.Partiality, inv.BuildList)
	}
}

// A go.work root resolves only its own module, so the workspace is declared unsupported and the
// list is not marked as the build's.
func TestResolveInventory_BuildList_Workspace(t *testing.T) {
	root := t.TempDir()
	writeDir(t, root, map[string]string{
		"go.work":      "go 1.21\n\nuse (\n\t.\n\t./other\n)\n",
		"go.mod":       "module example.test/app\n\ngo 1.21\n",
		"main.go":      "package main\n\nfunc main() {}\n",
		"other/go.mod": "module example.test/other\n\ngo 1.21\n",
	})
	inv := resolve(t, root)
	if inv.Partiality.Complete || !invHasReason(inv.Partiality, plugin.PartialReasonUnsupported) || inv.BuildList != "" {
		t.Errorf("partiality = %+v, build list %q; want unsupported, no build list", inv.Partiality, inv.BuildList)
	}
}

// workspaceTree writes a go.work using a and b under a fresh root and warms the module cache from
// the file proxy, so the offline graph the workspace read runs resolves. It returns the root.
func workspaceTree(t *testing.T, goWork string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeDir(t, root, map[string]string{"go.work": goWork})
	writeDir(t, root, files)
	for _, m := range []string{"a", "b"} {
		cmd := exec.Command("go", "mod", "tidy")
		cmd.Dir = filepath.Join(root, m)
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go mod tidy in %s: %v\n%s", m, err, out)
		}
	}
	return root
}

func resolveUnder(t *testing.T, buildDir, goWork string) plugin.DependencyInventory {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: buildDir, GoWork: goWork})
	if err != nil {
		t.Fatalf("ResolveInventory: %v", err)
	}
	return inv
}

// Under the build's go.work the graph is the workspace's: a version another member raises is the
// one selected. With the workspace off the module resolves its own graph.
func TestResolveInventory_UnderWorkspace_RaisedByMember(t *testing.T) {
	newFileProxy(t, []proxyModule{
		{"example.test/x", "v1.0.0", "module example.test/x\n\ngo 1.21\n"},
		{"example.test/x", "v1.2.0", "module example.test/x\n\ngo 1.21\n"},
	})
	root := workspaceTree(t, "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n", map[string]string{
		"a/go.mod":  "module example.test/a\n\ngo 1.21\n\nrequire example.test/x v1.0.0\n",
		"a/main.go": "package main\n\nimport _ \"example.test/x\"\n\nfunc main() {}\n",
		"b/go.mod":  "module example.test/b\n\ngo 1.21\n\nrequire example.test/x v1.2.0\n",
		"b/lib.go":  "package b\n\nimport _ \"example.test/x\"\n",
	})
	a := filepath.Join(root, "a")

	ws := resolveUnder(t, a, filepath.Join(root, "go.work"))
	if got, want := nodePURLs(ws), []string{"pkg:golang/example.test/x@v1.2.0"}; !slices.Equal(got, want) {
		t.Errorf("workspace nodes = %q, want %q", got, want)
	}
	if !ws.Partiality.Complete || ws.BuildList != plugin.BuildListGoModGraph || ws.MainModule != "example.test/a" || !slices.Equal(ws.WorkspaceModules, []string{"example.test/b"}) {
		t.Errorf("workspace partiality = %+v, build list %q for %q and %q; want complete, %q for example.test/a and [example.test/b]", ws.Partiality, ws.BuildList, ws.MainModule, ws.WorkspaceModules, plugin.BuildListGoModGraph)
	}
	// x@v1.2.0 is pinned only in b's go.sum, so that is the lockfile the digest came from.
	if len(ws.Nodes) == 1 && (ws.Nodes[0].Provenance.Lockfile != "../b/go.sum" || ws.Nodes[0].Artifact.Digest == "") {
		t.Errorf("workspace node lockfile %q, digest %q; want ../b/go.sum with a digest", ws.Nodes[0].Provenance.Lockfile, ws.Nodes[0].Artifact.Digest)
	}
	off := resolveUnder(t, a, "off")
	if got, want := nodePURLs(off), []string{"pkg:golang/example.test/x@v1.0.0"}; !slices.Equal(got, want) {
		t.Errorf("off nodes = %q, want %q", got, want)
	}
	if len(off.Nodes) == 1 && off.Nodes[0].Provenance.Lockfile != "go.sum" {
		t.Errorf("off node lockfile = %q, want go.sum", off.Nodes[0].Provenance.Lockfile)
	}
}

// A member the build requires through a replace is a main module under the workspace, not a
// dependency; with the workspace off it is the filesystem replace it names.
func TestResolveInventory_UnderWorkspace_MemberReplace(t *testing.T) {
	newFileProxy(t, []proxyModule{{"example.test/x", "v1.0.0", "module example.test/x\n\ngo 1.21\n"}})
	root := workspaceTree(t, "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n", map[string]string{
		"a/go.mod":  "module example.test/a\n\ngo 1.21\n\nrequire (\n\texample.test/b v0.0.0\n\texample.test/x v1.0.0\n)\n\nreplace example.test/b => ../b\n",
		"a/main.go": "package main\n\nimport (\n\t_ \"example.test/b\"\n\t_ \"example.test/x\"\n)\n\nfunc main() {}\n",
		"b/go.mod":  "module example.test/b\n\ngo 1.21\n",
		"b/lib.go":  "package b\n",
	})
	a := filepath.Join(root, "a")

	ws := resolveUnder(t, a, filepath.Join(root, "go.work"))
	if got, want := nodePURLs(ws), []string{"pkg:golang/example.test/x@v1.0.0"}; !slices.Equal(got, want) || !ws.Partiality.Complete {
		t.Errorf("workspace nodes = %q (partiality %+v), want %q, complete", got, ws.Partiality, want)
	}
	if _, ok := nodeByPathPrefix(resolveUnder(t, a, "off"), "pkg:golang/example.test/b"); !ok {
		t.Error("off: the replaced b is absent")
	}
}

// A go.work replace governs the workspace's graph ahead of any member's go.mod.
func TestResolveInventory_UnderWorkspace_GoWorkReplace(t *testing.T) {
	newFileProxy(t, []proxyModule{
		{"example.test/x", "v1.0.0", "module example.test/x\n\ngo 1.21\n"},
		{"example.test/fork", "v1.1.0", "module example.test/fork\n\ngo 1.21\n"},
	})
	root := workspaceTree(t, "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n", map[string]string{
		"a/go.mod":  "module example.test/a\n\ngo 1.21\n\nrequire example.test/x v1.0.0\n",
		"a/main.go": "package main\n\nimport _ \"example.test/x\"\n\nfunc main() {}\n",
		"b/go.mod":  "module example.test/b\n\ngo 1.21\n",
	})
	writeDir(t, root, map[string]string{"go.work": "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n\nreplace example.test/x => example.test/fork v1.1.0\n"})
	cmd := exec.Command("go", "mod", "download", "example.test/fork@v1.1.0")
	cmd.Dir = filepath.Join(root, "a")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("download fork: %v\n%s", err, out)
	}

	inv := resolveUnder(t, filepath.Join(root, "a"), filepath.Join(root, "go.work"))
	x, ok := nodeByPathPrefix(inv, "pkg:golang/example.test/x@")
	if !ok || x.Version != "v1.1.0" || x.Replace != "example.test/fork" {
		t.Errorf("x = %+v, %v; want v1.1.0 replaced by example.test/fork", x, ok)
	}
}

// Under the workspace the graph is read offline, as the host reads the workspace build list: a module
// missing from the cache is not fetched, even where the environment's proxy could serve it.
func TestResolveInventory_UnderWorkspace_Offline(t *testing.T) {
	newFileProxy(t, []proxyModule{{"example.test/x", "v1.0.0", "module example.test/x\n\ngo 1.21\n"}})
	root := t.TempDir()
	writeDir(t, root, map[string]string{
		"go.work":   "go 1.21\n\nuse ./a\n",
		"a/go.mod":  "module example.test/a\n\ngo 1.21\n\nrequire example.test/x v1.0.0\n",
		"a/main.go": "package main\n\nimport _ \"example.test/x\"\n\nfunc main() {}\n",
	})
	a := filepath.Join(root, "a")

	ws := resolveUnder(t, a, filepath.Join(root, "go.work"))
	if ws.Partiality.Complete || !invHasReason(ws.Partiality, plugin.PartialReasonToolFailure) || len(ws.Nodes) != 0 || ws.BuildList != "" {
		t.Errorf("workspace inventory = %+v; want tool_failure, no nodes and no build list", ws)
	}
	if got, want := nodePURLs(resolveUnder(t, a, "off")), []string{"pkg:golang/example.test/x@v1.0.0"}; !slices.Equal(got, want) {
		t.Errorf("off nodes = %q, want %q", got, want)
	}
}

// A workspace whose member go.mod cannot be read, or that does not use the build's module, leaves the
// inventory unresolved, never the module's own graph; a relative go.work is refused.
func TestResolveInventory_UnderWorkspace_Unreadable(t *testing.T) {
	root := t.TempDir()
	writeDir(t, root, map[string]string{
		"go.work":   "go 1.21\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod":  "module example.test/a\n\ngo 1.21\n",
		"a/main.go": "package main\n\nfunc main() {}\n",
	})
	inv := resolveUnder(t, filepath.Join(root, "a"), filepath.Join(root, "go.work"))
	if inv.Partiality.Complete || !invHasReason(inv.Partiality, plugin.PartialReasonToolFailure) || len(inv.Nodes) != 0 || inv.BuildList != "" {
		t.Errorf("inventory = %+v; want tool_failure, no nodes and no build list", inv)
	}
	writeDir(t, root, map[string]string{
		"b/go.mod":  "module example.test/b\n\ngo 1.21\n",
		"c/go.mod":  "module example.test/c\n\ngo 1.21\n",
		"c/main.go": "package main\n\nfunc main() {}\n",
	})
	inv = resolveUnder(t, filepath.Join(root, "c"), filepath.Join(root, "go.work"))
	if inv.Partiality.Complete || !invHasReason(inv.Partiality, plugin.PartialReasonToolFailure) || len(inv.Nodes) != 0 || inv.BuildList != "" {
		t.Errorf("module outside the workspace: inventory = %+v; want tool_failure, no nodes and no build list", inv)
	}
	if _, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: filepath.Join(root, "a"), GoWork: "go.work"}); err == nil {
		t.Error("a relative go.work was accepted")
	}
}
