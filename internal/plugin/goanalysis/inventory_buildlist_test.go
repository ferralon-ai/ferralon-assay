package goanalysis

import (
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
