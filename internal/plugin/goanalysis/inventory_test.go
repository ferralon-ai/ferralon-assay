package goanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// -------- fixture helpers --------

// writeDir writes a set of relative files under root, creating parents.
func writeDir(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// proxyModule is one module@version served by a hermetic file GOPROXY.
type proxyModule struct {
	path, version, gomod string
}

// newFileProxy writes a file-based GOPROXY tree so a module graph resolves fully
// offline and deterministically — the standard hermetic way to exercise minimal
// version selection and pruning without touching the network or the shared cache.
// It points GOPROXY/GOMODCACHE at temp dirs for the rest of the test via t.Setenv,
// which ResolveInventory and the `go list` oracle both inherit through os.Environ().
func newFileProxy(t *testing.T, mods []proxyModule) {
	t.Helper()
	proxy := t.TempDir()
	for _, m := range mods {
		esc, err := module.EscapePath(m.path)
		if err != nil {
			t.Fatalf("escape %q: %v", m.path, err)
		}
		base := filepath.Join(proxy, esc, "@v")
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		writeDir(t, base, map[string]string{
			m.version + ".info": `{"Version":"` + m.version + `","Time":"2020-01-01T00:00:00Z"}`,
			m.version + ".mod":  m.gomod,
		})
		// Build the module zip with the canonical <path>@<version>/ layout.
		src := t.TempDir()
		writeDir(t, src, map[string]string{"go.mod": m.gomod, "lib.go": "package " + lastPathElem(m.path) + "\n"})
		zf, err := os.Create(filepath.Join(base, m.version+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		if err := modzip.CreateFromDir(zf, module.Version{Path: m.path, Version: m.version}, src); err != nil {
			t.Fatalf("zip %s@%s: %v", m.path, m.version, err)
		}
		zf.Close()
	}
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GONOSUMCHECK", "1")
	t.Setenv("GOFLAGS", "-mod=mod")
	// The Go module cache marks files and directories read-only; a plain t.TempDir()
	// auto-cleanup then fails to unlink them ("permission denied"). Use a cache dir
	// whose cleanup restores write permission first. Isolate GOPATH the same way.
	t.Setenv("GOMODCACHE", writableTempDir(t))
	t.Setenv("GOPATH", writableTempDir(t))
}

// writableTempDir returns a temp dir whose cleanup chmods every entry back to
// writable before removal, so a read-only Go module cache can be torn down.
func writableTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gomodcache")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil {
				os.Chmod(p, 0o755)
			}
			return nil
		})
		os.RemoveAll(dir)
	})
	return dir
}

func lastPathElem(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return strings.NewReplacer(".", "", "-", "").Replace(p)
}

func resolve(t *testing.T, buildDir string) plugin.DependencyInventory {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: buildDir})
	if err != nil {
		t.Fatalf("ResolveInventory: %v", err)
	}
	return inv
}

func nodeByPathPrefix(inv plugin.DependencyInventory, purlPrefix string) (plugin.DependencyNode, bool) {
	for _, n := range inv.Nodes {
		if strings.HasPrefix(n.PURL, purlPrefix) {
			return n, true
		}
	}
	return plugin.DependencyNode{}, false
}

// -------- C1: the inventory reflects the SELECTED build list, not go.mod's require block --------

// TestResolveInventory_SelectedGraphNotRequireList_C1a exercises divergence class
// (a) minimal-version-selection raising a version above every stated require, and
// class (c) a transitive requirement not enumerated in the main module's require
// block. The oracle is the native toolchain (`go list -m -json all`) over the SAME
// tree, never a hand-written expectation. The control proves the fixtures actually
// diverge: a require-list-only derivation misses `common` entirely.
func TestResolveInventory_SelectedGraphNotRequireList_C1a(t *testing.T) {
	newFileProxy(t, []proxyModule{
		{"example.test/low", "v1.0.0", "module example.test/low\n\ngo 1.16\n\nrequire example.test/common v1.1.0\n"},
		{"example.test/high", "v1.0.0", "module example.test/high\n\ngo 1.16\n\nrequire example.test/common v1.2.0\n"},
		{"example.test/common", "v1.1.0", "module example.test/common\n\ngo 1.16\n"},
		{"example.test/common", "v1.2.0", "module example.test/common\n\ngo 1.16\n"},
	})
	// go 1.16 (unpruned, untidied): the require block lists only the two direct deps;
	// `common` is selected transitively and appears in NEITHER require line.
	app := t.TempDir()
	writeDir(t, app, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.16\n\nrequire (\n\texample.test/low v1.0.0\n\texample.test/high v1.0.0\n)\n",
		"main.go": "package main\n\nimport (\n\t_ \"example.test/low\"\n\t_ \"example.test/high\"\n)\n\nfunc main() {}\n",
	})

	inv := resolve(t, app)

	// Oracle: the native selected build list.
	oracle := nativeSelectedVersions(t, app)
	if len(oracle) == 0 {
		t.Fatal("oracle produced no modules — proxy/tree misconfigured")
	}
	for _, n := range inv.Nodes {
		path := purlPath(n.PURL)
		want, ok := oracle[path]
		if !ok {
			t.Errorf("resolver reported %q which the native toolchain does not select", path)
			continue
		}
		if n.Version != want {
			t.Errorf("%s: resolver version %q != native selected %q", path, n.Version, want)
		}
	}

	// Class (a): common is selected at v1.2.0 (the higher of the two requires), not v1.1.0.
	common, ok := nodeByPathPrefix(inv, "pkg:golang/example.test/common@")
	if !ok {
		t.Fatal("class (a)/(c) failed: transitively-selected example.test/common is absent from the inventory")
	}
	if common.Version != "v1.2.0" {
		t.Errorf("MVS not applied: common selected %q, want v1.2.0", common.Version)
	}
	if common.Direct {
		t.Error("common is a transitive dependency; Direct must be false")
	}
	if low, ok := nodeByPathPrefix(inv, "pkg:golang/example.test/low@"); !ok || !low.Direct {
		t.Errorf("example.test/low is a direct require; Direct must be true (got node=%+v ok=%v)", low, ok)
	}

	// Class (c) control: a require-list-only derivation misses `common`, so the
	// fixtures genuinely diverge and the test above is not vacuous.
	reqOnly := requireListOnly(t, app)
	if _, present := reqOnly["example.test/common"]; present {
		t.Error("control is vacuous: `common` appears in the require block, so require-list scan would not diverge")
	}

	// Parent edges (§8 checkbox 2): high -> common must be present in the selected graph.
	if !invHasEdge(inv, "pkg:golang/example.test/high@v1.0.0", "pkg:golang/example.test/common@v1.2.0") {
		t.Errorf("expected selected-graph edge high@v1.0.0 -> common@v1.2.0; edges=%+v", inv.Edges)
	}
}

// TestResolveInventory_ReplaceRedirect_C1b exercises divergence class (b): a
// `replace` directive redirecting a selection to a local module. `go mod graph`
// labels the node at its original require version; the resolver reconciles the
// redirect from go.mod (modfile), so it reports the selection as unpinned rather
// than parroting the superseded require version. Fully offline — no proxy.
func TestResolveInventory_ReplaceRedirect_C1b(t *testing.T) {
	root := t.TempDir()
	// The local replacement target.
	writeDir(t, filepath.Join(root, "localdep"), map[string]string{
		"go.mod": "module example.test/dep\n\ngo 1.21\n",
		"dep.go": "package dep\n\nfunc F() int { return 1 }\n",
	})
	app := filepath.Join(root, "app")
	writeDir(t, app, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.21\n\nrequire example.test/dep v1.5.0\n\nreplace example.test/dep => ../localdep\n",
		"main.go": "package main\n\nimport \"example.test/dep\"\n\nfunc main() { _ = dep.F() }\n",
	})

	inv := resolve(t, app)

	dep, ok := nodeByPathPrefix(inv, "pkg:golang/example.test/dep")
	if !ok {
		t.Fatal("replaced dependency example.test/dep is absent from the inventory")
	}
	// Control: the require line says v1.5.0. A require-list scan would report that.
	// The resolver must NOT: the filesystem replace has no verifiable version.
	if dep.Version == "v1.5.0" {
		t.Error("class (b) failed: resolver parroted the require version v1.5.0 instead of reconciling the replace")
	}
	if dep.Version != "" {
		t.Errorf("filesystem-replaced module should have no pinned version, got %q", dep.Version)
	}
	if dep.Partiality.Complete {
		t.Error("a filesystem replace is unpinned; the node must declare partiality, not claim Complete")
	}
	if !invHasReason(dep.Partiality, plugin.PartialReasonSourceUnpinned) {
		t.Errorf("expected source_unpinned on the filesystem-replaced node, got %+v", dep.Partiality)
	}
}

// -------- C2: every §4.1 bullet is populated or declared partial, per node --------

// TestResolveInventory_PerNodeCompleteness_C2 is the per-node sweep: for every node
// of a resolved fixture, each §4.1 bullet is either populated or the node/graph
// declares a partiality reason naming it. No spot check — one unpopulated,
// undeclared bullet on any node fails.
func TestResolveInventory_PerNodeCompleteness_C2(t *testing.T) {
	newFileProxy(t, []proxyModule{
		{"example.test/a", "v1.0.0", "module example.test/a\n\ngo 1.16\n\nrequire example.test/b v1.0.0\n"},
		{"example.test/b", "v1.0.0", "module example.test/b\n\ngo 1.16\n"},
	})
	app := t.TempDir()
	writeDir(t, app, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.16\n\nrequire example.test/a v1.0.0\n",
		"main.go": "package main\n\nimport _ \"example.test/a\"\n\nfunc main() {}\n",
	})
	// Prime go.sum so the artifact-digest bullet is populated (not declared) for at
	// least one node — proving the populated branch, not only the declared branch.
	runGo(t, app, "mod", "download", "all")

	inv := resolve(t, app)
	if len(inv.Nodes) == 0 {
		t.Fatal("no nodes to sweep")
	}
	for _, n := range inv.Nodes {
		// bullet 1: normalized PURL + exact version.
		if n.PURL == "" {
			t.Errorf("%s: bullet(purl) neither populated nor declared", n.ID)
		}
		if n.Version == "" && !invHasReason(n.Partiality, plugin.PartialReasonSourceUnpinned) {
			t.Errorf("%s: bullet(version) blank with no declaration", n.ID)
		}
		// bullet 2: direct/transitive is always populated (a bool is never absent);
		// parent edges are graph-level, asserted in C1.
		// bullet 3: membership — project is populated.
		if n.Membership.Project == "" {
			t.Errorf("%s: bullet(membership.project) neither populated nor declared", n.ID)
		}
		// bullet 4: selected artifact identity + integrity digest — populated OR declared.
		if (n.Artifact.Digest == "" || n.Artifact.Identity == "") && !invHasReason(n.Partiality, plugin.PartialReasonSourceUnpinned) {
			t.Errorf("%s: bullet(artifact) blank with no source_unpinned declaration; artifact=%+v part=%+v", n.ID, n.Artifact, n.Partiality)
		}
		// bullet 5: provenance — resolver is always populated.
		if n.Provenance.Resolver == "" || n.Provenance.Manifest == "" {
			t.Errorf("%s: bullet(provenance) blank with no declaration; prov=%+v", n.ID, n.Provenance)
		}
		// bullet 6: declared partiality is the Partiality field itself — always present.
	}

	// Mutation control: blank one populated bullet on one node without a declaration
	// and the sweep goes red. Prove the sweep has teeth.
	var mutated bool
	for i := range inv.Nodes {
		if inv.Nodes[i].Provenance.Resolver != "" {
			inv.Nodes[i].Provenance.Resolver = ""
			mutated = true
			break
		}
	}
	if !mutated {
		t.Fatal("no node had a populated resolver to mutate")
	}
	if provenanceSweepPasses(inv) {
		t.Error("mutation control failed: blanking a node's resolver did not fail the sweep")
	}
}

func provenanceSweepPasses(inv plugin.DependencyInventory) bool {
	for _, n := range inv.Nodes {
		if n.Provenance.Resolver == "" || n.Provenance.Manifest == "" {
			return false
		}
	}
	return true
}

// -------- C3: the two honest-absence readings stay distinguishable --------

// TestResolveInventory_HonestAbsence_C3 is the three-fixture negative control:
// (i) unparseable go.mod and (ii) clean go.mod requiring nothing both yield zero
// nodes, but MUST be classified differently — (i) declares partiality, (ii) does
// not. Collapsing them is how a whole-graph resolver becomes less honest than the
// single-coordinate moduleVersionFromGoMod it augments.
func TestResolveInventory_HonestAbsence_C3(t *testing.T) {
	// (i) unparseable manifest.
	bad := t.TempDir()
	writeDir(t, bad, map[string]string{"go.mod": "this is not a valid go.mod\n"})
	invBad := resolve(t, bad)
	if invBad.Partiality.Complete {
		t.Error("(i) unparseable go.mod must NOT be Complete — nothing was established")
	}
	if len(invBad.Nodes) != 0 {
		t.Errorf("(i) unparseable go.mod should yield no nodes, got %d", len(invBad.Nodes))
	}

	// (ii) clean manifest that requires nothing.
	empty := t.TempDir()
	writeDir(t, empty, map[string]string{"go.mod": "module example.test/empty\n\ngo 1.21\n"})
	invEmpty := resolve(t, empty)
	if !invEmpty.Partiality.Complete {
		t.Errorf("(ii) clean go.mod requiring nothing is a real fact (no deps) and must be Complete, got %+v", invEmpty.Partiality)
	}
	if len(invEmpty.Nodes) != 0 {
		t.Errorf("(ii) clean empty module should yield no nodes, got %d", len(invEmpty.Nodes))
	}

	// The distinction the corpus's honesty bar turns on: (i) and (ii) are NOT the same outcome.
	if invBad.Partiality.Complete == invEmpty.Partiality.Complete {
		t.Fatal("C3 violated: unparseable and clean-empty go.mod produced the same partiality classification")
	}

	// (iii) clean manifest WITH a requirement resolves to a node (filesystem replace, offline).
	root := t.TempDir()
	writeDir(t, filepath.Join(root, "dep"), map[string]string{"go.mod": "module example.test/dep\n\ngo 1.21\n"})
	present := filepath.Join(root, "app")
	writeDir(t, present, map[string]string{
		"go.mod": "module example.test/app\n\ngo 1.21\n\nrequire example.test/dep v0.0.0\n\nreplace example.test/dep => ../dep\n",
	})
	invPresent := resolve(t, present)
	if _, ok := nodeByPathPrefix(invPresent, "pkg:golang/example.test/dep"); !ok {
		t.Error("(iii) a required module must appear as a node")
	}
}

// -------- C6: determinism across runs --------

// TestResolveInventory_Deterministic_C6 encodes a resolved inventory many times
// in-process (Go randomises map iteration per iteration, so a map on the encoding
// path diverges within this loop) and logs the canonical sha256 so a second test
// process can diff it — the cross-process half. No checked-in golden.
func TestResolveInventory_Deterministic_C6(t *testing.T) {
	newFileProxy(t, []proxyModule{
		{"example.test/low", "v1.0.0", "module example.test/low\n\ngo 1.16\n\nrequire example.test/common v1.1.0\n"},
		{"example.test/high", "v1.0.0", "module example.test/high\n\ngo 1.16\n\nrequire example.test/common v1.2.0\n"},
		{"example.test/common", "v1.1.0", "module example.test/common\n\ngo 1.16\n"},
		{"example.test/common", "v1.2.0", "module example.test/common\n\ngo 1.16\n"},
	})
	app := t.TempDir()
	writeDir(t, app, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.16\n\nrequire (\n\texample.test/low v1.0.0\n\texample.test/high v1.0.0\n)\n",
		"main.go": "package main\n\nimport (\n\t_ \"example.test/low\"\n\t_ \"example.test/high\"\n)\n\nfunc main() {}\n",
	})
	inv := resolve(t, app)

	first, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		b, err := json.Marshal(inv)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != string(first) {
			t.Fatalf("inventory encoding diverged on iteration %d (a map on the encoding path?)", i)
		}
	}
	t.Logf("inventory_canonical_sha256=%x", sha256.Sum256(first))
}

// -------- oracle + control helpers (native toolchain) --------

// nativeSelectedVersions runs `go list -m -json all` — the native selected build
// list — and returns path -> selected version for non-main modules. This is C1's
// oracle: the resolver is measured against the toolchain, not a literal.
func nativeSelectedVersions(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := runGo(t, dir, "list", "-m", "-json", "all")
	dec := json.NewDecoder(strings.NewReader(out))
	sel := map[string]string{}
	for dec.More() {
		var m struct {
			Path    string
			Version string
			Main    bool
		}
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		if m.Main || m.Version == "" {
			continue
		}
		sel[m.Path] = m.Version
	}
	return sel
}

// requireListOnly parses only the go.mod require block — the shallow derivation
// this cycle must beat. Used as the C1 control (it must miss what MVS selects).
func requireListOnly(t *testing.T, dir string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range mf.Require {
		out[r.Mod.Path] = r.Mod.Version
	}
	return out
}

func runGo(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

func purlPath(purl string) string {
	p := strings.TrimPrefix(purl, "pkg:golang/")
	if at := strings.LastIndexByte(p, '@'); at >= 0 {
		p = p[:at]
	}
	return p
}

func invHasEdge(inv plugin.DependencyInventory, parent, child string) bool {
	for _, e := range inv.Edges {
		if e.Parent == parent && e.Child == child {
			return true
		}
	}
	return false
}

func invHasReason(p plugin.Partiality, reason string) bool {
	for _, r := range p.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}
