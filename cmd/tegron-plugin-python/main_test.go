package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fixtureDir writes a small Python tree carrying two of the target sink shapes and
// a requirements.txt pin, then returns its path. It is hermetic (no scip-python
// container, no network).
func fixtureDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"local_python_executor.py": "def evaluate_python_code(code, static_tools, custom_tools):\n    return eval(code)\n",
		"deepdiff/delta.py":        "class Delta:\n    def __init__(self, diff):\n        self.diff = diff\n",
		"requirements.txt":         "deepdiff==8.0.1\nflask>=2.0\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// roundTrip exercises the full subprocess JSON protocol path: it builds a Request, runs
// the same run() the binary's main does over on-disk pipes (hermetic), and decodes the
// Response.
func roundTrip(t *testing.T, req plugin.Request) plugin.Response {
	t.Helper()
	req.Protocol = plugin.ProtocolVersion
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.CreateTemp(t.TempDir(), "in")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), in, out); err != nil {
		t.Fatalf("run returned a hard error: %v", err)
	}
	if _, err := out.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(out); err != nil {
		t.Fatal(err)
	}
	var resp plugin.Response
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("decode response: %v\nraw: %s", err, buf.String())
	}
	if resp.Error != "" {
		t.Fatalf("response carried a hard error: %s", resp.Error)
	}
	return resp
}

func TestDispatch_IndexSymbolsRoundTrip(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpIndexSymbols, IndexSymbols: &plugin.IndexSymbolsRequest{BuildDir: dir}})
	if resp.SymbolIndex == nil {
		t.Fatal("missing symbol_index payload")
	}
	var sawSink bool
	for _, s := range resp.SymbolIndex.Symbols {
		if s.DisplayName == "evaluate_python_code(3)" {
			sawSink = true
		}
	}
	if !sawSink {
		t.Errorf("expected the evaluate_python_code sink through the subprocess; got %+v", resp.SymbolIndex.Symbols)
	}
}

func TestDispatch_ResolveSymbolsRoundTrip(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{
		Op:             plugin.OpResolveSymbols,
		ResolveSymbols: &plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"deepdiff.delta.Delta"}},
	})
	if resp.SymbolResolution == nil {
		t.Fatal("missing symbol_resolution payload")
	}
	if len(resp.SymbolResolution.Resolved) == 0 {
		t.Errorf("expected deepdiff.delta.Delta to resolve through the subprocess; got %+v", resp.SymbolResolution)
	}
}

func TestDispatch_ResolveVersionsRoundTrip(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{
		Op:              plugin.OpResolveVersions,
		ResolveVersions: &plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "deepdiff"},
	})
	if resp.VersionResult == nil {
		t.Fatal("missing version_result payload")
	}
	if !resp.VersionResult.Found || !resp.VersionResult.Match.Resolved || resp.VersionResult.Match.Version != "8.0.1" {
		t.Errorf("expected deepdiff==8.0.1 resolved through the subprocess; got %+v", resp.VersionResult)
	}
}

// The reachability-slice ops (call_graph, find_ingresses, reachability, compute_taint) are
// now LIVE through the subprocess: they return a real result, never the Unsupported stub.
// call_graph/reachability/compute_taint always carry dynamic_dispatch (Python is
// structurally weak); find_ingresses is LIVE and Complete on a route-free fixture.
func TestDispatch_ReachabilitySliceOps_Live(t *testing.T) {
	dir := fixtureDir(t)
	for _, c := range []struct {
		name string
		req  plugin.Request
		ok   func(plugin.Response) []string
	}{
		{"call_graph", plugin.Request{Op: plugin.OpCallGraph, CallGraph: &plugin.CallGraphRequest{BuildDir: dir}},
			func(r plugin.Response) []string { return reasons(r.CallGraph) }},
		{"reachability", plugin.Request{Op: plugin.OpReachability, Reachability: &plugin.ReachabilityRequest{BuildDir: dir}},
			func(r plugin.Response) []string { return reasons(r.Reachability) }},
		{"compute_taint", plugin.Request{Op: plugin.OpComputeTaint, ComputeTaint: &plugin.ComputeTaintRequest{BuildDir: dir}},
			func(r plugin.Response) []string { return reasons(r.Taint) }},
	} {
		resp := roundTrip(t, c.req)
		rs := c.ok(resp)
		if hasReason(rs, plugin.PartialReasonUnsupported) {
			t.Errorf("%s must be LIVE, not the Unsupported stub; got reasons %v", c.name, rs)
		}
		if !hasReason(rs, plugin.PartialReasonDynamicDispatch) {
			t.Errorf("%s must carry the standing dynamic_dispatch reason; got %v", c.name, rs)
		}
	}

	// find_ingresses is LIVE: a route-free fixture reports Complete (no Unsupported stub).
	resp := roundTrip(t, plugin.Request{Op: plugin.OpFindIngresses, FindIngresses: &plugin.FindIngressesRequest{BuildDir: dir}})
	if resp.Ingress == nil {
		t.Fatal("missing ingress payload")
	}
	if hasReason(resp.Ingress.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Errorf("find_ingresses must be LIVE, not the Unsupported stub; got %v", resp.Ingress.Partiality.Reasons)
	}
	if !resp.Ingress.Partiality.Complete {
		t.Errorf("find_ingresses on a route-free fixture must be Complete; got %+v", resp.Ingress.Partiality)
	}
}

// generate_harness stays CONTRACT-PRESENT Unsupported: the Python effect rides the corpus
// repro-runtime sandbox, so the plugin never scaffolds a harness. It appears in no §5.4
// deliverable, so it is out of PLAN-173's scope and unchanged.
func TestDispatch_GenerateHarness_Unsupported(t *testing.T) {
	resp := roundTrip(t, plugin.Request{Op: plugin.OpGenerateHarness, GenerateHarness: &plugin.GenerateHarnessRequest{Sink: "x", Kind: "unit"}})
	if !hasReason(reasons(resp.Harness), plugin.PartialReasonUnsupported) {
		t.Errorf("generate_harness must stay CONTRACT-PRESENT Unsupported; got reasons %v", reasons(resp.Harness))
	}
}

// build_manifest is LIVE (PLAN-173): over the subprocess protocol it derives the build
// context from declared metadata. The fixture declares only requirements.txt (no
// requires-python, no lockfile python constraint), so the interpreter version is
// undeterminable — the op returns a PARTIAL manifest naming the missing input, never
// Unsupported() and never a guessed version, with the pip resolver still detected.
func TestDispatch_BuildManifest_LivePartial(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpBuildManifest, BuildManifest: &plugin.BuildManifestRequest{BuildDir: dir}})
	if resp.BuildManifest == nil {
		t.Fatal("missing build_manifest payload")
	}
	if hasReason(reasons(resp.BuildManifest), plugin.PartialReasonUnsupported) {
		t.Fatalf("build_manifest must no longer be Unsupported (PLAN-173); got reasons %v", reasons(resp.BuildManifest))
	}
	if resp.BuildManifest.Partiality.Complete {
		t.Errorf("build_manifest over a fixture with no requires-python must be partial; got %+v", resp.BuildManifest.Partiality)
	}
	if !hasReason(reasons(resp.BuildManifest), plugin.PartialReasonEnvConditionUnresolved+":requires_python") {
		t.Errorf("partial reason must name the missing requires_python input; got %v", reasons(resp.BuildManifest))
	}
	if resp.BuildManifest.Runtime.Version != "" {
		t.Errorf("Runtime.Version = %q, want empty (undeterminable, never guessed)", resp.BuildManifest.Runtime.Version)
	}
	if resp.BuildManifest.Resolver.Name != "pip" {
		t.Errorf("Resolver.Name = %q, want pip (requirements.txt detected)", resp.BuildManifest.Resolver.Name)
	}
	if resp.BuildManifest.ProjectRoot != dir {
		t.Errorf("ProjectRoot = %q, want %q", resp.BuildManifest.ProjectRoot, dir)
	}
}

// resolve_inventory is LIVE (PLAN-170): it resolves the selected whole-graph inventory from the
// build dir's declared manifests, over the one-shot subprocess protocol. The fixture requirements
// file pins deepdiff (== -> resolved) and ranges flask (>= -> fail-open UNRESOLVED). Assert the
// round-trip yields a populated, graph-level-Complete inventory with the pinned node carrying its
// exact PURL@version and the ranged node present but unresolved (never fabricated to a version).
func TestDispatch_ResolveInventory_Live(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpResolveInventory, ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: dir}})
	if resp.Inventory == nil {
		t.Fatal("missing inventory payload")
	}
	if !resp.Inventory.Partiality.Complete {
		t.Errorf("resolve_inventory over a parseable manifest must be graph-level Complete; got %+v", resp.Inventory.Partiality)
	}

	byPURL := map[string]plugin.DependencyNode{}
	byName := map[string]plugin.DependencyNode{}
	for _, n := range resp.Inventory.Nodes {
		byPURL[n.PURL] = n
		byName[n.ID] = n
	}
	if _, ok := byPURL["pkg:pypi/deepdiff@8.0.1"]; !ok {
		t.Errorf("pinned deepdiff missing its exact PURL@version; nodes=%+v", resp.Inventory.Nodes)
	}
	var flask *plugin.DependencyNode
	for i := range resp.Inventory.Nodes {
		if resp.Inventory.Nodes[i].PURL == "pkg:pypi/flask" {
			flask = &resp.Inventory.Nodes[i]
		}
	}
	if flask == nil {
		t.Fatalf("ranged flask absent; a fail-open UNRESOLVED node must not be dropped; nodes=%+v", resp.Inventory.Nodes)
	}
	if flask.Version != "" {
		t.Errorf("ranged flask fabricated a version %q; fail-open must leave it empty", flask.Version)
	}
}

// reasons extracts the partiality reason codes from any result payload carrying a
// Partiality field, via a tiny type switch.
func reasons(payload any) []string {
	switch p := payload.(type) {
	case *plugin.CallGraphResult:
		return p.Partiality.Reasons
	case *plugin.IngressResult:
		return p.Partiality.Reasons
	case *plugin.ReachabilityResult:
		return p.Partiality.Reasons
	case *plugin.TaintResult:
		return p.Partiality.Reasons
	case *plugin.HarnessResult:
		return p.Partiality.Reasons
	case *plugin.BuildManifestResult:
		return p.Partiality.Reasons
	case *plugin.DependencyInventory:
		return p.Partiality.Reasons
	}
	return nil
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
