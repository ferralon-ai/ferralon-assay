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

// generate_harness and build_manifest stay CONTRACT-PRESENT Unsupported: the Python effect
// rides the corpus repro-runtime sandbox, so the plugin never scaffolds a harness.
func TestDispatch_HarnessOps_Unsupported(t *testing.T) {
	dir := fixtureDir(t)
	for _, c := range []struct {
		name string
		req  plugin.Request
		ok   func(plugin.Response) []string
	}{
		{"generate_harness", plugin.Request{Op: plugin.OpGenerateHarness, GenerateHarness: &plugin.GenerateHarnessRequest{Sink: "x", Kind: "unit"}},
			func(r plugin.Response) []string { return reasons(r.Harness) }},
		{"build_manifest", plugin.Request{Op: plugin.OpBuildManifest, BuildManifest: &plugin.BuildManifestRequest{BuildDir: dir}},
			func(r plugin.Response) []string { return reasons(r.BuildManifest) }},
	} {
		resp := roundTrip(t, c.req)
		if !hasReason(c.ok(resp), plugin.PartialReasonUnsupported) {
			t.Errorf("%s must stay CONTRACT-PRESENT Unsupported; got reasons %v", c.name, c.ok(resp))
		}
	}
}

// resolve_inventory stays CONTRACT-PRESENT Unsupported: Python has no whole-graph
// dependency resolver, so the op returns an honestly-partial inventory (Complete=false,
// unsupported_phase1) — NEVER an empty-but-successful one, which would read downstream as
// "this build has no dependencies".
func TestDispatch_ResolveInventory_Unsupported(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpResolveInventory, ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: dir}})
	if resp.Inventory == nil {
		t.Fatal("missing inventory payload")
	}
	if resp.Inventory.Partiality.Complete {
		t.Errorf("resolve_inventory must be honestly partial, never an empty-but-Complete inventory; got %+v", resp.Inventory.Partiality)
	}
	if !hasReason(resp.Inventory.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Errorf("resolve_inventory must carry unsupported_phase1; got %v", resp.Inventory.Partiality.Reasons)
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
