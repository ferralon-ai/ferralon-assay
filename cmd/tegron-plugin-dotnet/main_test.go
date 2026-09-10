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

// fixtureDir writes a small C# tree carrying the two CVE sink shapes and a .csproj pin, then
// returns its path. It is hermetic (no scip-dotnet container, no .NET SDK, no network).
func fixtureDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"ZipEntry.cs": "namespace Ionic.Zip { public class ZipEntry { public void Extract(string dir) { } } }\n",
		"Ecdsa.cs":    "namespace EllipticCurve;\npublic static class Ecdsa { public static bool Verify(string m, string s, string k) { return false; } }\n",
		"App.csproj":  "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><PackageReference Include=\"DotNetZip\" Version=\"1.16.0\" /></ItemGroup></Project>\n",
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

// roundTrip exercises the full subprocess JSON protocol path: it builds a Request, runs the
// same run() the binary's main does over on-disk pipes (hermetic), and decodes the Response.
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
		if s.DisplayName == "ZipEntry.Extract(1)" {
			sawSink = true
		}
	}
	if !sawSink {
		t.Errorf("expected the ZipEntry.Extract sink through the subprocess; got %+v", resp.SymbolIndex.Symbols)
	}
}

func TestDispatch_ResolveSymbolsRoundTrip(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{
		Op:             plugin.OpResolveSymbols,
		ResolveSymbols: &plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"Ionic.Zip.ZipEntry.Extract"}},
	})
	if resp.SymbolResolution == nil {
		t.Fatal("missing symbol_resolution payload")
	}
	if len(resp.SymbolResolution.Resolved) == 0 {
		t.Errorf("expected Ionic.Zip.ZipEntry.Extract to resolve through the subprocess; got %+v", resp.SymbolResolution)
	}
}

func TestDispatch_ResolveVersionsRoundTrip(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{
		Op:              plugin.OpResolveVersions,
		ResolveVersions: &plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "DotNetZip"},
	})
	if resp.VersionResult == nil {
		t.Fatal("missing version_result payload")
	}
	if !resp.VersionResult.Found || !resp.VersionResult.Match.Resolved || resp.VersionResult.Match.Version != "1.16.0" {
		t.Errorf("expected DotNetZip 1.16.0 resolved through the subprocess; got %+v", resp.VersionResult)
	}
}

// batch-2 promotes call_graph, find_ingresses, reachability, and compute_taint to live lexical
// analysis; build_manifest is now LIVE too (see TestDispatch_BuildManifestIsLive). generate_harness
// stays CONTRACT-PRESENT Unsupported (Prove-tier): it must return the Unsupported stub, never a hard
// error.
func TestDispatch_ContractPresentUnsupportedOps(t *testing.T) {
	for _, c := range []struct {
		name string
		req  plugin.Request
		ok   func(plugin.Response) []string
	}{
		{"generate_harness", plugin.Request{Op: plugin.OpGenerateHarness, GenerateHarness: &plugin.GenerateHarnessRequest{Sink: "x", Kind: "unit"}},
			func(r plugin.Response) []string { return reasons(r.Harness) }},
	} {
		resp := roundTrip(t, c.req)
		if !hasReason(c.ok(resp), plugin.PartialReasonUnsupported) {
			t.Errorf("%s must be CONTRACT-PRESENT Unsupported this pass; got reasons %v", c.name, c.ok(resp))
		}
	}
}

// build_manifest is LIVE through the subprocess (PLAN-151): the flat, ecosystem-neutral manifest is
// derived lexically from the checkout and returned populated — no longer Unsupported. The fixtureDir
// carries a .csproj with no restore output, so the honest result names its partiality (e.g.
// no_lockfile) while stamping the dotnet Resolver identity; it is never Unsupported and never a hard
// error. Mirrors how PLAN-150 turned the ResolveInventory dispatch test into a live assertion.
func TestDispatch_BuildManifestIsLive(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpBuildManifest, BuildManifest: &plugin.BuildManifestRequest{BuildDir: dir}})
	if resp.BuildManifest == nil {
		t.Fatal("missing build_manifest payload")
	}
	if hasReason(resp.BuildManifest.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Errorf("build_manifest must be LIVE, not Unsupported; got %v", resp.BuildManifest.Partiality.Reasons)
	}
	if resp.BuildManifest.Resolver.Name != "dotnet" {
		t.Errorf("build_manifest must stamp the dotnet resolver; got Resolver.Name=%q", resp.BuildManifest.Resolver.Name)
	}
	if resp.BuildManifest.Runtime.Name != "dotnet" {
		t.Errorf("build_manifest must return a populated result (Runtime.Name=dotnet); got %q", resp.BuildManifest.Runtime.Name)
	}
}

// call_graph is LIVE through the subprocess: the C# lexical graph is ALWAYS declared
// Partial(dynamic_dispatch) (interface/virtual/DI dispatch the lexer cannot resolve), never
// Unsupported and never Complete.
func TestDispatch_CallGraphRoundTripIsPartial(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpCallGraph, CallGraph: &plugin.CallGraphRequest{BuildDir: dir}})
	if resp.CallGraph == nil {
		t.Fatal("missing call_graph payload")
	}
	if resp.CallGraph.Partiality.Complete {
		t.Error("C# call_graph must never be Complete")
	}
	if !hasReason(resp.CallGraph.Partiality.Reasons, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("call_graph must carry dynamic_dispatch; got %v", resp.CallGraph.Partiality.Reasons)
	}
	if hasReason(resp.CallGraph.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Errorf("call_graph must be LIVE, not Unsupported; got %v", resp.CallGraph.Partiality.Reasons)
	}
}

// find_ingresses is LIVE through the subprocess: it detects an ASP.NET controller action and
// declares ingress discovery Complete on a clean parse (never Unsupported).
func TestDispatch_FindIngressesRoundTripIsLive(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "C.cs"),
		[]byte("using Microsoft.AspNetCore.Mvc;\nnamespace W { public class Ctl { [HttpGet] public string Go() { return \"\"; } } }\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	resp := roundTrip(t, plugin.Request{Op: plugin.OpFindIngresses, FindIngresses: &plugin.FindIngressesRequest{BuildDir: root}})
	if resp.Ingress == nil {
		t.Fatal("missing find_ingresses payload")
	}
	if hasReason(resp.Ingress.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Errorf("find_ingresses must be LIVE, not Unsupported; got %v", resp.Ingress.Partiality.Reasons)
	}
	if len(resp.Ingress.Ingresses) != 1 || resp.Ingress.Ingresses[0].Kind != "http_route" {
		t.Errorf("expected one http_route ingress; got %+v", resp.Ingress.Ingresses)
	}
}

// reachability is LIVE through the subprocess and ALWAYS Partial(dynamic_dispatch), never
// Unsupported and never Complete (C# static reachability is structurally weak).
func TestDispatch_ReachabilityRoundTripIsAlwaysPartial(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpReachability, Reachability: &plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"x"}}})
	if resp.Reachability == nil {
		t.Fatal("missing reachability payload")
	}
	if resp.Reachability.Partiality.Complete {
		t.Error("C# reachability must never be Complete")
	}
	if !hasReason(resp.Reachability.Partiality.Reasons, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("reachability must carry dynamic_dispatch; got %v", resp.Reachability.Partiality.Reasons)
	}
	if hasReason(resp.Reachability.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Errorf("reachability must be LIVE, not Unsupported; got %v", resp.Reachability.Partiality.Reasons)
	}
}

// resolve_inventory is LIVE through the subprocess (PLAN-150): the .NET whole-graph resolver
// runs over the checkout files and returns real data — no longer Unsupported. The fixtureDir
// carries a .csproj (declared DotNetZip pin) but no restore output, so the honest result is the
// declared-text tier: a populated DotNetZip node under Partial(no_resolver_output, no_lockfile),
// never Unsupported, never a hard error, never a Complete zero-node graph.
func TestDispatch_ResolveInventoryIsLive(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{Op: plugin.OpResolveInventory, ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: dir}})
	if resp.Inventory == nil {
		t.Fatal("missing inventory payload")
	}
	if hasReason(resp.Inventory.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Errorf("resolve_inventory must be LIVE, not Unsupported; got %v", resp.Inventory.Partiality.Reasons)
	}
	if len(resp.Inventory.Nodes) == 0 {
		t.Fatal("resolve_inventory must return real data — the declared DotNetZip pin")
	}
	found := false
	for _, n := range resp.Inventory.Nodes {
		if n.PURL == "pkg:nuget/dotnetzip@1.16.0" && n.Version == "1.16.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a DotNetZip@1.16.0 node; got %+v", resp.Inventory.Nodes)
	}
}

// A missing per-op payload is a hard failure (inv.4): run() returns a non-nil error and the
// Response carries a structured Error.
func TestDispatch_NilPayload_HardError(t *testing.T) {
	req := plugin.Request{Protocol: plugin.ProtocolVersion, Op: plugin.OpIndexSymbols} // IndexSymbols nil
	line, _ := json.Marshal(req)
	in, _ := os.CreateTemp(t.TempDir(), "in")
	_, _ = in.Write(append(line, '\n'))
	_, _ = in.Seek(0, 0)
	out, _ := os.CreateTemp(t.TempDir(), "out")
	if err := run(context.Background(), in, out); err == nil {
		t.Fatal("a nil per-op payload must be a hard error")
	}
	_, _ = out.Seek(0, 0)
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(out)
	var resp plugin.Response
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Error("hard-error Response must carry a structured Error")
	}
}

// reasons extracts the partiality reason codes from any result payload carrying a Partiality
// field, via a tiny type switch.
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
