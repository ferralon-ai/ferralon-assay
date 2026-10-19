package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/plugins/cfamily/cfamilycgx"
)

// noEngine is the lane a plugin with no cgx engine configured runs.
func noEngine() *cfamilycgx.Lane {
	return cfamilycgx.Unavailable(cfamilycgx.Config{}, cfamilycgx.ErrEngineUnconfigured)
}

const reasonUnconfigured = "tool_failure:cgx_engine_unconfigured"

// roundTrip exercises the full subprocess JSON protocol path: it builds a Request, runs the
// same run() the binary's main does (hermetic — no engine, no network), and decodes the
// Response.
func roundTrip(t *testing.T, lane *cfamilycgx.Lane, req plugin.Request) plugin.Response {
	t.Helper()
	req.Protocol = plugin.ProtocolVersion
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := run(context.Background(), lane, bytes.NewReader(append(line, '\n')), &buf); err != nil {
		t.Fatalf("run returned a hard error: %v", err)
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

// TestDispatch_OneRequestOneResponsePerOp round-trips every op through the subprocess protocol
// exactly once and asserts the matching response field is populated. ResolveDependencyVersions
// and BuildManifest are live; BuildManifest on a tree with no compile DB declares no_manifest.
// With no cgx engine the graph ops declare it loudly and return no graph, never a hard error and
// never an empty-clean result (inv.5); resolve_symbols with no symbol named declares the advisory
// symbol absent without needing the engine.
func TestDispatch_OneRequestOneResponsePerOp(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name string
		req  plugin.Request
		ok   func(plugin.Response) bool
	}{
		{"index_symbols", plugin.Request{Op: plugin.OpIndexSymbols, IndexSymbols: &plugin.IndexSymbolsRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.SymbolIndex != nil && hasReason(r.SymbolIndex.Partiality.Reasons, reasonUnconfigured)
			}},
		{"resolve_symbols", plugin.Request{Op: plugin.OpResolveSymbols, ResolveSymbols: &plugin.ResolveSymbolsRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.SymbolResolution != nil && hasReason(r.SymbolResolution.Partiality.Reasons, plugin.PartialReasonAdvisorySymbolAbsent)
			}},
		{"resolve_versions", plugin.Request{Op: plugin.OpResolveVersions, ResolveVersions: &plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "zlib"}},
			func(r plugin.Response) bool { return r.VersionResult != nil }},
		{"call_graph", plugin.Request{Op: plugin.OpCallGraph, CallGraph: &plugin.CallGraphRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.CallGraph != nil && hasReason(r.CallGraph.Partiality.Reasons, reasonUnconfigured)
			}},
		{"find_ingresses", plugin.Request{Op: plugin.OpFindIngresses, FindIngresses: &plugin.FindIngressesRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Ingress != nil && hasReason(r.Ingress.Partiality.Reasons, reasonUnconfigured)
			}},
		{"reachability", plugin.Request{Op: plugin.OpReachability, Reachability: &plugin.ReachabilityRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Reachability != nil && hasReason(r.Reachability.Partiality.Reasons, reasonUnconfigured)
			}},
		{"compute_taint", plugin.Request{Op: plugin.OpComputeTaint, ComputeTaint: &plugin.ComputeTaintRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Taint != nil && hasReason(r.Taint.Partiality.Reasons, reasonUnconfigured)
			}},
		{"generate_harness", plugin.Request{Op: plugin.OpGenerateHarness, GenerateHarness: &plugin.GenerateHarnessRequest{Sink: "x", Kind: "unit"}},
			func(r plugin.Response) bool {
				return r.Harness != nil && hasReason(r.Harness.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"build_manifest", plugin.Request{Op: plugin.OpBuildManifest, BuildManifest: &plugin.BuildManifestRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.BuildManifest != nil && hasReason(r.BuildManifest.Partiality.Reasons, plugin.PartialReasonNoManifest)
			}},
		{"resolve_inventory", plugin.Request{Op: plugin.OpResolveInventory, ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Inventory != nil && !r.Inventory.Partiality.Complete && hasReason(r.Inventory.Partiality.Reasons, plugin.PartialReasonNoManifest)
			}},
		{"capability_manifest", plugin.Request{Op: plugin.OpCapabilityManifest},
			func(r plugin.Response) bool {
				return r.Manifest != nil && r.Manifest.Supported && r.Manifest.Language == "cfamily"
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp := roundTrip(t, noEngine(), c.req)
			if !c.ok(resp) {
				t.Errorf("%s: unexpected response %+v", c.name, resp)
			}
		})
	}
}

// TestDispatch_NilPayload_HardError is the nil-payload guard (inv.4): a missing per-op payload is
// a hard failure, mirroring every other lane's dispatch.
func TestDispatch_NilPayload_HardError(t *testing.T) {
	req := plugin.Request{Protocol: plugin.ProtocolVersion, Op: plugin.OpBuildManifest} // BuildManifest nil
	line, _ := json.Marshal(req)
	var buf bytes.Buffer
	if err := run(context.Background(), noEngine(), bytes.NewReader(append(line, '\n')), &buf); err == nil {
		t.Fatal("a nil per-op payload must be a hard error")
	}
	var resp plugin.Response
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Error("hard-error Response must carry a structured Error")
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

// TestNewLane_BadSetting_DeclaresUnconfigured: a malformed engine setting never stops the plugin
// and never yields an empty-clean graph; every graph op declares the engine unconfigured and the
// cause reaches stderr.
func TestNewLane_BadSetting_DeclaresUnconfigured(t *testing.T) {
	for _, env := range []string{envTransport, envMinConfidence, envFallback, envFailureTTL, envPoolSize} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "bogus")
			var stderr bytes.Buffer
			lane := newLane(&stderr)
			if !strings.Contains(stderr.String(), env) {
				t.Errorf("stderr does not name %s: %q", env, stderr.String())
			}
			resp := roundTrip(t, lane, plugin.Request{Op: plugin.OpCallGraph, CallGraph: &plugin.CallGraphRequest{BuildDir: t.TempDir()}})
			if resp.CallGraph == nil || !hasReason(resp.CallGraph.Partiality.Reasons, reasonUnconfigured) || len(resp.CallGraph.Edges) != 0 {
				t.Errorf("call_graph = %+v, want declared %s and no edges", resp.CallGraph, reasonUnconfigured)
			}
		})
	}
}

// TestNewLane_WasmPinMismatch_DeclaresMismatch: an operator pin for a module other than the one
// recorded beside the SDK version is refused as a loud mismatch, not run and not a crash. (A test
// binary records no dependency list, so the SDK half of the pin refuses first here; the order of
// the checks is covered in cfamilycgx.)
func TestNewLane_WasmPinMismatch_DeclaresMismatch(t *testing.T) {
	t.Setenv(envCacheDir, t.TempDir())
	t.Setenv(envWasm, "/nonexistent/cgx.wasm")
	t.Setenv(envWasmSHA256, strings.Repeat("0", 64))
	resp := roundTrip(t, newLane(&bytes.Buffer{}), plugin.Request{Op: plugin.OpFindIngresses, FindIngresses: &plugin.FindIngressesRequest{BuildDir: t.TempDir()}})
	if resp.Ingress == nil || !hasReason(resp.Ingress.Partiality.Reasons, "tool_failure:cgx_engine_mismatch") || len(resp.Ingress.Ingresses) != 0 {
		t.Errorf("find_ingresses = %+v, want declared cgx_engine_mismatch and no ingresses", resp.Ingress)
	}
}
