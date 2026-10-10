package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// roundTrip exercises the full subprocess JSON protocol path: it builds a Request, runs the
// same run() the binary's main does over on-disk pipes (hermetic — no toolchain, no network),
// and decodes the Response.
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

// TestDispatch_OneRequestOneResponsePerOp round-trips every op through the subprocess protocol
// exactly once and asserts the matching response field is populated. ResolveDependencyVersions
// is Phase-0 LIVE; the graph and manifest ops are contract-present and must return the declared
// Unsupported stub, never a hard error and never a fabricated result (inv.5).
func TestDispatch_OneRequestOneResponsePerOp(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name string
		req  plugin.Request
		ok   func(plugin.Response) bool
	}{
		{"index_symbols", plugin.Request{Op: plugin.OpIndexSymbols, IndexSymbols: &plugin.IndexSymbolsRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.SymbolIndex != nil && hasReason(r.SymbolIndex.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"resolve_symbols", plugin.Request{Op: plugin.OpResolveSymbols, ResolveSymbols: &plugin.ResolveSymbolsRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.SymbolResolution != nil && hasReason(r.SymbolResolution.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"resolve_versions", plugin.Request{Op: plugin.OpResolveVersions, ResolveVersions: &plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "zlib"}},
			func(r plugin.Response) bool { return r.VersionResult != nil }},
		{"call_graph", plugin.Request{Op: plugin.OpCallGraph, CallGraph: &plugin.CallGraphRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.CallGraph != nil && hasReason(r.CallGraph.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"find_ingresses", plugin.Request{Op: plugin.OpFindIngresses, FindIngresses: &plugin.FindIngressesRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Ingress != nil && hasReason(r.Ingress.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"reachability", plugin.Request{Op: plugin.OpReachability, Reachability: &plugin.ReachabilityRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Reachability != nil && hasReason(r.Reachability.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"compute_taint", plugin.Request{Op: plugin.OpComputeTaint, ComputeTaint: &plugin.ComputeTaintRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Taint != nil && hasReason(r.Taint.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"generate_harness", plugin.Request{Op: plugin.OpGenerateHarness, GenerateHarness: &plugin.GenerateHarnessRequest{Sink: "x", Kind: "unit"}},
			func(r plugin.Response) bool {
				return r.Harness != nil && hasReason(r.Harness.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"build_manifest", plugin.Request{Op: plugin.OpBuildManifest, BuildManifest: &plugin.BuildManifestRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.BuildManifest != nil && hasReason(r.BuildManifest.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"resolve_inventory", plugin.Request{Op: plugin.OpResolveInventory, ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: dir}},
			func(r plugin.Response) bool {
				return r.Inventory != nil && hasReason(r.Inventory.Partiality.Reasons, plugin.PartialReasonUnsupported)
			}},
		{"capability_manifest", plugin.Request{Op: plugin.OpCapabilityManifest},
			func(r plugin.Response) bool {
				return r.Manifest != nil && r.Manifest.Supported && r.Manifest.Language == "cfamily"
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp := roundTrip(t, c.req)
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

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
