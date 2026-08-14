package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fixtureDir is the hermetic multi-package fixture module shared with the
// goanalysis tests, resolved relative to this package's directory.
func fixtureDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "internal", "plugin", "goanalysis", "testdata", "fixturemod"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "go.mod")); err != nil {
		t.Fatalf("fixture go.mod not found at %s: %v", abs, err)
	}
	return abs
}

// taintFixtureDir is the value-flow taint fixture (an http handler whose
// attacker-controlled request data reaches Sink), used to prove a real taint
// path travels end-to-end through the subprocess protocol.
func taintFixtureDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "internal", "plugin", "goanalysis", "testdata", "taintmod"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "go.mod")); err != nil {
		t.Fatalf("taint fixture go.mod not found at %s: %v", abs, err)
	}
	return abs
}

// roundTrip exercises the full subprocess JSON protocol path: it builds a
// Request, runs the same run() the binary's main does over in-memory pipes
// (hermetic — no net/Docker/govulncheck), and decodes the Response.
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

func TestDispatch_ComputeTaintRoundTrip(t *testing.T) {
	// Use the value-flow taint fixture: its http handler forwards attacker-
	// controlled request data to Sink, so variable-level taint produces a real
	// source->sink path (the multi-package fixturemod reaches Sink only via
	// literals, which value-flow taint correctly does NOT report).
	dir := taintFixtureDir(t)
	// Resolve the real Sink SCIP via the call_graph op, then trace toward it.
	cgResp := roundTrip(t, plugin.Request{Op: plugin.OpCallGraph, CallGraph: &plugin.CallGraphRequest{BuildDir: dir}})
	if cgResp.CallGraph == nil {
		t.Fatal("missing call_graph payload")
	}
	var sink string
	for _, e := range cgResp.CallGraph.Edges {
		if strings.Contains(e.Callee.SCIP, "Sink") {
			sink = e.Callee.SCIP
		}
	}
	if sink == "" {
		t.Fatal("could not resolve Sink SCIP from call graph")
	}

	resp := roundTrip(t, plugin.Request{
		Op:           plugin.OpComputeTaint,
		ComputeTaint: &plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}},
	})
	if resp.Taint == nil {
		t.Fatal("missing taint payload")
	}
	if len(resp.Taint.Paths) == 0 {
		t.Errorf("expected a taint path to Sink through the subprocess; got %+v", resp.Taint)
	}
	if hasReason(resp.Taint.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Error("taint must no longer be Unsupported through the subprocess")
	}
	if !resp.Taint.Partiality.Complete {
		t.Errorf("a fully-resolved clean value-flow path must be NON-Partial through the subprocess; got %+v", resp.Taint.Partiality)
	}
}

func TestDispatch_GenerateHarnessRoundTrip(t *testing.T) {
	resp := roundTrip(t, plugin.Request{
		Op: plugin.OpGenerateHarness,
		GenerateHarness: &plugin.GenerateHarnessRequest{
			Sink: "scip-go gomod tegron.test/fixturemod . tegron.test/fixturemod/util/Sink().",
			Kind: "unit",
		},
	})
	if resp.Harness == nil {
		t.Fatal("missing harness payload")
	}
	if resp.Harness.Source == "" || !resp.Harness.Skeleton {
		t.Errorf("expected a skeleton with source through the subprocess; got %+v", resp.Harness)
	}
	if hasReason(resp.Harness.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Error("harness must no longer be Unsupported through the subprocess")
	}
}

func TestDispatch_BuildManifestRoundTrip(t *testing.T) {
	dir := fixtureDir(t)
	resp := roundTrip(t, plugin.Request{
		Op:            plugin.OpBuildManifest,
		BuildManifest: &plugin.BuildManifestRequest{BuildDir: dir},
	})
	if resp.BuildManifest == nil {
		t.Fatal("missing build_manifest payload")
	}
	m := resp.BuildManifest
	if m.ProjectRoot != "tegron.test/fixturemod" || m.Resolver.Command != "go build ./..." || !m.Partiality.Complete {
		t.Errorf("expected a complete single-module manifest through the subprocess; got %+v", m)
	}
	if m.Runtime.Name != "go" {
		t.Errorf("Runtime.Name = %q, want \"go\"", m.Runtime.Name)
	}
	if hasReason(m.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Error("manifest must no longer be Unsupported through the subprocess")
	}
}

// TestDispatch_ResolveInventoryWired asserts PLAN-102's contract through the
// subprocess: the whole-graph resolver is implemented (no longer the Unsupported
// stub) and resolves the SELECTED graph of the fixture module. fixturemod declares
// no external dependencies, so the honest outcome is a Complete() zero-node
// inventory ("this build genuinely has no dependencies", C3 case (ii)) — NOT a
// declared-Unsupported graph, and NOT a fabricated node.
func TestDispatch_ResolveInventoryWired(t *testing.T) {
	resp := roundTrip(t, plugin.Request{
		Op:               plugin.OpResolveInventory,
		ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: fixtureDir(t)},
	})
	if resp.Inventory == nil {
		t.Fatal("missing inventory payload")
	}
	if hasReason(resp.Inventory.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Error("Go inventory must no longer be Unsupported through the subprocess (PLAN-102 implements it)")
	}
	if !resp.Inventory.Partiality.Complete {
		t.Errorf("fixturemod has no external deps; inventory must be Complete, got %v", resp.Inventory.Partiality.Reasons)
	}
	if len(resp.Inventory.Nodes) != 0 {
		t.Errorf("fixturemod has no external deps; want zero nodes, got %d", len(resp.Inventory.Nodes))
	}
}

// TestDispatch_ResolveInventoryNilPayloadFailsClosed asserts the whole-graph resolver op hard-fails
// when the request carries no payload, exactly like every other op — never a success response
// synthesized from a missing request (inv.4).
func TestDispatch_ResolveInventoryNilPayloadFailsClosed(t *testing.T) {
	_, err := dispatch(context.Background(), plugin.Request{Op: plugin.OpResolveInventory})
	if err == nil {
		t.Fatal("expected a hard error for a nil resolve_inventory payload, got a success response")
	}
	if !strings.Contains(err.Error(), "missing resolve_inventory request") {
		t.Errorf("error = %q, want it to name the missing resolve_inventory request", err)
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
