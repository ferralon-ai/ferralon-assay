package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// roundTrip exercises the full subprocess JSON protocol path: it builds a
// Request, runs the same run() the binary's main does over on-disk pipes
// (hermetic — no container, no JDK, no network), and decodes the Response.
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

// TestDispatch_ResolveInventoryIsLive asserts resolve_inventory is LIVE through the subprocess:
// a build graph naming one dependency yields its node (never Unsupported), and a run handed no
// graph is honest-absent (Partial, never Complete over zero nodes).
func TestDispatch_ResolveInventoryIsLive(t *testing.T) {
	dir := t.TempDir()
	root := buildgraph.Node{Group: "com.example", Artifact: "app", Version: "1.0.0", Type: "jar"}
	root.ID = buildgraph.NodeID(root.Group, root.Artifact, root.Type, "", root.Version)
	gson := buildgraph.Node{Group: "com.google.code.gson", Artifact: "gson", Version: "2.10.1", Type: "pom", Scope: "compile"}
	gson.ID = buildgraph.NodeID(gson.Group, gson.Artifact, gson.Type, "", gson.Version)
	g, err := json.Marshal(buildgraph.Graph{
		Schema: buildgraph.Schema,
		Tool:   buildgraph.Tool{Name: "maven", Version: "test"},
		JVM:    buildgraph.JVM{Version: "21.0.4"},
		Modules: []buildgraph.Module{{ID: "com.example:app", Path: ".", Root: root.ID,
			Nodes: []buildgraph.Node{root, gson}, Edges: []buildgraph.Edge{{From: root.ID, To: gson.ID}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	graph := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(graph, g, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(plugin.BuildGraphEnv, graph)
	resp := roundTrip(t, plugin.Request{
		Op:               plugin.OpResolveInventory,
		ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: dir},
	})
	if resp.Inventory == nil {
		t.Fatal("missing inventory payload")
	}
	for _, r := range resp.Inventory.Partiality.Reasons {
		if r == plugin.PartialReasonUnsupported {
			t.Errorf("resolve_inventory must be LIVE, not Unsupported; got %v", resp.Inventory.Partiality.Reasons)
		}
	}
	found := false
	for _, n := range resp.Inventory.Nodes {
		if n.PURL == "pkg:maven/com.google.code.gson/gson@2.10.1?type=pom" && n.Version == "2.10.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gson@2.10.1 node; got %+v", resp.Inventory.Nodes)
	}

	// Honest-absent floor: no graph ⇒ Partial, never a Complete() over zero nodes.
	t.Setenv(plugin.BuildGraphEnv, "")
	empty := roundTrip(t, plugin.Request{
		Op:               plugin.OpResolveInventory,
		ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: t.TempDir()},
	})
	if empty.Inventory == nil || empty.Inventory.Partiality.Complete {
		t.Error("resolve_inventory over an empty build dir must be Partial, never Complete")
	}
}

// TestDispatch_ResolveInventoryNilPayload_HardError asserts a missing per-op payload
// is a hard failure (inv.4): run() returns a non-nil error and the Response carries a
// structured Error.
func TestDispatch_ResolveInventoryNilPayload_HardError(t *testing.T) {
	req := plugin.Request{Protocol: plugin.ProtocolVersion, Op: plugin.OpResolveInventory} // ResolveInventory nil
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

// TestAnalyzerGate_ReadsBrandEnv asserts the binary opens the javaanalysis Prove-path gate from its
// own env vars: unset, call_graph stays pure-Go and declares no tool_failure; set with an
// unrunnable docker binary, the gate is open and the run degrades to tool_failure. Hermetic — the
// docker lookup fails before anything is executed.
func TestAnalyzerGate_ReadsBrandEnv(t *testing.T) {
	dir := t.TempDir()
	src := "package app;\npublic class App {\n  public static void main(String[] a) { run(); }\n  static void run() {}\n}\n"
	if err := os.WriteFile(dir+"/App.java", []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	hasToolFailure := func(resp plugin.Response) bool {
		if resp.CallGraph == nil {
			t.Fatal("missing call_graph payload")
		}
		for _, r := range resp.CallGraph.Partiality.Reasons {
			if r == plugin.PartialReasonToolFailure {
				return true
			}
		}
		return false
	}
	req := plugin.Request{Op: plugin.OpCallGraph, CallGraph: &plugin.CallGraphRequest{BuildDir: dir}}

	t.Setenv(envAnalyzerImage, "")
	t.Setenv(envAnalyzerDocker, "")
	if hasToolFailure(roundTrip(t, req)) {
		t.Error("image unset: tool_failure declared, want the gate closed")
	}

	t.Setenv(envAnalyzerImage, "example.invalid/scip-java@sha256:deadbeef")
	t.Setenv(envAnalyzerDocker, "no-such-docker-binary-for-this-test")
	if !hasToolFailure(roundTrip(t, req)) {
		t.Error("image set, docker unrunnable: want tool_failure (gate open, analyzer failed)")
	}
}
