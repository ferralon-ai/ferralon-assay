package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

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
// a reactor pom.xml with a literal-pinned dependency yields a real node (never Unsupported), and
// a build dir with no manifest is honest-absent (Partial, never Complete over zero nodes).
func TestDispatch_ResolveInventoryIsLive(t *testing.T) {
	dir := t.TempDir()
	pom := `<project><modelVersion>4.0.0</modelVersion>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>com.google.code.gson</groupId>
<artifactId>gson</artifactId><version>2.10.1</version></dependency></dependencies></project>`
	if err := os.WriteFile(dir+"/pom.xml", []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
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
		if n.PURL == "pkg:maven/com.google.code.gson/gson@2.10.1" && n.Version == "2.10.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gson@2.10.1 node; got %+v", resp.Inventory.Nodes)
	}

	// Honest-absent floor: no manifest ⇒ Partial, never a Complete() over zero nodes.
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
