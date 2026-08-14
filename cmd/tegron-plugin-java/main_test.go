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

// TestDispatch_ResolveInventoryIsContractPresentUnsupported asserts resolve_inventory
// is a CONTRACT-PRESENT stub through the subprocess: it returns an Inventory payload
// declaring Unsupported() — never a hard error, and never Complete() (which would
// falsely assert an empty dependency graph).
func TestDispatch_ResolveInventoryIsContractPresentUnsupported(t *testing.T) {
	resp := roundTrip(t, plugin.Request{
		Op:               plugin.OpResolveInventory,
		ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: t.TempDir()},
	})
	if resp.Inventory == nil {
		t.Fatal("missing inventory payload")
	}
	if resp.Inventory.Partiality.Complete {
		t.Error("resolve_inventory must never be Complete (would assert an empty dependency graph)")
	}
	var sawUnsupported bool
	for _, r := range resp.Inventory.Partiality.Reasons {
		if r == plugin.PartialReasonUnsupported {
			sawUnsupported = true
		}
	}
	if !sawUnsupported {
		t.Errorf("resolve_inventory must declare Unsupported; got reasons %v", resp.Inventory.Partiality.Reasons)
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
