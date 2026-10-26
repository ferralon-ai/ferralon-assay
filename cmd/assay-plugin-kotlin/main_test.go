package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A graph the host accepted that no longer decodes fails the request; it is never an absent
// graph.
func TestRun_UndecodableGraphIsAnError(t *testing.T) {
	graph := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(graph, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(plugin.BuildGraphEnv, graph)
	line, err := json.Marshal(plugin.Request{Protocol: plugin.ProtocolVersion, Op: plugin.OpResolveInventory,
		ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: t.TempDir()}})
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
	if err := run(context.Background(), in, out); err == nil {
		t.Fatal("an undecodable build graph must be a hard error")
	}
}
