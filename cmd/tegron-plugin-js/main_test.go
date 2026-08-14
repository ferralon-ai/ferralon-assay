package main

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestDispatch_ResolveInventoryResolvesFixture pins that the newly-live resolve_inventory op
// (PLAN-160) round-trips a real whole-graph inventory over the dispatch seam: given a build dir
// with a lockfile, it returns a populated, Complete inventory (nodes + parent edges), not the
// former Unsupported stub.
func TestDispatch_ResolveInventoryResolvesFixture(t *testing.T) {
	const fixture = "../../internal/plugin/jsanalysis/testdata/inventory/npm-transitive"
	resp, err := dispatch(context.Background(), plugin.Request{
		Op:               plugin.OpResolveInventory,
		ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: fixture},
	})
	if err != nil {
		t.Fatalf("dispatch(resolve_inventory): unexpected hard error: %v", err)
	}
	if resp.Inventory == nil {
		t.Fatal("resolve_inventory must populate the Inventory payload")
	}
	if !resp.Inventory.Partiality.Complete {
		t.Errorf("a clean lockfile must resolve Complete; got %+v", resp.Inventory.Partiality)
	}
	if len(resp.Inventory.Nodes) == 0 || len(resp.Inventory.Edges) == 0 {
		t.Fatalf("resolve_inventory must return a populated graph; got %d nodes, %d edges",
			len(resp.Inventory.Nodes), len(resp.Inventory.Edges))
	}
	found := false
	for _, n := range resp.Inventory.Nodes {
		if n.ID == "pkg:npm/ms@2.0.0" {
			found = true
		}
	}
	if !found {
		t.Error("resolve_inventory must resolve the transitive ms@2.0.0 node")
	}
}

// TestDispatch_ResolveInventoryNoProjectIsPartial pins the honest-absence path: a build dir with
// no lockfile and no package.json declares Partial(no_manifest), never an empty-but-Complete
// inventory (a zero-node Complete() would read downstream as "this build has no dependencies").
func TestDispatch_ResolveInventoryNoProjectIsPartial(t *testing.T) {
	resp, err := dispatch(context.Background(), plugin.Request{
		Op:               plugin.OpResolveInventory,
		ResolveInventory: &plugin.ResolveInventoryRequest{BuildDir: "."},
	})
	if err != nil {
		t.Fatalf("dispatch(resolve_inventory): unexpected hard error: %v", err)
	}
	if resp.Inventory == nil {
		t.Fatal("resolve_inventory must populate the Inventory payload")
	}
	if resp.Inventory.Partiality.Complete {
		t.Errorf("a dir with no JS project must declare Partial, not Complete; got %+v", resp.Inventory.Partiality)
	}
	if len(resp.Inventory.Nodes) != 0 || len(resp.Inventory.Edges) != 0 {
		t.Errorf("a non-project inventory must be empty; got %d nodes, %d edges", len(resp.Inventory.Nodes), len(resp.Inventory.Edges))
	}
}

// TestDispatch_ResolveInventoryMissingPayloadIsHardError pins that a resolve_inventory op with
// no per-op payload is a hard failure (inv.4), mirroring every other op.
func TestDispatch_ResolveInventoryMissingPayloadIsHardError(t *testing.T) {
	if _, err := dispatch(context.Background(), plugin.Request{Op: plugin.OpResolveInventory}); err == nil {
		t.Fatal("resolve_inventory with no payload must be a hard error")
	}
}
