package main

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestDispatch_ResolveInventoryIsUnsupported pins that the newly-landed resolve_inventory
// op returns an honestly-partial DependencyInventory{Unsupported} — never an
// empty-but-Complete inventory (a zero-node Complete() would read downstream as "this
// build has no dependencies"). No whole-graph resolver exists yet.
func TestDispatch_ResolveInventoryIsUnsupported(t *testing.T) {
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
		t.Errorf("resolve_inventory must be declared Partial (Unsupported), never Complete; got %+v", resp.Inventory.Partiality)
	}
	found := false
	for _, r := range resp.Inventory.Partiality.Reasons {
		if r == plugin.PartialReasonUnsupported {
			found = true
		}
	}
	if !found {
		t.Errorf("resolve_inventory must carry the unsupported_phase1 reason; got %+v", resp.Inventory.Partiality.Reasons)
	}
	if len(resp.Inventory.Nodes) != 0 || len(resp.Inventory.Edges) != 0 {
		t.Errorf("Unsupported inventory must be empty; got %d nodes, %d edges", len(resp.Inventory.Nodes), len(resp.Inventory.Edges))
	}
}

// TestDispatch_ResolveInventoryMissingPayloadIsHardError pins that a resolve_inventory op
// with no per-op payload is a hard failure (inv.4), mirroring every other op.
func TestDispatch_ResolveInventoryMissingPayloadIsHardError(t *testing.T) {
	if _, err := dispatch(context.Background(), plugin.Request{Op: plugin.OpResolveInventory}); err == nil {
		t.Fatal("resolve_inventory with no payload must be a hard error")
	}
}
