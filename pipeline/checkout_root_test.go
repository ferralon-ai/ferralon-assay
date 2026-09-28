package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// TestInventoryRecordsCheckoutRoot is the F39/TEG-064 port: codebase_inventory must persist the
// checkout root, readable back via InventoryCheckoutRoot. For the non-nested tree this module
// supports (there is no nested Go-module reassignment here — TEG-062 is out of scope), the checkout
// root is exactly the BuildDir, so the two accessors must agree. This mirrors the source commit's
// non-nested control assertion (InventoryCheckoutRoot == InventoryBuildDir).
func TestInventoryRecordsCheckoutRoot(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-checkout-root", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/repo", Revision: "v1"},
	}}
	fc := checkout.FakeCheckout{
		FixtureRoot: "../checkout/testdata",
		Map:         map[string]string{"example.com/repo@v1": "gomod-fixture"},
	}
	stage := codebaseInventory{checkout: fc}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run: %v", err)
	}

	got, err := InventoryCheckoutRoot(store, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("inventory must record the checkout root")
	}
	buildDir, err := InventoryBuildDir(store, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != buildDir {
		t.Fatalf("InventoryCheckoutRoot = %q, want %q (equal to BuildDir for a non-nested tree)", got, buildDir)
	}
}
