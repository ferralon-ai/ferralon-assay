// internal/checkout/checkout_test.go
package checkout

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFakeCheckoutResolvesFixture(t *testing.T) {
	root, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	fc := FakeCheckout{
		FixtureRoot: root,
		Map:         map[string]string{"example.com/repo@v1": "gomod-fixture"},
	}
	plan, err := fc.Fetch(context.Background(), "example.com/repo", "v1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	prim := plan.Primary()
	dir, lang := prim.Root, prim.Language
	if !filepath.IsAbs(dir) {
		t.Fatalf("Fetch must return an absolute path, got %q", dir)
	}
	if lang != LangGo {
		t.Fatalf("a go.mod fixture must detect as %q, got %q", LangGo, lang)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("BuildDir must contain go.mod: %v", err)
	}
}

func TestFakeCheckoutMissingFixtureIsError(t *testing.T) {
	fc := FakeCheckout{FixtureRoot: "testdata"}
	if _, err := fc.Fetch(context.Background(), "unknown", "rev"); err == nil {
		t.Fatal("Fetch of an unmapped repo@rev must error, never return an empty plan (inv.5)")
	}
}
