//go:build live

// internal/checkout/git_live_test.go
package checkout

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestGitCheckoutClonesShallow is OPT-IN (build tag `live`); it shells out to real git and the
// network, so it is excluded from the default `go test ./...` run.
func TestGitCheckoutClonesShallow(t *testing.T) {
	if !GitAvailable() {
		t.Skip("git not available")
	}
	gc := NewGitCheckout()
	dir, lang, err := gc.Fetch(context.Background(), "https://github.com/golang/example", "master")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer os.RemoveAll(dir)
	if lang != LangGo {
		t.Fatalf("golang/example must detect as %q, got %q", LangGo, lang)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		t.Fatalf("expected a real checkout at %q: %v", dir, err)
	}
}
