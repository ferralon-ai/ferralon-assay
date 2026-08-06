// internal/checkout/checkout.go
package checkout

import (
	"context"
	"fmt"
	"path/filepath"
)

// Checkout materializes a Case's source at a revision into a local BuildDir. It is injected into
// codebase_inventory behind pipeline.WithCheckout (mirroring WithPlugin/WithSandbox). The default
// is a hermetic FakeCheckout resolving to a local fixture; GitCheckout is the real impl, exercised
// only by a live-gated e2e test.
type Checkout interface {
	// Fetch materializes repo@revision into a directory and returns its absolute path (the
	// BuildDir) plus the detected source language ("go" | "java"). The BuildDir is the source
	// root (a Go module root containing go.mod, or a Java source tree). It returns an error
	// rather than an empty partial dir on failure (inv.5: no silent half-checkout).
	Fetch(ctx context.Context, repo, revision string) (buildDir, language string, err error)
}

// FakeCheckout is the hermetic default: it maps (repo, revision) to a subdirectory under
// FixtureRoot. No network, no git. If the fixture is absent it returns an error (never an empty
// dir). When Map has no entry for "repo@revision", it falls back to treating the revision-less
// repo basename as the subdir, then errors if that path is absent.
type FakeCheckout struct {
	FixtureRoot string            // directory holding fixture module roots
	Map         map[string]string // "repo@revision" -> subdir under FixtureRoot
}

var _ Checkout = FakeCheckout{}

// Fetch resolves the fixture subdir for repo@revision and returns its absolute path and the
// detected source language. The fixture must present a recognized source tree (Go module or
// Java sources); an unrecognized tree is an error, never an empty dir (inv.5).
func (f FakeCheckout) Fetch(_ context.Context, repo, revision string) (string, string, error) {
	key := repo + "@" + revision
	sub, ok := f.Map[key]
	if !ok {
		return "", "", fmt.Errorf("checkout: no fixture mapped for %q", key)
	}
	dir := filepath.Join(f.FixtureRoot, sub)
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", fmt.Errorf("checkout: resolve %q: %w", dir, err)
	}
	lang := DetectLanguage(abs)
	if lang == LangUnknown {
		return "", "", fmt.Errorf("checkout: fixture %q is not a recognized source tree (no go.mod and no .java sources)", abs)
	}
	return abs, lang, nil
}
