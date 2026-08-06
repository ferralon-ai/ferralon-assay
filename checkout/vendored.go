// internal/checkout/vendored.go
package checkout

import (
	"fmt"
	"path/filepath"
)

// ResolveVendored materializes a vendored_repro path into an absolute BuildDir with NO clone
// and NO network. relPath is the fixture's acquisition.path; the caller is responsible for
// passing an absolute or CWD-resolvable path (the live harness joins it against the corpus
// package dir). It is language-aware: the tree must present a RECOGNIZED source language
// (a Go module via go.mod, a Java source tree via .java files, OR a JS/TS source tree via
// .js/.ts files) — it returns the detected language alongside the absolute dir so the
// inventory stage routes to the matching plugin.
// A tree with no recognized source markers is an error rather than an empty partial dir
// (inv.5: no silent half-checkout). It is a free function, not a Checkout method: the
// acquisition branch happens at the call site, before any Fetch.
func ResolveVendored(relPath string) (buildDir, language string, err error) {
	if relPath == "" {
		return "", "", fmt.Errorf("checkout: vendored_repro requires a path")
	}
	abs, err := filepath.Abs(relPath)
	if err != nil {
		return "", "", fmt.Errorf("checkout: resolve %q: %w", relPath, err)
	}
	lang := DetectLanguage(abs)
	if lang == LangUnknown {
		return "", "", fmt.Errorf("checkout: vendored repro %q is not a recognized source tree (no go.mod, no .java, and no .js/.ts sources)", abs)
	}
	return abs, lang, nil
}
