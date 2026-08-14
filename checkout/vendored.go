// internal/checkout/vendored.go
package checkout

import (
	"fmt"
	"path/filepath"
)

// ResolveVendored materializes a vendored_repro path into an absolute BuildDir with NO clone
// and NO network. relPath is the fixture's acquisition.path; the caller is responsible for
// passing an absolute or CWD-resolvable path (the live harness joins it against the corpus
// package dir). It is language-aware: the tree must present a RECOGNIZED source language —
// a Go module (go.mod), a Java source tree (.java), a JS/TS source tree (.js/.ts and
// friends), a Python source tree (.py), or a .NET source tree (.cs/.csproj) — it returns a
// single-project WorkspacePlan (the absolute dir + detected
// language) so the vendored_repro path stays shape-identical to GitCheckout.Fetch and the
// inventory stage routes to the matching plugin.
// A tree with no recognized source markers is an error rather than an empty plan
// (inv.5: no silent half-checkout). It is a free function, not a Checkout method: the
// acquisition branch happens at the call site, before any Fetch.
func ResolveVendored(relPath string) (WorkspacePlan, error) {
	if relPath == "" {
		return WorkspacePlan{}, fmt.Errorf("checkout: vendored_repro requires a path")
	}
	abs, err := filepath.Abs(relPath)
	if err != nil {
		return WorkspacePlan{}, fmt.Errorf("checkout: resolve %q: %w", relPath, err)
	}
	lang := DetectLanguage(abs)
	if lang == LangUnknown {
		return WorkspacePlan{}, fmt.Errorf("checkout: vendored repro %q is not a recognized source tree (no go.mod, no .java, no .js/.ts, no .py, and no .cs/.csproj sources)", abs)
	}
	return singleProjectPlan(abs, lang), nil
}
