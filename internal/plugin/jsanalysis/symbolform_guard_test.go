package jsanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestJsSymbolMatches_IntelVerbatimNpmFormsConsumable locks the promise this repo makes to
// whoever populates the advisory corpus: *verbatim-from-source* symbol identifiers for an
// npm-scheme (JS/TS) advisory are directly consumable by jsSymbolMatches's DisplayName +
// module-qualified + bare-leaf + arity-tolerant comparison (ingress.go:112) — NEVER a
// SCIP-qualified string. Characterization/guard test: pins current behavior, does not change it.
// Hermetic (no toolchain, no parsed program — hand-built plugin.Symbol).
func TestJsSymbolMatches_IntelVerbatimNpmFormsConsumable(t *testing.T) {
	sym := plugin.Symbol{
		SCIP:        "scip-js npm util 1.0.0 fetcher/fetchUrl().",
		DisplayName: "fetchUrl",
		Package:     "util/fetcher",
	}

	// Representative verbatim-from-source forms (doc.go's JS/TS row): module-path-qualified,
	// module-leaf-qualified, the bare leaf, and the arity-tolerant form.
	for _, form := range []string{
		"util/fetcher.fetchUrl",
		"fetcher.fetchUrl",
		"fetchUrl",
		"fetchUrl(1)",
	} {
		if !jsSymbolMatches(sym, map[string]bool{form: true}) {
			t.Errorf("jsSymbolMatches(%+v, %q) = false, want true (verbatim form must resolve)", sym, form)
		}
	}

	// The engine's own SCIP output must NOT be a form an advisory could name a symbol by — matching
	// is DisplayName-based, never SCIP-based (the corpus-symbol-form gotcha: a SCIP-qualified
	// corpus string silently resolves nothing).
	if jsSymbolMatches(sym, map[string]bool{sym.SCIP: true}) {
		t.Errorf("jsSymbolMatches matched on the SCIP string %q — matching must be DisplayName-only, never SCIP", sym.SCIP)
	}
}
