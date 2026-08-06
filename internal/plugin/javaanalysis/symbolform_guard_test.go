package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestJavaSymbolMatches_IntelVerbatimMavenFormsConsumable locks the promise this repo makes to
// whoever populates the advisory corpus: *verbatim-from-source* symbol identifiers for a
// maven-scheme (Java) advisory are directly consumable by javaSymbolMatches's DisplayName +
// package-qualified + bare-leaf + arity-tolerant comparison (ingress.go:145) — NEVER a
// SCIP-qualified string. Characterization/guard test: pins current behavior, does not change it.
// Hermetic (no toolchain, no parsed program — hand-built plugin.Symbol).
func TestJavaSymbolMatches_IntelVerbatimMavenFormsConsumable(t *testing.T) {
	sym := plugin.Symbol{
		SCIP:        "scip-java maven . . com/example/web/UrlFetcher#fetch(1).",
		DisplayName: "UrlFetcher.fetch",
		Package:     "com.example.web",
	}

	// Representative verbatim-from-source forms (doc.go's Java row): fully package-qualified, the
	// bare display name, the bare leaf, and the arity-tolerant form.
	for _, form := range []string{
		"com.example.web.UrlFetcher.fetch",
		"UrlFetcher.fetch",
		"fetch",
		"UrlFetcher.fetch(1)",
	} {
		if !javaSymbolMatches(sym, map[string]bool{form: true}) {
			t.Errorf("javaSymbolMatches(%+v, %q) = false, want true (verbatim form must resolve)", sym, form)
		}
	}

	// The engine's own SCIP output must NOT be a form an advisory could name a symbol by — matching
	// is DisplayName-based, never SCIP-based (the corpus-symbol-form gotcha: a SCIP-qualified
	// corpus string silently resolves nothing).
	if javaSymbolMatches(sym, map[string]bool{sym.SCIP: true}) {
		t.Errorf("javaSymbolMatches matched on the SCIP string %q — matching must be DisplayName-only, never SCIP", sym.SCIP)
	}
}
