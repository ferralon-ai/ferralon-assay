package goanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestMatchesAdvisorySymbol_IntelVerbatimGoFormsConsumable locks the promise this repo makes to
// whoever populates the advisory corpus: *verbatim-from-source* symbol identifiers are
// directly consumable by the Go resolver, through matchesAdvisorySymbol's DisplayName +
// dotted-suffix + bare-leaf tolerance (packages.go:389) — NEVER a SCIP-qualified string. This is a
// characterization/guard test: it does not change resolver behavior, it pins it so a future
// resolver change can't silently break the contract. Hermetic (no toolchain, hand-built
// plugin.Symbol values, no fixture parsing).
func TestMatchesAdvisorySymbol_IntelVerbatimGoFormsConsumable(t *testing.T) {
	sym := plugin.Symbol{
		SCIP:        "scip-go gomod golang.org/x/text v0.3.0 language/Parse().",
		DisplayName: "language.Parse",
		Package:     "golang.org/x/text/language",
	}

	// Representative verbatim-from-source forms an advisory might name this symbol by (doc.go's Go
	// row): package-qualified, and the bare leaf. Both must resolve.
	for _, form := range []string{"language.Parse", "Parse"} {
		if !matchesAdvisorySymbol(sym, map[string]bool{form: true}) {
			t.Errorf("matchesAdvisorySymbol(%+v, %q) = false, want true (verbatim form must resolve)", sym, form)
		}
	}

	// A receiver-qualified form ("(*Service).Handle" shape) resolves the same way against a symbol
	// actually named that way — pin the shape with a second symbol rather than asserting a
	// non-matching string against the Parse fixture.
	recv := plugin.Symbol{
		SCIP:        "scip-go gomod example.com/m v0.0.0 m/(Service).Handle().",
		DisplayName: "(*Service).Handle",
		Package:     "example.com/m",
	}
	if !matchesAdvisorySymbol(recv, map[string]bool{"(*Service).Handle": true}) {
		t.Errorf("matchesAdvisorySymbol did not resolve the receiver-qualified verbatim form")
	}
	if !matchesAdvisorySymbol(recv, map[string]bool{"Handle": true}) {
		t.Errorf("matchesAdvisorySymbol did not resolve the bare-leaf form of a receiver method")
	}

	// The engine's own SCIP output must NOT be a form an advisory could name a symbol by — matching
	// is DisplayName-based, never SCIP-based. A corpus that mistakenly carried SCIP-qualified
	// strings would silently resolve nothing (the corpus-symbol-form gotcha; see
	// enrichment-work-populate-plus-wire-not-schema memory).
	if matchesAdvisorySymbol(sym, map[string]bool{sym.SCIP: true}) {
		t.Errorf("matchesAdvisorySymbol matched on the SCIP string %q — matching must be DisplayName-only, never SCIP", sym.SCIP)
	}
}
