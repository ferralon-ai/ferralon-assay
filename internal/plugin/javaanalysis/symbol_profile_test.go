package javaanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// This is the PLAN-040 C1 characterization test: it pins the emitter's behaviour
// against the published canonical symbol profile (SYMBOL_PROFILE.md). Every id
// string below is copied verbatim from that profile, so a change to either the
// emitter or the profile that breaks their agreement fails here.
//
// Horizon note (see the profile's "Two horizons" section): today the Java plugin
// populates only Symbol.SCIP/DisplayName/Package, so this test asserts the rendered
// SCIP strings. When PLAN-242 populates the structured identity fields, the
// COLLAPSED constructor/overload rows flip to SEPARATED (via Kind / Descriptor) and
// this test grows a structured-tuple horizon; the string assertions here stay.

const symbolProfileDir = "testdata/symbolprofile"

// profilePrefix is the local, coordinate/version-erased SCIP prefix every symbol in
// the fixture shares: manager "scip-java maven", both the coordinate slot and the
// version slot the localCoordinate placeholder ".". Package com.example.web renders
// as the namespace descriptor "com/example/web/".
const profilePrefix = "scip-java maven . . com/example/web/"

func indexSymbolProfile(t *testing.T) []plugin.Symbol {
	t.Helper()
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: symbolProfileDir})
	if err != nil {
		t.Fatalf("IndexSymbols(%s): %v", symbolProfileDir, err)
	}
	return res.Symbols
}

// scipCount returns how many indexed symbols carry exactly this SCIP id. A count > 1
// is a COLLAPSE: two source-distinct declarations rendered the same identity.
func scipCount(syms []plugin.Symbol, scip string) int {
	n := 0
	for _, s := range syms {
		if s.SCIP == scip {
			n++
		}
	}
	return n
}

// TestSymbolProfile_SeparatedIdsPresentAndDistinct pins the profile's SEPARATED
// rows: each construct renders a distinct id the emitter actually mints.
func TestSymbolProfile_SeparatedIdsPresentAndDistinct(t *testing.T) {
	syms := indexSymbolProfile(t)

	separated := []struct {
		row  string
		scip string
	}{
		{"type", profilePrefix + "UrlServiceImpl#"},
		{"method", profilePrefix + "UrlServiceImpl#fetch(1)."},
		{"fully-qualified method", profilePrefix + "UrlServiceImpl#handle(2)."},
		{"nested declaration (field)", profilePrefix + "Service#Config#retries."},
		{"nested class", profilePrefix + "Outer#Inner#"},
	}

	seen := map[string]string{}
	for _, e := range separated {
		if scipCount(syms, e.scip) == 0 {
			t.Errorf("SEPARATED row %q: expected id %q in the index, absent", e.row, e.scip)
		}
		if prev, ok := seen[e.scip]; ok {
			t.Errorf("SEPARATED rows %q and %q share id %q — not pairwise-distinct", prev, e.row, e.scip)
		}
		seen[e.scip] = e.row
	}
	if len(seen) != len(separated) {
		t.Errorf("expected %d pairwise-distinct SEPARATED ids, got %d", len(separated), len(seen))
	}
}

// TestSymbolProfile_CollapsedIdsCollide pins the profile's COLLAPSED rows: distinct
// source constructs that the arity-erased emitter renders identically. Each is a
// characterization of a documented gap, surfaced honestly (via Partiality) at the
// edge layer — not a silent mis-link.
func TestSymbolProfile_CollapsedIdsCollide(t *testing.T) {
	syms := indexSymbolProfile(t)

	// Same-arity overloads: f(int) and f(String) are two declarations that both
	// erase to Calc#f(1). — a genuine collision (count == 2 on one id).
	overload := profilePrefix + "Calc#f(1)."
	if got := scipCount(syms, overload); got != 2 {
		t.Errorf("same-arity overload collapse: expected 2 declarations sharing %q, got %d", overload, got)
	}

	// Constructor collapses into a method-shaped id with no <init> marker.
	ctor := profilePrefix + "UrlServiceImpl#UrlServiceImpl(1)."
	if scipCount(syms, ctor) == 0 {
		t.Errorf("constructor collapse: expected constructor id %q, absent", ctor)
	}
	for _, s := range syms {
		if strings.Contains(s.SCIP, "<init>") {
			t.Errorf("constructor is not machine-distinguishable today: unexpected <init> marker in %q", s.SCIP)
		}
	}

	// Generics: the type parameter is lexically stripped, so Box<T> renders Box#.
	box := profilePrefix + "Box#"
	if scipCount(syms, box) == 0 {
		t.Errorf("generics collapse: expected type-parameter-stripped id %q, absent", box)
	}
	for _, s := range syms {
		if strings.ContainsAny(s.SCIP, "<>") {
			t.Errorf("generics not stripped: unexpected type-argument bracket in %q", s.SCIP)
		}
	}

	// Coordinate/version collapse: every local symbol renders both slots as ".".
	for _, s := range syms {
		if !strings.HasPrefix(s.SCIP, "scip-java maven . . ") {
			t.Errorf("coordinate/version not collapsed to '. .' for %q (display %q)", s.SCIP, s.DisplayName)
		}
	}
}

// TestSymbolProfile_AbsentSymbolsNeverMinted pins the profile's ABSENT rows: the
// source-declaration parser never sees bytecode-synthesized members, so no id is
// minted for them — an omission, never a present-but-wrong entry.
func TestSymbolProfile_AbsentSymbolsNeverMinted(t *testing.T) {
	syms := indexSymbolProfile(t)

	for _, s := range syms {
		// Lambda desugars carry no source declaration; none is indexed.
		if strings.Contains(s.SCIP, "lambda") || strings.Contains(s.DisplayName, "lambda") {
			t.Errorf("generated ABSENT violated: a lambda symbol was minted: %q (%q)", s.SCIP, s.DisplayName)
		}
		// Enum synthetic values()/valueOf() are never modeled by the source parser.
		if strings.Contains(s.SCIP, "values(") || strings.Contains(s.SCIP, "valueOf(") {
			t.Errorf("generated ABSENT violated: a synthetic enum method was minted: %q", s.SCIP)
		}
	}
}
