package symboltest

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fullRows returns a must-match profile covering all eight required categories,
// so a test can isolate one polarity without tripping the coverage guard.
func fullRows() []ProfileRow {
	rows := make([]ProfileRow, 0, len(RequiredCategories))
	for i, c := range RequiredCategories {
		rows = append(rows, ProfileRow{
			Category:  c,
			Construct: "filler-" + c,
			// Distinct identities per row (Descriptor keeps them != under ==).
			Want: plugin.Symbol{Kind: plugin.SymbolKindType, Package: "p", Name: "Filler", Descriptor: string(rune('a' + i))},
		})
	}
	return rows
}

// emittedFor returns an emitted symbol whose identity key matches want, with the
// sym()-style SCIP==DisplayName collapse (mirrors goanalysis/packages.go:35).
func emittedFor(want plugin.Symbol) plugin.Symbol {
	e := want
	e.SCIP = "wire-id"
	e.DisplayName = "Human.Name"
	return e
}

func countKind(fs []Finding, k FindingKind) int {
	n := 0
	for _, f := range fs {
		if f.Kind == k {
			n++
		}
	}
	return n
}

// (a) must-match row + matching emitted symbol → GREEN (no regression finding).
func TestEvaluate_MustMatch_Green(t *testing.T) {
	want := plugin.Symbol{Kind: plugin.SymbolKindType, Package: "p", Name: "T"}
	p := Profile{Language: "x", Rows: []ProfileRow{{Category: "types", Construct: "t", Want: want}}}
	fs := Evaluate(p, []plugin.Symbol{emittedFor(want)})
	if got := countKind(fs, FindingRegression); got != 0 {
		t.Fatalf("must-match with a matching emitted symbol: want 0 regressions, got %d (%+v)", got, fs)
	}
}

// (b) must-match row + no/wrong emitted → RED (regression finding reported).
func TestEvaluate_MustMatch_Red(t *testing.T) {
	want := plugin.Symbol{Kind: plugin.SymbolKindType, Package: "p", Name: "T"}
	wrong := plugin.Symbol{Kind: plugin.SymbolKindType, Package: "p", Name: "Other", SCIP: "s", DisplayName: "Other"}
	p := Profile{Language: "x", Rows: []ProfileRow{{Category: "types", Construct: "t", Want: want}}}
	fs := Evaluate(p, []plugin.Symbol{wrong})
	if got := countKind(fs, FindingRegression); got != 1 {
		t.Fatalf("must-match with no matching emitted symbol: want 1 regression, got %d (%+v)", got, fs)
	}
}

// (c) KnownGap row + producer does NOT match → GREEN (gap present as declared).
func TestEvaluate_KnownGap_Green(t *testing.T) {
	want := plugin.Symbol{Kind: plugin.SymbolKindType, Package: "p", Name: "T"}
	// Producer emits only the sym()-style collapse: structured fields empty, so it
	// cannot match the structured Want.
	emitted := plugin.Symbol{SCIP: "T", DisplayName: "T", Package: "p"}
	p := Profile{Language: "x", Rows: []ProfileRow{{
		Category: "types", Construct: "t", Want: want,
		Gap: &KnownGap{Reason: "unpopulated", Closes: "PLAN-2x2"},
	}}}
	fs := Evaluate(p, []plugin.Symbol{emitted})
	if got := countKind(fs, FindingSilentClosure); got != 0 {
		t.Fatalf("known gap with a non-matching producer: want 0 silent-closures, got %d (%+v)", got, fs)
	}
	if got := countKind(fs, FindingRegression); got != 0 {
		t.Fatalf("a gap row must never report a regression; got %d (%+v)", got, fs)
	}
}

// (d) KnownGap row + producer DOES match → RED (silent-closure finding).
func TestEvaluate_KnownGap_SilentClosure(t *testing.T) {
	want := plugin.Symbol{Kind: plugin.SymbolKindType, Package: "p", Name: "T"}
	p := Profile{Language: "x", Rows: []ProfileRow{{
		Category: "types", Construct: "t", Want: want,
		Gap: &KnownGap{Reason: "unpopulated", Closes: "PLAN-2x2"},
	}}}
	fs := Evaluate(p, []plugin.Symbol{emittedFor(want)})
	if got := countKind(fs, FindingSilentClosure); got != 1 {
		t.Fatalf("known gap that the producer now matches: want 1 silent-closure, got %d (%+v)", got, fs)
	}
}

// Coverage guard fires once per dropped required category.
func TestEvaluate_CoverageGuard(t *testing.T) {
	rows := fullRows()[:7] // drop the last required category
	p := Profile{Language: "x", Rows: rows}
	fs := Evaluate(p, nil)
	if got := countKind(fs, FindingMissingCategory); got != 1 {
		t.Fatalf("dropping one required category: want 1 missing-category finding, got %d (%+v)", got, fs)
	}
	// A complete table produces no missing-category findings.
	full := Profile{Language: "x", Rows: fullRows()}
	if got := countKind(Evaluate(full, nil), FindingMissingCategory); got != 0 {
		t.Fatalf("a complete table must produce 0 missing-category findings, got %d", got)
	}
}

// SCIP==DisplayName on a matched symbol is a diagnostic note, never an equality
// failure.
func TestEvaluate_CollapsedSCIP_IsDiagnosticOnly(t *testing.T) {
	want := plugin.Symbol{Kind: plugin.SymbolKindType, Package: "p", Name: "T"}
	collapsed := want
	collapsed.SCIP = "T"
	collapsed.DisplayName = "T" // SCIP == DisplayName
	p := Profile{Language: "x", Rows: []ProfileRow{{Category: "types", Construct: "t", Want: want}}}
	fs := Evaluate(p, []plugin.Symbol{collapsed})
	if got := countKind(fs, FindingCollapsedSCIP); got != 1 {
		t.Fatalf("matched symbol with SCIP==DisplayName: want 1 diagnostic note, got %d (%+v)", got, fs)
	}
	if got := countKind(fs, FindingRegression); got != 0 {
		t.Fatalf("the collapse must not fail equality; got %d regressions (%+v)", got, fs)
	}
	for _, f := range fs {
		if f.Kind == FindingCollapsedSCIP && f.IsFailure() {
			t.Fatalf("CollapsedSCIP must not be a failure")
		}
	}
}

// IdentityKey zeroes exactly the two diagnostic fields and nothing else.
func TestIdentityKey_ZeroesRenderingOnly(t *testing.T) {
	s := plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "p", Enclosing: "T", Name: "M",
		Descriptor: "(int)", Generated: true, SCIP: "scip", DisplayName: "T.M",
	}
	k := IdentityKey(s)
	if k.SCIP != "" || k.DisplayName != "" {
		t.Fatalf("IdentityKey must zero SCIP and DisplayName, got %+v", k)
	}
	want := s
	want.SCIP, want.DisplayName = "", ""
	if k != want { // plain == over the comparable struct
		t.Fatalf("IdentityKey must preserve every structured field: got %+v want %+v", k, want)
	}
	// Two symbols differing only in SCIP/DisplayName share an identity key.
	other := s
	other.SCIP, other.DisplayName = "different", "different"
	if IdentityKey(s) != IdentityKey(other) {
		t.Fatal("symbols differing only in SCIP/DisplayName must share an identity key")
	}
}

// A NotApplicable row asserts nothing about emitted, satisfies the coverage
// guard, and never fails — even if a symbol happens to share its identity.
func TestEvaluate_NotApplicable_NoFindingAndSatisfiesCoverage(t *testing.T) {
	// Build a full 8-category table, but make one category NA. Want is deliberately
	// left matchable, to prove the NA row ignores emitted entirely.
	rows := fullRows()
	rows[2].NA = &NotApplicable{Reason: "language has no free functions"}
	emitted := []plugin.Symbol{emittedFor(rows[2].Want)} // would match rows[2].Want if evaluated
	fs := Evaluate(Profile{Language: "x", Rows: rows}, emitted)
	if got := countKind(fs, FindingMissingCategory); got != 0 {
		t.Fatalf("an NA row must satisfy coverage: want 0 missing-category, got %d (%+v)", got, fs)
	}
	// The NA category is a must-match everywhere else in fullRows, but rows[2] is NA
	// so no regression/closure/diagnostic may come from it. The other 7 must-match
	// rows have no matching emitted → 7 regressions, none from the NA row.
	for _, f := range fs {
		if f.Category == rows[2].Category && f.Construct == rows[2].Construct {
			t.Fatalf("NA row produced a finding it must not: %+v", f)
		}
	}
}

// Setting both Gap and NA on a row is an author error → conflict finding.
func TestEvaluate_RowStateConflict(t *testing.T) {
	rows := fullRows()
	rows[0].Gap = &KnownGap{Reason: "unpopulated", Closes: "PLAN-2x2"}
	rows[0].NA = &NotApplicable{Reason: "no such construct"}
	fs := Evaluate(Profile{Language: "x", Rows: rows}, nil)
	if got := countKind(fs, FindingRowStateConflict); got != 1 {
		t.Fatalf("a row with both Gap and NA: want 1 conflict finding, got %d (%+v)", got, fs)
	}
}

// A waiting consumer (e.g. quartz's C2) calls Evaluate directly and asserts its
// own failure count by Kind, rather than relying on AssertProfile's t.Error's.
func TestEvaluate_ConsumerCountsFailures(t *testing.T) {
	rows := fullRows() // 8 must-match rows, all identities distinct
	// Emit a match for exactly two of them; the rest are regressions.
	emitted := []plugin.Symbol{emittedFor(rows[0].Want), emittedFor(rows[3].Want)}
	fs := Evaluate(Profile{Language: "x", Rows: rows}, emitted)

	failures := 0
	for _, f := range fs {
		if f.IsFailure() {
			failures++
		}
	}
	if got, want := countKind(fs, FindingRegression), 6; got != want {
		t.Fatalf("consumer expected %d regressions (8 must-match minus 2 emitted), got %d", want, got)
	}
	if got := countKind(fs, FindingMissingCategory); got != 0 {
		t.Fatalf("complete table: want 0 missing-category, got %d", got)
	}
	if failures != 6 {
		t.Fatalf("consumer expected 6 total failures, got %d (%+v)", failures, fs)
	}
}

// AssertProfile passes cleanly for an all-gaps profile against a producer that
// matches none of the structured Wants (the reference-profile shape).
func TestAssertProfile_AllGapsGreen(t *testing.T) {
	rows := fullRows()
	for i := range rows {
		rows[i].Gap = &KnownGap{Reason: "unpopulated", Closes: "PLAN-2x2"}
	}
	// Producer emits collapse-style symbols with empty structured identity: matches
	// no structured Want.
	emitted := []plugin.Symbol{{SCIP: "x", DisplayName: "x", Package: "p"}}
	AssertProfile(t, Profile{Language: "x", Rows: rows}, emitted)
}
