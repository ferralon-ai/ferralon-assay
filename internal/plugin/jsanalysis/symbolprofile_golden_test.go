package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/plugin/symboltest"
)

// symbolProfileModule is the module path IndexSymbols derives for the fixture file
// testdata/symbolprofile/src/app.ts when driven with BuildDir=testdata/symbolprofile:
// the source path relative to the build root, extension stripped (moduleOf,
// index.go). Every Want below carries it as Package, the one structured field the
// producer already populates — so a future producer that starts populating
// Kind/Name/Enclosing/Descriptor (PLAN-262) makes the corresponding Want match and
// trips the harness's silent-closure guard, forcing the row's promotion.
const symbolProfileModule = "src/app"

// jsGap is the KnownGap almost every JS reference row carries today: the construct
// is emitted (or emittable) but the first-party producer populates only
// SCIP/DisplayName/Package — the structured identity fields Kind/Name/Enclosing/
// Descriptor/Generated are left zero (index.go:74-84). The JS lane's
// structured-field population (PLAN-262 / the per-lane PLAN-2x2 invariant) is the
// cycle that turns these gaps green.
func jsGap(reason string) *symboltest.KnownGap {
	return &symboltest.KnownGap{Reason: reason, Closes: "PLAN-262"}
}

// JSReferenceProfile is the JS/TS instance of the canonical symbol profile
// (PLAN-006 GoReferenceProfile, copied per its doc.go for the JS lane's PLAN-060).
// It is the eight-category table whose Want is the fully structured canonical
// symbol the field-contract froze, in JS/TS spellings (see docs/symbols/javascript.md
// Layer 2). Every row is a declared KnownGap today: the pure-Go lexical scanner
// emits no structured identity, so no row matches, and the profile is GREEN under
// xfail semantics. It goes RED the moment any producer silently starts populating a
// structured field (a "gap silently closed" finding) — which is the regression the
// golden table exists to catch.
//
// Producer attribution (the five §4.3 producers, mapped onto these category rows):
// the first-party indexer (index.go), call-graph builder (callgraph.go) and ingress
// discovery (ingress.go) all route identity through scipSymbol and populate no
// structured fields — PLAN-262 closes that for every row below. Advisory symbol
// normalization (jsSymbolMatches) keys on DisplayName only, also PLAN-262. The
// dependency-artifact indexer does not exist at all — node_modules is excluded from
// the walk (index.go skipDir) — so no dependency package/type symbol is emitted;
// that producer is PLAN-260 (OpResolveInventory), noted per-row where it applies.
func JSReferenceProfile() symboltest.Profile {
	pkg := symbolProfileModule
	return symboltest.Profile{
		Language: "javascript",
		Rows: []symboltest.ProfileRow{
			{
				Category:  "packages/modules",
				Construct: "the app.ts module (package/module identity)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: pkg},
				Gap: &symboltest.KnownGap{
					Reason: "no standalone package/module Symbol is emitted (module identity survives only as the SCIP namespace prefix); Kind is unpopulated; npm package-instance identity needs node_modules (PLAN-260)",
					Closes: "PLAN-262",
				},
			},
			{
				Category:  "types",
				Construct: "class Fetcher (a TS type)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: pkg, Name: "Fetcher"},
				Gap:       jsGap("class is emitted as SCIP/DisplayName only; Kind and Name are unpopulated (interfaces/type-aliases/enums are not parsed at all)"),
			},
			{
				Category:  "functions",
				Construct: "module-level function fetchUrl(u)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: pkg, Name: "fetchUrl", Descriptor: "(1)"},
				Gap:       jsGap("name and arity live only inside the SCIP string and DisplayName; Kind/Name/Descriptor are unpopulated"),
			},
			{
				Category:  "methods",
				Construct: "method Fetcher.fetch(path)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: pkg, Enclosing: "Fetcher", Name: "fetch", Descriptor: "(1)"},
				Gap:       jsGap("the enclosing class survives only as Fetcher# inside the SCIP string; Kind/Enclosing/Name/Descriptor are unpopulated"),
			},
			{
				Category:  "constructors",
				Construct: "constructor Fetcher.constructor(base)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindConstructor, Package: pkg, Enclosing: "Fetcher", Name: "constructor", Descriptor: "(1)"},
				Gap:       jsGap("not distinguished from an ordinary method; the only marker is the literal name 'constructor' in the SCIP string; Kind: SymbolKindConstructor is the frozen distinguisher and is unpopulated"),
			},
			{
				Category:  "overloads/generics",
				Construct: "generic method Fetcher.map<T>(fn, x)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: pkg, Enclosing: "Fetcher", Name: "map", Descriptor: "(2)"},
				Gap:       jsGap("generic type params are lexically stripped; arity is the JS spelling of Descriptor and is unpopulated (type-resolved descriptors would need a resolver the scanner does not have)"),
			},
			{
				Category:  "nested declarations",
				Construct: "class Inner nested inside a method body of Outer",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: pkg, Enclosing: "Outer", Name: "Inner"},
				Gap:       jsGap("the nested class is captured (Outer#Inner# in SCIP) but Kind/Enclosing/Name are unpopulated; the frozen Enclosing is a type/decl chain and does not capture function-scope nesting"),
			},
			{
				Category:  "generated symbols",
				Construct: "a decorator-/transpiler-synthesized member",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: pkg, Enclosing: "Fetcher", Name: "generated", Generated: true},
				Gap:       jsGap("the scanner reads raw source with no decorator/transpiler/source-map awareness, so it neither synthesizes nor flags a generated symbol; Generated is never set"),
			},
		},
	}
}

// indexFixture drives the real first-party producer against the offline fixture.
// The scanner is pure-Go (no Node/tsc/scip-typescript), so this is hermetic and
// needs no toolchain skip — unlike goanalysis.IndexSymbols, which needs `go` on
// PATH. It parses source text; it never executes it (§3).
func indexFixture(t *testing.T) []plugin.Symbol {
	t.Helper()
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{
		BuildDir: "testdata/symbolprofile",
	})
	if err != nil {
		t.Fatalf("IndexSymbols on testdata/symbolprofile: %v", err)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("IndexSymbols emitted no symbols for the symbolprofile fixture")
	}
	return res.Symbols
}

// TestSymbolProfileGolden is the cross-producer golden table (PLAN-060 C2), driven
// against the REAL first-party producer on the offline fixture.
//
// READINESS STATEMENT (asserted below, not narrated): the profile declares eight
// KnownGap rows — one per §4.3 category — and today produces ZERO harness findings,
// because the producer populates no structured identity so every declared gap is
// genuinely open. That is the criterion's "expected-failure count": eight declared
// gaps, zero unexpected findings. PLAN-006's harness models an expected gap as a
// GREEN xfail (not a RED row); C2's original "test exits non-zero" wording is
// superseded by that polarity — the operative assertion is the gap count plus zero
// regressions/silent-closures/missing-categories. A run with fewer or more findings
// than zero, or fewer or more than eight declared gaps, fails this criterion.
func TestSymbolProfileGolden(t *testing.T) {
	profile := JSReferenceProfile()
	emitted := indexFixture(t)

	// The single true fact that makes every KnownGap real: the producer populates
	// only SCIP/DisplayName/Package today. If any structured field starts being
	// populated, this trips here AND as a silent-closure finding below.
	for _, s := range emitted {
		key := symboltest.IdentityKey(s) // zeroes SCIP/DisplayName; Package is retained
		bare := plugin.Symbol{Package: s.Package}
		if key != bare {
			t.Errorf("producer populated a structured identity field unexpectedly (PLAN-262 not yet landed): %+v", s)
		}
	}

	// Expected-gap count: eight rows, every one a declared KnownGap (no must-match,
	// no NotApplicable), covering all eight required categories exactly once.
	assertAllRowsAreDeclaredGaps(t, profile)

	// Zero unexpected findings: every declared gap is genuinely open (no regression,
	// no silent-closure), and no required category is dropped (no missing-category).
	findings := symboltest.Evaluate(profile, emitted)
	failures := 0
	for _, f := range findings {
		if f.IsFailure() {
			failures++
			t.Errorf("unexpected golden-table finding (expected 0): %s", f.Message)
		}
	}
	if failures != 0 {
		t.Fatalf("golden table: want 0 unexpected findings, got %d", failures)
	}

	// Belt-and-suspenders: AssertProfile applies the same §2/§3 semantics and would
	// t.Error any regression/silent-closure/missing-category. It is GREEN today.
	symboltest.AssertProfile(t, profile, emitted)
}

// TestSymbolProfileGolden_MirrorsProducerShape checks — independently of the
// fixture — that the reference table is well-formed against a captured
// []plugin.Symbol mirroring IndexSymbols' real output shape today (SCIP/DisplayName/
// Package populated, structured fields empty; index.go:74-84). It keeps the
// mechanism verifiable even if the fixture changes, mirroring goref_test.go's
// second test.
func TestSymbolProfileGolden_MirrorsProducerShape(t *testing.T) {
	pkg := symbolProfileModule
	mirror := []plugin.Symbol{
		{SCIP: "scip-typescript npm . . " + pkg + "/fetchUrl(1).", DisplayName: "fetchUrl(1)", Package: pkg},
		{SCIP: "scip-typescript npm . . " + pkg + "/Fetcher#", DisplayName: "Fetcher", Package: pkg},
		{SCIP: "scip-typescript npm . . " + pkg + "/Fetcher#fetch(1).", DisplayName: "Fetcher.fetch(1)", Package: pkg},
		{SCIP: "scip-typescript npm . . " + pkg + "/Fetcher#constructor(1).", DisplayName: "Fetcher.constructor(1)", Package: pkg},
		{SCIP: "scip-typescript npm . . " + pkg + "/Fetcher#map(2).", DisplayName: "Fetcher.map(2)", Package: pkg},
		{SCIP: "scip-typescript npm . . " + pkg + "/Outer#Inner#", DisplayName: "Outer.Inner", Package: pkg},
	}
	symboltest.AssertProfile(t, JSReferenceProfile(), mirror)
	if got := countFailures(symboltest.Evaluate(JSReferenceProfile(), mirror)); got != 0 {
		t.Fatalf("mirror shape: want 0 findings, got %d", got)
	}
}

// assertAllRowsAreDeclaredGaps asserts the profile is exactly the eight required
// categories, each a declared KnownGap (Gap != nil, NA == nil) — the shape the
// readiness statement declares. A must-match row, an NA row, a missing category, or
// a duplicate category all fail C2's expected-gap count.
func assertAllRowsAreDeclaredGaps(t *testing.T, p symboltest.Profile) {
	t.Helper()
	if got, want := len(p.Rows), len(symboltest.RequiredCategories); got != want {
		t.Fatalf("profile row count: want %d (one per required category), got %d", want, got)
	}
	seen := map[string]bool{}
	for _, r := range p.Rows {
		if r.Gap == nil {
			t.Errorf("row %q (%s): want a declared KnownGap, got must-match/NA — no JS producer populates structured identity yet", r.Category, r.Construct)
		}
		if r.NA != nil {
			t.Errorf("row %q (%s): NotApplicable is wrong — the construct exists in JS/TS, it is merely unemitted", r.Category, r.Construct)
		}
		if r.Gap != nil && r.Gap.Closes == "" {
			t.Errorf("row %q (%s): KnownGap must name the closing PLAN", r.Category, r.Construct)
		}
		seen[r.Category] = true
	}
	for _, c := range symboltest.RequiredCategories {
		if !seen[c] {
			t.Errorf("profile drops required category %q", c)
		}
	}
}

func countFailures(fs []symboltest.Finding) int {
	n := 0
	for _, f := range fs {
		if f.IsFailure() {
			n++
		}
	}
	return n
}
