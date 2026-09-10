package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/plugin/symboltest"
)

// PLAN-070 C1/C2: the canonical Python symbol profile and its golden-equality run.
//
// This is the Python instance of the symboltest reference profile (the pattern
// GoReferenceProfile establishes in plugin/symboltest/goref.go). Each of the eight
// §4.3 categories binds a concrete Python construct in testdata/symbolprofile/mod.py
// to the fully-structured canonical plugin.Symbol a conformant producer must emit.
//
// Every row is a declared KnownGap today: the first-party lexical scanner
// (symbolsFromParse, index.go:96-115; sym(), callgraph.go:85) populates only
// SCIP/DisplayName/Package and leaves the structured identity fields
// (Kind/Enclosing/Name/Descriptor/Generated) zero, so no emitted symbol matches any
// structured Want. Under the harness's xfail semantics that is GREEN -- the gaps are
// real, exactly where declared. PLAN-272 (Python first-party structured symbol
// identity) is what turns these gaps green by populating the fields; when it lands, a
// row that starts matching flips to a FindingSilentClosure and must be promoted by
// deleting its KnownGap.
//
// The prose profile document (SYMBOL-PROFILE.md) carries the wider cross-producer
// (category x producer) table with a reason code per cell; this test is the
// executable single-producer golden the shipped harness models.
const symbolProfileModule = "mod" // moduleOf("testdata/symbolprofile", ".../mod.py")

// pythonStructuredGap is the KnownGap every row carries today: the scanner emits no
// structured identity. PLAN-272 closes it.
func pythonStructuredGap() *symboltest.KnownGap {
	return &symboltest.KnownGap{
		Reason: "scanner emits SCIP/DisplayName/Package only; structured identity (Kind/Enclosing/Name/Descriptor/Generated) is unpopulated",
		Closes: "PLAN-272 (Python first-party structured symbol identity)",
	}
}

// pythonProfile is the Python reference instance of the canonical symbol profile:
// the eight §4.3 categories in Python spelling, each Want the fully-structured
// canonical symbol the field-contract requires, each a declared KnownGap today.
func pythonProfile() symboltest.Profile {
	pkg := symbolProfileModule
	return symboltest.Profile{
		Language: "python",
		Rows: []symboltest.ProfileRow{
			{
				Category:  "packages/modules",
				Construct: "module clause of mod.py (import path \"mod\")",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: pkg},
				Gap:       pythonStructuredGap(),
			},
			{
				Category:  "types",
				Construct: "class Widget",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: pkg, Name: "Widget"},
				Gap:       pythonStructuredGap(),
			},
			{
				Category:  "functions",
				Construct: "module-level def build",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: pkg, Name: "build"},
				Gap:       pythonStructuredGap(),
			},
			{
				Category:  "methods",
				Construct: "method Widget.render",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: pkg, Enclosing: "Widget", Name: "render"},
				Gap:       pythonStructuredGap(),
			},
			{
				Category:  "constructors",
				Construct: "constructor Widget.__init__ (Python __init__ idiom)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindConstructor, Package: pkg, Enclosing: "Widget", Name: "__init__"},
				Gap:       pythonStructuredGap(),
			},
			{
				Category:  "overloads/generics",
				Construct: "typed_get (@overload arms + TypeVar target); scanner disambiguates by arity only",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: pkg, Name: "typed_get", Descriptor: "[T]"},
				Gap:       pythonStructuredGap(),
			},
			{
				Category:  "nested declarations",
				Construct: "class Config nested under Widget",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: pkg, Enclosing: "Widget", Name: "Config"},
				Gap:       pythonStructuredGap(),
			},
			{
				Category:  "generated symbols",
				Construct: "functools.wraps wrapper over traced (synthesized, lexically indistinguishable from its target)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: pkg, Name: "traced", Generated: true},
				Gap: &symboltest.KnownGap{
					Reason: "lexical scanner cannot distinguish a functools.wraps wrapper from its target, nor mark any symbol Generated",
					Closes: "PLAN-272 (Python first-party structured symbol identity)",
				},
			},
		},
	}
}

// TestPythonReferenceProfile_Categories is C1: the profile covers all eight §4.3
// categories in Python's spelling, and the eight representative canonical values are
// pairwise-distinct under the plugin.Symbol structured-identity key. A missing
// category (row count != 8) or a collapse of two categories to one identity is a
// defect the check must catch.
func TestPythonReferenceProfile_Categories(t *testing.T) {
	p := pythonProfile()

	// (a) exactly eight rows, one per required category, none dropped.
	if len(p.Rows) != len(symboltest.RequiredCategories) {
		t.Fatalf("profile must have exactly %d rows (one per §4.3 category); got %d",
			len(symboltest.RequiredCategories), len(p.Rows))
	}
	seen := make(map[string]bool, len(p.Rows))
	for _, r := range p.Rows {
		seen[r.Category] = true
	}
	for _, c := range symboltest.RequiredCategories {
		if !seen[c] {
			t.Errorf("profile drops required category %q (§1 requires all eight)", c)
		}
	}

	// (b) the eight Want values are pairwise unequal under the structured-identity
	// key -- a category that collapses onto another's identity is not measuring a
	// distinct construct. This is the control: collapse any two Wants and the map
	// size drops below eight and this fails.
	keys := make(map[plugin.Symbol]string, len(p.Rows))
	for _, r := range p.Rows {
		k := symboltest.IdentityKey(r.Want)
		if prev, dup := keys[k]; dup {
			t.Errorf("categories %q and %q share one canonical identity %+v; each category must be a distinct construct",
				prev, r.Category, k)
		}
		keys[k] = r.Category
	}
	if len(keys) != len(p.Rows) {
		t.Fatalf("expected %d pairwise-distinct canonical identities; got %d", len(p.Rows), len(keys))
	}
}

// TestPythonReferenceProfile_CollapseControl proves the pairwise-distinctness check
// in TestPythonReferenceProfile_Categories has teeth: a profile that collapses two
// categories onto one identity must be detected. Deliberately builds such a profile
// and asserts the duplicate is found -- if this ever stops finding it, the C1 control
// above is vacuous.
func TestPythonReferenceProfile_CollapseControl(t *testing.T) {
	rows := pythonProfile().Rows

	var methodsWant plugin.Symbol
	for _, r := range rows {
		if r.Category == "methods" {
			methodsWant = r.Want
		}
	}

	keys := make(map[plugin.Symbol]bool, len(rows))
	dupFound := false
	for _, r := range rows {
		if r.Category == "functions" {
			r.Want = methodsWant // collapse functions onto methods
		}
		k := symboltest.IdentityKey(r.Want)
		if keys[k] {
			dupFound = true
		}
		keys[k] = true
	}
	if !dupFound {
		t.Fatal("collapse control failed: collapsing functions onto methods was not detected -- the C1 distinctness check is vacuous")
	}
}

// TestPythonSymbolGolden is C2: drive the Python reference profile against the REAL
// first-party producer (IndexSymbols) over the offline testdata/symbolprofile
// fixture. Every row is a declared KnownGap and IndexSymbols emits no structured
// identity, so nothing matches any Want -- GREEN under xfail. The harness supersedes
// the pre-PLAN-006 "deliberately red golden table": a correctly-declared open gap is
// GREEN; RED is reserved for a silent closure (PLAN-272 landed but a row still
// declares a gap) or a regression. No skipped rows -- a KnownGap names each gap
// loudly rather than hiding it the way a skip would.
func TestPythonSymbolGolden(t *testing.T) {
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{
		BuildDir: "testdata/symbolprofile",
	})
	if err != nil {
		t.Fatalf("IndexSymbols on testdata/symbolprofile: %v", err)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("IndexSymbols emitted no symbols for the symbolprofile fixture")
	}
	for _, s := range res.Symbols {
		t.Logf("emitted: SCIP=%q DisplayName=%q Package=%q Kind=%q Enclosing=%q Name=%q Descriptor=%q Generated=%t",
			s.SCIP, s.DisplayName, s.Package, s.Kind, s.Enclosing, s.Name, s.Descriptor, s.Generated)
	}

	// GREEN under xfail: no declared gap has closed, so Evaluate returns no failures.
	for _, f := range symboltest.Evaluate(pythonProfile(), res.Symbols) {
		if f.IsFailure() {
			t.Errorf("unexpected failure (a gap closed or regressed -- promote or fix the row): %s", f.Message)
		}
	}
}

// TestPythonSymbolGolden_InverseControl proves the GREEN of TestPythonSymbolGolden is
// not vacuous: if the producer DID emit a structurally-matching symbol for a gap row,
// the harness catches it as a silent closure. Feeds a hand-built symbol whose
// identity equals the "types" row's Want and asserts exactly that finding. When
// PLAN-272 makes IndexSymbols emit structured identity for real, this is the failure
// the golden will raise until each closed row is promoted.
func TestPythonSymbolGolden_InverseControl(t *testing.T) {
	var typesWant plugin.Symbol
	for _, r := range pythonProfile().Rows {
		if r.Category == "types" {
			typesWant = r.Want
		}
	}
	// A conformant emission for the Widget class: structured identity populated.
	emitted := []plugin.Symbol{{
		SCIP:        "scip-python python . . mod/Widget#",
		DisplayName: "Widget",
		Package:     typesWant.Package,
		Kind:        typesWant.Kind,
		Name:        typesWant.Name,
	}}

	var closures int
	for _, f := range symboltest.Evaluate(pythonProfile(), emitted) {
		if f.Kind == symboltest.FindingSilentClosure && f.Category == "types" {
			closures++
		}
	}
	if closures != 1 {
		t.Fatalf("inverse control: a structured match for the types row must raise exactly one silent-closure finding; got %d", closures)
	}
}
