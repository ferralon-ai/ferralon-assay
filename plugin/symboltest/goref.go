package symboltest

import "github.com/ferralon-ai/ferralon-assay/plugin"

// goRefPkg is the import path of the testdata/goref fixture module the Go
// reference profile is driven against.
const goRefPkg = "symboltest.test/goref"

// goRefGap is the single KnownGap every Go reference row carries today: no Go
// producer populates the structured identity fields yet (goanalysis mints
// Symbol{SCIP:s, DisplayName:s} via sym(), and even IndexSymbols sets only
// SCIP/DisplayName/Package — packages.go:35,238-242). Structured-field population
// is the per-lane PLAN-2x2 work that turns these gaps green.
func goRefGap() *KnownGap {
	return &KnownGap{
		Reason: "structured identity unpopulated by current producer",
		Closes: "PLAN-300 / lane PLAN-2x2",
	}
}

// GoReferenceProfile is the Go reference instance of the canonical symbol profile
// (profile-format.md §5, slot §4.3.2). It is the eight-category table with Want =
// the fully structured canonical symbol the field-contract requires. Every row is
// a declared KnownGap today, so the profile is GREEN under xfail semantics when
// driven against goanalysis.IndexSymbols — demonstrating the mechanism the four
// language lanes copy for their PLAN-0x0. This function builds only the table; the
// toolchain-gated drive against the real producer lives in goref_test.go.
func GoReferenceProfile() Profile {
	return Profile{
		Language: "go",
		Rows: []ProfileRow{
			{
				Category:  "packages/modules",
				Construct: "package clause of the goref fixture module",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: goRefPkg},
				Gap:       goRefGap(),
			},
			{
				Category:  "types",
				Construct: "exported struct type Widget",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: goRefPkg, Name: "Widget"},
				Gap:       goRefGap(),
			},
			{
				Category:  "functions",
				Construct: "package-level func Build",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: goRefPkg, Name: "Build"},
				Gap:       goRefGap(),
			},
			{
				Category:  "methods",
				Construct: "method (*Widget).Render",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: goRefPkg, Enclosing: "Widget", Name: "Render"},
				Gap:       goRefGap(),
			},
			{
				Category:  "constructors",
				Construct: "constructor NewWidget (Go NewT idiom)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindConstructor, Package: goRefPkg, Enclosing: "Widget", Name: "NewWidget"},
				Gap:       goRefGap(),
			},
			{
				Category:  "overloads/generics",
				Construct: "generic func Map[T, U any] (type-parameter descriptor)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: goRefPkg, Name: "Map", Descriptor: "[T, U any]"},
				Gap:       goRefGap(),
			},
			{
				Category:  "nested declarations",
				Construct: "type Config nested under Widget",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: goRefPkg, Enclosing: "Widget", Name: "Config"},
				Gap:       goRefGap(),
			},
			{
				Category:  "generated symbols",
				Construct: "codegen-synthesized accessor GetName",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: goRefPkg, Enclosing: "Widget", Name: "GetName", Generated: true},
				Gap:       goRefGap(),
			},
		},
	}
}
