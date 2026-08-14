package symboltest

import "github.com/ferralon-ai/ferralon-assay/plugin"

// dotnetRefPkg is the first-party NuGet coordinate of the testdata/dotnetref fixture
// (its .csproj <PackageId>), spelled per SYMBOLS.md Decision A as a versionless
// "pkg:nuget/<coordinate>". Every .NET reference row rebases its Package onto this.
const dotnetRefPkg = "pkg:nuget/Symboltest.DotNetRef"

// Enclosing coordinates within the fixture: the namespace, and the namespace+type
// chain for members/nested declarations of Widget (SYMBOLS.md §Enclosing: namespace
// segments lead the type's Enclosing, "."-joined, outermost→innermost).
const (
	dotnetRefNamespace = "Symboltest.DotNetRef"
	dotnetRefWidget    = "Symboltest.DotNetRef.Widget"
)

// dotnetRefGap is the KnownGap rows 1–7 carry today. The dotnet first-party producer
// emits arity-only SCIP strings and populates only SCIP/DisplayName/Package
// (dotnetanalysis/index.go symbolsFromParse; scip.go functionDescriptor is arity-only),
// leaving the structured identity fields (Kind/Package/Enclosing/Name/Descriptor) zero —
// so no row structurally matches and the profile is GREEN under xfail. PLAN-252
// (first-party structured-field population) closes it.
func dotnetRefGap() *KnownGap {
	return &KnownGap{
		Reason: "structured identity unpopulated by the current arity-only producer (index.go sets SCIP/DisplayName/Package only)",
		Closes: "PLAN-252",
	}
}

// dotnetRefGeneratedGap is the row-8 gap, distinct from dotnetRefGap in its Closes. The
// async state-machine type <FetchAsync>d__0 exists only in compiled IL; the pure-source
// scanner never observes it (SYMBOLS.md ⚑SM), so it is metadata-reader work rather than
// structured-field population. PLAN-250 (the dependency-artifact / metadata reader)
// closes it.
func dotnetRefGeneratedGap() *KnownGap {
	return &KnownGap{
		Reason: "generated state-machine type is metadata-only; the pure-source scanner never observes <…>d__N (SYMBOLS.md ⚑SM)",
		Closes: "PLAN-250",
	}
}

// DotNetReferenceProfile is the .NET reference instance of the canonical symbol profile
// (profile-format.md §5, slot §4.3.2), the C# mirror of GoReferenceProfile. It is the
// eight-category table with Want = the canonical plugin.Symbol from SYMBOLS.md's
// coverage-table rows 1–8, rebased onto the fixture's own coordinate (dotnetRefPkg).
// Every row is a declared KnownGap today, so the profile is GREEN under xfail when driven
// against dotnetanalysis.IndexSymbols — demonstrating the mechanism the language lanes
// copy. This function builds only the table; the hermetic drive lives in dotnetref_test.go.
func DotNetReferenceProfile() Profile {
	return Profile{
		Language: "dotnet",
		Rows: []ProfileRow{
			{
				Category:  "packages/modules",
				Construct: "NuGet package coordinate of the dotnetref fixture (.csproj PackageId)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: dotnetRefPkg},
				Gap:       dotnetRefGap(),
			},
			{
				Category:  "types",
				Construct: "class type Widget (namespace → Enclosing, bare → Name)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: dotnetRefPkg, Enclosing: dotnetRefNamespace, Name: "Widget"},
				Gap:       dotnetRefGap(),
			},
			{
				Category:  "functions",
				Construct: "top-level-statement module-scope callable Run (no declaring type, Enclosing empty)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: dotnetRefPkg, Name: "Run", Descriptor: "()"},
				Gap:       dotnetRefGap(),
			},
			{
				Category:  "methods",
				Construct: "instance method Widget.Render(object) (Decision B short-name param list)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: dotnetRefPkg, Enclosing: dotnetRefWidget, Name: "Render", Descriptor: "(object)"},
				Gap:       dotnetRefGap(),
			},
			{
				Category:  "constructors",
				Construct: "explicit constructor Widget() (ECMA-335 metadata name .ctor)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindConstructor, Package: dotnetRefPkg, Enclosing: dotnetRefWidget, Name: ".ctor", Descriptor: "()"},
				Gap:       dotnetRefGap(),
			},
			{
				Category:  "overloads/generics",
				Construct: "1-arity generic method Widget.DeserializeObject<T>(string) — positional arity segment, distinct from its non-generic sibling",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: dotnetRefPkg, Enclosing: dotnetRefWidget, Name: "DeserializeObject", Descriptor: "`1(string)"},
				Gap:       dotnetRefGap(),
			},
			{
				Category:  "nested declarations",
				Construct: "type Inner nested under Widget (outer type is the innermost Enclosing segment)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: dotnetRefPkg, Enclosing: dotnetRefWidget, Name: "Inner"},
				Gap:       dotnetRefGap(),
			},
			{
				Category:  "generated symbols",
				Construct: "async state-machine type <FetchAsync>d__0 synthesized for Widget.FetchAsync (Generated=true)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: dotnetRefPkg, Enclosing: dotnetRefWidget, Name: "<FetchAsync>d__0", Generated: true},
				Gap:       dotnetRefGeneratedGap(),
			},
		},
	}
}
