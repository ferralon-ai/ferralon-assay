package dotnetanalysis

// PLAN-051 — .NET canonical symbol profile fixtures (see SYMBOLS.md, this directory).
//
// These fixtures are the machine-checkable half of the profile: one hand-written value per
// §4.3 category, all pairwise-distinct under the canonical match key, plus the C3 overload
// mutation control. They prove — TODAY, before PLAN-250/252/350/352 inherit the spellings —
// that the profile's categories do not collide.
//
// PLAN-000's frozen 8-field comparable plugin.Symbol
// (Kind/Package/Enclosing/Name/Descriptor/Generated/DisplayName/SCIP) is now durable in
// plugin/plugin.go, so PLAN-051's temporary fixture-local fxSymbol/fxSymbolKind stand-in
// has been deleted and every fixture re-points at the real plugin.Symbol /
// plugin.SymbolKind* (PLAN-051b, completing the substitution the stand-in notice foresaw).
// The field names and json tags are identical by construction; matchKey is now a free
// helper (matchKeyOf) because a match-key method cannot be attached to a type from another
// package.

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// matchKey is the canonical advisory/cross-producer match key: Package, Enclosing, Name,
// Descriptor, Kind — NEVER SCIP/DisplayName (field-contract.md §2 line 76,
// symbolform_guard_test contract), and NOT Generated (the dispatch fixes the key at these
// five fields). Distinctness under this SUBSET is strictly stronger than distinctness under
// full ==: a generated symbol here must be distinct on an identity field (its mangled name),
// not on the Generated bool alone.
type matchKey struct {
	Kind       plugin.SymbolKind
	Package    string
	Enclosing  string
	Name       string
	Descriptor string
}

// matchKeyOf projects a plugin.Symbol onto the canonical five-field match key. It is a free
// helper (not a method) because plugin.Symbol is defined in another package.
func matchKeyOf(s plugin.Symbol) matchKey {
	return matchKey{s.Kind, s.Package, s.Enclosing, s.Name, s.Descriptor}
}

// The eight §4.3 categories, as the coverage tags each fixture carries.
const (
	catPackages     = "packages"           // §4.3(1)
	catTypes        = "types"              // §4.3(2)
	catFunctions    = "functions"          // §4.3(3)
	catMethods      = "methods"            // §4.3(4)
	catConstructors = "constructors"       // §4.3(5)
	catOverloadsGen = "overloads-generics" // §4.3(6)
	catNested       = "nested"             // §4.3(7)
	catGenerated    = "generated"          // §4.3(8)
)

// allCategories is the set the coverage test requires to be non-empty (C3 fails below eight).
var allCategories = []string{
	catPackages, catTypes, catFunctions, catMethods,
	catConstructors, catOverloadsGen, catNested, catGenerated,
}

// profileFixture pairs a hand-written plugin.Symbol with the §4.3 category it exercises and a note.
type profileFixture struct {
	category string
	note     string
	sym      plugin.Symbol
}

// symbolsProfileFixtures — one or more hand-written values per §4.3 category, every field
// spelled straight from SYMBOLS.md (Decision A: Package = "pkg:nuget/<coordinate>", no
// version; Decision B: Descriptor = "(" + canonical short-name param types + ")"). All values
// hand-written; no toolchain, no parsed program — real plugin.Symbol values.
var symbolsProfileFixtures = []profileFixture{
	// §4.3(1) packages/modules — the NuGet/assembly coordinate, versionless (Decision A).
	{catPackages, "NuGet package coordinate (Decision A: versionless)", plugin.Symbol{
		Kind: plugin.SymbolKindPackage, Package: "pkg:nuget/Newtonsoft.Json",
		DisplayName: "Newtonsoft.Json",
	}},

	// §4.3(2) types — namespace lives in Enclosing; Name is the bare type.
	{catTypes, "top-level type; namespace in Enclosing", plugin.Symbol{
		Kind: plugin.SymbolKindType, Package: "pkg:nuget/Newtonsoft.Json",
		Enclosing: "Newtonsoft.Json", Name: "JsonConvert",
		DisplayName: "Newtonsoft.Json.JsonConvert",
	}},

	// §4.3(2) types — open generic type declaration: Descriptor is backtick-arity `2 (arity only,
	// NO type-param names, per the nickel barrier correction 2026-08-06). `class Cache<TKey,TValue>`
	// → Name="Cache", Descriptor="`2". Distinct from the non-generic JsonConvert type (Descriptor "").
	{catTypes, "open generic type; `2 arity-only Descriptor (no type-param names)", plugin.Symbol{
		Kind: plugin.SymbolKindType, Package: "pkg:nuget/MyApp",
		Enclosing: "MyApp", Name: "Cache", Descriptor: "`2",
		DisplayName: "MyApp.Cache<TKey,TValue>",
	}},

	// §4.3(3) functions — module-scope (C# top-level statements): no declaring type, so
	// Enclosing is empty; this is what distinguishes a function from a static method.
	{catFunctions, "module-scope function (top-level statements); empty Enclosing", plugin.Symbol{
		Kind: plugin.SymbolKindFunction, Package: "pkg:nuget/MyApp",
		Name: "Run", Descriptor: "()",
		DisplayName: "Run()",
	}},

	// §4.3(4) methods — Descriptor carries the canonical short-name param list (Decision B).
	{catMethods, "instance/static method; short-name param list", plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "pkg:nuget/Newtonsoft.Json",
		Enclosing: "Newtonsoft.Json.JsonConvert", Name: "SerializeObject", Descriptor: "(object)",
		DisplayName: "JsonConvert.SerializeObject(object)",
	}},

	// §4.3(5) constructors — ECMA-335 metadata name ".ctor" (both S and M derive it).
	{catConstructors, "instance constructor named .ctor", plugin.Symbol{
		Kind: plugin.SymbolKindConstructor, Package: "pkg:nuget/Newtonsoft.Json",
		Enclosing: "Newtonsoft.Json.JsonSerializerSettings", Name: ".ctor", Descriptor: "()",
		DisplayName: "JsonSerializerSettings.ctor()",
	}},

	// §4.3(6) overloads/generics — generic method: backtick-arity `1 segment (arity = count, NO
	// type-param name) then the canonical param list. Distinct from the non-generic Deserialize
	// overloads below. Positional/arity spelling (nickel barrier correction 2026-08-06): the
	// segment is `N, not <T>, so renaming the type param does not change identity.
	{catOverloadsGen, "generic method; `1 arity segment (positional, no type-param name)", plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "pkg:nuget/Newtonsoft.Json",
		Enclosing: "Newtonsoft.Json.JsonConvert", Name: "DeserializeObject", Descriptor: "`1(string)",
		DisplayName: "JsonConvert.DeserializeObject<T>(string)",
	}},

	// §4.3(6) overloads — C3 MUTATION CONTROL. Two same-arity overloads differing ONLY in a
	// parameter type. They MUST be unequal; a reviewer who collapses Descriptor to arity makes
	// these two collide and the pairwise-distinct test goes red.
	{catOverloadsGen, "overload A — Deserialize(string) (mutation control)", plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "pkg:nuget/Newtonsoft.Json",
		Enclosing: "Newtonsoft.Json.JsonConvert", Name: "Deserialize", Descriptor: "(string)",
		DisplayName: "JsonConvert.Deserialize(string)",
	}},
	{catOverloadsGen, "overload B — Deserialize(Type) (mutation control)", plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "pkg:nuget/Newtonsoft.Json",
		Enclosing: "Newtonsoft.Json.JsonConvert", Name: "Deserialize", Descriptor: "(Type)",
		DisplayName: "JsonConvert.Deserialize(Type)",
	}},

	// §5.2(5) explicit interface implementation (⚑EII) — interface qualifier in short-name
	// canonical form (IDisposable, not System.IDisposable), joined to the member with ".".
	// Distinct from an implicit Dispose (Name "Dispose").
	{catMethods, "explicit interface impl; short-name qualifier in Name", plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "pkg:nuget/MyApp",
		Enclosing: "MyApp.Widget", Name: "IDisposable.Dispose", Descriptor: "()",
		DisplayName: "Widget.IDisposable.Dispose()",
	}},

	// §4.3(7) nested declarations — outer type is the innermost Enclosing segment.
	{catNested, "nested type; Enclosing = namespace + outer type", plugin.Symbol{
		Kind: plugin.SymbolKindType, Package: "pkg:nuget/MyApp",
		Enclosing: "MyApp.Outer", Name: "Inner",
		DisplayName: "MyApp.Outer.Inner",
	}},

	// §4.3(8) generated symbols (⚑SM) — async state-machine type. Generated=true; distinct on
	// its mangled Name (<FetchAsync>d__0) WITHOUT relying on the Generated bool. The
	// source-method mapping (<Name>d__N → FetchAsync) is metadata-only; see SYMBOLS.md.
	{catGenerated, "async state-machine type; mangled name, Generated=true", plugin.Symbol{
		Kind: plugin.SymbolKindType, Package: "pkg:nuget/MyApp",
		Enclosing: "MyApp.Widget", Name: "<FetchAsync>d__0", Generated: true,
		DisplayName: "MyApp.Widget.<FetchAsync>d__0",
	}},
}

// TestSymbolsProfileFixtures_CategoryCoverage asserts (C3(a)) at least one fixture per §4.3
// category — the count of covered categories must be exactly the eight the profile enumerates.
func TestSymbolsProfileFixtures_CategoryCoverage(t *testing.T) {
	covered := map[string]int{}
	for _, f := range symbolsProfileFixtures {
		covered[f.category]++
	}
	for _, cat := range allCategories {
		if covered[cat] == 0 {
			t.Errorf("§4.3 category %q has no fixture — C3(a) requires >= 1 per category", cat)
		}
	}
	if len(covered) < len(allCategories) {
		t.Errorf("covered %d of %d §4.3 categories; C3(a) fails below %d",
			len(covered), len(allCategories), len(allCategories))
	}
	// Guard against a fixture tagged with a category outside the profile's eight.
	known := map[string]bool{}
	for _, c := range allCategories {
		known[c] = true
	}
	for _, f := range symbolsProfileFixtures {
		if !known[f.category] {
			t.Errorf("fixture %q carries unknown category %q", f.note, f.category)
		}
	}
}

// TestSymbolsProfileFixtures_PairwiseDistinct asserts (C3(b)) that no two fixtures collide
// under the canonical match key (Package, Enclosing, Name, Descriptor, Kind). This is the real
// value of the fixture set: it proves the profile's spellings do not collapse BEFORE
// PLAN-250/252/350/352 inherit them.
func TestSymbolsProfileFixtures_PairwiseDistinct(t *testing.T) {
	seen := map[matchKey]string{}
	for _, f := range symbolsProfileFixtures {
		k := matchKeyOf(f.sym)
		if prev, ok := seen[k]; ok {
			t.Errorf("match-key collision under (Package,Enclosing,Name,Descriptor,Kind):\n  %q\n  %q\n  key=%+v",
				prev, f.note, k)
			continue
		}
		seen[k] = f.note
	}
}

// TestSymbolsProfileFixtures_OverloadMutationControl is the C3 mutation control, isolated so a
// reviewer sees exactly what must stay red under an arity-only encoding: two same-arity
// overloads (Deserialize(string) vs Deserialize(Type)) that differ ONLY in a parameter type
// MUST be unequal. Collapse Descriptor to arity and this test fails.
func TestSymbolsProfileFixtures_OverloadMutationControl(t *testing.T) {
	var a, b *plugin.Symbol
	for i := range symbolsProfileFixtures {
		s := &symbolsProfileFixtures[i].sym
		if s.Name != "Deserialize" {
			continue
		}
		switch s.Descriptor {
		case "(string)":
			a = s
		case "(Type)":
			b = s
		}
	}
	if a == nil || b == nil {
		t.Fatalf("mutation control requires both Deserialize(string) and Deserialize(Type) fixtures; got string=%v type=%v", a != nil, b != nil)
	}
	if matchKeyOf(*a) == matchKeyOf(*b) {
		t.Errorf("Deserialize(string) and Deserialize(Type) share a match key — encoding is arity-only, not signature-based (C3 mutation control fails):\n  %+v", matchKeyOf(*a))
	}
}

// TestSymbolsProfileFixtures_TypeParamNameRenameStable locks Correction 1 (nickel barrier
// correction 2026-08-06): generic identity is POSITIONAL/ARITY, never type-parameter names. Two
// symbols identical in Kind/Package/Enclosing/Name and differing ONLY in a type-parameter *name*
// — an interface generic method `T Get<T>(T)` and an override/impl that renames the type param to
// `U` (`U Get<U>(U)`) — must be EQUAL under the match key, because the Descriptor is spelled
// positionally (`1(!!0)) with no name in it. This is the complement of the mutation control: the
// mutation control proves a real parameter-TYPE difference stays DISTINCT; this proves a
// type-param NAME difference collapses to EQUAL. If a future edit put type-param names back into
// the Descriptor, these two would diverge and this test goes red.
func TestSymbolsProfileFixtures_TypeParamNameRenameStable(t *testing.T) {
	// Interface declaration `TResult Get<TResult>(TResult key)` — the parameter is method
	// type-param 0, so Descriptor = `1(!!0). DisplayName carries the source spelling.
	ifaceDecl := plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "pkg:nuget/MyApp",
		Enclosing: "MyApp.IRepository", Name: "Get", Descriptor: "`1(!!0)",
		DisplayName: "IRepository.Get<TResult>(TResult)",
	}
	// The implementation renames the type param to `U`: `U Get<U>(U key)`. Source producer sees a
	// different NAME, but the positional Descriptor is byte-identical.
	renamedImpl := plugin.Symbol{
		Kind: plugin.SymbolKindMethod, Package: "pkg:nuget/MyApp",
		Enclosing: "MyApp.IRepository", Name: "Get", Descriptor: "`1(!!0)",
		DisplayName: "IRepository.Get<U>(U)",
	}
	if ifaceDecl.DisplayName == renamedImpl.DisplayName {
		t.Fatalf("test is vacuous — the two symbols must differ in their source type-param name (DisplayName)")
	}
	if matchKeyOf(ifaceDecl) != matchKeyOf(renamedImpl) {
		t.Errorf("type-param rename changed identity — generic Descriptor is name-based, not positional/arity (Correction 1 fails):\n  iface  = %+v\n  impl   = %+v",
			matchKeyOf(ifaceDecl), matchKeyOf(renamedImpl))
	}
}
