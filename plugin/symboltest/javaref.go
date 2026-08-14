package symboltest

import "github.com/ferralon-ai/ferralon-assay/plugin"

// javaRefPkg is the dotted Java package of the testdata/javaref fixture the Java
// reference profile is driven against.
const javaRefPkg = "com.example.web"

// javaRefGap is the generic KnownGap the categories the lexical producer CAN see
// but does not yet populate structurally carry: javaanalysis emits
// Symbol{SCIP, DisplayName, Package} via symbolsFromParse (index.go:105-109) with
// the structured identity fields (Kind/Enclosing/Name/Descriptor/Generated) empty.
// Populating them is PLAN-242's work; until then these rows are declared gaps and
// pass under xfail. It is distinct from the four MEASURED-red rows below, whose
// gap is a Java-specific canonicalization defect this cycle grades (§C2), not the
// cross-lane structured-population gap that goref carries identically.
func javaRefGap() *KnownGap {
	return &KnownGap{
		Reason: "structured identity unpopulated by current lexical producer",
		Closes: "PLAN-242",
	}
}

// JavaReferenceProfile is the Java instance of the canonical symbol profile
// (profile-format.md §5, slot §4.3.2), and the exemplar the JS/Python/.NET lanes
// copy for their PLAN-0x0. Unlike GoReferenceProfile — which declares every row a
// KnownGap and is GREEN under xfail — this profile deliberately makes FOUR rows
// must-match against a canonical Want the current lexical Java producer cannot
// satisfy, so the golden table is a MEASURED RED for the four enumerated
// Java-specific canonicalization reasons recorded in
// execution/golden-red-reasons.md (§C2):
//
//   - overloads/generics → arity-not-descriptor  (scip.go disambiguates by
//     parameter COUNT, not type: f(int)/f(String) collapse to Calc#f(1).)
//   - constructors       → no-<init> canonicalization (rendered as a method named
//     for the class: UrlService#UrlService(1)., no <init>, Kind unset)
//   - generated symbols  → no bridge/synthetic handling (the source parser never
//     sees the compiler-synthesized Box#get()Ljava/lang/Object; bridge)
//   - packages/modules   → no shading/relocation map (a shaded dependency
//     coordinate has no emitted symbol)
//
// The remaining categories the producer can see (types, methods, nested
// declarations, and the fixture's own package) are declared KnownGaps — their only
// gap is the cross-lane structured-population one PLAN-242 closes — and Java's
// absent free-function category is NotApplicable. So exactly the four rows above
// fail; their category/construct set equals the deposit's reason set. This builds
// only the table; the drive against the real producer lives in javaref_test.go.
func JavaReferenceProfile() Profile {
	return Profile{
		Language: "java",
		Rows: []ProfileRow{
			// packages/modules — the fixture's own package. The producer sets
			// Package but not Kind, so it is a structured-population gap (xfail).
			{
				Category:  "packages/modules",
				Construct: "package clause com.example.web",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: javaRefPkg},
				Gap:       javaRefGap(),
			},
			// packages/modules — MEASURED RED: a shaded/relocated dependency
			// coordinate. The producer has no relocation map, so no symbol is
			// emitted under the shaded coordinate.
			{
				Category:  "packages/modules",
				Construct: "shaded dependency coordinate com.example.shaded.urlkit",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: "com.example.shaded.urlkit"},
			},
			{
				Category:  "types",
				Construct: "top-level class UrlService",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: javaRefPkg, Name: "UrlService"},
				Gap:       javaRefGap(),
			},
			{
				Category:  "functions",
				Construct: "free function",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindFunction, Package: javaRefPkg},
				NA:        &NotApplicable{Reason: "Java has no free functions; every callable is a method or constructor on a type"},
			},
			{
				Category:  "methods",
				Construct: "method UrlService#fetch(String)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: javaRefPkg, Enclosing: "UrlService", Name: "fetch", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"},
				Gap:       javaRefGap(),
			},
			// constructors — MEASURED RED: canonical <init> + JVM descriptor; the
			// producer renders the constructor as a method named for the class
			// (UrlService#UrlService(1).), with no <init> and Kind unset.
			{
				Category:  "constructors",
				Construct: "constructor UrlService(String)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindConstructor, Package: javaRefPkg, Enclosing: "UrlService", Name: "<init>", Descriptor: "(Ljava/lang/String;)V"},
			},
			// overloads/generics — MEASURED RED: arity-not-descriptor. f(int) and
			// f(String) both collapse to Calc#f(1).; the canonical id separates
			// them by full JVM parameter descriptor.
			{
				Category:  "overloads/generics",
				Construct: "same-arity overload Calc#f(String) vs Calc#f(int)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: javaRefPkg, Enclosing: "Calc", Name: "f", Descriptor: "(Ljava/lang/String;)V"},
			},
			{
				Category:  "nested declarations",
				Construct: "nested class UrlService.Config",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: javaRefPkg, Enclosing: "UrlService", Name: "Config"},
				Gap:       javaRefGap(),
			},
			// generated symbols — MEASURED RED: no bridge/synthetic handling. The
			// compiler-synthesized Box#get()Ljava/lang/Object; bridge is invisible
			// to the source parser, so no Generated symbol is emitted.
			{
				Category:  "generated symbols",
				Construct: "synthetic bridge Box#get()Ljava/lang/Object;",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: javaRefPkg, Enclosing: "Box", Name: "get", Descriptor: "()Ljava/lang/Object;", Generated: true},
			},
		},
	}
}

// javaReferenceRedReasons is the enumerated set of MEASURED-red rows the Java
// golden table lands (§C2), keyed by "<category>|<construct>" — the same identity
// AssertProfile/Evaluate report a regression under. javaref_test.go asserts the
// producer's actual regression set equals this set exactly, so the golden red is
// measured, not merely asserted, and cannot silently drift. Each entry is
// documented with its named reason in execution/golden-red-reasons.md; a red row
// absent here (or an entry here that does not go red) fails the cycle.
var javaReferenceRedReasons = map[string]string{
	"packages/modules|shaded dependency coordinate com.example.shaded.urlkit": "no-shading-relocation-map",
	"constructors|constructor UrlService(String)":                             "no-<init>-canonicalization",
	"overloads/generics|same-arity overload Calc#f(String) vs Calc#f(int)":    "arity-not-descriptor",
	"generated symbols|synthetic bridge Box#get()Ljava/lang/Object;":          "no-bridge-synthetic-handling",
}
