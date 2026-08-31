package symboltest

import "github.com/ferralon-ai/ferralon-assay/plugin"

// kotlinRefPkg is the dotted package of the Kotlin reference fixture. Because Kotlin is
// analyzed as JVM bytecode, this is the same package a Java caller of the same classes
// observes — the identity both languages share.
const kotlinRefPkg = "com.example.kref"

// Enclosing binary class names within the fixture. DemoKt is the `<File>Kt` facade the
// Kotlin compiler synthesizes for a file's top-level declarations; UrlService is an
// ordinary class; UrlService$Companion is the companion object's declaring class ($-joined,
// exactly as it appears in bytecode and to a Java caller).
const (
	kotlinRefFacade    = "DemoKt"
	kotlinRefClass     = "UrlService"
	kotlinRefCompanion = "UrlService$Companion"
)

// KotlinReferenceProfile is the Kotlin instance of the canonical symbol profile
// (profile-format.md §5), and the K4 interop reference: every Want below is spelled as the
// JVM-canonical identity a Java caller of the same bytecode would resolve, and the Kotlin
// producer's normalization (kotlinanalysis.SymbolFromMethodRef / SymbolFromClass) must emit
// exactly that. AssertProfile equality therefore IS the "a Kotlin-declared symbol resolves
// EQUAL to its Java-visible form" proof.
//
// Unlike JavaReferenceProfile — whose source-lexical producer collapses overloads to arity
// and drops <init>/generated symbols, landing four MEASURED-red rows — the Kotlin producer
// reads bytecode, so every row is must-match GREEN, including the two the Java lane cannot
// yet satisfy:
//   - overloads/generics: separated by full JVM descriptor (fetch(I) vs fetch(String)), not
//     collapsed to an arity count;
//   - constructors: the canonical <init> name and JVM descriptor, Kind=constructor;
//   - generated symbols: the $default argument bridge, Generated=true.
//
// The one Kotlin-specific desugaring surfaced here: a top-level `fun topLevel` is lowered
// onto the DemoKt facade as an ordinary static method (Kotlin free functions have no
// bytecode of their own), so the "functions" row's canonical form is a method on the facade
// class with Generated=true.
func KotlinReferenceProfile() Profile {
	return Profile{
		Language: "kotlin",
		Rows: []ProfileRow{
			{
				Category:  "packages/modules",
				Construct: "package clause com.example.kref",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: kotlinRefPkg},
			},
			{
				Category:  "types",
				Construct: "top-level class UrlService",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: kotlinRefPkg, Name: kotlinRefClass},
			},
			{
				Category:  "functions",
				Construct: "top-level fun topLevel(String), lowered onto the DemoKt facade class",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: kotlinRefPkg, Enclosing: kotlinRefFacade, Name: "topLevel", Descriptor: "(Ljava/lang/String;)V", Generated: true},
			},
			{
				Category:  "methods",
				Construct: "method UrlService.fetch(String): String",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: kotlinRefPkg, Enclosing: kotlinRefClass, Name: "fetch", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"},
			},
			{
				Category:  "constructors",
				Construct: "constructor UrlService(String)",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindConstructor, Package: kotlinRefPkg, Enclosing: kotlinRefClass, Name: "<init>", Descriptor: "(Ljava/lang/String;)V"},
			},
			{
				Category:  "overloads/generics",
				Construct: "same-name overload UrlService.fetch(Int): String, separated by JVM descriptor",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: kotlinRefPkg, Enclosing: kotlinRefClass, Name: "fetch", Descriptor: "(I)Ljava/lang/String;"},
			},
			{
				Category:  "nested declarations",
				Construct: "companion object, declaring class UrlService$Companion",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindType, Package: kotlinRefPkg, Enclosing: kotlinRefClass, Name: "Companion", Generated: true},
			},
			{
				Category:  "generated symbols",
				Construct: "default-argument bridge topLevel$default on the DemoKt facade",
				Want:      plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: kotlinRefPkg, Enclosing: kotlinRefFacade, Name: "topLevel$default", Descriptor: "(Ljava/lang/String;ILjava/lang/Object;)V", Generated: true},
			},
		},
	}
}
