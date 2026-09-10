package symboltest

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/kotlinanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// kotlinRefClasses is the deterministic compiled form of the reference fixture — the exact
// classfile.Class shapes the Kotlin compiler emits for the source constructs the profile
// describes. It is built in memory (no kotlinc, no bytes) so the interop check is hermetic
// and reproducible: the "compiled Kotlin" is modeled as the bytecode identities a Java
// caller would see, and the producer's normalization must recover them.
func kotlinRefClasses() []classfile.Class {
	m := func(owner, name, desc string) classfile.Method {
		return classfile.Method{Ref: classfile.MethodRef{Owner: owner, Name: name, Descriptor: desc}}
	}
	const (
		facade    = "com/example/kref/DemoKt"
		cls       = "com/example/kref/UrlService"
		companion = "com/example/kref/UrlService$Companion"
	)
	return []classfile.Class{
		{
			Name: facade,
			Methods: []classfile.Method{
				m(facade, "topLevel", "(Ljava/lang/String;)V"),
				m(facade, "topLevel$default", "(Ljava/lang/String;ILjava/lang/Object;)V"),
			},
		},
		{
			Name:  cls,
			Super: "java/lang/Object",
			Methods: []classfile.Method{
				m(cls, "<init>", "(Ljava/lang/String;)V"),
				m(cls, "fetch", "(Ljava/lang/String;)Ljava/lang/String;"),
				m(cls, "fetch", "(I)Ljava/lang/String;"),
			},
		},
		{
			Name: companion,
			Methods: []classfile.Method{
				m(companion, "create", "()Lcom/example/kref/UrlService;"),
			},
		},
	}
}

// kotlinRefEmitted normalizes the compiled fixture the same way kotlinanalysis.IndexSymbols
// does — one package symbol per distinct package, a type symbol per class, a method symbol
// per method — driving the REAL producer normalization (SymbolFromClass / SymbolFromMethodRef).
func kotlinRefEmitted() []plugin.Symbol {
	var syms []plugin.Symbol
	seenPkg := map[string]bool{}
	for _, c := range kotlinRefClasses() {
		typeSym := kotlinanalysis.SymbolFromClass(c)
		if typeSym.Package != "" && !seenPkg[typeSym.Package] {
			seenPkg[typeSym.Package] = true
			syms = append(syms, plugin.Symbol{Kind: plugin.SymbolKindPackage, Package: typeSym.Package})
		}
		syms = append(syms, typeSym)
		for _, mt := range c.Methods {
			syms = append(syms, kotlinanalysis.SymbolFromMethodRef(mt.Ref))
		}
	}
	return syms
}

// TestKotlinReferenceProfile is the K4 interop acceptance check: it drives the Kotlin
// producer's canonical normalization over the reference fixture and asserts every profile
// row's independently-spelled Java-visible identity is matched. Green means a Kotlin-declared
// symbol resolves EQUAL to its Java-visible bytecode form for all eight categories — the seam
// GRANITE rides. It stays green precisely while that equality holds and goes red on any
// normalization drift.
func TestKotlinReferenceProfile(t *testing.T) {
	AssertProfile(t, KotlinReferenceProfile(), kotlinRefEmitted())
}

// TestKotlinOverloadsSeparateByDescriptor pins the bytecode-identity advantage over the
// source-lexical Java lane: two same-name, same-arity methods that Java collapses to an
// arity count (Calc#f(1).) remain DISTINCT under Kotlin's verbatim JVM descriptor. If the
// normalization ever discarded the descriptor, these two identity keys would collide.
func TestKotlinOverloadsSeparateByDescriptor(t *testing.T) {
	a := kotlinanalysis.SymbolFromMethodRef(classfile.MethodRef{Owner: "com/example/kref/UrlService", Name: "fetch", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"})
	b := kotlinanalysis.SymbolFromMethodRef(classfile.MethodRef{Owner: "com/example/kref/UrlService", Name: "fetch", Descriptor: "(I)Ljava/lang/String;"})
	if IdentityKey(a) == IdentityKey(b) {
		t.Fatalf("same-name overloads collapsed to one identity: %+v", IdentityKey(a))
	}
}
