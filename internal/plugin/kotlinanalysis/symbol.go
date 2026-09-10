package kotlinanalysis

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// symbol.go — the Kotlin→JVM canonical symbol normalization. This is the K4 interop
// seam: because Kotlin is analyzed as bytecode, a symbol is derived from the SAME
// .class a Java caller observes, so a Kotlin-declared symbol and its Java-visible form
// normalize to the IDENTICAL plugin.Symbol match key (Kind/Package/Enclosing/Name/
// Descriptor). The rules below are the R3 ABI table made executable.
//
// Design decisions (R3):
//   - Names and descriptors are preserved VERBATIM (Name/Descriptor). Kotlin's mangling
//     (`internal`→`-hash`, value-class `-impl`, `access$…` bridges) is the real JVM name a
//     Java caller must use; stripping it would break interop identity. Only DisplayName is
//     de-mangled for humans.
//   - The declaring class is the JVM binary name after the package, `$`-preserved:
//     a companion's declaring class is `Outer$Companion`, an object's is its own class.
//     This IS the Enclosing chain — it is the bytecode truth both languages share.
//   - Extension-function receivers ride as parameter 0 of the JVM descriptor, which
//     Descriptor carries verbatim; no special handling is needed here.
//   - Generated=true marks every compiler synthetic: the `<File>Kt` facade classes and
//     their members, `$default` argument bridges, and `access$` accessors.

// SymbolFromMethodRef normalizes one JVM method reference (owner/name/descriptor, exactly
// as the classfile parser resolved it from bytecode) to the canonical plugin.Symbol. It is
// exported because it is the interop seam: the K4 cross-lane check drives it to prove a
// Kotlin symbol equals its Java-visible form.
func SymbolFromMethodRef(ref classfile.MethodRef) plugin.Symbol {
	pkg, cls := splitInternalName(ref.Owner)
	kind := plugin.SymbolKindMethod
	if ref.Name == "<init>" {
		kind = plugin.SymbolKindConstructor
	}
	return plugin.Symbol{
		Kind:        kind,
		Package:     pkg,
		Enclosing:   cls,
		Name:        ref.Name,
		Descriptor:  ref.Descriptor,
		Generated:   isGeneratedClass(cls) || isGeneratedMember(ref.Name),
		DisplayName: methodDisplayName(cls, ref.Name, ref.Descriptor),
		SCIP:        ref.String(),
	}
}

// SymbolFromClass normalizes a parsed class to its canonical type Symbol. The binary
// name after the package is the type identity, `$`-preserved so a nested/companion type
// keeps the enclosing chain the JVM (and a Java caller) uses.
func SymbolFromClass(c classfile.Class) plugin.Symbol {
	pkg, cls := splitInternalName(c.Name)
	enclosing, name := splitNestedName(cls)
	return plugin.Symbol{
		Kind:        plugin.SymbolKindType,
		Package:     pkg,
		Enclosing:   enclosing,
		Name:        name,
		Generated:   isGeneratedClass(cls),
		DisplayName: strings.ReplaceAll(cls, "$", "."),
		SCIP:        c.Name,
	}
}

// splitInternalName splits a JVM internal class name ("com/example/Outer$Companion")
// into a dotted package ("com.example") and the binary class name after the last slash
// ("Outer$Companion", `$` preserved). A name with no slash is in the unnamed package.
func splitInternalName(internal string) (pkg, cls string) {
	if i := strings.LastIndex(internal, "/"); i >= 0 {
		return strings.ReplaceAll(internal[:i], "/", "."), internal[i+1:]
	}
	return "", internal
}

// splitNestedName splits a `$`-joined binary class name ("Outer$Inner$Deep") into the
// enclosing chain ("Outer.Inner") and the innermost simple name ("Deep"). A top-level
// class has an empty enclosing chain. Kotlin synthetic markers ($Companion, $default) are
// ordinary `$` segments here — the split is purely structural.
func splitNestedName(cls string) (enclosing, name string) {
	if i := strings.LastIndex(cls, "$"); i >= 0 {
		return strings.ReplaceAll(cls[:i], "$", "."), cls[i+1:]
	}
	return "", cls
}

// isGeneratedClass reports whether a binary class name is a compiler synthetic: the
// `<File>Kt` top-level facade, or a `$Companion` / `$WhenMappings` / `$…$…` desugaring
// class. The `Kt` facade is the one Kotlin-specific heuristic; it is sound to over-flag
// Generated (it never changes identity, only the advisory synthetic marker).
func isGeneratedClass(cls string) bool {
	if strings.Contains(cls, "$") {
		return true
	}
	return strings.HasSuffix(cls, "Kt")
}

// isGeneratedMember reports whether a method name is a compiler-synthesized member:
// a `$default` argument bridge or an `access$` synthetic accessor. Both are real JVM
// names preserved verbatim in Name; the flag is the advisory synthetic marker.
func isGeneratedMember(name string) bool {
	return strings.HasSuffix(name, "$default") ||
		strings.Contains(name, "$default$") ||
		strings.HasPrefix(name, "access$")
}

// methodDisplayName renders a human-readable, de-mangled label. Identity never keys on
// DisplayName (SYMBOL_PROFILE.md), so de-mangling here is safe: a Kotlin `internal`
// function `fetch-a1b2c3` displays as `fetch`.
func methodDisplayName(cls, name, descriptor string) string {
	display := name
	if i := strings.IndexByte(display, '-'); i > 0 {
		display = display[:i]
	}
	return strings.ReplaceAll(cls, "$", ".") + "." + display + descriptor
}
