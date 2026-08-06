// Package javaanalysis is the in-process Java analysis engine that backs the
// tegron-plugin-java subprocess. It parses Java source from a checked-out build
// directory with a focused, dependency-free declaration parser, emits stable
// SCIP symbol identities for the declared types/methods/fields, and answers the
// IndexSymbols operation of the LanguagePlugin contract in the plugin package.
//
// Why a source-declaration parser (and not scip-java/javac): the canonical Java
// indexer (scip-java) requires a JVM + a resolved build (Maven/Gradle), which is
// neither offline nor available in CI here. This engine mirrors the Go plugin's
// choice to emit SCIP "purely from the loaded program (no scip-go dependency)":
// for symbol IDENTITY (the IndexSymbols op), declarations are sufficient and the
// parse runs with zero external tools, no JVM, and no cgo. Where the parser
// cannot resolve a construct (it never tries to resolve types or generics
// semantically), it declares partiality rather than over-claiming.
//
// Import boundary (inv.8): this sub-package MAY import internal/plugin for the
// shared value types. The FORBIDDEN edge is the reverse one — internal/plugin
// MUST NOT import javaanalysis — so the parser links only into the subprocess
// binary, never into tegrond.
package javaanalysis

import (
	"fmt"
	"strings"
)

// scipManager is the SCIP "manager" token for Java symbols. The standard
// scip-java scheme is "scip-java maven <package> <version> <descriptors>"; we
// keep the maven manager so the IDs are recognizable to SCIP tooling even though
// local source carries no Maven coordinates.
const scipManager = "scip-java maven"

// localCoordinate is the package/version placeholder used for symbols that are
// declared in the build dir's own source rather than a resolved Maven artifact.
// It keeps the symbol string well-formed and stable (the Go plugin uses "." the
// same way for unknown module versions).
const localCoordinate = "."

// scipSymbol builds a stable, well-formed SCIP symbol string for a Java
// declaration from its enclosing package, the chain of enclosing type names, and
// a trailing per-declaration descriptor.
//
// Grammar (standard SCIP, space-separated):
//
//	scip-java maven <package> <version> <descriptors>
//
// where <descriptors> is, for a method Foo.Bar#baz(int):
//
//	com/example/pkg/   namespace descriptor — the package, dots rendered as '/'
//	Foo#                type descriptor — outer type
//	Bar#                type descriptor — nested type
//	baz().              method descriptor — the method (arity-erased; see note)
//
// Note on overloads: a fully disambiguated scip-java method descriptor encodes
// the erased signature. This engine does not type-resolve parameters, so it
// disambiguates overloads by arity ("baz(2).") rather than by type — a declared,
// honest approximation recorded via Partiality, never a silent collision.
func scipSymbol(pkg string, enclosing []string, descriptor string) string {
	var b strings.Builder
	b.WriteString(scipManager)
	b.WriteByte(' ')
	b.WriteString(localCoordinate) // package coordinate (local source)
	b.WriteByte(' ')
	b.WriteString(localCoordinate) // version
	b.WriteByte(' ')
	b.WriteString(packageDescriptor(pkg))
	for _, t := range enclosing {
		b.WriteString(t)
		b.WriteByte('#')
	}
	b.WriteString(descriptor)
	return b.String()
}

// packageDescriptor renders a dotted Java package as a SCIP namespace
// descriptor: "com.example.pkg" -> "com/example/pkg/". The default (unnamed)
// package renders as "_root_/" so symbols stay distinct and well-formed.
func packageDescriptor(pkg string) string {
	if pkg == "" {
		return "_root_/"
	}
	return strings.ReplaceAll(pkg, ".", "/") + "/"
}

// typeDescriptor is the trailing descriptor for a type declaration: "Name#".
func typeDescriptor(name string) string { return name + "#" }

// methodDescriptor is the trailing descriptor for a method declaration. Overloads
// are disambiguated by parameter arity, e.g. "handle()." for zero params or
// "handle(2)." for two — an arity-based approximation (see scipSymbol note).
func methodDescriptor(name string, arity int) string {
	if arity == 0 {
		return name + "()."
	}
	return fmt.Sprintf("%s(%d).", name, arity)
}

// fieldDescriptor is the trailing descriptor for a field declaration: "name.".
func fieldDescriptor(name string) string { return name + "." }
