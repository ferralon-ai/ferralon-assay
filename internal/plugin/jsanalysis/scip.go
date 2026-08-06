// Package jsanalysis is the in-process JavaScript/TypeScript analysis engine that
// backs the tegron-plugin-js subprocess. It parses JS/TS source from a checked-out
// build directory with a focused, dependency-free lexical scanner, emits stable
// SCIP-shaped symbol identities for the declared module-level functions and class
// methods, and answers the IndexSymbols / ResolveDependencySymbols / CallGraph /
// FindIngresses operations of the LanguagePlugin contract in the plugin package.
//
// Why a source scanner (and not tsc / scip-typescript): the canonical TS indexer
// (scip-typescript) requires Node.js + a resolved tsconfig + installed
// node_modules, none of which is offline or available in CI here. This engine
// mirrors the Go and Java plugins' choice to emit SCIP "purely from the loaded
// program (no external indexer dependency)": for symbol IDENTITY and source-level
// call/ingress structure, a lexical scan over the declarations is sufficient and
// runs with zero external tools, no Node, and no cgo. Where the scanner cannot
// resolve a construct (it never type-resolves prototype chains or dynamic
// require()), it declares partiality rather than over-claiming an edge it did not
// resolve.
//
// Import boundary (inv.8): this sub-package MAY import internal/plugin for the
// shared value types. The FORBIDDEN edge is the reverse one — internal/plugin MUST
// NOT import jsanalysis — so the scanner links only into the subprocess binary,
// never into tegrond.
package jsanalysis

import (
	"fmt"
	"strings"
)

// scipManager is the SCIP "manager" token for JS/TS symbols. The standard
// scip-typescript scheme is "scip-typescript npm <package> <version>
// <descriptors>"; we keep the npm manager so the IDs are recognizable to SCIP
// tooling even though local source carries no resolved npm coordinates.
const scipManager = "scip-typescript npm"

// localCoordinate is the package/version placeholder used for symbols declared in
// the build dir's own source rather than a resolved npm artifact. It keeps the
// symbol string well-formed and stable (the Go/Java plugins use "." the same way
// for unknown module coordinates).
const localCoordinate = "."

// scipSymbol builds a stable, well-formed SCIP symbol string for a JS/TS
// declaration from its module path (the source file's path relative to the build
// root, '/'-joined, extension stripped), the chain of enclosing class names, and a
// trailing per-declaration descriptor.
//
// Grammar (standard SCIP, space-separated):
//
//	scip-typescript npm <package> <version> <descriptors>
//
// where <descriptors> is, for a method Foo#bar in module src/util:
//
//	src/util/   namespace descriptor — the module path, '/'-terminated
//	Foo#        type descriptor — enclosing class
//	bar().      method descriptor — the method (arity-disambiguated; see note)
//
// Note on overloads/arity: JS/TS has no overloading by arity, but a name can be
// declared more than once (a class method vs a module function of the same name).
// This engine disambiguates by enclosing-class chain + arity, never type-resolving
// parameters — a declared, honest approximation recorded via Partiality, never a
// silent collision.
func scipSymbol(module string, enclosing []string, descriptor string) string {
	var b strings.Builder
	b.WriteString(scipManager)
	b.WriteByte(' ')
	b.WriteString(localCoordinate) // package coordinate (local source)
	b.WriteByte(' ')
	b.WriteString(localCoordinate) // version
	b.WriteByte(' ')
	b.WriteString(moduleDescriptor(module))
	for _, t := range enclosing {
		b.WriteString(t)
		b.WriteByte('#')
	}
	b.WriteString(descriptor)
	return b.String()
}

// moduleDescriptor renders a module path as a SCIP namespace descriptor:
// "src/util" -> "src/util/". The empty module (a source at the build root with no
// path) renders as "_root_/" so symbols stay distinct and well-formed.
func moduleDescriptor(module string) string {
	if module == "" {
		return "_root_/"
	}
	return module + "/"
}

// functionDescriptor is the trailing descriptor for a function/method declaration.
// Arity disambiguates same-named declarations, e.g. "handler()." for zero params or
// "handler(2)." for two.
func functionDescriptor(name string, arity int) string {
	if arity == 0 {
		return name + "()."
	}
	return fmt.Sprintf("%s(%d).", name, arity)
}
