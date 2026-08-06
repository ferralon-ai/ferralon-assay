// Package pythonanalysis is the in-process Python analysis engine that backs the
// tegron-plugin-python subprocess. It parses Python source from a checked-out build
// directory with a focused, dependency-free lexical scanner, emits stable SCIP-shaped
// symbol identities for the declared module-level functions, classes, and methods, and
// answers the IndexSymbols / ResolveDependencySymbols / ResolveDependencyVersions
// operations of the LanguagePlugin contract in the plugin package.
//
// Why a source scanner (and not scip-python / pyright): the canonical Python indexer
// (scip-python) requires Node.js + pyright + a resolved environment, none of which is
// offline or on the Assess path here. This engine mirrors the Go/Java/JS plugins'
// choice to emit SCIP "purely from the loaded program (no external indexer
// dependency)": for symbol IDENTITY a lexical scan over the declarations is sufficient
// and runs with zero external tools. A semantic scip-python index is a DEFERRED,
// optional Prove-tier seam (env-gated, TEGRON_PYTHON_ANALYZER_IMAGE), never on the
// Assess critical path. Where the scanner cannot resolve a construct (it never resolves
// getattr/decorator/metaclass dynamism) it declares partiality rather than over-claiming
// an edge it did not resolve.
//
// Import boundary (inv.8): this sub-package MAY import internal/plugin for the shared
// value types. The FORBIDDEN edge is the reverse one — internal/plugin MUST NOT import
// pythonanalysis — so the scanner links only into the subprocess binary, never into
// tegrond.
package pythonanalysis

import (
	"fmt"
	"strings"
)

// scipManager is the SCIP "manager" token for Python symbols. The standard scip-python
// scheme is "scip-python python <package> <version> <descriptors>"; we keep the python
// manager so the IDs are recognizable to SCIP tooling even though local source carries
// no resolved PyPI coordinates.
const scipManager = "scip-python python"

// localCoordinate is the package/version placeholder used for symbols declared in the
// build dir's own source rather than a resolved PyPI artifact. It keeps the symbol
// string well-formed and stable (the Go/Java/JS plugins use "." the same way).
const localCoordinate = "."

// scipSymbol builds a stable, well-formed SCIP symbol string for a Python declaration
// from its module path (the source file's import path — the file's path relative to the
// build root, '/'-joined, extension stripped, a trailing "/__init__" folded to the
// package dir), the chain of enclosing class names, and a trailing per-declaration
// descriptor.
//
// Grammar (standard SCIP, space-separated):
//
//	scip-python python <package> <version> <descriptors>
//
// where <descriptors> is, for a method Delta#apply in module deepdiff/delta:
//
//	deepdiff/delta/   namespace descriptor — the module path, '/'-terminated
//	Delta#            type descriptor — enclosing class
//	apply().          method descriptor — the method (arity-disambiguated)
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
// "deepdiff/delta" -> "deepdiff/delta/". The empty module (a source at the build root
// with no path) renders as "_root_/" so symbols stay distinct and well-formed.
func moduleDescriptor(module string) string {
	if module == "" {
		return "_root_/"
	}
	return module + "/"
}

// functionDescriptor is the trailing descriptor for a function/method declaration.
// Arity disambiguates same-named declarations, e.g. "apply()." for zero params or
// "apply(2)." for two.
func functionDescriptor(name string, arity int) string {
	if arity == 0 {
		return name + "()."
	}
	return fmt.Sprintf("%s(%d).", name, arity)
}

// classDescriptor is the trailing descriptor for a class declaration: "Delta#".
func classDescriptor(name string) string {
	return name + "#"
}
