// Package dotnetanalysis is the in-process .NET/C# analysis engine that backs the
// tegron-plugin-dotnet subprocess. It parses C# source from a checked-out build directory
// with a focused, dependency-free lexical scanner, emits stable SCIP-shaped symbol
// identities for the declared namespaces, types, and methods, and answers the IndexSymbols
// / ResolveDependencySymbols / ResolveDependencyVersions operations of the LanguagePlugin
// contract in the plugin package.
//
// Why a source scanner (and not scip-dotnet): the canonical .NET indexer (scip-dotnet) is
// Roslyn/MSBuild-based and requires the full .NET SDK plus a NuGet restore, none of which
// is offline or on the Assess path here. This engine mirrors the Go/Java/JS/Python plugins'
// choice to emit SCIP "purely from the loaded program (no external indexer dependency)":
// for symbol IDENTITY a lexical scan over the declarations is sufficient and runs with zero
// external tools. A semantic scip-dotnet index is a DEFERRED, optional Prove-tier seam
// (env-gated, TEGRON_DOTNET_ANALYZER_IMAGE), never on the Assess critical path. Where the
// scanner cannot resolve a construct (it never resolves interface/DI dispatch, reflection,
// or dynamic) it declares partiality rather than over-claiming an edge it did not resolve.
//
// Import boundary (inv.8): this sub-package MAY import internal/plugin for the shared value
// types. The FORBIDDEN edge is the reverse one — internal/plugin MUST NOT import
// dotnetanalysis — so the scanner links only into the subprocess binary, never into tegrond.
package dotnetanalysis

import (
	"fmt"
	"strings"
)

// scipManager is the SCIP "manager" token for .NET symbols. The standard scip-dotnet
// scheme is "scip-dotnet nuget <package> <version> <descriptors>"; we keep the nuget
// manager (the .NET package ecosystem, the analog of npm for JS) so the IDs are
// recognizable to SCIP tooling even though local source carries no resolved NuGet
// coordinates.
const scipManager = "scip-dotnet nuget"

// localCoordinate is the package/version placeholder used for symbols declared in the build
// dir's own source rather than a resolved NuGet artifact. It keeps the symbol string
// well-formed and stable (the Go/Java/JS/Python plugins use "." the same way).
const localCoordinate = "."

// scipSymbol builds a stable, well-formed SCIP symbol string for a .NET declaration from
// its namespace (dotted, e.g. "Ionic.Zip"), the chain of enclosing type names, and a
// trailing per-declaration descriptor.
//
// Grammar (standard SCIP, space-separated):
//
//	scip-dotnet nuget <package> <version> <descriptors>
//
// where <descriptors> is, for a method ZipEntry.Extract in namespace Ionic.Zip:
//
//	Ionic/Zip/   namespace descriptor — the dotted namespace, '/'-separated and terminated
//	ZipEntry#    type descriptor — enclosing type
//	Extract().   method descriptor — the method (arity-disambiguated)
func scipSymbol(namespace string, enclosing []string, descriptor string) string {
	var b strings.Builder
	b.WriteString(scipManager)
	b.WriteByte(' ')
	b.WriteString(localCoordinate) // package coordinate (local source)
	b.WriteByte(' ')
	b.WriteString(localCoordinate) // version
	b.WriteByte(' ')
	b.WriteString(namespaceDescriptor(namespace))
	for _, t := range enclosing {
		b.WriteString(t)
		b.WriteByte('#')
	}
	b.WriteString(descriptor)
	return b.String()
}

// namespaceDescriptor renders a dotted namespace as a SCIP namespace descriptor:
// "Ionic.Zip" -> "Ionic/Zip/". The empty namespace (a type declared with no namespace)
// renders as "_root_/" so symbols stay distinct and well-formed.
func namespaceDescriptor(namespace string) string {
	if namespace == "" {
		return "_root_/"
	}
	return strings.ReplaceAll(namespace, ".", "/") + "/"
}

// functionDescriptor is the trailing descriptor for a method/constructor declaration.
// Arity disambiguates same-named declarations, e.g. "Extract()." for zero params or
// "Extract(2)." for two.
//
// Target spelling: the arity-only descriptor here (and the localCoordinate="." above) is the
// pre-parity scheme. The canonical plugin.Symbol field-population contract these must move to —
// versionless Package="pkg:nuget/<coordinate>", signature-based Descriptor, generated/state-machine
// and explicit-interface handling — is specified in SYMBOLS.md (this directory), PLAN-051. PLAN-252
// re-spells this emitter to it; this cycle changes no behavior.
func functionDescriptor(name string, arity int) string {
	if arity == 0 {
		return name + "()."
	}
	return fmt.Sprintf("%s(%d).", name, arity)
}

// typeDescriptor is the trailing descriptor for a type declaration: "ZipEntry#".
func typeDescriptor(name string) string {
	return name + "#"
}
