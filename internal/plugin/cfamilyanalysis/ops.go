// Package cfamilyanalysis is the C/C++ (C-family) language lane's analysis surface.
//
// compiledb parses compile_commands.json into per-TU build context (file, c or c++, std, target,
// compiler), deriveBuildContext turns that into the lane's toolchains and generators, and
// ResolveDependencyVersions and ResolveInventory read Conan and vcpkg manifests. C++ TUs are
// carried through all of it exactly as C TUs are.
//
// The graph operations (IndexSymbols, CallGraph, FindIngresses, Reachability, ComputeTaint, and
// ResolveDependencySymbols for a named symbol) are served by the cgx lane, which links only into
// the assay-plugin-cfamily subprocess binary (inv.8), never into the host binary. This package
// hands that lane its inputs (ReadGraphSources) and declares the C/C++ norm, an advisory that
// names no vulnerable symbol, without consulting any engine. GenerateHarness returns declared
// partiality (Unsupported), never an empty-but-complete result (inv.5).
package cfamilyanalysis

import (
	"context"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencySymbols declares advisory_symbol_absent when the request names no vulnerable
// symbol, which is the norm for C/C++ advisories: they carry a version range only, so there is
// nothing to search the graph for and symbol-level reachability is never attempted. A request
// that names a symbol is the graph engine's to resolve; here it is Unsupported.
func ResolveDependencySymbols(_ context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	if !NamesSymbol(req) {
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(plugin.PartialReasonAdvisorySymbolAbsent), Resolved: []plugin.Symbol{}}, nil
	}
	return plugin.SymbolResolutionResult{Partiality: plugin.Unsupported()}, nil
}

// NamesSymbol reports whether req names at least one non-blank advisory symbol.
func NamesSymbol(req plugin.ResolveSymbolsRequest) bool {
	for _, s := range req.AdvisorySymbols {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// GenerateHarness is contract-present but unimplemented, mirroring every other lane: the effect
// proof rides the Prove-tier sandbox, not a plugin-generated harness.
func GenerateHarness(_ context.Context, _ plugin.GenerateHarnessRequest) (plugin.HarnessResult, error) {
	return plugin.HarnessResult{Partiality: plugin.Unsupported()}, nil
}

// manifestContentVersion is the C-family capability manifest's content version; it bumps when a
// later increment adds a supported axis.
const manifestContentVersion = "1.2.0"

// CapabilityManifest returns the C-family lane's capability manifest. Every listed axis is one
// the lane does today; all slices are pre-sorted. It is a static fact and takes no input.
//
//   - Resolvers: the files the lane reads. compile_commands.json and CMakeCache.txt give the
//     build context; conan.lock, conanfile.txt, vcpkg's installed status and vcpkg.json give
//     dependency versions and the inventory (exact pins only, everything else fails open).
//   - Runtimes: c and c++. Both run through the same cgx tree-sitter graph; C++ is a stepping
//     stone (no template, overload or exception precision) and declares its residue.
//   - GraphSemantics: direct, cgx's resolved direct calls; fn_ptr_candidate, cgx's possible-tier
//     candidate edges at a call through a function-pointer parameter; virtual_candidate, cgx's
//     C++ virtual calls, which go to every override. A call through a struct member gets no
//     edge, so the function-pointer site stays a declared boundary as well.
//   - DynamicBoundaries: the residue the lane names on every graph result that crosses it.
//   - Analyzers: the lane's own parsers and the cgx engine.
//
// Frameworks is empty because C has no dominant ingress framework.
func CapabilityManifest() capability.Manifest {
	return capability.Manifest{
		Version:   manifestContentVersion,
		Language:  "cfamily",
		Supported: true,
		Resolvers: []string{
			"CMakeCache.txt",
			"compile_commands.json",
			"conan.lock",
			"conanfile.txt",
			"vcpkg.json",
			"vcpkg_installed/vcpkg/status",
		},
		Runtimes:       []string{"c", "c++"},
		GraphSemantics: []string{"direct", "fn_ptr_candidate", "virtual_candidate"},
		DynamicBoundaries: []string{
			"fn_ptr",
			"macro_expansion",
			"native_link_boundary",
			"vtable",
		},
		Analyzers: []string{
			"cfamilyanalysis/compiledb",
			"cfamilyanalysis/versions",
			"cfamilycgx/cgx",
		},
	}
}
