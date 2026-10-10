// Package cfamilyanalysis is the C/C++ (C-family) language lane's analysis surface.
//
// The front half is live: compiledb parses compile_commands.json into per-TU build context
// (file, c or c++, std, target, compiler), deriveBuildContext turns that into the lane's
// toolchains and generators, and ResolveDependencyVersions reads Conan and vcpkg manifests. C++
// TUs are carried through all of it exactly as C TUs are.
//
// The graph operations (IndexSymbols, CallGraph, FindIngresses, Reachability, ComputeTaint,
// ResolveDependencySymbols, ResolveInventory) are contract-present and return declared
// partiality (Unsupported), never an empty-but-complete result and never a fabricated one: the
// inv.5 fail-open posture. Any C/C++ analysis toolchain links ONLY into the
// cmd/assay-plugin-cfamily subprocess binary (inv.8), never into the host binary.
package cfamilyanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// IndexSymbols is contract-present but unimplemented at Phase 0: no C/C++ symbol index exists
// yet (Phase 1: scip-clang over compile_commands.json). Honest absence, never a fabricated index.
func IndexSymbols(_ context.Context, _ plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	return plugin.SymbolIndexResult{Partiality: plugin.Unsupported()}, nil
}

// ResolveDependencySymbols is contract-present but unimplemented at Phase 0. C/C++ advisories
// name a version range, not a vulnerable symbol, so symbol resolution is deferred to Phase 3
// (patch-diff derivation); declared absent here, never a guessed symbol.
func ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{Partiality: plugin.Unsupported()}, nil
}

// CallGraph is contract-present but unimplemented at Phase 0 (Phase 1: clang/scip-clang direct-call
// graph). Honest absence, never a fabricated graph.
func CallGraph(_ context.Context, _ plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{Partiality: plugin.Unsupported()}, nil
}

// FindIngresses is contract-present but unimplemented at Phase 0. Honest absence, never invented
// entry points.
func FindIngresses(_ context.Context, _ plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{Partiality: plugin.Unsupported()}, nil
}

// Reachability is contract-present but unimplemented at Phase 0. The operation itself is a stub,
// so it declares Unsupported — never confident-unreachable (inv.5).
func Reachability(_ context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{Partiality: plugin.Unsupported()}, nil
}

// ComputeTaint is contract-present but unimplemented at Phase 0. Honest absence.
func ComputeTaint(_ context.Context, _ plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	return plugin.TaintResult{Partiality: plugin.Unsupported()}, nil
}

// GenerateHarness is contract-present but unimplemented, mirroring every other lane: the effect
// proof rides the Prove-tier sandbox, not a plugin-generated harness.
func GenerateHarness(_ context.Context, _ plugin.GenerateHarnessRequest) (plugin.HarnessResult, error) {
	return plugin.HarnessResult{Partiality: plugin.Unsupported()}, nil
}

// BuildManifest is contract-present but unimplemented at Phase 0. C/C++ has no single canonical
// manifest to parse; the Phase-1 build context comes from compile_commands.json. The RuntimeSpec
// and ResolverSpec are left as their honest zero values — no fabricated toolchain (inv.5).
func BuildManifest(_ context.Context, _ plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return plugin.BuildManifestResult{Partiality: plugin.Unsupported()}, nil
}

// ResolveInventory is contract-present but unimplemented at Phase 0. It returns an honestly-partial
// inventory (Unsupported), NOT an empty-but-successful one — a zero-node Complete() inventory would
// read downstream as "this build has no dependencies".
func ResolveInventory(_ context.Context, _ plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{Partiality: plugin.Unsupported()}, nil
}

// manifestContentVersion is the C-family capability manifest's content version; it bumps when a
// later increment adds a supported axis.
const manifestContentVersion = "1.0.0"

// CapabilityManifest returns the C-family lane's capability manifest, C profile. Every listed axis
// is one the lane does today; all slices are pre-sorted. It is a static fact and takes no input.
//
//   - Resolvers: the files the lane reads. compile_commands.json and CMakeCache.txt give the
//     build context; conan.lock, conanfile.txt and vcpkg.json give dependency versions (exact
//     pins only, everything else fails open).
//   - Runtimes: c, the language mode whose toolchains the build context reports for this
//     profile. C++ TUs are parsed and carried too; the C++ profile is authored with its graph
//     semantics.
//   - Analyzers: the lane's own parsers.
//
// GraphSemantics and DynamicBoundaries are left empty because they belong to the graph engine,
// which is not wired yet. Frameworks is empty because C has no dominant ingress framework.
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
		},
		Runtimes: []string{"c"},
		Analyzers: []string{
			"cfamilyanalysis/compiledb",
			"cfamilyanalysis/versions",
		},
	}
}
