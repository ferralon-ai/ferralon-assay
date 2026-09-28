// Package cfamilyanalysis is the C/C++ (C-family) language lane's analysis surface. At Phase 0
// (row zero) it is a skeleton: every LanguagePlugin operation is contract-present but
// unimplemented, returning its result type carrying declared partiality (Unsupported), never
// an empty-but-complete result and never a fabricated one. This is the inv.5 fail-open posture —
// an unknown is never rendered "safe"/"not reachable".
//
// The real C-family analysis (compile_commands.json ingestion, scip-clang symbol index,
// direct-call graph, dependency resolution) lands in Phase 1 and links ONLY into the
// cmd/assay-plugin-cfamily subprocess binary (inv.8), never into the host binary. This package mirrors
// the shape of kotlinanalysis/goanalysis so that seam is already in place.
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

// ResolveDependencyVersions is contract-present but unimplemented at Phase 0 (Phase 1:
// conanfile/vcpkg parse where present). Honest absence — the disqualification predicate fails
// OPEN on an unresolved version, never guesses one.
func ResolveDependencyVersions(_ context.Context, _ plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return plugin.DependencyVersionResult{Partiality: plugin.Unsupported()}, nil
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

// CapabilityManifest returns the C-family lane's honest-absent capability manifest: Supported=false,
// no axes. The lane is a Phase-0 skeleton and publishes no supported capability yet — never a
// Supported:true manifest with empty axes. Content is authored in Phase 4 once the engines land.
func CapabilityManifest() capability.Manifest {
	return capability.Manifest{
		Language:  "cfamily",
		Supported: false,
	}
}
