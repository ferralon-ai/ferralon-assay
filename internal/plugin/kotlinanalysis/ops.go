package kotlinanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ops.go — the contract-present operations the Kotlin lane does NOT implement at Assess
// tier, each returning an honestly-partial result (Unsupported()), never an empty-but-
// complete one. This mirrors the convention every language plugin uses for its non-live
// ops (a zero-value Complete() result would falsely assert "nothing here"). It also holds
// the lane's honest capability manifest (K5).

// ResolveDependencySymbols is contract-present but unimplemented for Kotlin: advisory-symbol
// resolution against the codebase is not performed at this tier. Honest absence, never an
// empty match asserted complete.
func ResolveDependencySymbols(_ context.Context, _ plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{Partiality: plugin.Unsupported()}, nil
}

// ResolveDependencyVersions is contract-present but unimplemented for Kotlin: declared
// dependency versions are NOT read from build.gradle.kts/pom.xml here — Gradle version
// resolution is a declared partiality boundary (see CapabilityManifest). It returns
// no_manifest partiality so the disqualification predicate fails OPEN (inv.5: an unknown
// version is never "not affected").
func ResolveDependencyVersions(_ context.Context, _ plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return plugin.DependencyVersionResult{Partiality: plugin.Partial(plugin.PartialReasonNoManifest)}, nil
}

// ComputeTaint is contract-present but unimplemented: variable-level dataflow is not
// modeled at Assess tier. Honest absence.
func ComputeTaint(_ context.Context, _ plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	return plugin.TaintResult{Partiality: plugin.Unsupported()}, nil
}

// GenerateHarness is contract-present but unimplemented: Kotlin's effect proof rides the
// Prove-tier repro-runtime sandbox, not a plugin-generated harness.
func GenerateHarness(_ context.Context, _ plugin.GenerateHarnessRequest) (plugin.HarnessResult, error) {
	return plugin.HarnessResult{Partiality: plugin.Unsupported()}, nil
}

// BuildManifest is contract-present but unimplemented at this tier. Honest absence.
func BuildManifest(_ context.Context, _ plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return plugin.BuildManifestResult{Partiality: plugin.Unsupported()}, nil
}

// ResolveInventory is contract-present but unimplemented: no whole-graph dependency
// inventory is resolved. It declares Unsupported() — never Complete() with zero nodes,
// which would falsely assert an empty dependency graph.
func ResolveInventory(_ context.Context, _ plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return plugin.DependencyInventory{Partiality: plugin.Unsupported()}, nil
}

// manifestContentVersion is the Kotlin capability manifest's content version; it bumps when
// a later increment adds a supported axis.
const manifestContentVersion = "1.0.0"

// CapabilityManifest returns the Kotlin lane's HONEST capability manifest (K5): every
// Supported axis is one the analyzer genuinely does at Assess tier over bytecode, and every
// desugaring boundary it cannot soundly resolve is a declared DynamicBoundary — never a
// silent gap. All slices are pre-sorted (no map is an iteration source on the encoding
// path). It is a static fact, so it takes no build input.
//
// The axes, and why each is honest:
//   - Resolvers: none. First-party code is read as compiled bytecode, not from a manifest
//     file, and dependency-version resolution from build files is deferred (a boundary
//     below) — so no resolver format is claimed.
//   - Runtimes: jvm — the only runtime the analyzer targets.
//   - GraphSemantics: cha — depreach's class-hierarchy analysis, used unchanged.
//   - Frameworks: none — framework ingress (Spring) is deliberately not detected here.
//   - DynamicBoundaries: the frontiers where a sound static graph must fail open —
//     coroutine builder dispatch, inline-function edge erasure, invokedynamic (SAM/lambda),
//     reflection, and the deferred Gradle build-file version resolution.
//   - Analyzers: the shared classfile reader + depreach engine the lane rides.
func CapabilityManifest() capability.Manifest {
	return capability.Manifest{
		Version:        manifestContentVersion,
		Language:       "kotlin",
		Supported:      true,
		Runtimes:       []string{"jvm"},
		GraphSemantics: []string{"cha"},
		DynamicBoundaries: []string{
			"coroutine_dispatch",
			"gradle_version_resolution",
			"inline_function",
			"invokedynamic",
			"reflection",
		},
		Analyzers: []string{
			"javaanalysis/classfile",
			"javaanalysis/depreach",
		},
	}
}
