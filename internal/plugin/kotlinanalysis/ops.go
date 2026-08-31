package kotlinanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ops.go — the contract-present operations the Kotlin lane does NOT implement at Assess
// tier, each returning an honestly-partial result (Unsupported()), never an empty-but-
// complete one. This mirrors the convention every language plugin uses for its non-live
// ops (a zero-value Complete() result would falsely assert "nothing here"). It also holds
// the lane's honest capability manifest (K5).
//
// ResolveDependencyVersions (P1) and ResolveDependencySymbols (P2, see resolve.go) are now
// LIVE at Assess tier — the two ops that read the build's declared dependency versions and
// resolve advisory symbols against the dependency artifact. The remaining ops below stay
// honest-absent.

// ResolveDependencyVersions reads the codebase's declared dependency versions from its
// build files (pom.xml, build.gradle, build.gradle.kts) and returns the declared version
// for the advisory's coordinate. It DELEGATES to javaanalysis.ResolveDependencyVersions:
// build-file parsing is JVM-generic (Maven POM + Gradle string/map notation), not
// Java-source-specific, and firstQuoted already tolerates the Kotlin-DSL parenthesized,
// double-quoted form `implementation("g:a:v")`. Soundness rides the shared parser (inv.5):
// a version it cannot pin to a literal — a version-catalog reference (`libs.foo`), the
// `kotlin("stdlib")` helper (no coordinate literal), or an interpolated `"$version"` — is
// returned Resolved=false (UNRESOLVED), never a guessed version, so the disqualification
// predicate fails OPEN. Non-literal Gradle version forms are the residual
// gradle_version_resolution boundary the manifest still declares.
func ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return javaanalysis.ResolveDependencyVersions(ctx, req)
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

// ResolveInventory DELEGATES to javaanalysis.ResolveInventory (C6): whole-graph dependency
// inventory is read from the build's resolved on-disk state (reactor POMs + ~/.m2 cache, or the
// Gradle lockfile + modules-2 cache), which is JVM-generic, not Java-source-specific — the same
// delegation shape as ResolveDependencyVersions. No resolution logic is duplicated in the Kotlin
// lane; honest-absent + determinism ride the shared resolver.
func ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return javaanalysis.ResolveInventory(ctx, req)
}

// manifestContentVersion is the Kotlin capability manifest's content version; it bumps when
// a later increment adds a supported axis. 1.1.0 adds the Resolvers axis (build-file
// version resolution went live, P1).
const manifestContentVersion = "1.1.0"

// CapabilityManifest returns the Kotlin lane's HONEST capability manifest (K5): every
// Supported axis is one the analyzer genuinely does at Assess tier over bytecode, and every
// desugaring boundary it cannot soundly resolve is a declared DynamicBoundary — never a
// silent gap. All slices are pre-sorted (no map is an iteration source on the encoding
// path). It is a static fact, so it takes no build input.
//
// The axes, and why each is honest:
//   - Resolvers: pom.xml, build.gradle.kts — the build-file formats the lane now reads to
//     resolve a dependency's declared version (P1, via the shared JVM build-file parser,
//     which also reads Groovy build.gradle). Only LITERAL versions resolve; non-literal
//     forms (version catalog, interpolation, the kotlin() helper) fail open UNRESOLVED —
//     the residual gradle_version_resolution boundary below.
//   - Runtimes: jvm — the only runtime the analyzer targets.
//   - GraphSemantics: cha — depreach's class-hierarchy analysis, used unchanged.
//   - Frameworks: none — framework ingress (Spring) is deliberately not detected here.
//   - DynamicBoundaries: the frontiers where a sound static graph must fail open —
//     coroutine builder dispatch, inline-function edge erasure, invokedynamic (SAM/lambda),
//     reflection, and the non-literal Gradle build-file version forms.
//   - Analyzers: the shared classfile reader + depreach engine the lane rides.
func CapabilityManifest() capability.Manifest {
	return capability.Manifest{
		Version:        manifestContentVersion,
		Language:       "kotlin",
		Supported:      true,
		Resolvers:      []string{"build.gradle.kts", "pom.xml"},
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
