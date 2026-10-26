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
// LIVE at Assess tier — the two ops that read the build graph's resolved dependency versions
// and resolve advisory symbols against the dependency artifact. The remaining ops below stay
// honest-absent.

// ResolveDependencyVersions DELEGATES to javaanalysis.ResolveDependencyVersions: the version
// is the one the build graph resolved, which is JVM-generic, not Kotlin-specific.
func ResolveDependencyVersions(ctx context.Context, req plugin.ResolveVersionsRequest, opts ...javaanalysis.Option) (plugin.DependencyVersionResult, error) {
	return javaanalysis.ResolveDependencyVersions(ctx, req, opts...)
}

// ComputeTaint is LIVE at Assess tier — see taint.go. It reports call-graph PATH PRESENCE
// (an ingress→sink path over the Kotlin/JVM bytecode call graph), the honest minimal-taint
// baseline the plugin contract defines; NOT variable-level dataflow. It mirrors the Java
// lane's path-presence semantics on the Kotlin lane's own CallGraph/FindIngresses infra.

// GenerateHarness is contract-present but unimplemented: Kotlin's effect proof rides the
// Prove-tier repro-runtime sandbox, not a plugin-generated harness.
func GenerateHarness(_ context.Context, _ plugin.GenerateHarnessRequest) (plugin.HarnessResult, error) {
	return plugin.HarnessResult{Partiality: plugin.Unsupported()}, nil
}

// BuildManifest DELEGATES to javaanalysis.BuildManifest (lang "kotlin"): the runtime is the JDK
// the build graph was resolved on, the resolver the build tool that resolved it. The "kotlin"
// lang keeps RuntimeSpec.Name honest per lane.
func BuildManifest(ctx context.Context, req plugin.BuildManifestRequest, opts ...javaanalysis.Option) (plugin.BuildManifestResult, error) {
	return javaanalysis.BuildManifest(ctx, req, "kotlin", opts...)
}

// ResolveInventory DELEGATES to javaanalysis.ResolveInventory (C6): the whole-graph dependency
// inventory is the build graph's, the same delegation shape as ResolveDependencyVersions.
func ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest, opts ...javaanalysis.Option) (plugin.DependencyInventory, error) {
	return javaanalysis.ResolveInventory(ctx, req, opts...)
}

// manifestContentVersion is the Kotlin capability manifest's content version; it bumps when
// the manifest's content changes.
const manifestContentVersion = "1.2.0"

// CapabilityManifest returns the Kotlin lane's HONEST capability manifest (K5): every
// Supported axis is one the analyzer genuinely does at Assess tier over bytecode, and every
// desugaring boundary it cannot soundly resolve is a declared DynamicBoundary — never a
// silent gap. All slices are pre-sorted (no map is an iteration source on the encoding
// path). It is a static fact, so it takes no build input.
//
// The axes, and why each is honest:
//   - Resolvers: gradle, maven — the build tools whose resolved graph the lane reads every
//     dependency version and JAR from.
//   - Runtimes: jvm — the only runtime the analyzer targets.
//   - GraphSemantics: cha — depreach's class-hierarchy analysis, used unchanged.
//   - Frameworks: none — framework ingress (Spring) is deliberately not detected here.
//   - DynamicBoundaries: the frontiers where a sound static graph must fail open —
//     coroutine builder dispatch, inline-function edge erasure, invokedynamic (SAM/lambda),
//     and reflection.
//   - Analyzers: the shared classfile reader + depreach engine the lane rides.
func CapabilityManifest() capability.Manifest {
	return capability.Manifest{
		Version:        manifestContentVersion,
		Language:       "kotlin",
		Supported:      true,
		Resolvers:      []string{"gradle", "maven"},
		Runtimes:       []string{"jvm"},
		GraphSemantics: []string{"cha"},
		DynamicBoundaries: []string{
			"coroutine_dispatch",
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
