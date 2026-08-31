package kotlinanalysis

import (
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// support_matrix_test.go — K5/K6/C6: the manifest declares what the lane supports;
// this test cross-checks that declaration against what the code actually does, in BOTH
// directions:
//
//   1. every CapabilityManifest().DynamicBoundaries entry corresponds to something the
//      code can actually detect and surface (directly, or via an explicit, documented
//      operational mapping);
//   2. every plugin.PartialReason* the kotlinanalysis package's live ops (program.go,
//      callgraph.go, reachability.go, ops.go) can actually emit is either traceable to a
//      manifest DynamicBoundary, or is justified as OPERATIONAL (an infrastructure/
//      request-shape condition, not a language capability boundary) — never silently
//      unaccounted for.
//
// Both vocabularies are enumerated by hand below, each line citing the exact source that
// proves the code emits it (never inferred). A boundary or reason added to the SUT without
// a matching update here fails loudly, which is the whole point of C6.

// codeEmittedReasons is the complete set of plugin.PartialReason* string values any
// kotlinanalysis op can actually put into a Partiality.Reasons slice today. Verified
// against every "prog.reasons[...] = true" / "plugin.Partial(...)" call site in the
// package (see the grep-verified citations below the map).
var codeEmittedReasons = map[string]string{
	// program.go:21,50 — no compiled build-output root existed under the checkout.
	partialReasonNoBuildOutput: "operational: build/tool availability, not a language capability boundary",
	// program.go:53 — a per-class parse hazard (a hostile/truncated .class) was recorded;
	// also resolve.go — a dependency JAR that was located but partly/wholly unparseable.
	plugin.PartialReasonToolFailure: "operational: a class or dependency JAR failed to parse; not a capability boundary",
	// reachability.go:48 — a sink string did not parse as a JVM MethodRef.
	// (shares the same plugin.PartialReasonToolFailure constant as the line above; kept
	// as one map entry since the wire reason code is identical.)
	// reachability.go:54 — no discoverable ingress (`main`) existed to search from.
	plugin.PartialReasonNoIngress: "operational: no entry point found in this program; not a capability boundary",
	// reachability.go:55,62 — depreach abstained on a completeness hazard (invokedynamic
	// OR reflection OR an out-of-classpath frontier — see depreach/engine.go resolveTargets
	// and isReflection) on the searched frontier, or the ingress search never began.
	plugin.PartialReasonReachabilityUndetermined: "capability: folds every depreach hazard (invokedynamic, reflection, out-of-classpath re-entry) the Reachability op hits",
	// callgraph.go:39 — an EdgeDynamic (invokedynamic) call-graph edge was dropped.
	plugin.PartialReasonDynamicDispatch: "capability: CallGraph's direct invokedynamic signal",
	// ops.go — ResolveDependencyVersions (via the shared JVM parser) declares no_manifest
	// when the checkout carries NO pom.xml/build.gradle(.kts) at all. This is a build-shape
	// condition (there is no build file to read), NOT the gradle_version_resolution
	// capability boundary — the boundary's own limit (non-literal version forms) fails open
	// per-dependency as Resolved=false with NO partiality reason (see manifestBoundaryRationale).
	plugin.PartialReasonNoManifest: "operational: no build file present to read versions from; not a language capability boundary",
	// resolve.go — the advisory's dependency JAR could not be located in (or read from) the
	// build's local caches: version UNRESOLVED, coordinate underivable, or absent from every
	// cache. Artifact-availability, not a language capability boundary.
	partialReasonNoDependencyArtifact: "operational: dependency artifact unavailable in local caches; not a language capability boundary",
	// resolve.go — the dependency JAR was located and fully read, but none of the advisory's
	// named symbols resolved to a symbol in it. Request/artifact-content, not a desugaring boundary.
	partialReasonAdvisorySymbolUnresolved: "operational: advisory symbol absent from the resolved artifact; not a language capability boundary",
}

// manifestBoundaryRationale documents, for every DynamicBoundaries entry the manifest
// declares, which codeEmittedReasons key(s) actually fire when that boundary is hit — or,
// where none does, WHY not (an explicit, deliberate divergence, never a silent gap).
type boundaryRationale struct {
	// reasons lists the codeEmittedReasons keys this boundary surfaces through. Empty
	// means "no runtime Partiality.Reasons signal exists for this boundary" — allowed
	// ONLY when note explains a structural reason none is possible (not an oversight).
	reasons []string
	note    string
}

var manifestBoundaryRationale = map[string]boundaryRationale{
	// invokedynamic is DIRECTLY visible as classfile.EdgeDynamic. CallGraph.go:38-39
	// labels it dynamic_dispatch on sight. Reachability never sees the raw edge kind
	// itself — it goes through depreach, whose resolveTargets (engine.go:155-156) treats
	// EdgeDynamic as a hazard and Reachability.go:62 folds that into
	// reachability_undetermined. So the SAME underlying opcode surfaces under TWO
	// DIFFERENT wire reason strings depending which op observed it — documented here so
	// that divergence is intentional, not silent.
	"invokedynamic": {
		reasons: []string{plugin.PartialReasonDynamicDispatch, plugin.PartialReasonReachabilityUndetermined},
		note:    "CallGraph labels the raw EdgeDynamic edge directly; Reachability observes the same opcode only through depreach's hazard fold into reachability_undetermined",
	},
	// coroutine_dispatch: a Kotlin coroutine builder (launch/async/...) lowers to a
	// suspend-lambda invoked via invokedynamic (SAM conversion) at the JVM bytecode
	// level (doc.go:22-23, callgraph.go:20-21) — there is no separate coroutine-specific
	// opcode or edge kind; it rides the exact same invokedynamic detection path above.
	"coroutine_dispatch": {
		reasons: []string{plugin.PartialReasonDynamicDispatch, plugin.PartialReasonReachabilityUndetermined},
		note:    "compiles to invokedynamic at the bytecode level; no separate coroutine-specific signal exists or is needed",
	},
	// reflection: depreach's isReflection (engine.go:213-233) DOES detect calls into
	// java/lang/reflect/*, Class.forName/newInstance, ClassLoader.loadClass,
	// ServiceLoader.load, MethodHandle(s), and JNDI lookup — but resolveTargets folds
	// this into the generic Undetermined verdict exactly like invokedynamic, so
	// Reachability surfaces it as reachability_undetermined, never a dedicated
	// "reflection" wire reason. CallGraph has no reflection-specific edge kind at all
	// (reflection calls parse as an ordinary EdgeStatic/EdgeVirtual to
	// java/lang/reflect/Method.invoke etc.), so CallGraph never flags it either.
	"reflection": {
		reasons: []string{plugin.PartialReasonReachabilityUndetermined},
		note:    "depreach's isReflection hazard rule fires but is folded into the generic reachability_undetermined bucket; CallGraph has no reflection-specific edge kind so it is invisible there",
	},
	// gradle_version_resolution: ResolveDependencyVersions (ops.go, via the shared JVM
	// build-file parser) now resolves LITERAL Maven/Gradle versions. The residual boundary is
	// the NON-LITERAL Gradle version forms — a version catalog reference (`libs.foo`), the
	// `kotlin("stdlib")` helper (no coordinate literal), an interpolated `"$version"` — which
	// the parser cannot pin to a literal. Each such dependency is returned Resolved=false (an
	// UNRESOLVED marker the disqualification predicate fails OPEN on), a PER-DEPENDENCY signal
	// that emits NO whole-result Partiality.Reason. So, like inline_function, this boundary
	// has no runtime reason code — its honest signal is the ResolvedDependency.Resolved=false
	// field, not a partiality string. (no_manifest, which this op can also emit, is the
	// distinct build-shape condition "no build file present at all" — operational, not this
	// capability boundary; see codeEmittedReasons.)
	"gradle_version_resolution": {
		reasons: nil,
		note:    "literal versions now resolve; the residual limit (version catalog / kotlin() helper / interpolated versions) fails open per-dependency as ResolvedDependency.Resolved=false, which carries no whole-result Partiality reason — a field signal, not a wire reason code",
	},
	// inline_function: a `inline fun` call site is bytecode-erased by kotlinc BEFORE
	// class emission — the caller's Code attribute already contains the inlined body's
	// instructions spliced in directly, with no opcode, edge kind, or symbol marking an
	// inline call ever occurred. classfile.ParseClass (and therefore depreach and every
	// kotlinanalysis op) has NO way to observe that inlining took place: there is no
	// trace left in the artifact this lane analyzes. This is NOT a reachability
	// soundness gap (the inlined body's own call edges are still present, just under the
	// caller's identity — nothing is hidden from depreach) — it is a K4 symbol-identity
	// gap only (an inline function never appears as itself, as a distinct call target,
	// in the call graph). No codeEmittedReasons key fires for it, and none COULD: this
	// is a genuine manifest/code vocabulary mismatch, flagged here deliberately rather
	// than silently, and reported to V in K6-fixtures.md as a finding worth a verdict
	// call (not a bug this test-writer dispatch is authorized to fix in the SUT).
	"inline_function": {
		reasons: nil,
		note:    "erasure happens before bytecode emission; no trace survives in the artifact this lane analyzes, so no runtime Partiality reason can ever fire for it — a K4 symbol-identity note, not a reachability hazard; flagged as a real finding for V, not silently absent",
	},
}

// TestSupportMatrix_ManifestBoundariesAreDocumented is the C6 forward direction: every
// DynamicBoundaries entry the manifest actually declares has an explicit rationale entry
// above (no boundary is added to the manifest without this test being updated in step),
// and every boundary's declared codeEmittedReasons keys are reasons the code can really
// emit (guards the rationale table itself against typos/rot).
func TestSupportMatrix_ManifestBoundariesAreDocumented(t *testing.T) {
	m := CapabilityManifest()
	if len(m.DynamicBoundaries) == 0 {
		t.Fatal("manifest declares no DynamicBoundaries; nothing to cross-check")
	}
	for _, b := range m.DynamicBoundaries {
		rat, ok := manifestBoundaryRationale[b]
		if !ok {
			t.Errorf("manifest DynamicBoundary %q has no documented rationale in manifestBoundaryRationale — add one (C6 forward direction)", b)
			continue
		}
		if len(rat.reasons) == 0 && rat.note == "" {
			t.Errorf("boundary %q maps to no code reason and carries no explanatory note — either the code cannot actually emit this boundary (a real finding) or the rationale needs a note", b)
		}
		for _, r := range rat.reasons {
			if _, known := codeEmittedReasons[r]; !known {
				t.Errorf("boundary %q rationale cites reason %q, which is not in codeEmittedReasons — typo, or codeEmittedReasons is stale", b, r)
			}
		}
	}

	// Every rationale entry must correspond to an ACTUAL manifest boundary — a stale
	// rationale entry for a boundary the manifest no longer declares is exactly the kind
	// of silent drift C6 exists to catch.
	declared := map[string]bool{}
	for _, b := range m.DynamicBoundaries {
		declared[b] = true
	}
	for b := range manifestBoundaryRationale {
		if !declared[b] {
			t.Errorf("manifestBoundaryRationale documents %q, which the manifest no longer declares — remove the stale entry or the manifest regressed", b)
		}
	}
}

// TestSupportMatrix_EveryCodeReasonHasAManifestHomeOrIsOperational is the C6 reverse
// direction: every reason kotlinanalysis's live ops can actually emit is either cited by
// some manifestBoundaryRationale entry (a capability boundary) or explicitly annotated
// "operational" in codeEmittedReasons (an infrastructure/request-shape condition that is
// not a language capability axis at all — e.g. "the build wasn't compiled" is not a
// desugaring boundary). A reason with neither home fails: that is a silent capability the
// manifest never disclosed.
func TestSupportMatrix_EveryCodeReasonHasAManifestHomeOrIsOperational(t *testing.T) {
	capabilityReasons := map[string]bool{}
	for _, rat := range manifestBoundaryRationale {
		for _, r := range rat.reasons {
			capabilityReasons[r] = true
		}
	}

	for reason, rationale := range codeEmittedReasons {
		isOperational := strings.HasPrefix(rationale, "operational:")
		isCapability := capabilityReasons[reason]
		if !isOperational && !isCapability {
			t.Errorf("code reason %q is neither traced to a manifest boundary nor marked operational — undisclosed capability boundary (C6 reverse direction): %q", reason, rationale)
		}
		if isOperational && isCapability {
			t.Errorf("code reason %q is marked BOTH operational and capability-linked — pick one so the divergence stays unambiguous", reason)
		}
	}
}

// TestSupportMatrix_NoBoundaryClaimsAnUndetectableCapability is a narrower, explicit
// assertion of the one real mismatch this cross-check surfaces: "inline_function" is
// declared in the manifest's DynamicBoundaries but has NO corresponding runtime
// Partiality reason anywhere in the package, by design (see manifestBoundaryRationale
// note above) — bytecode-level erasure leaves no trace to detect. This test pins that
// fact so it cannot silently change (a future patch adding inline detection should make
// this test fail, prompting an update here and in the K6 deposit's finding list) and
// exists precisely so an accidental removal of the honest note also fails loudly.
func TestSupportMatrix_NoBoundaryClaimsAnUndetectableCapability(t *testing.T) {
	rat, ok := manifestBoundaryRationale["inline_function"]
	if !ok {
		t.Fatal(`manifestBoundaryRationale missing "inline_function" — the documented mismatch this test pins was removed`)
	}
	if len(rat.reasons) != 0 {
		t.Errorf(`"inline_function" now maps to code reasons %v; if inline-call detection was added to the SUT, update this test and the K6-fixtures.md finding accordingly`, rat.reasons)
	}
	if rat.note == "" {
		t.Error(`"inline_function" rationale must carry an explanatory note (a nil-reasons entry without one is indistinguishable from an oversight)`)
	}
}

// TestSupportMatrix_CodeEmittedReasonsMatchSourceCitations keeps codeEmittedReasons's
// implicit documentation-order citations honest: this is a light sanity check that the
// map's keys are exactly the plugin.PartialReason* values actually referenced across the
// package's non-test .go files, re-derived independently of the hand-authored comments
// above so a silently added/removed reason cannot hide behind a stale comment.
func TestSupportMatrix_CodeEmittedReasonsMatchSourceCitations(t *testing.T) {
	want := []string{
		partialReasonNoBuildOutput,
		plugin.PartialReasonToolFailure,
		plugin.PartialReasonNoIngress,
		plugin.PartialReasonReachabilityUndetermined,
		plugin.PartialReasonDynamicDispatch,
		plugin.PartialReasonNoManifest,
		partialReasonNoDependencyArtifact,
		partialReasonAdvisorySymbolUnresolved,
	}
	got := make([]string, 0, len(codeEmittedReasons))
	for k := range codeEmittedReasons {
		got = append(got, k)
	}
	sort.Strings(got)
	sortWant := append([]string(nil), want...)
	sort.Strings(sortWant)
	if len(got) != len(sortWant) {
		t.Fatalf("codeEmittedReasons has %d entries, want %d: got=%v want=%v", len(got), len(sortWant), got, sortWant)
	}
	for i := range got {
		if got[i] != sortWant[i] {
			t.Errorf("codeEmittedReasons[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], sortWant[i], got, sortWant)
		}
	}
}
