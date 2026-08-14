package dotnetanalysis

// Lane-local partiality reason codes for the whole-graph dependency resolver
// (ResolveInventory). These name the intra-precedence-chain step-downs the frozen
// plugin.PartialReason* vocabulary has no code for (assets→lock, lock→declared-text, an
// unpinned range, an unevaluated MSBuild condition, a missing RID/platform selection).
//
// They live HERE — not in plugin/plugin.go — by the PLAN-150 barrier decision (Override 1).
// plugin.Partiality.Reasons is a free []string, so a distinguishable named reason needs no
// contract edit. Every value below is CANONICAL and GENERIC across dependency-resolving lanes
// (Maven has no lockfile; npm has ranges; every ecosystem has a resolved-graph file that may be
// absent), so minting them unilaterally in the PLAN-000-owned contract file would be the
// uncoordinated-shared-vocabulary trap. The strings are promotion-ready: a later lift into
// plugin.go is a pure move, value unchanged, zero behavior change. Flagged to L0 (TELL
// nickel-q11) as promotion candidates.
//
// Reused from the frozen vocabulary where they already fit: plugin.PartialReasonNoManifest (no
// project/lock/manifest at all) and plugin.PartialReasonToolFailure (a manifest that exists but
// is structurally unparseable — kept DISTINCT from no_manifest: a broken checkout vs an empty
// one).
const (
	// reasonNoResolverOutput: no project.assets.json (restore output) was read, so
	// restore-derived compile/runtime asset selection and per-RID target selection are absent.
	reasonNoResolverOutput = "no_resolver_output"

	// reasonNoLockfile: no packages.lock.json to pin transitives and parent edges; only the
	// directly-declared set is known.
	reasonNoLockfile = "no_lockfile"

	// reasonUnresolvedVersionRange: a declared dependency carries a range/float (or a
	// CPM-managed version that no props file pins exactly) and no restore output pins it. The
	// version is left empty and NEVER guessed (§3.1 — inferring resolution from missing evidence
	// is the soundness failure this code exists to disclose).
	reasonUnresolvedVersionRange = "unresolved_version_range"

	// reasonUnevaluatedCondition: an MSBuild Condition could not be evaluated to a verdict
	// without MSBuild; the declaration is emitted but marked, never silently applied or dropped.
	reasonUnevaluatedCondition = "unevaluated_condition"

	// reasonNoRuntimeTarget: no RID/platform-specific asset selection is recorded on this node
	// (a portable, RID-agnostic resolution). Per-node, never a guessed platform.
	reasonNoRuntimeTarget = "no_runtime_target"
)
