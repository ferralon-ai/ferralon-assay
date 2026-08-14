package pythonanalysis

// Lane-local placeholder partiality reason codes.
//
// PLAN-170's three §3.1 conditions (an unbound environment marker, an unresolvable
// VCS/URL/editable source, and an unexpressed parent relationship) map to SHARED-PLATFORM
// reason codes that anvil must add to the shared plugin.go contract (onyx-q6 L0 ASK); this
// lane may not edit plugin.go. Until those land, the resolver emits these lane-local
// string placeholders so the eventual swap is a one-line change per code.
//
// TODO(PLAN-170 E5): replace each with the canonical plugin.PartialReason… constant once
// anvil lands the shared codes (onyx-q6). The string values here intentionally match the
// architect-proposed spellings (architect-ruling.md item 2) so the swap is mechanical.
const (
	// reasonEnvUnresolvedPlaceholder marks a requirement whose environment marker
	// references a variable the declared descriptor does not bind (C1 row 3). The specific
	// unbound variable is appended as a ":<var>" detail (architect-ruling item 2; the
	// detail-shape itself is L0 sub-question onyx-q6 item 4).
	reasonEnvUnresolvedPlaceholder = "env_condition_unresolved"

	// reasonSourceUnpinnedPlaceholder marks a requirement whose source is a direct URL, a
	// VCS reference, an editable install, or a file include rather than a registry pin, so
	// its exact identity is undeclared without a fetch (C3 / §3.1). Used by E3.
	reasonSourceUnpinnedPlaceholder = "source_unpinned"

	// reasonRelationshipUnexpressedPlaceholder marks a node whose source format expresses no
	// parent relationship — a flat requirements.txt has no dependency edges, so its nodes are
	// neither direct nor transitive by any evidence in the file. Per C4 such a node names the
	// unexpressed relationship in its partiality rather than being defaulted to "direct". Used
	// by E4 (pyReq.relationshipReason); the pdm.lock/uv.lock parsers, which DO carry edges,
	// classify their nodes and never emit this.
	reasonRelationshipUnexpressedPlaceholder = "relationship_unexpressed"
)
