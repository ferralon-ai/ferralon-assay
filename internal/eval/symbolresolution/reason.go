package symbolresolution

import (
	"encoding/json"
	"fmt"
)

// ResolutionReason is the closed, actionable reason a (record × lane) did NOT resolve to a
// concrete symbol. Every member names what a HUMAN DOES NEXT and WHO OWNS it (field contract
// §1.1). There is no generic/other/unresolved member (C2). The empty value is NOT a member — it
// is the resolved sentinel, permitted only on an outcome whose Resolved==true (§2). Unknown
// values ERROR on unmarshal (§1.2, C2(b)) — this is a CLOSED enum, unlike AttributionStatus
// which fails open. Recognized() mirrors the STRUCTURE of pipeline.attributionStatusRecognized;
// UnmarshalJSON inverts its fail-open to fail-closed.
type ResolutionReason string

const (
	// ReasonAdvisoryNamesNoSymbol: the advisory record carries no vulnerable symbol
	// (len(Symbols)==0). Intel/producer gap — route to PLAN-024/PLAN-220; no resolver change
	// moves it.
	ReasonAdvisoryNamesNoSymbol ResolutionReason = "advisory-names-no-symbol"
	// ReasonArtifactNotIndexed: in-lane, symbol-bearing, but no indexable build context was
	// available — the resolver never ran. Supply a vendored_repro fixture ({go}) or land the
	// lane's PLAN-2x0 indexer (non-Go).
	ReasonArtifactNotIndexed ResolutionReason = "artifact-not-indexed"
	// ReasonSymbolIndexedNoMatch: the resolver built the index and RAN, matched 0 of the named
	// symbols, no gated path caught it. Resolver/normalisation gap — route to the lane's
	// PLAN-2x2. The honest miss.
	ReasonSymbolIndexedNoMatch ResolutionReason = "symbol-indexed-no-match"
	// ReasonAssessTierGap: the static Assess-tier resolver matched 0, but a candidate formed via
	// the toolchain-gated / Prove-tier path. Assess-tier parity gap — close the static resolver
	// gap (lane's PLAN-2x2).
	ReasonAssessTierGap ResolutionReason = "assess-tier-gap"
	// ReasonResolverToolFailure: a build context was supplied and the resolver's index toolchain
	// HARD-FAILED. Surfaced, not retried (inv.4). Toolchain/infra gap — distinct from
	// artifact-not-indexed (nothing supplied) and symbol-indexed-no-match (ran clean).
	ReasonResolverToolFailure ResolutionReason = "resolver-tool-failure"
	// ReasonOutOfLaneEcosystem: the record's ecosystem maps to a DIFFERENT in-program lane than
	// the one under measurement. Routing, not a gap — read its outcome from lane X's ledger.
	// Keeps the record visible in this lane's outcome set (C1).
	ReasonOutOfLaneEcosystem ResolutionReason = "out-of-lane-ecosystem"
	// ReasonEcosystemUnsupported: the record's ecosystem maps to NO lane in the program at all.
	// Program-scope decision (L0). 0 records hit this today; the member exists so the enum is
	// CLOSED against a record that isn't in the 5-ecosystem set.
	ReasonEcosystemUnsupported ResolutionReason = "ecosystem-unsupported"
)

// Recognized reports whether r is one of the seven closed members. It is FALSE for "" (empty is
// not a reason — it is the resolved sentinel handled at the outcome level, §2). Structural mirror
// of pipeline.attributionStatusRecognized.
func (r ResolutionReason) Recognized() bool {
	switch r {
	case ReasonAdvisoryNamesNoSymbol,
		ReasonArtifactNotIndexed,
		ReasonSymbolIndexedNoMatch,
		ReasonAssessTierGap,
		ReasonResolverToolFailure,
		ReasonOutOfLaneEcosystem,
		ReasonEcosystemUnsupported:
		return true
	default:
		return false
	}
}

// UnmarshalJSON fails CLOSED: it returns an error on any value that is not one of the seven
// members, INCLUDING "" (C2(b)). A catch-all that round-trips as an opaque string is exactly the
// laundering C2 forbids. A resolved outcome carries no reason key (omitempty on marshal), so this
// is never invoked for the resolved case.
func (r *ResolutionReason) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("resolution reason: %w", err)
	}
	rr := ResolutionReason(s)
	if !rr.Recognized() {
		return fmt.Errorf("resolution reason: unrecognized value %q (closed enum — %d members, no catch-all)", s, 7)
	}
	*r = rr
	return nil
}
