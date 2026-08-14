package symbolresolution

import (
	"fmt"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/reachcandidate"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// DenominatorReport is one candidate "supported subset" definition's rate, side by side with the
// others (C3 — compute all, grade none). The numerator is uniform across denominators: records in
// the denominator whose outcome has Resolved==true. Each denominator differs only in membership.
// Rate renders "n/a (0/0)" at Denom 0 (reachcandidate.Rate) — never a bare float (C3).
type DenominatorReport struct {
	Name     string              `json:"name"`     // "ecosystem-in-lane" | "symbol-bearing-in-lane" | "reviewed-attributed-in-lane" | "buildable-in-lane"
	Lane     string              `json:"lane"`     // e.g. "go"
	Rate     reachcandidate.Rate `json:"rate"`     // Num = Resolved==true within Included; Denom = Included
	Total    int                 `json:"total"`    // == len(corpus records) == 38
	Included int                 `json:"included"` // == Rate.Denom
	Excluded []ExclusionBucket   `json:"excluded"`
}

// ExclusionBucket names WHY a set of records is outside a denominator, so a dropped record is
// nameable, not just a count delta (C4). Reason draws from the §1 vocabulary for D1/D2/D4; for D3
// (an ATTRIBUTION-state exclusion) it carries the reportState string (unreviewed /
// reviewed-none-found / ambiguous / disputed) in the same field, per field contract §4.1's
// explicit sanction — see the note in buildDenominators. Because a D3 bucket may hold a non-§1
// value, a DenominatorReport is produced (marshaled) but is not round-tripped through
// ResolutionReason.UnmarshalJSON in this package.
type ExclusionBucket struct {
	Reason  ResolutionReason `json:"reason"`
	Count   int              `json:"count"`
	Records []string         `json:"records"` // vuln_ids, sorted
}

// CheckAccounting is the C4 identity: Included + Σ Excluded[i].Count == Total, per denominator.
// A record dropped from a denominator without being recorded in an ExclusionBucket makes the sum
// fall short and this return non-nil — the mutation control that must bite.
func (d DenominatorReport) CheckAccounting() error {
	excluded := 0
	for _, e := range d.Excluded {
		excluded += e.Count
	}
	if d.Included+excluded != d.Total {
		return fmt.Errorf("denominator %q (lane %s): included(%d) + excluded(%d) = %d, want total %d",
			d.Name, d.Lane, d.Included, excluded, d.Included+excluded, d.Total)
	}
	return nil
}

// recordCtx bundles a record's committed-field facts plus its classified outcome, so the four
// denominators read real fields (not the outcome reason) to decide membership — keeping each
// membership predicate independent of the classifier's step-5 result.
type recordCtx struct {
	id      string
	facts   pipeline.AdvisoryFacts
	eco     string // pipeline.EcosystemToken
	bound   bool   // has a bound vendored_repro fixture
	state   string // pipeline.ReportState
	outcome ResolutionOutcome
}

// buildRecordCtxs assembles the per-record context for one lane, in vuln_id order, aligning each
// record with its classified outcome.
func buildRecordCtxs(records map[string]pipeline.AdvisoryFacts, store pipeline.AttributionStore, bound map[string]corpus.Fixture, outcomes []ResolutionOutcome) []recordCtx {
	byID := make(map[string]ResolutionOutcome, len(outcomes))
	for _, o := range outcomes {
		byID[o.RecordID] = o
	}
	ids := sortedRecordIDs(records)
	ctxs := make([]recordCtx, 0, len(ids))
	for _, id := range ids {
		r := records[id]
		var ap *pipeline.AdvisoryAttribution
		if a, ok := store[id]; ok {
			av := a
			ap = &av
		}
		_, isBound := bound[id]
		ctxs = append(ctxs, recordCtx{
			id:      id,
			facts:   r,
			eco:     pipeline.EcosystemToken(r),
			bound:   isBound,
			state:   pipeline.ReportState(r, ap),
			outcome: byID[id],
		})
	}
	return ctxs
}

// buildDenominators computes D1–D4 (field contract §4 table) for one lane, side by side. Each
// membership predicate reads committed fields; each excluded record maps to exactly one named
// reason, so the four predicate/reason pairs PARTITION the corpus and CheckAccounting holds by
// construction.
//
// D3 exclusions are attribution-STATE exclusions, not resolution reasons: reviewed-none-found is
// a reviewer's "no symbol here" (not a resolver miss — including it would launder a human
// judgement into the rate, §3.1). Per §4.1 the D3 ExclusionBucket carries the reportState string
// in its Reason field; the C4 identity holds identically.
func buildDenominators(lane string, total int, ctxs []recordCtx) []DenominatorReport {
	laneEco := laneEcosystem(lane)
	inLane := func(rc recordCtx) bool { return rc.eco == laneEco }
	bearing := func(rc recordCtx) bool { return pipeline.SymbolBearing(rc.facts) }

	// ecoExclusion names why an out-of-lane record is excluded — the shared D1..D4 tail.
	ecoExclusion := func(rc recordCtx) string {
		if ecosystemLane[rc.eco] == "" {
			return string(ReasonEcosystemUnsupported)
		}
		return string(ReasonOutOfLaneEcosystem)
	}

	return []DenominatorReport{
		// D1 — ecosystem-in-lane
		buildDenominator("ecosystem-in-lane", lane, total, ctxs,
			inLane,
			func(rc recordCtx) (string, bool) { return ecoExclusion(rc), true }),

		// D2 — symbol-bearing-in-lane
		buildDenominator("symbol-bearing-in-lane", lane, total, ctxs,
			func(rc recordCtx) bool { return inLane(rc) && bearing(rc) },
			func(rc recordCtx) (string, bool) {
				if !inLane(rc) {
					return ecoExclusion(rc), true
				}
				return string(ReasonAdvisoryNamesNoSymbol), true
			}),

		// D3 — reviewed-attributed-in-lane (attribution-state exclusions, §4.1)
		buildDenominator("reviewed-attributed-in-lane", lane, total, ctxs,
			func(rc recordCtx) bool {
				return inLane(rc) && bearing(rc) && rc.state == pipeline.StateAttributedReviewed
			},
			func(rc recordCtx) (string, bool) {
				if !inLane(rc) {
					return ecoExclusion(rc), true
				}
				if !bearing(rc) {
					return string(ReasonAdvisoryNamesNoSymbol), true
				}
				return rc.state, true // reportState string: unreviewed/reviewed-none-found/ambiguous/disputed
			}),

		// D4 — buildable-in-lane (a bound vendored_repro fixture exists)
		buildDenominator("buildable-in-lane", lane, total, ctxs,
			func(rc recordCtx) bool { return inLane(rc) && bearing(rc) && rc.bound },
			func(rc recordCtx) (string, bool) {
				if !inLane(rc) {
					return ecoExclusion(rc), true
				}
				if !bearing(rc) {
					return string(ReasonAdvisoryNamesNoSymbol), true
				}
				return string(ReasonArtifactNotIndexed), true
			}),
	}
}

// buildDenominator assembles one DenominatorReport. include decides membership (numerator counts
// the resolved among them); reasonFor names the exclusion bucket for every non-included record.
// A reasonFor that returns ("", false) for some record leaves it in NEITHER included nor excluded
// — a hole CheckAccounting catches (the C4 mutation surface).
func buildDenominator(name, lane string, total int, ctxs []recordCtx,
	include func(recordCtx) bool, reasonFor func(recordCtx) (string, bool)) DenominatorReport {
	rep := DenominatorReport{Name: name, Lane: lane, Total: total}
	buckets := map[string][]string{}
	for _, rc := range ctxs {
		if include(rc) {
			rep.Included++
			if rc.outcome.Resolved {
				rep.Rate.Num++
			}
			continue
		}
		if reason, ok := reasonFor(rc); ok {
			buckets[reason] = append(buckets[reason], rc.id)
		}
	}
	rep.Rate.Denom = rep.Included
	rep.Excluded = bucketsToExclusions(buckets)
	return rep
}

// bucketsToExclusions renders the reason→records map as sorted ExclusionBuckets (reasons sorted,
// records sorted within each) for deterministic output.
func bucketsToExclusions(buckets map[string][]string) []ExclusionBucket {
	reasons := make([]string, 0, len(buckets))
	for r := range buckets {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	out := make([]ExclusionBucket, 0, len(reasons))
	for _, r := range reasons {
		recs := buckets[r]
		sort.Strings(recs)
		out = append(out, ExclusionBucket{Reason: ResolutionReason(r), Count: len(recs), Records: recs})
	}
	return out
}
