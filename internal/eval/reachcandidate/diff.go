package reachcandidate

import (
	"fmt"
	"sort"
	"strings"
)

// symbolMatchesAny reports whether the resolved display name corresponds to any expected
// sink identifier, using the same lenient comparison the engine resolvers apply: exact,
// last-dot leaf, and paren-stripped forms on both sides (see matchesAdvisorySymbol,
// goanalysis/packages.go). This lets a curated "language.Parse" match a resolved display of
// "Parse" or "language.Parse" without over-committing to one qualification depth.
func symbolMatchesAny(resolvedDisplay string, expected []string) bool {
	for _, e := range expected {
		if symbolMatches(resolvedDisplay, e) {
			return true
		}
	}
	return false
}

func symbolMatches(a, b string) bool {
	forms := func(s string) map[string]bool {
		s = strings.TrimSpace(s)
		leaf := s
		if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
			leaf = leaf[i+1:]
		}
		leaf = strings.TrimSuffix(leaf, ")")
		norm := strings.NewReplacer("(*", "", "(", "", ")", "").Replace(s)
		return map[string]bool{s: true, leaf: true, norm: true}
	}
	af, bf := forms(a), forms(b)
	for f := range af {
		if f == "" {
			continue
		}
		if bf[f] {
			return true
		}
	}
	return false
}

// Transition is one CVE's before→after change across two runs of the same case set.
type Transition struct {
	VulnID string
	// Recall transitions.
	GainedCandidate bool // no candidate before, candidate after (the recall gain — completeness surfaced a dropped CVE)
	LostCandidate   bool // candidate before, none after (a regression — should be empty on a populate)
	// Precision transitions (only meaningful when a candidate exists on both sides).
	SinkFixed  bool // candidate wrong-sink before, correct-sink after
	SinkBroken bool // candidate correct-sink before, wrong-sink after (over-population regression)
}

// DiffReport is the before/after delta between a partial-corpus run and a complete-corpus
// run — the artifact a downstream feature reads for its "recall ↑ vs pre-populate baseline;
// precision no regression" acceptance line.
type DiffReport struct {
	Before, After Report
	Transitions   []Transition
}

// Diff pairs the two reports by VulnID and computes per-CVE transitions plus the aggregate
// recall/precision deltas. Cases present in only one run are reported as a note, never
// silently dropped.
func Diff(before, after Report) DiffReport {
	byID := func(r Report) map[string]CaseResult {
		m := make(map[string]CaseResult, len(r.Results))
		for _, res := range r.Results {
			m[res.VulnID] = res
		}
		return m
	}
	b, a := byID(before), byID(after)
	seen := map[string]bool{}
	var ids []string
	for id := range b {
		ids = append(ids, id)
		seen[id] = true
	}
	for id := range a {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	dr := DiffReport{Before: before, After: after}
	for _, id := range ids {
		bs, hasB := b[id]
		as, hasA := a[id]
		if !hasB || !hasA {
			continue // reported in String() as a coverage note, not a transition
		}
		t := Transition{VulnID: id}
		if !bs.CandidatePairFormed && as.CandidatePairFormed {
			t.GainedCandidate = true
		}
		if bs.CandidatePairFormed && !as.CandidatePairFormed {
			t.LostCandidate = true
		}
		if bs.CandidatePairFormed && as.CandidatePairFormed {
			if !bs.SinkCorrect && as.SinkCorrect {
				t.SinkFixed = true
			}
			if bs.SinkCorrect && !as.SinkCorrect {
				t.SinkBroken = true
			}
		}
		if t.GainedCandidate || t.LostCandidate || t.SinkFixed || t.SinkBroken {
			dr.Transitions = append(dr.Transitions, t)
		}
	}
	return dr
}

// RecallDelta / PrecisionDelta return the before and after rates for the aggregate move.
func (d DiffReport) RecallDelta() (before, after Rate) { return d.Before.Recall(), d.After.Recall() }
func (d DiffReport) PrecisionDelta() (before, after Rate) {
	return d.Before.Precision(), d.After.Precision()
}

// Regressed reports whether the diff shows a regression that must fail the acceptance gate:
// a lost candidate (recall went backward) or a broken sink (precision went backward), or the
// aggregate precision fraction dropping.
func (d DiffReport) Regressed() bool {
	for _, t := range d.Transitions {
		if t.LostCandidate || t.SinkBroken {
			return true
		}
	}
	beforeP, afterP := d.PrecisionDelta()
	return afterP.Float() < beforeP.Float()
}

func (d DiffReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "reachable-candidate DIFF: %q → %q\n", d.Before.Label, d.After.Label)
	rb, ra := d.RecallDelta()
	pb, pa := d.PrecisionDelta()
	fmt.Fprintf(&b, "  recall    : %s → %s\n", rb, ra)
	fmt.Fprintf(&b, "  precision : %s → %s\n", pb, pa)
	if len(d.Transitions) == 0 {
		fmt.Fprintf(&b, "  (no per-CVE transitions)\n")
	}
	for _, t := range d.Transitions {
		var tags []string
		if t.GainedCandidate {
			tags = append(tags, "+candidate")
		}
		if t.LostCandidate {
			tags = append(tags, "-candidate(REGRESSION)")
		}
		if t.SinkFixed {
			tags = append(tags, "sink-fixed")
		}
		if t.SinkBroken {
			tags = append(tags, "sink-broken(REGRESSION)")
		}
		fmt.Fprintf(&b, "  %-24s  %s\n", t.VulnID, strings.Join(tags, " "))
	}
	if d.Regressed() {
		fmt.Fprintf(&b, "  RESULT: REGRESSED\n")
	} else {
		fmt.Fprintf(&b, "  RESULT: ok\n")
	}
	return b.String()
}
