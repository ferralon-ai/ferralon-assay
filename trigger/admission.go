package trigger

import (
	"sort"

	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// Band is the advisory prioritization band Intel emits as a scheduling hint. It is a
// SCHEDULER-ONLY signal: it decides whether/when a case is admitted for processing and
// NOTHING else. It is deliberately declared here in the trigger (scheduler) package and
// NOT on assessment.VulnRef / assessment.Request / assessment.Assessment / the pipeline
// AdvisoryFacts / the normalized_advisory artifact — so that no pipeline stage and no
// verdict path can even reference it (inv.5: severity/EPSS/KEV/band NEVER conclude a
// verdict). The structural quarantine is enforced by TestBandQuarantine_*.
//
// The band enum is Intel's emit-side contract (still being finalized; Tranche-B Q7). The
// scheduler treats any unrecognized or empty band as BandUnknown and FAILS OPEN — an
// absent band never drops a case (a missing hint is never "not affected"/"not relevant").
type Band string

const (
	// BandUnknown is the zero value: band absent or unrecognized. Fail-open → admit now.
	BandUnknown Band = ""
	// BandImmediate asks the scheduler to admit ahead of standard work.
	BandImmediate Band = "immediate"
	// BandStandard is normal admission.
	BandStandard Band = "standard"
	// BandDeferred asks the scheduler to hold the case for a later pass (not this one).
	BandDeferred Band = "deferred"
	// BandExcluded is a triage decision that the case should not be scheduled this pass.
	BandExcluded Band = "excluded"
)

// Admission is the scheduler's per-case decision. It gates SCHEDULING only; it never
// becomes a finding or a verdict. A non-admitted case simply is not run this pass — it
// receives NO verdict (that is the inv.5-preserving distinction from a not-affected
// finding: deferring is silence, not a conclusion).
type Admission string

const (
	// AdmitNow means the case is admitted for processing this pass.
	AdmitNow Admission = "assess-now"
	// AdmitDefer means the case is held back for a later pass; it is not run now and
	// receives no verdict this pass.
	AdmitDefer Admission = "defer"
	// AdmitSkip means the case is not scheduled this pass by a triage decision; it
	// receives no verdict this pass.
	AdmitSkip Admission = "skip"
)

// ScheduledAdvisory is the scheduler's INPUT record for one case: the advisory to assess
// plus its (scheduler-only) band. It exists solely so the admission gate can read band
// without band ever riding on assessment.VulnRef. The gate consumes it and emits a plain
// assessment.VulnRef (band dropped) for the pipeline — band never crosses the S1 seam.
type ScheduledAdvisory struct {
	Vuln assessment.VulnRef
	Band Band
}

// AdmissionResult is the observable outcome of an admission pass: the advisories admitted
// for processing (band already stripped — these are plain VulnRefs) plus the ids the gate
// held back, split by decision. Deferred and Skipped ids are NOT assessed this pass and
// therefore carry no finding.
type AdmissionResult struct {
	Admitted []assessment.VulnRef
	Deferred []string
	Skipped  []string
}

// admit is the admission gate: it maps a band to a scheduling decision. It is the whole
// of band's authority. FAIL-OPEN is structural here — BandUnknown and any value not in
// the recognized set both admit. Only an explicit deprioritization band (deferred /
// excluded) holds a case back.
func admit(band Band) Admission {
	switch band {
	case BandDeferred:
		return AdmitDefer
	case BandExcluded:
		return AdmitSkip
	case BandImmediate, BandStandard, BandUnknown:
		return AdmitNow
	default:
		return AdmitNow // fail open: an unrecognized band never drops a case
	}
}

// admitAdvisories runs the admission gate over the scheduler's input records and returns
// the admitted VulnRefs (band stripped) alongside the held-back ids. This is the seam
// that enforces the quarantine at runtime: band is read HERE and only here, and the
// returned []assessment.VulnRef — the only thing that reaches assess()/S1 — has no band.
//
// Admission is stable-ordered by band rank (immediate before standard before the
// fail-open default) so a higher band is assessed earlier; ordering is a scheduling
// effect only and never changes any verdict. With no bands supplied every case is
// BandUnknown and the order is unchanged (byte-identical to the pre-gate behavior).
func admitAdvisories(scheduled []ScheduledAdvisory) AdmissionResult {
	type ranked struct {
		vuln assessment.VulnRef
		rank int
		idx  int
	}
	var admit0 []ranked
	var res AdmissionResult
	for i, s := range scheduled {
		switch admit(s.Band) {
		case AdmitNow:
			admit0 = append(admit0, ranked{vuln: s.Vuln, rank: bandRank(s.Band), idx: i})
		case AdmitDefer:
			res.Deferred = append(res.Deferred, s.Vuln.ID)
		case AdmitSkip:
			res.Skipped = append(res.Skipped, s.Vuln.ID)
		}
	}
	sort.SliceStable(admit0, func(a, b int) bool {
		if admit0[a].rank != admit0[b].rank {
			return admit0[a].rank < admit0[b].rank
		}
		return admit0[a].idx < admit0[b].idx
	})
	res.Admitted = make([]assessment.VulnRef, 0, len(admit0))
	for _, r := range admit0 {
		res.Admitted = append(res.Admitted, r.vuln)
	}
	return res
}

// bandRank orders admitted cases within a pass. Lower runs earlier. The fail-open default
// (unknown/unrecognized) sorts with standard so an absent band is treated as normal work.
func bandRank(band Band) int {
	switch band {
	case BandImmediate:
		return 0
	default:
		return 1
	}
}

// scheduleFor pairs each advisory with its band from an optional advisory-id → band map
// (the scheduler's band source; nil map ⇒ every case BandUnknown ⇒ all admitted). It is
// the adapter from the run-mode request shape ([]VulnRef + a band map) to the gate input.
func scheduleFor(advisories []assessment.VulnRef, bands map[string]Band) []ScheduledAdvisory {
	out := make([]ScheduledAdvisory, 0, len(advisories))
	for _, v := range advisories {
		out = append(out, ScheduledAdvisory{Vuln: v, Band: bands[v.ID]})
	}
	return out
}
