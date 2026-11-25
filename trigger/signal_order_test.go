package trigger

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/internal/intel/inteltest"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// orderSignals: GO-T-3 is KEV-listed with a low EPSS, GO-T-2 has a high EPSS, GO-T-1 a low one,
// CVE-AMB-A/B are two CVEs of one advisory whose records disagree, and GO-T-5/GO-T-6 tie on EPSS.
func orderSignals(t *testing.T) *intel.Signals {
	t.Helper()
	const stamp = `"catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"`
	s, err := intel.Parse(inteltest.Sealed(t, `{"signals_version": "1.0.0", "record_count": 8,
	  "signals_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
	  "records": [
	    {"identifier": "GO-T-1", "epss": {"score": 0.01, "as_of": "2026-10-19"}},
	    {"identifier": "GO-T-2", "epss": {"score": 0.80, "as_of": "2026-10-19"}},
	    {"identifier": "GO-T-3", "epss": {"score": 0.02, "as_of": "2026-10-19"}, "kev": {"listed": true, "date_added": "2025-07-28", `+stamp+`}},
	    {"identifier": "GO-T-5", "epss": {"score": 0.30, "as_of": "2026-10-19"}},
	    {"identifier": "GO-T-6", "epss": {"score": 0.30, "as_of": "2026-10-19"}},
	    {"identifier": "GO-T-7", "kev": {"listed": false, `+stamp+`}},
	    {"identifier": "CVE-2026-0001", "epss": {"score": 0.90, "as_of": "2026-10-19"}, "kev": {"listed": true, `+stamp+`}},
	    {"identifier": "CVE-2026-0002", "epss": {"score": 0.10, "as_of": "2026-10-19"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// aliasSource lists aliases per id; an id it does not hold resolves to nothing.
type aliasSource map[string][]string

func (a aliasSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	al, ok := a[id]
	return pipeline.AdvisoryFacts{Aliases: al}, ok
}

func refs(ids ...string) []assessment.VulnRef {
	out := make([]assessment.VulnRef, len(ids))
	for i, id := range ids {
		out[i] = assessment.VulnRef{ID: id, Source: "corpus"}
	}
	return out
}

func idsOf(vs []assessment.VulnRef) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.ID
	}
	return out
}

// TestAdmissionOrdersBySignals: KEV-listed first, then EPSS descending, then advisories with no
// signal in input order; ties keep input position; no signals leaves the input order; an advisory
// whose alias join is refused is unsignaled; the band stays the primary key.
func TestAdmissionOrdersBySignals(t *testing.T) {
	src := aliasSource{"GHSA-AMB": {"CVE-2026-0001", "CVE-2026-0002"}, "GHSA-OK": {"CVE-2026-0002"}}
	cases := []struct {
		name  string
		in    []string
		bands map[string]Band
		noSig bool
		want  []string
	}{
		{
			name: "KEV before high EPSS before low EPSS before unsignaled",
			in:   []string{"HOUSE-1", "GO-T-1", "GO-T-2", "GO-T-3", "HOUSE-2"},
			want: []string{"GO-T-3", "GO-T-2", "GO-T-1", "HOUSE-1", "HOUSE-2"},
		},
		{
			name: "ties keep input position",
			in:   []string{"HOUSE-2", "GO-T-6", "HOUSE-1", "GO-T-5", "GO-T-7"},
			want: []string{"GO-T-6", "GO-T-5", "HOUSE-2", "HOUSE-1", "GO-T-7"},
		},
		{
			name:  "no signals loaded leaves the input order",
			in:    []string{"HOUSE-1", "GO-T-1", "GO-T-2", "GO-T-3"},
			noSig: true,
			want:  []string{"HOUSE-1", "GO-T-1", "GO-T-2", "GO-T-3"},
		},
		{
			name: "an alias-ambiguous advisory is unsignaled",
			in:   []string{"GHSA-AMB", "GO-T-1"},
			want: []string{"GO-T-1", "GHSA-AMB"},
		},
		{
			name: "an unambiguous alias join signals the advisory",
			in:   []string{"HOUSE-1", "GHSA-OK", "GO-T-1"},
			want: []string{"GHSA-OK", "GO-T-1", "HOUSE-1"},
		},
		{
			name:  "the band stays the primary key",
			in:    []string{"GO-T-3", "HOUSE-1"},
			bands: map[string]Band{"HOUSE-1": BandImmediate},
			want:  []string{"HOUSE-1", "GO-T-3"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sig *intel.Signals
			if !tc.noSig {
				sig = orderSignals(t)
			}
			sched := withSignalPriority(scheduleFor(refs(tc.in...), tc.bands), sig, src)
			if got := idsOf(admitAdvisories(sched).Admitted); !slices.Equal(got, tc.want) {
				t.Errorf("order = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBaseline_StopLeavesLowerPriorityCutShort: the input order is GO-T-1, GO-T-2, GO-T-3 but the
// signals rank GO-T-3 first and GO-T-2 second, so a stop inside the second assessment cuts exactly
// the lowest-priority advisory and the one it stopped in, and keeps the top one's verdict.
func TestBaseline_StopLeavesLowerPriorityCutShort(t *testing.T) {
	opts, analysis := stoppingOptions(t, "GO-T-2", stopAndWait)
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    cutShortCorpus,
		AssessOptions: opts,
		Analysis:      analysis,
		Signals:       orderSignals(t),
	})
	if err != nil {
		t.Fatalf("buildBaselineReport: %v", err)
	}
	checkCutShort(t, rep, map[string]report.Verdict{
		"GO-T-3": report.VerdictNotExploitable,
		"GO-T-2": report.VerdictUndetermined,
		"GO-T-1": report.VerdictUndetermined,
	}, "2 of 3 advisories were not assessed: test stop")
}

// TestBaseline_ReportIgnoresSignalOrder: for a scan that completes, the Report is the same whether
// or not the signals reordered the loop, apart from the Priority the signals rank rows with (and so
// the row order Build gives it) and the digest that names the file.
func TestBaseline_ReportIgnoresSignalOrder(t *testing.T) {
	run := func(sig *intel.Signals) *report.Report {
		opts, analysis := stoppingOptions(t, "never", stopAndWait)
		rep, err := buildBaselineReport(context.Background(), BaselineRequest{
			Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			Advisories:    cutShortCorpus,
			AssessOptions: opts,
			Analysis:      analysis,
			Signals:       sig,
		})
		if err != nil {
			t.Fatalf("buildBaselineReport: %v", err)
		}
		return rep
	}
	plain, ordered := run(nil), run(orderSignals(t))
	if !slices.ContainsFunc(ordered.Advisories, func(f report.AdvisoryFinding) bool { return f.Priority != nil }) {
		t.Fatal("no row carries a Priority; the signals did not apply")
	}
	// Build ranks rows by Priority, so the signals alone reorder the rows; compare them by id.
	for i := range ordered.Advisories {
		ordered.Advisories[i].Priority = nil
	}
	for _, r := range []*report.Report{plain, ordered} {
		slices.SortFunc(r.Advisories, func(a, b report.AdvisoryFinding) int { return strings.Compare(a.Advisory.ID, b.Advisory.ID) })
		r.Provenance.Timestamp = time.Time{}
	}
	ordered.Provenance.Intel = plain.Provenance.Intel
	a, errA := json.Marshal(plain)
	b, errB := json.Marshal(ordered)
	if errA != nil || errB != nil {
		t.Fatalf("marshal: %v, %v", errA, errB)
	}
	if string(a) != string(b) {
		t.Errorf("Report differs with signal ordering:\nplain   %s\nordered %s", a, b)
	}
}

// TestCVEWatch_StopLeavesLowerPriorityCutShort: the earnest pass takes the new advisories in OSV's
// order, GO-T-1 then GO-T-2 then GO-T-3, but the signals rank GO-T-3 then GO-T-2 then GO-T-1, so a
// stop inside the second assessment keeps GO-T-3's verdict and cuts the other two.
func TestCVEWatch_StopLeavesLowerPriorityCutShort(t *testing.T) {
	opts, analysis := stoppingOptions(t, "GO-T-2", stopAndWait)
	osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
		{ID: "GO-T-1", Package: wiringPkg},
		{ID: "GO-T-2", Package: wiringPkg},
		{ID: "GO-T-3", Package: wiringPkg},
	}}}
	res, err := RunCVEWatch(context.Background(), emptyBaseline(), osv, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: opts,
		Analysis:      analysis,
		Signals:       orderSignals(t),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Report == nil {
		t.Fatal("CVE-watch ran no earnest pass")
	}
	checkCutShort(t, res.Report, map[string]report.Verdict{
		"GO-T-3": report.VerdictNotExploitable,
		"GO-T-2": report.VerdictUndetermined,
		"GO-T-1": report.VerdictUndetermined,
	}, "2 of 3 advisories were not assessed: test stop")
}

// The PR fast path assesses its unrowed advisories in signal order too, so a stop cuts the least
// likely exploited.
func TestInheritFastPath_StopLeavesLowerPriorityCutShort(t *testing.T) {
	store := storedCorpus(nil, nil)
	opts, analysis := stoppingOptions(t, "GO-T-2", stopAndWait)
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:        report.SBOM{Packages: slices.Clone(store.state.Report.SBOM.Packages)},
		Advisories:    cutShortCorpus,
		AssessOptions: opts,
		Analysis:      analysis,
		Signals:       orderSignals(t),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if !res.Inherited {
		t.Fatalf("took the slow path (changed = %q)", res.ChangedPackages)
	}
	checkCutShort(t, res.Report, map[string]report.Verdict{
		"GO-T-3": report.VerdictNotExploitable,
		"GO-T-2": report.VerdictUndetermined,
		"GO-T-1": report.VerdictUndetermined,
	}, "2 of 3 advisories were not assessed: test stop")
}

// PR re-analysis re-runs the work set in signal order, so a stop cuts the least likely exploited.
func TestPRReanalysis_StopLeavesLowerPriorityCutShort(t *testing.T) {
	opts, analysis := stoppingOptions(t, "GO-T-2", stopAndWait)
	store, _ := groundedBaseline()
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:        report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}},
		Advisories:    append(slices.Clone(cutShortCorpus), wiringAdvisory),
		AssessOptions: opts,
		Analysis:      analysis,
		Signals:       orderSignals(t),
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if res.Inherited {
		t.Fatal("took the fast path; the head changed a package")
	}
	rows := rowsByID(res.Report)
	if r := rows["GO-T-3"]; len(r) != 1 || r[0].UndeterminedReason == report.ReasonScanCutShort {
		t.Errorf("GO-T-3, the likeliest exploited, rows = %+v, want one assessed row", r)
	}
	for _, id := range []string{"GO-T-2", "GO-T-1", wiringAdvisory.ID} {
		if r := rows[id]; len(r) != 1 || r[0].UndeterminedReason != report.ReasonScanCutShort {
			t.Errorf("%s rows = %+v, want one scan_cut_short row", id, r)
		}
	}
}
