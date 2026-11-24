package trigger

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/intel"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// carryRun runs a baseline over corpus against store and returns the order its plugin assessed
// the advisories in, with the committed Report.
func carryRun(t *testing.T, store *memStore, corpus []assessment.VulnRef, bands map[string]Band, sig *intel.Signals, stopAt string) ([]string, *report.Report) {
	t.Helper()
	opts, analysis, calls := recordingStoppingOptions(t, stopAt, stopAndWait)
	rep, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    corpus,
		Bands:         bands,
		Signals:       sig,
		AssessOptions: opts,
		Analysis:      analysis,
	})
	if err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return calls.order(), rep
}

// cutIDs is the IDs of rep's scan_cut_short rows, sorted.
func cutIDs(rep *report.Report) []string {
	var ids []string
	for _, f := range rep.Advisories {
		if f.UndeterminedReason == report.ReasonScanCutShort {
			ids = append(ids, f.Advisory.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

// TestRunBaseline_CarriesCutShortFirst: a baseline stopped after k of n leaves the rest as
// scan_cut_short rows, and the next baseline over the same work set assesses those first.
func TestRunBaseline_CarriesCutShortFirst(t *testing.T) {
	store := &memStore{}
	first, rep1 := carryRun(t, store, cutShortCorpus, nil, nil, "GO-T-2")
	if want := []string{"GO-T-1", "GO-T-2"}; !slices.Equal(first, want) {
		t.Fatalf("run 1 assessed %v, want %v", first, want)
	}
	if got := cutIDs(rep1); !slices.Equal(got, []string{"GO-T-2", "GO-T-3"}) {
		t.Fatalf("run 1 cut rows = %v", got)
	}

	second, rep2 := carryRun(t, store, cutShortCorpus, nil, nil, "never")
	if want := []string{"GO-T-2", "GO-T-3", "GO-T-1"}; !slices.Equal(second, want) {
		t.Errorf("run 2 assessed %v, want the previously cut advisories first: %v", second, want)
	}
	// Every carried advisory completed, so the stored Report has no cut row and no note: state
	// replacement clears the backlog.
	if got := cutIDs(rep2); len(got) != 0 {
		t.Errorf("run 2 cut rows = %v, want none", got)
	}
	if notes := cutShortNotes(rep2); len(notes) != 0 {
		t.Errorf("run 2 notes = %+v, want none", notes)
	}
	if stored := store.state.Report; len(cutIDs(stored)) != 0 || len(cutShortNotes(stored)) != 0 {
		t.Errorf("stored Report still carries a backlog: rows %v, notes %+v", cutIDs(stored), cutShortNotes(stored))
	}
}

// TestRunBaseline_CarryOrdering: carried goes after the band and ahead of signal priority, and a
// run with nothing carried keeps today's order.
func TestRunBaseline_CarryOrdering(t *testing.T) {
	cases := []struct {
		name   string
		store  func() *memStore
		bands  map[string]Band
		sig    bool
		corpus []assessment.VulnRef
		want   []string
	}{
		{
			name:  "no prior state",
			store: func() *memStore { return &memStore{} },
			want:  []string{"GO-T-1", "GO-T-2", "GO-T-3"},
		},
		{
			name:  "prior state with no cut rows",
			store: func() *memStore { return storedCorpus(cutShortCorpus, nil) },
			want:  []string{"GO-T-1", "GO-T-2", "GO-T-3"},
		},
		{
			name:  "no prior state, signals",
			store: func() *memStore { return &memStore{} },
			sig:   true,
			want:  []string{"GO-T-3", "GO-T-2", "GO-T-1"},
		},
		{
			name:  "carried beats a higher signal priority within a band",
			store: func() *memStore { return storedCorpus(cutShortCorpus[1:], cutShortCorpus[:1]) },
			sig:   true,
			want:  []string{"GO-T-1", "GO-T-3", "GO-T-2"},
		},
		{
			name:   "carried beats a higher signal priority that sits earlier in the input",
			store:  func() *memStore { return storedCorpus(cutShortCorpus[1:], cutShortCorpus[:1]) },
			sig:    true,
			corpus: []assessment.VulnRef{cutShortCorpus[2], cutShortCorpus[1], cutShortCorpus[0]},
			want:   []string{"GO-T-1", "GO-T-3", "GO-T-2"},
		},
		{
			name:  "signal priority orders the carried among themselves",
			store: func() *memStore { return storedCorpus(nil, cutShortCorpus[:2]) },
			sig:   true,
			want:  []string{"GO-T-2", "GO-T-1", "GO-T-3"},
		},
		{
			name:  "band beats carried",
			store: func() *memStore { return storedCorpus(cutShortCorpus[1:], cutShortCorpus[:1]) },
			bands: map[string]Band{"GO-T-3": BandImmediate},
			want:  []string{"GO-T-3", "GO-T-1", "GO-T-2"},
		},
		{
			name: "a carried advisory whose source differs is not carried",
			store: func() *memStore {
				return storedCorpus(cutShortCorpus[:2], []assessment.VulnRef{{ID: "GO-T-3", Source: "osv"}})
			},
			want: []string{"GO-T-1", "GO-T-2", "GO-T-3"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sig *intel.Signals
			if tc.sig {
				sig = orderSignals(t)
			}
			corpus := tc.corpus
			if corpus == nil {
				corpus = cutShortCorpus
			}
			got, _ := carryRun(t, tc.store(), corpus, tc.bands, sig, "never")
			if !slices.Equal(got, tc.want) {
				t.Errorf("assessed %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRunBaseline_DropsCutRowsOutsideTheWorkSet: a stored cut row whose advisory is no longer in
// the work set is neither assessed nor stored again.
func TestRunBaseline_DropsCutRowsOutsideTheWorkSet(t *testing.T) {
	gone := assessment.VulnRef{ID: "GO-T-9", Source: "corpus"}
	store := storedCorpus(cutShortCorpus[:1], []assessment.VulnRef{gone, cutShortCorpus[2]})
	got, rep := carryRun(t, store, cutShortCorpus, nil, nil, "never")
	if want := []string{"GO-T-3", "GO-T-1", "GO-T-2"}; !slices.Equal(got, want) {
		t.Errorf("assessed %v, want %v", got, want)
	}
	if rows := rowsByID(rep)[gone.ID]; len(rows) != 0 {
		t.Errorf("rows for the departed advisory = %+v, want none", rows)
	}
	if got := cutIDs(store.state.Report); len(got) != 0 {
		t.Errorf("stored cut rows = %v, want none", got)
	}
}

// TestRunBaseline_CarriedNote: a run stopped again, after carrying, says how many advisories it
// carried, and the count's parse still reads the cause.
func TestRunBaseline_CarriedNote(t *testing.T) {
	store := storedCorpus(cutShortCorpus[:1], cutShortCorpus[1:])
	got, rep := carryRun(t, store, cutShortCorpus, nil, nil, "GO-T-3")
	if want := []string{"GO-T-2", "GO-T-3"}; !slices.Equal(got, want) {
		t.Fatalf("assessed %v, want %v", got, want)
	}
	const want = "2 of 3 advisories were not assessed: test stop. 2 advisories carried from the previous run and assessed first."
	notes := cutShortNotes(rep)
	if len(notes) != 1 || notes[0].Detail != want {
		t.Fatalf("notes = %+v, want one %q", notes, want)
	}
	if len(cutIDs(rep)) != 2 {
		t.Fatalf("cut rows = %v", cutIDs(rep))
	}

	// A later pass recounts over the stored notes: the cause survives, the stale sentence does not.
	cutOnly := slices.DeleteFunc(slices.Clone(rep.Advisories), func(f report.AdvisoryFinding) bool {
		return f.UndeterminedReason != report.ReasonScanCutShort
	})
	recount, ok := recountCutShort(cutOnly[:1], rep.Partiality, "")
	if !ok || recount.Detail != "1 of 1 advisories were not assessed: test stop" {
		t.Errorf("recount = %+v, %v", recount, ok)
	}
}

func TestCutShortNote_Carried(t *testing.T) {
	cases := []struct {
		carried int
		want    string
	}{
		{0, "1 of 4 advisories were not assessed: why"},
		{1, "1 of 4 advisories were not assessed: why. 1 advisory carried from the previous run and assessed first."},
		{3, "1 of 4 advisories were not assessed: why. 3 advisories carried from the previous run and assessed first."},
	}
	for _, tc := range cases {
		n := cutShortNote(1, 4, "why", tc.carried)
		if n.Detail != tc.want {
			t.Errorf("carried %d: detail %q, want %q", tc.carried, n.Detail, tc.want)
		}
		if !isCutShortCount(n) {
			t.Errorf("carried %d: not read as a cut-short count", tc.carried)
		}
		rows := []report.AdvisoryFinding{cutShortFinding(assessment.VulnRef{ID: "A", Source: "s"})}
		got, ok := recountCutShort(rows, []report.PartialityNote{n}, "")
		if !ok || got.Detail != "1 of 1 advisories were not assessed: why" {
			t.Errorf("carried %d: recount %+v, %v", tc.carried, got, ok)
		}
	}
}

// TestCVEWatch_RetriesStoredCutShortRows: a cve-watch with nothing new still assesses the stored
// scan_cut_short rows, once each, and clears them when they complete.
func TestCVEWatch_RetriesStoredCutShortRows(t *testing.T) {
	store := storedCorpus(cutShortCorpus[:1], cutShortCorpus[1:])
	store.state.Cursor = "GO-T-1"
	opts, analysis, calls := recordingStoppingOptions(t, "never", stopAndWait)
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: opts,
		Analysis:      analysis,
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Heartbeat || res.Report == nil {
		t.Fatalf("heartbeat = %v, report = %v; want an earnest run", res.Heartbeat, res.Report != nil)
	}
	got := calls.order()
	slices.Sort(got)
	if want := []string{"GO-T-2", "GO-T-3"}; !slices.Equal(got, want) {
		t.Errorf("assessed %v, want %v", got, want)
	}
	if len(cutIDs(res.Report)) != 0 || len(cutShortNotes(res.Report)) != 0 {
		t.Errorf("cut rows %v, notes %+v remain after the retry", cutIDs(res.Report), cutShortNotes(res.Report))
	}
}

// TestCutShortRetry: each stored cut row once, none for a row a new OSV advisory or an earlier
// retry already assesses, none for a row that is not cut short.
func TestCutShortRetry(t *testing.T) {
	prior := storedCorpus(cutShortCorpus[:1], []assessment.VulnRef{{ID: "GO-T-2", Source: osvSource}, {ID: "GO-T-3", Source: "corpus"}}).state.Report
	already := []report.AdvisoryFinding{{Advisory: report.Advisory{ID: "GO-T-3", Source: "corpus"}}}
	got := retriedIDs(cutShortRetry(prior, []string{"GO-T-2"}, already))
	if want := []string{"GO-T-3"}; !slices.Equal(got, want) {
		t.Errorf("retried %v, want %v (GO-T-2 is a new advisory)", got, want)
	}
	if rows := cutShortRetry(prior, nil, nil); len(rows) != 2 {
		t.Errorf("retried %d rows, want 2", len(rows))
	}
}

// TestCarryIsSchedulerOnly: the carry flag never rides on the VulnRef the pipeline sees, and a
// completed scan's Report is identical whatever order carried advisories ran in.
func TestCarryIsSchedulerOnly(t *testing.T) {
	scheduled := withCarried(scheduleFor(cutShortCorpus, nil), storedCorpus(nil, cutShortCorpus[2:]).state.Report)
	res := admitAdvisories(scheduled)
	if res.Carried != 1 || res.Admitted[0] != cutShortCorpus[2] {
		t.Fatalf("admitted %+v, carried %d", res.Admitted, res.Carried)
	}

	plainStore := &memStore{}
	_, plain := carryRun(t, plainStore, cutShortCorpus, nil, nil, "never")
	_, carried := carryRun(t, storedCorpus(cutShortCorpus[:2], cutShortCorpus[2:]), cutShortCorpus, nil, nil, "never")
	if !reflect.DeepEqual(plain.Advisories, carried.Advisories) {
		t.Errorf("a completed scan's verdicts depend on order:\nplain   %+v\ncarried %+v", plain.Advisories, carried.Advisories)
	}
}
