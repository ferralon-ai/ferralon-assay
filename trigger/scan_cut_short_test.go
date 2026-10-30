package trigger

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// cutShortCorpus is three advisories that each assess exactly as GO-2021-0113 does under
// refutingGoPlugin: a grounded not_exploitable when nothing stops the scan.
var cutShortCorpus = []assessment.VulnRef{
	{ID: "GO-T-1", Source: "corpus"},
	{ID: "GO-T-2", Source: "corpus"},
	{ID: "GO-T-3", Source: "corpus"},
}

// clonedSource answers every id with GO-2021-0113's built-in facts.
type clonedSource struct{}

func (clonedSource) Lookup(string) (pipeline.AdvisoryFacts, bool) {
	return pipeline.NewTableSource().Lookup(wiringAdvisory.ID)
}

// stopMode is what stoppingPlugin does once it has stopped the scan.
type stopMode int

const (
	// stopAndWait stops the scan and returns the cancellation, as a plugin subprocess killed
	// mid-call does.
	stopAndWait stopMode = iota
	// stopAndSucceed stops the scan and then returns the refutation anyway: a stage that
	// swallowed the cancellation.
	stopAndSucceed
)

// stoppingPlugin is refutingGoPlugin with a stop: Reachability for the advisory stopAt, or the
// inventory when stopAt is "inventory", cancels the scan's analysis context from inside the call.
type stoppingPlugin struct {
	refutingGoPlugin
	stop   context.CancelFunc
	stopAt string
	mode   stopMode
}

func (p stoppingPlugin) ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	if p.stopAt != "inventory" {
		return p.refutingGoPlugin.ResolveInventory(ctx, req)
	}
	p.stop()
	<-ctx.Done()
	return plugin.DependencyInventory{}, ctx.Err()
}

func (p stoppingPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if req.VulnID != p.stopAt {
		return p.refutingGoPlugin.Reachability(ctx, req)
	}
	p.stop()
	if p.mode == stopAndSucceed {
		return p.refutingGoPlugin.Reachability(ctx, req)
	}
	<-ctx.Done()
	return plugin.ReachabilityResult{}, ctx.Err()
}

var errTestStop = errors.New("test stop")

// stoppingOptions returns the assess options and the analysis context their plugin stops.
func stoppingOptions(t *testing.T, stopAt string, mode stopMode) ([]pipeline.AssessOption, context.Context) {
	t.Helper()
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	p := stoppingPlugin{
		refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()},
		stop:             func() { cancel(errTestStop) },
		stopAt:           stopAt,
		mode:             mode,
	}
	return []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
		pipeline.WithPlugin(p),
		pipeline.WithAdvisorySource(clonedSource{}),
	}, analysis
}

func rowsByID(rep *report.Report) map[string][]report.AdvisoryFinding {
	rows := make(map[string][]report.AdvisoryFinding)
	for _, f := range rep.Advisories {
		rows[f.Advisory.ID] = append(rows[f.Advisory.ID], f)
	}
	return rows
}

func cutShortNotes(rep *report.Report) []report.PartialityNote {
	var notes []report.PartialityNote
	for _, n := range rep.Partiality {
		if n.Reason == report.ReasonScanCutShort {
			notes = append(notes, n)
		}
	}
	return notes
}

// TestBaseline_CutShort: a scan stopped mid-run keeps the verdicts it finished, gives every
// advisory it did not finish a scan_cut_short row, and discloses the stop once. The stop lands
// inside an assessment, in the inventory, or inside an assessment that then returns a refutation
// anyway; in each case nothing assessed after the stop keeps a verdict.
func TestBaseline_CutShort(t *testing.T) {
	cases := []struct {
		name     string
		stopAt   string
		mode     stopMode
		verdicts map[string]report.Verdict
		// cutNote is the scan-level note's detail, "" for none.
		cutNote string
	}{
		{
			name: "control: no stop", stopAt: "never",
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictNotExploitable, "GO-T-3": report.VerdictNotExploitable},
		},
		{
			name: "stopped inside the second assessment", stopAt: "GO-T-2", mode: stopAndWait,
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictUndetermined, "GO-T-3": report.VerdictUndetermined},
			cutNote:  "2 of 3 advisories were not assessed: test stop",
		},
		{
			name: "an assessment that returns a refutation after the stop is discarded", stopAt: "GO-T-2", mode: stopAndSucceed,
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictUndetermined, "GO-T-3": report.VerdictUndetermined},
			cutNote:  "2 of 3 advisories were not assessed: test stop",
		},
		{
			name: "stopped during the inventory", stopAt: "inventory",
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictUndetermined, "GO-T-2": report.VerdictUndetermined, "GO-T-3": report.VerdictUndetermined},
			cutNote:  "3 of 3 advisories were not assessed: test stop",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, analysis := stoppingOptions(t, tc.stopAt, tc.mode)
			rep, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    cutShortCorpus,
				AssessOptions: opts,
				Analysis:      analysis,
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			if err := rep.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			rows := rowsByID(rep)
			for _, adv := range cutShortCorpus {
				got := rows[adv.ID]
				if len(got) != 1 {
					t.Fatalf("%d rows for %s, want exactly one: %+v", len(got), adv.ID, got)
				}
				f := got[0]
				if f.Verdict != tc.verdicts[adv.ID] {
					t.Errorf("%s verdict = %q, want %q", adv.ID, f.Verdict, tc.verdicts[adv.ID])
				}
				if f.Verdict != report.VerdictUndetermined {
					continue
				}
				if f.UndeterminedReason != report.ReasonScanCutShort || f.Evidence.Basis != "" || f.Package != nil {
					t.Errorf("%s = reason %q basis %q package %+v, want scan_cut_short with no basis or package",
						adv.ID, f.UndeterminedReason, f.Evidence.Basis, f.Package)
				}
			}
			notes := cutShortNotes(rep)
			var scanNotes []report.PartialityNote
			for _, n := range notes {
				if n.Detail != inventoryLimitDetail {
					scanNotes = append(scanNotes, n)
				}
			}
			switch {
			case tc.cutNote == "" && len(notes) > 0:
				t.Errorf("scan_cut_short notes = %+v, want none", notes)
			case tc.cutNote != "" && (len(scanNotes) != 1 || scanNotes[0].Detail != tc.cutNote):
				t.Errorf("scan-level scan_cut_short notes = %+v, want one with detail %q", scanNotes, tc.cutNote)
			case tc.cutNote != "" && scanNotes[0].EffectiveClass() != report.PartialityDidNotRun:
				t.Errorf("note class = %q, want %q", scanNotes[0].EffectiveClass(), report.PartialityDidNotRun)
			}
			if tc.stopAt == "inventory" && len(notes) != 2 {
				t.Errorf("scan_cut_short notes = %+v, want the inventory disclosure and the scan-level note", notes)
			}
		})
	}
}

// TestPRReanalysis_CutShort: a PR re-analysis stopped mid-run replaces the baseline's
// not_exploitable with a scan_cut_short row for every advisory it did not finish.
func TestPRReanalysis_CutShort(t *testing.T) {
	opts, analysis := stoppingOptions(t, "GO-T-1", stopAndSucceed)
	store, _ := groundedBaseline()
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:        report.SBOM{Packages: []report.Package{{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.5"}}},
		Advisories:    append([]assessment.VulnRef{wiringAdvisory}, cutShortCorpus...),
		AssessOptions: opts,
		Analysis:      analysis,
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	want := map[string]report.Verdict{
		wiringAdvisory.ID: report.VerdictNotExploitable,
		"GO-T-1":          report.VerdictUndetermined,
		"GO-T-2":          report.VerdictUndetermined,
		"GO-T-3":          report.VerdictUndetermined,
	}
	rows := rowsByID(res.Report)
	for id, v := range want {
		if len(rows[id]) != 1 || rows[id][0].Verdict != v {
			t.Errorf("%s rows = %+v, want one %q", id, rows[id], v)
		}
	}
	if notes := cutShortNotes(res.Report); len(notes) != 1 || notes[0].Detail != "3 of 4 advisories were not assessed: test stop" {
		t.Errorf("scan_cut_short notes = %+v, want one naming 3 of 4", notes)
	}
}

// storedCorpus is a stored baseline on wiringPkg holding a not_exploitable row for each of
// assessed and a scan_cut_short row for each of cut, counted with the cause "test stop", as a
// baseline stopped after assessed would store them.
func storedCorpus(assessed, cut []assessment.VulnRef) *memStore {
	pkg := wiringPkg
	b := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).AddPackage(pkg)
	for _, adv := range assessed {
		b.NotExploitable(report.Advisory{ID: adv.ID, Source: adv.Source}, &pkg, "vulnerable_symbol_absent", baselineDetail)
	}
	for _, adv := range cut {
		b.AddFinding(cutShortFinding(adv))
	}
	if len(cut) > 0 {
		b.AddPartiality(cutShortNote(len(cut), len(assessed)+len(cut), errTestStop.Error()))
	}
	baseline := b.WithProvenance(report.Provenance{CommitSHA: "base-sha"}).Build()
	return &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM}}
}

// fastPathOverCorpus runs PR re-analysis of advisories over a head identical to store's baseline,
// so it takes the fast path, with the stopping plugin stopAt and mode.
func fastPathOverCorpus(t *testing.T, store *memStore, advisories []assessment.VulnRef, stopAt string, mode stopMode) *report.Report {
	t.Helper()
	opts, analysis := stoppingOptions(t, stopAt, mode)
	res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		PRSBOM:        report.SBOM{Packages: slices.Clone(store.state.Report.SBOM.Packages)},
		Advisories:    advisories,
		AssessOptions: opts,
		Analysis:      analysis,
	})
	if err != nil {
		t.Fatalf("RunPRInherit: %v", err)
	}
	if !res.Inherited {
		t.Fatalf("took the slow path (changed = %q); the head is the baseline's", res.ChangedPackages)
	}
	if err := res.Report.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return res.Report
}

// checkCutShort fails the test unless rep holds one row per id in verdicts, with that verdict
// (an undetermined one cut short), and one scan-level scan_cut_short note with detail cutNote,
// or none when cutNote is "".
func checkCutShort(t *testing.T, rep *report.Report, verdicts map[string]report.Verdict, cutNote string) {
	t.Helper()
	rows := rowsByID(rep)
	if len(rows) != len(verdicts) {
		t.Errorf("rows for %d advisories, want %d: %+v", len(rows), len(verdicts), rep.Advisories)
	}
	for id, v := range verdicts {
		if len(rows[id]) != 1 || rows[id][0].Verdict != v {
			t.Errorf("%s rows = %+v, want one %q", id, rows[id], v)
			continue
		}
		if v == report.VerdictUndetermined && rows[id][0].UndeterminedReason != report.ReasonScanCutShort {
			t.Errorf("%s reason = %q, want scan_cut_short", id, rows[id][0].UndeterminedReason)
		}
	}
	notes := cutShortNotes(rep)
	switch {
	case cutNote == "" && len(notes) != 0:
		t.Errorf("scan_cut_short notes = %+v, want none", notes)
	case cutNote != "" && (len(notes) != 1 || notes[0].Detail != cutNote):
		t.Errorf("scan_cut_short notes = %+v, want one %q", notes, cutNote)
	}
}

// TestInheritFastPath_CutShort: the fast path's fresh rows run under the scan's time budget, as
// the slow path's do. Over a complete baseline holding GO-T-1 and an unchanged head, GO-T-2 and
// GO-T-3 are assessed fresh; a stop inside one of them gives it, and every advisory after it, a
// scan_cut_short row, discards a refutation returned after the stop, and is counted once.
func TestInheritFastPath_CutShort(t *testing.T) {
	cases := []struct {
		name     string
		stopAt   string
		mode     stopMode
		verdicts map[string]report.Verdict
		cutNote  string // "" for none
	}{
		{
			name: "control: no stop", stopAt: "never",
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictNotExploitable, "GO-T-3": report.VerdictNotExploitable},
		},
		{
			name: "stopped inside the last fresh assessment", stopAt: "GO-T-3", mode: stopAndWait,
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictNotExploitable, "GO-T-3": report.VerdictUndetermined},
			cutNote:  "1 of 3 advisories were not assessed: test stop",
		},
		{
			name: "a refutation returned after the stop is discarded", stopAt: "GO-T-2", mode: stopAndSucceed,
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictUndetermined, "GO-T-3": report.VerdictUndetermined},
			cutNote:  "2 of 3 advisories were not assessed: test stop",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := fastPathOverCorpus(t, storedCorpus(cutShortCorpus[:1], nil), cutShortCorpus, tc.stopAt, tc.mode)
			checkCutShort(t, rep, tc.verdicts, tc.cutNote)
		})
	}
}

// TestInheritFastPath_RecountsCutShort: TestPRReanalysis_RecountsCutShort on the fast path. A
// stored baseline cut short after GO-T-1 holds scan_cut_short rows for GO-T-2 and GO-T-3, and the
// head is unchanged. A cut row is no row to inherit, so each one in the work set is assessed fresh
// and replaced, and the scan_cut_short note counts the cut rows left, with the baseline's cause,
// or is gone when none is left.
func TestInheritFastPath_RecountsCutShort(t *testing.T) {
	cases := []struct {
		name       string
		advisories []assessment.VulnRef
		verdicts   map[string]report.Verdict
		cutNote    string
	}{
		{
			name: "a complete run clears the note", advisories: cutShortCorpus,
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictNotExploitable, "GO-T-3": report.VerdictNotExploitable},
		},
		{
			name: "a partial run recounts it", advisories: cutShortCorpus[1:2],
			verdicts: map[string]report.Verdict{"GO-T-1": report.VerdictNotExploitable, "GO-T-2": report.VerdictNotExploitable, "GO-T-3": report.VerdictUndetermined},
			cutNote:  "1 of 3 advisories were not assessed: test stop",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := fastPathOverCorpus(t, storedCorpus(cutShortCorpus[:1], cutShortCorpus[1:]), tc.advisories, "never", stopAndWait)
			checkCutShort(t, rep, tc.verdicts, tc.cutNote)
		})
	}
}

// TestResolveSBOM_CutShort: a head inventory the stop interrupted is declared, not failed.
func TestResolveSBOM_CutShort(t *testing.T) {
	opts, analysis := stoppingOptions(t, "inventory", stopAndWait)
	sbom, notes, err := ResolveSBOM(analysis, ResolveSBOMRequest{
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: opts,
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}
	if len(sbom.Packages) != 0 || len(notes) != 1 || notes[0].Reason != report.ReasonScanCutShort {
		t.Fatalf("ResolveSBOM = %d packages, notes %+v; want none and one scan_cut_short note", len(sbom.Packages), notes)
	}
}

// TestCVEWatch_CutShortHoldsCursor: an earnest run the stop cut short keeps the stored cursor, so
// the advisories it did not assess are new again next run; a run that finished advances it.
func TestCVEWatch_CutShortHoldsCursor(t *testing.T) {
	cases := []struct {
		name       string
		stopAt     string
		wantCursor string
		wantCut    bool
	}{
		{name: "finished advances the cursor", stopAt: "never", wantCursor: "GO-2021-0113,GO-T-1,GO-T-2"},
		{name: "cut short holds the cursor", stopAt: "GO-T-2", wantCursor: wiringAdvisory.ID, wantCut: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, analysis := stoppingOptions(t, tc.stopAt, stopAndSucceed)
			store := emptyBaseline()
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
				{ID: wiringAdvisory.ID, Package: wiringPkg},
				{ID: "GO-T-1", Package: wiringPkg},
				{ID: "GO-T-2", Package: wiringPkg},
			}}}
			res, err := RunCVEWatch(context.Background(), store, osv, CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				AssessOptions: opts,
				Analysis:      analysis,
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if res.Report == nil {
				t.Fatal("CVE-watch ran no earnest pass")
			}
			if res.Cursor != tc.wantCursor || res.Report.Provenance.AdvisoryCursor != tc.wantCursor {
				t.Errorf("cursor = %q, provenance cursor = %q, want %q", res.Cursor, res.Report.Provenance.AdvisoryCursor, tc.wantCursor)
			}
			rows := rowsByID(res.Report)
			if got := rows["GO-T-2"]; len(got) != 1 || (got[0].UndeterminedReason == report.ReasonScanCutShort) != tc.wantCut {
				t.Errorf("GO-T-2 rows = %+v, want one, cut short %v", got, tc.wantCut)
			}
			if got := len(cutShortNotes(res.Report)) == 1; got != tc.wantCut {
				t.Errorf("scan_cut_short note present = %v, want %v", got, tc.wantCut)
			}
		})
	}
}

// TestRunBaseline_CutInventoryKeepsStoredSBOM: a baseline stopped during the inventory replaces the
// stored Report but not the stored SBOM, which CVE-watch queries; with none stored there is nothing
// to keep. A CVE-watch heartbeat after it still reports the scan truncated, and says when it had no
// inventory to query.
func TestRunBaseline_CutInventoryKeepsStoredSBOM(t *testing.T) {
	cases := []struct {
		name     string
		store    func() *memStore
		wantPkgs []report.Package
	}{
		{name: "stored SBOM kept", store: func() *memStore { s, _ := groundedBaseline(); return s }, wantPkgs: []report.Package{wiringPkg}},
		{name: "nothing stored", store: func() *memStore { return &memStore{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, analysis := stoppingOptions(t, "inventory", stopAndWait)
			store := tc.store()
			rep, err := RunBaseline(context.Background(), store, BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    cutShortCorpus,
				AssessOptions: opts,
				Analysis:      analysis,
			})
			if err != nil {
				t.Fatalf("RunBaseline: %v", err)
			}
			if store.state.Report.Subject.ResolvedCommit != "head-sha" || len(rowsByID(store.state.Report)) != len(cutShortCorpus) {
				t.Errorf("stored Report = %+v, want this run's", store.state.Report)
			}
			if !slices.Equal(store.state.SBOM.Packages, tc.wantPkgs) || !slices.Equal(rep.SBOM.Packages, tc.wantPkgs) {
				t.Errorf("stored SBOM %+v, Report SBOM %+v; want %+v", store.state.SBOM.Packages, rep.SBOM.Packages, tc.wantPkgs)
			}
			got := slices.ContainsFunc(rep.Partiality, func(n report.PartialityNote) bool { return n.Detail == priorSBOMNote.Detail })
			if got != (len(tc.wantPkgs) > 0) {
				t.Errorf("prior-SBOM disclosure present = %v, want %v", got, len(tc.wantPkgs) > 0)
			}

			watch, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
				Subject:  Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase: assessment.CodebaseRef{Repo: "r", Revision: "main"},
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if !watch.Heartbeat || !watch.Truncated || watch.NoInventory != (len(tc.wantPkgs) == 0) {
				t.Errorf("heartbeat %v, truncated %v, no inventory %v; want a truncated heartbeat, no inventory %v",
					watch.Heartbeat, watch.Truncated, watch.NoInventory, len(tc.wantPkgs) == 0)
			}
		})
	}
}

// TestRunCVEWatch_CompleteBaselineHeartbeat: a heartbeat over a baseline that ran to the end is
// neither truncated nor short of an inventory.
func TestRunCVEWatch_CompleteBaselineHeartbeat(t *testing.T) {
	opts, analysis := stoppingOptions(t, "never", stopAndWait)
	store := &memStore{}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    cutShortCorpus,
		AssessOptions: opts,
		Analysis:      analysis,
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	watch, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
		Subject:  Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase: assessment.CodebaseRef{Repo: "r", Revision: "main"},
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if !watch.Heartbeat || watch.Truncated || watch.NoInventory {
		t.Errorf("heartbeat %v, truncated %v, no inventory %v; want a complete heartbeat",
			watch.Heartbeat, watch.Truncated, watch.NoInventory)
	}
}

// TestPRReanalysis_RecountsCutShort: a stored baseline cut short after GO-T-1 leaves GO-T-2 and
// GO-T-3 unassessed. A PR re-analysis replaces each cut row it re-assesses, even on an unchanged
// package, and its scan_cut_short note counts the cut rows left, with the baseline's cause, or is
// gone when none is left.
func TestPRReanalysis_RecountsCutShort(t *testing.T) {
	cases := []struct {
		name       string
		advisories []assessment.VulnRef
		wantCut    []string
		wantNote   string
	}{
		{name: "a complete run clears the note", advisories: cutShortCorpus},
		{name: "a partial run recounts it", advisories: cutShortCorpus[1:2], wantCut: []string{"GO-T-3"}, wantNote: "1 of 3 advisories were not assessed: test stop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cutOpts, cutAnalysis := stoppingOptions(t, "GO-T-2", stopAndWait)
			baseline, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    cutShortCorpus,
				AssessOptions: cutOpts,
				Analysis:      cutAnalysis,
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			store := &memStore{state: &statestore.State{Report: baseline, SBOM: baseline.SBOM}}

			opts, analysis := stoppingOptions(t, "never", stopAndWait)
			head := append(slices.Clone(baseline.SBOM.Packages), report.Package{Ecosystem: "Go", Name: "example.com/other", Version: "v1.0.0"})
			res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				PRSBOM:        report.SBOM{Packages: head},
				Advisories:    tc.advisories,
				AssessOptions: opts,
				Analysis:      analysis,
			})
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			var cut []string
			for id, rows := range rowsByID(res.Report) {
				if len(rows) != 1 {
					t.Fatalf("%s rows = %+v, want one", id, rows)
				}
				if rows[0].UndeterminedReason == report.ReasonScanCutShort {
					cut = append(cut, id)
				} else if rows[0].Verdict != report.VerdictNotExploitable {
					t.Errorf("%s = %q, want not_exploitable", id, rows[0].Verdict)
				}
			}
			slices.Sort(cut)
			if !slices.Equal(cut, tc.wantCut) {
				t.Errorf("cut rows = %v, want %v", cut, tc.wantCut)
			}
			notes := cutShortNotes(res.Report)
			switch {
			case tc.wantNote == "" && len(notes) != 0:
				t.Errorf("scan_cut_short notes = %+v, want none", notes)
			case tc.wantNote != "" && (len(notes) != 1 || notes[0].Detail != tc.wantNote):
				t.Errorf("scan_cut_short notes = %+v, want one %q", notes, tc.wantNote)
			}
		})
	}
}
