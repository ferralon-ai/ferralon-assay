package trigger

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// disqualifiableSource serves GO-2021-0113's facts for every id, with the affected range closed
// below the build's v0.3.6 for each id starting "GO-D-": those advisories settle at disqualification
// discovery, the others need the plugin.
type disqualifiableSource struct{}

func (disqualifiableSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	facts, ok := fixtureSource().Lookup(wiringAdvisory.ID)
	if strings.HasPrefix(id, "GO-D-") {
		facts.UpperExclusive, facts.FixedVersion = "v0.3.0", "v0.3.0"
	}
	return facts, ok
}

func passAdvisories(ids ...string) []assessment.VulnRef {
	out := make([]assessment.VulnRef, len(ids))
	for i, id := range ids {
		out[i] = assessment.VulnRef{ID: id, Source: "corpus"}
	}
	return out
}

func passOptions(t *testing.T, stopAt string, mode stopMode) ([]pipeline.AssessOption, context.Context) {
	t.Helper()
	opts, analysis := stoppingOptions(t, stopAt, mode)
	return append(opts, pipeline.WithAdvisorySource(disqualifiableSource{})), analysis
}

func runPasses(t *testing.T, advisories []assessment.VulnRef, opts []pipeline.AssessOption, analysis context.Context) *report.Report {
	t.Helper()
	rep, err := buildBaselineReport(context.Background(), BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    advisories,
		AssessOptions: opts,
		Analysis:      analysis,
	})
	if err != nil {
		t.Fatalf("buildBaselineReport: %v", err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return rep
}

// TestBaseline_CutShortKeepsDisqualified: a scan stopped inside one advisory's plugin analysis
// still gives every advisory that disqualifies without analysis its real row, wherever it sits in
// the work set; the advisory in flight and the unreached ones needing analysis are cut short, and
// the note counts exactly those.
func TestBaseline_CutShortKeepsDisqualified(t *testing.T) {
	const (
		ne  = report.VerdictNotExploitable
		dq  = report.VerdictDisqualified
		und = report.VerdictUndetermined
	)
	cases := []struct {
		name     string
		order    []string
		stopAt   string
		mode     stopMode
		verdicts map[string]report.Verdict
		cutNote  string
	}{
		{
			name: "no stop", order: []string{"GO-A-1", "GO-D-1", "GO-A-2", "GO-D-2"}, stopAt: "never",
			verdicts: map[string]report.Verdict{"GO-A-1": ne, "GO-D-1": dq, "GO-A-2": ne, "GO-D-2": dq},
		},
		{
			name: "the first advisory stalls", order: []string{"GO-A-1", "GO-D-1", "GO-A-2", "GO-D-2", "GO-D-3"}, stopAt: "GO-A-1", mode: stopAndWait,
			verdicts: map[string]report.Verdict{"GO-A-1": und, "GO-D-1": dq, "GO-A-2": und, "GO-D-2": dq, "GO-D-3": dq},
			cutNote:  "2 of 5 advisories were not assessed: test stop",
		},
		{
			name: "a middle advisory stalls", order: []string{"GO-D-1", "GO-A-1", "GO-A-2", "GO-D-2", "GO-A-3", "GO-D-3"}, stopAt: "GO-A-2", mode: stopAndWait,
			verdicts: map[string]report.Verdict{"GO-D-1": dq, "GO-A-1": ne, "GO-A-2": und, "GO-D-2": dq, "GO-A-3": und, "GO-D-3": dq},
			cutNote:  "2 of 6 advisories were not assessed: test stop",
		},
		{
			name: "an in-flight result returned after the stop is discarded", order: []string{"GO-A-1", "GO-D-1", "GO-A-2"}, stopAt: "GO-A-1", mode: stopAndSucceed,
			verdicts: map[string]report.Verdict{"GO-A-1": und, "GO-D-1": dq, "GO-A-2": und},
			cutNote:  "2 of 3 advisories were not assessed: test stop",
		},
		{
			name: "only disqualifiable advisories", order: []string{"GO-D-1", "GO-D-2"}, stopAt: "GO-D-1", mode: stopAndWait,
			verdicts: map[string]report.Verdict{"GO-D-1": dq, "GO-D-2": dq},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, analysis := passOptions(t, tc.stopAt, tc.mode)
			rep := runPasses(t, passAdvisories(tc.order...), opts, analysis)
			checkCutShort(t, rep, tc.verdicts, tc.cutNote)
		})
	}
}

// TestBaseline_TwoPassMatchesSinglePass: with nothing stopping the scan, each advisory's row is the
// one a single assess call builds for it, in the work set's order, and every stage runs once per
// advisory.
func TestBaseline_TwoPassMatchesSinglePass(t *testing.T) {
	advisories := passAdvisories("GO-A-1", "GO-D-1", "GO-A-2", "GO-D-2", "GO-A-3")
	opts, analysis := passOptions(t, "never", stopAndWait)
	timer := pipeline.NewStageTimer()
	analysis = pipeline.WithStageTimer(analysis, timer)
	rep := runPasses(t, advisories, opts, analysis)

	var want []report.AdvisoryFinding
	for _, adv := range advisories {
		areq := assessment.Request{Vulnerability: adv, Codebase: assessment.CodebaseRef{Repo: "r", Revision: "main"}}
		st, id, err := assess(context.Background(), areq, opts...)
		if err != nil {
			t.Fatalf("assess %s: %v", adv.ID, err)
		}
		advisory, pkg := advisoryFromArtifacts(st, id, areq, rep.SBOM.Packages)
		want = append(want, findingInBuild(st, id, advisory, pkg, goModulesOf(rep.SBOM, nil)))
	}
	if len(rep.Advisories) != len(want) {
		t.Fatalf("%d rows, want %d: %+v", len(rep.Advisories), len(want), rep.Advisories)
	}
	// The Report ranks its rows; compare by advisory.
	for _, w := range want {
		rows := rowsByID(rep)[w.Advisory.ID]
		if len(rows) != 1 {
			t.Fatalf("%d rows for %s, want one", len(rows), w.Advisory.ID)
		}
		got := rows[0]
		if got.Verdict != w.Verdict || got.UndeterminedReason != w.UndeterminedReason || !reflect.DeepEqual(got.Evidence, w.Evidence) {
			t.Errorf("%s row = %+v, want %+v", w.Advisory.ID, got, w)
		}
	}

	runs := map[string]int{}
	for _, s := range timer.Stages() {
		runs[s.Stage] = s.Runs
	}
	for _, stage := range pipeline.AssessStages() {
		if runs[stage.Name()] != len(advisories) {
			t.Errorf("stage %s ran %d times, want %d", stage.Name(), runs[stage.Name()], len(advisories))
		}
	}
	var order []string
	for _, s := range timer.Stages() {
		order = append(order, s.Stage)
	}
	var stages []string
	for _, s := range pipeline.AssessStages() {
		stages = append(stages, s.Name())
	}
	if !slices.Equal(order, stages) {
		t.Errorf("stages first ran in order %v, want %v", order, stages)
	}
}

// TestSplitAssessStages: the split stages are AssessStages, in order, cut after disqualification.
func TestSplitAssessStages(t *testing.T) {
	settle, analyze := pipeline.SplitAssessStages()
	var got, want []string
	for _, s := range append(slices.Clone(settle), analyze...) {
		got = append(got, s.Name())
	}
	for _, s := range pipeline.AssessStages() {
		want = append(want, s.Name())
	}
	if !slices.Equal(got, want) {
		t.Errorf("split stages = %v, want %v", got, want)
	}
	if last := settle[len(settle)-1].Name(); last != "disqualification_discovery" {
		t.Errorf("settle ends at %s, want disqualification_discovery", last)
	}
}

const siblingGoMod = "module example.com/target\n\ngo 1.21\n\nrequire (\n\texample.com/lib v1.2.0\n\texample.com/lib/v2 v2.0.0\n)\n"

// siblingSource serves one advisory affecting two major versions of example.com/lib, both in range
// for the build, so the primary's assessment fans out to a sibling instance.
type siblingSource struct{}

func (siblingSource) Lookup(string) (pipeline.AdvisoryFacts, bool) {
	facts, _ := fixtureSource().Lookup(wiringAdvisory.ID)
	facts.Module, facts.PURL, facts.UpperExclusive, facts.FixedVersion = "example.com/lib", "pkg:golang/example.com/lib", "v1.5.0", "v1.5.0"
	facts.AffectedPackages = []pipeline.AffectedPackage{
		{Module: "example.com/lib", PURL: "pkg:golang/example.com/lib", UpperExclusive: "v1.5.0", FixedVersion: "v1.5.0"},
		{Module: "example.com/lib/v2", PURL: "pkg:golang/example.com/lib/v2", UpperExclusive: "v2.5.0", FixedVersion: "v2.5.0"},
	}
	return facts, true
}

// stopOnNthPlugin is refutingGoPlugin whose nth Reachability call stops the scan.
type stopOnNthPlugin struct {
	refutingGoPlugin
	stop  context.CancelFunc
	calls *atomic.Int32
	n     int32
}

func (p stopOnNthPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if p.calls.Add(1) == p.n {
		p.stop()
		<-ctx.Done()
		return plugin.ReachabilityResult{}, ctx.Err()
	}
	return p.refutingGoPlugin.Reachability(ctx, req)
}

// TestBaseline_CutShortCountsSiblingRows: an advisory whose assessment finished and whose sibling
// instance the scan stopped before assessing has a scan_cut_short row for the sibling, and the
// scan-level note counts it: the note's count is the number of scan_cut_short rows, of all rows.
func TestBaseline_CutShortCountsSiblingRows(t *testing.T) {
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	p := stopOnNthPlugin{
		refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()},
		stop:             func() { cancel(errTestStop) },
		calls:            &atomic.Int32{},
		n:                2,
	}
	opts := []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, siblingGoMod), lang: "go"}),
		pipeline.WithPlugin(p),
		pipeline.WithAdvisorySource(siblingSource{}),
	}
	rep := runPasses(t, passAdvisories("GO-S-1"), opts, analysis)
	rows := rowsByID(rep)["GO-S-1"]
	cutRows := 0
	for _, f := range rows {
		if f.UndeterminedReason == report.ReasonScanCutShort {
			cutRows++
		}
	}
	if len(rows) != 2 || cutRows != 1 {
		t.Fatalf("rows for GO-S-1 = %+v, want the primary and one cut sibling", rows)
	}
	want := fmt.Sprintf("%d of %d advisories were not assessed: test stop", cutRows, len(rows))
	if notes := cutShortNotes(rep); len(notes) != 1 || notes[0].Detail != want {
		t.Errorf("scan_cut_short notes = %+v, want one %q", notes, want)
	}
}

// storeState is the stored state a baseline report leaves.
func storeState(r *report.Report) *statestore.State {
	return &statestore.State{Report: r, SBOM: r.SBOM}
}

// TestCutShortKeepsDisqualified_EveryLoop: in the PR re-analysis (slow and fast path) and the
// CVE-watch earnest run, a scan stopped inside GO-A-2's analysis still gives the disqualified
// advisories after the stop their rows, and the note counts only the rows it cut.
func TestCutShortKeepsDisqualified_EveryLoop(t *testing.T) {
	ids := []string{"GO-A-1", "GO-A-2", "GO-D-1", "GO-A-3", "GO-D-2"}
	want := map[string]report.Verdict{
		"GO-A-1": report.VerdictNotExploitable, "GO-A-2": report.VerdictUndetermined, "GO-D-1": report.VerdictDisqualified,
		"GO-A-3": report.VerdictUndetermined, "GO-D-2": report.VerdictDisqualified,
	}
	const note = "2 of 5 advisories were not assessed: test stop"
	baseline := func(t *testing.T) *report.Report {
		t.Helper()
		opts, analysis := passOptions(t, "never", stopAndWait)
		rep, err := buildBaselineReport(context.Background(), BaselineRequest{
			Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			Advisories:    passAdvisories("GO-A-1"),
			AssessOptions: opts,
			Analysis:      analysis,
		})
		if err != nil {
			t.Fatalf("baseline: %v", err)
		}
		return rep
	}
	prInherit := func(t *testing.T, changeHead bool) *report.Report {
		t.Helper()
		base := baseline(t)
		head := slices.Clone(base.SBOM.Packages)
		if changeHead {
			head = append(head, report.Package{Ecosystem: "Go", Name: "example.com/other", Version: "v1.0.0"})
		}
		opts, analysis := passOptions(t, "GO-A-2", stopAndWait)
		res, err := RunPRInherit(context.Background(), &memStore{state: storeState(base)}, PRInheritRequest{
			Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
			Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
			PRSBOM:        report.SBOM{Packages: head},
			Advisories:    passAdvisories(ids...),
			AssessOptions: opts,
			Analysis:      analysis,
		})
		if err != nil {
			t.Fatalf("RunPRInherit: %v", err)
		}
		if res.Inherited == changeHead {
			t.Fatalf("Inherited = %v with a changed head = %v", res.Inherited, changeHead)
		}
		return res.Report
	}
	cases := []struct {
		name string
		run  func(t *testing.T) *report.Report
	}{
		{"PR re-analysis, changed head", func(t *testing.T) *report.Report { return prInherit(t, true) }},
		{"PR re-analysis, unchanged head", func(t *testing.T) *report.Report { return prInherit(t, false) }},
		{"CVE-watch earnest run", func(t *testing.T) *report.Report {
			st := storeState(storedCorpus(passAdvisories("GO-A-1"), nil).state.Report)
			st.Cursor = wiringAdvisory.ID
			osv := &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{
				{ID: "GO-A-2", Package: wiringPkg}, {ID: "GO-D-1", Package: wiringPkg}, {ID: "GO-A-3", Package: wiringPkg}, {ID: "GO-D-2", Package: wiringPkg},
			}}}
			opts, analysis := passOptions(t, "GO-A-2", stopAndWait)
			res, err := RunCVEWatch(context.Background(), &memStore{state: st}, osv, CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    passAdvisories("GO-A-1"),
				AssessOptions: opts,
				Analysis:      analysis,
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			return res.Report
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := tc.run(t)
			if err := rep.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			checkCutShort(t, rep, want, note)
		})
	}
}

// stopOnManifestPlugin is refutingGoPlugin whose nth BuildManifest call, one per advisory in its
// inventory stage, stops the scan.
type stopOnManifestPlugin struct {
	refutingGoPlugin
	stop  context.CancelFunc
	calls *atomic.Int32
	n     int32
}

// Reachability holds every analysis until the scan stops, so the first pass running ahead of it
// never lets an advisory finish before the stop.
func (p stopOnManifestPlugin) Reachability(ctx context.Context, _ plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	<-ctx.Done()
	return plugin.ReachabilityResult{}, ctx.Err()
}

func (p stopOnManifestPlugin) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	if p.calls.Add(1) != p.n {
		return p.refutingGoPlugin.BuildManifest(ctx, req)
	}
	p.stop()
	<-ctx.Done()
	return plugin.BuildManifestResult{}, ctx.Err()
}

// TestBaseline_StopDuringFirstPass: a stop inside the third advisory's manifest stage, with every
// analysis still in flight, leaves the advisory settled before it its disqualified row and cuts
// every other one, the advisories that need analysis included, and the note counts them.
func TestBaseline_StopDuringFirstPass(t *testing.T) {
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	p := stopOnManifestPlugin{
		refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()},
		stop:             func() { cancel(errTestStop) },
		calls:            &atomic.Int32{},
		n:                3,
	}
	opts := []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
		pipeline.WithPlugin(p),
		pipeline.WithAdvisorySource(disqualifiableSource{}),
	}
	rep := runPasses(t, passAdvisories("GO-A-1", "GO-D-1", "GO-A-2", "GO-D-2"), opts, analysis)
	checkCutShort(t, rep, map[string]report.Verdict{
		"GO-A-1": report.VerdictUndetermined, "GO-D-1": report.VerdictDisqualified,
		"GO-A-2": report.VerdictUndetermined, "GO-D-2": report.VerdictUndetermined,
	}, "3 of 4 advisories were not assessed: test stop")
}

// failNthCheckout is fixedCheckout whose nth Fetch fails.
type failNthCheckout struct {
	fixedCheckout
	calls *atomic.Int32
	n     int32
}

func (c failNthCheckout) Fetch(ctx context.Context, repo, rev string) (checkout.WorkspacePlan, error) {
	if c.calls.Add(1) == c.n {
		return checkout.WorkspacePlan{}, errors.New("checkout failed")
	}
	return c.fixedCheckout.Fetch(ctx, repo, rev)
}

// TestBaseline_FirstPassErrorIsAnAssessmentFailure: an advisory whose first-pass stages fail gets the
// failure row and note an assessment error always gets, the others keep their verdicts, and every
// advisory, the failed one included, is counted by the per-advisory timing hook.
func TestBaseline_FirstPassErrorIsAnAssessmentFailure(t *testing.T) {
	opts, analysis := passOptions(t, "never", stopAndWait)
	opts = append(opts, pipeline.WithCheckout(failNthCheckout{
		fixedCheckout: fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"},
		calls:         &atomic.Int32{},
		n:             3,
	}))
	var observed []string
	analysis = WithAdvisoryTiming(analysis, func(v assessment.VulnRef, _ time.Duration) { observed = append(observed, v.ID) })
	rep := runPasses(t, passAdvisories("GO-A-1", "GO-A-2", "GO-A-3"), opts, analysis)

	rows := rowsByID(rep)
	for id, v := range map[string]report.Verdict{"GO-A-1": report.VerdictNotExploitable, "GO-A-2": report.VerdictUndetermined, "GO-A-3": report.VerdictNotExploitable} {
		if len(rows[id]) != 1 || rows[id][0].Verdict != v {
			t.Errorf("%s rows = %+v, want one %q", id, rows[id], v)
		}
	}
	if got := rows["GO-A-2"]; len(got) == 1 && got[0].UndeterminedReason != report.ReasonAnalysisDidNotRun {
		t.Errorf("GO-A-2 reason = %q, want %q", got[0].UndeterminedReason, report.ReasonAnalysisDidNotRun)
	}
	slices.Sort(observed)
	if !slices.Equal(observed, []string{"GO-A-1", "GO-A-2", "GO-A-3"}) {
		t.Errorf("advisories timed = %v, want all three", observed)
	}
}

// slowManifestPlugin is refutingGoPlugin whose BuildManifest calls after the first fast never
// return until the scan stops: the inventory stage of every advisory from then on is a slow one, as
// a lane's per-coordinate membership calls make it.
type slowManifestPlugin struct {
	refutingGoPlugin
	calls *atomic.Int32
	fast  int32
}

func (p slowManifestPlugin) BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	if p.calls.Add(1) <= p.fast {
		return p.refutingGoPlugin.BuildManifest(ctx, req)
	}
	<-ctx.Done()
	return plugin.BuildManifestResult{}, ctx.Err()
}

// TestBaseline_SlowInventoryDoesNotDelayAnalysis: with an inventory stage that stalls from the
// third advisory on, a scan stopped once two advisories are analysed keeps both. One serial pass
// analyses exactly those two before it stalls in the third; a first pass that ran to completion
// before any analysis would never get past the stall and keep none. The logical clock is the
// advisory timing hook: the stop is the second finished assessment. The timer is only a backstop
// that turns a regression into a failed assertion instead of a hang.
func TestBaseline_SlowInventoryDoesNotDelayAnalysis(t *testing.T) {
	const k = 2
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	backstop := time.AfterFunc(5*time.Second, func() { cancel(errors.New("backstop")) })
	t.Cleanup(func() { backstop.Stop() })
	var assessed atomic.Int32
	analysis = WithTiming(analysis, func(phase string, _ time.Duration) {
		if phase == "advisory" && assessed.Add(1) == k {
			cancel(errTestStop)
		}
	})
	opts := []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}),
		pipeline.WithPlugin(slowManifestPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, calls: &atomic.Int32{}, fast: k}),
		pipeline.WithAdvisorySource(disqualifiableSource{}),
	}
	rep := runPasses(t, passAdvisories("GO-A-1", "GO-A-2", "GO-A-3", "GO-A-4"), opts, analysis)
	checkCutShort(t, rep, map[string]report.Verdict{
		"GO-A-1": report.VerdictNotExploitable, "GO-A-2": report.VerdictNotExploitable,
		"GO-A-3": report.VerdictUndetermined, "GO-A-4": report.VerdictUndetermined,
	}, "2 of 4 advisories were not assessed: test stop")
}

// TestBaseline_ManyAdvisoriesOverlappedPasses runs the overlapped passes over many advisories with
// nothing stopping them, for -race: the rows are the ones each advisory settles or analyses to, in
// the Report's order.
func TestBaseline_ManyAdvisoriesOverlappedPasses(t *testing.T) {
	var ids []string
	want := map[string]report.Verdict{}
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("GO-A-%d", i)
		v := report.VerdictNotExploitable
		if i%3 == 0 {
			id, v = fmt.Sprintf("GO-D-%d", i), report.VerdictDisqualified
		}
		ids = append(ids, id)
		want[id] = v
	}
	opts, analysis := passOptions(t, "never", stopAndWait)
	// A committed repository, so the inventory memo's checkout reads (go.work search, HEAD) settle on
	// the first advisory and the 40 do not each fork git, which a -race build on darwin can livelock.
	opts = append(opts, pipeline.WithCheckout(fixedCheckout{dir: gitRepoWithGoMod(t, wiringGoMod), lang: "go"}))
	rep := runPasses(t, passAdvisories(ids...), opts, analysis)
	checkCutShort(t, rep, want, "")
	got := make([]string, len(rep.Advisories))
	for i, f := range rep.Advisories {
		got[i] = f.Advisory.ID
	}
	slices.Sort(ids)
	if !reflect.DeepEqual(got, ids) {
		t.Errorf("row order = %v, want the Report's order %v", got, ids)
	}
}

// gitRepoWithGoMod is a directory holding go.mod as the one commit of a git repository.
func gitRepoWithGoMod(t *testing.T, body string) string {
	t.Helper()
	dir := writeGoMod(t, body)
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "go.mod"},
		{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "go.mod"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// TestCVEWatch_RetriedCutRowAssessesSiblingInstances: a cut row cve-watch retries gets the rows a
// completed baseline gives its advisory, the sibling instance included, so the retry cannot clear
// the cut disclosure while another major version of the module was never assessed.
func TestCVEWatch_RetriedCutRowAssessesSiblingInstances(t *testing.T) {
	assessOpts := func(p plugin.LanguagePlugin) []pipeline.AssessOption {
		return []pipeline.AssessOption{
			pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, siblingGoMod), lang: "go"}),
			pipeline.WithPlugin(p),
			pipeline.WithAdvisorySource(siblingSource{}),
		}
	}
	complete := refutingGoPlugin{inventory: plugin.Complete()}
	store := &memStore{}
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	stopFirst := stopOnNthPlugin{refutingGoPlugin: complete, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: 1}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    passAdvisories("GO-S-1"),
		AssessOptions: assessOpts(stopFirst),
		Analysis:      analysis,
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if got := cutIDs(store.state.Report); !slices.Equal(got, []string{"GO-S-1"}) {
		t.Fatalf("stored cut rows = %v, want GO-S-1", got)
	}

	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: assessOpts(complete),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Report == nil {
		t.Fatal("cve-watch ran no earnest pass")
	}
	want := rowsByID(runPasses(t, passAdvisories("GO-S-1"), assessOpts(complete), nil))["GO-S-1"]
	got := rowsByID(res.Report)["GO-S-1"]
	if len(want) != 2 {
		t.Fatalf("baseline rows = %+v, want the primary and a sibling", want)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cve-watch rows for GO-S-1:\n%+v\nbaseline rows:\n%+v", got, want)
	}
	if len(cutShortNotes(res.Report)) != 0 {
		t.Errorf("cut-short notes remain: %+v", cutShortNotes(res.Report))
	}
}

// siblingNotesSource is siblingSource whose second major version lists a vulnerable symbol and
// whose first does not, so the two instances' rows carry different notes.
type siblingNotesSource struct{}

func (siblingNotesSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	facts, _ := siblingSource{}.Lookup(id)
	base, _ := fixtureSource().Lookup(wiringAdvisory.ID)
	facts.AffectedPackages[1].Symbols = base.Symbols
	return facts, true
}

func siblingAssessOpts(t *testing.T, p plugin.LanguagePlugin, src pipeline.AdvisorySource) []pipeline.AssessOption {
	t.Helper()
	return []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, siblingGoMod), lang: "go"}),
		pipeline.WithPlugin(p),
		pipeline.WithAdvisorySource(src),
	}
}

// cutSiblingBaseline stores a baseline over the sibling advisory that the scan stopped at its first
// reachability call, so its one row is cut, under source.
func cutSiblingBaseline(t *testing.T, src pipeline.AdvisorySource, source string, n int32) *memStore {
	t.Helper()
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	p := stopOnNthPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: n}
	store := &memStore{}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    []assessment.VulnRef{{ID: "GO-S-1", Source: source}},
		AssessOptions: siblingAssessOpts(t, p, src),
		Analysis:      analysis,
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if got := cutIDs(store.state.Report); !slices.Equal(got, []string{"GO-S-1"}) {
		t.Fatalf("stored cut rows = %v, want GO-S-1", got)
	}
	return store
}

// TestCVEWatch_RetriedOSVCutRowAssessesSiblingInstances: a cut row stored under source osv, whose
// ID OSV reports again, is assessed as a new advisory and gets the rows and notes a completed
// baseline gives it, the sibling instance's included.
func TestCVEWatch_RetriedOSVCutRowAssessesSiblingInstances(t *testing.T) {
	src := siblingNotesSource{}
	complete := refutingGoPlugin{inventory: plugin.Complete()}
	store := cutSiblingBaseline(t, src, osvSource, 1)
	full := runPasses(t, []assessment.VulnRef{{ID: "GO-S-1", Source: osvSource}}, siblingAssessOpts(t, complete, src), nil)
	want := rowsByID(full)["GO-S-1"]
	if len(want) != 2 {
		t.Fatalf("baseline rows = %+v, want the primary and a sibling", want)
	}
	var pkg report.Package
	for _, f := range want {
		if f.Package != nil && f.Package.Name == "example.com/lib" {
			pkg = *f.Package
		}
	}
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{result: OSVResult{Advisories: []OSVAdvisory{{ID: "GO-S-1", Package: pkg}}}}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: siblingAssessOpts(t, complete, src),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if !slices.Equal(res.NewAdvisories, []string{"GO-S-1"}) {
		t.Fatalf("new advisories = %v, want GO-S-1 assessed by the new-advisory lane", res.NewAdvisories)
	}
	if got := rowsByID(res.Report)["GO-S-1"]; !reflect.DeepEqual(got, want) {
		t.Errorf("cve-watch rows for GO-S-1:\n%+v\nbaseline rows:\n%+v", got, want)
	}
	if len(cutShortNotes(res.Report)) != 0 {
		t.Errorf("cut-short notes remain: %+v", cutShortNotes(res.Report))
	}
	for _, n := range full.Partiality {
		if !hasNoteReason(res.Report.Partiality, n.Reason) {
			t.Errorf("baseline note %q missing from the cve-watch report: %+v", n.Reason, res.Report.Partiality)
		}
	}
}

// TestCVEWatch_SiblingStopsAgainStaysDisclosed: a retried cut row whose sibling instance the scan
// stops before assessing again keeps the sibling's cut row, discloses it as 1 of 2, and holds the
// cursor so the next run assesses it.
func TestCVEWatch_SiblingStopsAgainStaysDisclosed(t *testing.T) {
	store := cutSiblingBaseline(t, siblingSource{}, "corpus", 1)
	store.state.Cursor = "held"
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	p := stopOnNthPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: 2}
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: siblingAssessOpts(t, p, siblingSource{}),
		Analysis:      analysis,
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Report == nil {
		t.Fatal("cve-watch ran no earnest pass")
	}
	if rows := rowsByID(res.Report)["GO-S-1"]; len(rows) != 2 || len(cutIDs(res.Report)) != 1 {
		t.Errorf("rows for GO-S-1 = %+v, want the primary and one cut sibling", rows)
	}
	const want = "1 of 2 advisories were not assessed: test stop"
	if notes := cutShortNotes(res.Report); len(notes) != 1 || notes[0].Detail != want {
		t.Errorf("scan_cut_short notes = %+v, want one %q", notes, want)
	}
	if res.Cursor != "held" || !res.Truncated {
		t.Errorf("cursor = %q, truncated = %v; want the held cursor and a truncated report", res.Cursor, res.Truncated)
	}
}

// TestCVEWatch_RetriedCutRowReplacesEveryCutRowUnderItsKey: a key holding two cut rows is cleared by
// one retry, which leaves the rows a completed baseline gives, not a stale cut row beside them.
func TestCVEWatch_RetriedCutRowReplacesEveryCutRowUnderItsKey(t *testing.T) {
	src := siblingSource{}
	complete := refutingGoPlugin{inventory: plugin.Complete()}
	store := cutSiblingBaseline(t, src, "corpus", 1)
	store.state.Report.Advisories = append(store.state.Report.Advisories, cutShortFinding(assessment.VulnRef{ID: "GO-S-1", Source: "corpus"}))
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: siblingAssessOpts(t, complete, src),
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	want := rowsByID(runPasses(t, passAdvisories("GO-S-1"), siblingAssessOpts(t, complete, src), nil))["GO-S-1"]
	if got := rowsByID(res.Report)["GO-S-1"]; !reflect.DeepEqual(got, want) {
		t.Errorf("cve-watch rows for GO-S-1:\n%+v\nbaseline rows:\n%+v", got, want)
	}
	if len(cutIDs(res.Report)) != 0 || len(cutShortNotes(res.Report)) != 0 {
		t.Errorf("cut rows %v, notes %+v remain", cutIDs(res.Report), cutShortNotes(res.Report))
	}
}

// TestCVEWatch_NotFetchedRetryLeavesSiblingRows: a retry of a completed parent that is not a cut row
// replaces the parent and keeps the stored sibling row; it does not assess the siblings again.
func TestCVEWatch_NotFetchedRetryLeavesSiblingRows(t *testing.T) {
	src := siblingSource{}
	complete := refutingGoPlugin{inventory: plugin.Complete()}
	store := &memStore{}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    passAdvisories("GO-S-1"),
		AssessOptions: siblingAssessOpts(t, complete, src),
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	if rows := rowsByID(store.state.Report)["GO-S-1"]; len(rows) != 2 {
		t.Fatalf("stored rows = %+v, want the primary and a sibling", rows)
	}
	store.state.DepFetch = &statestore.DepFetch{Reassess: []string{"GO-S-1"}}
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
		Subject:         Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:        assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions:   siblingAssessOpts(t, complete, src),
		DependencyFetch: func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch { return prior },
	})
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if !slices.Equal(res.Reassessed, []string{"GO-S-1"}) {
		t.Fatalf("reassessed = %v, want GO-S-1", res.Reassessed)
	}
	if rows := rowsByID(res.Report)["GO-S-1"]; len(rows) != 2 {
		t.Errorf("rows for GO-S-1 = %+v, want the primary and the one stored sibling", rows)
	}
}

// TestCVEWatch_RetryKeepsCutSiblingWhateverTheStoredOrder: a baseline whose stop landed in the
// sibling pass stores the completed parent and a cut sibling under one key. A not-fetched retry of
// the parent replaces the parent's row only, whichever row the stored order puts first.
func TestCVEWatch_RetryKeepsCutSiblingWhateverTheStoredOrder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cutFirst bool
	}{{"cut row first", true}, {"parent first", false}} {
		t.Run(tc.name, func(t *testing.T) {
			src := siblingSource{}
			store := cutSiblingBaseline(t, src, "corpus", 2)
			rows := store.state.Report.Advisories
			slices.SortStableFunc(rows, func(a, b report.AdvisoryFinding) int {
				ac, bc := a.UndeterminedReason == report.ReasonScanCutShort, b.UndeterminedReason == report.ReasonScanCutShort
				switch {
				case ac == bc:
					return 0
				case ac == tc.cutFirst:
					return -1
				}
				return 1
			})
			if (rows[0].UndeterminedReason == report.ReasonScanCutShort) != tc.cutFirst {
				t.Fatalf("stored order = %+v, want the cut row first = %v", rows, tc.cutFirst)
			}
			store.state.DepFetch = &statestore.DepFetch{Reassess: []string{"GO-S-1"}}
			res, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
				Subject:         Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase:        assessment.CodebaseRef{Repo: "r", Revision: "main"},
				AssessOptions:   siblingAssessOpts(t, refutingGoPlugin{inventory: plugin.Complete()}, src),
				DependencyFetch: func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch { return prior },
			})
			if err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			if got := cutIDs(res.Report); !slices.Equal(got, []string{"GO-S-1"}) {
				t.Errorf("cut rows = %v, want the one cut sibling", got)
			}
			if got := rowsByID(res.Report)["GO-S-1"]; len(got) != 2 {
				t.Errorf("rows for GO-S-1 = %+v, want the fresh parent and the cut sibling", got)
			}
			if len(cutShortNotes(res.Report)) != 1 {
				t.Errorf("cut-short notes = %+v, want one", cutShortNotes(res.Report))
			}
		})
	}
}

// retryStored runs a cve-watch over store's GO-S-1 rows with the retry lane named: "not fetched"
// lists the ID for reassessment, "restated" stores an entry-point statement the run does not state.
func retryStored(t *testing.T, store *memStore, lane string, p plugin.LanguagePlugin, analysis context.Context) *CVEWatchResult {
	t.Helper()
	return retryStoredFrom(t, store, lane, p, siblingSource{}, analysis)
}

// retryStoredFrom is retryStored with the advisory facts read from src.
func retryStoredFrom(t *testing.T, store *memStore, lane string, p plugin.LanguagePlugin, src pipeline.AdvisorySource, analysis context.Context) *CVEWatchResult {
	t.Helper()
	req := CVEWatchRequest{
		Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		AssessOptions: siblingAssessOpts(t, p, src),
		Analysis:      analysis,
	}
	switch lane {
	case "not fetched":
		store.state.DepFetch = &statestore.DepFetch{Reassess: []string{"GO-S-1"}}
		req.DependencyFetch = func(prior *statestore.DepFetch, _ DependencyFetchRun) *statestore.DepFetch { return prior }
	case "restated":
		store.state.Report.LibraryEntrypoints = []plugin.ResolvedLibraryEntrypoints{{Ecosystem: "golang", Input: "none,auto"}}
	}
	res, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, req)
	if err != nil {
		t.Fatalf("RunCVEWatch: %v", err)
	}
	if res.Report == nil {
		t.Fatal("cve-watch ran no earnest pass")
	}
	return res
}

// completedSiblingBaseline stores a completed baseline's GO-S-1 rows, the parent and one sibling,
// the sibling made a failed assessment's row when failed, in the order sibling-first or not.
func completedSiblingBaseline(t *testing.T, failed, siblingFirst bool) *memStore {
	t.Helper()
	store := &memStore{}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    passAdvisories("GO-S-1"),
		AssessOptions: siblingAssessOpts(t, refutingGoPlugin{inventory: plugin.Complete()}, siblingSource{}),
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	rows := store.state.Report.Advisories
	if len(rows) != 2 {
		t.Fatalf("stored rows = %+v, want the parent and a sibling", rows)
	}
	sib := slices.IndexFunc(rows, func(f report.AdvisoryFinding) bool { return f.Package != nil && f.Package.Name == "example.com/lib/v2" })
	if sib < 0 {
		t.Fatalf("stored rows = %+v, want a sibling of example.com/lib/v2", rows)
	}
	if failed {
		ref := assessment.VulnRef{ID: "GO-S-1", Source: "corpus"}
		err := errors.New("boom")
		rows[sib] = assessFailureFinding(ref, err)
		store.state.Report.Partiality = append(store.state.Report.Partiality, assessFailureNote(ref, err))
	}
	if (sib == 0) != siblingFirst {
		rows[0], rows[1] = rows[1], rows[0]
	}
	return store
}

// TestCVEWatch_RetryOfParentKeepsCompletedAndFailedSiblings: a not-fetched or restated retry of a
// completed parent replaces the parent's row and leaves its sibling's row, completed or failed (a
// failed sibling's names no package), as stored, in either stored order.
func TestCVEWatch_RetryOfParentKeepsCompletedAndFailedSiblings(t *testing.T) {
	complete := refutingGoPlugin{inventory: plugin.Complete()}
	for _, lane := range []string{"not fetched", "restated"} {
		for _, failed := range []bool{false, true} {
			for _, siblingFirst := range []bool{true, false} {
				name := fmt.Sprintf("%s/failed=%v/sibling first=%v", lane, failed, siblingFirst)
				t.Run(name, func(t *testing.T) {
					store := completedSiblingBaseline(t, failed, siblingFirst)
					var sibling report.AdvisoryFinding
					for _, f := range store.state.Report.Advisories {
						if failed == (f.UndeterminedReason == report.ReasonAnalysisDidNotRun) && (f.Package == nil || f.Package.Name == "example.com/lib/v2") {
							sibling = f
						}
					}
					res := retryStored(t, store, lane, complete, context.Background())
					rows := rowsByID(res.Report)["GO-S-1"]
					if len(rows) != 2 || !slices.ContainsFunc(rows, func(f report.AdvisoryFinding) bool { return reflect.DeepEqual(f, sibling) }) {
						t.Errorf("rows = %+v, want the fresh parent and the stored sibling %+v", rows, sibling)
					}
					if failed && !hasNoteReason(res.Report.Partiality, plugin.PartialReasonToolFailure) {
						t.Errorf("the sibling's failure note was dropped: %+v", res.Report.Partiality)
					}
				})
			}
		}
	}
}

// TestCVEWatch_RetryReplacesParentFailureRow: a parent whose stored assessment failed has no package
// and no sibling rows, so a retry's fresh row replaces it.
func TestCVEWatch_RetryReplacesParentFailureRow(t *testing.T) {
	for _, lane := range []string{"not fetched", "restated"} {
		t.Run(lane, func(t *testing.T) {
			store := completedSiblingBaseline(t, false, false)
			ref := assessment.VulnRef{ID: "GO-S-1", Source: "corpus"}
			store.state.Report.Advisories = []report.AdvisoryFinding{assessFailureFinding(ref, errors.New("boom"))}
			res := retryStored(t, store, lane, refutingGoPlugin{inventory: plugin.Complete()}, context.Background())
			rows := rowsByID(res.Report)["GO-S-1"]
			if len(rows) != 1 || rows[0].UndeterminedReason == report.ReasonAnalysisDidNotRun {
				t.Errorf("rows = %+v, want the fresh row alone", rows)
			}
		})
	}
}

// TestCVEWatch_RetryThatStopsReplacesParentRow: a retry of a completed parent that stops replaces
// the parent's row with a cut row and leaves the completed sibling.
func TestCVEWatch_RetryThatStopsReplacesParentRow(t *testing.T) {
	store := completedSiblingBaseline(t, false, false)
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	p := stopOnNthPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: 1}
	res := retryStored(t, store, "not fetched", p, analysis)
	rows := rowsByID(res.Report)["GO-S-1"]
	if len(rows) != 2 || len(cutIDs(res.Report)) != 1 {
		t.Errorf("rows = %+v, want one cut row and the stored sibling", rows)
	}
}

// TestCVEWatch_RetryThatStopsAgainReturnsKeyToCutOnly: a retry that stops again leaves its key
// holding only cut rows, so the next run fans it out. Stopped in analysis, the retry names the
// parent, and its cut row replaces the parent's beside the cut sibling. Stopped before its first
// pass, it names no instance; beside one packaged row and otherwise cut rows it takes that row as
// the parent's, even when it is a completed sibling's, in either stored order and either lane.
func TestCVEWatch_RetryThatStopsAgainReturnsKeyToCutOnly(t *testing.T) {
	t.Run("in analysis beside a cut sibling", func(t *testing.T) {
		store := cutSiblingBaseline(t, siblingSource{}, "corpus", 2)
		slices.SortStableFunc(store.state.Report.Advisories, func(a, b report.AdvisoryFinding) int {
			return cmp.Compare(btoi(b.UndeterminedReason == report.ReasonScanCutShort), btoi(a.UndeterminedReason == report.ReasonScanCutShort))
		})
		analysis, cancel := context.WithCancelCause(context.Background())
		t.Cleanup(func() { cancel(nil) })
		p := stopOnNthPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: 1}
		res := retryStored(t, store, "not fetched", p, analysis)
		rows := rowsByID(res.Report)["GO-S-1"]
		if len(rows) != 2 || len(cutIDs(res.Report)) != 2 {
			t.Errorf("rows = %+v, want two cut rows and no completed one", rows)
		}
		if notes := cutShortNotes(res.Report); len(notes) != 1 || !strings.HasPrefix(notes[0].Detail, "2 of 2 advisories") {
			t.Errorf("scan_cut_short notes = %+v, want one for 2 of 2", notes)
		}
	})
	for _, lane := range []string{"not fetched", "restated"} {
		for _, siblingFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("before its first pass beside a completed sibling/%s/sibling first=%v", lane, siblingFirst), func(t *testing.T) {
				store := completedSiblingBaseline(t, false, siblingFirst)
				for i, f := range store.state.Report.Advisories {
					if f.Package != nil && f.Package.Name == "example.com/lib" {
						store.state.Report.Advisories[i] = cutShortFinding(assessment.VulnRef{ID: "GO-S-1", Source: "corpus"})
					}
				}
				analysis, cancel := context.WithCancelCause(context.Background())
				cancel(errTestStop)
				res := retryStored(t, store, lane, refutingGoPlugin{inventory: plugin.Complete()}, analysis)
				rows := rowsByID(res.Report)["GO-S-1"]
				if len(rows) != 2 || len(cutIDs(res.Report)) != 2 {
					t.Errorf("rows = %+v, want two cut rows and no completed one", rows)
				}
			})
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// failFirstPlugin errors the first Reachability call, so the assessment that makes it fails.
type failFirstPlugin struct {
	refutingGoPlugin
	calls *atomic.Int32
}

func (p failFirstPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if p.calls.Add(1) == 1 {
		return plugin.ReachabilityResult{}, errors.New("plugin crashed")
	}
	return p.refutingGoPlugin.Reachability(ctx, req)
}

// rowKind names what a GO-S-1 row records: the module a completed row names, or cut, or failure.
func rowKind(f report.AdvisoryFinding) string {
	switch f.UndeterminedReason {
	case report.ReasonScanCutShort:
		return "cut"
	case report.ReasonAnalysisDidNotRun:
		return "failure"
	}
	if f.Package == nil {
		return "completed:none"
	}
	return "completed:" + f.Package.Name
}

// TestCVEWatch_RetryRowMatrix holds the retry merge to one invariant over every state a key can be
// stored in and every retry that can reach it. The key's parent row is completed (naming
// example.com/lib), cut or a failure (naming no package); its sibling instance's row, for
// example.com/lib/v2, is absent, completed, cut or a failure; the two are stored in either order.
// The run retries the parent and it completes, stops or fails. Afterwards:
//
//	(a) the sibling's stored row is unchanged, and a failed sibling's note stands;
//	(b) the parent has exactly one row, fresh: completed, cut when it stopped, a failure when it failed;
//	(c) no stale row for the parent stays beside it.
//
// A key holding only cut rows is a retried cut row's: every row under it is replaced, and the run
// assesses the sibling again, as a baseline does.
//
// Every stop and failure here comes in analysis, after the retry's first pass adjudicated the
// parent, so the retry always names the parent's package, whatever the stored order. The invariant
// gives way in one family of cells, where the stored rows cannot say which row is the parent's: the
// key's package-less rows differ (a cut row beside a failure row, either of which may be the
// parent's). The run then keeps every stored row and adds the fresh one: three rows, every stored one
// disclosed, none lost. A stale duplicate is the price of never dropping a sibling's row on a guess.
func TestCVEWatch_RetryRowMatrix(t *testing.T) {
	base := completedSiblingBaseline(t, false, false)
	var parent, sibling report.AdvisoryFinding
	for _, f := range base.state.Report.Advisories {
		if f.Package != nil && f.Package.Name == "example.com/lib/v2" {
			sibling = f
		} else {
			parent = f
		}
	}
	ref := assessment.VulnRef{ID: "GO-S-1", Source: "corpus"}
	stored := map[string]report.AdvisoryFinding{
		"completed": parent,
		"cut":       cutShortFinding(ref),
		"failure":   assessFailureFinding(ref, errors.New("boom")),
	}
	siblingRows := map[string]report.AdvisoryFinding{
		"completed": sibling,
		"cut":       cutShortFinding(ref),
		"failure":   assessFailureFinding(ref, errors.New("boom")),
	}
	kinds := func(rows ...report.AdvisoryFinding) []string {
		var out []string
		for _, f := range rows {
			out = append(out, rowKind(f))
		}
		slices.Sort(out)
		return out
	}
	for _, parentKind := range []string{"completed", "cut", "failure"} {
		for _, siblingKind := range []string{"absent", "completed", "cut", "failure"} {
			for _, siblingFirst := range []bool{false, true} {
				if siblingKind == "absent" && siblingFirst {
					continue
				}
				for _, outcome := range []string{"completes", "stops", "fails"} {
					cutOnly := parentKind == "cut" && (siblingKind == "absent" || siblingKind == "cut")
					lanes := []string{"not fetched", "restated"}
					if cutOnly {
						lanes = append(lanes, "cut retry")
					}
					for _, lane := range lanes {
						name := fmt.Sprintf("parent %s/sibling %s/sibling first=%v/%s/%s", parentKind, siblingKind, siblingFirst, lane, outcome)
						t.Run(name, func(t *testing.T) {
							store := &memStore{}
							st := *base.state
							rep := *base.state.Report
							rep.Advisories = []report.AdvisoryFinding{stored[parentKind]}
							rep.Partiality = nil
							if siblingKind != "absent" {
								rep.Advisories = append(rep.Advisories, siblingRows[siblingKind])
								if siblingFirst {
									rep.Advisories[0], rep.Advisories[1] = rep.Advisories[1], rep.Advisories[0]
								}
							}
							for _, k := range []string{parentKind, siblingKind} {
								if k == "failure" {
									rep.Partiality = append(rep.Partiality, assessFailureNote(ref, errors.New("boom")))
								}
							}
							st.Report = &rep
							store.state = &st
							var p plugin.LanguagePlugin = refutingGoPlugin{inventory: plugin.Complete()}
							analysis := context.Background()
							switch outcome {
							case "stops":
								ctx, cancel := context.WithCancelCause(context.Background())
								t.Cleanup(func() { cancel(nil) })
								p = stopOnNthPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: 1}
								analysis = ctx
							case "fails":
								p = failFirstPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, calls: &atomic.Int32{}}
							}
							storedRows := slices.Clone(store.state.Report.Advisories)
							res := retryStored(t, store, lane, p, analysis)
							got := kinds(rowsByID(res.Report)["GO-S-1"]...)

							fresh := map[string]string{"completes": "completed:example.com/lib", "stops": "cut", "fails": "failure"}[outcome]
							var want []string
							if cutOnly {
								// Replaced as a baseline gives them: a parent that completes brings its
								// sibling instance, one that stops or fails brings none.
								want = []string{fresh}
								if outcome == "completes" {
									want = append(want, "completed:example.com/lib/v2")
								}
							} else {
								want = []string{fresh}
								if siblingKind != "absent" {
									want = append(want, rowKind(siblingRows[siblingKind]))
								}
							}
							differ := siblingKind != "absent" && parentKind != "completed" && siblingKind != "completed" && parentKind != siblingKind
							exception := !cutOnly && differ
							if exception {
								want = append([]string{fresh}, kinds(storedRows...)...)
							}
							slices.Sort(want)
							if !slices.Equal(got, want) {
								t.Errorf("rows = %v, want %v", got, want)
							}
							if !cutOnly {
								// (a), and in the exception cells every stored row survives.
								var keep []report.AdvisoryFinding
								switch {
								case exception:
									keep = storedRows
								case siblingKind != "absent":
									keep = []report.AdvisoryFinding{siblingRows[siblingKind]}
								}
								for _, k := range keep {
									if !slices.ContainsFunc(rowsByID(res.Report)["GO-S-1"], func(f report.AdvisoryFinding) bool { return reflect.DeepEqual(f, k) }) {
										t.Errorf("stored row %s changed or was dropped: %+v", rowKind(k), rowsByID(res.Report)["GO-S-1"])
									}
								}
							}
							if !cutOnly && siblingKind == "failure" && !hasNoteReason(res.Report.Partiality, plugin.PartialReasonToolFailure) {
								t.Errorf("the failed sibling's note was dropped: %+v", res.Report.Partiality)
							}
						})
					}
				}
			}
		}
	}
}

// stopOnFirst returns a plugin whose first Reachability call stops the run, and its analysis context.
func stopOnFirst(t *testing.T) (plugin.LanguagePlugin, context.Context) {
	t.Helper()
	analysis, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	return stopOnNthPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: 1}, analysis
}

// TestCVEWatch_StoppedRetryThenNextRunKeepsSibling: a restated retry that stops on the parent leaves
// no new entry-point statement, so the next scheduled cve-watch retries the key again. The sibling's
// completed row survives both runs, and the parent ends with one completed row.
func TestCVEWatch_StoppedRetryThenNextRunKeepsSibling(t *testing.T) {
	store := completedSiblingBaseline(t, false, false)
	p, analysis := stopOnFirst(t)
	res := retryStored(t, store, "restated", p, analysis)
	if rows := rowsByID(res.Report)["GO-S-1"]; len(rows) != 2 || len(cutIDs(res.Report)) != 1 {
		t.Fatalf("after the stopped retry rows = %+v, want one cut row and the sibling", rows)
	}
	res = retryStored(t, store, "plain", refutingGoPlugin{inventory: plugin.Complete()}, context.Background())
	got := []string{}
	for _, f := range rowsByID(res.Report)["GO-S-1"] {
		got = append(got, rowKind(f))
	}
	slices.Sort(got)
	if want := []string{"completed:example.com/lib", "completed:example.com/lib/v2"}; !slices.Equal(got, want) {
		t.Errorf("after the next run rows = %v, want %v", got, want)
	}
}

// TestCVEWatch_RetryOfStoredParentFailureLeavesNoFailureRow: a parent whose retry errored stores a
// package-less failure row beside its sibling; the next retry completes and replaces it, in either
// stored order.
func TestCVEWatch_RetryOfStoredParentFailureLeavesNoFailureRow(t *testing.T) {
	for _, siblingFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("sibling first=%v", siblingFirst), func(t *testing.T) {
			store := completedSiblingBaseline(t, false, siblingFirst)
			ref := assessment.VulnRef{ID: "GO-S-1", Source: "corpus"}
			rows := store.state.Report.Advisories
			for i, f := range rows {
				if f.Package != nil && f.Package.Name != "example.com/lib/v2" {
					rows[i] = assessFailureFinding(ref, errors.New("boom"))
				}
			}
			res := retryStored(t, store, "not fetched", refutingGoPlugin{inventory: plugin.Complete()}, context.Background())
			got := []string{}
			for _, f := range rowsByID(res.Report)["GO-S-1"] {
				got = append(got, rowKind(f))
			}
			slices.Sort(got)
			if want := []string{"completed:example.com/lib", "completed:example.com/lib/v2"}; !slices.Equal(got, want) {
				t.Errorf("rows = %v, want %v", got, want)
			}
		})
	}
}

// TestCVEWatch_RetryThatLearnsNoPackageKeepsFailedSibling: a failed sibling stored above its parent,
// and a retry that stops. Stopped in analysis, the retry's first pass has named the parent, so the
// parent's row gives way to the fresh cut row and the failure row stays. Stopped before its first
// pass, the retry names no package and the stored rows cannot say which is the parent's (the accepted
// residue), so every stored row stays beside the fresh cut row: the failure row is not lost.
func TestCVEWatch_RetryThatLearnsNoPackageKeepsFailedSibling(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"stops in analysis", []string{"cut", "failure"}},
		{"stops before its first pass", []string{"completed:example.com/lib", "cut", "failure"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := completedSiblingBaseline(t, true, true)
			p, analysis := stopOnFirst(t)
			if tc.name == "stops before its first pass" {
				ctx, cancel := context.WithCancelCause(context.Background())
				cancel(errTestStop)
				analysis = ctx
			}
			res := retryStored(t, store, "not fetched", p, analysis)
			var got []string
			for _, f := range rowsByID(res.Report)["GO-S-1"] {
				got = append(got, rowKind(f))
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("rows = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCVEWatch_RetryReplacesTheOnlyRowWhateverItsPackage: a key's only row is the retried
// instance's even when it names another package than the fresh row (the instance is labeled
// differently from one run to the next), so the retry leaves one row, not two.
func TestCVEWatch_RetryReplacesTheOnlyRowWhateverItsPackage(t *testing.T) {
	store := completedSiblingBaseline(t, false, false)
	rep := store.state.Report
	rep.Advisories = slices.DeleteFunc(slices.Clone(rep.Advisories), func(f report.AdvisoryFinding) bool {
		return f.Package == nil || f.Package.Name != "example.com/lib/v2"
	})
	res := retryStored(t, store, "not fetched", refutingGoPlugin{inventory: plugin.Complete()}, context.Background())
	rows := rowsByID(res.Report)["GO-S-1"]
	if len(rows) != 1 || rowKind(rows[0]) != "completed:example.com/lib" {
		t.Errorf("rows = %+v, want the fresh row alone", rows)
	}
}
