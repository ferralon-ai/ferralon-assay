package trigger

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
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
