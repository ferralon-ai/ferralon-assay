package trigger

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

func TestRunMode(t *testing.T) {
	tests := []struct {
		name   string
		opts   []pipeline.AssessOption
		source string
		want   report.Mode
	}{
		{name: "no option, no source", want: report.Mode{Strictness: report.StrictnessPractical, Source: report.ModeSourceDefault}},
		{name: "strict from input", opts: []pipeline.AssessOption{pipeline.WithStrict(true)}, source: report.ModeSourceInput, want: report.Mode{Strictness: report.StrictnessStrict, Source: report.ModeSourceInput}},
		{name: "strict, no source", opts: []pipeline.AssessOption{pipeline.WithStrict(true)}, want: report.Mode{Strictness: report.StrictnessStrict, Source: report.ModeSourceInput}},
		{name: "practical option, no source", opts: []pipeline.AssessOption{pipeline.WithStrict(false)}, want: report.Mode{Strictness: report.StrictnessPractical, Source: report.ModeSourceDefault}},
		{name: "practical from config", opts: []pipeline.AssessOption{pipeline.WithStrict(false)}, source: report.ModeSourceConfig, want: report.Mode{Strictness: report.StrictnessPractical, Source: report.ModeSourceConfig}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runMode(tt.opts, tt.source); got != tt.want {
				t.Errorf("runMode = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A stored baseline is inherited only by a run in the same mode; a baseline with no mode field reads
// as practical.
const storedToolchain = "go1.1.0"

func TestInheritBlockedOnModeChange(t *testing.T) {
	strict, practical := report.Mode{Strictness: report.StrictnessStrict}, report.Mode{Strictness: report.StrictnessPractical}
	tests := []struct {
		name      string
		stored    *report.Mode
		runStrict bool
		inherited bool
	}{
		{name: "practical to practical", stored: &practical, inherited: true},
		{name: "strict to strict", stored: &strict, runStrict: true, inherited: true},
		{name: "legacy baseline, practical run", stored: nil, inherited: true},
		{name: "legacy baseline, strict run", stored: nil, runStrict: true},
		{name: "practical baseline, strict run", stored: &practical, runStrict: true},
		{name: "strict baseline, practical run", stored: &strict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := wiringPkg
			b := report.NewBuilder(report.Subject{Repo: "r", ResolvedCommit: "base-sha"}).
				AddPackage(pkg).
				NotExploitable(report.Advisory{ID: twoPackageAdvisory.ID, Source: twoPackageAdvisory.Source}, &pkg, "vulnerable_symbol_absent", baselineDetail).
				WithProvenance(report.Provenance{CommitSHA: "base-sha", AdvisoryCursor: twoPackageAdvisory.ID})
			if tt.stored != nil {
				b = b.WithMode(*tt.stored)
			}
			b = b.WithSubjectToolchain(&report.SubjectToolchain{Version: storedToolchain, Bound: "exact", Source: "ci_observed"})
			baseline := b.Build()
			fetches := 0
			req := PRInheritRequest{
				Subject:    Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				Codebase:   assessment.CodebaseRef{Repo: "r", Revision: "main"},
				PRSBOM:     report.SBOM{Packages: []report.Package{wiringPkg}},
				Advisories: []assessment.VulnRef{twoPackageAdvisory},
				Cursor:     "",
				AssessOptions: []pipeline.AssessOption{
					pipeline.WithCheckout(countingCheckout{fixedCheckout{dir: writeGoMod(t, wiringGoMod), lang: "go"}, &fetches}),
					pipeline.WithPlugin(refutingGoPlugin{inventory: plugin.Complete()}),
					pipeline.WithStrict(tt.runStrict),
				},
			}
			store := &memStore{state: &statestore.State{Report: &baseline, SBOM: baseline.SBOM, Cursor: twoPackageAdvisory.ID}}
			res, err := RunPRInherit(context.Background(), store, req)
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			if res.Inherited != tt.inherited {
				t.Errorf("Inherited = %v, want %v", res.Inherited, tt.inherited)
			}
			want := report.StrictnessPractical
			if tt.runStrict {
				want = report.StrictnessStrict
			}
			if got := res.Report.ModeOf(); got != want {
				t.Errorf("published report mode = %s, want %s", got, want)
			}
			gotTC := res.Report.SubjectToolchain
			if gotTC == nil {
				t.Fatal("published report records no subject toolchain")
			}
			if tt.inherited && gotTC.Version != storedToolchain {
				t.Errorf("inherited toolchain = %+v, want the stored %s", gotTC, storedToolchain)
			}
			if !tt.inherited && gotTC.Version == storedToolchain {
				t.Errorf("re-analysed report kept the stored toolchain %+v over the one this run resolved", gotTC)
			}
			if a := res.Report.RunAssumptions; a != nil && a.Build.Toolchain != nil && *a.Build.Toolchain != *gotTC {
				t.Errorf("run_assumptions toolchain %+v differs from subject_toolchain %+v", a.Build.Toolchain, gotTC)
			}
			if !tt.inherited && fetches == 0 {
				t.Error("blocked inherit did not re-analyse the baseline's advisory")
			}
		})
	}
}

// otherModeDetail marks every row of a stored report, so a run in another mode can be checked for
// carrying one.
const otherModeDetail = "reached under the stored report's mode"

// storedSiblingState is the state a baseline in the given mode leaves over GO-S-1, whose primary and
// sibling instance each have a row, plus a row for GO-OUT-1, an advisory outside the later runs' work
// set. Every row is marked with otherModeDetail.
func storedSiblingState(t *testing.T, strict bool) *memStore {
	t.Helper()
	store := &memStore{}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    passAdvisories("GO-S-1"),
		AssessOptions: append(siblingAssessOpts(t, refutingGoPlugin{inventory: plugin.Complete()}, siblingSource{}), pipeline.WithStrict(strict)),
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	rep := store.state.Report
	if rows := rowsByID(rep)["GO-S-1"]; len(rows) != 2 {
		t.Fatalf("stored rows = %+v, want the primary and a sibling", rows)
	}
	out := rep.Advisories[0]
	out.Advisory.ID = "GO-OUT-1"
	rep.Advisories = append(rep.Advisories, out)
	for i := range rep.Advisories {
		rep.Advisories[i].Evidence.Detail = otherModeDetail
	}
	return store
}

func otherModeRows(rep *report.Report) []report.AdvisoryFinding {
	var out []report.AdvisoryFinding
	for _, f := range rep.Advisories {
		if f.Evidence.Detail == otherModeDetail {
			out = append(out, f)
		}
	}
	return out
}

func strictnessName(strict bool) string {
	if strict {
		return report.StrictnessStrict
	}
	return report.StrictnessPractical
}

// A PR run in another mode than the baseline's carries none of the baseline's rows: the primary and
// sibling rows of an advisory in its work set are assessed again, and a row outside it is dropped.
func TestPRInheritCarriesNoRowAcrossModes(t *testing.T) {
	tests := []struct {
		name                    string
		storedStrict, runStrict bool
	}{
		{name: "practical baseline, strict run", runStrict: true},
		{name: "strict baseline, practical run", storedStrict: true},
		{name: "same mode inherits", storedStrict: true, runStrict: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storedSiblingState(t, tt.storedStrict)
			res, err := RunPRInherit(context.Background(), store, PRInheritRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "pr-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				PRSBOM:        store.state.Report.SBOM,
				Advisories:    passAdvisories("GO-S-1"),
				AssessOptions: append(siblingAssessOpts(t, refutingGoPlugin{inventory: plugin.Complete()}, siblingSource{}), pipeline.WithStrict(tt.runStrict)),
			})
			if err != nil {
				t.Fatalf("RunPRInherit: %v", err)
			}
			if got, want := res.Report.ModeOf(), strictnessName(tt.runStrict); got != want {
				t.Fatalf("report mode = %s, want %s", got, want)
			}
			carried := otherModeRows(res.Report)
			if tt.storedStrict == tt.runStrict {
				if len(carried) != 3 {
					t.Errorf("same-mode run carried %d of the baseline's 3 rows: %+v", len(carried), res.Report.Advisories)
				}
				return
			}
			if len(carried) != 0 {
				t.Errorf("%s report carries rows reached under the other mode: %+v", res.Report.ModeOf(), carried)
			}
			rows := rowsByID(res.Report)
			if len(rows["GO-S-1"]) != 2 {
				t.Errorf("rows for GO-S-1 = %+v, want the primary and the sibling assessed again", rows["GO-S-1"])
			}
			if len(rows["GO-OUT-1"]) != 0 {
				t.Errorf("rows for GO-OUT-1, outside the work set = %+v, want none", rows["GO-OUT-1"])
			}
		})
	}
}

// A cve-watch run in another mode than the stored report's stores none of its rows: every stored
// advisory is assessed again with its sibling instances, and a retry the scan stopped before leaves
// a cut row, not the stored sibling's.
func TestCVEWatchStoresNoRowAcrossModes(t *testing.T) {
	tests := []struct {
		name                    string
		storedStrict, runStrict bool
		stopAt                  int32
	}{
		{name: "practical state, strict run", runStrict: true},
		{name: "strict state, practical run", storedStrict: true},
		{name: "practical state, strict run stopped at the first analysis", runStrict: true, stopAt: 1},
		{name: "practical state, strict run stopped at the sibling", runStrict: true, stopAt: 2},
		{name: "same mode keeps the stored rows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := storedSiblingState(t, tt.storedStrict)
			var p plugin.LanguagePlugin = refutingGoPlugin{inventory: plugin.Complete()}
			analysis, cancel := context.WithCancelCause(context.Background())
			t.Cleanup(func() { cancel(nil) })
			if tt.stopAt > 0 {
				p = stopOnNthPlugin{refutingGoPlugin: refutingGoPlugin{inventory: plugin.Complete()}, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: tt.stopAt}
			}
			if _, err := RunCVEWatch(context.Background(), store, &fakeOSV{}, CVEWatchRequest{
				Subject:       Subject{Repo: "r", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				AssessOptions: append(siblingAssessOpts(t, p, siblingSource{}), pipeline.WithStrict(tt.runStrict)),
				Analysis:      analysis,
			}); err != nil {
				t.Fatalf("RunCVEWatch: %v", err)
			}
			stored := store.state.Report
			carried := otherModeRows(stored)
			if tt.storedStrict == tt.runStrict {
				if len(carried) != 3 {
					t.Errorf("same-mode run kept %d of the stored 3 rows: %+v", len(carried), stored.Advisories)
				}
				return
			}
			if got, want := stored.ModeOf(), strictnessName(tt.runStrict); got != want {
				t.Fatalf("stored mode = %s, want %s", got, want)
			}
			if len(carried) != 0 {
				t.Errorf("state stored as %s carries rows reached under the other mode: %+v", stored.ModeOf(), carried)
			}
			if tt.stopAt == 0 {
				for _, id := range []string{"GO-S-1", "GO-OUT-1"} {
					if rows := rowsByID(stored)[id]; len(rows) != 2 {
						t.Errorf("rows for %s = %+v, want the primary and the sibling assessed again", id, rows)
					}
				}
			}
		})
	}
}
