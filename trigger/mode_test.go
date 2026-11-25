package trigger

import (
	"context"
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
