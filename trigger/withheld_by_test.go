package trigger

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_WithheldBy: an undetermined row the analysis withheld lists the limits that withheld
// it, and its detail names each. A limit the host dropped, or a scoped one that cannot reach the
// advisory's package, is not listed; a row that is not withheld lists none.
func TestFinding_WithheldBy(t *testing.T) {
	elsewhere := artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/other", Targets: []string{"pkg:golang/example.com/other"}}
	here := artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/c", Path: "bridge.go", Targets: []string{"pkg:golang/golang.org/x/net", "pkg:golang/stdlib"}}
	const versionLimit = "version_limit_under_test"
	cases := []struct {
		name       string
		mutate     func(*groundsFixture)
		wantReason string
		want       []report.Limit
	}{
		{
			name: "two run-wide limits, in the order declared",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonUnsearchedMethods, plugin.PartialReasonExcludedFilesLinkname}
			},
			wantReason: report.ReasonRefutationWithheld,
			want:       []report.Limit{{Reason: plugin.PartialReasonUnsearchedMethods}, {Reason: plugin.PartialReasonExcludedFilesLinkname}},
		},
		{
			name: "a limit the kept refutation states is dropped",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonExcludedFilesBuildConstraint, plugin.PartialReasonUnsearchedMethods}
			},
			wantReason: report.ReasonRefutationWithheld,
			want:       []report.Limit{{Reason: plugin.PartialReasonUnsearchedMethods}},
		},
		{
			name: "a scoped limit carries its place and targets; one that cannot reach the package is left out",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.scoped = []artifact.ScopedPartialityFlag{elsewhere, here}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
			want:       []report.Limit{{Reason: plugin.PartialReasonCgo, Package: here.Package, Path: here.Path, Targets: here.Targets}},
		},
		{
			name: "a scoped limit that cannot reach the package is left out wherever it is declared",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.scoped = []artifact.ScopedPartialityFlag{here, elsewhere}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
			want:       []report.Limit{{Reason: plugin.PartialReasonCgo, Package: here.Package, Path: here.Path, Targets: here.Targets}},
		},
		{
			name: "two scoped limits of one reason are both listed",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.scoped = []artifact.ScopedPartialityFlag{
					here,
					{Reason: here.Reason, Package: here.Package, Path: "other.go", Targets: here.Targets},
					{Reason: here.Reason, Package: here.Package, Path: here.Path, Targets: here.Targets[:1]},
					here,
				}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
			want: []report.Limit{
				{Reason: plugin.PartialReasonCgo, Package: here.Package, Path: here.Path, Targets: here.Targets},
				{Reason: plugin.PartialReasonCgo, Package: here.Package, Path: "other.go", Targets: here.Targets},
				{Reason: plugin.PartialReasonCgo, Package: here.Package, Path: here.Path, Targets: here.Targets[:1]},
			},
		},
		{
			name: "a limit declared twice is listed once",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonUnsearchedMethods, plugin.PartialReasonUnsearchedMethods}
				fx.scoped = []artifact.ScopedPartialityFlag{here, here}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
			want: []report.Limit{
				{Reason: plugin.PartialReasonUnsearchedMethods},
				{Reason: plugin.PartialReasonCgo, Package: here.Package, Path: here.Path, Targets: here.Targets},
			},
		},
		{
			name: "a scoped limit the kept refutation states is dropped",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonUnsearchedMethods}
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: plugin.PartialReasonExcludedFilesBuildConstraint, Package: here.Package, Path: here.Path, Targets: here.Targets}}
			},
			wantReason: report.ReasonRefutationWithheld,
			want:       []report.Limit{{Reason: plugin.PartialReasonUnsearchedMethods}},
		},
		{
			name: "a run-wide limit the unresolved version covers is dropped; its scoped namesake stays",
			mutate: func(fx *groundsFixture) {
				fx.pkg.Version = ""
				fx.reach.Refutation = nil
				fx.inventory = []string{versionLimit}
				fx.footprint = []string{versionLimit}
				fx.scoped = []artifact.ScopedPartialityFlag{{Reason: versionLimit, Package: elsewhere.Package, Path: "o.go", Targets: elsewhere.Targets}}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
			want:       []report.Limit{{Reason: versionLimit, Package: elsewhere.Package, Path: "o.go", Targets: elsewhere.Targets}},
		},
		{
			name: "a row with another reason lists none, whatever limits were kept",
			mutate: func(fx *groundsFixture) {
				fx.pkg.Version = ""
				fx.reach.Refutation = nil
				fx.inventory = []string{versionLimit}
				fx.footprint = []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer, versionLimit}
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name:   "a kept refutation with no limit lists none",
			mutate: func(fx *groundsFixture) {},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			tc.mutate(&fx)
			f := fx.finding(t)
			if f.UndeterminedReason != tc.wantReason {
				t.Fatalf("got %s/%q, want reason %q", f.Verdict, f.UndeterminedReason, tc.wantReason)
			}
			if !reflect.DeepEqual(f.WithheldBy, tc.want) {
				t.Fatalf("withheld_by = %+v, want %+v", f.WithheldBy, tc.want)
			}
			for _, l := range tc.want {
				if !strings.Contains(f.Evidence.Detail, report.LimitPhrase(l)) {
					t.Errorf("detail %q does not name %q", f.Evidence.Detail, report.LimitPhrase(l))
				}
			}
			r := report.Report{SchemaVersion: report.SchemaVersion, Advisories: []report.AdvisoryFinding{f}}
			if err := r.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
			if len(tc.want) > 0 && f.Evidence.Detail != report.WithheldDetail(f.UndeterminedReason, f.WithheldBy) {
				t.Errorf("detail = %q, want WithheldDetail of the row's limits", f.Evidence.Detail)
			}
		})
	}
}

// TestWithInventoryLimits_WithheldBy: a row an inventory limit demotes lists that limit.
func TestWithInventoryLimits_WithheldBy(t *testing.T) {
	f := report.AdvisoryFinding{
		Package: &report.Package{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", PURL: "pkg:npm/left-pad@1.0.0"},
		Verdict: report.VerdictNotExploitable,
	}
	limit := report.PartialityNote{Reason: plugin.PartialReasonToolFailure, Ecosystem: "npm", Package: "pkg:npm/other", Path: "index.js", Targets: []string{"pkg:npm/left-pad"}}
	got := withInventoryLimits(f, []report.PartialityNote{limit}, nil)
	want := []report.Limit{{Reason: limit.Reason, Package: limit.Package, Path: limit.Path, Targets: limit.Targets}}
	if got.UndeterminedReason != report.ReasonAnalysisDidNotRun || !reflect.DeepEqual(got.WithheldBy, want) {
		t.Fatalf("got %s/%q withheld_by %+v, want analysis_did_not_run and %+v", got.Verdict, got.UndeterminedReason, got.WithheldBy, want)
	}
	if got.Evidence.Detail != report.WithheldDetail(got.UndeterminedReason, want) {
		t.Errorf("detail = %q, want WithheldDetail of the limit", got.Evidence.Detail)
	}
}
