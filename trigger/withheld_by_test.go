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
			if len(tc.want) > 0 && f.Evidence.Detail != report.WithheldDetail(f.UndeterminedReason, f.WithheldBy) {
				t.Errorf("detail = %q, want WithheldDetail of the row's limits", f.Evidence.Detail)
			}
		})
	}
}
