package trigger

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_WithheldByElsewhere: scoped limits that count against a row without naming its
// package are listed in full only while few; past that the row lists their reason once, so a row's
// list does not grow with the run's limits.
func TestFinding_WithheldByElsewhere(t *testing.T) {
	const net = "pkg:golang/golang.org/x/net"
	bounded := func(reason string, n int) []artifact.ScopedPartialityFlag {
		var out []artifact.ScopedPartialityFlag
		for i := range n {
			p := fmt.Sprintf("pkg:golang/example.com/dep%03d", i)
			out = append(out, artifact.ScopedPartialityFlag{Reason: reason, Package: p, Targets: []string{p + "/sub"}})
		}
		return out
	}
	unbounded := func(reason string, n int) []artifact.ScopedPartialityFlag {
		out := bounded(reason, n)
		for i := range out {
			out[i].Targets = nil
		}
		return out
	}
	full := func(scoped []artifact.ScopedPartialityFlag) []report.Limit {
		var out []report.Limit
		for _, s := range scoped {
			out = append(out, report.Limit{Reason: s.Reason, Package: s.Package, Path: s.Path, Targets: s.Targets})
		}
		return out
	}
	naming := artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/c", Path: "bridge.go", Targets: []string{net}}
	unversioned := func(fx *groundsFixture) {
		fx.pkg.Version = ""
		fx.reach.Refutation = nil
	}
	cases := []struct {
		name   string
		mutate func(*groundsFixture)
		want   []report.Limit
	}{
		{
			name: "an unversioned row under a run's worth of scoped limits lists the reason once",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.footprint = []string{plugin.PartialReasonCgo}
				fx.scoped = bounded(plugin.PartialReasonCgo, 324)
			},
			want: []report.Limit{{Reason: plugin.PartialReasonCgo}},
		},
		{
			name: "at the cap they are listed in full",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.scoped = bounded(plugin.PartialReasonCgo, maxLimitsElsewhere)
			},
			want: full(bounded(plugin.PartialReasonCgo, maxLimitsElsewhere)),
		},
		{
			name: "one past the cap, the reason once",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.scoped = bounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1)
			},
			want: []report.Limit{{Reason: plugin.PartialReasonCgo}},
		},
		{
			name: "each reason is counted alone",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.scoped = append(bounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), bounded(plugin.PartialReasonCgoUnresolved, 2)...)
			},
			want: append([]report.Limit{{Reason: plugin.PartialReasonCgo}}, full(bounded(plugin.PartialReasonCgoUnresolved, 2))...),
		},
		{
			name: "a limit naming the row's package stays in full beside the reason",
			mutate: func(fx *groundsFixture) {
				fx.scoped = append(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), naming)
			},
			want: []report.Limit{{Reason: plugin.PartialReasonCgo}, {Reason: naming.Reason, Package: naming.Package, Path: naming.Path, Targets: naming.Targets}},
		},
		{
			name: "limits naming the row's package are not counted toward the cap",
			mutate: func(fx *groundsFixture) {
				fx.scoped = append(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere), naming)
			},
			want: append(full(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere)), report.Limit{Reason: naming.Reason, Package: naming.Package, Path: naming.Path, Targets: naming.Targets}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			tc.mutate(&fx)
			f := fx.finding(t)
			if f.UndeterminedReason != report.ReasonAnalysisDidNotRun {
				t.Fatalf("got %s/%q, want %q", f.Verdict, f.UndeterminedReason, report.ReasonAnalysisDidNotRun)
			}
			if !reflect.DeepEqual(f.WithheldBy, tc.want) {
				t.Fatalf("withheld_by = %+v, want %+v", f.WithheldBy, tc.want)
			}
			if f.Evidence.Detail != report.WithheldDetail(f.UndeterminedReason, f.WithheldBy) {
				t.Errorf("detail = %q, want WithheldDetail of the row's limits", f.Evidence.Detail)
			}
			r := report.Report{SchemaVersion: report.SchemaVersion, Advisories: []report.AdvisoryFinding{f}}
			if err := r.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}
