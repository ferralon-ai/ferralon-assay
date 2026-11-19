package trigger

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_WithheldByElsewhere: a row lists scoped limits in full only while few; past that it
// carries their number in one entry per reason, so a row's list does not grow with the run's limits.
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
	count := func(reason string, n int) report.Limit { return report.Limit{Reason: reason, Others: n} }
	one := func(s artifact.ScopedPartialityFlag) report.Limit { return full([]artifact.ScopedPartialityFlag{s})[0] }
	namingN := func(n int) []artifact.ScopedPartialityFlag {
		var out []artifact.ScopedPartialityFlag
		for i := range n {
			out = append(out, artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: fmt.Sprintf("pkg:golang/example.com/c%03d", i), Targets: []string{net}})
		}
		return out
	}
	cases := []struct {
		name   string
		mutate func(*groundsFixture)
		want   []report.Limit
	}{
		{
			name: "an unversioned row under a run's worth of scoped limits lists their number",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.footprint = []string{plugin.PartialReasonCgo}
				fx.scoped = bounded(plugin.PartialReasonCgo, 324)
			},
			want: []report.Limit{{Reason: plugin.PartialReasonCgo}, count(plugin.PartialReasonCgo, 324)},
		},
		{
			name: "at the cap they are listed in full, beside a run-wide limit of the reason",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.footprint = []string{plugin.PartialReasonCgo}
				fx.scoped = bounded(plugin.PartialReasonCgo, maxLimitsElsewhere)
			},
			want: append([]report.Limit{{Reason: plugin.PartialReasonCgo}}, full(bounded(plugin.PartialReasonCgo, maxLimitsElsewhere))...),
		},
		{
			name: "one past the cap, their number",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.scoped = bounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1)
			},
			want: []report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1)},
		},
		{
			name: "a limit declared twice is counted once",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				b := bounded(plugin.PartialReasonCgo, maxLimitsElsewhere)
				fx.scoped = append(b, b...)
			},
			want: full(bounded(plugin.PartialReasonCgo, maxLimitsElsewhere)),
		},
		{
			name: "each reason is counted alone",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.scoped = append(bounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), bounded(plugin.PartialReasonCgoUnresolved, 2)...)
			},
			want: append([]report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1)}, full(bounded(plugin.PartialReasonCgoUnresolved, 2))...),
		},
		{
			name: "a limit naming the row's package stays in full beside the number",
			mutate: func(fx *groundsFixture) {
				fx.scoped = append(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), naming)
			},
			want: []report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1), one(naming)},
		},
		{
			name: "limits naming the row's package are not counted toward the cap",
			mutate: func(fx *groundsFixture) {
				fx.scoped = append(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere), naming)
			},
			want: append(full(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere)), one(naming)),
		},
		{
			name: "an unversioned row keeps the limit declared in its own package",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				own := artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: net + "@v0.1.0"}
				fx.scoped = append(bounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), own)
			},
			want: []report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1), {Reason: plugin.PartialReasonCgo, Package: net + "@v0.1.0"}},
		},
		{
			name: "a limit targeting a package inside the row's module names it",
			mutate: func(fx *groundsFixture) {
				in := artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/c", Targets: []string{net + "/html"}}
				fx.scoped = append(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), in)
			},
			want: []report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1), {Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/c", Targets: []string{net + "/html"}}},
		},
		{
			name: "a first-party limit names the root row",
			mutate: func(fx *groundsFixture) {
				fx.pkg.Root = true
				first := artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Path: "main.go"}
				fx.scoped = append(unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), first)
			},
			want: []report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1), {Reason: plugin.PartialReasonCgo, Path: "main.go"}},
		},
		{
			name: "limits that name the row and limits that do not share one number",
			mutate: func(fx *groundsFixture) {
				fx.scoped = append(namingN(maxLimitsNaming+2), unbounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1)...)
			},
			want: append(full(namingN(maxLimitsNaming)), count(plugin.PartialReasonCgo, 2+maxLimitsElsewhere+1)),
		},
		{
			name: "limits declared by path alone are counted",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				for i := range maxLimitsElsewhere + 1 {
					fx.scoped = append(fx.scoped, artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Path: fmt.Sprintf("nested%d/go.mod", i)})
				}
			},
			want: []report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1)},
		},
		{
			name: "a row with no package URL is matched by ecosystem and name",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				fx.pkg.PURL = ""
				fx.advisoryPURL = ""
				own := artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: net}
				fx.scoped = append(bounded(plugin.PartialReasonCgo, maxLimitsElsewhere+1), own)
			},
			want: []report.Limit{count(plugin.PartialReasonCgo, maxLimitsElsewhere+1), {Reason: plugin.PartialReasonCgo, Package: net}},
		},
		{
			name: "each package naming the row is listed before a second limit in any",
			mutate: func(fx *groundsFixture) {
				unversioned(fx)
				for i := range maxLimitsNaming {
					fx.scoped = append(fx.scoped, artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: net + "@v0.1.0", Path: fmt.Sprintf("f%d.go", i)})
				}
				fx.scoped = append(fx.scoped, artifact.ScopedPartialityFlag{Reason: plugin.PartialReasonCgo, Package: net + "@v0.2.0", Path: "g.go"})
			},
			want: func() []report.Limit {
				var out []report.Limit
				for i := range maxLimitsNaming - 1 {
					out = append(out, report.Limit{Reason: plugin.PartialReasonCgo, Package: net + "@v0.1.0", Path: fmt.Sprintf("f%d.go", i)})
				}
				return append(out, count(plugin.PartialReasonCgo, 1), report.Limit{Reason: plugin.PartialReasonCgo, Package: net + "@v0.2.0", Path: "g.go"})
			}(),
		},
		{
			name: "past the naming cap the rest join the number",
			mutate: func(fx *groundsFixture) {
				fx.scoped = namingN(maxLimitsNaming + 2)
			},
			want: append(full(namingN(maxLimitsNaming)), count(plugin.PartialReasonCgo, 2)),
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
