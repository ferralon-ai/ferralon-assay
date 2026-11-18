package trigger

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const cgoFilesDroppedScope = "holds for CGO_ENABLED=0, which leaves the build's cgo files out; a build with cgo on was not checked"

// TestFinding_GoCgoFilesDropped: a scoped cgo:files_dropped that targets the admitted module clears
// into not_exploitable beside a kept refutation, with the cgo scope stated. Without a refutation,
// beside another limit, or as scoped cgo, the row stays undetermined.
func TestFinding_GoCgoFilesDropped(t *testing.T) {
	const xnet = "pkg:golang/golang.org/x/net"
	scoped := func(reason string) []artifact.ScopedPartialityFlag {
		return []artifact.ScopedPartialityFlag{{Reason: reason, Path: "example.com/app/native", Targets: []string{"", xnet, "pkg:golang/stdlib"}}}
	}
	cases := []struct {
		name        string
		mutate      func(*groundsFixture)
		wantVerdict report.Verdict
		wantReason  string
	}{
		{
			name:        "beside a kept refutation it clears, with the scope text",
			mutate:      func(fx *groundsFixture) { fx.scoped = scoped(plugin.PartialReasonCgoFilesDropped) },
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "beside plugin_load:cgo_off and a kept refutation it clears",
			mutate: func(fx *groundsFixture) {
				fx.scoped = scoped(plugin.PartialReasonCgoFilesDropped)
				fx.footprint = []string{plugin.PartialReasonPluginLoadCgoOff}
			},
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "beside a refutation restated as not imported it clears",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation.Basis = plugin.RefutationAnalyzerPackageNotImported
				fx.scoped = scoped(plugin.PartialReasonCgoFilesDropped)
			},
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "beside a refutation on another basis it stays undetermined",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation.Basis = plugin.RefutationPackageNotLoaded
				fx.scoped = scoped(plugin.PartialReasonCgoFilesDropped)
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "without a refutation it stays undetermined",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.scoped = scoped(plugin.PartialReasonCgoFilesDropped)
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name:        "scoped cgo beside a kept refutation stays undetermined",
			mutate:      func(fx *groundsFixture) { fx.scoped = scoped(plugin.PartialReasonCgo) },
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "beside run-wide cgo it stays undetermined",
			mutate: func(fx *groundsFixture) {
				fx.scoped = scoped(plugin.PartialReasonCgoFilesDropped)
				fx.footprint = []string{plugin.PartialReasonCgo}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			fx.reach.Refutation.Detail += "; " + cgoFilesDroppedScope
			tc.mutate(&fx)
			f := fx.finding(t)
			if f.Verdict != tc.wantVerdict || f.UndeterminedReason != tc.wantReason {
				t.Fatalf("got %s/%q, want %s/%q", f.Verdict, f.UndeterminedReason, tc.wantVerdict, tc.wantReason)
			}
			if tc.wantVerdict == report.VerdictNotExploitable && !strings.Contains(f.Evidence.Detail, cgoFilesDroppedScope) {
				t.Errorf("detail = %q, want it to state the scope %q", f.Evidence.Detail, cgoFilesDroppedScope)
			}
		})
	}
}
