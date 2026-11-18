package trigger

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const pluginCgoOffScope = "holds for CGO_ENABLED=0, where the plugin.Open call the program reaches loads nothing; a build with cgo on was not checked"

// TestFinding_GoPluginLoadCgoOff: plugin_load:cgo_off beside a kept refutation clears into
// not_exploitable with the cgo scope stated. Without a refutation, beside another limit, or as plain
// plugin_load, the row stays undetermined.
func TestFinding_GoPluginLoadCgoOff(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*groundsFixture)
		wantVerdict report.Verdict
		wantReason  string
	}{
		{
			name:        "beside a kept refutation it clears, with the scope text",
			mutate:      func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonPluginLoadCgoOff} },
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "beside the build-constraint limit and a kept refutation it clears",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonPluginLoadCgoOff, plugin.PartialReasonExcludedFilesBuildConstraint}
			},
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "without a refutation it stays undetermined",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonPluginLoadCgoOff}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name:        "plugin_load beside a kept refutation stays undetermined",
			mutate:      func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonPluginLoad} },
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "beside a step that did not run it stays undetermined",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonPluginLoadCgoOff, plugin.PartialReasonToolFailure}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			fx.reach.Refutation.Detail += "; " + pluginCgoOffScope
			tc.mutate(&fx)
			f := fx.finding(t)
			if f.Verdict != tc.wantVerdict || f.UndeterminedReason != tc.wantReason {
				t.Fatalf("got %s/%q, want %s/%q", f.Verdict, f.UndeterminedReason, tc.wantVerdict, tc.wantReason)
			}
			if tc.wantVerdict == report.VerdictNotExploitable && !strings.Contains(f.Evidence.Detail, pluginCgoOffScope) {
				t.Errorf("detail = %q, want it to state the scope %q", f.Evidence.Detail, pluginCgoOffScope)
			}
		})
	}
}
