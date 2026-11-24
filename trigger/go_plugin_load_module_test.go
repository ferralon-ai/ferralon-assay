package trigger

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_GoPluginLoadModuleLevel: plugin_load with cgo on clears a refutation resting on the
// build importing none of the advisory's vulnerable packages once it carries the plugin assumption,
// and the finding carries that assumption. A refutation resting on call paths, one without the
// assumption, or one beside another limit stays undetermined.
func TestFinding_GoPluginLoadModuleLevel(t *testing.T) {
	cases := []struct {
		name        string
		basis       string
		assume      bool
		footprint   []string
		wantVerdict report.Verdict
		wantReason  string
	}{
		{
			name:        "not imported, with the assumption, clears",
			basis:       plugin.RefutationAnalyzerPackageNotImported,
			assume:      true,
			footprint:   []string{plugin.PartialReasonPluginLoad},
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name:        "not imported, without the assumption, stays undetermined",
			basis:       plugin.RefutationAnalyzerPackageNotImported,
			footprint:   []string{plugin.PartialReasonPluginLoad},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name:        "a call-path refutation keeps withholding at package level",
			basis:       plugin.RefutationAnalyzerSymbolNotReached,
			assume:      true,
			footprint:   []string{plugin.PartialReasonPluginLoad},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name:        "beside a step that did not run it stays undetermined",
			basis:       plugin.RefutationAnalyzerPackageNotImported,
			assume:      true,
			footprint:   []string{plugin.PartialReasonPluginLoad, plugin.PartialReasonToolFailure},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			fx.reach.Refutation.Basis = tc.basis
			if tc.assume {
				fx.reach.Refutation.Assumptions = []string{plugin.AssumptionPluginsNotAssessed}
			}
			fx.footprint = tc.footprint
			f := fx.finding(t)
			if f.Verdict != tc.wantVerdict || f.UndeterminedReason != tc.wantReason {
				t.Fatalf("got %s/%q, want %s/%q", f.Verdict, f.UndeterminedReason, tc.wantVerdict, tc.wantReason)
			}
			if tc.wantVerdict == report.VerdictNotExploitable && !slices.Contains(f.Evidence.Assumptions, plugin.AssumptionPluginsNotAssessed) {
				t.Errorf("assumptions = %q, want %q", f.Evidence.Assumptions, plugin.AssumptionPluginsNotAssessed)
			}
		})
	}
}
