package trigger

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const buildConstraintScope = "scope: decided for GOOS=linux GOARCH=amd64 with default build tags only, and 3 file(s) built only for other platforms or build tags may call into golang.org/x/net and were not analyzed, so other platforms were not checked"

// TestFinding_GoBuildConstraintLimit: the one limit a kept refutation carries for the scanned platform
// (excluded_files:build_constraint) is cleared into not_exploitable with its scope stated, and every
// other limit, or a result that is not a refutation, keeps what it did before.
func TestFinding_GoBuildConstraintLimit(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*groundsFixture)
		wantVerdict report.Verdict
		wantReason  string
	}{
		{
			name:        "build-constraint exclusion alone clears, with the scope text",
			mutate:      func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonExcludedFilesBuildConstraint} },
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "build-constraint exclusion clears a package the lane refuted beside another",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutations = []plugin.Refutation{*fx.reach.Refutation}
				fx.reach.Refutation = &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/first", Detail: "d"}
				fx.footprint = []string{plugin.PartialReasonExcludedFilesBuildConstraint}
			},
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "build-constraint exclusion beside unsearched methods stays withheld",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonExcludedFilesBuildConstraint, plugin.PartialReasonUnsearchedMethods}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonRefutationWithheld,
		},
		{
			name: "a kept refutation does not clear unsearched methods declared beside it",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonExcludedFilesBuildConstraint, plugin.PartialReasonUnsearchedMethods}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonRefutationWithheld,
		},
		{
			name: "linkname alone stays withheld",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonExcludedFilesLinkname}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonRefutationWithheld,
		},
		{
			name: "any other exclusion stays withheld",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonExcludedFiles}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonRefutationWithheld,
		},
		{
			name: "build-constraint exclusion without a refutation stays withheld",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.footprint = []string{plugin.PartialReasonExcludedFilesBuildConstraint}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonRefutationWithheld,
		},
		{
			name: "build-constraint exclusion beside a step that did not run stays undetermined",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonExcludedFilesBuildConstraint, plugin.PartialReasonToolFailure}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			fx.reach.Refutation.Detail += "; " + buildConstraintScope
			tc.mutate(&fx)
			f := fx.finding(t)
			if f.Verdict != tc.wantVerdict || f.UndeterminedReason != tc.wantReason {
				t.Fatalf("got %s/%q, want %s/%q", f.Verdict, f.UndeterminedReason, tc.wantVerdict, tc.wantReason)
			}
			if tc.wantVerdict == report.VerdictNotExploitable && !strings.Contains(f.Evidence.Detail, buildConstraintScope) {
				t.Errorf("detail = %q, want it to state the scope %q", f.Evidence.Detail, buildConstraintScope)
			}
		})
	}
}
