package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_VersionLimitsScopedToInventory: a limit on resolving the package's version holds the
// advisory as package_version_unresolved, never as a run that did not happen, and never opens a
// refutation. A version that resolved anyway, and every other axis's limits, still hold the row as
// analysis_did_not_run.
func TestFinding_VersionLimitsScopedToInventory(t *testing.T) {
	const failed = plugin.PartialReasonToolFailure
	unresolved := func(fx *groundsFixture) {
		fx.pkg = &report.Package{Ecosystem: "PyPI", Name: "PyYAML", PURL: "pkg:pypi/pyyaml"}
	}
	cases := []struct {
		name       string
		base       func() groundsFixture
		mutate     func(*groundsFixture)
		wantReason string
	}{
		{
			// The gate row: the package is declared only in a manifest the lane could not read, so
			// nothing resolves its version, and its symbols were searched without a path.
			name: "a package only an unread manifest declares",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.footprint = []string{plugin.PartialReasonDynamicDispatch, failed}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name: "the lane's refutation of a package with no version",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.reach.Refutation = refutation("pkg:pypi/pyyaml")
				fx.affected = []string{"pkg:pypi/pyyaml"}
				fx.footprint = []string{failed}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name: "no footprint: the inventory's own limits",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name: "a version resolved despite the limit",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{failed}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "another axis declared the same limit",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.footprint = []string{failed, failed}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "another axis declared another limit",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.footprint = []string{plugin.PartialReasonRelationshipUnexpressed + ":unlisted_sites", failed}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			name: "the analyzer does not know the advisory either",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.footprint = []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer, failed}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
		{
			name: "the analyzer does not know the advisory, and no version limit",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.footprint = []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer}
				fx.inventory = []string{}
			},
			wantReason: report.ReasonAdvisoryUnknownToAnalyzer,
		},
		{
			// Only a limit the footprint lists counts as removed; an inventory flag alone does not.
			name: "the analyzer does not know the advisory, and the footprint lists no version limit",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.footprint = []string{plugin.PartialReasonAdvisoryUnknownToAnalyzer}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonAdvisoryUnknownToAnalyzer,
		},
		{
			name: "a footprint that does not list the inventory's limit",
			base: yamlSearched,
			mutate: func(fx *groundsFixture) {
				unresolved(fx)
				fx.footprint = []string{plugin.PartialReasonRelationshipUnexpressed + ":unlisted_sites"}
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonAnalysisDidNotRun,
		},
		{
			// outsideBuildGrounds needs no admitted package, so the limit still holds it.
			name: "a module search with version resolution failed",
			base: gogsOutsideBuild,
			mutate: func(fx *groundsFixture) {
				fx.footprint = append(fx.footprint, failed)
				fx.inventory = []string{failed}
			},
			wantReason: report.ReasonPackageVersionUnresolved,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := tc.base()
			tc.mutate(&fx)
			f := fx.finding(t)
			if f.Verdict != report.VerdictUndetermined {
				t.Fatalf("got %s, want undetermined", f.Verdict)
			}
			if tc.wantReason != "" && f.UndeterminedReason != tc.wantReason {
				t.Fatalf("got undetermined/%q, want %q", f.UndeterminedReason, tc.wantReason)
			}
		})
	}
}
