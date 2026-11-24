package goanalysis

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestAssumePluginsSeparate: plugin_load attaches the plugin assumption to each not-imported
// refutation, the admitted one and those beside it, once; a call-path refutation, and a build where
// plugin.Open loads nothing (plugin_load:cgo_off), get none.
func TestAssumePluginsSeparate(t *testing.T) {
	notImported := plugin.Refutation{Basis: plugin.RefutationAnalyzerPackageNotImported, Package: "pkg:golang/example.com/m"}
	notReached := plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/n"}
	assumed := func(r *plugin.Refutation) bool {
		return r != nil && slices.Contains(r.Assumptions, plugin.AssumptionPluginsNotAssessed)
	}
	cases := []struct {
		name        string
		reasons     []string
		refutation  plugin.Refutation
		wantPrimary bool
		wantBeside  bool
	}{
		{"plugin_load, not imported", []string{plugin.PartialReasonPluginLoad}, notImported, true, true},
		{"plugin_load, call-path refutation", []string{plugin.PartialReasonPluginLoad}, notReached, false, true},
		{"plugin_load:cgo_off", []string{plugin.PartialReasonPluginLoadCgoOff}, notImported, false, false},
		{"no plugin load", nil, notImported, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.refutation
			in := plugin.ReachabilityResult{
				Partiality:  plugin.Partiality{Reasons: tc.reasons},
				Refutation:  &r,
				Refutations: []plugin.Refutation{notImported, notReached},
			}
			got := assumePluginsSeparate(in)
			if assumed(got.Refutation) != tc.wantPrimary {
				t.Errorf("admitted refutation assumptions = %q, want assumed=%v", got.Refutation.Assumptions, tc.wantPrimary)
			}
			if assumed(&got.Refutations[0]) != tc.wantBeside {
				t.Errorf("not-imported refutation beside: assumptions = %q, want assumed=%v", got.Refutations[0].Assumptions, tc.wantBeside)
			}
			if assumed(&got.Refutations[1]) {
				t.Errorf("call-path refutation beside got the assumption")
			}
			if len(in.Refutations[0].Assumptions) != 0 || len(r.Assumptions) != 0 {
				t.Errorf("input mutated")
			}
			if again := assumePluginsSeparate(got); got.Refutation != nil && len(again.Refutation.Assumptions) != len(got.Refutation.Assumptions) {
				t.Errorf("not idempotent: %q", again.Refutation.Assumptions)
			}
		})
	}
}
