package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_OwnAdvisoryOnPartialRun: the scanned module's own advisory, held because its version
// is not established and the lane answered from a partial run, is undetermined and says so. The
// same row without the partial run, or with a version, keeps the reason's general detail.
func TestFinding_OwnAdvisoryOnPartialRun(t *testing.T) {
	unversioned := plugin.Partial(plugin.PartialReasonToolFailure, plugin.PartialReasonPartialRunUnversioned)
	cases := []struct {
		name       string
		inv        map[string]any
		part       plugin.Partiality
		wantDetail string
	}{
		{name: "own advisory, no version, partial run", inv: map[string]any{"root": true}, part: unversioned, wantDetail: ownAdvisoryPartialRunDetail},
		{name: "own advisory, no version, another tool failure", inv: map[string]any{"root": true}, part: plugin.Partial(plugin.PartialReasonToolFailure)},
		{name: "own advisory, version known, partial run", inv: map[string]any{"root": true, "resolved_version": "1.4.0"}, part: unversioned},
		{name: "a dependency's advisory, partial run", inv: map[string]any{}, part: unversioned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			const aid = "own"
			tc.inv["partiality_flags"] = tc.part.Reasons
			putJSON(t, store, aid, artifact.TypeInventory, tc.inv)
			putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{"purl": "pkg:golang/example.com/app"})
			cg := plugin.CallGraphResult{Partiality: plugin.Complete(), Edges: []plugin.CallEdge{depEdge("main", "lib")}}
			seedReachArtifact(t, store, aid, cg, plugin.ReachabilityResult{Partiality: tc.part})

			f := finding(store, aid, report.Advisory{ID: "GHSA-own", Source: "osv"}, nil)
			if f.Verdict != report.VerdictUndetermined {
				t.Fatalf("verdict = %s, want undetermined", f.Verdict)
			}
			want := tc.wantDetail
			if want == "" {
				want = report.UndeterminedDetail(f.UndeterminedReason)
			}
			if f.Evidence.Detail != want {
				t.Fatalf("detail = %q, want %q (reason %s)", f.Evidence.Detail, want, f.UndeterminedReason)
			}
			if tc.wantDetail != "" && f.UndeterminedReason != report.ReasonOwnReleaseVersionUnknown {
				t.Errorf("reason = %q, want %s", f.UndeterminedReason, report.ReasonOwnReleaseVersionUnknown)
			}
		})
	}
}
