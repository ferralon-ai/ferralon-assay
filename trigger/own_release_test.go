package trigger

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_OwnReleaseVersionUnknown pins the kubeedge shape of GO-2022-0500 and its siblings: an
// advisory on the scanned module itself, whose ranges name the module's own releases and carry no
// fix commit, in a checkout whose own release version was not established. The row is held for
// that missing version, whatever steps beside it also did not run. A row whose version is known, or
// whose advisory is on a dependency, keeps the reason it had. The held row owes a scan-level note
// naming the missing version, which no other limit states, scoped to no ecosystem since it names no
// package.
func TestFinding_OwnReleaseVersionUnknown(t *testing.T) {
	kubeedge := plugin.Partial(plugin.PartialReasonAdvisoryUnknownToAnalyzer, plugin.PartialReasonPluginLoad, plugin.PartialReasonCgo)
	cases := []struct {
		name string
		inv  map[string]any
		part plugin.Partiality
		want string
	}{
		{"own advisory, no version, steps did not run", map[string]any{"root": true}, kubeedge, report.ReasonOwnReleaseVersionUnknown},
		{"own advisory, no version, analyzer silent alone", map[string]any{"root": true},
			plugin.Partial(plugin.PartialReasonAdvisoryUnknownToAnalyzer), report.ReasonOwnReleaseVersionUnknown},
		{"own advisory, no version, nothing else held", map[string]any{"root": true}, plugin.Complete(), report.ReasonOwnReleaseVersionUnknown},
		{"own advisory, version known", map[string]any{"root": true, "resolved_version": "1.9.0"}, kubeedge, report.ReasonAnalysisDidNotRun},
		{"a dependency's advisory, no version", map[string]any{}, kubeedge, report.ReasonAnalysisDidNotRun},
		{"a dependency's advisory, no version, nothing else held", map[string]any{}, plugin.Complete(), report.ReasonPackageVersionUnresolved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			const aid = "own"
			tc.inv["partiality_flags"] = []string{}
			putJSON(t, store, aid, artifact.TypeInventory, tc.inv)
			putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{"purl": "pkg:golang/github.com/kubeedge/kubeedge"})
			cg := plugin.CallGraphResult{Partiality: plugin.Complete(), Edges: []plugin.CallEdge{depEdge("main", "lib")}}
			seedReachArtifact(t, store, aid, cg, plugin.ReachabilityResult{Partiality: tc.part})
			putJSON(t, store, aid, artifact.TypeExposureFootprint, artifact.ExposureFootprintPayload{PartialityFlags: tc.part.Reasons})

			var pkg *report.Package
			if v, ok := tc.inv["resolved_version"].(string); ok {
				pkg = &report.Package{Ecosystem: "Go", Name: "github.com/kubeedge/kubeedge", Version: v,
					PURL: "pkg:golang/github.com/kubeedge/kubeedge@" + v, Root: true}
			}
			f := finding(store, aid, report.Advisory{ID: "GO-2022-0500", Source: "osv"}, pkg)
			if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != tc.want {
				t.Fatalf("got %s/%q, want undetermined/%q (%s)", f.Verdict, f.UndeterminedReason, tc.want, f.Evidence.Detail)
			}
			note, owes := limitNoteFor(f)
			switch tc.want {
			case report.ReasonOwnReleaseVersionUnknown, report.ReasonPackageVersionUnresolved:
				if !owes || !reflect.DeepEqual(note, report.PartialityNote{Reason: tc.want}) {
					t.Errorf("note = %+v, %v; want an unscoped %s note", note, owes, tc.want)
				}
			default:
				if owes {
					t.Errorf("note = %+v; want none: the scan's own limits carry %s", note, tc.want)
				}
			}
		})
	}
}
