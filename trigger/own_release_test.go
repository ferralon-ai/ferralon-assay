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
		name    string
		inv     map[string]any
		pkgless bool
		part    plugin.Partiality
		want    string
	}{
		{"own advisory, no version, steps did not run", map[string]any{"root": true}, false, kubeedge, report.ReasonOwnReleaseVersionUnknown},
		{"own advisory, no version, analyzer silent alone", map[string]any{"root": true}, false,
			plugin.Partial(plugin.PartialReasonAdvisoryUnknownToAnalyzer), report.ReasonOwnReleaseVersionUnknown},
		{"own advisory, no version, nothing else held", map[string]any{"root": true}, false, plugin.Complete(), report.ReasonOwnReleaseVersionUnknown},
		{"own advisory, version known", map[string]any{"root": true, "resolved_version": "1.9.0"}, false, kubeedge, report.ReasonAnalysisDidNotRun},
		{"own advisory, version known, row without a package", map[string]any{"root": true, "resolved_version": "1.9.0"}, true, kubeedge, report.ReasonAnalysisDidNotRun},
		{"own advisory, no project version, row with a package", map[string]any{"root": true, "pkg_version": "1.9.0"}, false, kubeedge, report.ReasonAnalysisDidNotRun},
		{"a dependency's advisory, no version", map[string]any{}, false, kubeedge, report.ReasonAnalysisDidNotRun},
		{"a dependency's advisory, no version, nothing else held", map[string]any{}, false, plugin.Complete(), report.ReasonPackageVersionUnresolved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgVersion, _ := tc.inv["pkg_version"].(string)
			delete(tc.inv, "pkg_version")
			store := artifact.NewMemStore()
			const aid = "own"
			tc.inv["partiality_flags"] = []string{}
			putJSON(t, store, aid, artifact.TypeInventory, tc.inv)
			putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{"purl": "pkg:golang/github.com/kubeedge/kubeedge"})
			cg := plugin.CallGraphResult{Partiality: plugin.Complete(), Edges: []plugin.CallEdge{depEdge("main", "lib")}}
			seedReachArtifact(t, store, aid, cg, plugin.ReachabilityResult{Partiality: tc.part})
			putJSON(t, store, aid, artifact.TypeExposureFootprint, artifact.ExposureFootprintPayload{PartialityFlags: tc.part.Reasons})

			var pkg *report.Package
			v, ok := tc.inv["resolved_version"].(string)
			if pkgVersion != "" {
				v, ok = pkgVersion, true
			}
			if ok && !tc.pkgless {
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

// TestFinding_OwnReleaseCandidateSaysVersionUnresolved pins that a reachable candidate on the scanned
// project's own code, in a checkout whose release version was not established, stays a candidate and
// says the version is unresolved. A versioned project and a dependency's advisory carry no such detail.
func TestFinding_OwnReleaseCandidateSaysVersionUnresolved(t *testing.T) {
	advisory := map[string]any{"purl": "pkg:golang/github.com/kubeedge/kubeedge", "affected_ranges": []map[string]string{{"upper_exclusive": "1.9.4"}}}
	cases := []struct {
		name       string
		inv        map[string]any
		pkg        *report.Package
		wantDetail string
	}{
		{"own advisory, no version", map[string]any{"root": true}, nil, ownReleaseCandidateDetail},
		{"own advisory, version known", map[string]any{"root": true, "resolved_version": "1.9.0"},
			&report.Package{Ecosystem: "Go", Name: "github.com/kubeedge/kubeedge", Version: "1.9.0", Root: true}, ""},
		// A row with a package names the version it was placed at, so it carries no own-release
		// sentence, as on the hold path.
		{"own advisory, no project version, row with a package", map[string]any{"root": true},
			&report.Package{Ecosystem: "Go", Name: "github.com/kubeedge/kubeedge", Version: "v0.0.0-20240101000000-b1a36daf1737", Root: true}, ""},
		{"a dependency's advisory", map[string]any{}, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, aid := seedRangeCandidate(t, advisory, tc.inv)
			f := finding(store, aid, report.Advisory{ID: "GO-2022-0500", Source: "osv"}, tc.pkg)
			if f.Verdict != report.VerdictReachableCandidate {
				t.Fatalf("verdict = %s/%q, want reachable_candidate", f.Verdict, f.UndeterminedReason)
			}
			if f.Evidence.Detail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", f.Evidence.Detail, tc.wantDetail)
			}
		})
	}
}
