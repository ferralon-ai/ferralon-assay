package trigger

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_OwnFixCommitUnanswered pins the kubeedge shape of GO-2022-0507: an advisory on the
// scanned module itself, fixed at releases the unversioned checkout cannot be placed against, whose
// fix commit only a full history could find, reached on a real path from a shallow checkout. The
// row is held as own_release_version_unknown with the path kept and the remedy named. A full history
// that lacks the fix leaves no unanswered commit, so the path stays a reachable_candidate, as it does
// for a versioned project and for a dependency's advisory.
func TestFinding_OwnFixCommitUnanswered(t *testing.T) {
	const fix = "1f3c2b0d9e8a7f6b5c4d3e2f1a0b9c8d7e6f5a4b"
	advisory := map[string]any{"purl": "pkg:golang/github.com/kubeedge/kubeedge", "affected_ranges": []map[string]string{{"upper_exclusive": "1.9.4"}}}
	cases := []struct {
		name       string
		inv        map[string]any
		unanswered string
		pkg        *report.Package
		want       report.Verdict
	}{
		{"shallow: the fix commit went unanswered", map[string]any{"root": true}, fix, nil, report.VerdictUndetermined},
		{"full history without the fix", map[string]any{"root": true}, "", nil, report.VerdictReachableCandidate},
		{"a versioned project", map[string]any{"root": true, "resolved_version": "1.9.0"}, fix,
			&report.Package{Ecosystem: "Go", Name: "github.com/kubeedge/kubeedge", Version: "1.9.0", Root: true}, report.VerdictReachableCandidate},
		{"a dependency's advisory", map[string]any{}, fix, nil, report.VerdictReachableCandidate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, aid := seedRangeCandidate(t, advisory, tc.inv)
			putJSON(t, store, aid, artifact.TypeDiscovery, pipeline.DisqualResult{FixCommitUnanswered: tc.unanswered})
			f := finding(store, aid, report.Advisory{ID: "GO-2022-0507", Source: "osv"}, tc.pkg)
			if f.Verdict != tc.want {
				t.Fatalf("verdict = %s/%q, want %s (%s)", f.Verdict, f.UndeterminedReason, tc.want, f.Evidence.Detail)
			}
			if len(f.Evidence.CallPath) == 0 || f.Evidence.ReachablePath == "" {
				t.Fatalf("the path was not kept as evidence: %+v", f.Evidence)
			}
			if tc.want != report.VerdictUndetermined {
				return
			}
			if f.UndeterminedReason != report.ReasonOwnReleaseVersionUnknown {
				t.Fatalf("reason = %q, want %s", f.UndeterminedReason, report.ReasonOwnReleaseVersionUnknown)
			}
			for _, want := range []string{fix[:12], "fetch-depth: 0"} {
				if !strings.Contains(f.Evidence.Detail, want) {
					t.Errorf("detail does not name %q: %s", want, f.Evidence.Detail)
				}
			}
			if f.Evidence.SymbolConfidence != "" || f.Evidence.ExploitPreconditions != nil || f.Evidence.GuardSufficiency != nil || f.Evidence.Grade != "" {
				t.Errorf("candidate-only annotations kept on a held row: %+v", f.Evidence)
			}
			if note, owes := limitNoteFor(f); !owes || !reflect.DeepEqual(note, report.PartialityNote{Reason: report.ReasonOwnReleaseVersionUnknown}) {
				t.Errorf("note = %+v, %v; want an unscoped %s note", note, owes, report.ReasonOwnReleaseVersionUnknown)
			}
		})
	}
}
