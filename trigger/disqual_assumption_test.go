package trigger

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// A version-axis refute that rests on ordering an installed pseudo-version by an order that does not
// prove its revision's ancestry is not_exploitable under that stated assumption, never disqualified;
// one that rests on version order alone stays disqualified with no assumption.
func TestFinding_PseudoVersionOrderAssumption(t *testing.T) {
	const assumption = "the pinned revision 123456abcdef (v0.0.0-20220101000000-123456abcdef) contains revision 0123456789ab (the advisory's bound v0.0.0-20210101000000-0123456789ab): its pseudo-version orders later, and a pseudo-version's order does not prove ancestry"
	for _, tc := range []struct {
		name        string
		assumptions []string
		want        report.Verdict
	}{
		{"ordered by pseudo-version time", []string{assumption}, report.VerdictNotExploitable},
		{"ordinary version order", nil, report.VerdictDisqualified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			payload, err := json.Marshal(pipeline.DisqualResult{Disqualified: true, Reason: pipeline.ReasonVersionNotInRange, Assumptions: tc.assumptions})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := store.Put(&artifact.Artifact{AssessmentID: "a1", Type: artifact.TypeDiscovery, ProducedBy: "test", Payload: payload}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			f := finding(store, "a1", report.Advisory{ID: "GO-TEST-0001", Source: "osv"}, nil)
			if f.Verdict != tc.want || f.Evidence.Basis != verdict.BasisVersionNotAffected || !slices.Equal(f.Evidence.Assumptions, tc.assumptions) {
				t.Fatalf("got %s basis %q assumptions %q, want %s basis %q assumptions %q",
					f.Verdict, f.Evidence.Basis, f.Evidence.Assumptions, tc.want, verdict.BasisVersionNotAffected, tc.assumptions)
			}
			if err := report.NewBuilder(report.Subject{ResolvedCommit: "c"}).AddFinding(f).Build().Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}
