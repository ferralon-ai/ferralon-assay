package trigger

import (
	"context"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestBaseline_Timing: a run reports the inventory once and each assessment it ran, and no time
// for an advisory the stop kept it from starting.
func TestBaseline_Timing(t *testing.T) {
	cases := []struct {
		name       string
		stopAt     string
		advisories int
	}{
		{name: "finished", stopAt: "never", advisories: 3},
		{name: "stopped inside the second assessment", stopAt: "GO-T-2", advisories: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, analysis := stoppingOptions(t, tc.stopAt, stopAndWait)
			got := map[string]int{}
			_, err := buildBaselineReport(context.Background(), BaselineRequest{
				Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "head-sha"},
				Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
				Advisories:    cutShortCorpus,
				AssessOptions: opts,
				Analysis:      WithTiming(analysis, func(phase string, _ time.Duration) { got[phase]++ }),
			})
			if err != nil {
				t.Fatalf("buildBaselineReport: %v", err)
			}
			if got["inventory"] != 1 || got["advisory"] != tc.advisories || len(got) != 2 {
				t.Fatalf("phases observed = %v, want inventory 1 and advisory %d", got, tc.advisories)
			}
		})
	}
}
