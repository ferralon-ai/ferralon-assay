package trigger

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestBaseline_Timing: a run reports the inventory and each assessment only when it finished before
// the stop, never one the stop discarded or kept from starting.
func TestBaseline_Timing(t *testing.T) {
	cases := []struct {
		name   string
		stopAt string
		mode   stopMode
		want   map[string]int
	}{
		{name: "finished", stopAt: "never", want: map[string]int{"inventory": 1, "advisory": 3}},
		{name: "stopped inside the second assessment", stopAt: "GO-T-2", mode: stopAndWait, want: map[string]int{"inventory": 1, "advisory": 1}},
		{name: "an assessment that returns after the stop", stopAt: "GO-T-2", mode: stopAndSucceed, want: map[string]int{"inventory": 1, "advisory": 1}},
		{name: "stopped during the inventory", stopAt: "inventory", mode: stopAndWait, want: map[string]int{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, analysis := stoppingOptions(t, tc.stopAt, tc.mode)
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
			if !maps.Equal(got, tc.want) {
				t.Fatalf("phases observed = %v, want %v", got, tc.want)
			}
		})
	}
}
