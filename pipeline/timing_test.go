package pipeline

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestStageTimer pins that every Orchestrator run on a timed context records each stage it ran —
// summed across runs, in first-run order, including the stage that failed — and that a run without
// a timer on its context is unaffected.
func TestStageTimer(t *testing.T) {
	tests := []struct {
		name      string
		failB     bool
		runs      int
		timed     bool
		wantNames []string
		wantRuns  []int
	}{
		{name: "two clean runs", runs: 2, timed: true, wantNames: []string{"a", "b", "c"}, wantRuns: []int{2, 2, 2}},
		{name: "failing stage is timed, later stages are not", failB: true, runs: 1, timed: true, wantNames: []string{"a", "b"}, wantRuns: []int{1, 1}},
		{name: "untimed context", runs: 1, timed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timer := NewStageTimer()
			ctx := context.Background()
			if tt.timed {
				ctx = WithStageTimer(ctx, timer)
			}
			cases := assessment.NewMemStore()
			var ran []string
			orch := NewOrchestrator(cases, artifact.NewMemStore(), []Stage{
				fakeStage{name: "a", status: assessment.StatusInventory, ran: &ran},
				fakeStage{name: "b", status: assessment.StatusAnalysis, fail: tt.failB, ran: &ran},
				fakeStage{name: "c", status: statusExtra, ran: &ran},
			})
			for i := 0; i < tt.runs; i++ {
				_ = orch.Run(ctx, newRunCase(t, cases).ID)
			}
			if len(ran) == 0 {
				t.Fatal("no stage ran")
			}
			var names []string
			var runs []int
			for _, st := range timer.Stages() {
				names = append(names, st.Stage)
				runs = append(runs, st.Runs)
				if st.Total < 0 {
					t.Errorf("stage %s total = %v", st.Stage, st.Total)
				}
			}
			if !reflect.DeepEqual(names, tt.wantNames) || !reflect.DeepEqual(runs, tt.wantRuns) {
				t.Errorf("stages = %v runs = %v, want %v %v", names, runs, tt.wantNames, tt.wantRuns)
			}
		})
	}
}
