package main

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

type clockStage struct{}

func (clockStage) Name() string              { return "inventory" }
func (clockStage) Status() assessment.Status { return assessment.StatusInventory }
func (clockStage) Run(context.Context, *assessment.Assessment, artifact.Store) error {
	return nil
}

// TestRunClockTimings pins that a run mode's clock reports the pipeline stages run on its context,
// and that a Report published without a clock carries no timings.
func TestRunClockTimings(t *testing.T) {
	var none *runClock
	if got := none.timings(); got != nil {
		t.Fatalf("nil clock timings = %+v, want nil", got)
	}

	ctx, clock := startRunClock(context.Background())
	cases := assessment.NewMemStore()
	orch := pipeline.NewOrchestrator(cases, artifact.NewMemStore(), []pipeline.Stage{clockStage{}})
	for i := 0; i < 3; i++ {
		c, err := cases.Create(assessment.Request{Vulnerability: assessment.VulnRef{ID: "GO-2099-0001", Source: "osv"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := orch.Run(ctx, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	got := clock.timings()
	if got == nil || got.WallSeconds <= 0 {
		t.Fatalf("timings = %+v, want a positive wall time", got)
	}
	if len(got.Stages) != 1 || got.Stages[0].Stage != "inventory" || got.Stages[0].Runs != 3 {
		t.Errorf("stages = %+v, want inventory x3", got.Stages)
	}
}
