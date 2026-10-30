package pipeline

import (
	"context"
	"sync"
	"time"
)

// StageTimer accumulates how long each pipeline stage ran, summed over every assessment run on a
// context that carries it (see WithStageTimer). It is safe for concurrent use.
type StageTimer struct {
	mu     sync.Mutex
	order  []string
	totals map[string]*StageTiming
}

// StageTiming is one stage's accumulated wall time.
type StageTiming struct {
	Stage string
	Runs  int
	Total time.Duration
}

// NewStageTimer returns an empty StageTimer.
func NewStageTimer() *StageTimer {
	return &StageTimer{totals: map[string]*StageTiming{}}
}

func (t *StageTimer) record(stage string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.totals[stage]
	if !ok {
		st = &StageTiming{Stage: stage}
		t.totals[stage] = st
		t.order = append(t.order, stage)
	}
	st.Runs++
	st.Total += d
}

// Stages returns the accumulated timings in the order each stage first ran.
func (t *StageTimer) Stages() []StageTiming {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]StageTiming, 0, len(t.order))
	for _, name := range t.order {
		out = append(out, *t.totals[name])
	}
	return out
}

type stageTimerKey struct{}

// WithStageTimer returns a context whose Orchestrator runs record every stage's duration into t.
// The context is the carrier because it already reaches Orchestrator.Run from every run mode, so
// timing needs no change to how stages are assembled or how a run is requested.
func WithStageTimer(ctx context.Context, t *StageTimer) context.Context {
	return context.WithValue(ctx, stageTimerKey{}, t)
}

func stageTimerFrom(ctx context.Context) *StageTimer {
	t, _ := ctx.Value(stageTimerKey{}).(*StageTimer)
	return t
}
