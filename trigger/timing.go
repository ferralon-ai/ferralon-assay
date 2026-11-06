package trigger

import (
	"context"
	"time"
)

type timingKey struct{}

// WithTiming returns ctx carrying observe, which a run given it as its analysis context calls with
// how long the codebase inventory ("inventory") and each advisory's assessment ("advisory") took.
func WithTiming(ctx context.Context, observe func(phase string, d time.Duration)) context.Context {
	return context.WithValue(ctx, timingKey{}, observe)
}

func observePhase(ctx context.Context, phase string, start time.Time) {
	if observe, ok := ctx.Value(timingKey{}).(func(string, time.Duration)); ok {
		observe(phase, time.Since(start))
	}
}

type advisoryTimingKey struct{}

// WithAdvisoryTiming returns ctx carrying observe, which a run given it as its analysis context calls
// with the id and duration of each advisory's assessment, so a caller can name the slow ones. It is
// called alongside the "advisory" phase of WithTiming, under the same rule: only for an assessment
// that finished before the scan stopped.
func WithAdvisoryTiming(ctx context.Context, observe func(advisoryID string, d time.Duration)) context.Context {
	return context.WithValue(ctx, advisoryTimingKey{}, observe)
}

func observeAdvisory(ctx context.Context, advisoryID string, start time.Time) {
	if observe, ok := ctx.Value(advisoryTimingKey{}).(func(string, time.Duration)); ok {
		observe(advisoryID, time.Since(start))
	}
}
