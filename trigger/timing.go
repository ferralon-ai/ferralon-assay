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
