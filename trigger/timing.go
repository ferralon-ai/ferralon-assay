package trigger

import (
	"context"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
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
// with the advisory (id and source) and duration of each advisory's assessment, so a caller can name
// the slow ones. It is called alongside the "advisory" phase of WithTiming, with the same duration,
// under the same rule: only for an assessment that finished before the scan stopped.
func WithAdvisoryTiming(ctx context.Context, observe func(advisory assessment.VulnRef, d time.Duration)) context.Context {
	return context.WithValue(ctx, advisoryTimingKey{}, observe)
}

// observeAssessed reports one finished assessment to the "advisory" phase hook and to the advisory
// hook, reading the clock once so both see the same duration.
func observeAssessed(ctx context.Context, advisory assessment.VulnRef, start time.Time) {
	d := time.Since(start)
	if observe, ok := ctx.Value(timingKey{}).(func(string, time.Duration)); ok {
		observe("advisory", d)
	}
	if observe, ok := ctx.Value(advisoryTimingKey{}).(func(assessment.VulnRef, time.Duration)); ok {
		observe(advisory, d)
	}
}
