// noop.go — the safe-default ResultSink that discards everything.
package resultsink

import "context"

// Noop is a ResultSink that accepts and discards every Result. It is the safe
// default when no surface is wired: a run still completes, no artifacts are
// published, and no error is returned.
type Noop struct{}

// Publish discards res and returns nil.
func (Noop) Publish(_ context.Context, _ Result) error { return nil }

// NewNoop returns a Noop sink. Provided for symmetry with NewLocal so callers can
// select a sink uniformly.
func NewNoop() Noop { return Noop{} }
