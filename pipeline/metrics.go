// internal/pipeline/metrics.go
//
// The business counter for the Assess pipeline: tegron.scan.count, incremented
// once per Orchestrator.Run (orchestrator.go). Constructed once at package init via the global
// otel.Meter(...) — the shared provider (ferralon-assay/telemetry) installs the real
// MeterProvider before this name is ever recorded against, and go.opentelemetry.io/otel's
// global package upgrades already-vended instruments to it automatically, so this works
// identically whether telemetry is enabled, disabled, or not yet configured.
package pipeline

import (
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// pipelineScope is the instrumentation scope for the instruments in this file.
const pipelineScope = "github.com/ferralon-ai/ferralon-assay/pipeline"

// scanCounter is tegron.scan.count — incremented once per Orchestrator.Run, regardless of
// whether the run's stages eventually succeed or fail (a failed scan still ran). No attributes:
// vuln_class and codebase.language would both be worth slicing on, but neither is available at
// Run's seam today — both are per-stage-local values (vulnClass in advisoryIntake.Run, language
// in codebaseInventory.Run) never persisted onto the Assessment the orchestrator holds. Adding
// either dimension means persisting it first.
var scanCounter = newInt64Counter(
	"tegron.scan.count", "{scan}",
	"Assess scan run (cost_class=billable_candidate).")

// newInt64Counter registers a Counter against the global MeterProvider. The instrument
// identifier here is a static, compile-time-known string, so a construction failure can only be
// a programming error — but telemetry must never break the boot, so this degrades to a
// discarded no-op instrument rather than panicking.
func newInt64Counter(name, unit, desc string) metric.Int64Counter {
	c, err := otel.Meter(pipelineScope).Int64Counter(name, metric.WithUnit(unit), metric.WithDescription(desc))
	if err != nil {
		log.Printf("pipeline: telemetry: register %s: %v (metric disabled)", name, err)
		c, _ = noop.Meter{}.Int64Counter(name)
	}
	return c
}
