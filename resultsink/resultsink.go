// Package resultsink defines the announce-results contract — what a CI surface
// implements to publish a completed scan Report and its projections.
//
// # Role in the data plane
//
// A scan run produces a report.Report; projectors render it into OpenVEX, SARIF,
// and an inlined HTML page. A ResultSink is the seam between "the run produced
// results" and "the results are surfaced to the operator". The OSS tool calls
// Publish once per run with the Report and the rendered projections; the concrete
// sink decides where they go.
//
// # Tier boundary
//
// This package provides only portable, host-agnostic sinks:
//
//   - Noop  — a safe default that discards everything (used when no surface is wired).
//   - Local — writes the projections to a local directory (the dogfood / CLI path).
//
// The GitHub-tiered sinks (PR comments, checks, code-scanning upload, permission
// tiers) are Phase 3 adapters over this same interface and deliberately do NOT
// live here — keeping this package free of any platform specifics.
package resultsink

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// Projections carries the rendered output formats for one Report. Each field is
// the already-serialized bytes a projector produced; a nil/empty field means that
// projection was not requested for this run, and a sink should skip it rather than
// emit an empty artifact.
type Projections struct {
	// OpenVEX is the serialized OpenVEX document (projection.MarshalReportVEX).
	OpenVEX []byte
	// SARIF is the serialized SARIF 2.1.0 log (projection.MarshalReportSARIF).
	SARIF []byte
	// HTML is the self-contained, file://-safe report.html page
	// (projection.MarshalReportHTML).
	HTML []byte
}

// Result is the full payload announced for one scan run: the canonical Report
// plus its rendered projections. The Report is the source of truth; Projections
// are views a sink may surface directly.
type Result struct {
	// Report is the canonical neutral scan Report this run produced.
	Report report.Report
	// Projections are the rendered output formats for Report.
	Projections Projections
}

// ResultSink publishes a completed scan Result to a CI surface. Implementations
// MUST be safe to call exactly once per run and SHOULD be idempotent for retries.
//
// Publish returns an error only when the surface could not be written; a sink that
// intentionally discards results (Noop) returns nil.
type ResultSink interface {
	// Publish announces the Result. The context bounds any I/O the sink performs.
	Publish(ctx context.Context, res Result) error
}
