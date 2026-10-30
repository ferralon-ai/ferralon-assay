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
// The GitHub-tiered sinks (job summary, PR comment, Issue, SARIF, Pages) live in
// resultsink/github as adapters over this same interface and deliberately do NOT
// live here — keeping this package free of any platform specifics.
package resultsink

import (
	"context"
	"time"

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
	// DependencyFetch is what the run's dependency code fetch needs from the operator, one entry
	// per registry: a refused token, a token the run did not have, a held or stalled cursor. It
	// names registries, which Report never does, so only a surface the repository's operators read
	// (the job summary) renders it. Nil when the fetch needs nothing.
	DependencyFetch []DependencyFetchNote
}

// Dependency fetch outcomes, as DependencyFetchNote.Outcome.
const (
	// DependencyFetchCredentialRejected is a registry that refused a token the run sent. The run
	// fails.
	DependencyFetchCredentialRejected = "credential_rejected"
	// DependencyFetchStalled is a registry whose cve-watch hold has lasted long enough to fail the
	// run.
	DependencyFetchStalled = "dependency_fetch_stalled"
	// DependencyFetchHeld is a registry that served nothing on a cve-watch run and held its
	// advisory cursor.
	DependencyFetchHeld = "held"
	// DependencyFetchMissingCredential is a registry that asked for a token the run did not have.
	DependencyFetchMissingCredential = "missing_credential"
)

// DependencyFetchNote is one registry's dependency fetch outcome for the operator.
type DependencyFetchNote struct {
	// Registry is the registry's base URL.
	Registry string
	// Outcome is one of the DependencyFetch constants.
	Outcome string
	// Package is the package whose token was refused, for DependencyFetchCredentialRejected.
	Package string
	// HeldRuns and Since are the hold, for DependencyFetchHeld and DependencyFetchStalled.
	HeldRuns int
	Since    time.Time
	// Hint is what the operator can do about it, in a sentence.
	Hint string
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
