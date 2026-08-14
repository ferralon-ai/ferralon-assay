// Package symbolresolution is the measurement instrument for §4.7's symbol-resolution-rate
// metric (PLAN-221). It answers, per corpus record and per in-scope lane: did the advisory's
// vulnerable symbol resolve to a concrete symbol in its affected artifact, or — if not — WHY, in
// a closed, actionable vocabulary.
//
// # Two corpora, joined by vuln_id
//
// The metric joins two recorded datasets and counts; it executes no target code (§3
// non-negotiables). The DENOMINATOR is the advisory corpus (pipeline.AdvisoryTable — 38 records
// / 5 ecosystems, each carrying PURL + Symbols but NO codebase). The BuildDir+Category source is
// the code-fixture corpus (corpus.Fixture, vendored_repro mode → a checked-out repo). A record
// with a bound vendored_repro fixture can be measured by the {go} resolver today; a record with
// none is honestly artifact-not-indexed. That boundary is the point of the metric, not a defect.
//
// # What this package is NOT
//
// It builds no resolution engine and drives no normaliser/indexer (C7 — a rate that moved
// because this cycle changed a normaliser is confounded). Resolution is obtained by reusing
// reachcandidate.RunCase over a Case synthesised per bound record via reachcandidate.CaseFrom —
// the byte-identical production consumer path — behind an injected CaseRunner so the hermetic
// suite needs no toolchain. Steps 1-4 of the classifier (ecosystem/lane/symbol/bound) are pure
// over committed fields; only step 5 runs the resolver, and only for the buildable subset.
//
// # Honest absence (§3.1, HONEST-ABSENT)
//
// Absent ≠ empty ≠ reviewed-none-found. Every (record × in-scope lane) yields exactly one
// ResolutionOutcome — never an absent row (C1). A lane whose dependency-artifact indexer has not
// landed reports LaneUnmeasurable with a reason naming the missing input, never 0.0 (C6). No
// resolution or reason is ever fabricated.
package symbolresolution
