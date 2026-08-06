// Package statestore persists the ferralon-assay tool's durable per-repo state at a
// git ref. The state is the substrate the run triggers (baseline / PR-inherit /
// scheduled CVE-watch) and the operator CLI read and write: it carries the last
// canonical Report, the resolved SBOM, the advisory cursor, and an append-only log
// of OpenVEX statements.
//
// # Why a git ref
//
// The state travels with the repository — no external database, no separate
// storage account — and is naturally distributed and content-addressed. The
// default implementation writes an orphan ref ("refs/assay/state") whose tree is
// file-granular and content-addressed: an unchanged file reuses its existing blob
// SHA and produces ZERO new git objects. This is what makes a CVE-watch heartbeat
// (cursor bump only) cheap — only the changed cursor blob is written.
//
// # CAS (compare-and-swap)
//
// State is updated with a fast-forward-only compare-and-swap: a writer reads the
// current state (capturing the ref's commit SHA), computes the new state, and
// commits it only if the ref still points at the SHA it read. A race-loser whose
// expected SHA is stale re-reads, MERGES its intent onto the winner's state
// (Merge), and retries with bounded backoff. This is the portable contract; the
// GitHub Refs-API CAS path (Phase 3) is an adapter over this same interface
// (PATCH .../git/refs with force=false expressing the FF-only update).
//
// # Ref portability
//
// Custom refs (refs/assay/*) are not portable across all hosts (Gerrit / GitLab /
// Azure DevOps deny or restrict them). The Config exposes Ref plus a load-bearing
// Fallback ("refs/heads/assay/state", a hidden branch) so an adapter can cascade
// to the fallback when the host rejects the custom namespace. See the brain note
// "custom-ref-statestore-portability".
package statestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// DefaultRef is the orphan ref the default implementation writes. It is invisible
// to branch lists and default CI triggers on hosts that accept custom refs.
const DefaultRef = "refs/" + brand.RefNamespace + "/state"

// FallbackRef is the load-bearing hidden-branch fallback used when a host rejects
// the custom DefaultRef namespace (Gerrit / GitLab / Azure DevOps). It is a normal
// branch ref, so it is accepted everywhere, at the cost of being visible in branch
// lists.
const FallbackRef = "refs/heads/" + brand.RefNamespace + "/state"

// File names inside the state tree. They are content-addressed individually: an
// unchanged file's blob SHA is reused, so writing only the cursor (a heartbeat)
// produces exactly one new blob and one new tree+commit, never new report/sbom/vex
// objects.
const (
	fileReport = "report.json"
	fileSBOM   = "sbom.json"
	fileCursor = "cursor"
	fileVEXLog = "vex.log"
	// fileRevoke holds the consecutive-signed-revoke counter (a plain base-10
	// integer, no newline sensitivity). It is written only by the self-cleanup
	// revoke check (selfcleanup package) and is omitted from the tree while zero, so
	// a repo that never sees a signed revoke produces no revoke blob — preserving the
	// zero-new-objects heartbeat guarantee.
	fileRevoke = "revoke"
)

// ErrNotFound is returned by Read when the state ref does not yet exist (a fresh
// repository with no baseline run). Callers treat it as "no prior state".
var ErrNotFound = errors.New("statestore: no state at ref")

// ErrConflict is returned by Write when the CAS fails because the ref moved since
// the State was Read (a concurrent writer won the race). The default Store retries
// internally with Merge + backoff and only surfaces ErrConflict when retries are
// exhausted.
var ErrConflict = errors.New("statestore: compare-and-swap conflict (ref moved)")

// decodeReport decodes a stored report.json and UPGRADES it to the current schema. It is the
// single migration boundary for persisted state: every StateStore implementation reads report.json
// through here, so nothing above the store ever sees an older schema version, and every consumer
// (triggers, projectors, the CLI, the merge rule) can assume the current one.
//
// Readers upgrade on read, and no separate rewrite pass exists: a pre-bump ref keeps its stored
// bytes until a run writes state for its own reasons, at which point the upgraded form is what gets
// committed. An unrecognized schema_version is an error rather than a best-effort decode — the ref
// may have been written by a newer tool whose field meanings this code does not know, and a report
// is a verdict document, so guessing is the one thing a reader must not do.
func decodeReport(b []byte) (*report.Report, error) {
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("statestore: decode %s: %w", fileReport, err)
	}
	upgraded, err := report.Upgrade(r)
	if err != nil {
		return nil, fmt.Errorf("statestore: %s: %w", fileReport, err)
	}
	// Validate at the boundary, not later. A stored report is a FOREIGN document — written by
	// another version of this tool, or by something else entirely — and the only alternative to
	// checking it here is discovering the problem at the next BuildValidated() on a reanalyze
	// path, arbitrarily far from the ref that actually holds the bad bytes. Refusing to interpret
	// a malformed verdict document is the same reader rule Upgrade applies to an unrecognized
	// schema_version.
	if err := upgraded.Validate(); err != nil {
		return nil, fmt.Errorf("statestore: %s: %w", fileReport, err)
	}
	return &upgraded, nil
}

// State is the durable per-repo state read from / written to the ref. It is the
// in-memory projection of the state tree's four files. CommitSHA is the CAS token:
// it records the commit the State was read from; Write uses it to detect a moved
// ref. A State built fresh (no prior Read) has an empty CommitSHA, which Write
// treats as "create the ref if it does not exist".
type State struct {
	// Report is the canonical Report (report.json). It is the last full scan result.
	// nil for a never-written state.
	Report *report.Report
	// SBOM is the resolved dependency set (sbom.json), stored separately from the
	// Report so a CVE-watch heartbeat can read it without unmarshalling the whole
	// Report. It mirrors Report.SBOM when both are present.
	SBOM report.SBOM
	// Cursor is the advisory cursor (cursor) — the CVE-watch position. A scheduled
	// run diffs OSV.dev results against this to decide heartbeat vs earnest run.
	Cursor string
	// VEXLog is the append-only log of OpenVEX statements (vex.log, one JSON object
	// per line / NDJSON). Each element is an opaque, already-projected OpenVEX
	// statement; the store does not interpret it, keeping the store decoupled from
	// the projection grammar. New statements are appended; the log is never rewritten
	// on a normal write.
	VEXLog []json.RawMessage
	// RevokeCount is the number of CONSECUTIVE cryptographically-signed install-revoke
	// responses the self-cleanup revoke check has observed on the ingest POST. A signed
	// revoke increments it; a signed OK (active install) resets it to 0; a transient
	// error (unsigned 4xx/5xx/network) leaves it unchanged. The self-cleanup actuator
	// fires when it reaches the confirmation threshold (N=2). Zero for a state that has
	// never seen a revoke (the file is then absent from the tree).
	RevokeCount int
	// CommitSHA is the commit the State was read from — the CAS expected-old token.
	// Empty for a freshly constructed State (signals create-if-absent to Write).
	CommitSHA string
}

// StateStore reads and writes the durable per-repo state at a git ref under a
// fast-forward-only compare-and-swap. The default implementation is the
// git-orphan-ref Store (NewGitRefStore); the GitHub Refs-API adapter (Phase 3)
// implements this same interface over REST.
type StateStore interface {
	// Read returns the current State at the ref, including the CommitSHA CAS token.
	// It returns ErrNotFound when the ref does not exist yet (no baseline run).
	Read(ctx context.Context) (*State, error)

	// Write commits next as the new state under a fast-forward-only CAS against
	// next.CommitSHA. If the ref has moved since next was read, Write re-reads,
	// re-applies next's intent via Merge, and retries with bounded backoff; it
	// returns the State that was actually committed. It returns ErrConflict only when
	// the retry budget is exhausted.
	Write(ctx context.Context, next *State) (*State, error)
}
