// Package ferralon holds the ResultSinks that push a completed scan to the Ferralon
// backend. Unlike the portable (resultsink) and GitHub-tier (resultsink/github) sinks,
// these are the sinks that contact Ferralon: they carry the run's OWN report to the
// Ferralon control plane at run time, under the workflow's GitHub-Actions OIDC token.
//
// The sink here is RunSnapshot: the run-snapshot PUSH counterpart to the backend's
// /runs endpoint. The push is the ONLY run-frozen source — re-reading refs/assay/state
// later is deliberately not done, because the ref moves and the run does not. It POSTs the verbatim
// tegron.report.v2 verdict layer so the backend can persist a report_runs row — the
// spine the console fleet view renders an assessment from. Absent this push a
// green field scan surfaces as "INSTALLED · NO ASSESSMENT YET".
package ferralon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// TokenSource yields the bearer credential for the push: the run's GitHub-Actions
// OIDC token (audience ferralon-ingest — the same verifier the ingest/beacon path
// uses). It is resolved at Publish time, not construction, so a token is minted only
// when a report is actually pushed. An empty return posts without an Authorization
// header (the backend then refuses with 401 — a fail-open no-op for the scan job);
// Publish logs a stderr warning in that case so a misconfigured workflow (missing
// `id-token: write`) is self-diagnosing instead of silently losing the push.
type TokenSource func(ctx context.Context) string

// httpDoer is the subset of *http.Client RunSnapshot needs; tests inject a stub.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// RunSnapshot is a ResultSink that pushes the run's tegron.report.v2 report to the
// backend run-snapshot endpoint (/runs). The run identity + provenance (owner, repo,
// run_id, ref, sha) are taken by the backend from the VERIFIED OIDC token, never the
// body, so the sink sends ONLY the report bytes — no envelope.
//
// It is FAIL-OPEN: a rejected or unreachable push NEVER fails the customer's scan job
// (Publish always returns nil, logging the problem to stderr). The live-view report_runs
// row is a durability convenience, not a gate on the scan succeeding — mirroring the
// self-cleanup beacon's posture. A run whose push is refused (e.g. no active install,
// transient outage) still completes green locally; the next default-branch run re-pushes.
type RunSnapshot struct {
	url   string
	token TokenSource
	http  httpDoer
}

// pushClient is the default HTTP client: a bounded timeout so a hung backend cannot
// stall the scan job (the push is best-effort).
var pushClient = &http.Client{Timeout: 15 * time.Second}

// NewRunSnapshot returns a RunSnapshot posting to url with token as the bearer source.
func NewRunSnapshot(url string, token TokenSource) *RunSnapshot {
	return &RunSnapshot{url: url, token: token}
}

// result is the backend's 200 outcome: the opaque repo handle + the
// echoed run_id. Decoded best-effort for the run summary; a decode failure is ignored.
type result struct {
	Handle string `json:"handle"`
	RunID  string `json:"run_id"`
}

// Publish marshals res.Report to its tegron.report.v2 JSON and POSTs it to the
// run-snapshot endpoint with Content-Type application/json and the OIDC token as a
// Bearer credential. It is fail-open: every error path logs and returns nil.
func (s *RunSnapshot) Publish(ctx context.Context, res resultsink.Result) error {
	body, err := json.Marshal(res.Report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  run-snapshot: marshal report: %v\n", err)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  run-snapshot: build request: %v\n", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != nil {
		if tok := s.token(ctx); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		} else {
			fmt.Fprintln(os.Stderr, "  run-snapshot: OIDC token unavailable (ACTIONS_ID_TOKEN_REQUEST_* not set?) — pushing unauthenticated; backend will reject. Ensure the workflow grants 'id-token: write' permission.")
		}
	}

	cl := s.http
	if cl == nil {
		cl = pushClient
	}
	resp, err := cl.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  run-snapshot: push failed (transport): %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "  run-snapshot: push rejected: HTTP %d\n", resp.StatusCode)
		return nil
	}

	var out result
	if err := json.NewDecoder(resp.Body).Decode(&out); err == nil && out.RunID != "" {
		fmt.Fprintf(os.Stdout, "  run-snapshot: report pushed (run %s)\n", out.RunID)
	} else {
		fmt.Fprintln(os.Stdout, "  run-snapshot: report pushed")
	}
	return nil
}
