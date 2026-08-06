package selfcleanup

import (
	"context"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// CheckConfig configures one post-scan revoke check. It is assembled from the run
// environment by the caller (cmd/ferralon-assay). Store and Ingest are required; the
// actuator is built lazily (only when the threshold is reached) via NewActuator so a
// normal run wires no git/gh surface.
type CheckConfig struct {
	// Store is the durable StateStore holding the consecutive-revoke counter. The
	// check reads it, folds the ingest Outcome in, and writes it back when it changed.
	Store statestore.StateStore
	// Ingest is the configured ingest client (URL + OIDC token + trusted key).
	Ingest IngestClient
	// Beacon is the payload to POST (org/repo/commit + optional rescan metadata).
	Beacon BeaconRequest
	// NewActuator constructs the Actuator to fire when the threshold is reached. It is
	// a field (not a hardcoded NewGitActuator call) so tests inject a mock. When nil,
	// the threshold path is a no-op that still reports it would have actuated.
	NewActuator func() Actuator
}

// CheckResult reports what one revoke check did, for the run summary / logging.
type CheckResult struct {
	Outcome  Outcome
	Count    int  // the counter value after applying Outcome
	Actuated bool // the ladder fired this run
	Rung     Rung // which rung succeeded (when Actuated)
}

// RunCheck performs one post-scan revoke check: POST the beacon, classify the
// response, fold it into the persisted consecutive-revoke counter, and — only when
// the counter reaches the N=2 threshold — run the actuation ladder.
//
// It is fail-safe by construction: a transport error or any non-verified response is
// OutcomeTransient (counts nothing), and a missing trusted key makes every 410
// transient. It returns an error only for a genuine fault (state I/O, marshal); an
// actuation error is carried on the result's Rung but does not fail the run — the
// customer's build must not break because cleanup hit an API hiccup.
func RunCheck(ctx context.Context, cfg CheckConfig) (CheckResult, error) {
	outcome, _, err := cfg.Ingest.Beacon(ctx, cfg.Beacon)
	if err != nil {
		return CheckResult{}, fmt.Errorf("selfcleanup: beacon: %w", err)
	}

	st, err := cfg.Store.Read(ctx)
	if err == statestore.ErrNotFound {
		st = &statestore.State{}
	} else if err != nil {
		return CheckResult{Outcome: outcome}, fmt.Errorf("selfcleanup: read state: %w", err)
	}

	next, changed := applyOutcome(st.RevokeCount, outcome)
	if changed {
		st.RevokeCount = next
		if _, werr := cfg.Store.Write(ctx, st); werr != nil {
			return CheckResult{Outcome: outcome, Count: next}, fmt.Errorf("selfcleanup: persist counter: %w", werr)
		}
	}

	res := CheckResult{Outcome: outcome, Count: next}
	if !shouldActuate(next) {
		return res, nil
	}

	res.Actuated = true
	if cfg.NewActuator == nil {
		return res, nil
	}
	rung, aerr := Actuate(ctx, cfg.NewActuator())
	res.Rung = rung
	if aerr != nil {
		// Surface for logging via the returned error, but the caller treats the run as
		// non-fatal (self-cleanup best-effort).
		return res, fmt.Errorf("selfcleanup: actuation %s: %w", rung, aerr)
	}
	return res, nil
}
