package selfcleanup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
)

// Outcome is the classification of one ingest POST, from the self-cleanup counter's
// point of view. Only OutcomeRevoked (a VERIFIED signed 410) moves toward actuation;
// OutcomeActive (any 2xx — the install is live) breaks the streak; OutcomeTransient
// (unsigned/invalid 410, other 4xx/5xx, network error) is ambiguous and changes
// nothing.
type Outcome int

const (
	// OutcomeTransient — the ingest result carries no trustworthy signal. Count
	// nothing, reset nothing. Covers unsigned/invalid 410 bodies, other non-2xx
	// statuses, and transport errors.
	OutcomeTransient Outcome = iota
	// OutcomeActive — a 2xx ingest response. The App installation is live; reset the
	// consecutive-revoke counter to zero. (Reset is the safe direction — it only ever
	// DELAYS actuation, so it need not be signed.)
	OutcomeActive
	// OutcomeRevoked — an HTTP 410 with a body whose Ed25519 signature verified
	// against the baked public key AND whose org/repo match the repo we posted for.
	// Increment the counter.
	OutcomeRevoked
)

func (o Outcome) String() string {
	switch o {
	case OutcomeActive:
		return "active"
	case OutcomeRevoked:
		return "revoked"
	default:
		return "transient"
	}
}

// BeaconRequest is the minimal payload the scanner POSTs to the ingest endpoint. Its
// primary purpose in THIS package is to elicit the install-status response (the 200
// vs signed-410 the counter reads); Org/Repo also bind the response — a signed
// revoke whose org/repo do not match this request is not ours and stays transient.
// Reason/GHSAID, when a run was triggered by an advisory rescan, are forwarded so the
// platform can correlate the scan with the Dependabot alert that caused it.
type BeaconRequest struct {
	Org    string `json:"org"`
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Reason string `json:"reason,omitempty"`
	GHSAID string `json:"ghsa_id,omitempty"`
}

// httpDoer is the subset of *http.Client the ingest client needs; tests inject a
// stub.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// IngestClient posts the beacon to the ingest endpoint and classifies the response.
// A zero HTTP uses http.DefaultClient. Token, when set, is sent as a Bearer
// credential (the run's OIDC token); PubKey/KeyID are the trusted revoke-signing key
// (from TrustedKey) — an empty PubKey means no revoke can ever be verified, so every
// 410 is transient.
type IngestClient struct {
	URL    string
	HTTP   httpDoer
	Token  string
	PubKey ed25519.PublicKey
	KeyID  string
}

// Beacon posts req to the ingest endpoint and classifies the response. It returns the
// Outcome and, for OutcomeRevoked, the verified RevokeBody (for logging/correlation).
// A transport error never propagates as a Go error here — it is a transient Outcome —
// so a backend outage can never actuate self-cleanup; err is returned only for a
// programming/marshal fault.
func (c IngestClient) Beacon(ctx context.Context, req BeaconRequest) (Outcome, *RevokeBody, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return OutcomeTransient, nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return OutcomeTransient, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}

	cl := c.HTTP
	if cl == nil {
		cl = http.DefaultClient
	}
	resp, err := cl.Do(httpReq)
	if err != nil {
		return OutcomeTransient, nil, nil // network error → transient, no actuation
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return OutcomeActive, nil, nil
	}
	if resp.StatusCode != http.StatusGone {
		return OutcomeTransient, nil, nil
	}

	// HTTP 410: only a VERIFIED signed body bound to this repo counts as a revoke.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return OutcomeTransient, nil, nil
	}
	rb, err := parseRevokeBody(raw)
	if err != nil {
		return OutcomeTransient, nil, nil
	}
	if err := Verify(rb, c.PubKey, c.KeyID); err != nil {
		return OutcomeTransient, nil, nil
	}
	if rb.Org != req.Org || rb.Repo != req.Repo {
		// A validly-signed revoke for a DIFFERENT repo must never remove ours.
		return OutcomeTransient, nil, nil
	}
	return OutcomeRevoked, &rb, nil
}
