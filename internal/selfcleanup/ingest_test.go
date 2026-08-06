package selfcleanup

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// stubDoer returns a canned response (or error) and records the last request.
type stubDoer struct {
	status  int
	body    string
	err     error
	lastReq *http.Request
	lastRaw []byte
}

func (s *stubDoer) Do(req *http.Request) (*http.Response, error) {
	s.lastReq = req
	if req.Body != nil {
		s.lastRaw, _ = io.ReadAll(req.Body)
	}
	if s.err != nil {
		return nil, s.err
	}
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     make(http.Header),
	}, nil
}

func signedRevoke(t *testing.T, priv ed25519.PrivateKey, keyID, org, repo string) string {
	t.Helper()
	b, err := Sign(priv, keyID, org, repo, "bm9uY2U=", "2026-07-09T12:00:00Z")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func req() BeaconRequest { return BeaconRequest{Org: "acme", Repo: "acme/widget", Commit: "c0ffee"} }

func TestBeaconActiveOn200(t *testing.T) {
	c := IngestClient{URL: "https://x", HTTP: &stubDoer{status: 200, body: `{"status":"ok"}`}}
	out, _, err := c.Beacon(context.Background(), req())
	if err != nil || out != OutcomeActive {
		t.Fatalf("200 → active, got %v err=%v", out, err)
	}
}

func TestBeaconRevokedOnVerified410(t *testing.T) {
	pub, priv := testKeypair(t)
	body := signedRevoke(t, priv, "k1", "acme", "acme/widget")
	c := IngestClient{URL: "https://x", HTTP: &stubDoer{status: http.StatusGone, body: body}, PubKey: pub, KeyID: "k1"}
	out, rb, err := c.Beacon(context.Background(), req())
	if err != nil || out != OutcomeRevoked {
		t.Fatalf("verified 410 → revoked, got %v err=%v", out, err)
	}
	if rb == nil || rb.Org != "acme" {
		t.Fatalf("revoked outcome must return the body, got %+v", rb)
	}
}

func TestBeaconTransientOnUnsigned410(t *testing.T) {
	pub, _ := testKeypair(t)
	c := IngestClient{URL: "https://x", HTTP: &stubDoer{status: http.StatusGone, body: `{"schema":"ferralon.revoke/v1","org":"acme","repo":"acme/widget","sig":"AAAA"}`}, PubKey: pub, KeyID: "k1"}
	out, _, _ := c.Beacon(context.Background(), req())
	if out != OutcomeTransient {
		t.Fatalf("unsigned 410 → transient, got %v", out)
	}
}

func TestBeaconTransientOn410WhenNoTrustedKey(t *testing.T) {
	_, priv := testKeypair(t)
	body := signedRevoke(t, priv, "k1", "acme", "acme/widget")
	// No PubKey configured (OSS build): a 410 can never be verified → transient.
	c := IngestClient{URL: "https://x", HTTP: &stubDoer{status: http.StatusGone, body: body}}
	out, _, _ := c.Beacon(context.Background(), req())
	if out != OutcomeTransient {
		t.Fatalf("410 with no trusted key → transient, got %v", out)
	}
}

func TestBeaconTransientOnRepoMismatch(t *testing.T) {
	pub, priv := testKeypair(t)
	// Validly signed, but for a DIFFERENT repo — must not remove ours.
	body := signedRevoke(t, priv, "k1", "acme", "acme/other")
	c := IngestClient{URL: "https://x", HTTP: &stubDoer{status: http.StatusGone, body: body}, PubKey: pub, KeyID: "k1"}
	out, _, _ := c.Beacon(context.Background(), req())
	if out != OutcomeTransient {
		t.Fatalf("signed revoke for another repo → transient, got %v", out)
	}
}

func TestBeaconTransientOnNetworkError(t *testing.T) {
	c := IngestClient{URL: "https://x", HTTP: &stubDoer{err: io.ErrUnexpectedEOF}}
	out, _, err := c.Beacon(context.Background(), req())
	if err != nil || out != OutcomeTransient {
		t.Fatalf("network error → transient (no Go error), got %v err=%v", out, err)
	}
}

func TestBeaconTransientOn500(t *testing.T) {
	c := IngestClient{URL: "https://x", HTTP: &stubDoer{status: 500, body: "boom"}}
	out, _, _ := c.Beacon(context.Background(), req())
	if out != OutcomeTransient {
		t.Fatalf("500 → transient, got %v", out)
	}
}

func TestBeaconForwardsRescanMetadata(t *testing.T) {
	s := &stubDoer{status: 200, body: `{}`}
	c := IngestClient{URL: "https://x", HTTP: s, Token: "oidc-tok"}
	r := req()
	r.Reason = "dependabot_alert"
	r.GHSAID = "GHSA-xxxx"
	if _, _, err := c.Beacon(context.Background(), r); err != nil {
		t.Fatalf("beacon: %v", err)
	}
	if got := s.lastReq.Header.Get("Authorization"); got != "Bearer oidc-tok" {
		t.Fatalf("OIDC bearer not sent: %q", got)
	}
	raw := string(s.lastRaw)
	if !strings.Contains(raw, `"reason":"dependabot_alert"`) || !strings.Contains(raw, `"ghsa_id":"GHSA-xxxx"`) {
		t.Fatalf("rescan metadata not forwarded on the ingest POST: %s", raw)
	}
}
