package selfcleanup

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os/exec"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// newTempStore inits a hermetic bare repo and returns a StateStore over it.
func newTempStore(t *testing.T) statestore.StateStore {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	cmd := exec.Command("git", "-C", dir, "init", "--bare", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return statestore.NewGitRefStore(statestore.Config{GitDir: dir})
}

func revokeClient(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, org, repo string) IngestClient {
	t.Helper()
	b, _ := Sign(priv, "k1", org, repo, "bm9uY2U=", "2026-07-09T12:00:00Z")
	raw, _ := json.Marshal(b)
	return IngestClient{URL: "https://x", HTTP: &stubDoer{status: http.StatusGone, body: string(raw)}, PubKey: pub, KeyID: "k1"}
}

func TestRunCheckNoActuationUntilThreshold(t *testing.T) {
	pub, priv := testKeypair(t)
	store := newTempStore(t)
	beacon := BeaconRequest{Org: "acme", Repo: "acme/widget", Commit: "c0ffee"}

	actuated := false
	cfg := CheckConfig{
		Store:       store,
		Ingest:      revokeClient(t, pub, priv, "acme", "acme/widget"),
		Beacon:      beacon,
		NewActuator: func() Actuator { actuated = true; return newMock() },
	}

	// First signed revoke: counter → 1, no actuation.
	res, err := RunCheck(context.Background(), cfg)
	if err != nil {
		t.Fatalf("check 1: %v", err)
	}
	if res.Count != 1 || res.Actuated || actuated {
		t.Fatalf("first revoke must not actuate: %+v actuated=%v", res, actuated)
	}

	// Second consecutive signed revoke: counter → 2, actuate.
	res, err = RunCheck(context.Background(), cfg)
	if err != nil {
		t.Fatalf("check 2: %v", err)
	}
	if res.Count != 2 || !res.Actuated || !actuated {
		t.Fatalf("second consecutive revoke must actuate: %+v actuated=%v", res, actuated)
	}
	if res.Rung != Rung1DirectPush {
		t.Fatalf("mock actuator succeeds at rung 1, got %v", res.Rung)
	}
}

func TestRunCheckActiveResetsCounter(t *testing.T) {
	pub, priv := testKeypair(t)
	store := newTempStore(t)
	beacon := BeaconRequest{Org: "acme", Repo: "acme/widget", Commit: "c0ffee"}
	revoke := CheckConfig{Store: store, Ingest: revokeClient(t, pub, priv, "acme", "acme/widget"), Beacon: beacon,
		NewActuator: func() Actuator { return newMock() }}

	// One revoke → count 1.
	if res, _ := RunCheck(context.Background(), revoke); res.Count != 1 {
		t.Fatalf("want count 1, got %d", res.Count)
	}

	// An active (200) response resets to 0.
	active := revoke
	active.Ingest = IngestClient{URL: "https://x", HTTP: &stubDoer{status: 200, body: `{"status":"ok"}`}}
	res, err := RunCheck(context.Background(), active)
	if err != nil {
		t.Fatalf("active check: %v", err)
	}
	if res.Count != 0 || res.Actuated {
		t.Fatalf("active must reset the streak: %+v", res)
	}

	// A subsequent single revoke is only 1 again — the streak restarted.
	if res, _ := RunCheck(context.Background(), revoke); res.Count != 1 || res.Actuated {
		t.Fatalf("streak must restart at 1, got %+v", res)
	}
}

func TestRunCheckTransientHolds(t *testing.T) {
	pub, priv := testKeypair(t)
	store := newTempStore(t)
	beacon := BeaconRequest{Org: "acme", Repo: "acme/widget", Commit: "c0ffee"}
	revoke := CheckConfig{Store: store, Ingest: revokeClient(t, pub, priv, "acme", "acme/widget"), Beacon: beacon,
		NewActuator: func() Actuator { return newMock() }}

	if res, _ := RunCheck(context.Background(), revoke); res.Count != 1 {
		t.Fatalf("want 1, got %d", res.Count)
	}
	// A 500 (transient) must neither count nor reset — the streak holds at 1.
	transient := revoke
	transient.Ingest = IngestClient{URL: "https://x", HTTP: &stubDoer{status: 500, body: "boom"}}
	res, _ := RunCheck(context.Background(), transient)
	if res.Count != 1 || res.Actuated {
		t.Fatalf("transient must hold at 1, got %+v", res)
	}
}

func TestRunCheckActuationErrorIsNonFatalOnResult(t *testing.T) {
	pub, priv := testKeypair(t)
	store := newTempStore(t)
	beacon := BeaconRequest{Org: "acme", Repo: "acme/widget", Commit: "c0ffee"}
	// A mock that lands on rung 3 with a disable error (guaranteed-progress path).
	newAct := func() Actuator {
		m := newMock()
		m.errs["direct"] = ErrPushRejected
		m.errs["pr"] = context.DeadlineExceeded
		m.errs["disable"] = context.DeadlineExceeded
		return m
	}
	cfg := CheckConfig{Store: store, Ingest: revokeClient(t, pub, priv, "acme", "acme/widget"), Beacon: beacon, NewActuator: newAct}
	RunCheck(context.Background(), cfg)             // count → 1
	res, err := RunCheck(context.Background(), cfg) // count → 2, actuate, rung 3 with errors
	if !res.Actuated || res.Rung != Rung3DisableIssue {
		t.Fatalf("expected rung3 actuation, got %+v", res)
	}
	if err == nil {
		t.Fatal("actuation error should be surfaced on the returned error for logging")
	}
}
