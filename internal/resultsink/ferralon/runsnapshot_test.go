package ferralon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written to it. Used to assert on the sink's operability warnings without
// disturbing its fail-open control flow.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	if cerr := w.Close(); cerr != nil {
		t.Fatalf("close pipe writer: %v", cerr)
	}
	out, rerr := io.ReadAll(r)
	if rerr != nil {
		t.Fatalf("read pipe: %v", rerr)
	}
	return string(out)
}

func sampleResult() resultsink.Result {
	return resultsink.Result{
		Report: report.Report{
			SchemaVersion: report.SchemaVersion,
			Subject:       report.Subject{Repo: "example-org/example-svc", ResolvedCommit: "abc123"},
		},
	}
}

// TestPublishRequestShape asserts the on-the-wire contract the backend /runs handler
// expects: POST, application/json, Bearer OIDC token, body = verbatim tegron.report.v2
// JSON (identity is taken by the backend from the token, so the body carries ONLY the
// report).
func TestPublishRequestShape(t *testing.T) {
	var (
		gotMethod, gotPath, gotCT, gotAuth string
		gotBody                            []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"handle":"h123","run_id":"run-9"}`))
	}))
	defer srv.Close()

	sink := NewRunSnapshot(srv.URL+"/runs", func(context.Context) string { return "oidc-token" })
	if err := sink.Publish(context.Background(), sampleResult()); err != nil {
		t.Fatalf("Publish returned error (must be fail-open, nil): %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/runs" {
		t.Errorf("path = %q, want /runs", gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	if gotAuth != "Bearer oidc-token" {
		t.Errorf("authorization = %q, want Bearer oidc-token", gotAuth)
	}
	// Body must be the verbatim tegron.report.v2 report — decodable, schema-versioned,
	// carrying no run-identity envelope.
	var rep report.Report
	if err := json.Unmarshal(gotBody, &rep); err != nil {
		t.Fatalf("body is not decodable report JSON: %v", err)
	}
	if rep.SchemaVersion != report.SchemaVersion {
		t.Errorf("body schema_version = %q, want %q", rep.SchemaVersion, report.SchemaVersion)
	}
	if rep.Subject.Repo != "example-org/example-svc" {
		t.Errorf("body subject.repo = %q, want example-org/example-svc", rep.Subject.Repo)
	}
}

// TestPublishOmitsAuthWhenNoToken confirms an empty token source posts with no
// Authorization header (the backend then refuses with 401 — a fail-open no-op), and
// that Publish logs an actionable stderr warning so the silent loss is
// self-diagnosing.
func TestPublishOmitsAuthWhenNoToken(t *testing.T) {
	var hadAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadAuth = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := NewRunSnapshot(srv.URL, func(context.Context) string { return "" })

	var pubErr error
	stderr := captureStderr(t, func() {
		pubErr = sink.Publish(context.Background(), sampleResult())
	})
	if pubErr != nil {
		t.Fatalf("Publish: %v", pubErr)
	}
	if hadAuth {
		t.Errorf("Authorization header sent despite an empty token")
	}
	if !strings.Contains(stderr, "OIDC token unavailable") || !strings.Contains(stderr, "id-token: write") {
		t.Errorf("expected an actionable OIDC-unavailable warning on stderr, got: %q", stderr)
	}
}

// TestPublishNon2xxIsFailOpen confirms a rejected push (e.g. 403 no active install)
// NEVER fails the scan job — Publish logs and returns nil.
func TestPublishNon2xxIsFailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden","detail":"no active installation for this owner"}`))
	}))
	defer srv.Close()

	sink := NewRunSnapshot(srv.URL, func(context.Context) string { return "tok" })
	if err := sink.Publish(context.Background(), sampleResult()); err != nil {
		t.Fatalf("a non-2xx push must be fail-open (nil), got: %v", err)
	}
}

// TestPublishTransportErrorIsFailOpen confirms an unreachable backend never fails the
// scan job.
func TestPublishTransportErrorIsFailOpen(t *testing.T) {
	// A closed server address → connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	sink := NewRunSnapshot(url, func(context.Context) string { return "tok" })
	if err := sink.Publish(context.Background(), sampleResult()); err != nil {
		t.Fatalf("a transport error must be fail-open (nil), got: %v", err)
	}
}
