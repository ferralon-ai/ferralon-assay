package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestScanWindowEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.ferralon.com/runs":       "https://api.ferralon.com/policy/scan-window",
		"https://api.example.test:8443/x/y?q": "https://api.example.test:8443/policy/scan-window",
		"http://127.0.0.1:9/runs":             "http://127.0.0.1:9/policy/scan-window",
		"":                                    "",
		"api.ferralon.com/runs":               "",
		"file:///etc/passwd":                  "",
	} {
		if got := scanWindowEndpoint(in); got != want {
			t.Errorf("scanWindowEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseScanWindowResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       report.ScanWindow
		wantErr    string
	}{
		{name: "customer", body: `{"version":1,"window":"7d","policy":"published-7d","source":{"kind":"customer","customer_id":"cus_1","distance":0}}`,
			want: report.ScanWindow{Window: "7d", Policy: "published-7d", ResolvedVia: "api", Source: report.ScanWindowSource{Kind: "customer", CustomerID: "cus_1", Distance: intPtr(0)}}},
		{name: "ancestor, unknown fields ignored", body: `{"version":1,"window":"full","policy":"full","source":{"kind":"ancestor","customer_id":"cus_2","distance":1,"name":"x"},"extra":true}`,
			want: report.ScanWindow{Window: "full", Policy: "full", ResolvedVia: "api", Source: report.ScanWindowSource{Kind: "ancestor", CustomerID: "cus_2", Distance: intPtr(1)}}},
		{name: "default", body: `{"version":1,"window":"24h","policy":"published-24h","source":{"kind":"default"}}`,
			want: report.ScanWindow{Window: "24h", Policy: "published-24h", ResolvedVia: "api", Source: report.ScanWindowSource{Kind: "default"}}},
		{name: "unknown version", body: `{"version":2,"window":"7d","policy":"published-7d","source":{"kind":"default"}}`, wantErr: "unknown response version"},
		{name: "unknown window", body: `{"version":1,"window":"90d","policy":"published-90d","source":{"kind":"default"}}`, wantErr: "not a scan window"},
		{name: "policy mismatch", body: `{"version":1,"window":"7d","policy":"full","source":{"kind":"default"}}`, wantErr: "does not back"},
		{name: "unknown kind", body: `{"version":1,"window":"7d","policy":"published-7d","source":{"kind":"repo"}}`, wantErr: "unknown source kind"},
		{name: "customer without id", body: `{"version":1,"window":"7d","policy":"published-7d","source":{"kind":"customer","distance":0}}`, wantErr: "customer_id"},
		{name: "id with a newline", body: `{"version":1,"window":"7d","policy":"published-7d","source":{"kind":"customer","customer_id":"a\nsource=repo_config","distance":0}}`, wantErr: "customer_id"},
		{name: "ancestor at distance 0", body: `{"version":1,"window":"7d","policy":"published-7d","source":{"kind":"ancestor","customer_id":"c","distance":0}}`, wantErr: "does not match distance"},
		{name: "distance out of range", body: `{"version":1,"window":"7d","policy":"published-7d","source":{"kind":"ancestor","customer_id":"c","distance":65}}`, wantErr: "out of range"},
		{name: "not JSON", body: `<html>`, wantErr: "malformed response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseScanWindowResponse([]byte(tc.body))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v (%+v)", tc.wantErr, err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.Window != tc.want.Window || got.Policy != tc.want.Policy || got.ResolvedVia != tc.want.ResolvedVia ||
				encodeAPISource(got.Source) != encodeAPISource(tc.want.Source) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

const okBody = `{"version":1,"window":"30d","policy":"published-30d","source":{"kind":"customer","customer_id":"cus_1","distance":0}}`

// The lookup retries a network error or a 5xx once, never a 4xx or a bad body, and gives up
// within its time budget.
func TestScanWindowLookupFetch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		responses []func(http.ResponseWriter)
		token     string
		wantCalls int32
		wantErr   string
	}{
		{name: "ok", responses: []func(http.ResponseWriter){status(200, okBody)}, token: "t", wantCalls: 1},
		{name: "5xx then ok", responses: []func(http.ResponseWriter){status(503, ""), status(200, okBody)}, token: "t", wantCalls: 2},
		{name: "5xx twice", responses: []func(http.ResponseWriter){status(500, ""), status(502, "")}, token: "t", wantCalls: 2, wantErr: "HTTP 502"},
		{name: "403 is not retried", responses: []func(http.ResponseWriter){status(403, `{"message":"no"}`)}, token: "t", wantCalls: 1, wantErr: "HTTP 403"},
		{name: "bad body is not retried", responses: []func(http.ResponseWriter){status(200, `{"version":9}`)}, token: "t", wantCalls: 1, wantErr: "unknown response version"},
		{name: "slow attempts time out", responses: []func(http.ResponseWriter){slow, slow}, token: "t", wantCalls: 2, wantErr: "request failed"},
		{name: "no token, no request", token: "", wantCalls: 0, wantErr: "no OIDC token"},
		{name: "redirect is not followed", responses: []func(http.ResponseWriter){redirect}, token: "t", wantCalls: 1, wantErr: "HTTP 307"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != scanWindowPath || r.Header.Get("Authorization") != "Bearer "+tc.token {
					t.Errorf("unexpected request %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
				}
				tc.responses[n-1](w)
			}))
			defer srv.Close()
			l := scanWindowLookup{
				endpoint:       srv.URL + scanWindowPath,
				token:          func(context.Context) string { return tc.token },
				attemptTimeout: 50 * time.Millisecond,
				totalTimeout:   time.Second,
			}
			sw, err := l.fetch(context.Background())
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("calls = %d, want %d", got, tc.wantCalls)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || sw.Policy != "published-30d" || sw.ResolvedVia != report.ScanWindowViaAPI {
				t.Fatalf("got %+v, %v", sw, err)
			}
		})
	}
}

func status(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

func redirect(w http.ResponseWriter) {
	w.Header().Set("Location", "/elsewhere")
	w.WriteHeader(http.StatusTemporaryRedirect)
}

// A token request that stalls is bounded by the lookup's total time budget.
func TestScanWindowLookupFetch_TokenStall(t *testing.T) {
	l := scanWindowLookup{
		endpoint:     "http://127.0.0.1:9" + scanWindowPath,
		token:        func(ctx context.Context) string { <-ctx.Done(); return "" },
		totalTimeout: 50 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { _, err := l.fetch(context.Background()); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "no OIDC token") {
			t.Fatalf("err = %v, want no OIDC token", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled token request outlived the lookup's time budget")
	}
}

func slow(w http.ResponseWriter) {
	time.Sleep(200 * time.Millisecond)
	status(200, okBody)(w)
}

// End to end through the scan-window command: the repository config wins without a lookup; a
// linked run asks Ferralon; a failed lookup falls back to the input and says so; an unlinked run
// never asks.
func TestRunScanWindow_PolicyLookup(t *testing.T) {
	for _, tc := range []struct {
		name, config, policy, linked string
		code                         int
		wantOut, wantLog             string
		wantCalls                    int32
	}{
		{name: "repo window, no lookup", config: "version: 2\nscan:\n  window: full\n", policy: "published-7d", linked: "true", code: 200,
			wantOut: "window=full\npolicy=full\nsource=repo_config\n", wantCalls: 0},
		{name: "lookup answers", policy: "published-7d", linked: "true", code: 200,
			wantOut: "window=30d\npolicy=published-30d\nsource=api\napi-source={\"kind\":\"customer\",\"customer_id\":\"cus_1\",\"distance\":0}\n",
			wantLog: "from this repository's Ferralon customer policy", wantCalls: 1},
		{name: "lookup fails, input used", policy: "published-7d", linked: "true", code: 403,
			wantOut: "window=7d\npolicy=published-7d\nsource=policy_input\n", wantLog: "lookup unavailable (HTTP 403)", wantCalls: 1},
		{name: "lookup fails, no input", linked: "true", code: 500,
			wantOut: "window=\npolicy=\nsource=none\n", wantLog: "lookup unavailable (HTTP 500)", wantCalls: 2},
		{name: "unlinked, no lookup", policy: "published-7d", linked: "false", code: 200,
			wantOut: "window=7d\npolicy=published-7d\nsource=policy_input\n", wantCalls: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				status(tc.code, okBody)(w)
			}))
			defer srv.Close()
			t.Setenv(envLinkToConsole, tc.linked)
			t.Setenv(envRunsURL, srv.URL+"/runs")
			t.Setenv(envOIDCToken, "oidc")

			root := writeRepoConfig(t, tc.config)
			var out, log bytes.Buffer
			if err := runScanWindow([]string{"-target", root, "-advisory-corpus-policy", tc.policy}, &out, &log); err != nil {
				t.Fatalf("runScanWindow: %v (log %q)", err, log.String())
			}
			if out.String() != tc.wantOut {
				t.Errorf("outputs = %q, want %q", out.String(), tc.wantOut)
			}
			if !strings.Contains(log.String(), tc.wantLog) {
				t.Errorf("log %q does not contain %q", log.String(), tc.wantLog)
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("lookups = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}
