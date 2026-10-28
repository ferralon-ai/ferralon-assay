package acquire

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

// statusThen answers the first len(statuses) requests with those statuses (and header, when
// set) and every later one with body.
type statusThen struct {
	statuses []int
	header   http.Header
	body     []byte
	requests atomic.Int32
}

func (s *statusThen) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	n := int(s.requests.Add(1))
	if n <= len(s.statuses) {
		for k, v := range s.header {
			w.Header()[k] = v
		}
		w.WriteHeader(s.statuses[n-1])
		return
	}
	_, _ = w.Write(s.body)
}

func repeat(status, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = status
	}
	return out
}

// A registry that throttles, fails or times out is unavailable, never a registry that does not
// serve the artifact, and Acquire retries it a bounded number of times, waiting what the
// registry asks within a cap and never past the caller's deadline. Only a 404 or another
// non-transient status reads as absent.
func TestAcquireTransientFailures(t *testing.T) {
	data := []byte("hermetic .nupkg fixture bytes")
	retryAfter := func(v string) http.Header { return http.Header{"Retry-After": []string{v}} }

	tests := []struct {
		name     string
		statuses []int
		header   http.Header
		deadline time.Duration // non-zero: Acquire runs under a context with this deadline
		auth     bool          // the registry has an auth entry
		want     error         // nil: acquired
		wantCode string        // FetchReason or PolicyReason code
		wantReqs int
		wantWait []time.Duration
	}{
		{name: "429 without Retry-After backs off and gives up", statuses: repeat(http.StatusTooManyRequests, 3),
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchRateLimited, wantReqs: 3, wantWait: []time.Duration{time.Second, 2 * time.Second}},
		{name: "429 with Retry-After waits what it asks", statuses: repeat(http.StatusTooManyRequests, 3), header: retryAfter("7"),
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchRateLimited, wantReqs: 3, wantWait: []time.Duration{7 * time.Second, 7 * time.Second}},
		{name: "429 then served", statuses: []int{http.StatusTooManyRequests}, header: retryAfter("2"),
			wantReqs: 2, wantWait: []time.Duration{2 * time.Second}},
		{name: "Retry-After past the cap is not waited for", statuses: repeat(http.StatusTooManyRequests, 3), header: retryAfter("3600"),
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchRateLimited, wantReqs: 1},
		{name: "Retry-After past the deadline is not waited for", statuses: repeat(http.StatusTooManyRequests, 3), header: retryAfter("20"), deadline: 10 * time.Second,
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchRateLimited, wantReqs: 1},
		{name: "backoff past the deadline is not waited for", statuses: repeat(http.StatusServiceUnavailable, 3), deadline: 1500 * time.Millisecond,
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchServerError, wantReqs: 2, wantWait: []time.Duration{time.Second}},
		{name: "500", statuses: repeat(http.StatusInternalServerError, 3),
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchServerError, wantReqs: 3, wantWait: []time.Duration{time.Second, 2 * time.Second}},
		{name: "503", statuses: repeat(http.StatusServiceUnavailable, 3),
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchServerError, wantReqs: 3, wantWait: []time.Duration{time.Second, 2 * time.Second}},
		{name: "408", statuses: repeat(http.StatusRequestTimeout, 3),
			want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchTimeout, wantReqs: 3, wantWait: []time.Duration{time.Second, 2 * time.Second}},
		{name: "success after one 503", statuses: []int{http.StatusServiceUnavailable},
			wantReqs: 2, wantWait: []time.Duration{time.Second}},
		{name: "404 is absent and not retried", statuses: []int{http.StatusNotFound},
			want: artifactcache.ErrDeclaredAbsent, wantReqs: 1},
		{name: "401 with an auth entry is a missing credential", statuses: []int{http.StatusUnauthorized}, auth: true,
			want: artifactcache.ErrPolicyRefused, wantCode: artifactcache.PolicyMissingCredential, wantReqs: 1},
		{name: "403 with an auth entry is a missing credential", statuses: []int{http.StatusForbidden}, auth: true,
			want: artifactcache.ErrPolicyRefused, wantCode: artifactcache.PolicyMissingCredential, wantReqs: 1},
		{name: "401 with no auth entry is a missing credential", statuses: []int{http.StatusUnauthorized},
			want: artifactcache.ErrPolicyRefused, wantCode: artifactcache.PolicyMissingCredential, wantReqs: 1},
		{name: "403 with no auth entry is a missing credential", statuses: []int{http.StatusForbidden},
			want: artifactcache.ErrPolicyRefused, wantCode: artifactcache.PolicyMissingCredential, wantReqs: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			srv := &statusThen{statuses: tt.statuses, header: tt.header, body: data}
			h.serve(t, nugetHost, srv)
			a := NewAcquirer(t.TempDir(), h.client)
			var waits []time.Duration
			a.SetRetrySleep(func(_ context.Context, d time.Duration) error {
				waits = append(waits, d)
				return nil
			})
			policy := nugetPolicy(nugetHost, false, RegistryCredentials{})
			if tt.auth {
				reg := policy.Registries["nuget"]
				reg.AuthConfigured = true
				policy.Registries["nuget"] = reg
			}
			ctx := context.Background()
			if tt.deadline != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.deadline)
				defer cancel()
			}

			_, err := a.Acquire(ctx, nugetRef(data), policy)
			switch {
			case tt.want == nil && err != nil:
				t.Fatalf("Acquire: %v, want acquired", err)
			case tt.want != nil && !errors.Is(err, tt.want):
				t.Fatalf("Acquire err = %v, want %v", err, tt.want)
			}
			if errors.Is(err, artifactcache.ErrDeclaredAbsent) && errors.Is(err, artifactcache.ErrRegistryUnavailable) {
				t.Fatalf("%v reads as both absent and unavailable", err)
			}
			if tt.wantCode != "" {
				var fr *artifactcache.FetchReason
				var pr *artifactcache.PolicyReason
				got := ""
				switch {
				case errors.As(err, &fr):
					got = fr.Code
					if fr.Host != nugetHost {
						t.Fatalf("FetchReason host = %q, want %q", fr.Host, nugetHost)
					}
				case errors.As(err, &pr):
					got = pr.Code
				}
				if got != tt.wantCode {
					t.Fatalf("code = %q, want %q", got, tt.wantCode)
				}
			}
			if n := int(srv.requests.Load()); n != tt.wantReqs {
				t.Fatalf("requests = %d, want %d", n, tt.wantReqs)
			}
			if !slices.Equal(waits, tt.wantWait) {
				t.Fatalf("waits = %v, want %v", waits, tt.wantWait)
			}
		})
	}
}

// A registry that does not answer within the client's own timeout is unavailable and retried;
// one still not answering when the caller's deadline passes is the caller's deadline, returned
// as is for the caller to read as cancelled, and not retried.
func TestAcquireSlowRegistry(t *testing.T) {
	data := []byte("hermetic .nupkg fixture bytes")
	tests := []struct {
		name          string
		clientTimeout time.Duration
		deadline      time.Duration
		wantReqs      int
		wantErr       error
	}{
		{name: "request timeout", clientTimeout: 50 * time.Millisecond, wantReqs: 3, wantErr: artifactcache.ErrRegistryUnavailable},
		{name: "caller deadline", deadline: 50 * time.Millisecond, wantReqs: 1, wantErr: context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			release := make(chan struct{})
			var requests atomic.Int32
			h.serve(t, nugetHost, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			t.Cleanup(func() { close(release) })
			client := *h.client
			client.Timeout = tt.clientTimeout
			a := NewAcquirer(t.TempDir(), &client)
			a.SetRetrySleep(func(context.Context, time.Duration) error { return nil })
			ctx := context.Background()
			if tt.deadline != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.deadline)
				defer cancel()
			}
			_, err := a.Acquire(ctx, nugetRef(data), nugetPolicy(nugetHost, false, RegistryCredentials{}))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Acquire err = %v, want %v", err, tt.wantErr)
			}
			if errors.Is(err, artifactcache.ErrDeclaredAbsent) {
				t.Fatalf("a slow registry reads as absent: %v", err)
			}
			if n := int(requests.Load()); n != tt.wantReqs {
				t.Fatalf("requests = %d, want %d", n, tt.wantReqs)
			}
		})
	}
}

// A connection the registry drops is unavailable and retried; a host that does not resolve or
// refuses the connection is unreachable and is not.
func TestAcquireTransportFailures(t *testing.T) {
	data := []byte("hermetic .nupkg fixture bytes")
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedAddr := refused.Addr().String()
	refused.Close()

	tests := []struct {
		name     string
		host     string
		setup    func(*testing.T, *harness) *atomic.Int32
		want     error
		wantCode string
		wantWait int
	}{
		{name: "connection dropped before a response", host: nugetHost, setup: func(t *testing.T, h *harness) *atomic.Int32 {
			var n atomic.Int32
			h.serve(t, nugetHost, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n.Add(1)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
			}))
			return &n
		}, want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchConnectionReset, wantWait: 2},
		{name: "body cut short", host: nugetHost, setup: func(t *testing.T, h *harness) *atomic.Int32 {
			var n atomic.Int32
			h.serve(t, nugetHost, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n.Add(1)
				w.Header().Set("Content-Length", "1000")
				_, _ = w.Write(data[:4])
			}))
			return &n
		}, want: artifactcache.ErrRegistryUnavailable, wantCode: artifactcache.FetchConnectionReset, wantWait: 2},
		{name: "connection refused", host: "refused.test", setup: func(_ *testing.T, h *harness) *atomic.Int32 {
			h.backends["refused.test"] = refusedAddr
			return nil
		}, want: artifactcache.ErrRegistryUnreachable, wantCode: artifactcache.FetchConnectFailure},
		{name: "host does not resolve", host: "nonexistent.invalid", setup: func(*testing.T, *harness) *atomic.Int32 { return nil },
			want: artifactcache.ErrRegistryUnreachable, wantCode: artifactcache.FetchDNSFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			n := tt.setup(t, h)
			a := NewAcquirer(t.TempDir(), h.client)
			waits := 0
			a.SetRetrySleep(func(context.Context, time.Duration) error { waits++; return nil })
			_, err := a.Acquire(context.Background(), nugetRef(data), nugetPolicy(tt.host, false, RegistryCredentials{}))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Acquire err = %v, want %v", err, tt.want)
			}
			var fr *artifactcache.FetchReason
			if !errors.As(err, &fr) || fr.Code != tt.wantCode || fr.Host != tt.host {
				t.Fatalf("Acquire err = %#v, want FetchReason %q for %s", err, tt.wantCode, tt.host)
			}
			if waits != tt.wantWait {
				t.Fatalf("waits = %d, want %d", waits, tt.wantWait)
			}
			if n != nil && int(n.Load()) != tt.wantWait+1 {
				t.Fatalf("requests = %d, want %d", n.Load(), tt.wantWait+1)
			}
		})
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-5", 0},
		{"12", 12 * time.Second},
		{"99999999999999999", maxRetryWait + time.Second},
		{"soon", 0},
		{now.Add(20 * time.Second).Format(http.TimeFormat), 20 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	}
	for _, tt := range tests {
		if got := retryAfter(tt.in, now); got != tt.want {
			t.Errorf("retryAfter(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestRegistryID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://registry.npmjs.org/", "https://registry.npmjs.org"},
		{"https://user:pass@NPM.Corp.Example./api/npm/npm-remote/?token=x#f", "https://npm.corp.example/api/npm/npm-remote"},
		{"https://npm.pkg.github.com:8443/owner", "https://npm.pkg.github.com:8443/owner"},
		{"https://[::1]/", "https://[::1]"},
		{"not a url", ""},
	}
	for _, tt := range tests {
		if got := RegistryID(tt.in); got != tt.want {
			t.Errorf("RegistryID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
