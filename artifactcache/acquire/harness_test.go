package acquire

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

// harness maps fake registry hostnames onto real local TLS httptest listeners, so tests can
// exercise host-based allowlisting, credential binding, and cross-host redirects with
// DISTINCT hostnames (a plain 127.0.0.1 httptest server cannot: two servers would share the
// loopback host and defeat the cred-binding test). A single client's DialContext rewrites the
// fake host to the backend's real address; TLS verification is skipped since the self-signed
// httptest cert is for 127.0.0.1, not the fake host.
type harness struct {
	client   *http.Client
	backends map[string]string // fake hostname -> real "127.0.0.1:port"
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{backends: map[string]string{}}
	h.client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if real, ok := h.backends[host]; ok {
					addr = real
				} else {
					addr = net.JoinHostPort(host, port)
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // hermetic self-signed test cert
		},
	}
	return h
}

// serve registers handler for fake hostname on a fresh TLS listener.
func (h *harness) serve(t *testing.T, hostname string, handler http.Handler) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.backends[hostname] = u.Host
}

// nugetDigestWire returns the genuine "sha512:<base64-std>" wire digest of data — the exact
// wire form a real NuGet inventory node emits.
func nugetDigestWire(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512:" + base64.StdEncoding.EncodeToString(sum[:])
}

// nugetPolicy builds a Policy for a single allowlisted NuGet registry host.
func nugetPolicy(host string, requireAuth bool, creds RegistryCredentials) Policy {
	return Policy{
		Allowlist:   NewAllowlist(host),
		Registries:  map[string]RegistryConfig{"nuget": {BaseURL: "https://" + host, RequireAuth: requireAuth}},
		Backends:    map[string]RegistryBackend{"nuget": NewNuGetBackend()},
		Credentials: creds,
	}
}

// countingHandler serves body at the NuGet flat-container path and counts requests.
type countingHandler struct {
	body     []byte
	requests int
	authSeen string
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.requests++
	if a := r.Header.Get("Authorization"); a != "" {
		c.authSeen = a
	}
	_, _ = w.Write(c.body)
}

// newtsonRef is the canonical NuGet coordinate the e2e tests bind to.
func nugetRef(data []byte) artifactcache.Ref {
	return artifactcache.Ref{PURL: "pkg:nuget/Newtonsoft.Json@13.0.3", Digest: nugetDigestWire(data)}
}
