package acquire

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

const (
	hostA   = "registry.a.test"
	hostB   = "registry.b.test"
	tokenA  = "tokenAAA_boundToHostA_neverToB"
	tokenB  = "tokenBBB_boundToHostB"
	nupkgAt = "/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
)

func twoHostPolicy(creds RegistryCredentials, base string) Policy {
	return Policy{
		Allowlist:   NewAllowlist(hostA, hostB),
		Registries:  map[string]RegistryConfig{"nuget": {BaseURL: base}},
		Backends:    map[string]RegistryBackend{"nuget": NewNuGetBackend()},
		Credentials: creds,
	}
}

// Test 4.1: allowlisted host + bound cred → request carries the correct Authorization for
// that host.
func TestAllowlistedHostSendsBoundCredential(t *testing.T) {
	h := newHarness(t)
	data := []byte("bytes served by host A")
	ch := &countingHandler{body: data}
	h.serve(t, hostA, ch)

	creds := NewRegistryCredentials(map[string]checkout.Credential{hostA: checkout.NewCredential(tokenA)})
	acq := NewAcquirer(t.TempDir(), h.client)
	if _, err := acq.Acquire(t.Context(), nugetRef(data), twoHostPolicy(creds, "https://"+hostA)); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if ch.authSeen != "Bearer "+tokenA {
		t.Fatalf("host A saw Authorization %q, want Bearer <tokenA>", ch.authSeen)
	}
}

// Test 4.6: missing cred for a private (RequireAuth) allowlisted registry → ErrPolicyRefused
// missing-credential, NOT a silent anonymous fetch that 401s into a false miss.
func TestPrivateRegistryMissingCredentialRefused(t *testing.T) {
	h := newHarness(t)
	ch := &countingHandler{body: []byte("private")}
	h.serve(t, hostA, ch)

	acq := NewAcquirer(t.TempDir(), h.client)
	policy := nugetPolicy(hostA, true /*requireAuth*/, RegistryCredentials{})
	_, err := acq.Acquire(t.Context(), nugetRef(ch.body), policy)
	var pr *artifactcache.PolicyReason
	if !errors.As(err, &pr) || pr.Code != artifactcache.PolicyMissingCredential {
		t.Fatalf("err = %v, want PolicyReason missing-credential", err)
	}
	if ch.requests != 0 {
		t.Fatalf("private registry with no cred was still fetched (%d requests)", ch.requests)
	}
}

// Test 4.3: redirect allowlisted A → off-allowlist B → abort ErrPolicyRefused; B saw NO
// request (so no Authorization, no body request could reach it).
func TestRedirectToOffAllowlistRefused(t *testing.T) {
	h := newHarness(t)
	offHost := "evil.attacker.test"
	bCounter := &countingHandler{body: []byte("attacker bytes")}
	h.serve(t, offHost, bCounter)
	h.serve(t, hostA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+offHost+"/steal", http.StatusFound)
	}))

	creds := NewRegistryCredentials(map[string]checkout.Credential{hostA: checkout.NewCredential(tokenA)})
	acq := NewAcquirer(t.TempDir(), h.client)
	_, err := acq.Acquire(t.Context(), nugetRef([]byte("x")), twoHostPolicy(creds, "https://"+hostA))
	var pr *artifactcache.PolicyReason
	if !errors.As(err, &pr) || pr.Code != artifactcache.PolicyRedirectOffAllowlist {
		t.Fatalf("err = %v, want PolicyReason redirect-off-allowlist", err)
	}
	if bCounter.requests != 0 {
		t.Fatalf("off-allowlist redirect target received %d requests (auth seen %q)", bCounter.requests, bCounter.authSeen)
	}
}

// Test 4.4: redirect allowlisted A → allowlisted B with a DIFFERENT bound cred → A's
// Authorization is stripped and re-derived from B's cred; A's token NEVER reaches B.
func TestCrossHostRedirectStripsAndRebinds(t *testing.T) {
	h := newHarness(t)
	data := []byte("bytes finally served by host B")
	bCounter := &countingHandler{body: data}
	h.serve(t, hostB, bCounter)
	h.serve(t, hostA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+hostB+nupkgAt, http.StatusFound)
	}))

	creds := NewRegistryCredentials(map[string]checkout.Credential{
		hostA: checkout.NewCredential(tokenA),
		hostB: checkout.NewCredential(tokenB),
	})
	acq := NewAcquirer(t.TempDir(), h.client)
	if _, err := acq.Acquire(t.Context(), nugetRef(data), twoHostPolicy(creds, "https://"+hostA)); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if bCounter.authSeen == "Bearer "+tokenA {
		t.Fatalf("host B received host A's token — credential leak across redirect")
	}
	if bCounter.authSeen != "Bearer "+tokenB {
		t.Fatalf("host B saw %q, want its own Bearer <tokenB>", bCounter.authSeen)
	}
}

// Test 4.5: same-host redirect A → A (different path) proceeds; the header is explicitly
// re-derived for A (not left to the stdlib default).
func TestSameHostRedirectProceeds(t *testing.T) {
	h := newHarness(t)
	data := []byte("bytes after a same-host redirect")
	var served bool
	var lastAuth string
	h.serve(t, hostA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == nupkgAt {
			http.Redirect(w, r, "https://"+hostA+"/final", http.StatusFound)
			return
		}
		served = true
		lastAuth = r.Header.Get("Authorization")
		_, _ = w.Write(data)
	}))

	creds := NewRegistryCredentials(map[string]checkout.Credential{hostA: checkout.NewCredential(tokenA)})
	acq := NewAcquirer(t.TempDir(), h.client)
	if _, err := acq.Acquire(t.Context(), nugetRef(data), twoHostPolicy(creds, "https://"+hostA)); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if !served {
		t.Fatal("same-host redirect target was never served")
	}
	if lastAuth != "Bearer "+tokenA {
		t.Fatalf("same-host redirect carried Authorization %q, want Bearer <tokenA>", lastAuth)
	}
}

// Redirect HTTPS→HTTP downgrade (security-gate change #4a) is refused even to an allowlisted
// host, so re-attached auth is never sent in cleartext.
func TestRedirectDowngradeRefused(t *testing.T) {
	h := newHarness(t)
	h.serve(t, hostA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+hostA+"/plaintext", http.StatusFound) // http, not https
	}))
	creds := NewRegistryCredentials(map[string]checkout.Credential{hostA: checkout.NewCredential(tokenA)})
	acq := NewAcquirer(t.TempDir(), h.client)
	_, err := acq.Acquire(t.Context(), nugetRef([]byte("x")), twoHostPolicy(creds, "https://"+hostA))
	var pr *artifactcache.PolicyReason
	if !errors.As(err, &pr) || pr.Code != artifactcache.PolicyRedirectDowngrade {
		t.Fatalf("err = %v, want PolicyReason https-downgrade-on-redirect", err)
	}
}

// Redirect hop cap (security-gate change #4b) restores the finite bound the stdlib default
// loses when CheckRedirect is overridden: an allowlisted self-redirect loop is stopped.
func TestRedirectHopCapEnforced(t *testing.T) {
	h := newHarness(t)
	h.serve(t, hostA, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+hostA+"/loop", http.StatusFound) // infinite loop
	}))
	acq := NewAcquirer(t.TempDir(), h.client)
	_, err := acq.Acquire(t.Context(), nugetRef([]byte("x")), twoHostPolicy(RegistryCredentials{}, "https://"+hostA))
	var pr *artifactcache.PolicyReason
	if !errors.As(err, &pr) || pr.Code != artifactcache.PolicyRedirectHopCap {
		t.Fatalf("err = %v, want PolicyReason redirect-hop-cap-exceeded", err)
	}
}
