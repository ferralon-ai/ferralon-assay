package acquire

import (
	"net/url"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// Host canonicalization before the allowlist compare (security-gate change #3): url.Hostname()
// strips port/userinfo, lowercase, strip trailing dot; userinfo is rejected outright.
func TestCanonicalHost(t *testing.T) {
	cases := []struct {
		name     string
		rawURL   string
		wantHost string
		wantErr  bool
	}{
		{"plain", "https://registry.npmjs.org/x", "registry.npmjs.org", false},
		{"uppercase", "https://Registry.NPMJS.org/x", "registry.npmjs.org", false},
		{"trailing dot", "https://registry.npmjs.org./x", "registry.npmjs.org", false},
		{"explicit port stripped", "https://registry.npmjs.org:443/x", "registry.npmjs.org", false},
		{"userinfo spoof rejected", "https://registry.npmjs.org@evil.com/x", "", true},
		{"userinfo with password rejected", "https://user:pass@evil.com/x", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			host, err := canonicalHost(u)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("canonicalHost(%q) = %q, want error", tc.rawURL, host)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalHost(%q): %v", tc.rawURL, err)
			}
			if host != tc.wantHost {
				t.Fatalf("canonicalHost(%q) = %q, want %q", tc.rawURL, host, tc.wantHost)
			}
		})
	}
}

// Allowlist match is EXACT (no suffix/substring), so a look-alike host is refused.
func TestAllowlistExactMatch(t *testing.T) {
	allow := NewAllowlist("registry.npmjs.org")
	if !allow.Allows("registry.npmjs.org") {
		t.Fatal("exact host not allowed")
	}
	// canonicalized inputs
	if !allow.Allows("Registry.NPMJS.org") {
		t.Fatal("case variant should canonicalize to an allowed host")
	}
	for _, bad := range []string{
		"evil-npmjs.org.attacker.com",
		"registry.npmjs.org.attacker.com",
		"npmjs.org",
		"aregistry.npmjs.org",
		"registry.npmjs.org.evil",
	} {
		if allow.Allows(canonicalizeHostString(bad)) {
			t.Fatalf("look-alike host %q was allowed", bad)
		}
	}
}

// Credential binding follows the canonical host: a credential registered under one host is
// returned for that host (case-insensitively) and never for a different (look-alike) host.
func TestCredentialBindingIsHostExact(t *testing.T) {
	rc := NewRegistryCredentials(map[string]checkout.Credential{
		"registry.npmjs.org": checkout.NewCredential("tok"),
	})
	if rc.For("registry.npmjs.org").IsEmpty() {
		t.Fatal("bound host should return its credential")
	}
	if rc.For("REGISTRY.NPMJS.ORG").IsEmpty() {
		t.Fatal("bound host should match case-insensitively")
	}
	if !rc.For("registry.npmjs.org.attacker.com").IsEmpty() {
		t.Fatal("look-alike host must not receive the bound credential")
	}
	if !rc.For("registry.other.org").IsEmpty() {
		t.Fatal("unbound host must return the empty credential")
	}
}
