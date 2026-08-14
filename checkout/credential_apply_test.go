package checkout

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const applyToken = "npm_s3cr3tRegistryToken_MUSTNOTLEAK"

// ApplyTo sets Authorization: Bearer <token> from the unexported token in place, and the
// plaintext appears nowhere except that one header value it constructs on the request.
func TestApplyToSetsBearerHeader(t *testing.T) {
	c := NewCredential(applyToken)
	req, err := http.NewRequest(http.MethodGet, "https://registry.example.com/pkg/-/pkg-1.0.0.tgz", nil)
	if err != nil {
		t.Fatal(err)
	}
	c.ApplyTo(req)

	if got := req.Header.Get("Authorization"); got != "Bearer "+applyToken {
		t.Fatalf("Authorization = %q, want Bearer <token>", got)
	}
	// The token is not smeared anywhere else on the request (URL, other headers).
	if strings.Contains(req.URL.String(), applyToken) {
		t.Fatalf("token leaked into the URL: %s", req.URL)
	}
	for k, vs := range req.Header {
		if k == "Authorization" {
			continue
		}
		for _, v := range vs {
			if strings.Contains(v, applyToken) {
				t.Fatalf("token leaked into header %s: %q", k, v)
			}
		}
	}
}

// The empty credential is a no-op: no Authorization header (bare/anonymous fetch).
func TestApplyToEmptyIsNoOp(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://registry.example.com/x", nil)
	NewCredential("").ApplyTo(req)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("empty credential set an Authorization header: %q", got)
	}
}

// ApplyBasicAuth sets Basic auth without surfacing the plaintext token as a return value or
// smearing it into the URL.
func TestApplyBasicAuth(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://registry.example.com/x", nil)
	NewCredential(applyToken).ApplyBasicAuth(req, "x-access-token")
	user, pass, ok := req.BasicAuth()
	if !ok || user != "x-access-token" || pass != applyToken {
		t.Fatalf("BasicAuth = (%q,%q,%v), want the token as password", user, pass, ok)
	}
	if strings.Contains(req.URL.String(), applyToken) {
		t.Fatalf("token leaked into the URL")
	}
}

// Redaction holds under every fmt verb over (a) a map-of-Credentials and (b) a wrapped
// error — the two shapes the security gate requires (change #1 test bar). This proves the
// header-egress method did not open a token exit that formatting could reach.
func TestCredentialRedactionUnderFmtVerbs(t *testing.T) {
	c := NewCredential(applyToken)
	m := map[string]Credential{"registry.example.com": c, "registry.other.com": NewCredential("")}
	wrapped := fmt.Errorf("acquire failed for host %s with cred %v: %w", "registry.example.com", c, http.ErrHandlerTimeout)

	verbs := []string{"%v", "%s", "%#v", "%+v", "%q"}
	for _, verb := range verbs {
		t.Run("map "+verb, func(t *testing.T) {
			out := fmt.Sprintf(verb, m)
			if strings.Contains(out, applyToken) {
				t.Fatalf("map-of-Credentials leaked token under %s: %s", verb, out)
			}
		})
		t.Run("wrapped-error "+verb, func(t *testing.T) {
			out := fmt.Sprintf(verb, wrapped)
			if strings.Contains(out, applyToken) {
				t.Fatalf("wrapped error leaked token under %s: %s", verb, out)
			}
		})
	}
	// Error() string itself must not leak.
	if strings.Contains(wrapped.Error(), applyToken) {
		t.Fatalf("wrapped error Error() leaked token: %s", wrapped.Error())
	}
}
