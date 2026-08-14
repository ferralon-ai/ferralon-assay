// internal/checkout/credential.go
package checkout

import (
	"context"
	"net/http"
)

// Credential is a per-fire clone credential — the ownership token that authenticates a
// clone/fetch of a PRIVATE repo (the submit body's ownership_proof.token). It is carried
// in-process ONLY, exactly like the model key (service/internal/model.AnthropicModel.apiKey):
// the token is never written to disk, never placed in a URL or a process argv, and never
// logged. Its String/GoString REDACT, so a stray %v / %s / %#v on a Credential — or on any
// struct that embeds one — cannot leak the token into a log line or a wrapped error string.
//
// The zero value is the EMPTY credential: an unauthenticated bare clone, byte-identical to a
// public-repo / ambient-cred fetch (see GitCheckout.run). Public repos, hermetic fakes, and
// local ambient-cred dev never carry a credential, so they take exactly today's path.
type Credential struct {
	token string // the ownership token; unexported so it can only leave this package into a child git env
}

// NewCredential wraps a per-fire ownership token. An empty token yields the empty credential
// (the bare-clone path), so callers can pass through OwnershipProof.Token unconditionally.
func NewCredential(token string) Credential { return Credential{token: token} }

// IsEmpty reports whether there is no token to authenticate with (the bare-clone branch).
func (c Credential) IsEmpty() bool { return c.token == "" }

// String redacts. It NEVER returns the token — so logging a Credential (or an error/struct that
// interpolates one) cannot leak it. This is the active leak-guard behind AC #2.
func (c Credential) String() string {
	if c.token == "" {
		return "checkout.Credential(empty)"
	}
	return "checkout.Credential(REDACTED)"
}

// GoString redacts too, so a %#v cannot leak the token either.
func (c Credential) GoString() string { return c.String() }

// ApplyTo sets an `Authorization: Bearer <token>` header on req FROM the unexported token,
// in place. It is the ONLY sanctioned egress of the token into a registry request (PLAN-200
// artifact acquisition): it never returns the plaintext, never stores it in another struct,
// and never logs it — so the token's only exit stays inside this package (threat 3). A value
// receiver, so it works on a Credential held in a map/struct without a pointer. The empty
// credential and a nil req are no-ops, leaving the request unauthenticated (bare fetch).
//
// There is deliberately NO token getter/serializer anywhere: header construction happens
// here, in place, so no caller can obtain the raw token to leak it.
func (c Credential) ApplyTo(req *http.Request) {
	if c.token == "" || req == nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
}

// ApplyBasicAuth is the sibling for registries that require HTTP Basic (the token as the
// password under a fixed username). It uses (*http.Request).SetBasicAuth, which base64-encodes
// in place and never surfaces the plaintext. Same custody guarantee as ApplyTo: value
// receiver, no return of the token, no store, no log.
func (c Credential) ApplyBasicAuth(req *http.Request, username string) {
	if c.token == "" || req == nil {
		return
	}
	req.SetBasicAuth(username, c.token)
}

// credentialContextKey is a private, unexported context-key type ⇒ collision-free with any
// other package's context values.
type credentialContextKey struct{}

// WithCredential returns a context carrying cred for a downstream Checkout.Fetch. This is how
// the per-fire ownership token reaches GitCheckout WITHOUT widening the shared Checkout seam:
// request-scoped, in-flight, never at rest (the model-key posture, AC #4). An empty credential
// is treated as none, so the returned context takes the unauthenticated path unchanged.
func WithCredential(ctx context.Context, cred Credential) context.Context {
	if cred.IsEmpty() {
		return ctx
	}
	return context.WithValue(ctx, credentialContextKey{}, cred)
}

// CredentialFrom extracts the per-fire credential a caller stashed with WithCredential, or the
// empty credential if none — so an unauthenticated caller (public repo / hermetic fake / local
// ambient-cred dev) takes exactly today's bare path.
func CredentialFrom(ctx context.Context) Credential {
	if c, ok := ctx.Value(credentialContextKey{}).(Credential); ok {
		return c
	}
	return Credential{}
}
