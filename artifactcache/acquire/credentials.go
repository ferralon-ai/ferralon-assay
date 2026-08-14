// Package acquire is the PLAN-200 network-acquisition seam for artifactcache: given an
// inventory Ref plus a resolved fetch coordinate it does a plain net/http GET, verifies the
// digest in-process with crypto/sha{1,256,512} BEFORE an atomic publish to the
// content-addressed path, and returns one of the typed taxonomy outcomes (never an empty
// success). It is a SEPARATE package from the artifactcache leaf precisely because it holds
// the credential and network surface the leaf must not (see artifactcache/doc.go): the leaf
// stays stdlib-only and acquisition-agnostic; this package owns the credential trust
// boundary (threat 3) and the third-party supply-chain surface (threat 2).
//
// It never executes target code: fetch/read bytes only, in-process hashing only, no os/exec,
// no shelling to mvn/npm/dotnet/pip (which would run lifecycle hooks). Method names avoid the
// noexec regex (Acquire, ResolveURL, For, ApplyTo).
package acquire

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// RegistryCredentials is the custody wrapper: a host -> checkout.Credential map that lets N
// private registries coexist (checkout.Credential is single-token/unscoped, so a second
// WithCredential would shadow the first). It WRAPS checkout.Credential and never
// reimplements custody: the values self-redact, so redaction is inherited verbatim, and the
// token never leaves checkout except via Credential.ApplyTo. It is in-process only,
// request-scoped via context, with no on-disk store (Q7 constraint 1).
type RegistryCredentials struct {
	byHost map[string]checkout.Credential
}

// NewRegistryCredentials builds a RegistryCredentials from a host->Credential map,
// canonicalizing each host key (lowercase, trailing dot stripped) so lookups match the
// canonicalized request host. An empty/nil map yields an all-anonymous set.
func NewRegistryCredentials(byHost map[string]checkout.Credential) RegistryCredentials {
	cp := make(map[string]checkout.Credential, len(byHost))
	for h, c := range byHost {
		cp[canonicalizeHostString(h)] = c
	}
	return RegistryCredentials{byHost: cp}
}

// For returns the credential bound to host, or the empty credential when none is bound. host
// is canonicalized before the lookup, so a credential is only ever returned for its exact
// bound host. A credential is never returned for a host it is not bound to — the mechanism
// behind "A's token never goes to B".
func (rc RegistryCredentials) For(host string) checkout.Credential {
	return rc.byHost[canonicalizeHostString(host)]
}

// String redacts. VALUE receiver (security-gate required change #2), so a RegistryCredentials
// held by value formats through this method under every fmt verb rather than dumping its map.
// It holds only self-redacting Credentials and non-secret host keys, but redacts explicitly
// for defense-in-depth (host names are not secret; the counts are not either).
func (rc RegistryCredentials) String() string {
	return fmt.Sprintf("acquire.RegistryCredentials(REDACTED; %d host(s))", len(rc.byHost))
}

// GoString redacts too (value receiver), so %#v cannot dump the underlying map.
func (rc RegistryCredentials) GoString() string { return rc.String() }

type registryCredentialsKey struct{}

// WithRegistryCredentials returns a context carrying rc for a downstream Acquire — the
// request-scoped, in-flight, never-at-rest posture inherited from checkout.WithCredential.
func WithRegistryCredentials(ctx context.Context, rc RegistryCredentials) context.Context {
	return context.WithValue(ctx, registryCredentialsKey{}, rc)
}

// RegistryCredentialsFrom extracts credentials stashed with WithRegistryCredentials, or an
// empty set if none.
func RegistryCredentialsFrom(ctx context.Context) RegistryCredentials {
	if rc, ok := ctx.Value(registryCredentialsKey{}).(RegistryCredentials); ok {
		return rc
	}
	return RegistryCredentials{}
}

// canonicalHost extracts and canonicalizes the host of u for the allowlist compare and the
// credential binding (security-gate required change #3). It uses url.Hostname() (never a
// hand-rolled split) to strip the port, lowercases, and strips a trailing dot; and it REJECTS
// any URL carrying userinfo (e.g. https://registry.npmjs.org@evil.com/) outright, since
// userinfo is a credential-misbinding / leak vector. Returns the canonical host, or an error
// naming the reason.
func canonicalHost(u *url.URL) (string, error) {
	if u.User != nil {
		return "", fmt.Errorf("url carries userinfo (%s)", PolicyUserinfo)
	}
	h := canonicalizeHostString(u.Hostname())
	if h == "" {
		return "", fmt.Errorf("url has no host")
	}
	return h, nil
}

// PolicyUserinfo is re-exported here only so canonicalHost's error message is self-describing;
// the canonical constant lives in the artifactcache package.
const PolicyUserinfo = "userinfo-in-url"

// canonicalizeHostString lowercases and strips a single trailing dot. Input is assumed to
// already be a bare hostname (no port/userinfo) — callers that start from a URL go through
// canonicalHost, which reads url.Hostname().
func canonicalizeHostString(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// Allowlist is a closed set of canonical HTTPS registry hosts. The zero value denies
// everything (default-DENY).
type Allowlist map[string]struct{}

// NewAllowlist builds an Allowlist from hosts, canonicalizing each. Off-list or non-HTTPS
// hosts are refused at fetch time (ErrPolicyRefused), never warned.
func NewAllowlist(hosts ...string) Allowlist {
	a := make(Allowlist, len(hosts))
	for _, h := range hosts {
		a[canonicalizeHostString(h)] = struct{}{}
	}
	return a
}

// Allows reports whether host h is on the allowlist. h is canonicalized defensively before
// the exact match, so a non-canonical input can never bypass or spuriously fail the gate;
// real call sites already pass canonicalHost() output, making this idempotent.
func (a Allowlist) Allows(h string) bool {
	_, ok := a[canonicalizeHostString(h)]
	return ok
}
