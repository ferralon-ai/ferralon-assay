package artifactcache

import (
	"errors"
	"fmt"
)

// The acquisition failure taxonomy (PLAN-200). These are ADDITIVE siblings of
// ErrDeclaredAbsent: they add no method to Store/Handle, change no existing signature,
// and are invisible to noexec_test.go layer-1 (errors are values, not methods). The
// load-bearing invariant behind all of them: acquisition writes to the canonical
// content-addressed path ONLY after full digest verification (atomic temp->rename), so
// no failed acquisition can ever leave a zero-byte artifact that Store.Lookup would
// serve as a successful empty Handle. Each outcome maps to exactly one sentinel; none is
// an empty success.
var (
	// ErrIntegrityMismatch: fetched bytes' hash != ref.Digest. Active-tampering signal —
	// telemeter loudly; never degrade into a silent partial a retry could launder clean.
	ErrIntegrityMismatch = errors.New("artifactcache: integrity mismatch (fetched bytes' hash != ref.Digest)")
	// ErrPolicyRefused: off-allowlist host, non-HTTPS, missing credential for a private
	// registry, or a disallowed/downgrading/looping redirect. No fetch, no credential leak.
	ErrPolicyRefused = errors.New("artifactcache: policy refused (off-allowlist host, non-HTTPS, missing credential, or disallowed redirect)")
	// ErrUnpinnedArtifact: the coordinate does not resolve to a single verifiable
	// (url, digest). Python wheel-selection gap (OQ2) and deferred Maven both surface here.
	ErrUnpinnedArtifact = errors.New("artifactcache: unpinned artifact (coordinate does not resolve to a single verifiable (url, digest))")
	// ErrMalformedRef: ref.Digest failed the decode-validate gate (unknown algo,
	// undecodable payload, or wrong byte length). An inventory/caller BUG, not a
	// partiality — a resolver should never emit it. Kept out of the four so a real
	// partiality is never masked by a validation error; surfaces on Acquire and Lookup.
	ErrMalformedRef = errors.New("artifactcache: malformed ref digest (failed decode-validate gate)")
)

// Policy-refusal reason codes (non-secret, matchable telemetry).
const (
	PolicyOffAllowlist         = "off-allowlist"
	PolicyNonHTTPS             = "non-https"
	PolicyMissingCredential    = "missing-credential"
	PolicyUserinfoInURL        = "userinfo-in-url"
	PolicyRedirectOffAllowlist = "redirect-off-allowlist"
	PolicyRedirectDowngrade    = "https-downgrade-on-redirect"
	PolicyRedirectHopCap       = "redirect-hop-cap-exceeded"
	PolicyNoBackend            = "no-backend-for-ecosystem"
)

// IsPartiality reports whether err is one of the four typed declared-partial outcomes —
// MISS / INTEGRITY / POLICY / UNPINNED — so a caller can route all four to a
// declared-partial result in one check. ErrMalformedRef is deliberately EXCLUDED: it is a
// bug to surface loudly, not a partiality to absorb.
func IsPartiality(err error) bool {
	return errors.Is(err, ErrDeclaredAbsent) ||
		errors.Is(err, ErrIntegrityMismatch) ||
		errors.Is(err, ErrPolicyRefused) ||
		errors.Is(err, ErrUnpinnedArtifact)
}

// IntegrityReason carries non-secret context for an integrity failure. It holds only the
// hex canonical forms of the expected and computed digests — NEVER the bytes, never a
// credential — so it is secret-free by construction under every fmt verb.
type IntegrityReason struct {
	PURL              string
	Algo              string
	ExpectedCanonical string // "<algo>:<hex>"
	GotCanonical      string // "<algo>:<hex>"
}

func (r *IntegrityReason) Error() string {
	return fmt.Sprintf("artifactcache: integrity mismatch for %s: expected %s, got %s",
		r.PURL, r.ExpectedCanonical, r.GotCanonical)
}

func (r *IntegrityReason) Unwrap() error { return ErrIntegrityMismatch }

// PolicyReason carries the refused host and a matchable Code (one of the Policy*
// constants). It holds NO credential/token, so it is secret-free by construction.
type PolicyReason struct {
	PURL string
	Host string
	Code string
}

func (r *PolicyReason) Error() string {
	return fmt.Sprintf("artifactcache: policy refused for %s (host %q): %s", r.PURL, r.Host, r.Code)
}

func (r *PolicyReason) Unwrap() error { return ErrPolicyRefused }

// UnpinnedReason explains why a coordinate did not resolve to a single verifiable
// artifact. Detail is a stable, matchable token (e.g. "python-wheel-selection-gap").
type UnpinnedReason struct {
	PURL   string
	Detail string
}

func (r *UnpinnedReason) Error() string {
	return fmt.Sprintf("artifactcache: unpinned artifact for %s: %s", r.PURL, r.Detail)
}

func (r *UnpinnedReason) Unwrap() error { return ErrUnpinnedArtifact }

// MalformedReason explains why a ref.Digest failed the decode-validate gate.
type MalformedReason struct {
	PURL   string
	Algo   string
	Detail string
}

func (r *MalformedReason) Error() string {
	return fmt.Sprintf("artifactcache: malformed ref digest (algo %q): %s", r.Algo, r.Detail)
}

func (r *MalformedReason) Unwrap() error { return ErrMalformedRef }
