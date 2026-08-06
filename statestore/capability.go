package statestore

import (
	"context"
	"net/http"
	"sync"
)

// ensureRef resolves the state ref exactly once, lazily, before the first Read or
// Write. The resolution is the custom-ref capability probe: it decides whether the
// host accepts the candidate custom ref (DefaultRef, "refs/assay/state") or whether
// the adapter must cascade to FallbackRef ("refs/heads/assay/state", a hidden
// branch). The result is cached on the store so the common path costs at most one
// extra cheap round-trip on the first operation, never per-write (R6).
func (s *GitHubRefStore) ensureRef(ctx context.Context) error {
	s.probeOnce.Do(func() {
		s.probeErr = s.probedFn(ctx)
	})
	return s.probeErr
}

// probeCapability is the default capability resolver. It probes whether the host
// accepts the configured custom ref and selects the ref the store will use:
//
//   - If the candidate is already a plain branch ref (FallbackRef or any
//     "refs/heads/*"), no probe is needed — branch refs are accepted everywhere.
//   - Otherwise it asks the host whether the custom namespace is usable. GitHub
//     accepts custom refs (per the portability matrix), so the probe normally passes
//     and the store keeps DefaultRef. A host that rejects the custom namespace
//     (an HTTP 422 on the create endpoint, or a refs/heads/* allowlist enforced by a
//     pre-receive hook / branch protection) causes the cascade to FallbackRef.
//
// The probe is read-only and side-effect-free: it consults the ref's existence via
// GET. A real rejection of the custom namespace on GitHub manifests only at write
// time, so to keep the probe cheap and non-mutating we treat "the host answered the
// GET about the custom ref normally" (200 found, or 404 not-yet-created) as
// acceptance, and a hard 422 as the cascade trigger. Callers that need a definitive
// branch-protection answer get it for free: the first Write's force=false CAS
// surfaces a namespace rejection as ErrConflict and the operator falls back via
// configuration. For GitHub the matrix guarantees acceptance, so this stays a single
// cached GET.
func (s *GitHubRefStore) probeCapability(ctx context.Context) error {
	candidate := s.cfg.Ref
	if !isCustomRef(candidate) {
		s.ref = candidate
		return nil
	}

	accepted, err := s.customRefAccepted(ctx, candidate)
	if err != nil {
		return err
	}
	if accepted {
		s.ref = candidate
	} else {
		s.ref = FallbackRef
	}
	return nil
}

// customRefAccepted probes the host for the custom ref. A GET that returns 200
// (ref present) or 404 (ref absent but the namespace is addressable) means the host
// accepts the namespace. A 422 means the host rejects custom refs (the cascade
// signal). Any other status is treated as acceptance — GitHub is the matrix's
// custom-ref-accepting host, and an unexpected status should not silently downgrade
// to the visible fallback branch.
func (s *GitHubRefStore) customRefAccepted(ctx context.Context, ref string) (bool, error) {
	var discard ghRef
	status, err := s.do(ctx, http.MethodGet, "/git/ref/"+refPath(ref), nil, &discard)
	if err != nil {
		return false, err
	}
	if status == http.StatusUnprocessableEntity {
		return false, nil
	}
	return true, nil
}

// isCustomRef reports whether ref is a custom namespace (not a plain branch). Branch
// refs ("refs/heads/*") are accepted by every host, so they need no probe.
func isCustomRef(ref string) bool {
	const branchPrefix = "refs/heads/"
	return !hasPrefix(ref, branchPrefix)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// probeOnce / probeErr cache the one-time capability probe (R6). They live in
// capability.go alongside the probe logic; the store struct embeds them.
type probeState struct {
	probeOnce sync.Once
	probeErr  error
}
