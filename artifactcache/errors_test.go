package artifactcache

import (
	"errors"
	"fmt"
	"testing"
)

// Test 2.7: IsPartiality is true for the four declared partial outcomes and FALSE for
// ErrMalformedRef (a bug to surface loudly, not a partiality to absorb).
func TestIsPartiality(t *testing.T) {
	partial := []error{
		ErrDeclaredAbsent,
		ErrIntegrityMismatch,
		ErrPolicyRefused,
		ErrUnpinnedArtifact,
		ErrRegistryUnavailable,
		ErrRegistryUnreachable,
		&FetchReason{PURL: "pkg:npm/x@1", Host: "h", Code: FetchRateLimited, Status: 429},
		&FetchReason{PURL: "pkg:npm/x@1", Host: "h", Code: FetchDNSFailure},
		&IntegrityReason{PURL: "pkg:nuget/x@1"},
		&PolicyReason{PURL: "pkg:nuget/x@1", Code: PolicyOffAllowlist},
		&UnpinnedReason{PURL: "pkg:pypi/x@1", Detail: "python-wheel-selection-gap"},
		fmt.Errorf("wrapped: %w", ErrPolicyRefused),
	}
	for _, err := range partial {
		if !IsPartiality(err) {
			t.Errorf("IsPartiality(%v) = false, want true", err)
		}
	}

	notPartial := []error{
		ErrMalformedRef,
		&MalformedReason{Algo: "md5", Detail: "unknown algo"},
		fmt.Errorf("wrapped: %w", ErrMalformedRef),
		errors.New("some unrelated error"),
		nil,
	}
	for _, err := range notPartial {
		if IsPartiality(err) {
			t.Errorf("IsPartiality(%v) = true, want false", err)
		}
	}
}

// Reason types unwrap to their sentinel so errors.Is routes them, and their Error() strings
// are secret-free (they hold no Credential and no raw bytes by construction).
func TestReasonUnwrap(t *testing.T) {
	cases := []struct {
		err      error
		sentinel error
	}{
		{&IntegrityReason{PURL: "p", Algo: "sha256", ExpectedCanonical: "sha256:aa", GotCanonical: "sha256:bb"}, ErrIntegrityMismatch},
		{&PolicyReason{PURL: "p", Host: "h", Code: PolicyOffAllowlist}, ErrPolicyRefused},
		{&UnpinnedReason{PURL: "p", Detail: "python-wheel-selection-gap"}, ErrUnpinnedArtifact},
		{&MalformedReason{Algo: "md5", Detail: "unknown"}, ErrMalformedRef},
		{&FetchReason{PURL: "p", Host: "h", Code: FetchRateLimited, Status: 429}, ErrRegistryUnavailable},
		{&FetchReason{PURL: "p", Host: "h", Code: FetchServerError, Status: 503}, ErrRegistryUnavailable},
		{&FetchReason{PURL: "p", Host: "h", Code: FetchTimeout}, ErrRegistryUnavailable},
		{&FetchReason{PURL: "p", Host: "h", Code: FetchConnectionReset}, ErrRegistryUnavailable},
		{&FetchReason{PURL: "p", Host: "h", Code: FetchDNSFailure}, ErrRegistryUnreachable},
		{&FetchReason{PURL: "p", Host: "h", Code: FetchConnectFailure}, ErrRegistryUnreachable},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.sentinel) {
			t.Errorf("errors.Is(%T, %v) = false, want true", tc.err, tc.sentinel)
		}
		// A reason must never carry an empty message.
		if tc.err.Error() == "" {
			t.Errorf("%T.Error() is empty", tc.err)
		}
		// A registry failure is never evidence the artifact is absent.
		if errors.Is(tc.err, ErrDeclaredAbsent) {
			t.Errorf("errors.Is(%v, ErrDeclaredAbsent) = true, want false", tc.err)
		}
	}
}
