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
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.sentinel) {
			t.Errorf("errors.Is(%T, %v) = false, want true", tc.err, tc.sentinel)
		}
		// A reason must never carry an empty message.
		if tc.err.Error() == "" {
			t.Errorf("%T.Error() is empty", tc.err)
		}
	}
}
