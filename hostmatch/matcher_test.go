package hostmatch

import (
	"errors"
	"sync"
	"testing"
)

// mainMatcher is the shared allowlist used by the bulk of the Allows table tests.
var mainPatterns = []string{
	"github.com",
	"*.ghe.com",
	"git-codecommit.*.amazonaws.com",
	"10.0.0.0/8",
	"2001:db8::/32",
	"203.0.113.7",
}

func mustNew(t *testing.T, patterns []string) *Matcher {
	t.Helper()
	m, err := New(patterns)
	if err != nil {
		t.Fatalf("New(%v) unexpected error: %v", patterns, err)
	}
	return m
}

// TestAllows_MainMatrix drives the primary allow/deny/error matrix.
func TestAllows_MainMatrix(t *testing.T) {
	m := mustNew(t, mainPatterns)

	tests := []struct {
		name    string
		host    string
		want    bool
		wantErr bool
	}{
		// --- Name allow ---
		{"exact name", "github.com", true, false},
		{"exact name case-fold", "GitHub.CoM", true, false},
		{"wildcard one label", "acme.ghe.com", true, false},
		{"wildcard hyphen label", "a-b.ghe.com", true, false},
		{"interior wildcard", "git-codecommit.us-east-1.amazonaws.com", true, false},

		// --- Name deny (well-formed, false/nil) ---
		{"prefix anchor unconsumed label", "sub.github.com", false, false},
		{"suffix anchor", "github.com.evil.com", false, false},
		{"lexical prefix not subdomain", "evilgithub.com", false, false},
		{"lexical prefix 2", "notgithub.com", false, false},
		{"wildcard needs a label (bare apex)", "ghe.com", false, false},
		{"wildcard is single label only", "a.b.ghe.com", false, false},
		{"wildcard apex suffix anchor", "ghe.com.evil.com", false, false},
		{"interior wildcard two labels in slot", "git-codecommit.a.b.amazonaws.com", false, false},
		{"unlisted name", "example.com", false, false},

		// --- IP allow ---
		{"ipv4 in /8", "10.255.1.2", true, false},
		{"ipv6 in /32", "2001:db8::dead", true, false},
		{"ipv4 exact", "203.0.113.7", true, false},
		{"v4-mapped equals v4 in /8", "::ffff:10.0.0.9", true, false},

		// --- IP deny ---
		{"ipv4 outside /8", "11.0.0.1", false, false},
		{"v4-mapped out of range denies", "::ffff:11.0.0.1", false, false},
		{"ipv4 adjacent to exact", "203.0.113.8", false, false},
		{"ipv6 outside /32", "2001:db9::1", false, false},
		{"ipv4 unlisted", "192.0.2.1", false, false},

		// --- Alternate v4 encodings: ParseIP nil -> name branch. All are LDH-valid
		// single/multi labels, so they MISS the trie -> (false, nil). Never (true, …). ---
		{"hex-octet encoding", "0x0a.0.0.1", false, false},
		{"leading-zero octet", "012.0.0.1", false, false},
		{"integer encoding", "167772161", false, false},

		// --- Input contract -> ERROR (false, err) ---
		{"CIDR on input", "10.0.0.0/8", false, true},
		{"slash foo/bar", "foo/bar", false, true},
		{"path suffix", "github.com/x", false, true},
		{"host with port", "github.com:443", false, true},
		{"bracketed ipv6", "[2001:db8::1]", false, true},
		{"zone id", "fe80::1%eth0", false, true},
		{"literal wildcard on input", "*.ghe.com", false, true},
		{"empty host", "", false, true},
		{"underscore non-LDH", "foo_bar.com", false, true},
		{"oversize 64-char label", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.Allows(tc.host)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Allows(%q) = (%v, nil); want error", tc.host, got)
				}
				if !errors.Is(err, ErrMalformedHost) {
					t.Fatalf("Allows(%q) err = %v; want ErrMalformedHost", tc.host, err)
				}
			} else if err != nil {
				t.Fatalf("Allows(%q) unexpected error: %v", tc.host, err)
			}
			if got != tc.want {
				t.Fatalf("Allows(%q) = %v; want %v", tc.host, got, tc.want)
			}
			// Global invariant: NEVER (true, non-nil).
			if got && err != nil {
				t.Fatalf("Allows(%q) returned (true, %v) — forbidden", tc.host, err)
			}
		})
	}
}

// TestAllows_ExactVsWildcardBacktrack proves the trie tries an exact child then
// backtracks to the wildcard edge, and that a two-label input is denied.
func TestAllows_ExactVsWildcardBacktrack(t *testing.T) {
	m := mustNew(t, []string{"foo.example.com", "*.example.com"})

	tests := []struct {
		host string
		want bool
	}{
		{"foo.example.com", true},  // exact
		{"bar.example.com", true},  // wildcard
		{"a.b.example.com", false}, // two labels vs single "*"
		{"example.com", false},     // wildcard needs a label
	}
	for _, tc := range tests {
		got, err := m.Allows(tc.host)
		if err != nil {
			t.Fatalf("Allows(%q) unexpected error: %v", tc.host, err)
		}
		if got != tc.want {
			t.Fatalf("Allows(%q) = %v; want %v", tc.host, got, tc.want)
		}
	}
}

// TestAllows_ExactPrefixDeadEndBacktrack is the load-bearing backtrack case: an
// exact-prefix label ("b") is a live trie node that dead-ends (non-terminal), so the
// walk MUST fall back to the sibling wildcard edge. A naive leftmost-only or
// exact-preferring-without-fallback walk would wrongly deny b.example.com.
func TestAllows_ExactPrefixDeadEndBacktrack(t *testing.T) {
	m := mustNew(t, []string{"a.b.example.com", "*.example.com"})

	tests := []struct {
		host string
		want bool
	}{
		{"a.b.example.com", true},  // exact deep match
		{"b.example.com", true},    // "b" node exists but dead-ends -> must match wildcard
		{"c.example.com", true},    // plain wildcard
		{"x.b.example.com", false}, // two labels below example vs single "*"
	}
	for _, tc := range tests {
		got, err := m.Allows(tc.host)
		if err != nil {
			t.Fatalf("Allows(%q) unexpected error: %v", tc.host, err)
		}
		if got != tc.want {
			t.Fatalf("Allows(%q) = %v; want %v", tc.host, got, tc.want)
		}
	}
}

// TestNew_ConstructionErrors covers the construction-side guardrails.
func TestNew_ConstructionErrors(t *testing.T) {
	bad := []struct {
		name     string
		patterns []string
	}{
		{"bare wildcard", []string{"*"}},
		{"wildcard one fixed label", []string{"*.com"}},
		{"two wildcards", []string{"*.*.ghe.com"}},
		{"partial-label wildcard", []string{"foo*.com"}},
		{"bad v4 mask", []string{"10.0.0.0/33"}},
		{"bad v6 mask", []string{"::1/129"}},
		{"bad LDH underscore", []string{"foo_bar.com"}},
		{"empty pattern", []string{""}},
		{"leading hyphen label", []string{"-foo.com"}},
		{"trailing hyphen label", []string{"foo-.com"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.patterns); err == nil {
				t.Fatalf("New(%v) = nil error; want error", tc.patterns)
			}
		})
	}
}

// TestNew_ValidPatterns confirms the accepted grammar compiles cleanly.
func TestNew_ValidPatterns(t *testing.T) {
	ok := []string{
		"github.com",
		"*.ghe.com",
		"git-codecommit.*.amazonaws.com",
		"10.0.0.1",
		"2001:db8::1",
		"10.0.0.0/8",
		"2001:db8::/32",
		"xn--nxasmq6b.example.com", // punycode label stays valid LDH
	}
	if _, err := New(ok); err != nil {
		t.Fatalf("New(%v) unexpected error: %v", ok, err)
	}
}

// TestNew_IPv6ExactNotWideRange guards the family-correct full-mask: an exact IPv6
// host must admit ONLY itself, never a surrounding range.
func TestNew_IPv6ExactNotWideRange(t *testing.T) {
	m := mustNew(t, []string{"2001:db8::1"})

	if got, err := m.Allows("2001:db8::1"); err != nil || !got {
		t.Fatalf("Allows(exact ipv6) = (%v, %v); want (true, nil)", got, err)
	}
	// A neighbor that would be admitted if the mask were mistakenly /32.
	if got, err := m.Allows("2001:db8::2"); err != nil || got {
		t.Fatalf("Allows(neighbor ipv6) = (%v, %v); want (false, nil)", got, err)
	}
}

// TestAllows_NeverTrueWithError is a property-style assertion over a broad host set:
// if err != nil then the result must be false.
func TestAllows_NeverTrueWithError(t *testing.T) {
	m := mustNew(t, mainPatterns)
	hosts := []string{
		"github.com", "GitHub.CoM", "acme.ghe.com", "git-codecommit.us-east-1.amazonaws.com",
		"sub.github.com", "github.com.evil.com", "ghe.com", "example.com",
		"10.255.1.2", "203.0.113.7", "::ffff:10.0.0.9", "11.0.0.1", "2001:db9::1",
		"0x0a.0.0.1", "012.0.0.1", "167772161",
		"10.0.0.0/8", "foo/bar", "github.com:443", "[2001:db8::1]", "fe80::1%eth0",
		"*.ghe.com", "", "foo_bar.com",
	}
	for _, h := range hosts {
		got, err := m.Allows(h)
		if err != nil && got {
			t.Fatalf("Allows(%q) = (true, %v) — forbidden (true,non-nil)", h, err)
		}
	}
}

// TestAllows_Concurrent exercises a single immutable Matcher from many goroutines
// under the race detector.
func TestAllows_Concurrent(t *testing.T) {
	m := mustNew(t, mainPatterns)
	hosts := []string{
		"github.com", "acme.ghe.com", "git-codecommit.eu-west-1.amazonaws.com",
		"10.1.2.3", "2001:db8::beef", "203.0.113.7", "evil.com", "sub.github.com",
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				for _, h := range hosts {
					_, _ = m.Allows(h)
				}
			}
		}()
	}
	wg.Wait()
}
