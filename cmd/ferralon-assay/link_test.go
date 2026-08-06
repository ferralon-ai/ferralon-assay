package main

import "testing"

func TestLinkedToConsole(t *testing.T) {
	// Fails closed: only an explicit, parseable true links the run. Everything else — unset,
	// empty, a typo, a word ParseBool doesn't accept — degrades to a standalone scan.
	cases := []struct {
		name string
		set  bool
		val  string
		want bool
	}{
		{"unset", false, "", false},
		{"empty", true, "", false},
		{"false", true, "false", false},
		{"true", true, "true", true},
		{"True", true, "True", true},
		{"one", true, "1", true},
		{"zero", true, "0", false},
		{"padded true", true, "  true  ", true},
		{"unparseable is not linked", true, "yes", false},
		{"typo is not linked", true, "ture", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(envLinkToConsole, tc.val)
			}
			if got := linkedToConsole(); got != tc.want {
				t.Fatalf("linkedToConsole() with %s=%q = %v, want %v", envLinkToConsole, tc.val, got, tc.want)
			}
		})
	}
}

func TestResolveEndpoint(t *testing.T) {
	const (
		baked    = "https://api.ferralon.com/ingest"
		override = "https://ghe.example/ferralon/ingest"
	)
	cases := []struct {
		name     string
		linked   bool
		override string
		baked    string
		want     string
	}{
		// The load-bearing case: the toggle wins over ANY configured URL. A customer who sets
		// link-to-console false must not be beaconed just because a URL is still lying around
		// in their workflow or baked into the release they pinned.
		{"unlinked beats a baked endpoint", false, "", baked, ""},
		{"unlinked beats an explicit override", false, override, baked, ""},

		{"linked uses the baked default", true, "", baked, baked},
		{"linked prefers the override", true, override, baked, override},
		{"linked with only an override", true, override, "", override},

		// An OSS build bakes nothing, so linking it resolves to off rather than to some
		// assumed host — location-is-tier default-deny survives the toggle.
		{"linked OSS build stays off", true, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveEndpoint(tc.linked, tc.override, tc.baked); got != tc.want {
				t.Fatalf("resolveEndpoint(%v, %q, %q) = %q, want %q", tc.linked, tc.override, tc.baked, got, tc.want)
			}
		})
	}
}

// TestBakedEndpointsEmptyByDefault pins the OSS posture: an ordinary `go build` (which is what
// `go test` links) must carry NO Ferralon endpoint. Only the publish pipeline's -ldflags stamps
// one in. If this fails, a host literal reached the source and the OSS binary is no longer inert.
func TestBakedEndpointsEmptyByDefault(t *testing.T) {
	if bakedIngestURL != "" || bakedRunsURL != "" {
		t.Fatalf("baked endpoints must be empty in an unstamped build, got ingest=%q runs=%q", bakedIngestURL, bakedRunsURL)
	}
}
