package symbolresolution

import (
	"encoding/json"
	"testing"
)

// TestReasonRecognized pins the closed membership: the seven members recognize, "" and any
// unknown do not (empty is the resolved sentinel, not a reason — §1.2).
func TestReasonRecognized(t *testing.T) {
	tests := []struct {
		reason ResolutionReason
		want   bool
	}{
		{ReasonAdvisoryNamesNoSymbol, true},
		{ReasonArtifactNotIndexed, true},
		{ReasonSymbolIndexedNoMatch, true},
		{ReasonAssessTierGap, true},
		{ReasonResolverToolFailure, true},
		{ReasonOutOfLaneEcosystem, true},
		{ReasonEcosystemUnsupported, true},
		{"", false},
		{"unresolved", false},
		{"other", false},
		{"symbol-indexed-no-match ", false}, // trailing space is not the member
	}
	for _, tt := range tests {
		if got := tt.reason.Recognized(); got != tt.want {
			t.Errorf("Recognized(%q) = %v, want %v", tt.reason, got, tt.want)
		}
	}
}

// TestReasonUnmarshalFailsClosed is C2(b): an unknown reason value ERRORS on unmarshal rather
// than round-tripping as an opaque string, and "" errors too (a catch-all that round-trips is the
// laundering C2 forbids). A recognized member decodes cleanly.
func TestReasonUnmarshalFailsClosed(t *testing.T) {
	type wrap struct {
		Reason ResolutionReason `json:"reason"`
	}
	tests := []struct {
		name    string
		payload string
		wantErr bool
		want    ResolutionReason
	}{
		{"unknown value errors", `{"reason":"bogus"}`, true, ""},
		{"empty value errors", `{"reason":""}`, true, ""},
		{"generic catch-all errors", `{"reason":"unresolved"}`, true, ""},
		{"known member ok", `{"reason":"symbol-indexed-no-match"}`, false, ReasonSymbolIndexedNoMatch},
		{"another known member ok", `{"reason":"out-of-lane-ecosystem"}`, false, ReasonOutOfLaneEcosystem},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w wrap
			err := json.Unmarshal([]byte(tt.payload), &w)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("unmarshal %s: want error, got nil (decoded %q — laundered as opaque string)", tt.payload, w.Reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal %s: unexpected error %v", tt.payload, err)
			}
			if w.Reason != tt.want {
				t.Fatalf("unmarshal %s: got %q, want %q", tt.payload, w.Reason, tt.want)
			}
		})
	}
}
