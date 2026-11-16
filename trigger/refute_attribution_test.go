package trigger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// A refute's detail names the advisory record it relied on (tracker#633); a result with no
// source adds nothing.
func TestRefuteAttribution(t *testing.T) {
	const rec = "sha256:0123456789abcdef0123456789abcdef"
	const corp = "sha256:fedcba9876543210fedcba9876543210"
	tests := []struct {
		name string
		src  *pipeline.RefuteSource
		want string
	}{
		{"nil source", nil, ""},
		{"no advisory id", &pipeline.RefuteSource{Corpus: corp}, ""},
		{"advisory only", &pipeline.RefuteSource{Advisory: "CVE-2026-5038"}, " (per advisory CVE-2026-5038)"},
		{
			"public bundle record",
			&pipeline.RefuteSource{Advisory: "CVE-2026-5038", Record: rec, Corpus: corp},
			" (per advisory CVE-2026-5038, record sha256:0123456789ab, corpus sha256:fedcba987654)",
		},
		{
			"customer feed",
			&pipeline.RefuteSource{Advisory: "ACME-1", Record: rec, Corpus: corp, Feed: "acme-feed", TrustTier: "byo"},
			" (per advisory ACME-1, record sha256:0123456789ab, corpus sha256:fedcba987654, feed acme-feed)",
		},
		{
			"built-in record",
			&pipeline.RefuteSource{Advisory: "FERRALON-JAVA-SSRF-0001", BuiltIn: true},
			" (per advisory FERRALON-JAVA-SSRF-0001, built into the scanner)",
		},
		{
			"overlong feed name is cut",
			&pipeline.RefuteSource{Advisory: "ACME-2", Feed: strings.Repeat("f", 70)},
			" (per advisory ACME-2, feed " + strings.Repeat("f", 64) + "…)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refuteAttribution(tt.src); got != tt.want {
				t.Fatalf("refuteAttribution = %q, want %q", got, tt.want)
			}
		})
	}
}

// End to end: a version refute carrying a source surfaces that source in the finding's detail.
func TestFinding_VersionRefuteNamesRecord(t *testing.T) {
	store := artifact.NewMemStore()
	payload, err := json.Marshal(pipeline.DisqualResult{
		Disqualified: true,
		Reason:       pipeline.ReasonVersionNotInRange,
		Source:       &pipeline.RefuteSource{Advisory: "CVE-2026-5038", Record: "sha256:0123456789abcdef", Corpus: "sha256:fedcba9876543210"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{AssessmentID: "a1", Type: artifact.TypeDiscovery, ProducedBy: "test", Payload: payload}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	f := finding(store, "a1", report.Advisory{ID: "CVE-2026-5038", Source: "test"}, nil)
	for _, want := range []string{"outside the advisory's affected range", "per advisory CVE-2026-5038, record sha256:0123456789ab, corpus sha256:fedcba987654"} {
		if !strings.Contains(f.Evidence.Detail, want) {
			t.Fatalf("detail %q lacks %q", f.Evidence.Detail, want)
		}
	}
}
