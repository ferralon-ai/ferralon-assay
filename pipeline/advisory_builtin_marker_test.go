package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// TestAdvisoryIntake_BuiltInMarkedByOrigin: S1 marks a record built_in only when the built-in table
// answered it. A corpus record that declares itself first-party, and even writes built_in into its
// own document, stays unmarked; the same chain answering a table id marks it.
func TestAdvisoryIntake_BuiltInMarkedByOrigin(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"CVE-TEST-SELF-CLAIM": `{"schema_version":"ferralon.normalized_advisory.v3","vuln_id":"CVE-TEST-SELF-CLAIM","version_scheme":"gomod","module":"example.com/claim","symbols":["Claim"],"built_in":true,"provenance":{"source":"curated","trust_tier":"first_party"}}`,
	})
	chain := NewChainSource(NewArtifactSource(root), NewTableSource())
	tests := []struct {
		id        string
		wantTrust string
		want      bool
	}{
		{"CVE-TEST-SELF-CLAIM", string(TrustFirstParty), false},
		{"FERRALON-JAVA-SSRF-0002", string(TrustFirstParty), true},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-builtin", Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: tt.id, Source: "corpus"},
			}}
			if err := (advisoryIntake{src: chain}).Run(context.Background(), c, store); err != nil {
				t.Fatal(err)
			}
			arts, err := store.Query(c.ID, artifact.TypeNormalizedAdvisory)
			if err != nil || len(arts) != 1 {
				t.Fatalf("normalized advisory: %d artifacts, err %v", len(arts), err)
			}
			var got struct {
				TrustTier string `json:"trust_tier"`
				BuiltIn   bool   `json:"built_in"`
			}
			if err := json.Unmarshal(arts[0].Payload, &got); err != nil {
				t.Fatal(err)
			}
			if got.TrustTier != tt.wantTrust {
				t.Fatalf("trust_tier = %q, want %q", got.TrustTier, tt.wantTrust)
			}
			if got.BuiltIn != tt.want {
				t.Errorf("built_in = %v, want %v", got.BuiltIn, tt.want)
			}
		})
	}
}
