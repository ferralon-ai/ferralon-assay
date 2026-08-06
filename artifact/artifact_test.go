package artifact_test

import (
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

func TestArtifactRef(t *testing.T) {
	a := &artifact.Artifact{
		ID:           "01900000-0000-7000-8000-000000000001",
		AssessmentID: "01900000-0000-7000-8000-000000000002",
		Type:         artifact.TypeReachability,
		ContentHash:  "sha256:abc",
		Descriptor:   "test descriptor",
		ProducedBy:   "test_stage",
		Payload:      []byte(`{}`),
		CreatedAt:    time.Now(),
	}

	ref := a.Ref()

	if ref.ID != a.ID {
		t.Errorf("Ref.ID = %q; want %q", ref.ID, a.ID)
	}
	if ref.Type != a.Type {
		t.Errorf("Ref.Type = %q; want %q", ref.Type, a.Type)
	}
}

func TestTypeConstants(t *testing.T) {
	// Assert every constant has the exact string value frozen in the contract.
	cases := []struct {
		got  artifact.Type
		want artifact.Type
	}{
		{artifact.TypeNormalizedAdvisory, "normalized_advisory"},
		{artifact.TypeInventory, "inventory"},
		{artifact.TypePublicPoC, "public_poc"},
		{artifact.TypeDisqualification, "disqualification"},
		{artifact.TypeDiscovery, "discovery"},
		{artifact.TypeVulnerableSymbol, "vulnerable_symbol"},
		{artifact.TypeReachability, "reachability"},
		{artifact.TypeIngressMap, "ingress_map"},
		{artifact.TypeCandidatePair, "candidate_pair"},
		{artifact.TypeTaint, "taint"},
		{artifact.TypeHarness, "harness"},
		{artifact.TypePoE, "proof_of_exploitability"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("constant mismatch: got %q, want %q", c.got, c.want)
		}
	}
}
