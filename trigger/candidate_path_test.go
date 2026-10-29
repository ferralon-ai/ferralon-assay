package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

// TestCandidatePath_StableAcrossPairs proves the label and the candidate decision read every
// pair rather than whichever one Query happens to return first.
func TestCandidatePath_StableAcrossPairs(t *testing.T) {
	sink := artifact.Ref{ID: "sink", Type: artifact.TypeCandidatePair}
	ingress := &artifact.Ref{ID: "ingress", Type: artifact.TypeIngressMap}
	plain := artifact.CandidatePair{Sink: sink}
	entry := artifact.CandidatePair{Sink: sink, Ingress: ingress}

	tests := []struct {
		name     string
		pairs    []artifact.CandidatePair
		garbage  int
		wantPath string
		wantOK   bool
	}{
		{"no pairs", nil, 0, "", false},
		{"one pair without an ingress", []artifact.CandidatePair{plain}, 0, "advisory symbol reachable", true},
		{"pairs without an ingress", []artifact.CandidatePair{plain, plain, plain}, 0, "advisory symbol reachable", true},
		{"one ingress pair among many without", []artifact.CandidatePair{plain, plain, plain, plain, plain, plain, plain, entry}, 0, "entrypoint → advisory symbol", true},
		{"only undecodable pairs", nil, 2, "", false},
		{"undecodable pairs beside a decodable one", []artifact.CandidatePair{plain}, 3, "advisory symbol reachable", true},
		{"undecodable pairs beside an ingress pair", []artifact.CandidatePair{entry}, 3, "entrypoint → advisory symbol", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Query iterates a map, so repeat with fresh stores to cover different orders.
			for range 20 {
				store := artifact.NewMemStore()
				const aid = "a1"
				for _, p := range tc.pairs {
					putJSON(t, store, aid, artifact.TypeCandidatePair, p)
				}
				for range tc.garbage {
					if _, err := store.Put(&artifact.Artifact{AssessmentID: aid, Type: artifact.TypeCandidatePair, Payload: []byte(`[`)}); err != nil {
						t.Fatalf("put: %v", err)
					}
				}
				path, ok := candidatePath(store, aid)
				if path != tc.wantPath || ok != tc.wantOK {
					t.Fatalf("candidatePath = (%q, %v), want (%q, %v)", path, ok, tc.wantPath, tc.wantOK)
				}
				if hasCandidate(store, aid) != tc.wantOK {
					t.Fatalf("hasCandidate = %v, want %v", !tc.wantOK, tc.wantOK)
				}
			}
		})
	}
}
