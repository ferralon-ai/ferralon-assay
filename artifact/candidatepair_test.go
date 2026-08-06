package artifact

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestCandidatePairSchemaVersionConst(t *testing.T) {
	if CandidatePairSchemaVersion != "tegron.candidate_pair.v1" {
		t.Fatalf("CandidatePairSchemaVersion = %q, want %q", CandidatePairSchemaVersion, "tegron.candidate_pair.v1")
	}
}

// TestCandidatePairWireShape locks the frozen (ingress, sink, path) contract: the
// always-present keys plus the omitempty ingress, so an accidental rename/retype fails.
func TestCandidatePairWireShape(t *testing.T) {
	full := CandidatePair{
		SchemaVersion: CandidatePairSchemaVersion,
		Sink:          Ref{ID: "sink-id", Type: TypeVulnerableSymbol},
		Ingress:       &Ref{ID: "ingress-id", Type: TypeIngressMap},
		Path:          Ref{ID: "path-id", Type: TypeReachability},
		Partial:       true,
	}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}
	got := keys(m)
	want := []string{"ingress", "partial", "path", "schema_version", "sink"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("full pair keys = %v, want %v", got, want)
	}
}

// TestCandidatePairOmitsIngressWhenNil asserts the declared-partiality omitempty: a
// pair with no known ingress drops the key rather than emitting null.
func TestCandidatePairOmitsIngressWhenNil(t *testing.T) {
	partial := CandidatePair{
		SchemaVersion: CandidatePairSchemaVersion,
		Sink:          Ref{ID: "sink-id", Type: TypeVulnerableSymbol},
		Path:          Ref{ID: "path-id", Type: TypeReachability},
		Partial:       true,
	}
	b, err := json.Marshal(partial)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal to map: %v", err)
	}
	if _, ok := m["ingress"]; ok {
		t.Fatalf("nil Ingress should be omitted, got keys %v", keys(m))
	}
}

func TestCandidatePairRoundTrips(t *testing.T) {
	want := CandidatePair{
		SchemaVersion: CandidatePairSchemaVersion,
		Sink:          Ref{ID: "sink-id", Type: TypeVulnerableSymbol},
		Ingress:       &Ref{ID: "ingress-id", Type: TypeIngressMap},
		Path:          Ref{ID: "path-id", Type: TypeReachability},
		Partial:       true,
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got CandidatePair
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func keys(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
