package artifact_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

func TestMemStorePutGetRoundTrip(t *testing.T) {
	s := artifact.NewMemStore()
	a := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000010",
		Type:         artifact.TypeInventory,
		Descriptor:   "test-inventory",
		ProducedBy:   "codebase_inventory",
		Payload:      []byte(`{"packages":[]}`),
	}

	ref, err := s.Put(a)
	if err != nil {
		t.Fatalf("Put returned error: %v", err)
	}
	if ref.ID == "" {
		t.Fatal("Put returned empty Ref.ID")
	}
	if ref.Type != artifact.TypeInventory {
		t.Errorf("Ref.Type = %q; want %q", ref.Type, artifact.TypeInventory)
	}
	if !strings.HasPrefix(a.ContentHash, "sha256:") {
		t.Errorf("ContentHash = %q; want sha256: prefix", a.ContentHash)
	}
	// Verify the hash length: "sha256:" + 64 hex chars
	if len(a.ContentHash) != 7+64 {
		t.Errorf("ContentHash length = %d; want 71", len(a.ContentHash))
	}

	got, err := s.Get(ref.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.ID != ref.ID {
		t.Errorf("Get returned ID %q; want %q", got.ID, ref.ID)
	}
	if string(got.Payload) != string(a.Payload) {
		t.Errorf("Get Payload = %q; want %q", got.Payload, a.Payload)
	}
	if !strings.HasPrefix(got.ContentHash, "sha256:") {
		t.Errorf("stored ContentHash = %q; want sha256: prefix", got.ContentHash)
	}
	if got.CreatedAt.IsZero() {
		t.Error("stored CreatedAt is zero")
	}
}

func TestMemStoreGetUnknown(t *testing.T) {
	s := artifact.NewMemStore()
	_, err := s.Get("does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing artifact, got nil")
	}
	if !errors.Is(err, artifact.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemStoreQuery(t *testing.T) {
	s := artifact.NewMemStore()
	caseA := "01900000-0000-7000-8000-000000000020"
	caseB := "01900000-0000-7000-8000-000000000021"

	// Put two artifacts for caseA, one for caseB, one different type for caseA.
	put := func(caseID string, typ artifact.Type, payload string) {
		_, err := s.Put(&artifact.Artifact{
			AssessmentID: caseID,
			Type:         typ,
			Payload:      []byte(payload),
		})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	put(caseA, artifact.TypeInventory, `{"a":1}`)
	put(caseA, artifact.TypeInventory, `{"a":2}`)
	put(caseA, artifact.TypeReachability, `{"a":3}`)
	put(caseB, artifact.TypeInventory, `{"b":1}`)

	results, err := s.Query(caseA, artifact.TypeInventory)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Query returned %d results; want 2", len(results))
	}
	for _, r := range results {
		if r.AssessmentID != caseA {
			t.Errorf("result has AssessmentID %q; want %q", r.AssessmentID, caseA)
		}
		if r.Type != artifact.TypeInventory {
			t.Errorf("result has Type %q; want %q", r.Type, artifact.TypeInventory)
		}
	}
}

func TestMemStoreIdenticalPayloadSameHash(t *testing.T) {
	s := artifact.NewMemStore()
	payload := []byte(`{"key":"value"}`)
	a1 := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000030",
		Type:         artifact.TypePublicPoC,
		Payload:      payload,
	}
	a2 := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000030",
		Type:         artifact.TypePublicPoC,
		Payload:      payload,
	}

	_, err := s.Put(a1)
	if err != nil {
		t.Fatalf("Put a1: %v", err)
	}
	_, err = s.Put(a2)
	if err != nil {
		t.Fatalf("Put a2: %v", err)
	}
	if a1.ContentHash != a2.ContentHash {
		t.Errorf("identical payloads produced different hashes: %q vs %q", a1.ContentHash, a2.ContentHash)
	}
}

func TestMemStorePutAssignsID(t *testing.T) {
	s := artifact.NewMemStore()
	a := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000040",
		Type:         artifact.TypeDiscovery,
		Payload:      []byte(`{}`),
	}
	if a.ID != "" {
		t.Fatal("precondition: ID should be empty before Put")
	}
	ref, err := s.Put(a)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if a.ID == "" {
		t.Error("Put did not assign ID to artifact")
	}
	if a.ID != ref.ID {
		t.Errorf("a.ID %q != ref.ID %q", a.ID, ref.ID)
	}
}

func TestMemStorePutSetsCreatedAt(t *testing.T) {
	s := artifact.NewMemStore()
	a := &artifact.Artifact{
		AssessmentID: "01900000-0000-7000-8000-000000000050",
		Type:         artifact.TypeDiscovery,
		Payload:      []byte(`{}`),
	}
	before := time.Now()
	_, err := s.Put(a)
	after := time.Now()
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if a.CreatedAt.Before(before) || a.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v not in expected range [%v, %v]", a.CreatedAt, before, after)
	}
}
