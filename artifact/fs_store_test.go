package artifact_test

import (
	"errors"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

func TestFSStore_PutAssignsIDAndContentHash(t *testing.T) {
	root := t.TempDir()
	s, err := artifact.NewFSStore(root)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	a := &artifact.Artifact{
		AssessmentID: "case-1",
		Type:         artifact.TypeReachability,
		Descriptor:   "d",
		ProducedBy:   "test",
		Payload:      []byte(`{"ok":true}`),
	}
	ref, err := s.Put(a)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if a.ID == "" {
		t.Fatal("ID not assigned")
	}
	if ref.ID != a.ID {
		t.Fatalf("ref.ID %q != a.ID %q", ref.ID, a.ID)
	}
	if ref.Type != artifact.TypeReachability {
		t.Fatalf("ref.Type = %q, want TypeReachability", ref.Type)
	}
	if a.ContentHash == "" {
		t.Fatal("ContentHash not set")
	}
	// sha256 of `{"ok":true}` must be present in the hash field.
	if len(a.ContentHash) < 8 || a.ContentHash[:7] != "sha256:" {
		t.Fatalf("ContentHash %q does not start with sha256:", a.ContentHash)
	}
}

func TestFSStore_PutGetRoundTripsPayload(t *testing.T) {
	root := t.TempDir()
	s, err := artifact.NewFSStore(root)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)
	a := &artifact.Artifact{
		AssessmentID: "case-2",
		Type:         artifact.TypeInventory,
		ProducedBy:   "stage1",
		Payload:      payload,
	}
	if _, err := s.Put(a); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Payload) != string(payload) {
		t.Fatalf("Payload = %q, want %q", got.Payload, payload)
	}
	if got.AssessmentID != "case-2" {
		t.Fatalf("AssessmentID = %q, want case-2", got.AssessmentID)
	}
	if got.Type != artifact.TypeInventory {
		t.Fatalf("Type = %q, want TypeInventory", got.Type)
	}
}

func TestFSStore_GetUnknownIDReturnsErrNotFound(t *testing.T) {
	root := t.TempDir()
	s, err := artifact.NewFSStore(root)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	_, err = s.Get("no-such-id")
	if !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("Get unknown: got %v, want ErrNotFound", err)
	}
}

func TestFSStore_QueryFiltersCorrectly(t *testing.T) {
	root := t.TempDir()
	s, err := artifact.NewFSStore(root)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	putArt := func(caseID string, t2 artifact.Type) {
		_, err := s.Put(&artifact.Artifact{
			AssessmentID: caseID,
			Type:         t2,
			ProducedBy:   "test",
			Payload:      []byte("{}"),
		})
		if err != nil {
			t.Fatalf("Put(%s,%s): %v", caseID, t2, err)
		}
	}

	putArt("case-A", artifact.TypeReachability)
	putArt("case-A", artifact.TypeInventory)
	putArt("case-B", artifact.TypeReachability)

	res, err := s.Query("case-A", artifact.TypeReachability)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("Query(case-A, reachability) = %d results, want 1", len(res))
	}
	if res[0].AssessmentID != "case-A" || res[0].Type != artifact.TypeReachability {
		t.Fatalf("unexpected result: %+v", res[0])
	}
}

func TestFSStore_Durability(t *testing.T) {
	root := t.TempDir()
	s1, err := artifact.NewFSStore(root)
	if err != nil {
		t.Fatalf("NewFSStore s1: %v", err)
	}
	a := &artifact.Artifact{
		AssessmentID: "case-dur",
		Type:         artifact.TypePoE,
		ProducedBy:   "stage",
		Payload:      []byte(`{"durable":true}`),
	}
	if _, err := s1.Put(a); err != nil {
		t.Fatalf("Put: %v", err)
	}

	s2, err := artifact.NewFSStore(root)
	if err != nil {
		t.Fatalf("NewFSStore s2: %v", err)
	}
	got, err := s2.Get(a.ID)
	if err != nil {
		t.Fatalf("s2.Get: %v", err)
	}
	if got.ID != a.ID {
		t.Fatalf("durability: ID %q vs %q", got.ID, a.ID)
	}
	if string(got.Payload) != `{"durable":true}` {
		t.Fatalf("durability: Payload %q", got.Payload)
	}
}
