package assessment

import (
	"testing"

	"github.com/google/uuid"
)

func sampleRequest() Request {
	return Request{
		Vulnerability:  VulnRef{ID: "GO-2021-0001", Source: "osv"},
		Codebase:       CodebaseRef{Repo: "github.com/acme/app", Revision: "abc123"},
		Execution:      ExecutionContext{Kind: "compose"},
		OwnershipProof: OwnershipProof{Token: "tok-123"},
	}
}

func TestCreateYieldsQueuedAssessmentWithUUIDv7(t *testing.T) {
	s := NewMemStore()
	c, err := s.Create(sampleRequest())
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if c.Status != StatusQueued {
		t.Errorf("Status = %q, want %q", c.Status, StatusQueued)
	}
	if c.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, want set")
	}
	u, err := uuid.Parse(c.ID)
	if err != nil {
		t.Fatalf("ID %q is not a UUID: %v", c.ID, err)
	}
	if u.Version() != 7 {
		t.Errorf("ID version = %d, want 7 (UUIDv7)", u.Version())
	}
	if c.Request.Vulnerability.ID != "GO-2021-0001" {
		t.Errorf("Request not preserved: %+v", c.Request)
	}
}

func TestGetRoundTrips(t *testing.T) {
	s := NewMemStore()
	created, err := s.Create(sampleRequest())
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	got, err := s.Get(created.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("Get ID = %q, want %q", got.ID, created.ID)
	}
	if got.Status != StatusQueued {
		t.Errorf("Get Status = %q, want %q", got.Status, StatusQueued)
	}
}

func TestGetUnknownReturnsErrNotFound(t *testing.T) {
	s := NewMemStore()
	_, err := s.Get("no-such-id")
	if err != ErrNotFound {
		t.Errorf("Get(unknown) error = %v, want ErrNotFound", err)
	}
}

func TestUpdatePersistsStatusChange(t *testing.T) {
	s := NewMemStore()
	c, err := s.Create(sampleRequest())
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	c.Status = StatusComplete
	c.VerdictID = "verdict-abc"
	if err := s.Update(c); err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	got, err := s.Get(c.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got.Status != StatusComplete {
		t.Errorf("after Update, Status = %q, want %q", got.Status, StatusComplete)
	}
	if got.VerdictID != "verdict-abc" {
		t.Errorf("after Update, VerdictID = %q, want %q", got.VerdictID, "verdict-abc")
	}
}

func TestUpdateUnknownReturnsErrNotFound(t *testing.T) {
	s := NewMemStore()
	err := s.Update(&Assessment{ID: "no-such-id"})
	if err != ErrNotFound {
		t.Errorf("Update(unknown) error = %v, want ErrNotFound", err)
	}
}
