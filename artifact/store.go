package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/ids"
)

// ErrNotFound is returned by Get when no artifact matches the given id.
var ErrNotFound = errors.New("artifact not found")

// Store is the content-addressed artifact store. Discovery is by (assessmentID, type).
type Store interface {
	// Put assigns ID (if empty), computes ContentHash from Payload, stores, returns Ref.
	Put(a *Artifact) (Ref, error)
	// Get returns the artifact by id, or ErrNotFound if absent.
	Get(id string) (*Artifact, error)
	// Query returns all artifacts for an assessment of a given type (semantic discovery).
	Query(assessmentID string, t Type) ([]*Artifact, error)
	// List returns all artifacts of a given type across every assessment in the corpus.
	// This is the cross-assessment discovery primitive episodic recall draws on; Query is
	// the per-assessment narrowing of the same scan.
	List(t Type) ([]*Artifact, error)
}

// MemStore is an in-memory Store.
type MemStore struct {
	mu   sync.RWMutex
	byID map[string]*Artifact
}

// NewMemStore creates an initialised, empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{byID: make(map[string]*Artifact)}
}

// Put assigns ID (if empty), computes ContentHash = "sha256:"+hex(sha256(Payload)),
// sets CreatedAt if zero, stores a copy, and returns a Ref.
func (s *MemStore) Put(a *Artifact) (Ref, error) {
	if a.ID == "" {
		a.ID = ids.New()
	}
	sum := sha256.Sum256(a.Payload)
	a.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}

	// Store a defensive copy.
	cp := *a
	payloadCopy := make([]byte, len(a.Payload))
	copy(payloadCopy, a.Payload)
	cp.Payload = payloadCopy

	s.mu.Lock()
	s.byID[cp.ID] = &cp
	s.mu.Unlock()

	return a.Ref(), nil
}

// Get returns the artifact for the given id, or ErrNotFound.
func (s *MemStore) Get(id string) (*Artifact, error) {
	s.mu.RLock()
	a, ok := s.byID[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	// Return a copy so callers cannot mutate internal state.
	cp := *a
	payloadCopy := make([]byte, len(a.Payload))
	copy(payloadCopy, a.Payload)
	cp.Payload = payloadCopy
	return &cp, nil
}

// Query returns all artifacts whose AssessmentID and Type match the given values.
func (s *MemStore) Query(assessmentID string, t Type) ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var results []*Artifact
	for _, a := range s.byID {
		if a.AssessmentID == assessmentID && a.Type == t {
			results = append(results, copyArtifact(a))
		}
	}
	return results, nil
}

// List returns all artifacts of the given type across every assessment.
func (s *MemStore) List(t Type) ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var results []*Artifact
	for _, a := range s.byID {
		if a.Type == t {
			results = append(results, copyArtifact(a))
		}
	}
	return results, nil
}

// copyArtifact returns a defensive deep copy (Payload slice copied) so callers
// cannot mutate stored state.
func copyArtifact(a *Artifact) *Artifact {
	cp := *a
	payloadCopy := make([]byte, len(a.Payload))
	copy(payloadCopy, a.Payload)
	cp.Payload = payloadCopy
	return &cp
}
