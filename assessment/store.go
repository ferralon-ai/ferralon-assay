package assessment

import (
	"errors"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/ids"
)

// ErrNotFound is returned when an Assessment id is absent from the store.
var ErrNotFound = errors.New("assessment: not found")

// Store is the durable Assessment record store.
type Store interface {
	Create(r Request) (*Assessment, error) // assigns UUIDv7, Status=queued, CreatedAt
	Get(id string) (*Assessment, error)    // ErrNotFound if absent
	Update(a *Assessment) error            // persist a mutated assessment
}

// MemStore is an in-memory Store. Callers that need durability supply their own.
type MemStore struct {
	mu   sync.RWMutex
	byID map[string]*Assessment
}

// NewMemStore returns an empty in-memory Store.
func NewMemStore() *MemStore {
	return &MemStore{byID: make(map[string]*Assessment)}
}

// Create assigns a UUIDv7 id, sets Status=StatusQueued and CreatedAt, caches the
// request's OwnershipProof on the record, and stores a copy.
func (s *MemStore) Create(r Request) (*Assessment, error) {
	a := &Assessment{
		ID:             ids.New(),
		Status:         StatusQueued,
		Request:        r,
		OwnershipProof: r.OwnershipProof,
		// Capture the subject snapshot at launch from the requested coordinates: downstream
		// consumers key off Subject, not Request, so leaving it empty here would strand them.
		// ResolvedCommit stays empty; the checkout stage pins it.
		Subject: SubjectSnapshot{
			URL:           r.Codebase.Repo,
			Ref:           r.Codebase.Revision,
			Vulnerability: r.Vulnerability,
		},
		CreatedAt: time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := *a
	s.byID[a.ID] = &stored
	return a, nil
}

// Get returns a copy of the Assessment by id, or ErrNotFound.
func (s *MemStore) Get(id string) (*Assessment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *a
	return &cp, nil
}

// Update persists a mutated Assessment. ErrNotFound if the id is unknown.
func (s *MemStore) Update(a *Assessment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[a.ID]; !ok {
		return ErrNotFound
	}
	cp := *a
	s.byID[a.ID] = &cp
	return nil
}
