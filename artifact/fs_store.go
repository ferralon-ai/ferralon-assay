package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/ids"
	"github.com/ferralon-ai/ferralon-assay/internal/storage"
)

// Conformance assert: FSStore must satisfy Store.
var _ Store = (*FSStore)(nil)

// FSStore is a Store that persists Artifacts as JSON files under
// <root>/artifacts/<id>.json.
type FSStore struct {
	dir string
	mu  sync.RWMutex
}

// NewFSStore initialises the data root and returns a ready FSStore.
func NewFSStore(root string) (*FSStore, error) {
	if err := storage.Ensure(root); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FSStore{dir: dir}, nil
}

// Put mirrors MemStore.Put: assigns ID if empty, computes ContentHash, sets
// CreatedAt if zero, persists via WriteAtomic, and returns the Ref.
func (s *FSStore) Put(a *Artifact) (Ref, error) {
	if a.ID == "" {
		a.ID = ids.New()
	}
	sum := sha256.Sum256(a.Payload)
	a.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}

	data, err := json.Marshal(a)
	if err != nil {
		return Ref{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := storage.WriteAtomic(s.path(a.ID), data); err != nil {
		return Ref{}, err
	}
	return a.Ref(), nil
}

// Get returns the Artifact for the given id, or ErrNotFound (wrapped as the Mem store does).
func (s *FSStore) Get(id string) (*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return nil, err
	}
	var a Artifact
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Query scans the artifacts directory and returns all Artifacts matching assessmentID and type.
// Non-.json entries and *.tmp-* leftovers are skipped.
func (s *FSStore) Query(assessmentID string, t Type) ([]*Artifact, error) {
	return s.scan(t, func(a *Artifact) bool { return a.AssessmentID == assessmentID })
}

// List scans the artifacts directory and returns all Artifacts of the given type across
// every assessment (the cross-assessment corpus discovery primitive for recall).
func (s *FSStore) List(t Type) ([]*Artifact, error) {
	return s.scan(t, func(*Artifact) bool { return true })
}

// scan reads every artifact JSON of type t and returns those passing keep. Non-.json
// entries and *.tmp-* leftovers are skipped; unreadable/undecodable entries are skipped
// defensively.
func (s *FSStore) scan(t Type, keep func(*Artifact) bool) ([]*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var results []*Artifact
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.Contains(name, ".tmp-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			continue // skip unreadable entries defensively
		}
		var a Artifact
		if err := json.Unmarshal(data, &a); err != nil {
			continue
		}
		if a.Type == t && keep(&a) {
			results = append(results, &a)
		}
	}
	return results, nil
}

func (s *FSStore) path(id string) string {
	return filepath.Join(s.dir, id+".json")
}
