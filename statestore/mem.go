package statestore

import (
	"context"
	"fmt"
	"sync"
)

// MemStore is an in-memory StateStore. It exists so an example, a consumer's own
// tests, or a caller experimenting with the trigger API can run against a real
// StateStore with no git repository, no refs, and no filesystem.
//
// It honours the same fast-forward-only CAS contract as the git-ref store: Read
// hands out the current CommitSHA as the CAS token, and Write accepts a State only
// when that token still matches. A stale token is not an error — as in the git-ref
// store, Write re-applies the caller's intent onto the current state via Merge and
// commits that. There is no retry budget to exhaust (the mutex serialises writers
// and the merged write always succeeds), so MemStore never returns ErrConflict.
//
// CommitSHAs are synthetic ("mem-1", "mem-2", …), monotonic per store, and carry no
// meaning beyond CAS identity. The zero value is not usable; call NewMemStore.
type MemStore struct {
	mu      sync.Mutex
	state   *State
	writes  int
	written bool
}

// NewMemStore creates an empty MemStore. Read returns ErrNotFound until the first
// Write, mirroring a repository whose state ref does not exist yet.
func NewMemStore() *MemStore {
	return &MemStore{}
}

// Read returns a copy of the current State, including its CommitSHA CAS token. It
// returns ErrNotFound before the first Write.
func (s *MemStore) Read(ctx context.Context) (*State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.written {
		return nil, ErrNotFound
	}
	cp := *s.state
	return &cp, nil
}

// Write commits next under a fast-forward-only CAS against next.CommitSHA and
// returns the State that was actually committed. When next.CommitSHA is stale, the
// stored state is the merge base and next's intent is re-applied onto it via Merge.
func (s *MemStore) Write(ctx context.Context, next *State) (*State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if next == nil {
		return nil, fmt.Errorf("statestore: nil state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	committed := *next
	if s.written && next.CommitSHA != s.state.CommitSHA {
		committed = *Merge(s.state, next)
	}
	s.writes++
	committed.CommitSHA = fmt.Sprintf("mem-%d", s.writes)
	s.state = &committed
	s.written = true

	cp := committed
	return &cp, nil
}
