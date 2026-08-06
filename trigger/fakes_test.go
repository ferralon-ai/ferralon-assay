package trigger

import (
	"context"
	"errors"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// memStore is an in-memory StateStore for the trigger unit tests. The baseline
// acceptance test instead exercises the real git-ref StateStore against a temp bare
// repo (see TestRunBaseline_RealGitRefStore).
type memStore struct {
	mu       sync.Mutex
	state    *statestore.State
	writes   int
	lastSeen *statestore.State
}

func (m *memStore) Read(ctx context.Context) (*statestore.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return nil, statestore.ErrNotFound
	}
	cp := *m.state
	cp.CommitSHA = "mem-cas-token"
	return &cp, nil
}

func (m *memStore) Write(ctx context.Context, next *statestore.State) (*statestore.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes++
	cp := *next
	m.lastSeen = &cp
	stored := *next
	stored.CommitSHA = "mem-commit"
	m.state = &stored
	out := stored
	return &out, nil
}

// fakeOSV is a fixture-backed OSVClient: it returns a pre-canned OSVResult and never
// touches the network. It is how every CVE-watch test mocks OSV.dev.
type fakeOSV struct {
	result OSVResult
	err    error
	calls  int
}

func (f *fakeOSV) QueryBatch(ctx context.Context, pkgs []report.Package) (OSVResult, error) {
	f.calls++
	if f.err != nil {
		return OSVResult{}, f.err
	}
	return f.result, nil
}

var errFakeOSV = errors.New("fake osv error")
