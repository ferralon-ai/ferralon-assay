package artifactcache

import (
	"context"
	"errors"
	"io"
)

// declaredAbsentStore is the trivial read-only fake whose Lookup always reports
// ErrDeclaredAbsent — the Phase-1 posture in which nothing has acquired any artifact.
// It touches no network and no credential and holds no capability to execute.
type declaredAbsentStore struct{}

// NewDeclaredAbsentStore returns a Store that always reports ErrDeclaredAbsent. It is
// the inert Phase-1 fake a lane's indexer codes against today.
func NewDeclaredAbsentStore() Store { return declaredAbsentStore{} }

func (declaredAbsentStore) Lookup(context.Context, Ref) (Handle, error) {
	return nil, ErrDeclaredAbsent
}

// memStore is an in-memory read-only fake mapping a Ref to inert bytes. It exists to
// exercise the read path and the ConformanceTest harness; it performs no I/O beyond the
// in-memory slice and holds no capability to execute.
type memStore struct {
	byRef map[Ref][]byte
}

// NewMemStore returns an inert in-memory Store seeded from contents. Lookup returns a
// read-only memHandle over the bytes on a hit and ErrDeclaredAbsent on a miss. The
// returned bytes are held by reference; callers must not mutate them.
func NewMemStore(contents map[Ref][]byte) Store {
	cp := make(map[Ref][]byte, len(contents))
	for r, b := range contents {
		cp[r] = b
	}
	return &memStore{byRef: cp}
}

func (s *memStore) Lookup(_ context.Context, ref Ref) (Handle, error) {
	b, ok := s.byRef[ref]
	if !ok {
		return nil, ErrDeclaredAbsent
	}
	return &memHandle{data: b}, nil
}

// memHandle is an inert, read-only Handle over an in-memory byte slice. It is not
// path-backed (Path returns ""). It satisfies io.ReaderAt / Size / io.Closer and holds
// no execution capability whatsoever.
type memHandle struct {
	data   []byte
	closed bool
}

// ReadAt implements io.ReaderAt over the backing slice.
func (h *memHandle) ReadAt(p []byte, off int64) (int, error) {
	if h.closed {
		return 0, errors.New("artifactcache: read after close")
	}
	if off < 0 {
		return 0, errors.New("artifactcache: negative offset")
	}
	if off >= int64(len(h.data)) {
		return 0, io.EOF
	}
	n := copy(p, h.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Path returns "" — the in-memory handle is not path-backed.
func (h *memHandle) Path() string { return "" }

// Size returns the length of the backing bytes.
func (h *memHandle) Size() int64 { return int64(len(h.data)) }

// Close marks the handle closed; subsequent reads fail. It releases no OS resource.
func (h *memHandle) Close() error {
	h.closed = true
	return nil
}
