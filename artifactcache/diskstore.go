package artifactcache

import (
	"context"
	"errors"
	"io"
	"os"
)

// diskStore is the content-addressed, disk-backed Store implementation. It is a PURE READ
// seam: Lookup derives the canonical path from ref.Digest (running the same decode-validate
// gate as the Acquirer), opens the file read-only on a hit, and returns ErrDeclaredAbsent on
// a miss. It never blocks on the network and never touches a credential — network
// acquisition is the separate Acquirer seam (see artifactcache/acquire). It adds no method
// to Store/Handle and holds no capability to execute, so noexec_test.go layer-1 stays green.
type diskStore struct {
	root string
}

// NewDiskStore returns a disk-backed Store rooted at root. root is the cache root the
// Acquirer publishes verified bytes under; the two share CanonicalPath so a published
// artifact is exactly what Lookup reads.
func NewDiskStore(root string) Store { return &diskStore{root: root} }

// Lookup derives the canonical content-addressed path from ref.Digest and returns an inert
// read-only Handle on a hit. A ref.Digest that fails the decode-validate gate returns
// ErrMalformedRef (a caller/inventory bug, distinct from a miss); a valid ref with no
// published bytes returns ErrDeclaredAbsent. Nothing here is ever the empty-success trap:
// an absent artifact is ErrDeclaredAbsent, never a zero-byte Handle.
func (s *diskStore) Lookup(_ context.Context, ref Ref) (Handle, error) {
	path, err := CanonicalPath(s.root, ref.Digest)
	if err != nil {
		return nil, err // ErrMalformedRef — inventory bug, not a partiality
	}
	f, err := os.Open(path) // read-only; no O_CREATE, no write mode
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrDeclaredAbsent
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileHandle{f: f, size: fi.Size(), path: path}, nil
}

// fileHandle is an inert, read-only, path-backed Handle over a cached artifact file. It
// exposes io.ReaderAt / Path / Size / io.Closer and DELIBERATELY exposes no
// Run/Exec/Start/Command and no open-for-write — the absence is the no-execution guarantee.
type fileHandle struct {
	f    *os.File
	size int64
	path string
}

// ReadAt reads through the underlying read-only file descriptor.
func (h *fileHandle) ReadAt(p []byte, off int64) (int, error) { return h.f.ReadAt(p, off) }

// Path returns the content-addressed local path (a foreign-toolchain indexer hands a jar on
// disk to scip-java).
func (h *fileHandle) Path() string { return h.path }

// Size returns the artifact size in bytes.
func (h *fileHandle) Size() int64 { return h.size }

// Close releases the file descriptor; subsequent reads fail.
func (h *fileHandle) Close() error { return h.f.Close() }

var _ io.ReaderAt = (*fileHandle)(nil)
