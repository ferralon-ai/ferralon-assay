package artifactcache

import (
	"context"
	"errors"
	"io"
)

// Ref keys a cache lookup: the normalized PURL and the algorithm-prefixed integrity
// digest of the selected artifact (both plain strings — the PLAN-000
// DependencyNode.PURL / DependencyArtifact.Digest shapes). Ref owns its fields; it
// deliberately does NOT embed a plugin type, so this package needs no plugin import.
type Ref struct {
	PURL   string // "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0"
	Digest string // "sha256:<hex>" — the load-bearing integrity anchor
}

// ErrDeclaredAbsent is the first-class "nothing has acquired this artifact" state — the
// honest Phase-1 answer, NOT a failure. A lane's indexer branches on it to a
// declared-partial result (mirrors plugin.Unsupported()). Do NOT overload
// artifact.ErrNotFound: absent is a stage state, not a miss.
var ErrDeclaredAbsent = errors.New("artifactcache: artifact declared absent (no acquisition in this phase)")

// Store is a content-addressed, read-through view of locally-cached dependency
// artifacts. It is ACQUISITION-AGNOSTIC: Lookup never blocks on the network and never
// touches a credential — it returns ErrDeclaredAbsent on a miss. Network acquisition and
// the customer registry credential are a separate seam that lands in PLAN-200 (see
// threatmodel.md). This keeps the Phase-0 contract a pure leaf.
type Store interface {
	// Lookup returns an inert read-only Handle to the local bytes for ref, whose
	// content MUST match ref.Digest (the digest IS the integrity check — a cache
	// serving wrong bytes fails it). Returns ErrDeclaredAbsent when nothing has
	// acquired ref.
	Lookup(ctx context.Context, ref Ref) (Handle, error)
}

// Handle is an INERT, read-only view of cached artifact bytes. It exposes ReaderAt
// (pure-Go indexers read the zip central directory) and Path (foreign-toolchain
// indexers hand scip-java a jar on disk). It deliberately exposes NO
// Run/Exec/Start/Command and no open-for-write — that ABSENCE is the mechanical
// no-execution guarantee the noexec_test.go layer-1 test pins.
type Handle interface {
	io.ReaderAt
	// Path is the content-addressed local path; "" when the handle is not path-backed.
	Path() string
	Size() int64
	io.Closer
}
