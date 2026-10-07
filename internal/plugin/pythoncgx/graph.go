// Package pythoncgx serves the graph-shaped Python plugin operations (IndexSymbols,
// ResolveDependencySymbols, CallGraph, FindIngresses, Reachability, ComputeTaint) from a cgx
// call graph, opened through the cgx Go SDK over an on-disk index. It backs the
// assay-plugin-python-cgx subprocess; like pythonanalysis it links only into that binary,
// never into the host (inv.8).
//
// The package owns mechanism only: where the index lives, process lifecycle, paging, and the
// mapping of cgx answers onto plugin types. Every question about the code — which node a
// dotted Python name denotes, which edges exist and how confident they are, whether one
// symbol reaches another — is asked of cgx and its answer passed through verbatim. cgx FQNs
// become Symbol.SCIP unchanged, so one id space spans edges, roots, ingresses, resolved
// sinks and traces.
package pythoncgx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Graph is the slice of the cgx SDK this package uses: the MCP tool surface by name, plus the
// SDK's own counters. Keeping it this narrow lets the operations be tested against a fake and
// keeps the SDK's types out of everything but the adapter.
type Graph interface {
	// Index brings the stored graph up to date with repo's HEAD tree; it does nothing when the
	// stored graph is already fresh. An engine failure is returned as an *EngineFailure.
	Index(ctx context.Context) error
	// Call runs one cgx tool and returns its structured result. The SDK owns `root`.
	Call(ctx context.Context, tool string, args map[string]any) (json.RawMessage, error)
	// Stats returns the SDK's counters (memory peaks, phase timings) as JSON, for the stats
	// record; nil when the transport reports none.
	Stats() json.RawMessage
	Close() error
}

// Opener opens a Graph over the git repository at repo. It must not index; Graph.Index does.
type Opener func(ctx context.Context, repo string, cfg Config) (Graph, error)

// Errors an Opener's Graph wraps so the operations can tell a cgx answer apart from a failure.
var (
	// ErrUnresolved: cgx could not resolve a symbol argument to a node.
	ErrUnresolved = errors.New("cgx: symbol not resolved")
	// ErrRejected: cgx rejected the arguments (for example a selector that does not compile).
	ErrRejected = errors.New("cgx: request rejected")
)

// EngineFailureKind classifies an EngineFailure.
type EngineFailureKind string

const (
	// EngineMemoryLimit: the wasm engine reached its linear-memory ceiling.
	EngineMemoryLimit EngineFailureKind = "memory_limit"
	// EngineTrap: the wasm engine trapped for another reason.
	EngineTrap EngineFailureKind = "trap"
	// EngineExit: the native engine process exited.
	EngineExit EngineFailureKind = "exit"
)

// EngineFailure is a failure of the cgx engine itself rather than an answer from it. Indexing the
// same tree with the same engine build and options is expected to fail the same way.
type EngineFailure struct {
	Kind EngineFailureKind
	Err  error
}

func (e *EngineFailure) Error() string { return fmt.Sprintf("cgx engine %s: %v", e.Kind, e.Err) }

func (e *EngineFailure) Unwrap() error { return e.Err }
