// Package cfamilycgx serves the C/C++ lane's graph operations (IndexSymbols, CallGraph,
// FindIngresses, Reachability, ComputeTaint, and ResolveDependencySymbols for a named symbol)
// from a cgx call graph, opened through the cgx Go SDK over an on-disk index. It backs the
// assay-plugin-cfamily subprocess and links only into that binary, never into the host (inv.8).
//
// cgx reads the tree with tree-sitter only: no compilation database and no SCIP index is handed
// to it. The compilation database decides which files are staged for it (each translation unit,
// plus the headers beside them), and with no database the C/C++ sources of the tree are staged
// under a declared no_manifest. cgx FQNs become Symbol.SCIP unchanged. Nodes are keyed by FQN, so
// the several nodes cgx makes for one C++ name (a header prototype and its out-of-line
// definition, or overloads) are one symbol here: an anchor is never ambiguous, and a merge only
// over-approximates.
//
// Every result is declared partial and names its residue: function-pointer and virtual call
// sites, function-like macros, and calls to functions the tree does not define. A missing,
// unpinned or mismatched engine is a loud declared partiality on every operation, never an
// empty-but-clean result.
package cfamilycgx

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

// Errors an Opener returns, or its Graph wraps, so the operations can tell an engine problem or
// a cgx answer apart from a failure.
var (
	// ErrUnresolved: cgx could not resolve a symbol argument to a node.
	ErrUnresolved = errors.New("cgx: symbol not resolved")
	// ErrRejected: cgx rejected the arguments (for example a query that does not compile).
	ErrRejected = errors.New("cgx: request rejected")
	// ErrEngineUnconfigured: no engine is available to run, neither a wasm module (the SDK at
	// the pinned commit embeds none) nor a native binary.
	ErrEngineUnconfigured = errors.New(reasonEngineUnconfigured)
	// ErrEngineUnverified: an engine file the configuration names is unpinned or does not match
	// its pin, so it was not run.
	ErrEngineUnverified = errors.New(reasonEngineUnverified)
	// ErrEngineMismatch: the engine and the SDK do not come from the same cgx commit (the wasm
	// module is not the one pinned beside the SDK version, the SDK in the build is not the pinned
	// version, or the engine reports another ABI or schema), so it was not run.
	ErrEngineMismatch = errors.New(reasonEngineMismatch)
	// ErrEngineABIMismatch: the engine reports a different ABI or session protocol than this
	// SDK speaks (cgx.ErrABIMismatch at Open) — a module built from another cgx commit than the
	// SDK, surfaced at instantiation rather than by the pin check. It satisfies
	// errors.Is(err, ErrEngineMismatch).
	ErrEngineABIMismatch = fmt.Errorf("%w: cgx engine speaks a different ABI or session protocol", ErrEngineMismatch)
)

// EngineFailureKind classifies an EngineFailure.
type EngineFailureKind string

const (
	// EngineMemoryLimit: the wasm engine reached its linear-memory ceiling.
	EngineMemoryLimit EngineFailureKind = "memory_limit"
	// EngineTrap: the wasm engine trapped for another reason.
	EngineTrap EngineFailureKind = "trap"
	// EngineExit: the native engine process exited (or was killed).
	EngineExit EngineFailureKind = "exit"
	// EngineContext: the operation's context ended while the engine was indexing.
	EngineContext EngineFailureKind = "context"
)

// EngineFailure is a failure of the cgx engine itself rather than an answer from it.
type EngineFailure struct {
	Kind EngineFailureKind
	Err  error
}

func (e *EngineFailure) Error() string { return fmt.Sprintf("cgx engine %s: %v", e.Kind, e.Err) }

func (e *EngineFailure) Unwrap() error { return e.Err }
