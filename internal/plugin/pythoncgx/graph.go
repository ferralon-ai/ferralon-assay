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
)

// Graph is the slice of the cgx SDK this package uses: the MCP tool surface by name, plus the
// SDK's own counters. Keeping it this narrow lets the operations be tested against a fake and
// keeps the SDK's types out of everything but the adapter.
type Graph interface {
	// Call runs one cgx tool and returns its structured result. The SDK owns `root`.
	Call(ctx context.Context, tool string, args map[string]any) (json.RawMessage, error)
	// Stats returns the SDK's counters (memory peaks, phase timings) as JSON, for the stats
	// record; nil when the transport reports none.
	Stats() json.RawMessage
	Close() error
}

// Opener opens a Graph over the git repository at repo. It must not index; the first query
// indexes when the stored graph is not fresh for repo's HEAD tree.
type Opener func(ctx context.Context, repo string, cfg Config) (Graph, error)

// Errors an Opener's Graph wraps so the operations can tell a cgx answer apart from a failure.
var (
	// ErrUnresolved: cgx could not resolve a symbol argument to a node.
	ErrUnresolved = errors.New("cgx: symbol not resolved")
	// ErrRejected: cgx rejected the arguments (for example a selector that does not compile).
	ErrRejected = errors.New("cgx: request rejected")
)
