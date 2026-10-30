package plugin

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/capability"
)

// Memoize wraps p so each operation whose answer depends only on the build tree runs at most once
// per distinct request for the wrapper's lifetime. A scan assesses every advisory against the same
// tree, and each assessment otherwise re-runs the call graph, ingress discovery and manifest reads
// from scratch.
//
// Memoized: IndexSymbols, ResolveDependencyVersions, CallGraph, FindIngresses, BuildManifest and
// ResolveInventory, keyed on the op and the request's JSON encoding. Never memoized: any operation
// whose request names the advisory (ResolveDependencySymbols, Reachability) and the operations that
// act on per-advisory sinks (ComputeTaint, GenerateHarness).
//
// The wrapper is meant to live for one run over one checkout. A failed call is not cached, so the
// next caller retries it exactly as it would without the wrapper. A cached answer is handed out as a
// fresh decode of its JSON encoding, so no two callers share a slice or map. Every assessment reads
// the run's whole call graph, and decoding it again for each one dominates a large scan, so
// SharedCallGraph hands the wrapper's callers one decode of it, behind a read-only CallGraphView.
func Memoize(p LanguagePlugin) LanguagePlugin {
	if p == nil {
		return nil
	}
	return &memoPlugin{inner: p, calls: map[string]*memoCall{}}
}

type memoPlugin struct {
	inner LanguagePlugin
	mu    sync.Mutex
	calls map[string]*memoCall
}

type memoCall struct {
	done    chan struct{}
	payload []byte
	ok      bool

	// graph is CallGraph's payload decoded once for SharedCallGraph.
	graphOnce sync.Once
	graph     *CallGraphResult
}

var _ LanguagePlugin = (*memoPlugin)(nil)

// memoized runs op through m's cache and hands the caller its own decode of the answer.
func memoized[Req, Res any](ctx context.Context, m *memoPlugin, op string, req Req, run func(context.Context, Req) (Res, error)) (Res, error) {
	c, res, ran, err := fill(ctx, m, op, req, run)
	if ran || err != nil {
		return res, err
	}
	var out Res
	if err := json.Unmarshal(c.payload, &out); err != nil {
		return run(ctx, req)
	}
	return out, nil
}

// fill makes sure op's answer for req is in m's cache and returns its entry. Concurrent callers with
// the same key wait for the first; if it fails, they each retry rather than inherit an error that may
// belong to the first caller's context.
//
// When ran, this caller ran op itself: res and err are what the plugin returned, and c, if it is not
// nil, is the entry, which holds the answer if c.ok. Otherwise err is the wait's error or c holds the
// answer.
func fill[Req, Res any](ctx context.Context, m *memoPlugin, op string, req Req, run func(context.Context, Req) (Res, error)) (c *memoCall, res Res, ran bool, err error) {
	enc, err := json.Marshal(req)
	if err != nil {
		res, err = run(ctx, req)
		return nil, res, true, err
	}
	key := op + "\x00" + string(enc)
	for {
		m.mu.Lock()
		call, found := m.calls[key]
		if !found {
			call = &memoCall{done: make(chan struct{})}
			m.calls[key] = call
			m.mu.Unlock()

			// Deferred so a panicking plugin call still releases its waiters, which then retry.
			defer func() {
				if !call.ok {
					m.mu.Lock()
					delete(m.calls, key)
					m.mu.Unlock()
				}
				close(call.done)
			}()
			res, err = run(ctx, req)
			if err == nil {
				if payload, mErr := json.Marshal(res); mErr == nil {
					call.payload, call.ok = payload, true
				}
			}
			return call, res, true, err
		}
		m.mu.Unlock()

		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, res, false, ctx.Err()
		}
		if call.ok {
			return call, res, false, nil
		}
	}
}

func (m *memoPlugin) Language() string { return m.inner.Language() }

func (m *memoPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	return memoized(ctx, m, OpIndexSymbols, req, m.inner.IndexSymbols)
}

func (m *memoPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	return m.inner.ResolveDependencySymbols(ctx, req)
}

func (m *memoPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	return memoized(ctx, m, OpResolveVersions, req, m.inner.ResolveDependencyVersions)
}

func (m *memoPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	return memoized(ctx, m, OpCallGraph, req, m.inner.CallGraph)
}

// sharedCallGraph shares CallGraph's cache entry, so the plugin runs once whichever of the two a
// caller uses, and decodes the answer at most once for every view.
func (m *memoPlugin) sharedCallGraph(ctx context.Context, req CallGraphRequest) (CallGraphView, error) {
	c, res, ran, err := fill(ctx, m, OpCallGraph, req, m.inner.CallGraph)
	if err != nil {
		return CallGraphView{}, err
	}
	if c == nil || !c.ok {
		return NewCallGraphView(res), nil
	}
	c.graphOnce.Do(func() {
		var cg CallGraphResult
		if json.Unmarshal(c.payload, &cg) == nil {
			c.graph = &cg
		}
	})
	if c.graph == nil {
		if !ran {
			if res, err = m.inner.CallGraph(ctx, req); err != nil {
				return CallGraphView{}, err
			}
		}
		return NewCallGraphView(res), nil
	}
	return CallGraphView{cg: c.graph, enc: c.payload}, nil
}

func (m *memoPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	return memoized(ctx, m, OpFindIngresses, req, m.inner.FindIngresses)
}

func (m *memoPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	return m.inner.Reachability(ctx, req)
}

func (m *memoPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	return m.inner.ComputeTaint(ctx, req)
}

func (m *memoPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	return m.inner.GenerateHarness(ctx, req)
}

func (m *memoPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	return memoized(ctx, m, OpBuildManifest, req, m.inner.BuildManifest)
}

func (m *memoPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	return memoized(ctx, m, OpResolveInventory, req, m.inner.ResolveInventory)
}

func (m *memoPlugin) CapabilityManifest(ctx context.Context, req CapabilityManifestRequest) (capability.Manifest, error) {
	return m.inner.CapabilityManifest(ctx, req)
}
