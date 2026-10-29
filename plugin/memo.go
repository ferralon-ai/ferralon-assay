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
// fresh decode of its JSON encoding, so no two callers share a slice or map, except CallGraph's:
// every assessment reads the run's whole call graph, and decoding it again for each one dominates a
// large scan, so the callers after the first share one decode and must not modify it, including
// its slices.
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
	shared  any
	ok      bool
}

var _ LanguagePlugin = (*memoPlugin)(nil)

// memoized runs op through m's cache. Concurrent callers with the same key wait for the first; if it
// fails, they each retry rather than inherit an error that may belong to the first caller's context.
//
// With share, the answer is decoded once and every later caller gets that same value; the first
// caller still gets the answer the plugin returned, so nothing it does to it reaches the cache.
func memoized[Req, Res any](ctx context.Context, m *memoPlugin, op string, share bool, req Req, run func(context.Context, Req) (Res, error)) (Res, error) {
	enc, err := json.Marshal(req)
	if err != nil {
		return run(ctx, req)
	}
	key := op + "\x00" + string(enc)
	for {
		m.mu.Lock()
		c, found := m.calls[key]
		if !found {
			c = &memoCall{done: make(chan struct{})}
			m.calls[key] = c
			m.mu.Unlock()

			// Deferred so a panicking plugin call still releases its waiters, which then retry.
			defer func() {
				if !c.ok {
					m.mu.Lock()
					delete(m.calls, key)
					m.mu.Unlock()
				}
				close(c.done)
			}()
			res, err := run(ctx, req)
			if err == nil {
				if payload, mErr := json.Marshal(res); mErr == nil {
					if !share {
						c.payload, c.ok = payload, true
					} else {
						var dec Res
						if json.Unmarshal(payload, &dec) == nil {
							c.shared, c.ok = dec, true
						}
					}
				}
			}
			return res, err
		}
		m.mu.Unlock()

		select {
		case <-c.done:
		case <-ctx.Done():
			var zero Res
			return zero, ctx.Err()
		}
		if !c.ok {
			continue
		}
		if share {
			return c.shared.(Res), nil
		}
		var res Res
		if err := json.Unmarshal(c.payload, &res); err != nil {
			return run(ctx, req)
		}
		return res, nil
	}
}

func (m *memoPlugin) Language() string { return m.inner.Language() }

func (m *memoPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	return memoized(ctx, m, OpIndexSymbols, false, req, m.inner.IndexSymbols)
}

func (m *memoPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	return m.inner.ResolveDependencySymbols(ctx, req)
}

func (m *memoPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	return memoized(ctx, m, OpResolveVersions, false, req, m.inner.ResolveDependencyVersions)
}

func (m *memoPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	return memoized(ctx, m, OpCallGraph, true, req, m.inner.CallGraph)
}

func (m *memoPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	return memoized(ctx, m, OpFindIngresses, false, req, m.inner.FindIngresses)
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
	return memoized(ctx, m, OpBuildManifest, false, req, m.inner.BuildManifest)
}

func (m *memoPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	return memoized(ctx, m, OpResolveInventory, false, req, m.inner.ResolveInventory)
}

func (m *memoPlugin) CapabilityManifest(ctx context.Context, req CapabilityManifestRequest) (capability.Manifest, error) {
	return m.inner.CapabilityManifest(ctx, req)
}
