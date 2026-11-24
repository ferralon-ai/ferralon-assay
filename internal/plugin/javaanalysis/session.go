package javaanalysis

import (
	"context"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// session.go — what one scan's analyzer process keeps between the requests it serves.
//
// The pipeline asks Reachability once per advisory. Each ask parses the whole source tree and
// builds the call graph, which opens every dependency JAR the build graph names; on a large
// Maven reactor that is seconds per advisory, spent on the same answer every time. A process
// that serves a whole scan (cmd/assay-plugin-java's serve mode) carries a session, and the
// session keeps the parsed program, the call graph and the ingresses per build dir and options,
// so they are built on the first request that needs them and read by every later one.
//
// A session lives in memory only, for one scan over one checkout whose tree does not change
// while the scan runs (the same contract plugin.Memoize keeps on the host side). Nothing is
// written to disk and nothing outlives the process. Without a session every call computes its
// answer as before.
//
// What the session hands out is shared: callers read it and never modify it.

type sessionCtxKey struct{}

// scanSession is one scan's in-memory memo. A failed computation is not kept, so the next
// request computes it again.
type scanSession struct {
	mu        sync.Mutex
	programs  map[string]*program
	graphs    map[sessionKey]plugin.CallGraphResult
	ingresses map[sessionKey]plugin.IngressResult
}

// sessionKey names one answer: the build dir and every option an op reads.
type sessionKey struct {
	buildDir string
	opts     analyzer
}

// WithSession returns ctx carrying a new session. A process that serves one scan's requests
// passes the same ctx to every op it runs; a one-shot process does not call it.
func WithSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, &scanSession{
		programs:  map[string]*program{},
		graphs:    map[sessionKey]plugin.CallGraphResult{},
		ingresses: map[sessionKey]plugin.IngressResult{},
	})
}

func sessionFrom(ctx context.Context) *scanSession {
	s, _ := ctx.Value(sessionCtxKey{}).(*scanSession)
	return s
}

// Seams the session's test counts through: what the session saves is a call to one of these.
var (
	parseProgram     = loadProgram
	openDependencies = buildDependencyGraph
)

// sessionProgram is loadProgram, read from ctx's session when one carries the tree.
func sessionProgram(ctx context.Context, buildDir string) (*program, error) {
	s := sessionFrom(ctx)
	if s == nil {
		return parseProgram(buildDir)
	}
	return memo(&s.mu, s.programs, buildDir, func() (*program, error) { return parseProgram(buildDir) })
}

// CallGraph builds the source-level call graph for the Java module at req.BuildDir (see
// callGraph), once per session.
func CallGraph(ctx context.Context, req plugin.CallGraphRequest, opts ...Option) (plugin.CallGraphResult, error) {
	s := sessionFrom(ctx)
	if s == nil {
		return callGraph(ctx, req, opts...)
	}
	return memo(&s.mu, s.graphs, sessionKey{req.BuildDir, resolveOptions(opts)}, func() (plugin.CallGraphResult, error) {
		return callGraph(ctx, req, opts...)
	})
}

// FindIngresses identifies the framework entry points in the Java module at req.BuildDir (see
// findIngresses), once per session.
func FindIngresses(ctx context.Context, req plugin.FindIngressesRequest, opts ...Option) (plugin.IngressResult, error) {
	s := sessionFrom(ctx)
	if s == nil {
		return findIngresses(ctx, req, opts...)
	}
	return memo(&s.mu, s.ingresses, sessionKey{req.BuildDir, resolveOptions(opts)}, func() (plugin.IngressResult, error) {
		return findIngresses(ctx, req, opts...)
	})
}

// memo returns m[key], computing and storing it when absent. The lock is not held while
// compute runs, which may itself read the session; a served process runs one request at a time,
// so two computations of one key do not overlap there, and where they do the first stored wins.
func memo[K comparable, V any](mu *sync.Mutex, m map[K]V, key K, compute func() (V, error)) (V, error) {
	mu.Lock()
	v, ok := m[key]
	mu.Unlock()
	if ok {
		return v, nil
	}
	v, err := compute()
	if err != nil {
		return v, err
	}
	mu.Lock()
	defer mu.Unlock()
	if prev, ok := m[key]; ok {
		return prev, nil
	}
	m[key] = v
	return v, nil
}
