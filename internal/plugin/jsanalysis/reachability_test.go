package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolveSink runs the real resolver over src and returns the SCIP of the named advisory
// sink symbol (the SAME identity the call graph emits).
func resolveSink(t *testing.T, src, symbol string) string {
	t.Helper()
	rs, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        src,
		AdvisorySymbols: []string{symbol},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(rs.Resolved) == 0 {
		t.Fatalf("symbol %q did not resolve in %q", symbol, src)
	}
	return rs.Resolved[0].SCIP
}

// TestReachability_IngressToSinkPath is the hermetic proof that the REAL lexical
// reachability connects the Express route ingress (handleFetch) through the utility hop
// (handle) to the SSRF sink (fetchUrl), emitting the ingress→sink trace evidence in the
// SCIP identity space the call graph uses.
func TestReachability_IngressToSinkPath(t *testing.T) {
	ctx := context.Background()
	src := "../../../corpus/testdata/repros/TEGRON-JS-SSRF-0001-vulnerable/src"
	sink := resolveSink(t, src, "fetchUrl")

	res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: src, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want exactly one reach path to the sink, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Sink != sink {
		t.Fatalf("path sink = %q, want %q", p.Sink, sink)
	}
	if p.Ingress == "" {
		t.Fatal("path must carry a non-empty ingress (the route handler entry)")
	}
	if p.Ingress != p.Trace[0] {
		t.Fatalf("ingress %q must be the first trace frame %q", p.Ingress, p.Trace[0])
	}
	if p.Trace[len(p.Trace)-1] != sink {
		t.Fatalf("final trace frame must be the sink; got %q", p.Trace[len(p.Trace)-1])
	}
	// The handle() utility hop must be on the path (handleFetch -> handle -> fetchUrl).
	if len(p.Trace) < 3 {
		t.Fatalf("expected the multi-hop trace handleFetch->handle->fetchUrl; got %v", p.Trace)
	}
}

// TestReachability_DynamicDispatchIsPartial proves the inv.5 honesty boundary: a program
// whose only call to the sink is through a COMPUTED member call the lexer cannot resolve
// yields NO ingress→sink path AND declares Partial (dynamic_dispatch + no_known_ingress) —
// never a confident "not reachable".
func TestReachability_DynamicDispatchIsPartial(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// dangerousSink is only ever invoked through a computed member access
	// (handlers[name](x)), which the lexical scanner cannot resolve to a concrete callee,
	// so no edge to it is fabricated.
	const src = `'use strict';
const http = require('http');

function dangerousSink(u) {
    return http.get(u);
}

function dispatch(name, u) {
    const handlers = { fetch: dangerousSink };
    return handlers[name](u);   // computed member call — lexer cannot resolve the callee
}

const app = makeApp();
app.get('/go', route);

function route(req, res) {
    return dispatch('fetch', req.query.u);
}
`
	if err := os.WriteFile(filepath.Join(dir, "dyn.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := resolveSink(t, dir, "dangerousSink")

	res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("a computed-dispatch sink must yield NO resolved path (lexer cannot see the edge); got %+v", res.Paths)
	}
	if res.Partiality.Complete {
		t.Fatal("a computed-dispatch miss must be declared Partial, never a confident not-reachable")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Fatalf("an unreached sink must declare no_known_ingress; got %v", res.Partiality.Reasons)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Fatalf("a computed-member call must declare dynamic_dispatch; got %v", res.Partiality.Reasons)
	}
}
