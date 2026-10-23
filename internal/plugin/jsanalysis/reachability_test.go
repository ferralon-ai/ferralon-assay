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
	src := "../../../corpus/testdata/repros/FERRALON-JS-SSRF-0001-vulnerable/src"
	sink := resolveSink(t, src, "fetchUrl")

	res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: src, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want exactly one reach path to the sink, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Sink.SCIP != sink {
		t.Fatalf("path sink = %q, want %q", p.Sink.SCIP, sink)
	}
	if p.Ingress.SCIP == "" {
		t.Fatal("path must carry a non-empty ingress (the route handler entry)")
	}
	if p.Ingress.SCIP != p.Trace[0].SCIP {
		t.Fatalf("ingress %q must be the first trace frame %q", p.Ingress.SCIP, p.Trace[0].SCIP)
	}
	if p.Trace[len(p.Trace)-1].SCIP != sink {
		t.Fatalf("final trace frame must be the sink; got %q", p.Trace[len(p.Trace)-1].SCIP)
	}
	// The handle() utility hop must be on the path (handleFetch -> handle -> fetchUrl).
	if len(p.Trace) < 3 {
		t.Fatalf("expected the multi-hop trace handleFetch->handle->fetchUrl; got %v", p.Trace)
	}
}

// TestReachability_DynamicDispatchIsPartial proves the inv.5 honesty boundary: a program
// whose only call to the sink is through a COMPUTED member call the lexer cannot resolve
// never gets a fabricated ingress→sink path, and declares Partial (dynamic_dispatch). The
// sink's value is stored in an object, so it is an escape root: it is searched, and its
// path is the root alone with no ingress claimed.
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
	if len(res.Paths) != 1 {
		t.Fatalf("the address-taken sink is an escape root and must yield exactly its root path; got %+v", res.Paths)
	}
	if p := res.Paths[0]; p.Ingress != (plugin.Symbol{}) || len(p.Trace) != 1 || p.Trace[0].SCIP != sink {
		t.Fatalf("a computed-dispatch sink must not get an ingress→sink path (lexer cannot see the edge); got %+v", p)
	}
	if res.Partiality.Complete {
		t.Fatal("a computed-dispatch miss must be declared Partial, never a confident not-reachable")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Fatalf("a computed-member call must declare dynamic_dispatch; got %v", res.Partiality.Reasons)
	}
}

// An empty ReachabilityRequest.Package means the admitted package or its resolved version is
// unknown. The lane must then never refute, even for an installed dev-only package no code loads.
func TestReachability_EmptyPackageNeverRefutes(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","main":"index.js","devDependencies":{"left-pad":"1.3.0"}}`,
		"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
			"":{"name":"app","version":"1.0.0","devDependencies":{"left-pad":"1.3.0"}},
			"node_modules/left-pad":{"version":"1.3.0","dev":true}}}`,
		"index.js": "console.log('no dependency is loaded');\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, VulnID: "CVE-0000-0000"})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if res.Refutation != nil {
		t.Fatalf("empty Package must yield no Refutation; got %+v", res.Refutation)
	}
}
