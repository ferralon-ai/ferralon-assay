package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeProgram writes a name→source map into a temp build dir and returns it.
func writeProgram(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return dir
}

func hasEdge(edges []plugin.CallEdge, caller, callee string) bool {
	for _, e := range edges {
		if e.Caller.SCIP == caller && e.Callee.SCIP == callee {
			return true
		}
	}
	return false
}

func hasReason(p plugin.Partiality, reason string) bool {
	for _, r := range p.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// An Express app whose route handler (registered by a NAMED reference) calls a
// utility that calls the SSRF sink — the canonical Increment-1 chain. The callee
// names are unique by (name,arity) so the source-lexical resolver connects every
// edge soundly: handleFetch -> handle -> fetchUrl -> openConn.
const expressApp = `
const express = require('express');
const { fetchUrl } = require('./fetcher');
const app = express();

function handleFetch(req, res) {
    const status = handle(req.query.target);
    res.send(String(status));
}

function handle(target) {
    return fetchUrl(target);
}

app.get('/fetch', handleFetch);
app.listen(8080);
`

const fetcherModule = `
function fetchUrl(target) {
    return openConn(target);
}

function openConn(url) {
    return url;
}

module.exports = { fetchUrl };
`

func TestCallGraph_RouteChainEdgesResolve(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"app.js":     expressApp,
		"fetcher.js": fetcherModule,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handleFetch", 2)
	handle := funcSCIP("app", nil, "handle", 1)
	fetchURL := funcSCIP("fetcher", nil, "fetchUrl", 1)
	openConn := funcSCIP("fetcher", nil, "openConn", 1)

	for _, want := range [][2]string{{handleFetch, handle}, {handle, fetchURL}, {fetchURL, openConn}} {
		if !hasEdge(res.Edges, want[0], want[1]) {
			t.Errorf("missing edge %s -> %s\nedges: %+v", want[0], want[1], res.Edges)
		}
	}
}

func TestCallGraph_RouteHandlerIsRoot(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"app.js":     expressApp,
		"fetcher.js": fetcherModule,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handleFetch", 2)
	found := false
	for _, r := range res.Roots {
		if r.SCIP == handleFetch {
			found = true
		}
	}
	if !found {
		t.Errorf("route handler handleFetch not registered as a call-graph root; roots=%v", res.Roots)
	}
}

func TestCallGraph_ControlFlowKeywordsAreNotEdges(t *testing.T) {
	// if/for/while/return/new/switch look like "word(" but must NOT become call edges.
	src := `
function run() {
    if (cond()) { while (loop()) { return; } }
    for (let i = 0; i < 1; i++) {}
    const o = new Object();
    switch (pick()) { default: break; }
}
function cond() { return true; }
function loop() { return false; }
function pick() { return 0; }
`
	dir := writeProgram(t, map[string]string{"c.js": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	run := funcSCIP("c", nil, "run", 0)
	cond := funcSCIP("c", nil, "cond", 0)
	loop := funcSCIP("c", nil, "loop", 0)
	pick := funcSCIP("c", nil, "pick", 0)
	if !hasEdge(res.Edges, run, cond) || !hasEdge(res.Edges, run, loop) || !hasEdge(res.Edges, run, pick) {
		t.Errorf("expected run->cond, run->loop, run->pick edges; edges=%+v", res.Edges)
	}
	for _, e := range res.Edges {
		if e.Caller.SCIP == "" || e.Callee.SCIP == "" {
			t.Errorf("empty endpoint in edge %+v", e)
		}
	}
}

// TestCallGraph_DottedChainLeafResolvesAsBareCall covers a member-access call chain
// "a.b.c(x)": the receiver expression "a.b" is a member expression, not a single local
// instance, so the call must resolve as a bare call to a uniquely-declared module-level
// c(1) — not be dropped as an unresolved receiver-method call on the intermediate "b".
func TestCallGraph_DottedChainLeafResolvesAsBareCall(t *testing.T) {
	src := `
function caller(v) {
    return a.b.c(v);
}
function c(x) {
    return x;
}
`
	dir := writeProgram(t, map[string]string{"m.js": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	caller := funcSCIP("m", nil, "caller", 1)
	c := funcSCIP("m", nil, "c", 1)
	if !hasEdge(res.Edges, caller, c) {
		t.Errorf("dotted chain a.b.c() must resolve as a bare call to c; missing %s -> %s\nedges: %+v", caller, c, res.Edges)
	}
}

// TestCallGraph_DottedChainLeafUnknownFabricatesNoEdge is the soundness control for the
// case above: a member-chain leaf with no uniquely-declared module-level target must
// fabricate no edge — the bare-name fallback stays fail-closed.
func TestCallGraph_DottedChainLeafUnknownFabricatesNoEdge(t *testing.T) {
	src := `
function caller(v) {
    return a.b.c(v);
}
`
	dir := writeProgram(t, map[string]string{"m.js": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if len(res.Edges) != 0 {
		t.Errorf("chained leaf with no local declaration must fabricate no edge; got %+v", res.Edges)
	}
}

// TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge is the inv.5 honesty test: when
// a callee's (name,arity) matches MORE THAN ONE declared function (two modules each
// declare process(1)), the resolver cannot soundly pick one, so it fabricates NO
// edge and declares partiality (dynamic_dispatch). The sink must NOT be reachable.
func TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge(t *testing.T) {
	a := `
function entry(x) {
    process(x);
}
`
	// Two distinct modules both declare process(1); a bare call to process(x) is
	// ambiguous across them (the lexical resolver cannot scope-resolve the import).
	b := `
function process(x) { sink(); }
function sink() {}
`
	c := `
function process(x) {}
`
	dir := writeProgram(t, map[string]string{"a.js": a, "b.js": b, "c.js": c})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if res.Partiality.Complete {
		t.Errorf("ambiguous callee must declare partiality, got Complete")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("ambiguous callee must carry dynamic_dispatch reason, got %+v", res.Partiality)
	}
	entry := funcSCIP("a", nil, "entry", 1)
	for _, e := range res.Edges {
		if e.Caller.SCIP == entry {
			t.Errorf("ambiguous call fabricated an edge from entry: %+v", e)
		}
	}
}

func TestCallGraph_UnknownCalleeIsPartialNoEdge(t *testing.T) {
	// A call to a library/imported function with no source declaration must not
	// fabricate an edge and must declare partiality.
	src := `
function run() {
    externalLibraryCall(1, 2);
}
`
	dir := writeProgram(t, map[string]string{"c.js": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if res.Partiality.Complete {
		t.Errorf("unknown callee must declare partiality")
	}
	if len(res.Edges) != 0 {
		t.Errorf("unknown callee must not fabricate any edge; got %+v", res.Edges)
	}
}

func TestCallGraph_MissingBuildDirIsHardError(t *testing.T) {
	_, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}

func TestIndexSymbols_NoSourcesIsHardError(t *testing.T) {
	dir := writeProgram(t, map[string]string{"README.md": "no source here\n"})
	if _, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir}); err == nil {
		t.Fatal("expected a hard error for a build dir with no JS/TS sources")
	}
}
