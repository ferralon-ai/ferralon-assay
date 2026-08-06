package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func hasEdge(edges []plugin.CallEdge, caller, callee string) bool {
	for _, e := range edges {
		if e.Caller == caller && e.Callee == callee {
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

// flaskApp is the canonical chain: a Flask route handler (registered by the @app.route
// decorator) calls a utility that calls the sink — handle_fetch → handle → fetch_url →
// open_conn. Every callee is unique by (name, arity) so the source-lexical resolver
// connects each edge soundly.
const flaskApp = `
from flask import Flask
app = Flask(__name__)

@app.route('/fetch')
def handle_fetch():
    return handle(1)

def handle(target):
    return fetch_url(target)

def fetch_url(target):
    return open_conn(target)

def open_conn(url):
    return url
`

func TestCallGraph_RouteChainEdgesResolve(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handle_fetch", 0)
	handle := funcSCIP("app", nil, "handle", 1)
	fetchURL := funcSCIP("app", nil, "fetch_url", 1)
	openConn := funcSCIP("app", nil, "open_conn", 1)

	for _, want := range [][2]string{{handleFetch, handle}, {handle, fetchURL}, {fetchURL, openConn}} {
		if !hasEdge(res.Edges, want[0], want[1]) {
			t.Errorf("missing edge %s -> %s\nedges: %+v", want[0], want[1], res.Edges)
		}
	}
	// A lexical Python call graph is ALWAYS declared Partial (dynamic dispatch).
	if res.Partiality.Complete {
		t.Error("Python call graph must never be Complete (structurally weak; dynamic dispatch)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("call graph must carry standing dynamic_dispatch reason; got %+v", res.Partiality)
	}
}

func TestCallGraph_RouteHandlerIsRoot(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handle_fetch", 0)
	found := false
	for _, r := range res.Roots {
		if r == handleFetch {
			found = true
		}
	}
	if !found {
		t.Errorf("Flask route handler handle_fetch not registered as a call-graph root; roots=%v", res.Roots)
	}
}

func TestCallGraph_ControlFlowKeywordsAreNotEdges(t *testing.T) {
	// if/while/for/return look like "word(" but must NOT become call edges; the real
	// calls cond()/loop()/pick() must.
	src := `
def run():
    if cond():
        while loop():
            return
    for i in pick():
        pass

def cond():
    return True

def loop():
    return False

def pick():
    return []
`
	dir := writeTree(t, map[string]string{"c.py": src})
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
		if e.Caller == "" || e.Callee == "" {
			t.Errorf("empty endpoint in edge %+v", e)
		}
	}
}

// TestCallGraph_MethodChainResolves proves the scanner handles a class with a method that
// calls the sink (a different declaration shape than the module-function chain).
func TestCallGraph_MethodChainResolves(t *testing.T) {
	src := `
class Fetcher:
    def fetch(self, target):
        return self.open(target)

    def open(self, url):
        return url
`
	dir := writeTree(t, map[string]string{"svc.py": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	fetch := funcSCIP("svc", []string{"Fetcher"}, "fetch", 2)
	open := funcSCIP("svc", []string{"Fetcher"}, "open", 2)
	if !hasEdge(res.Edges, fetch, open) {
		t.Errorf("expected Fetcher.fetch -> Fetcher.open edge; edges=%+v", res.Edges)
	}
}

// TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge is the inv.5 honesty test: when a
// callee's (name, arity) matches MORE THAN ONE declared function (two modules each declare
// process(1)), the resolver cannot soundly pick one, so it fabricates NO edge. The sink
// must NOT be reachable from entry.
func TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge(t *testing.T) {
	a := `
def entry(x):
    process(x)
`
	b := `
def process(x):
    sink()

def sink():
    pass
`
	c := `
def process(x):
    pass
`
	dir := writeTree(t, map[string]string{"a.py": a, "b.py": b, "c.py": c})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("ambiguous callee must carry dynamic_dispatch reason, got %+v", res.Partiality)
	}
	entry := funcSCIP("a", nil, "entry", 1)
	for _, e := range res.Edges {
		if e.Caller == entry {
			t.Errorf("ambiguous call fabricated an edge from entry: %+v", e)
		}
	}
}

func TestCallGraph_UnknownCalleeIsPartialNoEdge(t *testing.T) {
	src := `
def run():
    external_library_call(1, 2)
`
	dir := writeTree(t, map[string]string{"c.py": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("unknown callee must declare partiality")
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
