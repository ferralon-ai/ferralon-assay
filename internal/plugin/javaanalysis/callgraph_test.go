package javaanalysis

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

// A servlet whose doGet calls a utility method that calls the SSRF sink — the
// canonical Increment-1 chain. The callee names are unique by (name,arity) so the
// source-lexical resolver connects every edge soundly.
const servletChain = `
package com.example.web;
public class FetchServlet extends javax.servlet.http.HttpServlet {
    public void doGet(Object req, Object resp) {
        handle(req);
    }
    void handle(Object req) {
        UrlFetcher.fetch("http://internal");
    }
}
`

const utilFetcher = `
package com.example.web;
public class UrlFetcher {
    static String fetch(String url) {
        return open(url);
    }
    static String open(String url) {
        return url;
    }
}
`

func TestCallGraph_ServletChainEdgesResolve(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"web/FetchServlet.java": servletChain,
		"web/UrlFetcher.java":   utilFetcher,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	doGet := methodSCIP("com.example.web", []string{"FetchServlet"}, "doGet", 2)
	handle := methodSCIP("com.example.web", []string{"FetchServlet"}, "handle", 1)
	fetch := methodSCIP("com.example.web", []string{"UrlFetcher"}, "fetch", 1)
	open := methodSCIP("com.example.web", []string{"UrlFetcher"}, "open", 1)

	for _, want := range [][2]string{{doGet, handle}, {handle, fetch}, {fetch, open}} {
		if !hasEdge(res.Edges, want[0], want[1]) {
			t.Errorf("missing edge %s -> %s\nedges: %+v", want[0], want[1], res.Edges)
		}
	}
}

func TestCallGraph_ServletDoGetIsRoot(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"web/FetchServlet.java": servletChain,
		"web/UrlFetcher.java":   utilFetcher,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	doGet := methodSCIP("com.example.web", []string{"FetchServlet"}, "doGet", 2)
	found := false
	for _, r := range res.Roots {
		if r.SCIP == doGet {
			found = true
		}
	}
	if !found {
		t.Errorf("servlet doGet not registered as a call-graph root; roots=%v", res.Roots)
	}
}

func TestCallGraph_ControlFlowKeywordsAreNotEdges(t *testing.T) {
	// if/for/while/return/new look like "word(" but must NOT become call edges.
	src := `
package p;
public class C {
    void run() {
        if (cond()) { while (loop()) { return; } }
        for (int i = 0; i < 1; i++) {}
        Object o = new Object();
    }
    boolean cond() { return true; }
    boolean loop() { return false; }
}
`
	dir := writeProgram(t, map[string]string{"C.java": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	run := methodSCIP("p", []string{"C"}, "run", 0)
	cond := methodSCIP("p", []string{"C"}, "cond", 0)
	loop := methodSCIP("p", []string{"C"}, "loop", 0)
	if !hasEdge(res.Edges, run, cond) || !hasEdge(res.Edges, run, loop) {
		t.Errorf("expected run->cond and run->loop edges; edges=%+v", res.Edges)
	}
	for _, e := range res.Edges {
		// No edge's callee should be a control-flow keyword node (those resolve to
		// nothing, so they can never appear, but assert no spurious caller either).
		if e.Caller.SCIP == "" || e.Callee.SCIP == "" {
			t.Errorf("empty endpoint in edge %+v", e)
		}
	}
}

// TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge is the inv.5 honesty test:
// when a callee's (name,arity) matches MORE THAN ONE declared method, the resolver
// cannot soundly pick one, so it fabricates NO edge and declares partiality
// (dynamic_dispatch). The unresolved sink must therefore NOT be reachable.
func TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge(t *testing.T) {
	// Two distinct types both declare process(1); a call to process(x) is ambiguous.
	src := `
package p;
public class Caller {
    void entry(Object x) {
        process(x);
    }
}
class A {
    void process(Object x) { sink(); }
    void sink() {}
}
class B {
    void process(Object x) {}
}
`
	dir := writeProgram(t, map[string]string{"All.java": src})
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
	// The ambiguous call must NOT have produced an edge from entry to either process.
	entry := methodSCIP("p", []string{"Caller"}, "entry", 1)
	for _, e := range res.Edges {
		if e.Caller.SCIP == entry {
			t.Errorf("ambiguous call fabricated an edge from entry: %+v", e)
		}
	}
}

func TestCallGraph_UnknownCalleeIsPartialNoEdge(t *testing.T) {
	// A call to a library/interface method with no source declaration must not
	// fabricate an edge and must declare partiality.
	src := `
package p;
public class C {
    void run() {
        externalLibraryCall(1, 2);
    }
}
`
	dir := writeProgram(t, map[string]string{"C.java": src})
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
