package javaanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reachFixture writes the canonical Increment-1 servlet chain plus a utility
// fetcher that has an ORPHAN method no caller invokes, into a temp build dir. The
// resolved chain is doGet(ingress) -> handle -> UrlFetcher.fetch -> open; orphan()
// is a declared method with no incoming edge (the not-reachable control).
func reachFixture(t *testing.T) string {
	t.Helper()
	const utilFetcherWithOrphan = `
package com.example.web;
public class UrlFetcher {
    static String fetch(String url) {
        return open(url);
    }
    static String open(String url) {
        return url;
    }
    static String orphan(String url) {
        return open(url);
    }
}
`
	return writeProgram(t, map[string]string{
		"web/FetchServlet.java": servletChain,
		"web/UrlFetcher.java":   utilFetcherWithOrphan,
	})
}

// ambiguousChain has a servlet whose doGet dispatches to an ambiguous overload the
// lexical resolver refuses to connect (two types declare process(1)), so the sink
// is NOT connected to the ingress and the call graph is Partial(dynamic_dispatch).
const ambiguousChain = `
package com.example.web;
public class FetchServlet extends javax.servlet.http.HttpServlet {
    public void doGet(Object req, Object resp) {
        process(req);
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

func TestReachability_ReachableFromServletIngress(t *testing.T) {
	dir := reachFixture(t)
	fetch := methodSCIP("com.example.web", []string{"UrlFetcher"}, "fetch", 1)
	doGet := methodSCIP("com.example.web", []string{"FetchServlet"}, "doGet", 2)
	handle := methodSCIP("com.example.web", []string{"FetchServlet"}, "handle", 1)

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{fetch},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("expected exactly one reach path, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Sink.SCIP != fetch {
		t.Errorf("path sink = %q, want %q", p.Sink.SCIP, fetch)
	}
	if p.Ingress.SCIP != doGet {
		t.Errorf("path ingress = %q, want servlet doGet %q", p.Ingress.SCIP, doGet)
	}
	wantTrace := []string{doGet, handle, fetch}
	if len(p.Trace) != len(wantTrace) {
		t.Fatalf("trace = %v, want %v", p.Trace, wantTrace)
	}
	for i := range wantTrace {
		if p.Trace[i].SCIP != wantTrace[i] {
			t.Errorf("trace[%d] = %q, want %q (full trace %v)", i, p.Trace[i].SCIP, wantTrace[i], p.Trace)
		}
	}
	// Every callee in this fixture resolves uniquely and no library call is made,
	// so the call graph is Complete and the reachable path carries no partiality.
	if !res.Partiality.Complete {
		t.Errorf("fully-resolved reachable path should be Complete, got %+v", res.Partiality)
	}
}

func TestReachability_NotReachableIsNoKnownIngress(t *testing.T) {
	dir := reachFixture(t)
	orphan := methodSCIP("com.example.web", []string{"UrlFetcher"}, "orphan", 1)

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{orphan},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Errorf("orphan sink must yield no path, got %+v", res.Paths)
	}
	// Honesty (inv.5): no path found is UNKNOWN, declared no_known_ingress — never
	// a clean "not reachable"/Complete verdict.
	if res.Partiality.Complete {
		t.Errorf("unreachable sink must NOT be Complete (fail open), got Complete")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("unreachable sink must declare no_known_ingress, got %+v", res.Partiality)
	}
}

// TestReachability_AmbiguousDispatchIsPartialNotReachable is the doctrine test:
// when the only route to the sink runs through an ambiguous callee the resolver
// will not fabricate, reachability must return Partial (carrying BOTH the
// call-graph dynamic_dispatch reason AND no_known_ingress) with no path — never a
// false not-reachable. Uncertainty stays uncertain.
func TestReachability_AmbiguousDispatchIsPartialNotReachable(t *testing.T) {
	dir := writeProgram(t, map[string]string{"web/All.java": ambiguousChain})
	sink := methodSCIP("com.example.web", []string{"A"}, "sink", 0)

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{sink},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Errorf("ambiguous route must yield no path, got %+v", res.Paths)
	}
	if res.Partiality.Complete {
		t.Fatal("ambiguous dispatch must declare partiality, got Complete")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("must carry dynamic_dispatch from the partial call graph, got %+v", res.Partiality)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("must carry no_known_ingress for the unreached sink, got %+v", res.Partiality)
	}
}

func TestReachability_MissingBuildDirIsHardError(t *testing.T) {
	_, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}
