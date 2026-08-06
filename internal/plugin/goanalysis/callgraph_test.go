package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func callGraphMust(t *testing.T, algo string) plugin.CallGraphResult {
	t.Helper()
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: fixtureDir, Algorithm: algo})
	if err != nil {
		t.Fatalf("CallGraph(%q): %v", algo, err)
	}
	return res
}

// hasEdge reports whether the graph contains an edge whose caller SCIP id
// contains callerSub and whose callee SCIP id contains calleeSub.
func hasEdge(edges []plugin.CallEdge, callerSub, calleeSub string) bool {
	for _, e := range edges {
		if strings.Contains(e.Caller, callerSub) && strings.Contains(e.Callee, calleeSub) {
			return true
		}
	}
	return false
}

func TestCallGraph_ContainsKnownChain(t *testing.T) {
	res := callGraphMust(t, "")
	if res.Algorithm != "vta" {
		t.Errorf("default algorithm should be vta, got %q", res.Algorithm)
	}
	if !hasEdge(res.Edges, "main", "Handle") {
		t.Errorf("expected edge main -> (*Service).Handle; edges=%v", res.Edges)
	}
	if !hasEdge(res.Edges, "Handle", "Sink") {
		t.Errorf("expected edge (*Service).Handle -> util.Sink; edges=%v", res.Edges)
	}
}

func TestCallGraph_RootsIncludeMain(t *testing.T) {
	res := callGraphMust(t, "")
	found := false
	for _, r := range res.Roots {
		if strings.Contains(r, "fixturemod") && strings.Contains(r, "main") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a main root among roots=%v", res.Roots)
	}
}

func TestCallGraph_AlgorithmSwitch(t *testing.T) {
	for _, algo := range []string{"vta", "cha", "rta"} {
		res := callGraphMust(t, algo)
		if res.Algorithm != algo {
			t.Errorf("requested %q, used %q", algo, res.Algorithm)
		}
		if len(res.Edges) == 0 {
			t.Errorf("algorithm %q built an empty graph", algo)
		}
		if !hasEdge(res.Edges, "Handle", "Sink") {
			t.Errorf("algorithm %q missing Handle->Sink edge", algo)
		}
	}
}

func TestCallGraph_UnknownAlgorithmIsError(t *testing.T) {
	_, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: fixtureDir, Algorithm: "bogus"})
	if err == nil {
		t.Fatal("expected an error for an unknown algorithm")
	}
}

func TestCallGraph_BrokenDirIsHardError(t *testing.T) {
	_, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir (inv.4)")
	}
}

func ingressesMust(t *testing.T) plugin.IngressResult {
	t.Helper()
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: fixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	return res
}

func hasIngress(ings []plugin.Ingress, kind, symbolSub string) bool {
	for _, in := range ings {
		if in.Kind == kind && strings.Contains(in.Symbol, symbolSub) {
			return true
		}
	}
	return false
}

func TestFindIngresses_FindsMain(t *testing.T) {
	res := ingressesMust(t)
	if !hasIngress(res.Ingresses, "main", "main") {
		t.Errorf("expected a main ingress; got %+v", res.Ingresses)
	}
}

func TestFindIngresses_FindsHTTPHandler(t *testing.T) {
	res := ingressesMust(t)
	if !hasIngress(res.Ingresses, "handler", "Handle") {
		t.Errorf("expected an http handler ingress for Handle; got %+v", res.Ingresses)
	}
}

func TestFindIngresses_FindsRegisteredRoute(t *testing.T) {
	res := ingressesMust(t)
	found := false
	for _, in := range res.Ingresses {
		if in.Kind == "http_route" && in.Selector == "/handle" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an http_route ingress with selector /handle; got %+v", res.Ingresses)
	}
}

func TestFindIngresses_DoesNotGuessArbitraryExports(t *testing.T) {
	res := ingressesMust(t)
	for _, in := range res.Ingresses {
		// util.Sink and service.New are exported but are NOT ingresses.
		if strings.Contains(in.Symbol, "Sink") || strings.Contains(in.Symbol, "New(") {
			t.Errorf("must not fabricate ingress for arbitrary export: %+v", in)
		}
	}
}
