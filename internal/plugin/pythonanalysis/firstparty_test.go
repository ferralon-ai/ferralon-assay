package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// vulnReproSrc / fixedReproSrc are the source roots of the Apache Airflow experimental-API
// removal repro (advisory TEGRON-PY-AIRFLOW-EXPAPI-0001), relative to this package. The
// hermetic first-party-reachability proof runs the REAL Python analysis over both trees to
// MEASURE the reachable_candidate -> not_exploitable flip the real fix (apache/airflow
// PR #41434, Airflow 3.0.0) produces: at the fix commit the get_code sink module AND the
// decorated route handler are deleted wholesale (symbol-removal + path-removal).
const (
	vulnReproSrc  = "../../../corpus/testdata/repros/TEGRON-PY-AIRFLOW-EXPAPI-0001-vulnerable/src"
	fixedReproSrc = "../../../corpus/testdata/repros/TEGRON-PY-AIRFLOW-EXPAPI-0001-fixed/src"
)

// reverseReachable reports whether sink is reachable from any of entries over the directed
// call-graph edges. This mirrors the pipeline's firstPartyReachPaths BFS (which is unexported
// in package pipeline) so this analysis-layer test can assert the SAME structural-reachability
// property the production fallback consumes — without crossing the inv.8 import boundary
// (pipeline must not import pythonanalysis).
func reverseReachable(edges []plugin.CallEdge, entries map[string]bool, sink string) bool {
	callers := map[string][]string{}
	for _, e := range edges {
		callers[e.Callee] = append(callers[e.Callee], e.Caller)
	}
	visited := map[string]bool{sink: true}
	queue := []string{sink}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if entries[cur] {
			return true
		}
		for _, c := range callers[cur] {
			if !visited[c] {
				visited[c] = true
				queue = append(queue, c)
			}
		}
	}
	return false
}

// TestFirstParty_AirflowExpApiSinkReachableFromRouteIngress is the hermetic end-to-end proof
// that the VULNERABLE Airflow repro yields the ingredients for a CandidatePair: the REAL
// Python analysis resolves the advisory sink (get_code) to a SCIP that is a node in the REAL
// call graph, the @api_experimental.route Flask-blueprint decorator on get_dag_code resolves
// to an http_route ingress, and a directed path connects the ingress to the sink. That is
// exactly what the pipeline's firstPartyReachPaths fallback turns into a pair — the
// reachable_candidate basis.
func TestFirstParty_AirflowExpApiSinkReachableFromRouteIngress(t *testing.T) {
	ctx := context.Background()

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        vulnReproSrc,
		AdvisorySymbols: []string{"get_code"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) != 1 {
		t.Fatalf("advisory symbol get_code must resolve to exactly one sink in the vulnerable repro; got %d: %+v", len(res.Resolved), res.Resolved)
	}
	sink := res.Resolved[0].SCIP

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: vulnReproSrc})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: vulnReproSrc})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}

	// The resolved sink must be a real call-graph node (the SCIP-equality property
	// firstPartyReachPaths relies on: resolver, call graph, and ingress all use the same
	// emitter).
	sinkIsNode := false
	for _, e := range cg.Edges {
		if e.Caller == sink || e.Callee == sink {
			sinkIsNode = true
		}
	}
	if !sinkIsNode {
		t.Fatalf("resolved sink %q is not a node in the call graph;\nedges=%+v", sink, cg.Edges)
	}

	// Entries are the route ingresses plus call-graph roots — exactly the set
	// firstPartyReachPaths terminates its reverse BFS at.
	entries := map[string]bool{}
	for _, in := range ing.Ingresses {
		entries[in.Symbol] = true
	}
	for _, r := range cg.Roots {
		entries[r] = true
	}
	if len(entries) == 0 {
		t.Fatal("no ingress/root entries discovered for the repro")
	}

	if !reverseReachable(cg.Edges, entries, sink) {
		t.Fatalf("sink %q is NOT reachable from any ingress/root over the call graph;\nentries=%v\nedges=%+v", sink, entries, cg.Edges)
	}

	// The Flask-blueprint route ingress (@api_experimental.route on get_dag_code)
	// specifically must be present.
	routeFound := false
	for _, in := range ing.Ingresses {
		if in.Kind == "http_route" {
			routeFound = true
		}
	}
	if !routeFound {
		t.Errorf("expected an http_route ingress (@api_experimental.route get_dag_code) in the repro; got %+v", ing.Ingresses)
	}
}

// TestFirstParty_AirflowExpApiFixedRemovesSink confirms the FIXED repro flips the verdict to
// not_exploitable by STRUCTURAL removal: at the real fix commit the get_code sink module is
// deleted wholesale, so the advisory sink no longer resolves at all (len(Resolved) == 0).
// With no resolved sink there is no ingress→sink path — the not_exploitable basis. This is
// the INVERSE of the JS PatchedReproStillResolvesSinkAndIngress control: the JS patch is a
// runtime guard (sink stays), whereas the Airflow fix is a structural delete (sink gone),
// which is the only shape that flips the Assess-tier verdict.
func TestFirstParty_AirflowExpApiFixedRemovesSink(t *testing.T) {
	ctx := context.Background()

	res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        fixedReproSrc,
		AdvisorySymbols: []string{"get_code"},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) != 0 {
		t.Fatalf("fixed repro: advisory sink get_code must NOT resolve (it is deleted wholesale); got %d: %+v", len(res.Resolved), res.Resolved)
	}
}
