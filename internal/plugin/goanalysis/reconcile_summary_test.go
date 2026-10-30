package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// summaryTree is a module whose main package calls vulnmod.Safe; a module-level finding on vulnmod
// refutes it and so asks reconciledResult for the loaded program.
var summaryTree = merge(reflectBase, map[string]string{"main.go": "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n"})

// summaryFixture loads summaryTree once and returns its directory and load function.
func summaryFixture(t *testing.T) (string, func() (*LoadResult, error)) {
	t.Helper()
	dir := writeTree(t, summaryTree)
	loaded, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, func() (*LoadResult, error) { return loaded, nil }
}

// pathFinding is a symbol-level finding main -> vulnmod.Bad, which derives one path.
var pathFinding = vulnFinding{OSV: "GO-1", Trace: []vulnFrame{
	{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod", Function: "Bad"},
	{Module: "example.com/m", Package: "example.com/m", Function: "main"},
}}

// moduleFinding is a module-level finding on vulnmod: no path, and a refutation.
var moduleFinding = vulnFinding{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}

func scannedWith(findings ...vulnFinding) vulnScan {
	return vulnScan{
		findings: findings,
		imports:  map[string][]string{"example.com/vulnmod": {"example.com/vulnmod"}},
		symbols:  map[string][]string{"example.com/vulnmod": {"Bad"}},
	}
}

// pathEdges is every consecutive pair along the paths findings derive.
func pathEdges(findings []vulnFinding) []plugin.CallEdge {
	var edges []plugin.CallEdge
	for _, p := range stacksToReachPaths(findingsToStacks(findings)) {
		for i := 0; i+1 < len(p.Trace); i++ {
			edges = append(edges, plugin.CallEdge{Caller: p.Trace[i], Callee: p.Trace[i+1]})
		}
	}
	return edges
}

// fullDecode is the result reconciledResult gave before the summary: every field from a decode of
// the whole edges entry.
func fullDecode(t *testing.T, scanned vulnScan, b []byte, dir string, load func() (*LoadResult, error)) plugin.ReachabilityResult {
	t.Helper()
	g, err := decodeReconcileGraph(b)
	if err != nil {
		t.Fatal(err)
	}
	res, err := resultFromGraph(context.Background(), scanned, g, dir, summaryEnv(), load, plugin.LibraryEntrypoints{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func summaryEnv() []string { return append(os.Environ(), "GOWORK=off") }

func reconciledFromCache(ctx context.Context, scanned vulnScan, dir string, load func() (*LoadResult, error)) (plugin.ReachabilityResult, error) {
	return reconciledResult(ctx, scanned, dir, summaryEnv(), load, plugin.LibraryEntrypoints{})
}

// TestReconciledResult_SummaryEqualsFullDecode: reading the summary for a result with no path, and
// the whole graph for one with a path, gives exactly the result a decode of the whole graph gives,
// for every partiality and reflect reach the graph may carry.
func TestReconciledResult_SummaryEqualsFullDecode(t *testing.T) {
	dir, load := summaryFixture(t)
	partialities := []struct {
		name string
		p    plugin.Partiality
	}{
		{"complete", plugin.Complete()},
		{"reasons", plugin.Partial(plugin.PartialReasonDynamicDispatch, plugin.PartialReasonCgo)},
		{"scoped only", plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/vulnmod"}}}},
		{"incomplete with no reasons", plugin.Partiality{}},
	}
	reaches := []struct {
		name  string
		reach map[string][]string
	}{
		{"reach present, misses", map[string][]string{"example.com/vulnmod": {"Safe"}}},
		{"reach present, hits", map[string][]string{"example.com/vulnmod": {"Bad"}}},
		{"reach absent", map[string][]string{}},
		{"reach unknown", nil},
	}
	findings := []struct {
		name     string
		scanned  vulnScan
		edges    []plugin.CallEdge
		withPath bool
	}{
		{"no finding", scannedWith(), nil, false},
		{"module-level refutation", scannedWith(moduleFinding), nil, false},
		{"path, every pair an edge", scannedWith(pathFinding), pathEdges([]vulnFinding{pathFinding}), true},
		{"path, a pair missing", scannedWith(pathFinding), nil, true},
	}
	for _, pt := range partialities {
		for _, rt := range reaches {
			for _, ft := range findings {
				t.Run(pt.name+"/"+rt.name+"/"+ft.name, func(t *testing.T) {
					b, err := json.Marshal(reconcileGraph{
						CallGraph:    plugin.CallGraphResult{Partiality: pt.p, Algorithm: "vta", Edges: ft.edges, Roots: []plugin.Symbol{{SCIP: "root"}}},
						ReflectReach: rt.reach,
					})
					if err != nil {
						t.Fatal(err)
					}
					want := fullDecode(t, ft.scanned, b, dir, load)

					cache := t.TempDir()
					ctx := WithRunCacheDir(context.Background(), cache)
					key := reconcileKey(dir)
					if _, err := storeReconcileGraph(cache, key, b); err != nil {
						t.Fatal(err)
					}
					got, err := reconciledFromCache(ctx, ft.scanned, dir, load)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("result = %+v\nwant the full decode's %+v", got, want)
					}

					// Garble the edges entry and keep it present: a result with no path still reads
					// only the summary, and one with a path decodes the edges entry and fails.
					if err := os.WriteFile(runCachePath(cache, "reconcile", key), []byte("not json"), 0o600); err != nil {
						t.Fatal(err)
					}
					got, err = reconciledFromCache(ctx, ft.scanned, dir, load)
					if ft.withPath {
						if err == nil {
							t.Fatalf("with a path the garbled edges entry was not decoded: %+v", got)
						}
					} else if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("with no path the edges entry was decoded: %+v, %v", got, err)
					}
				})
			}
		}
	}
}

// TestReconcileSummaryGraph_UntrustedFallsBack: a summary is read only when the marker holds its id
// and the edges entry is present; otherwise the result is the full decode, or a recompute when the
// edges entry is gone. The stored summary differs from the edges entry so that reading it shows.
func TestReconcileSummaryGraph_UntrustedFallsBack(t *testing.T) {
	dir, load := summaryFixture(t)
	scanned := scannedWith(moduleFinding)
	edges, err := json.Marshal(reconcileGraph{CallGraph: plugin.CallGraphResult{Partiality: plugin.Complete()}, ReflectReach: map[string][]string{}})
	if err != nil {
		t.Fatal(err)
	}
	full := fullDecode(t, scanned, edges, dir, load)
	recomputed, err := reconciledResult(context.Background(), scanned, dir, summaryEnv(), load, plugin.LibraryEntrypoints{})
	if err != nil {
		t.Fatal(err)
	}
	forged := reconcileSummary{ID: "forged", Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch), ReflectReach: nil}
	forgedRes := fullDecode(t, scanned, mustJSON(t, reconcileGraph{CallGraph: plugin.CallGraphResult{Partiality: forged.Partiality}, ReflectReach: forged.ReflectReach}), dir, load)
	if reflect.DeepEqual(forgedRes, full) {
		t.Fatal("the forged summary does not change the result; the cases below cannot tell it was read")
	}

	cases := []struct {
		name   string
		edges  bool
		marker []byte // nil: no marker
		sum    []byte // nil: no summary
		want   plugin.ReachabilityResult
	}{
		{"trusted: marker holds its id, edges present", true, []byte("forged"), mustJSON(t, forged), forgedRes},
		{"summary present, edges missing", false, []byte("forged"), mustJSON(t, forged), recomputed},
		{"summary present, marker missing", true, nil, mustJSON(t, forged), full},
		{"summary present, marker holds another id", true, []byte("other"), mustJSON(t, forged), full},
		{"summary with no id, empty marker", true, []byte(""), mustJSON(t, reconcileSummary{Partiality: forged.Partiality}), full},
		{"summary missing, edges present", true, []byte("forged"), nil, full},
		{"summary corrupt", true, []byte("forged"), []byte(`{"id":"forged","partiality":`), full},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := t.TempDir()
			key := reconcileKey(dir)
			write := func(kind string, b []byte) {
				if b == nil {
					return
				}
				if err := os.WriteFile(runCachePath(cache, kind, key), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.edges {
				write("reconcile", edges)
			}
			write("reconcile-marker", tc.marker)
			write("reconcile-summary", tc.sum)
			got, err := reconciledFromCache(WithRunCacheDir(context.Background(), cache), scanned, dir, load)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("result = %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReconcileCallGraph_EntryBytes: the edges entry holds exactly json.Marshal(reconcileGraph{...})
// as the compute encoded it, and the compute that stored it also stored a summary the reader trusts.
// Without a run cache the summary graph is the whole graph, computed in-process.
func TestReconcileCallGraph_EntryBytes(t *testing.T) {
	dir, load := summaryFixture(t)
	want, err := computeReconcileGraph(load)
	if err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	ctx := WithRunCacheDir(context.Background(), cache)
	g, err := reconcileCallGraph(ctx, dir, load)
	if err != nil {
		t.Fatal(err)
	}
	key := reconcileKey(dir)
	got, err := os.ReadFile(runCachePath(cache, "reconcile", key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("edges entry is not the compute's encoding:\n%s\nwant\n%s", got, want)
	}
	if again, err := json.Marshal(reconcileGraph{CallGraph: g.CallGraph, ReflectReach: g.ReflectReach}); err != nil || !bytes.Equal(again, want) {
		t.Fatalf("edges entry is not json.Marshal(reconcileGraph{...}): %v", err)
	}
	s, ok := readReconcileSummary(cache, key)
	if !ok || !reflect.DeepEqual(s.Partiality, g.CallGraph.Partiality) || !reflect.DeepEqual(s.ReflectReach, g.ReflectReach) {
		t.Fatalf("stored summary = %+v (trusted %v), want the graph's partiality and reflect reach", s, ok)
	}

	inProcess, err := reconcileSummaryGraph(context.Background(), dir, load)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inProcess, g) {
		t.Fatalf("without a run cache the summary graph = %+v, want the whole graph", inProcess)
	}
}

// TestReconcileSummaryGraph_ConcurrentComputes: computes racing on one key each store a whole graph
// and its summary; whatever a reader is served, from the summary or the edges entry, its partiality
// and reflect reach come from one compute.
func TestReconcileSummaryGraph_ConcurrentComputes(t *testing.T) {
	cache := t.TempDir()
	ctx := WithRunCacheDir(context.Background(), cache)
	const buildDir = "/src"
	key := reconcileKey(buildDir)
	graph := func(i int) []byte {
		return mustJSON(t, reconcileGraph{
			CallGraph:    plugin.CallGraphResult{Partiality: plugin.Partial("r" + strconv.Itoa(i)), Edges: []plugin.CallEdge{{Caller: sym("a"), Callee: sym("b")}}},
			ReflectReach: map[string][]string{"m": {"F" + strconv.Itoa(i)}},
		})
	}
	noLoad := func() (*LoadResult, error) { return nil, errors.New("tree loaded") }
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				if _, err := storeReconcileGraph(cache, key, graph(i)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				g, err := reconcileSummaryGraph(ctx, buildDir, noLoad)
				if err != nil {
					continue // nothing stored yet
				}
				if len(g.CallGraph.Partiality.Reasons) != 1 || len(g.ReflectReach["m"]) != 1 ||
					g.CallGraph.Partiality.Reasons[0][1:] != g.ReflectReach["m"][0][1:] {
					t.Errorf("served a mix of computes: %+v / %v", g.CallGraph.Partiality, g.ReflectReach)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// BenchmarkReconcileDecode: what one Reachability call pays to read a cached 100k-edge reconcile
// graph, with no path (the summary) and with a path (the whole graph, as every call paid before).
func BenchmarkReconcileDecode(b *testing.B) {
	cache := b.TempDir()
	const buildDir = "/src"
	key := reconcileKey(buildDir)
	edges := make([]plugin.CallEdge, 100_000)
	for i := range edges {
		edges[i] = plugin.CallEdge{
			Caller: sym(fmt.Sprintf("scip-go gomod github.com/example/project v1.2.3 `github.com/example/project/internal/pkg%d`/Caller%d().", i%500, i)),
			Callee: sym(fmt.Sprintf("scip-go gomod github.com/example/dep v0.9.1 `github.com/example/dep/pkg%d`/Callee%d().", i%700, i)),
		}
	}
	reach := map[string][]string{}
	for i := range 200 {
		reach[fmt.Sprintf("github.com/example/dep/pkg%d", i)] = []string{"A", "B", "C"}
	}
	enc, err := json.Marshal(reconcileGraph{CallGraph: plugin.CallGraphResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch), Algorithm: "vta", Edges: edges}, ReflectReach: reach})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := storeReconcileGraph(cache, key, enc); err != nil {
		b.Fatal(err)
	}
	b.Logf("edges entry %d bytes", len(enc))
	ctx := WithRunCacheDir(context.Background(), cache)
	noLoad := func() (*LoadResult, error) { return nil, errors.New("tree loaded") }
	b.Run("no-path", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := reconcileSummaryGraph(ctx, buildDir, noLoad); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("path", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := reconcileCallGraph(ctx, buildDir, noLoad); err != nil {
				b.Fatal(err)
			}
		}
	})
}
