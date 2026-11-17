package goanalysis

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestEdgeDigest_CoversEverySymbolField: the digest must separate symbols on every field, so a field
// added to plugin.Symbol fails here until edgeDigest reads it.
func TestEdgeDigest_CoversEverySymbolField(t *testing.T) {
	if n := reflect.TypeFor[plugin.Symbol]().NumField(); n != 8 {
		t.Fatalf("plugin.Symbol has %d fields; edgeDigest reads 8: update it and this count", n)
	}
	base := plugin.Symbol{Kind: "k", Package: "p", Enclosing: "e", Name: "n", Descriptor: "d", DisplayName: "dn", SCIP: "s"}
	want := edgeDigest(base, base)
	for _, mut := range []func(*plugin.Symbol){
		func(s *plugin.Symbol) { s.Kind = "k2" },
		func(s *plugin.Symbol) { s.Package = "p2" },
		func(s *plugin.Symbol) { s.Enclosing = "e2" },
		func(s *plugin.Symbol) { s.Name = "n2" },
		func(s *plugin.Symbol) { s.Descriptor = "d2" },
		func(s *plugin.Symbol) { s.Generated = true },
		func(s *plugin.Symbol) { s.DisplayName = "dn2" },
		func(s *plugin.Symbol) { s.SCIP = "s2" },
	} {
		for side := range 2 {
			a, b := base, base
			if side == 0 {
				mut(&a)
			} else {
				mut(&b)
			}
			if edgeDigest(a, b) == want {
				t.Errorf("digest ignores a field: %+v -> %+v", a, b)
			}
		}
	}
	// Field boundaries are length prefixed: moving a byte between fields changes the digest.
	if edgeDigest(plugin.Symbol{Package: "ab", Name: "c"}, base) == edgeDigest(plugin.Symbol{Package: "a", Name: "bc"}, base) {
		t.Error("digest does not separate field boundaries")
	}
	if edgeDigest(sym("a"), sym("b")) == edgeDigest(sym("b"), sym("a")) {
		t.Error("digest does not separate edge direction")
	}
}

// syntheticGraph is a graph of nChains chains of length chainLen over functions, with edges stored in
// both directions of listing and duplicated, so the index sees repeated edges.
func syntheticGraph(nChains, chainLen int, p plugin.Partiality, reach map[string][]string) reconcileGraph {
	var edges []plugin.CallEdge
	for c := range nChains {
		for i := 0; i+1 < chainLen; i++ {
			e := plugin.CallEdge{Caller: sym(frameName(c, i)), Callee: sym(frameName(c, i+1))}
			edges = append(edges, e)
			if i%3 == 0 {
				edges = append(edges, e)
			}
		}
	}
	rand.New(rand.NewSource(1)).Shuffle(len(edges), func(i, j int) { edges[i], edges[j] = edges[j], edges[i] })
	return reconcileGraph{
		CallGraph:    plugin.CallGraphResult{Partiality: p, Algorithm: "vta", Edges: edges, Roots: []plugin.Symbol{sym("root")}},
		ReflectReach: reach,
	}
}

func frameName(chain, i int) string { return fmt.Sprintf("scip-go gomod m v c%d/f%d().", chain, i) }

// findingChain is a symbol-level finding walking chain c from frame lo to hi (ingress first).
func findingChain(c, lo, hi int) vulnFinding {
	var trace []vulnFrame
	for i := hi; i >= lo; i-- { // govulncheck traces are sink-first
		trace = append(trace, vulnFrame{Module: "m", Version: "v", Package: fmt.Sprintf("c%d", c), Function: fmt.Sprintf("f%d", i)})
	}
	return vulnFinding{OSV: "GO-1", Trace: trace}
}

// TestReconcileIndex_EqualsFullDecode: for many symbol sets (no path in the graph, one path, many
// paths, a path with one pair missing, a path in no chain) the result read through the index is
// exactly the result of a decode of the whole edges entry.
func TestReconcileIndex_EqualsFullDecode(t *testing.T) {
	dir, load := summaryFixture(t)
	partialities := []plugin.Partiality{plugin.Complete(), plugin.Partial(plugin.PartialReasonDynamicDispatch), {}}
	reaches := []map[string][]string{nil, {}, {"example.com/vulnmod": {"Bad"}}}
	rng := rand.New(rand.NewSource(7))

	for pi, part := range partialities {
		for ri, reach := range reaches {
			g := syntheticGraph(12, 9, part, reach)
			b := mustJSON(t, g)
			cache := t.TempDir()
			ctx := WithRunCacheDir(context.Background(), cache)
			key := reconcileKey(context.Background(), dir, nil)
			if _, err := storeReconcileGraph(cache, key, b); err != nil {
				t.Fatal(err)
			}
			noLoad := func() (*LoadResult, error) { return nil, errors.New("tree loaded") }

			for n := range 60 {
				var findings []vulnFinding
				switch n % 5 {
				case 0: // one full path
					findings = []vulnFinding{findingChain(rng.Intn(12), 0, 8)}
				case 1: // many paths, each over a different chain and span
					for range 1 + rng.Intn(10) {
						lo := rng.Intn(5)
						findings = append(findings, findingChain(rng.Intn(12), lo, lo+1+rng.Intn(4)))
					}
				case 2: // a path past the end of its chain: the last pair is no edge
					findings = []vulnFinding{findingChain(rng.Intn(12), 3, 9)}
				case 3: // a chain the graph does not have
					findings = []vulnFinding{findingChain(100+rng.Intn(5), 0, 4)}
				case 4: // a one-frame path has no pair at all
					findings = []vulnFinding{findingChain(rng.Intn(12), 2, 2)}
				}
				scanned := scannedWith(findings...)
				if len(stacksToReachPaths(findingsToStacks(findings))) == 0 {
					t.Fatalf("case %d derived no path", n)
				}
				want := fullDecode(t, scanned, b, dir, load)
				got, err := reconciledResult(ctx, scanned, dir, summaryEnv(), noLoad, plugin.LibraryEntrypoints{})
				if err != nil {
					t.Fatalf("p%d r%d case %d: %v", pi, ri, n, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("p%d r%d case %d: index result\n%+v\nwant full decode\n%+v", pi, ri, n, got, want)
				}
			}
		}
	}
}

// TestReconcileIndex_ReconcileSeesSameEdges: reconcile, the one reader of the edges, answers the
// same from the index's restricted graph as from the whole graph, for both outcomes it can give.
func TestReconcileIndex_ReconcileSeesSameEdges(t *testing.T) {
	g := syntheticGraph(3, 6, plugin.Complete(), nil)
	enc, err := encodeReconcileIndex(g)
	if err != nil {
		t.Fatal(err)
	}
	x, ok := decodeReconcileIndex(enc)
	if !ok {
		t.Fatal("a freshly encoded index does not decode")
	}
	for _, f := range []vulnFinding{findingChain(0, 0, 5), findingChain(0, 0, 6), findingChain(9, 0, 2)} {
		paths := stacksToReachPaths(findingsToStacks([]vulnFinding{f}))
		if got, want := reconcile(paths, x.graphFor(paths).CallGraph, false), reconcile(paths, g.CallGraph, false); !reflect.DeepEqual(got, want) {
			t.Errorf("reconcile from index = %+v, from graph = %+v", got, want)
		}
	}
}

// indexFixture stores a graph with a path through the cache and returns what a damaged index test needs.
type indexFixture struct {
	dir, cache string
	ctx        context.Context
	key        []string
	load       func() (*LoadResult, error)
	scanned    vulnScan
	b          []byte
	loads      *int
}

func newIndexFixture(t *testing.T) indexFixture {
	t.Helper()
	dir, load := summaryFixture(t)
	g := syntheticGraph(4, 7, plugin.Partial(plugin.PartialReasonDynamicDispatch), map[string][]string{"m": {"F"}})
	f := indexFixture{
		dir: dir, cache: t.TempDir(), load: load, b: mustJSON(t, g),
		scanned: scannedWith(findingChain(1, 0, 6), findingChain(2, 1, 4)),
		loads:   new(int),
	}
	f.ctx = WithRunCacheDir(context.Background(), f.cache)
	f.key = reconcileKey(context.Background(), dir, nil)
	if _, err := storeReconcileGraph(f.cache, f.key, f.b); err != nil {
		t.Fatal(err)
	}
	counting := f.load
	f.load = func() (*LoadResult, error) { *f.loads++; return counting() }
	return f
}

func (f indexFixture) indexPath() string { return runCachePath(f.cache, "reconcile-index", f.key) }

func (f indexFixture) result(t *testing.T) plugin.ReachabilityResult {
	t.Helper()
	res, err := reconciledResult(f.ctx, f.scanned, f.dir, summaryEnv(), f.load, plugin.LibraryEntrypoints{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestReconcileIndex_DamagedIndexFallsBack: a truncated, corrupted or emptied index is never read as
// a graph. The result is the full decode's, the whole edges entry is what answered, and the index is
// stored whole again for the next advisory.
func TestReconcileIndex_DamagedIndexFallsBack(t *testing.T) {
	f := newIndexFixture(t)
	want := fullDecode(t, f.scanned, f.b, f.dir, f.load)
	good, err := os.ReadFile(f.indexPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeReconcileIndex(good); !ok {
		t.Fatal("stored index does not verify")
	}

	damage := map[string][]byte{"empty": {}}
	for _, n := range []int{1, 7, 8, 11, 12, 20, len(good) / 2, len(good) - 33, len(good) - 32, len(good) - 1} {
		if n >= 0 && n < len(good) {
			damage[fmt.Sprintf("truncated to %d of %d", n, len(good))] = good[:n]
		}
	}
	for _, at := range []int{0, 9, 13, len(good) / 2, len(good) - 40, len(good) - 1} {
		c := append([]byte(nil), good...)
		c[at] ^= 0x40
		damage[fmt.Sprintf("byte %d flipped", at)] = c
	}
	damage["appended"] = append(append([]byte(nil), good...), 0)
	damage["not an index"] = []byte("{}")

	for name, b := range damage {
		t.Run(name, func(t *testing.T) {
			if _, ok := decodeReconcileIndex(b); ok {
				t.Fatal("a damaged index verifies")
			}
			if err := os.WriteFile(f.indexPath(), b, 0o600); err != nil {
				t.Fatal(err)
			}
			before := *f.loads
			if got := f.result(t); !reflect.DeepEqual(got, want) {
				t.Fatalf("result from damaged index\n%+v\nwant\n%+v", got, want)
			}
			if *f.loads != before {
				t.Fatal("rebuilt the graph although the edges entry was whole")
			}
			healed, err := os.ReadFile(f.indexPath())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := decodeReconcileIndex(healed); !ok {
				t.Fatal("index was not stored whole again")
			}
		})
	}
}

// TestReconcileIndex_MissingOrStaleReadsTheGraph: an index with no edges entry behind it, and a cache
// with no index at all (one an earlier build wrote), give the full decode's result, and a missing
// edges entry rebuilds from the tree rather than answering from the index alone.
func TestReconcileIndex_MissingOrStaleReadsTheGraph(t *testing.T) {
	t.Run("no index", func(t *testing.T) {
		f := newIndexFixture(t)
		want := fullDecode(t, f.scanned, f.b, f.dir, f.load)
		if err := os.Remove(f.indexPath()); err != nil {
			t.Fatal(err)
		}
		if got := f.result(t); !reflect.DeepEqual(got, want) {
			t.Fatalf("result = %+v, want %+v", got, want)
		}
		if _, err := os.Stat(f.indexPath()); err != nil {
			t.Fatalf("index was not stored: %v", err)
		}
		if *f.loads != 0 {
			t.Fatal("rebuilt the graph although the edges entry was whole")
		}
	})
	t.Run("edges entry gone", func(t *testing.T) {
		f := newIndexFixture(t)
		if err := os.Remove(runCachePath(f.cache, "reconcile", f.key)); err != nil {
			t.Fatal(err)
		}
		f.result(t)
		if *f.loads != 1 {
			t.Fatalf("loads = %d, want 1: an index with no edges entry behind it was trusted", *f.loads)
		}
	})
	t.Run("edges entry corrupt and index damaged", func(t *testing.T) {
		f := newIndexFixture(t)
		if err := os.WriteFile(runCachePath(f.cache, "reconcile", f.key), []byte(`{"call_graph":`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.indexPath(), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := reconciledResult(f.ctx, f.scanned, f.dir, summaryEnv(), f.load, plugin.LibraryEntrypoints{}); err == nil {
			t.Fatal("a corrupt edges entry and a damaged index answered; want an error, never an empty graph")
		}
	})
}

// TestReconcileIndex_NoRunCache: with no run cache the whole graph is computed in-process, as before.
func TestReconcileIndex_NoRunCache(t *testing.T) {
	dir, load := summaryFixture(t)
	scanned := scannedWith(pathFinding)
	b, err := computeReconcileGraph(load, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := fullDecode(t, scanned, b, dir, load)
	got, err := reconciledFromCache(context.Background(), scanned, dir, load)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, %v; want %+v", got, err, want)
	}
}
