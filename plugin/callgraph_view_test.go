package plugin

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

// richGraphPlugin answers CallGraph with a graph whose every slice is populated, so a test can
// reach each one through a view.
type richGraphPlugin struct {
	*countingPlugin
}

func richGraph() CallGraphResult {
	a := Symbol{Kind: SymbolKindFunction, Package: "example.com/p", Name: "A", DisplayName: "p.A<&>", SCIP: "scip:p#A"}
	b := Symbol{Kind: SymbolKindFunction, Package: "example.com/p", Name: "B", DisplayName: "p.B", SCIP: "scip:p#B"}
	return CallGraphResult{
		Partiality: Partiality{
			Reasons: []string{PartialReasonReflection},
			Scoped:  []ScopedReason{{Reason: PartialReasonReflection, Package: "pkg:golang/x", Targets: []string{"pkg:golang/y"}}},
		},
		Algorithm: "vta",
		Edges:     []CallEdge{{Caller: a, Callee: b}, {Caller: b, Callee: a}},
		Roots:     []Symbol{a},
		Escaped:   []Symbol{b},
	}
}

func (p richGraphPlugin) CallGraph(_ context.Context, _ CallGraphRequest) (CallGraphResult, error) {
	if err := p.hit(OpCallGraph); err != nil {
		return CallGraphResult{}, err
	}
	return richGraph(), nil
}

// TestSharedCallGraph pins what SharedCallGraph hands out: the plugin's graph, with the plugin run
// once per memo whichever of CallGraph and SharedCallGraph runs first, and one decode shared by every
// view of a memoized plugin. A plugin that is not memoized still answers through the fallback.
func TestSharedCallGraph(t *testing.T) {
	ctx := context.Background()
	req := CallGraphRequest{BuildDir: "/src"}
	tests := []struct {
		name     string
		memoized bool
		// interfaceFirst calls CallGraph before any view.
		interfaceFirst bool
		wantRuns       int
	}{
		{"memoized, view first", true, false, 1},
		{"memoized, CallGraph first", true, true, 1},
		{"not memoized", false, false, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inner := richGraphPlugin{newCountingPlugin()}
			var lp LanguagePlugin = inner
			if tc.memoized {
				lp = Memoize(inner)
			}
			if tc.interfaceFirst {
				if _, err := lp.CallGraph(ctx, req); err != nil {
					t.Fatal(err)
				}
			}
			var views []CallGraphView
			for len(views) < 3-btoi(tc.interfaceFirst) {
				v, err := SharedCallGraph(ctx, lp, req)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := mustJSON(t, v), mustJSON(t, richGraph()); got != want {
					t.Errorf("view: got %s, want %s", got, want)
				}
				views = append(views, v)
			}
			if n := inner.count(OpCallGraph); n != tc.wantRuns {
				t.Errorf("inner calls = %d, want %d", n, tc.wantRuns)
			}
			shared := views[0].cg == views[1].cg
			if tc.memoized && !shared {
				t.Error("views of a memoized plugin decoded the graph separately; they are meant to share one decode")
			}
			if !tc.memoized && shared {
				t.Error("views of separate CallGraph answers share a graph")
			}
		})
	}
}

// TestSharedCallGraphFailure pins that a failed call graph reaches the view's caller and is not
// cached.
func TestSharedCallGraphFailure(t *testing.T) {
	ctx := context.Background()
	inner := richGraphPlugin{newCountingPlugin()}
	inner.fail[OpCallGraph] = true
	lp := Memoize(inner)
	if _, err := SharedCallGraph(ctx, lp, CallGraphRequest{BuildDir: "/src"}); err == nil {
		t.Fatal("want the inner error")
	}
	inner.mu.Lock()
	inner.fail[OpCallGraph] = false
	inner.mu.Unlock()
	v, err := SharedCallGraph(ctx, lp, CallGraphRequest{BuildDir: "/src"})
	if err != nil {
		t.Fatalf("retry after a failure: %v", err)
	}
	if v.EdgeCount() != len(richGraph().Edges) {
		t.Errorf("EdgeCount = %d, want %d", v.EdgeCount(), len(richGraph().Edges))
	}
}

// TestCallGraphViewNoAlias pins that nothing a view returns aliases the shared graph: each
// accessor's result is edited, then the graph is read again through the same view and a fresh one.
func TestCallGraphViewNoAlias(t *testing.T) {
	ctx := context.Background()
	want := mustJSON(t, richGraph())
	tests := []struct {
		name string
		edit func(t *testing.T, v CallGraphView)
	}{
		{"partiality", func(t *testing.T, v CallGraphView) {
			p := v.Partiality()
			p.Complete = !p.Complete
			p.Reasons[0] = "mutated"
			p.Scoped[0].Reason = "mutated"
			p.Scoped[0].Targets[0] = "mutated"
			_ = append(p.Reasons[:0], "mutated")
			_ = append(p.Scoped[0].Targets[:0], "mutated")
		}},
		{"edges", func(t *testing.T, v CallGraphView) {
			for e := range v.Edges() {
				e.Caller.SCIP = "mutated"
				e.Callee = Symbol{}
			}
		}},
		{"roots", func(t *testing.T, v CallGraphView) {
			for r := range v.Roots() {
				r.SCIP = "mutated"
			}
		}},
		{"marshal", func(t *testing.T, v CallGraphView) {
			b, err := v.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			for i := range b {
				b[i] = 'x'
			}
		}},
		{"append into spare capacity", func(t *testing.T, v CallGraphView) {
			b, err := v.AppendJSON(make([]byte, 0, 1<<16))
			if err != nil {
				t.Fatal(err)
			}
			for i := range b {
				b[i] = 'x'
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lp := Memoize(richGraphPlugin{newCountingPlugin()})
			v, err := SharedCallGraph(ctx, lp, CallGraphRequest{BuildDir: "/src"})
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(t, v)
			again, err := SharedCallGraph(ctx, lp, CallGraphRequest{BuildDir: "/src"})
			if err != nil {
				t.Fatal(err)
			}
			for name, view := range map[string]CallGraphView{"same view": v, "fresh view": again} {
				if got := mustJSON(t, view); got != want {
					t.Errorf("%s after the edit: got %s, want %s", name, got, want)
				}
				if got := mustJSON(t, readBack(view)); got != want {
					t.Errorf("%s read back through its accessors after the edit: got %s, want %s", name, got, want)
				}
			}
		})
	}
}

// readBack rebuilds the graph's fields that a view exposes from its accessors.
func readBack(v CallGraphView) CallGraphResult {
	g := richGraph()
	g.Partiality = v.Partiality()
	g.Edges = slices.Collect(v.Edges())
	g.Roots = slices.Collect(v.Roots())
	return g
}

// TestCallGraphViewEncoding pins that a view encodes exactly as json.Marshal encodes the graph it
// views, whether it holds the memo's encoding or encodes the graph itself.
func TestCallGraphViewEncoding(t *testing.T) {
	ctx := context.Background()
	memo, err := SharedCallGraph(ctx, Memoize(richGraphPlugin{newCountingPlugin()}), CallGraphRequest{BuildDir: "/src"})
	if err != nil {
		t.Fatal(err)
	}
	if memo.enc == nil {
		t.Fatal("a memoized view holds no encoding; the test would not cover that path")
	}
	tests := []struct {
		name string
		v    CallGraphView
		want any
	}{
		{"memoized", memo, richGraph()},
		{"wrapped", NewCallGraphView(richGraph()), richGraph()},
		{"zero", CallGraphView{}, CallGraphResult{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			want, err := json.Marshal(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tc.v.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("MarshalJSON: got %s, want %s", got, want)
			}
			got, err = tc.v.AppendJSON([]byte("prefix"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "prefix"+string(want) {
				t.Errorf("AppendJSON: got %s, want prefix%s", got, want)
			}
		})
	}
}

// TestCallGraphViewSurface pins the view's surface: no exported field, and exactly the methods
// below. A new method must be added here, which is where to check it returns nothing aliasing the
// graph.
func TestCallGraphViewSurface(t *testing.T) {
	typ := reflect.TypeOf(CallGraphView{})
	for i := 0; i < typ.NumField(); i++ {
		if f := typ.Field(i); f.IsExported() {
			t.Errorf("CallGraphView exports field %s", f.Name)
		}
	}
	var methods []string
	for i := 0; i < typ.NumMethod(); i++ {
		methods = append(methods, typ.Method(i).Name)
	}
	want := []string{"AppendJSON", "Callers", "EdgeCount", "Edges", "IsRoot", "MarshalJSON", "Partiality", "Roots", "Symbol"}
	if !slices.Equal(methods, want) {
		t.Errorf("CallGraphView methods = %v, want %v", methods, want)
	}
	if n := reflect.PointerTo(typ).NumMethod(); n != len(want) {
		t.Errorf("*CallGraphView has %d methods, want %d (no pointer-receiver methods)", n, len(want))
	}
}

// TestSharedCallGraphConcurrent pins that concurrent views and CallGraph calls run the plugin once
// and all see the plugin's graph. Run it under -race.
func TestSharedCallGraphConcurrent(t *testing.T) {
	ctx := context.Background()
	inner := richGraphPlugin{newCountingPlugin()}
	lp := Memoize(inner)
	want := mustJSON(t, richGraph())
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var got any
			var err error
			if i%2 == 0 {
				got, err = SharedCallGraph(ctx, lp, CallGraphRequest{BuildDir: "/src"})
			} else {
				got, err = lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"})
			}
			if err != nil {
				t.Error(err)
				return
			}
			if g := mustJSON(t, got); g != want {
				t.Errorf("got %s, want %s", g, want)
			}
		}(i)
	}
	wg.Wait()
	if n := inner.count(OpCallGraph); n != 1 {
		t.Errorf("inner calls = %d, want 1", n)
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// countReverseIndexBuilds counts buildReverseIndex calls until the test ends.
func countReverseIndexBuilds(t *testing.T) func() int64 {
	var n atomic.Int64
	build := buildReverseIndex
	buildReverseIndex = func(r *reverseIndex, cg *CallGraphResult) {
		n.Add(1)
		build(r, cg)
	}
	t.Cleanup(func() { buildReverseIndex = build })
	return n.Load
}

// TestCallGraphViewReverseIndexBuiltOnce pins that the reverse-edge index is built once per graph:
// once for every view of a memoized decode, however many goroutines read it, and once per wrapped
// view however often it is read.
func TestCallGraphViewReverseIndexBuiltOnce(t *testing.T) {
	ctx := context.Background()
	req := CallGraphRequest{BuildDir: "/src"}
	read := func(v CallGraphView) {
		v.IsRoot("scip:p#A")
		v.Symbol("scip:p#B")
		for range v.Callers("scip:p#A") {
		}
	}

	t.Run("memoized", func(t *testing.T) {
		builds := countReverseIndexBuilds(t)
		lp := Memoize(richGraphPlugin{newCountingPlugin()})
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, err := SharedCallGraph(ctx, lp, req)
				if err != nil {
					t.Error(err)
					return
				}
				read(v)
				read(v)
			}()
		}
		wg.Wait()
		if n := builds(); n != 1 {
			t.Errorf("builds = %d, want 1", n)
		}
	})

	t.Run("wrapped", func(t *testing.T) {
		builds := countReverseIndexBuilds(t)
		v, w := NewCallGraphView(richGraph()), NewCallGraphView(richGraph())
		read(v)
		read(v)
		read(w)
		if n := builds(); n != 2 {
			t.Errorf("builds = %d, want 2", n)
		}
	})

	t.Run("not built unless read", func(t *testing.T) {
		builds := countReverseIndexBuilds(t)
		v, err := SharedCallGraph(ctx, Memoize(richGraphPlugin{newCountingPlugin()}), req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.MarshalJSON(); err != nil {
			t.Fatal(err)
		}
		v.EdgeCount()
		if n := builds(); n != 0 {
			t.Errorf("builds = %d, want 0", n)
		}
	})
}

// TestCallGraphViewReverseIndex pins the index accessors over memoized, wrapped and zero views, and
// that what they return is the caller's own.
func TestCallGraphViewReverseIndex(t *testing.T) {
	sym := func(scip, tag string) Symbol { return Symbol{Name: scip, DisplayName: tag, SCIP: scip} }
	cg := CallGraphResult{
		Edges: []CallEdge{
			{Caller: sym("a", "e1"), Callee: sym("s", "e1")},
			{Caller: sym("r", "e1"), Callee: sym("a", "e2")},
			{Caller: sym("b", "e1"), Callee: sym("s", "e2")},
			{Caller: sym("a", "e3"), Callee: sym("s", "e3")},
		},
		Roots: []Symbol{sym("r", "r1"), sym("r", "r2")},
	}
	memo, err := SharedCallGraph(context.Background(), Memoize(payloadPlugin{cg: cg}), CallGraphRequest{BuildDir: "/src"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		v       CallGraphView
		callers map[string][]string
		roots   []string
		syms    map[string]Symbol
	}{
		{"memoized", memo, map[string][]string{"s": {"a", "b", "a"}, "a": {"r"}}, []string{"r"},
			map[string]Symbol{"a": sym("a", "e3"), "s": sym("s", "e3"), "r": sym("r", "r2"), "b": sym("b", "e1")}},
		{"wrapped", NewCallGraphView(cg), map[string][]string{"s": {"a", "b", "a"}, "a": {"r"}}, []string{"r"},
			map[string]Symbol{"a": sym("a", "e3"), "s": sym("s", "e3"), "r": sym("r", "r2"), "b": sym("b", "e1")}},
		{"zero", CallGraphView{}, nil, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, id := range []string{"a", "b", "s", "r", "absent", ""} {
				got := slices.Collect(tc.v.Callers(id))
				if !slices.Equal(got, tc.callers[id]) {
					t.Errorf("Callers(%q) = %v, want %v", id, got, tc.callers[id])
				}
				if len(got) > 0 {
					got[0] = "mutated"
					if again := slices.Collect(tc.v.Callers(id)); !slices.Equal(again, tc.callers[id]) {
						t.Errorf("after editing, Callers(%q) = %v", id, again)
					}
				}
				if got, want := tc.v.IsRoot(id), slices.Contains(tc.roots, id); got != want {
					t.Errorf("IsRoot(%q) = %v, want %v", id, got, want)
				}
				s := tc.v.Symbol(id)
				if s != tc.syms[id] {
					t.Errorf("Symbol(%q) = %+v, want %+v", id, s, tc.syms[id])
				}
				s.DisplayName = "mutated"
				if again := tc.v.Symbol(id); again != tc.syms[id] {
					t.Errorf("after editing, Symbol(%q) = %+v", id, again)
				}
			}
			for range tc.v.Callers("s") {
				break
			}
		})
	}
}

type payloadPlugin struct {
	StubPlugin
	cg CallGraphResult
}

func (p payloadPlugin) CallGraph(context.Context, CallGraphRequest) (CallGraphResult, error) {
	return p.cg, nil
}
