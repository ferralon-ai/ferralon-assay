package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// countingPlugin counts every call per op and can be told to fail an op.
type countingPlugin struct {
	StubPlugin
	mu    sync.Mutex
	calls map[string]int
	fail  map[string]bool
}

func newCountingPlugin() *countingPlugin {
	return &countingPlugin{calls: map[string]int{}, fail: map[string]bool{}}
}

func (p *countingPlugin) hit(op string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[op]++
	if p.fail[op] {
		return errors.New(op + " failed")
	}
	return nil
}

func (p *countingPlugin) count(op string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[op]
}

func (p *countingPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	if err := p.hit(OpIndexSymbols); err != nil {
		return SymbolIndexResult{}, err
	}
	return p.StubPlugin.IndexSymbols(ctx, req)
}

func (p *countingPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	if err := p.hit(OpResolveSymbols); err != nil {
		return SymbolResolutionResult{}, err
	}
	return p.StubPlugin.ResolveDependencySymbols(ctx, req)
}

func (p *countingPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	if err := p.hit(OpResolveVersions); err != nil {
		return DependencyVersionResult{}, err
	}
	return p.StubPlugin.ResolveDependencyVersions(ctx, req)
}

func (p *countingPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	if err := p.hit(OpCallGraph); err != nil {
		return CallGraphResult{}, err
	}
	return p.StubPlugin.CallGraph(ctx, req)
}

func (p *countingPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	if err := p.hit(OpFindIngresses); err != nil {
		return IngressResult{}, err
	}
	return p.StubPlugin.FindIngresses(ctx, req)
}

func (p *countingPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	if err := p.hit(OpReachability); err != nil {
		return ReachabilityResult{}, err
	}
	return p.StubPlugin.Reachability(ctx, req)
}

func (p *countingPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	if err := p.hit(OpComputeTaint); err != nil {
		return TaintResult{}, err
	}
	return p.StubPlugin.ComputeTaint(ctx, req)
}

func (p *countingPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	if err := p.hit(OpGenerateHarness); err != nil {
		return HarnessResult{}, err
	}
	return p.StubPlugin.GenerateHarness(ctx, req)
}

func (p *countingPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	if err := p.hit(OpBuildManifest); err != nil {
		return BuildManifestResult{}, err
	}
	return p.StubPlugin.BuildManifest(ctx, req)
}

func (p *countingPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	if err := p.hit(OpResolveInventory); err != nil {
		return DependencyInventory{}, err
	}
	return p.StubPlugin.ResolveInventory(ctx, req)
}

// memoOp calls one op through lp with a request built from dir and vuln, returning the result's JSON.
type memoOp struct {
	op       string
	memoized bool
	call     func(ctx context.Context, lp LanguagePlugin, dir, vuln string) (any, error)
}

var memoOps = []memoOp{
	{OpIndexSymbols, true, func(ctx context.Context, lp LanguagePlugin, dir, _ string) (any, error) {
		return lp.IndexSymbols(ctx, IndexSymbolsRequest{BuildDir: dir})
	}},
	{OpResolveVersions, true, func(ctx context.Context, lp LanguagePlugin, dir, _ string) (any, error) {
		return lp.ResolveDependencyVersions(ctx, ResolveVersionsRequest{BuildDir: dir})
	}},
	{OpCallGraph, true, func(ctx context.Context, lp LanguagePlugin, dir, _ string) (any, error) {
		return lp.CallGraph(ctx, CallGraphRequest{BuildDir: dir})
	}},
	{OpFindIngresses, true, func(ctx context.Context, lp LanguagePlugin, dir, _ string) (any, error) {
		return lp.FindIngresses(ctx, FindIngressesRequest{BuildDir: dir})
	}},
	{OpBuildManifest, true, func(ctx context.Context, lp LanguagePlugin, dir, _ string) (any, error) {
		return lp.BuildManifest(ctx, BuildManifestRequest{BuildDir: dir})
	}},
	{OpResolveInventory, true, func(ctx context.Context, lp LanguagePlugin, dir, _ string) (any, error) {
		return lp.ResolveInventory(ctx, ResolveInventoryRequest{BuildDir: dir})
	}},
	{OpResolveSymbols, false, func(ctx context.Context, lp LanguagePlugin, dir, vuln string) (any, error) {
		return lp.ResolveDependencySymbols(ctx, ResolveSymbolsRequest{BuildDir: dir, VulnID: vuln})
	}},
	{OpReachability, false, func(ctx context.Context, lp LanguagePlugin, dir, vuln string) (any, error) {
		return lp.Reachability(ctx, ReachabilityRequest{BuildDir: dir, VulnID: vuln})
	}},
	{OpComputeTaint, false, func(ctx context.Context, lp LanguagePlugin, dir, _ string) (any, error) {
		return lp.ComputeTaint(ctx, ComputeTaintRequest{BuildDir: dir})
	}},
	{OpGenerateHarness, false, func(ctx context.Context, lp LanguagePlugin, _, _ string) (any, error) {
		return lp.GenerateHarness(ctx, GenerateHarnessRequest{Sink: "s", Kind: "fuzz"})
	}},
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestMemoize pins which ops collapse to one inner call per distinct request, that a memoized answer
// encodes byte-identically to the unwrapped one, and that a different request is a different entry.
// The repeated requests are identical, advisory included, so a pass-through op that started caching
// would collapse them and fail here.
func TestMemoize(t *testing.T) {
	ctx := context.Background()
	for _, tt := range memoOps {
		t.Run(tt.op, func(t *testing.T) {
			inner := newCountingPlugin()
			lp := Memoize(inner)
			want, err := tt.call(ctx, StubPlugin{}, "/src", "GO-2099-0001")
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				got, err := tt.call(ctx, lp, "/src", "GO-2099-0001")
				if err != nil {
					t.Fatal(err)
				}
				if mustJSON(t, got) != mustJSON(t, want) {
					t.Errorf("call %d: got %s, want %s", i, mustJSON(t, got), mustJSON(t, want))
				}
			}
			wantCalls := 3
			if tt.memoized {
				wantCalls = 1
			}
			if n := inner.count(tt.op); n != wantCalls {
				t.Errorf("inner calls = %d, want %d", n, wantCalls)
			}
			if _, err := tt.call(ctx, lp, "/other", "GO-2099-0001"); err != nil {
				t.Fatal(err)
			}
			if n := inner.count(tt.op); n != wantCalls+1 {
				t.Errorf("a different build dir must reach the inner plugin: calls = %d, want %d", n, wantCalls+1)
			}
		})
	}
}

// TestMemoizeKeysOnWholeRequest pins that two requests for the same build dir that differ in any
// other field are separate entries, so a key narrowed to op and build dir fails here.
func TestMemoizeKeysOnWholeRequest(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		op   string
		call func(lp LanguagePlugin, variant int) error
	}{
		{"call graph algorithm", OpCallGraph, func(lp LanguagePlugin, v int) error {
			_, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src", Algorithm: []string{"vta", "rta"}[v]})
			return err
		}},
		{"version coordinate", OpResolveVersions, func(lp LanguagePlugin, v int) error {
			_, err := lp.ResolveDependencyVersions(ctx, ResolveVersionsRequest{BuildDir: "/src", Coordinate: []string{"a:b", "a:c"}[v]})
			return err
		}},
		{"inventory selection", OpResolveInventory, func(lp LanguagePlugin, v int) error {
			_, err := lp.ResolveInventory(ctx, ResolveInventoryRequest{BuildDir: "/src", Selection: [][]string{{"a"}, {"b"}}[v]})
			return err
		}},
		{"inventory target env", OpResolveInventory, func(lp LanguagePlugin, v int) error {
			_, err := lp.ResolveInventory(ctx, ResolveInventoryRequest{BuildDir: "/src", TargetEnv: []map[string]string{{"GOOS": "linux"}, {"GOOS": "windows"}}[v]})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner := newCountingPlugin()
			lp := Memoize(inner)
			for _, v := range []int{0, 1, 0, 1} {
				if err := tt.call(lp, v); err != nil {
					t.Fatal(err)
				}
			}
			if n := inner.count(tt.op); n != 2 {
				t.Errorf("inner calls = %d, want 2 (one per distinct request)", n)
			}
		})
	}
}

// panickingPlugin panics on its first CallGraph call and succeeds after.
type panickingPlugin struct {
	StubPlugin
	panicked bool
}

func (p *panickingPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	if !p.panicked {
		p.panicked = true
		panic("plugin call panicked")
	}
	return p.StubPlugin.CallGraph(ctx, req)
}

// TestMemoizeReleasesAfterPanic pins that a panicking inner call leaves no entry behind for the next
// caller to wait on forever.
func TestMemoizeReleasesAfterPanic(t *testing.T) {
	ctx := context.Background()
	lp := Memoize(&panickingPlugin{})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("want the inner panic")
			}
		}()
		_, _ = lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"})
	}()
	done := make(chan error, 1)
	go func() {
		_, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retry after a panic: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call after a panic is still waiting on the panicked entry")
	}
}

// TestMemoizeDoesNotCacheFailure pins that a failed call is retried by the next caller.
func TestMemoizeDoesNotCacheFailure(t *testing.T) {
	ctx := context.Background()
	inner := newCountingPlugin()
	inner.fail[OpCallGraph] = true
	lp := Memoize(inner)
	if _, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"}); err == nil {
		t.Fatal("want the inner error")
	}
	inner.mu.Lock()
	inner.fail[OpCallGraph] = false
	inner.mu.Unlock()
	if _, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"}); err != nil {
		t.Fatalf("retry after a failure: %v", err)
	}
	if _, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"}); err != nil {
		t.Fatal(err)
	}
	if n := inner.count(OpCallGraph); n != 2 {
		t.Errorf("inner calls = %d, want 2 (one failure, one cached success)", n)
	}
}

// TestMemoizeConcurrent pins that concurrent identical requests share one inner call and never
// share a mutable result.
func TestMemoizeConcurrent(t *testing.T) {
	ctx := context.Background()
	inner := newCountingPlugin()
	lp := Memoize(inner)
	var wg sync.WaitGroup
	results := make([]CallGraphResult, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"})
			if err != nil {
				t.Error(err)
			}
			results[i] = res
		}(i)
	}
	wg.Wait()
	if n := inner.count(OpCallGraph); n != 1 {
		t.Errorf("inner calls = %d, want 1", n)
	}
	for i := range results {
		results[i].Partiality.Reasons = append(results[i].Partiality.Reasons, "mutated")
	}
	res, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Partiality.Reasons {
		if r == "mutated" {
			t.Fatal("a caller's mutation leaked into the cached answer")
		}
	}
}

// TestMemoizeCallGraphUnshared pins that the interface's CallGraph hands every caller its own
// value: the plugin runs once, and no caller's edit to its result reaches any other caller.
func TestMemoizeCallGraphUnshared(t *testing.T) {
	ctx := context.Background()
	want, err := StubPlugin{}.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"})
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*CallGraphResult)
	}{
		{"untouched", func(*CallGraphResult) {}},
		{"edits edges and roots", func(r *CallGraphResult) {
			r.Edges[0].Caller.SCIP = "mutated"
			r.Roots[0].Name = "mutated"
			r.Edges = append(r.Edges[:0], CallEdge{})
		}},
		{"edits partiality", func(r *CallGraphResult) {
			r.Partiality.Complete = !r.Partiality.Complete
			r.Partiality.Reasons = append(r.Partiality.Reasons, "mutated")
		}},
	}
	// mutator is the call, 0-based, whose result is edited before the calls after it read.
	for _, mutator := range []int{0, 1} {
		for _, tc := range mutations {
			t.Run(fmt.Sprintf("caller %d %s", mutator, tc.name), func(t *testing.T) {
				inner := newCountingPlugin()
				lp := Memoize(inner)
				var got []CallGraphResult
				for i := 0; i < 4; i++ {
					r, err := lp.CallGraph(ctx, CallGraphRequest{BuildDir: "/src"})
					if err != nil {
						t.Fatal(err)
					}
					if i > mutator && mustJSON(t, r) != mustJSON(t, want) {
						t.Errorf("call %d after caller %d's edit: got %s, want %s", i, mutator, mustJSON(t, r), mustJSON(t, want))
					}
					if i == mutator {
						tc.mutate(&r)
					}
					got = append(got, r)
				}
				if &got[2].Edges[0] == &got[3].Edges[0] {
					t.Error("two callers share one decode; each is meant to get its own")
				}
				v, err := SharedCallGraph(ctx, lp, CallGraphRequest{BuildDir: "/src"})
				if err != nil {
					t.Fatal(err)
				}
				if mustJSON(t, v) != mustJSON(t, want) {
					t.Errorf("view after caller %d's edit: got %s, want %s", mutator, mustJSON(t, v), mustJSON(t, want))
				}
				if n := inner.count(OpCallGraph); n != 1 {
					t.Errorf("inner calls = %d, want 1", n)
				}
			})
		}
	}
}
