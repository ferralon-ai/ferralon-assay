package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
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
				got, err := tt.call(ctx, lp, "/src", "GO-2099-000"+string(rune('1'+i)))
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
