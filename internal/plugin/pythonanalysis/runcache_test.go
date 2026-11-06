package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const runCacheCallsEncode = "import jwt\n\ndef issue(c):\n    return jwt.encode(c)\n"

// countComputes records which cached ops compute while it is installed; the run cache is correct
// only if a replay computes nothing.
func countComputes(t *testing.T) map[string]int {
	t.Helper()
	got := map[string]int{}
	onRunCacheCompute = func(kind string) { got[kind]++ }
	t.Cleanup(func() { onRunCacheCompute = nil })
	return got
}

func cachedCtx(t *testing.T) context.Context {
	t.Helper()
	return WithRunCacheDir(context.Background(), t.TempDir())
}

// TestRunCacheOpsReplayWithoutComputing pins, per op, that a run cache changes no result and that a
// second identical request computes nothing. A change that drops a cached op's caching leaves
// its count above zero.
func TestRunCacheOpsReplayWithoutComputing(t *testing.T) {
	files := map[string]string{"app.py": flaskApp, "myapp/auth.py": "def encode(c):\n    return c\n", "myapp/use.py": runCacheCallsEncode}
	dir := writeTree(t, files)
	sink := funcSCIP("app", nil, "open_conn", 1)
	tests := []struct {
		name string
		op   func(ctx context.Context) (any, error)
		// kinds is what the first call computes under a cache, once each.
		kinds []string
	}{
		{"call graph", func(ctx context.Context) (any, error) {
			return CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
		}, []string{"callgraph"}},
		{"find ingresses", func(ctx context.Context) (any, error) {
			return FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
		}, []string{"ingress"}},
		{"index symbols", func(ctx context.Context) (any, error) {
			return IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: dir})
		}, []string{"index"}},
		{"reachability", func(ctx context.Context) (any, error) {
			return Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
		}, []string{"callgraph", "ingress", "reachability"}},
		{"reachability without symbols", func(ctx context.Context) (any, error) {
			return Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir})
		}, []string{"callgraph", "ingress", "reachability"}},
		{"resolve first party", func(ctx context.Context) (any, error) {
			return ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"open_conn"}})
		}, []string{"index", "resolve"}},
		{"resolve dependency", func(ctx context.Context) (any, error) {
			return ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, PURL: "pkg:pypi/pyjwt", AdvisorySymbols: []string{"jwt.encode"}})
		}, []string{"index", "resolve"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := tt.op(context.Background())
			if err != nil {
				t.Fatalf("uncached: %v", err)
			}
			counts := countComputes(t)
			ctx := cachedCtx(t)
			for i := range 3 {
				got, err := tt.op(ctx)
				if err != nil {
					t.Fatalf("call %d: %v", i, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("call %d with a run cache differs from none:\n got %+v\nwant %+v", i, got, want)
				}
			}
			for _, k := range tt.kinds {
				if counts[k] != 1 {
					t.Errorf("%s computed %d times over three calls, want 1", k, counts[k])
				}
			}
			if len(counts) != len(tt.kinds) {
				t.Errorf("computed kinds = %v, want only %v", counts, tt.kinds)
			}
		})
	}
}

// TestRunCacheNoDirComputesEveryTime pins that without a cache directory each call computes.
func TestRunCacheNoDirComputesEveryTime(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	counts := countComputes(t)
	for range 2 {
		if _, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir}); err != nil {
			t.Fatal(err)
		}
		if _, err := CallGraph(WithRunCacheDir(context.Background(), ""), plugin.CallGraphRequest{BuildDir: dir}); err != nil {
			t.Fatal(err)
		}
	}
	if counts["callgraph"] != 4 {
		t.Fatalf("computed %d times, want 4", counts["callgraph"])
	}
}

// TestRunCacheKeysSeparateRequests pins that requests differing in a field the op reads miss each
// other, and that those differing only in a field it does not read hit.
func TestRunCacheKeysSeparateRequests(t *testing.T) {
	files := map[string]string{"app.py": flaskApp, "myapp/auth.py": "def encode(c):\n    return c\n", "myapp/use.py": runCacheCallsEncode}
	dirA := writeTree(t, files)
	dirB := writeTree(t, files)
	openConn := funcSCIP("app", nil, "open_conn", 1)
	fetchURL := funcSCIP("app", nil, "fetch_url", 1)

	type step struct {
		name string
		do   func(ctx context.Context) (any, error)
		// want is the compute count for kind after this step.
		kind string
		want int
	}
	reach := func(dir string, syms ...string) func(context.Context) (any, error) {
		return func(ctx context.Context) (any, error) {
			return Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: syms})
		}
	}
	resolve := func(req plugin.ResolveSymbolsRequest) func(context.Context) (any, error) {
		return func(ctx context.Context) (any, error) { return ResolveDependencySymbols(ctx, req) }
	}
	steps := []step{
		{"reach sink A", reach(dirA, openConn), "reachability", 1},
		{"reach sink B misses", reach(dirA, fetchURL), "reachability", 2},
		{"reach both misses", reach(dirA, openConn, fetchURL), "reachability", 3},
		{"reach both reordered misses", reach(dirA, fetchURL, openConn), "reachability", 4},
		{"reach sink A again hits", reach(dirA, openConn), "reachability", 4},
		{"reach other tree misses", reach(dirB, openConn), "reachability", 5},
		{"reach nil and empty share", reach(dirA), "reachability", 6},
		{"reach empty hits nil", func(ctx context.Context) (any, error) {
			return Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dirA, Symbols: []string{}})
		}, "reachability", 6},
		{"reach ignores the advisory", func(ctx context.Context) (any, error) {
			return Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dirA, Symbols: []string{openConn}, VulnID: "PYSEC-1", Package: "pkg:pypi/x@1", TargetEnv: map[string]string{"os": "linux"}})
		}, "reachability", 6},
		{"resolve", resolve(plugin.ResolveSymbolsRequest{BuildDir: dirA, PURL: "pkg:pypi/pyjwt", AdvisorySymbols: []string{"jwt.encode"}}), "resolve", 1},
		{"resolve other purl misses", resolve(plugin.ResolveSymbolsRequest{BuildDir: dirA, PURL: "pkg:pypi/python-jose", AdvisorySymbols: []string{"jwt.encode"}}), "resolve", 2},
		{"resolve other symbol misses", resolve(plugin.ResolveSymbolsRequest{BuildDir: dirA, PURL: "pkg:pypi/pyjwt", AdvisorySymbols: []string{"jwt.decode"}}), "resolve", 3},
		{"resolve other tree misses", resolve(plugin.ResolveSymbolsRequest{BuildDir: dirB, PURL: "pkg:pypi/pyjwt", AdvisorySymbols: []string{"jwt.encode"}}), "resolve", 4},
		{"resolve symbols do not run together", resolve(plugin.ResolveSymbolsRequest{BuildDir: dirA, PURL: "pkg:pypi/pyjwt", AdvisorySymbols: []string{"jwt.", "encode"}}), "resolve", 5},
		{"resolve ignores the advisory", resolve(plugin.ResolveSymbolsRequest{
			BuildDir: dirA, PURL: "pkg:pypi/pyjwt", AdvisorySymbols: []string{"jwt.encode"},
			VulnID: "PYSEC-2", Package: "pkg:pypi/pyjwt@2.8.0", PackageVersions: []string{"2.8.0"}, TargetEnv: map[string]string{"os": "linux"}, DependencyCache: "/x", GoWork: "off",
		}), "resolve", 5},
	}
	counts := countComputes(t)
	ctx := cachedCtx(t)
	for _, s := range steps {
		if _, err := s.do(ctx); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if counts[s.kind] != s.want {
			t.Fatalf("%s: %s computed %d times, want %d", s.name, s.kind, counts[s.kind], s.want)
		}
	}
}

// TestRunCacheKeysCoverEveryRequestField fails when a request type gains a field, so whoever adds
// it decides whether the op reads it and, if so, adds it to the run cache key.
func TestRunCacheKeysCoverEveryRequestField(t *testing.T) {
	fields := func(v any) []string {
		var names []string
		for f := range reflect.TypeOf(v).Fields() {
			names = append(names, f.Name)
		}
		slices.Sort(names)
		return names
	}
	tests := []struct {
		name string
		req  any
		// keyed are the fields the op reads, all in the key; unread are the ones it never reads.
		keyed, unread []string
	}{
		{"reachability", plugin.ReachabilityRequest{}, []string{"BuildDir", "Symbols"},
			[]string{"DependencyCache", "GoToolchain", "GoToolchainFloor", "GoWork", "LibraryEntrypoints", "Package", "TargetEnv", "VulnID"}},
		{"resolve symbols", plugin.ResolveSymbolsRequest{}, []string{"AdvisorySymbols", "BuildDir", "PURL"},
			[]string{"DependencyCache", "GoWork", "Package", "PackageVersions", "TargetEnv", "VulnID"}},
		{"call graph", plugin.CallGraphRequest{}, []string{"BuildDir"}, []string{"Algorithm", "DependencyCache", "GoWork"}},
		{"find ingresses", plugin.FindIngressesRequest{}, []string{"BuildDir"}, []string{"GoWork"}},
		{"index symbols", plugin.IndexSymbolsRequest{}, []string{"BuildDir"}, []string{"GoWork"}},
	}
	for _, tt := range tests {
		want := slices.Sorted(slices.Values(append(slices.Clone(tt.keyed), tt.unread...)))
		if got := fields(tt.req); !slices.Equal(got, want) {
			t.Errorf("%s request fields = %v, classified %v: decide whether the new field is read and keyed", tt.name, got, want)
		}
	}
}

// TestRunCacheDegrades pins that a cache directory that cannot be written, or an entry that cannot
// be decoded, still yields the right result, and that a failure is never stored.
func TestRunCacheDegrades(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	want, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unwritable dir", func(t *testing.T) {
		ctx := WithRunCacheDir(context.Background(), filepath.Join(t.TempDir(), "missing", "cache"))
		for range 2 {
			got, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, %v; want the uncached result", got, err)
			}
		}
	})

	t.Run("corrupt entry", func(t *testing.T) {
		cache := t.TempDir()
		ctx := WithRunCacheDir(context.Background(), cache)
		if _, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir}); err != nil {
			t.Fatal(err)
		}
		entries, _ := filepath.Glob(filepath.Join(cache, "callgraph-*"))
		if len(entries) != 1 {
			t.Fatalf("want one callgraph entry, got %v", entries)
		}
		if err := os.WriteFile(entries[0], []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, %v; want the uncached result", got, err)
		}
	})

	t.Run("failure not stored", func(t *testing.T) {
		counts := countComputes(t)
		cache := t.TempDir()
		ctx := WithRunCacheDir(context.Background(), cache)
		missing := filepath.Join(t.TempDir(), "absent")
		for range 2 {
			if _, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: missing}); err == nil {
				t.Fatal("want an error for a missing build dir")
			}
		}
		if counts["callgraph"] != 2 {
			t.Fatalf("computed %d times, want 2", counts["callgraph"])
		}
		if entries, _ := filepath.Glob(filepath.Join(cache, "*")); len(entries) != 0 {
			t.Fatalf("a failure left entries behind: %v", entries)
		}
	})
}
