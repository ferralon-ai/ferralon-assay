package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/scan"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestRunCached pins that the run cache computes once per key when the host provides a directory,
// computes every time when it does not, and never stores a failure.
func TestRunCached(t *testing.T) {
	tests := []struct {
		name      string
		cacheDir  bool
		keys      [][]string
		failFirst bool
		wantRuns  int
	}{
		{name: "no cache dir", cacheDir: false, keys: [][]string{{"/src"}, {"/src"}, {"/src"}}, wantRuns: 3},
		{name: "same key", cacheDir: true, keys: [][]string{{"/src"}, {"/src"}, {"/src"}}, wantRuns: 1},
		{name: "different keys", cacheDir: true, keys: [][]string{{"/src"}, {"/other"}, {"/src", "GOTOOLCHAIN=go1.22.0"}}, wantRuns: 3},
		{name: "key parts are delimited", cacheDir: true, keys: [][]string{{"/s", "rc"}, {"/src"}}, wantRuns: 2},
		{name: "failure not stored", cacheDir: true, keys: [][]string{{"/src"}, {"/src"}, {"/src"}}, failFirst: true, wantRuns: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := ""
			if tt.cacheDir {
				dir = t.TempDir()
			}
			ctx := WithRunCacheDir(context.Background(), dir)
			runs := 0
			for i, key := range tt.keys {
				out, err := runCached(ctx, "test", key, func() ([]byte, error) {
					runs++
					if tt.failFirst && runs == 1 {
						return nil, errors.New("tool failed")
					}
					return []byte("result"), nil
				})
				if tt.failFirst && i == 0 {
					if err == nil {
						t.Fatal("want the first call's error")
					}
					continue
				}
				if err != nil || string(out) != "result" {
					t.Fatalf("call %d: got %q, %v", i, out, err)
				}
			}
			if runs != tt.wantRuns {
				t.Errorf("compute ran %d times, want %d", runs, tt.wantRuns)
			}
		})
	}
}

// TestRunGovulncheckSlicesCachedStream pins that every advisory sliced from one cached govulncheck
// stream sees exactly what its own run would: the symbol-level finding, the package-level finding,
// and nothing for an id govulncheck does not know — with the raw stream, osv entries included,
// kept byte-for-byte for whatever else reads it.
func TestRunGovulncheckSlicesCachedStream(t *testing.T) {
	const stream = `{"osv":{"id":"GO-2024-0001"}}
{"osv":{"id":"GO-2024-0002"}}
{"finding":{"osv":"GO-2024-0001","trace":[{"module":"example.com/dep","version":"v1.0.0","package":"example.com/dep/a","function":"Vuln"},{"module":"example.com/app","package":"example.com/app","function":"main"}]}}
{"finding":{"osv":"GO-2024-0002","trace":[{"module":"example.com/dep","version":"v1.0.0","package":"example.com/dep/b"}]}}
`
	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	// A build dir that does not exist: a cache miss would run govulncheck and fail, so a pass proves
	// every slice came from the cached stream.
	buildDir := filepath.Join(t.TempDir(), "absent")
	env := []string{"GOWORK=off"}
	if _, err := runCached(ctx, "govulncheck", append([]string{buildDir}, env...), func() ([]byte, error) {
		return []byte(stream), nil
	}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		vulnID  string
		wantOSV bool
		wantLen int
	}{
		{name: "found at symbol", vulnID: "GO-2024-0001", wantOSV: true, wantLen: 1},
		{name: "package level only", vulnID: "GO-2024-0002", wantOSV: true, wantLen: 1},
		{name: "unknown to analyzer", vulnID: "GO-2024-9999", wantOSV: false, wantLen: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runGovulncheck(ctx, plugin.ReachabilityRequest{BuildDir: buildDir, VulnID: tt.vulnID}, env, true)
			if err != nil {
				t.Fatalf("runGovulncheck: %v", err)
			}
			want, err := parseFindings([]byte(stream), tt.vulnID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || len(got.findings) != tt.wantLen {
				t.Errorf("findings = %+v, want %+v (len %d)", got, want, tt.wantLen)
			}
			out, err := runCached(ctx, "govulncheck", append([]string{buildDir}, env...), func() ([]byte, error) {
				t.Fatal("cache miss")
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, []byte(stream)) {
				t.Fatal("cached stream differs from what govulncheck emitted")
			}
			if has := bytes.Contains(out, []byte(`{"osv":{"id":"`+tt.vulnID+`"}}`)); has != tt.wantOSV {
				t.Errorf("osv entry present = %v, want %v", has, tt.wantOSV)
			}
		})
	}
}

// TestReachabilityWithholdsFromCache pins that a refutation reached through the cached govulncheck
// stream and call graph is still withheld exactly as an uncached run withholds it, for every
// advisory that reads the cache, and is kept when nothing contradicts it.
func TestReachabilityWithholdsFromCache(t *testing.T) {
	tree := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
	}
	// A package-level finding and no symbol finding: govulncheck matched the advisory to the
	// build and traced no call, so the result refutes example.com/vulnmod.
	const stream = `{"osv":{"id":"GO-2099-0001"}}
{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/vulnmod","version":"v0.0.0","package":"example.com/vulnmod"}]}}
`
	cases := []struct {
		name     string
		extra    map[string]string
		withheld bool
	}{
		{"nothing contradicts the refutation", nil, false},
		{"a tagged file the build left out imports the module", map[string]string{"prod.go": "//go:build prod\n\npackage main\n\nimport _ \"example.com/vulnmod\"\n"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithRunCacheDir(context.Background(), t.TempDir())
			files := map[string]string{}
			for k, v := range tree {
				files[k] = v
			}
			for k, v := range tc.extra {
				files[k] = v
			}
			dir := writeTree(t, files)
			// Seeded under the key Reachability asks for, so no govulncheck runs: a key mismatch
			// would scan the tree for real, find nothing, and fail the kept case.
			if _, err := runCached(ctx, "govulncheck", append([]string{dir}, reachBaseEnv()...), func() ([]byte, error) {
				return []byte(stream), nil
			}); err != nil {
				t.Fatal(err)
			}
			// The first advisory builds the cached call graph; the second reads it.
			for i := range 2 {
				res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, VulnID: "GO-2099-0001"})
				if err != nil {
					t.Fatalf("advisory %d: %v", i, err)
				}
				if withheld := res.Refutation == nil; withheld != tc.withheld {
					t.Fatalf("advisory %d: withheld = %v, want %v (partiality %+v)", i, withheld, tc.withheld, res.Partiality)
				}
				if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != tc.withheld {
					t.Errorf("advisory %d: excluded_files declared = %v, want %v", i, declared, tc.withheld)
				}
			}
		})
	}
}

// TestRunCacheKeys pins what each per-tree result is keyed on, so one environment's answer never
// serves another: the govulncheck stream on the child's exact environment, toolchain included, and
// the call graph on the process environment the program load reads. Every entry is seeded for a
// build dir that does not exist, so a hit returns the seed and a miss fails.
func TestRunCacheKeys(t *testing.T) {
	buildDir := filepath.Join(t.TempDir(), "absent")

	t.Run("govulncheck", func(t *testing.T) {
		ctx := WithRunCacheDir(context.Background(), t.TempDir())
		const stream = `{"finding":{"osv":"GO-2024-0001","trace":[{"module":"example.com/dep","version":"v1.0.0","package":"example.com/dep"}]}}` + "\n"
		seeded := []string{"GOWORK=off", "GOTOOLCHAIN=go1.22.0"}
		if _, err := runCached(ctx, "govulncheck", append([]string{buildDir}, seeded...), func() ([]byte, error) {
			return []byte(stream), nil
		}); err != nil {
			t.Fatal(err)
		}
		tests := []struct {
			name    string
			env     []string
			wantHit bool
		}{
			{name: "same environment", env: seeded, wantHit: true},
			{name: "no toolchain", env: []string{"GOWORK=off"}, wantHit: false},
			{name: "other toolchain", env: []string{"GOWORK=off", "GOTOOLCHAIN=go1.23.0"}, wantHit: false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := runGovulncheck(ctx, plugin.ReachabilityRequest{BuildDir: buildDir, VulnID: "GO-2024-0001"}, tt.env, true)
				if hit := err == nil && len(got.findings) == 1; hit != tt.wantHit {
					t.Errorf("served from the seed = %v, want %v (err %v)", hit, tt.wantHit, err)
				}
			})
		}
	})

	t.Run("call graph", func(t *testing.T) {
		ctx := WithRunCacheDir(context.Background(), t.TempDir())
		seed := reconcileGraph{
			CallGraph:    plugin.CallGraphResult{Algorithm: "vta", Roots: []plugin.Symbol{{SCIP: "seeded"}}},
			ReflectReach: map[string][]string{"example.com/m": {"F"}},
		}
		if _, err := runCached(ctx, "reconcile", reconcileCacheKey(buildDir, nil), func() ([]byte, error) {
			return json.Marshal(seed)
		}); err != nil {
			t.Fatal(err)
		}
		loads := 0
		load := func() (*LoadResult, error) {
			loads++
			return nil, errors.New("tree loaded")
		}
		if got, err := reconcileCallGraph(ctx, buildDir, nil, load); err != nil || !reflect.DeepEqual(got, seed) || loads != 0 {
			t.Fatalf("same environment: got %+v, %v after %d loads, want the seed and no load", got, err, loads)
		}
		if _, err := reconcileCallGraph(ctx, buildDir, []string{"example.com/m/p"}, load); err == nil || loads != 1 {
			t.Fatalf("other known packages: err %v after %d loads, want a fresh load", err, loads)
		}
		loads = 0
		t.Setenv("ASSAY_RUN_CACHE_KEY_PROBE", "1")
		if _, err := reconcileCallGraph(ctx, buildDir, nil, load); err == nil || loads != 1 {
			t.Fatalf("changed environment: err %v after %d loads, want a fresh load", err, loads)
		}
	})

	// An unknown reflect reach is cached as unknown, and a known empty one as known.
	t.Run("reflect reach", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			reach   map[string][]string
			unknown bool
		}{
			{"unknown", nil, true},
			{"known and empty", map[string][]string{}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx := WithRunCacheDir(context.Background(), t.TempDir())
				if _, err := runCached(ctx, "reconcile", reconcileCacheKey(buildDir, nil), func() ([]byte, error) {
					return json.Marshal(reconcileGraph{ReflectReach: tc.reach})
				}); err != nil {
					t.Fatal(err)
				}
				got, err := reconcileCallGraph(ctx, buildDir, nil, func() (*LoadResult, error) { return nil, errors.New("tree loaded") })
				if err != nil {
					t.Fatal(err)
				}
				if (got.ReflectReach == nil) != tc.unknown || len(got.ReflectReach) != 0 {
					t.Errorf("ReflectReach read back = %#v, want unknown = %v", got.ReflectReach, tc.unknown)
				}
			})
		}
	})
}

// TestRunCachedReadersSeeWholeEntries pins that a concurrent reader of an entry being written gets
// the whole entry or a miss, never a prefix: a govulncheck stream cut after a package-level finding
// parses cleanly and would refute a module the dropped lines show is called.
func TestRunCachedReadersSeeWholeEntries(t *testing.T) {
	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<17) // 2 MiB
	for round := range 16 {
		key := []string{"/src", strconv.Itoa(round)}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for hits := 0; hits < 2; {
					computed := false
					out, err := runCached(ctx, "test", key, func() ([]byte, error) {
						computed = true
						return payload, nil
					})
					if err != nil || !bytes.Equal(out, payload) {
						t.Errorf("round %d: read %d of %d bytes (err %v)", round, len(out), len(payload), err)
						return
					}
					if !computed {
						hits++
					}
				}
			}()
		}
		wg.Wait()
	}
}

// TestResolveDependencySymbolsFromCachedIndex pins that every advisory resolved against the cached
// symbol index gets exactly what it gets from a fresh index, and that the index is built once.
func TestResolveDependencySymbolsFromCachedIndex(t *testing.T) {
	reqs := []plugin.ResolveSymbolsRequest{
		{BuildDir: fixtureDir, PURL: "pkg:golang/tegron.test/fixturemod/util", AdvisorySymbols: []string{"Sink"}, VulnID: "GO-TEST-0001"},
		{BuildDir: fixtureDir, PURL: "pkg:golang/tegron.test/fixturemod/util", AdvisorySymbols: []string{"NoSuchSymbol"}, VulnID: "GO-TEST-0002"},
	}
	resolve := func(ctx context.Context, req plugin.ResolveSymbolsRequest) string {
		t.Helper()
		res, err := ResolveDependencySymbols(ctx, req)
		if err != nil {
			t.Fatalf("%s: %v", req.VulnID, err)
		}
		b, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	want := make([]string, len(reqs))
	for i, req := range reqs {
		want[i] = resolve(context.Background(), req)
	}

	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	for round := range 2 {
		for i, req := range reqs {
			if got := resolve(ctx, req); got != want[i] {
				t.Errorf("round %d, %s: cached resolution = %s, want %s", round, req.VulnID, got, want[i])
			}
		}
	}
	if _, err := runCached(ctx, "symbolindex", append([]string{fixtureDir}, os.Environ()...), func() ([]byte, error) {
		t.Fatal("symbol index was not cached")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestComputeTaintFromCachedIngresses pins that every advisory's taint run from the cached
// ingresses gets exactly what it gets from a fresh ingress search, and that the search runs once.
func TestComputeTaintFromCachedIngresses(t *testing.T) {
	sinks := [][]string{
		{sinkSCIPIn(t, taintFixtureDir, "/Sink().")},
		{"scip-go gomod example.com/absent . example.com/absent/Nowhere()."},
	}
	taint := func(ctx context.Context, s []string) string {
		t.Helper()
		res, err := ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: taintFixtureDir, Sinks: s})
		if err != nil {
			t.Fatalf("%v: %v", s, err)
		}
		b, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	want := make([]string, len(sinks))
	for i, s := range sinks {
		want[i] = taint(context.Background(), s)
	}

	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	for round := range 2 {
		for i, s := range sinks {
			if got := taint(ctx, s); got != want[i] {
				t.Errorf("round %d, sinks %v: cached taint = %s, want %s", round, s, got, want[i])
			}
		}
	}
	if _, err := runCached(ctx, "ingresses", append([]string{taintFixtureDir}, os.Environ()...), func() ([]byte, error) {
		t.Fatal("ingresses were not cached")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestGovulncheckCachedSettlesFailure pins that a settled govulncheck failure runs once per tree and
// environment and every later call gets the same error, while a failure that is not settled, a run
// the caller may retry (the switched toolchain's), or a scan without a run cache runs every time.
// A successful stream is cached exactly as before whether or not the caller lets failures settle.
func TestGovulncheckCachedSettlesFailure(t *testing.T) {
	const buildDir = "/src"
	env := []string{"GOWORK=off"}
	key := append([]string{buildDir}, env...)
	cause := fmt.Errorf("govulncheck: %w", errors.New("loading packages: olm/olm.h file not found"))
	tests := []struct {
		name       string
		cacheDir   bool
		settle     bool
		outcome    string // "stream", "settled", "unsettled"
		wantRuns   int
		wantRecord bool
	}{
		{name: "settled failure runs once and replays", cacheDir: true, settle: true, outcome: "settled", wantRuns: 1, wantRecord: true},
		{name: "unsettled failure runs every time", cacheDir: true, settle: true, outcome: "unsettled", wantRuns: 3},
		{name: "retryable run never settles", cacheDir: true, settle: false, outcome: "settled", wantRuns: 3},
		{name: "no cache dir", cacheDir: false, settle: true, outcome: "settled", wantRuns: 3},
		{name: "stream cached", cacheDir: true, settle: true, outcome: "stream", wantRuns: 1},
		{name: "stream cached on a retryable run", cacheDir: true, settle: false, outcome: "stream", wantRuns: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := ""
			if tt.cacheDir {
				dir = t.TempDir()
			}
			ctx := WithRunCacheDir(context.Background(), dir)
			runs := 0
			stream := func() ([]byte, error) {
				runs++
				switch tt.outcome {
				case "stream":
					return []byte(`{"config":{}}` + "\n"), nil
				default:
					return nil, &govulncheckError{buildDir: buildDir, cause: cause, stderr: "stderr text", settled: tt.outcome == "settled"}
				}
			}
			var first error
			var firstOut []byte
			for i := range 3 {
				out, err := govulncheckCached(ctx, buildDir, env, tt.settle, stream)
				if i == 0 {
					first, firstOut = err, out
					continue
				}
				if !bytes.Equal(out, firstOut) {
					t.Errorf("call %d: stream %q, want %q", i, out, firstOut)
				}
				if (err == nil) != (first == nil) {
					t.Fatalf("call %d: err %v, first call's %v", i, err, first)
				}
				if err == nil {
					continue
				}
				if err.Error() != first.Error() {
					t.Errorf("call %d: error %q, want the first call's %q", i, err, first)
				}
				var got, want *govulncheckError
				if !errors.As(err, &got) || !errors.As(first, &want) {
					t.Fatalf("call %d: error %T, first %T, want *govulncheckError", i, err, first)
				}
				if got.buildDir != want.buildDir || got.stderr != want.stderr || got.settled != want.settled || errors.Unwrap(err).Error() != errors.Unwrap(first).Error() {
					t.Errorf("call %d: replay %+v differs from the first call's %+v", i, got, want)
				}
			}
			if tt.outcome != "stream" && first == nil {
				t.Fatal("failure became a stream")
			}
			if runs != tt.wantRuns {
				t.Errorf("govulncheck ran %d times, want %d", runs, tt.wantRuns)
			}
			if tt.cacheDir {
				_, statErr := os.Stat(runCachePath(dir, govulncheckFailureKind, key))
				if recorded := statErr == nil; recorded != tt.wantRecord {
					t.Errorf("failure recorded = %v, want %v", recorded, tt.wantRecord)
				}
			}
		})
	}
}

// TestGovulncheckErrorMessage pins the failure message every caller sees, fresh or replayed.
func TestGovulncheckErrorMessage(t *testing.T) {
	cause := errors.New("govulncheck: loading packages: boom")
	want := fmt.Errorf("govulncheck failed (%q): %w: %s", "/src", cause, "err text").Error()
	fresh := &govulncheckError{buildDir: "/src", cause: cause, stderr: "err text"}
	if got := fresh.Error(); got != want {
		t.Errorf("fresh = %q, want %q", got, want)
	}
	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	key := []string{"/src", "GOWORK=off"}
	recordGovulncheckFailure(ctx, key, fresh)
	replayed := replayGovulncheckFailure(ctx, "/src", key)
	if replayed == nil || replayed.Error() != want || !errors.Is(fresh, cause) || errors.Unwrap(replayed).Error() != cause.Error() {
		t.Errorf("replayed = %v, want %q wrapping %q", replayed, want, cause)
	}
}

// fakeVulnPackageError has the shape of the error x/vuln returns for a load whose packages carry
// errors.
type fakeVulnPackageError struct{ Errors []packages.Error }

func (e *fakeVulnPackageError) Error() string {
	return "There are errors with the provided package patterns"
}

type exitCoded struct {
	code int
	err  error
}

func (e *exitCoded) Error() string { return e.err.Error() }
func (e *exitCoded) ExitCode() int { return e.code }
func (e *exitCoded) Unwrap() error { return e.err }

// TestSettledLoadFailure pins which govulncheck failures settle: a completed load whose packages
// carry errors, and nothing cancelled, timed out, killed by a signal, failed outright, or past the
// load.
func TestSettledLoadFailure(t *testing.T) {
	asVuln := func(err error) error { return fmt.Errorf("govulncheck: %w", fmt.Errorf("loading packages: %w", err)) }
	cgo := &fakeVulnPackageError{Errors: []packages.Error{
		{Msg: "# example.com/libolm\nerror.go:4:11: fatal error: 'olm/olm.h' file not found", Kind: packages.ListError},
		{Pos: "account.go:5:8", Msg: "could not import C (no metadata for C)", Kind: packages.TypeError},
	}}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelExpired()
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "package errors", ctx: context.Background(), err: asVuln(cgo), want: true},
		{name: "ctx cancelled", ctx: cancelled, err: asVuln(cgo), want: false},
		{name: "ctx timed out", ctx: expired, err: asVuln(cgo), want: false},
		{name: "a subprocess killed by a signal", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{Errors: []packages.Error{{Msg: "# example.com/libolm\ncgo: signal: killed", Kind: packages.ListError}}}), want: false},
		{name: "a fork that ran out of processes", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{Errors: []packages.Error{{Msg: "# example.com/libolm\ncgo: fork/exec /usr/bin/cc: resource temporarily unavailable", Kind: packages.ListError}}}), want: false},
		{name: "a full disk", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{Errors: []packages.Error{{Msg: "# example.com/libolm\ncgo: write /cache/ab/cd: no space left on device", Kind: packages.ListError}}}), want: false},
		{name: "out of file descriptors", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{Errors: []packages.Error{{Msg: "# example.com/libolm\ncgo: open /tmp/x.c: too many open files", Kind: packages.ListError}}}), want: false},
		{name: "out of memory", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{Errors: []packages.Error{{Msg: "# example.com/libolm\ncgo: fork/exec /usr/bin/cc: cannot allocate memory", Kind: packages.ListError}}}), want: false},
		{name: "cc reporting errno in libc's form", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{Errors: []packages.Error{{Msg: "# example.com/libolm\ncc1: error: Resource temporarily unavailable", Kind: packages.ListError}}}), want: false},
		{name: "cc out of memory", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{Errors: []packages.Error{{Msg: "# example.com/libolm\ncc1: out of memory allocating 65536 bytes", Kind: packages.ListError}}}), want: false},
		{name: "exit code -1", ctx: context.Background(), err: &exitCoded{code: -1, err: asVuln(cgo)}, want: false},
		{name: "go command failed outright", ctx: context.Background(), err: asVuln(errors.New("err: signal: killed: stderr: ")), want: false},
		{name: "vulnerability database unreachable", ctx: context.Background(), err: fmt.Errorf("govulncheck: %w", errors.New(`fetching vulnerabilities: Get "https://vuln.go.dev/index/modules.json.gz": dial tcp: i/o timeout`)), want: false},
		{name: "usage error", ctx: context.Background(), err: &exitCoded{code: 2, err: errors.New("invalid usage")}, want: false},
		{name: "no package errors", ctx: context.Background(), err: asVuln(&fakeVulnPackageError{}), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := settledLoadFailure(tt.ctx, tt.err); got != tt.want {
				t.Errorf("settledLoadFailure = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLoadPackageErrorsFindsVulnPackageErrors is the tripwire on x/vuln's unexported package-error
// shape. It runs a real govulncheck load against a local, empty vulnerability database with
// GOPROXY=off, so it needs no network, and asserts loadPackageErrors still finds the load's package
// errors. If it fails after an x/vuln bump, the reflected Errors []packages.Error field moved or
// changed type: re-verify loadPackageErrors against the new x/vuln before taking the bump, or every
// deterministic load failure goes back to costing one full source load per advisory.
func TestLoadPackageErrorsFindsVulnPackageErrors(t *testing.T) {
	db := writeTree(t, map[string]string{"index/modules.json": "[]", "index/db.json": `{"modified":"2024-01-01T00:00:00Z"}`})
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() { var x int = \"s\"; _ = x }\n",
	})
	var stderr bytes.Buffer
	cmd := scan.Command(context.Background(), "-db", "file://"+filepath.ToSlash(db), "-C", dir, "-json", "-mode=source", "-scan=symbol", "./...")
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr
	cmd.Env = append(reachBaseEnv(), "GOPROXY=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	err := cmd.Wait()
	if err == nil {
		t.Fatal("govulncheck succeeded on a tree with a type error")
	}
	if len(loadPackageErrors(err)) == 0 {
		t.Fatalf("loadPackageErrors found no package errors in %v (stderr %q); x/vuln's packageError shape changed — re-verify loadPackageErrors before bumping golang.org/x/vuln", err, stderr.String())
	}
}

// TestPackagesResolveOffline pins that a tree whose packages need a module fetch never counts as
// resolving locally, while one whose only faults are cgo or type errors does.
func TestPackagesResolveOffline(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{name: "clean", files: map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n", "main.go": "package main\n\nfunc main() {}\n"}, want: true},
		{name: "type error", files: map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n", "main.go": "package main\n\nfunc main() { var x int = \"s\"; _ = x }\n"}, want: true},
		{name: "missing cgo header", files: map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n", "main.go": "package main\n\n// #include <assay/absent.h>\nimport \"C\"\n\nfunc main() {}\n"}, want: true},
		{name: "needs a module fetch", files: map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire example.com/absent v1.0.0\n", "main.go": "package main\n\nimport _ \"example.com/absent\"\n\nfunc main() {}\n"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			if got := packagesResolveOffline(context.Background(), dir, reachBaseEnv()); got != tt.want {
				t.Errorf("packagesResolveOffline = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGovulncheckFailureEntryIsolation pins that a stored failure and a stored stream are never read
// as each other, and that a stream stored under the key wins over a failure record.
func TestGovulncheckFailureEntryIsolation(t *testing.T) {
	const buildDir = "/src"
	env := []string{"GOWORK=off"}
	key := append([]string{buildDir}, env...)
	const stream = `{"config":{"protocol_version":"v1.0.0"}}` + "\n"
	record := &govulncheckError{buildDir: buildDir, cause: errors.New("loading packages: x"), stderr: "", settled: true}

	t.Run("failure not read as a stream", func(t *testing.T) {
		ctx := WithRunCacheDir(context.Background(), t.TempDir())
		recordGovulncheckFailure(ctx, key, record)
		computed := false
		if _, err := runCached(ctx, "govulncheck", key, func() ([]byte, error) {
			computed = true
			return []byte(stream), nil
		}); err != nil || !computed {
			t.Fatalf("stream lookup: err %v, computed %v; want a miss", err, computed)
		}
	})
	for _, tc := range []struct{ name, body string }{
		{"stream", stream},
		{"record without the marker", `{"cause":"loading packages: x","stderr":""}`},
		{"truncated record", `{"marker":"` + govulncheckFailureMarker},
	} {
		t.Run(tc.name+" at the failure entry not read as a failure", func(t *testing.T) {
			dir := t.TempDir()
			ctx := WithRunCacheDir(context.Background(), dir)
			if err := os.WriteFile(runCachePath(dir, govulncheckFailureKind, key), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := replayGovulncheckFailure(ctx, buildDir, key); err != nil {
				t.Errorf("replayed %v from %q", err, tc.body)
			}
		})
	}
	t.Run("stream wins over a failure record", func(t *testing.T) {
		ctx := WithRunCacheDir(context.Background(), t.TempDir())
		recordGovulncheckFailure(ctx, key, record)
		if _, err := runCached(ctx, "govulncheck", key, func() ([]byte, error) { return []byte(stream), nil }); err != nil {
			t.Fatal(err)
		}
		out, err := govulncheckCached(ctx, buildDir, env, true, func() ([]byte, error) {
			t.Fatal("govulncheck ran")
			return nil, nil
		})
		if err != nil || string(out) != stream {
			t.Errorf("got %q, %v; want the stored stream", out, err)
		}
	})
}
