package pythoncgx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythonanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const flaskApp = `
from flask import Flask
app = Flask(__name__)

@app.route('/fetch')
def handle_fetch():
    return handle(1)

@app.route('/other')
def other():
    return 1

@app.route('/ghost')
def ghost():
    return 2

def handle(target):
    return fetch_url(target)

def fetch_url(target):
    return open_conn(target)

def open_conn(url):
    return url
`

func newFake() *fakeGraph {
	return &fakeGraph{
		kinds: map[string]string{
			"app::handle_fetch": "function", "app::other": "function", "app::handle": "function",
			"app::fetch_url": "function", "app::open_conn": "function", "app::Client": "type",
		},
		edges: []fakeEdge{
			{"app::handle_fetch", "app::handle", ConfidenceCertain},
			{"app::handle", "app::fetch_url", ConfidenceProbable},
			{"app::handle", "app::fetch_url", ConfidenceProbable},
			{"app::fetch_url", "app::open_conn", ConfidencePossible},
		},
		selectors: map[string][]string{
			"app.handle_fetch":     {"app::handle_fetch"},
			"app.fetch_url":        {"app::fetch_url"},
			"**.svc.app.fetch_url": {"app::fetch_url"},
			"app.other":            {"app::other"}, // a node with no call edges
			"app.open_conn":        {"app::open_conn"},
		},
		rejected:  map[string]bool{"bad(": true},
		truncated: map[string]bool{"app.open_conn": true},
	}
}

type harness struct {
	lane     *Lane
	fake     *fakeGraph
	opens    int
	opensBy  map[Transport]int
	indexErr map[Transport]error // Index fails with this on graphs opened for the transport
	buildDir string
	stats    string
	stderr   *bytes.Buffer
}

func newHarness(t *testing.T, minConfidence string) *harness {
	t.Helper()
	h := &harness{fake: newFake(), opensBy: map[Transport]int{}, indexErr: map[Transport]error{}, buildDir: t.TempDir(), stderr: &bytes.Buffer{}}
	if err := os.WriteFile(filepath.Join(h.buildDir, "app.py"), []byte(flaskApp), 0o644); err != nil {
		t.Fatal(err)
	}
	h.stats = filepath.Join(t.TempDir(), "stats.jsonl")
	cfg := Config{Transport: TransportNative, CacheDir: t.TempDir(), MinConfidence: minConfidence, StatsFile: h.stats}
	h.lane = New(cfg, func(_ context.Context, repo string, cfg Config) (Graph, error) {
		if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
			t.Errorf("opener got %q, not a git repository: %v", repo, err)
		}
		h.opens++
		h.opensBy[cfg.Transport]++
		if err := h.indexErr[cfg.Transport]; err != nil {
			return failingIndex{h.fake, err}, nil
		}
		return h.fake, nil
	}, "test", "test-fallback")
	h.lane.scan = "scan-1"
	h.lane.stderr = h.stderr
	return h
}

func TestCallGraph_FloorRootsAndPaging(t *testing.T) {
	h := newHarness(t, "")
	h.fake.pageSize = 1
	res, err := h.lane.CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: h.buildDir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	wantEdges := []plugin.CallEdge{
		{Caller: sym("app::handle"), Callee: sym("app::fetch_url")},
		{Caller: sym("app::handle_fetch"), Callee: sym("app::handle")},
	}
	if !reflect.DeepEqual(res.Edges, wantEdges) {
		t.Errorf("edges = %+v, want %+v (possible-tier edge dropped, duplicate folded, sorted)", res.Edges, wantEdges)
	}
	if !reflect.DeepEqual(res.Roots, []plugin.Symbol{sym("app::handle_fetch"), sym("app::other")}) {
		t.Errorf("roots = %+v, want the resolved route handlers", res.Roots)
	}
	if res.Algorithm != "cgx(min_confidence=probable)" {
		t.Errorf("algorithm = %q", res.Algorithm)
	}
	wantReasons := []string{plugin.PartialReasonDynamicDispatch, reasonConfidenceFloor + "probable", reasonIngressUnresolved}
	if res.Partiality.Complete || !reflect.DeepEqual(res.Partiality.Reasons, wantReasons) {
		t.Errorf("partiality = %+v, want reasons %v", res.Partiality, wantReasons)
	}
	if !h.fake.closed {
		t.Error("graph not closed after the operation")
	}
}

func TestCallGraph_PossibleFloorKeepsEveryEdge(t *testing.T) {
	h := newHarness(t, ConfidencePossible)
	res, err := h.lane.CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: h.buildDir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if len(res.Edges) != 3 {
		t.Errorf("got %d edges at floor possible, want 3", len(res.Edges))
	}
}

func TestFindIngresses_ResolvesHandlersAndDeclaresMisses(t *testing.T) {
	h := newHarness(t, "")
	res, err := h.lane.FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: h.buildDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	want := []plugin.Ingress{
		{Kind: "http_route", Symbol: sym("app::handle_fetch"), Selector: "route"},
		{Kind: "http_route", Symbol: sym("app::other"), Selector: "route"},
	}
	if !reflect.DeepEqual(res.Ingresses, want) {
		t.Errorf("ingresses = %+v, want %+v (an edge-less handler is still an ingress)", res.Ingresses, want)
	}
	// app.ghost has no cgx node: declared, not dropped silently.
	if res.Partiality.Complete || !reflect.DeepEqual(res.Partiality.Reasons, []string{reasonIngressUnresolved}) {
		t.Errorf("partiality = %+v, want %s", res.Partiality, reasonIngressUnresolved)
	}
	if h.fake.resolveBatches != 2 {
		t.Errorf("three handlers took %d resolve calls, want 2 (one exact batch, one suffix batch)", h.fake.resolveBatches)
	}
}

func TestResolveDependencySymbols(t *testing.T) {
	cases := []struct {
		name    string
		symbols []string
		want    []plugin.Symbol
		reasons []string
	}{
		{"exact dotted name", []string{" app.fetch_url ", "app.fetch_url"}, []plugin.Symbol{sym("app::fetch_url")}, nil},
		{"suffix match is declared", []string{"svc.app.fetch_url"}, []plugin.Symbol{sym("app::fetch_url")}, []string{reasonSuffixMatch}},
		{"rejected selector is declared", []string{"bad("}, []plugin.Symbol{}, []string{reasonSelectorRejected}},
		{"absent symbol is an empty complete answer", []string{"requests.get"}, []plugin.Symbol{}, nil},
		{"edge-less node resolves", []string{"app.other"}, []plugin.Symbol{sym("app::other")}, nil},
		{"truncated match is declared", []string{"app.open_conn"}, []plugin.Symbol{sym("app::open_conn")}, []string{reasonResolveTruncated}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "")
			res, err := h.lane.ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{BuildDir: h.buildDir, AdvisorySymbols: tc.symbols})
			if err != nil {
				t.Fatalf("ResolveDependencySymbols: %v", err)
			}
			if !reflect.DeepEqual(res.Resolved, tc.want) {
				t.Errorf("resolved = %+v, want %+v", res.Resolved, tc.want)
			}
			if res.Partiality.Complete != (tc.reasons == nil) || !reflect.DeepEqual(res.Partiality.Reasons, tc.reasons) {
				t.Errorf("partiality = %+v, want reasons %v", res.Partiality, tc.reasons)
			}
		})
	}
}

func TestComputeTaint_PathsUnderTheFloor(t *testing.T) {
	h := newHarness(t, "")
	res, err := h.lane.ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: h.buildDir,
		Sinks:    []string{"app::fetch_url", "app::open_conn", "app::nowhere"},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	want := []plugin.ReachPath{{
		Sink:    sym("app::fetch_url"),
		Ingress: sym("app::handle_fetch"),
		Trace:   []plugin.Symbol{sym("app::handle_fetch"), sym("app::handle"), sym("app::fetch_url")},
	}}
	if !reflect.DeepEqual(res.Paths, want) {
		t.Errorf("paths = %+v, want %+v", res.Paths, want)
	}
	// open_conn is reached only through a possible-tier edge; nowhere is not a node.
	wantReasons := []string{plugin.PartialReasonDynamicDispatch, plugin.PartialReasonNoIngress, reasonIngressUnresolved, reasonSinkUnresolved}
	if !reflect.DeepEqual(res.Partiality.Reasons, wantReasons) {
		t.Errorf("reasons = %v, want %v", res.Partiality.Reasons, wantReasons)
	}
	if res.PrecisionNote == "" {
		t.Error("taint result must carry its precision note")
	}
}

func TestReachability_NoSymbolsOpensNothing(t *testing.T) {
	h := newHarness(t, "")
	res, err := h.lane.Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: h.buildDir})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if h.opens != 0 || len(res.Paths) != 0 || res.Partiality.Complete {
		t.Errorf("opens=%d paths=%d partiality=%+v; want no graph, no paths, partial", h.opens, len(res.Paths), res.Partiality)
	}

	res, err = h.lane.Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: h.buildDir, Symbols: []string{"app::handle"}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 || res.Paths[0].Ingress != sym("app::handle_fetch") {
		t.Errorf("paths = %+v, want one path from app::handle_fetch", res.Paths)
	}
}

func TestIndexSymbols_ListsCallablesAndTypes(t *testing.T) {
	h := newHarness(t, "")
	res, err := h.lane.IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: h.buildDir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	if len(res.Symbols) != 6 || !res.Partiality.Complete {
		t.Errorf("got %d symbols (%+v), want 6, complete", len(res.Symbols), res.Partiality)
	}
}

func TestStatsRecordPerOperation(t *testing.T) {
	h := newHarness(t, "")
	ctx := context.Background()
	if _, err := h.lane.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: h.buildDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.lane.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: h.buildDir}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(h.stats)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("stats file has %d lines, want 2:\n%s", len(lines), data)
	}
	var rec opStats
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Op != plugin.OpCallGraph || rec.Items != 2 || rec.Tree == "" || rec.ToolCalls == 0 || string(rec.SDK) != `{"fake":true}` {
		t.Errorf("stats record = %+v", rec)
	}
	var ing opStats
	if err := json.Unmarshal([]byte(lines[0]), &ing); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, r := range ing.Resolutions {
		paths[r.Name] = r.Role + "/" + r.Path
	}
	wantPaths := map[string]string{"app.handle_fetch": "ingress/exact", "app.other": "ingress/exact", "app.ghost": "ingress/unresolved"}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Errorf("find_ingresses resolutions = %v, want %v", paths, wantPaths)
	}
	if !strings.Contains(h.stderr.String(), `"op":"call_graph"`) {
		t.Errorf("stderr lacks the stats record: %q", h.stderr.String())
	}
}

func TestOpenFailureIsHardError(t *testing.T) {
	h := newHarness(t, "")
	h.lane.open = func(context.Context, string, Config) (Graph, error) { return nil, os.ErrNotExist }
	if _, err := h.lane.CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: h.buildDir}); err == nil {
		t.Fatal("CallGraph with a failing opener: want error")
	}
}

func TestParseConfig(t *testing.T) {
	for in, want := range map[string]Transport{"": TransportWasm, "WASM": TransportWasm, " native ": TransportNative} {
		if got, err := ParseTransport(in); err != nil || got != want {
			t.Errorf("ParseTransport(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseTransport("nativ"); err == nil {
		t.Error("ParseTransport(typo): want error")
	}
	for in, want := range map[string]string{"": ConfidenceProbable, "Certain": ConfidenceCertain, "possible": ConfidencePossible} {
		if got, err := ParseMinConfidence(in); err != nil || got != want {
			t.Errorf("ParseMinConfidence(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseMinConfidence("likely"); err == nil {
		t.Error("ParseMinConfidence(unknown): want error")
	}
}

// An unreadable Python source is declared exactly as the incumbent lane declares it.
func TestUnreadableSourceIsToolFailure(t *testing.T) {
	h := newHarness(t, "")
	if err := os.Symlink(filepath.Join(h.buildDir, "absent.py"), filepath.Join(h.buildDir, "dangling.py")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	want := plugin.Partial(plugin.PartialReasonToolFailure)

	inc, err := pythonanalysis.IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: h.buildDir})
	if err != nil || !reflect.DeepEqual(inc.Partiality, want) {
		t.Fatalf("incumbent IndexSymbols partiality = %+v, %v; the fixture must reproduce its tool_failure", inc.Partiality, err)
	}
	idx, err := h.lane.IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: h.buildDir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	if !reflect.DeepEqual(idx.Partiality, want) || len(idx.Symbols) != 6 {
		t.Errorf("IndexSymbols = %d symbols, %+v; want 6, %+v", len(idx.Symbols), idx.Partiality, want)
	}

	for _, tc := range []struct {
		symbols []string
		reasons []string
	}{
		{[]string{"app.fetch_url"}, []string{plugin.PartialReasonToolFailure}},
		{[]string{"requests.get"}, []string{plugin.PartialReasonToolFailure}},
		{[]string{"svc.app.fetch_url"}, []string{reasonSuffixMatch, plugin.PartialReasonToolFailure}},
	} {
		req := plugin.ResolveSymbolsRequest{BuildDir: h.buildDir, AdvisorySymbols: tc.symbols}
		res, err := h.lane.ResolveDependencySymbols(ctx, req)
		if err != nil {
			t.Fatalf("ResolveDependencySymbols(%v): %v", tc.symbols, err)
		}
		if !reflect.DeepEqual(res.Partiality, plugin.Partial(tc.reasons...)) {
			t.Errorf("ResolveDependencySymbols(%v) partiality = %+v, want reasons %v", tc.symbols, res.Partiality, tc.reasons)
		}
		inc, err := pythonanalysis.ResolveDependencySymbols(ctx, req)
		if err != nil || !hasReason(inc.Partiality, plugin.PartialReasonToolFailure) {
			t.Errorf("incumbent ResolveDependencySymbols(%v) partiality = %+v, %v; want tool_failure", tc.symbols, inc.Partiality, err)
		}
	}
}

func TestReadableSourcesStayComplete(t *testing.T) {
	h := newHarness(t, "")
	res, err := h.lane.ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{BuildDir: h.buildDir, AdvisorySymbols: []string{"app.fetch_url"}})
	if err != nil || !res.Partiality.Complete {
		t.Fatalf("ResolveDependencySymbols = %+v, %v; want complete", res.Partiality, err)
	}
}

func statsRecords(t *testing.T, path string) []opStats {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []opStats
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var rec opStats
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func memLimit() error {
	return &EngineFailure{Kind: EngineMemoryLimit, Err: errors.New("linear-memory limit (4 GiB) reached at peak 3857 MiB")}
}

// After an engine failure while indexing, the scan's later operations on the same tree fail at
// once with the same error and never open the engine again.
func TestIndexFailureIsMemoizedForTheScan(t *testing.T) {
	h := newHarness(t, "")
	h.lane.cfg.Transport = TransportWasm
	h.indexErr[TransportWasm] = memLimit()
	ctx := context.Background()

	_, first := h.lane.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: h.buildDir})
	var f *IndexFailure
	if !errors.As(first, &f) || f.Kind != EngineMemoryLimit || f.Transport != TransportWasm || f.Tree == "" {
		t.Fatalf("CallGraph err = %v, want an IndexFailure (wasm, memory_limit)", first)
	}
	if !strings.HasPrefix(first.Error(), reasonIndexFailed+": ") {
		t.Errorf("error %q does not lead with %s", first, reasonIndexFailed)
	}

	for _, op := range []func() error{
		func() error {
			_, err := h.lane.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: h.buildDir})
			return err
		},
		func() error {
			_, err := h.lane.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: h.buildDir, AdvisorySymbols: []string{"app.fetch_url"}})
			return err
		},
		func() error {
			_, err := h.lane.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: h.buildDir, Sinks: []string{"app::fetch_url"}})
			return err
		},
	} {
		if err := op(); err == nil || err.Error() != first.Error() {
			t.Errorf("later op err = %v, want the memoized %v", err, first)
		}
	}
	if h.opens != 1 {
		t.Errorf("engine opened %d times, want 1", h.opens)
	}
	recs := statsRecords(t, h.stats)
	if len(recs) != 4 || recs[0].MemoizedFailure || !recs[1].MemoizedFailure || !recs[3].MemoizedFailure || recs[3].Error != first.Error() {
		t.Errorf("stats records = %+v; want 4, memoized after the first, same error", recs)
	}

	// A new scan indexes again.
	h.lane.scan = "scan-2"
	if _, err := h.lane.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: h.buildDir}); !errors.As(err, &f) {
		t.Fatalf("new scan: err = %v, want an IndexFailure", err)
	}
	if h.opens != 2 {
		t.Errorf("new scan: engine opened %d times in all, want 2", h.opens)
	}

	// The tree changing is a different index.
	h.indexErr[TransportWasm] = nil
	if err := os.WriteFile(filepath.Join(h.buildDir, "more.py"), []byte("def more():\n    return 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.lane.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: h.buildDir}); err != nil {
		t.Fatalf("changed tree: %v", err)
	}
}

func TestOtherIndexErrorsAreNotMemoized(t *testing.T) {
	h := newHarness(t, "")
	h.indexErr[TransportNative] = errors.New("index lock timeout")
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, err := h.lane.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: h.buildDir})
		var f *IndexFailure
		if err == nil || errors.As(err, &f) {
			t.Fatalf("FindIngresses err = %v, want a plain index error", err)
		}
	}
	if h.opens != 2 {
		t.Errorf("engine opened %d times, want 2 (no memo)", h.opens)
	}
}

func TestNativeFallback(t *testing.T) {
	ctx := context.Background()
	t.Run("off by default", func(t *testing.T) {
		h := newHarness(t, "")
		h.lane.cfg.Transport = TransportWasm
		h.indexErr[TransportWasm] = &EngineFailure{Kind: EngineTrap, Err: errors.New("unreachable")}
		if _, err := h.lane.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: h.buildDir}); err == nil {
			t.Fatal("want the wasm failure")
		}
		if h.opensBy[TransportNative] != 0 {
			t.Errorf("native opened %d times without a fallback configured", h.opensBy[TransportNative])
		}
	})
	t.Run("retries once on native, then goes straight to it", func(t *testing.T) {
		h := newHarness(t, "")
		h.lane.cfg.Transport = TransportWasm
		h.lane.cfg.Fallback = TransportNative
		h.indexErr[TransportWasm] = memLimit()
		for i := 0; i < 3; i++ {
			res, err := h.lane.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: h.buildDir})
			if err != nil || len(res.Ingresses) != 2 {
				t.Fatalf("FindIngresses #%d = %+v, %v; want the native answer", i, res, err)
			}
		}
		if h.opensBy[TransportWasm] != 1 || h.opensBy[TransportNative] != 3 {
			t.Errorf("opens = %v, want wasm 1, native 3", h.opensBy)
		}
		recs := statsRecords(t, h.stats)
		if recs[0].Transport != TransportNative || recs[0].FallbackFrom != TransportWasm || recs[0].MemoizedFailure {
			t.Errorf("first record = %+v; want native, fallback from wasm", recs[0])
		}
		if recs[2].Transport != TransportNative || recs[2].FallbackFrom != TransportWasm || !recs[2].MemoizedFailure {
			t.Errorf("third record = %+v; want native after the memoized wasm failure", recs[2])
		}
	})
	t.Run("a failing fallback is memoized too", func(t *testing.T) {
		h := newHarness(t, "")
		h.lane.cfg.Transport = TransportWasm
		h.lane.cfg.Fallback = TransportNative
		h.indexErr[TransportWasm] = memLimit()
		h.indexErr[TransportNative] = &EngineFailure{Kind: EngineExit, Err: errors.New("signal: killed")}
		var errs []string
		for i := 0; i < 2; i++ {
			_, err := h.lane.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: h.buildDir})
			var f *IndexFailure
			if !errors.As(err, &f) || f.Transport != TransportNative || f.Kind != EngineExit {
				t.Fatalf("FindIngresses #%d err = %v, want the native IndexFailure", i, err)
			}
			errs = append(errs, err.Error())
		}
		if errs[0] != errs[1] || h.opens != 2 {
			t.Errorf("errors %q, opens %d; want one identical error and 2 opens", errs, h.opens)
		}
	})
	t.Run("a native exit is not retried", func(t *testing.T) {
		h := newHarness(t, "")
		h.lane.cfg.Fallback = TransportNative
		h.indexErr[TransportNative] = &EngineFailure{Kind: EngineExit, Err: errors.New("exit status 101")}
		if _, err := h.lane.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: h.buildDir}); err == nil {
			t.Fatal("want the native failure")
		}
		if h.opens != 1 {
			t.Errorf("opens = %d, want 1", h.opens)
		}
	})
}

func hasReason(p plugin.Partiality, reason string) bool {
	for _, r := range p.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}
