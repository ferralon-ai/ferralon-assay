package pythoncgx

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
	buildDir string
	stats    string
	stderr   *bytes.Buffer
}

func newHarness(t *testing.T, minConfidence string) *harness {
	t.Helper()
	h := &harness{fake: newFake(), buildDir: t.TempDir(), stderr: &bytes.Buffer{}}
	if err := os.WriteFile(filepath.Join(h.buildDir, "app.py"), []byte(flaskApp), 0o644); err != nil {
		t.Fatal(err)
	}
	h.stats = filepath.Join(t.TempDir(), "stats.jsonl")
	cfg := Config{Transport: TransportNative, CacheDir: t.TempDir(), MinConfidence: minConfidence, StatsFile: h.stats}
	h.lane = New(cfg, func(_ context.Context, repo string, _ Config) (Graph, error) {
		if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
			t.Errorf("opener got %q, not a git repository: %v", repo, err)
		}
		h.opens++
		return h.fake, nil
	}, "test")
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
