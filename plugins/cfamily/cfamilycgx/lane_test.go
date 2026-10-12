package cfamilycgx

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis/compiledb"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// copyFixture copies testdata/<name> into a fresh temp dir and returns it.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	files := map[string]string{}
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		files[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return writeTree(t, files)
}

// cGraph is what cgx reports for testdata/c: prototypes are not nodes, the cross-file edges are
// "possible" and the same-file one "certain", and the call through h->on_token is no edge.
func cGraph() *fakeGraph {
	return &fakeGraph{
		nodes: []node{
			{FQN: "main", Kind: "function", File: "main.c", Line: 5},
			{FQN: "apply", Kind: "function", File: "apply.c", Line: 9},
			{FQN: "count", Kind: "function", File: "apply.c", Line: 3},
			{FQN: "unused_export", Kind: "function", File: "apply.c", Line: 15},
			{FQN: "parse", Kind: "function", File: "parse.c", Line: 15},
			{FQN: "scan", Kind: "function", File: "parse.c", Line: 7},
			{FQN: "CHECK", Kind: "constant", File: "parse.c", Line: 5},
			{FQN: "handler", Kind: "type", File: "parse.h", Line: 6},
		},
		rows: []edgeRow{
			{"main", "calls", "possible", "apply"},
			{"apply", "calls", "possible", "parse"},
			{"parse", "calls", "certain", "scan"},
		},
	}
}

// cxxGraph is what cgx reports for testdata/cpp: a name declared in the header and defined in
// the .cpp is two nodes with one FQN, and each call to it is one row per node pair.
func cxxGraph() *fakeGraph {
	return &fakeGraph{
		nodes: []node{
			{FQN: "main", Kind: "function", File: "main.cpp", Line: 10},
			{FQN: "run", Kind: "function", File: "main.cpp", Line: 5},
			{FQN: "codec::checksum", Kind: "function", File: "codec.hpp", Line: 19},
			{FQN: "codec::checksum", Kind: "function", File: "codec.cpp", Line: 5},
			{FQN: "codec::Inflate::decode", Kind: "method", File: "codec.hpp", Line: 15},
			{FQN: "codec::Inflate::decode", Kind: "method", File: "codec.cpp", Line: 18},
			{FQN: "codec::Inflate::window", Kind: "method", File: "codec.cpp", Line: 13},
			{FQN: "codec::Decoder::decode", Kind: "method", File: "codec.hpp", Line: 10},
			{FQN: "codec::Decoder", Kind: "type", File: "codec.hpp", Line: 7},
		},
		rows: []edgeRow{
			{"main", "calls", "possible", "codec::checksum"},
			{"main", "calls", "possible", "codec::checksum"},
			{"main", "calls", "certain", "run"},
			{"run", "calls-virtual", "possible", "codec::Decoder::decode"},
			{"codec::Inflate::decode", "calls", "certain", "codec::checksum"},
			{"codec::Inflate::decode", "calls", "certain", "codec::Inflate::window"},
		},
	}
}

func edgesOf(r plugin.CallGraphResult) [][2]string {
	var out [][2]string
	for _, e := range r.Edges {
		out = append(out, [2]string{e.Caller.SCIP, e.Callee.SCIP})
	}
	return out
}

func ingressesOf(r plugin.IngressResult) map[string]string {
	out := map[string]string{}
	for _, in := range r.Ingresses {
		out[in.Symbol.SCIP] = in.Kind
	}
	return out
}

// Every graph op over a lane with no verified engine declares the engine state loudly and
// returns an empty result: never a hard error, never an empty-clean graph.
func TestLane_EngineStates_DeclaredLoud(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		lane func(t *testing.T) *Lane
		want string
	}{
		{"unavailable", func(t *testing.T) *Lane {
			l := Unavailable(Config{}, ErrEngineUnconfigured)
			l.stderr = io.Discard
			return l
		}, reasonEngineUnconfigured},
		{"unavailable_other_error", func(t *testing.T) *Lane {
			l := Unavailable(Config{}, errors.New("no cache dir"))
			l.stderr = io.Discard
			return l
		}, reasonEngineUnconfigured},
		{"open_unverified", func(t *testing.T) *Lane {
			return newTestLane(t, Config{}, (&fakeOpener{err: ErrEngineUnverified}).open)
		}, reasonEngineUnverified},
		{"open_mismatch", func(t *testing.T) *Lane {
			return newTestLane(t, Config{}, (&fakeOpener{err: ErrEngineMismatch}).open)
		}, reasonEngineMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := c.lane(t)
			dir := copyFixture(t, "c")
			idx, err := l.IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: dir})
			check(t, "index_symbols", err, idx.Partiality, c.want, len(idx.Symbols))
			res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"parse"}})
			check(t, "resolve_symbols", err, res.Partiality, c.want, len(res.Resolved))
			cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
			check(t, "call_graph", err, cg.Partiality, c.want, len(cg.Edges)+len(cg.Roots))
			in, err := l.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
			check(t, "find_ingresses", err, in.Partiality, c.want, len(in.Ingresses))
			re, err := l.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"scan"}})
			check(t, "reachability", err, re.Partiality, c.want, len(re.Paths))
			ta, err := l.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{"scan"}})
			check(t, "compute_taint", err, ta.Partiality, c.want, len(ta.Paths))
			if re.Paths == nil || ta.Paths == nil {
				t.Error("paths must be an empty slice, not nil")
			}
		})
	}
}

func check(t *testing.T, op string, err error, p plugin.Partiality, want string, n int) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: hard error %v, want declared %s", op, err, want)
		return
	}
	if p.Complete || !hasReason(p, want) {
		t.Errorf("%s: partiality %+v, want %s", op, p, want)
	}
	if n != 0 {
		t.Errorf("%s: %d results with no engine, want none", op, n)
	}
}

// The C fixture with no compilation database: every source and header is staged, no_manifest
// is declared, the residue is named per kind, main and the non-static functions are ingresses,
// and the call graph is cgx's edges at the possible floor.
func TestLane_C_NoDB(t *testing.T) {
	ctx := context.Background()
	dir := copyFixture(t, "c")
	op := &fakeOpener{g: cGraph()}
	l := newTestLane(t, Config{}, op.open)

	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	wantEdges := [][2]string{{"apply", "parse"}, {"main", "apply"}, {"parse", "scan"}}
	if got := edgesOf(cg); !reflect.DeepEqual(got, wantEdges) {
		t.Errorf("edges = %v, want %v", got, wantEdges)
	}
	for _, r := range []string{plugin.PartialReasonNoManifest, reasonFnPtr, reasonMacro, reasonLinkPrefix + "memcpy", reasonLinkPrefix + "strlen"} {
		if !hasReason(cg.Partiality, r) {
			t.Errorf("call_graph partiality %v lacks %s", cg.Partiality.Reasons, r)
		}
	}
	for _, r := range []string{reasonVtable, reasonEmptyTU, plugin.PartialReasonNoIngress, reasonLinkPrefix + "on_token", reasonLinkPrefix + "CHECK", reasonLinkPrefix + "sizeof"} {
		if hasReason(cg.Partiality, r) {
			t.Errorf("call_graph partiality %v declares %s", cg.Partiality.Reasons, r)
		}
	}
	for _, r := range cg.Partiality.Reasons {
		if strings.HasPrefix(r, reasonConfidenceFloor) {
			t.Errorf("the default floor is declared: %s", r)
		}
	}
	if got := stagedFiles(t, op.repos[0]); !reflect.DeepEqual(got, []string{"apply.c", "main.c", "parse.c", "parse.h"}) {
		t.Errorf("staged %v", got)
	}

	in, err := l.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"main": IngressMain, "apply": IngressExported, "parse": IngressExported, "unused_export": IngressExported}
	if got := ingressesOf(in); !reflect.DeepEqual(got, want) {
		t.Errorf("ingresses = %v, want %v (static scan/count excluded)", got, want)
	}

	idx, err := l.IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Symbols) != 6 {
		t.Errorf("index_symbols = %d symbols, want the 6 functions", len(idx.Symbols))
	}
}

// A raised floor drops the possible edges and is itself declared.
func TestLane_ConfidenceFloor(t *testing.T) {
	dir := copyFixture(t, "c")
	l := newTestLane(t, Config{MinConfidence: ConfidenceCertain}, (&fakeOpener{g: cGraph()}).open)
	cg, err := l.CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got := edgesOf(cg); !reflect.DeepEqual(got, [][2]string{{"parse", "scan"}}) {
		t.Errorf("edges = %v, want only the certain one", got)
	}
	if !hasReason(cg.Partiality, reasonConfidenceFloor+ConfidenceCertain) {
		t.Errorf("partiality %v lacks the floor", cg.Partiality.Reasons)
	}
}

// Reachability and ComputeTaint find the path, carry the always-present dispatch partiality, and
// declare a sink that is not in the graph.
func TestLane_PathsAndTaint(t *testing.T) {
	ctx := context.Background()
	dir := copyFixture(t, "c")
	l := newTestLane(t, Config{}, (&fakeOpener{g: cGraph()}).open)

	ta, err := l.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{"scan", "inflate"}})
	if err != nil {
		t.Fatal(err)
	}
	if ta.PrecisionNote != taintPrecisionNote || !strings.Contains(ta.PrecisionNote, "NOT variable-level dataflow") {
		t.Errorf("precision note = %q", ta.PrecisionNote)
	}
	if len(ta.Paths) != 1 {
		t.Fatalf("paths = %+v, want one to scan", ta.Paths)
	}
	var trace []string
	for _, s := range ta.Paths[0].Trace {
		trace = append(trace, s.SCIP)
	}
	// "apply" and "parse" are exported ingresses too; the shortest path from any ingress wins.
	if !reflect.DeepEqual(trace, []string{"parse", "scan"}) || ta.Paths[0].Ingress.SCIP != "parse" {
		t.Errorf("trace = %v from %s", trace, ta.Paths[0].Ingress.SCIP)
	}
	for _, r := range []string{plugin.PartialReasonDynamicDispatch, reasonSinkUnresolved} {
		if !hasReason(ta.Partiality, r) {
			t.Errorf("taint partiality %v lacks %s", ta.Partiality.Reasons, r)
		}
	}

	re, err := l.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(re.Paths) != 0 || !hasReason(re.Partiality, plugin.PartialReasonDynamicDispatch) || !hasReason(re.Partiality, reasonFnPtr) {
		t.Errorf("sinkless reachability = %+v, want no paths and the graph's partiality", re)
	}
}

// C++: a name with a header prototype and a definition is one symbol, its duplicated edge rows
// one edge, and a path to it is found from the merged anchor, never "absent".
func TestLane_CXX_SplitDeclarationsMerged(t *testing.T) {
	ctx := context.Background()
	dir := copyFixture(t, "cpp")
	l := newTestLane(t, Config{}, (&fakeOpener{g: cxxGraph()}).open)

	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range edgesOf(cg) {
		if e == [2]string{"main", "codec::checksum"} {
			n++
		}
	}
	if n != 1 {
		t.Errorf("main->codec::checksum appears %d times, want 1", n)
	}
	if !hasReason(cg.Partiality, reasonVtable) {
		t.Errorf("partiality %v lacks %s", cg.Partiality.Reasons, reasonVtable)
	}
	if hasReason(cg.Partiality, reasonHAsC) {
		t.Error("a .hpp-only tree declares cgx_h_as_c")
	}

	idx, err := l.IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, s := range idx.Symbols {
		seen[s.SCIP]++
	}
	if seen["codec::checksum"] != 1 || seen["codec::Inflate::decode"] != 1 {
		t.Errorf("symbols not merged by FQN: %v", seen)
	}

	res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"codec::checksum"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].SCIP != "codec::checksum" {
		t.Errorf("resolve = %+v, want the merged codec::checksum", res.Resolved)
	}

	re, err := l.Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"codec::checksum"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(re.Paths) != 1 {
		t.Errorf("reachability = %+v, want a path to codec::checksum", re.Paths)
	}

	in, err := l.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	got := ingressesOf(in)
	if got["main"] != IngressMain || got["codec::Inflate::decode"] != IngressExported || got["codec::checksum"] != IngressExported {
		t.Errorf("ingresses = %v", got)
	}
	if _, ok := got["run"]; ok {
		t.Error("static run is an ingress")
	}
}

// With no main, nothing is invented: the exported functions are the only ingresses and
// no_known_ingress is declared.
func TestLane_NoMain(t *testing.T) {
	dir := writeTree(t, map[string]string{"lib.c": "int api(int x)\n{\n\treturn helper(x);\n}\n\nstatic int helper(int x)\n{\n\treturn x;\n}\n"})
	g := &fakeGraph{
		nodes: []node{{FQN: "api", Kind: "function", File: "lib.c", Line: 1}, {FQN: "helper", Kind: "function", File: "lib.c", Line: 6}},
		rows:  []edgeRow{{"api", "calls", "certain", "helper"}},
	}
	l := newTestLane(t, Config{}, (&fakeOpener{g: g}).open)
	in, err := l.FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got := ingressesOf(in); !reflect.DeepEqual(got, map[string]string{"api": IngressExported}) {
		t.Errorf("ingresses = %v", got)
	}
	if !hasReason(in.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("partiality %v lacks %s", in.Partiality.Reasons, plugin.PartialReasonNoIngress)
	}
}

// A translation unit cgx found nothing in is declared, as is a tree with no C/C++ at all.
func TestLane_EmptyTUAndNoSources(t *testing.T) {
	ctx := context.Background()
	dir := writeTree(t, map[string]string{"a.c": "int a(void) { return 0; }\n", "b.c": "#error unparseable\n"})
	g := &fakeGraph{nodes: []node{{FQN: "a", Kind: "function", File: "a.c", Line: 1}}}
	l := newTestLane(t, Config{}, (&fakeOpener{g: g}).open)
	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(cg.Partiality, reasonEmptyTU) {
		t.Errorf("partiality %v lacks %s", cg.Partiality.Reasons, reasonEmptyTU)
	}

	empty := writeTree(t, map[string]string{"README": "nothing here\n"})
	l = newTestLane(t, Config{}, (&fakeOpener{g: &fakeGraph{}}).open)
	cg, err = l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: empty})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(cg.Partiality, reasonNoSources) || !hasReason(cg.Partiality, plugin.PartialReasonNoManifest) {
		t.Errorf("partiality %v lacks no_manifest / %s", cg.Partiality.Reasons, reasonNoSources)
	}
}

// With a compilation database only its translation units (and the tree's headers) are staged;
// a TU outside the tree is an empty TU, a TU whose language disagrees with its extension is
// declared, and .h headers in a C++ build are declared misread.
func TestLane_CompileDBSelection(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"src/a.cc":                 "int a() { return 0; }\n",
		"src/b.c":                  "int b(void) { return 0; }\n",
		"src/unbuilt.c":            "int unbuilt(void) { return 0; }\n",
		"include/x.h":              "int a();\n",
		"build/CMakeFiles/probe.c": "int probe(void) { return 0; }\n",
	})
	db := &compiledb.DB{TUs: []compiledb.TU{
		{File: filepath.Join(dir, "src/a.cc"), Lang: compiledb.LangCXX},
		{File: filepath.Join(dir, "src/b.c"), Lang: compiledb.LangCXX}, // compiled as C++ (-x c++)
		{File: "/elsewhere/gen.c", Lang: compiledb.LangC},
	}}
	g := &fakeGraph{nodes: []node{
		{FQN: "a", Kind: "function", File: "src/a.cc", Line: 1},
		{FQN: "b", Kind: "function", File: "src/b.c", Line: 1},
	}}
	op := &fakeOpener{g: g}
	l := newTestLane(t, Config{}, op.open)
	withDB(l, db)
	cg, err := l.CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if got := stagedFiles(t, op.repos[0]); !reflect.DeepEqual(got, []string{"include/x.h", "src/a.cc", "src/b.c"}) {
		t.Errorf("staged %v", got)
	}
	for _, r := range []string{reasonEmptyTU, reasonTULang, reasonHAsC} {
		if !hasReason(cg.Partiality, r) {
			t.Errorf("partiality %v lacks %s", cg.Partiality.Reasons, r)
		}
	}
	if hasReason(cg.Partiality, plugin.PartialReasonNoManifest) {
		t.Error("no_manifest declared with a compilation database")
	}
}

// Advisory symbols: none named is advisory_symbol_absent without touching the engine; an exact
// name resolves; a bare name matching a qualified C++ name is declared; a name the graph does
// not define is declared cgx_sink_unresolved, never read as absent-and-safe.
func TestLane_ResolveDependencySymbols(t *testing.T) {
	ctx := context.Background()
	dir := copyFixture(t, "cpp")
	op := &fakeOpener{g: cxxGraph()}
	l := newTestLane(t, Config{}, op.open)

	res, err := l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonAdvisorySymbolAbsent) || len(res.Resolved) != 0 || len(op.repos) != 0 {
		t.Errorf("no symbol: %+v (engine opened %d times)", res, len(op.repos))
	}

	res, err = l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: dir, AdvisorySymbols: []string{"checksum()"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].SCIP != "codec::checksum" || !hasReason(res.Partiality, reasonSuffixMatch) {
		t.Errorf("suffix: %+v", res)
	}

	cdir := copyFixture(t, "c")
	l = newTestLane(t, Config{}, (&fakeOpener{g: cGraph()}).open)
	res, err = l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: cdir, AdvisorySymbols: []string{"memcpy"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 0 || !hasReason(res.Partiality, reasonSinkUnresolved) {
		t.Errorf("external: %+v", res)
	}
	res, err = l.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{BuildDir: cdir, AdvisorySymbols: []string{"parse"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || hasReason(res.Partiality, reasonSinkUnresolved) || hasReason(res.Partiality, reasonSuffixMatch) {
		t.Errorf("exact: %+v", res)
	}
}

// cgx answers are read to exhaustion across pages; a truncated answer is declared, and a graph
// that changes between pages is a hard error rather than a stitched graph.
func TestLane_Paging(t *testing.T) {
	ctx := context.Background()
	dir := copyFixture(t, "c")

	g := cGraph()
	g.pageLen = 2
	l := newTestLane(t, Config{}, (&fakeOpener{g: g}).open)
	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(cg.Edges) != 3 || g.calls["search"] != 4 || g.calls["graph_query"] != 2 {
		t.Errorf("edges %d, pages %v", len(cg.Edges), g.calls)
	}

	g = cGraph()
	g.truncate = true
	l = newTestLane(t, Config{}, (&fakeOpener{g: g}).open)
	if cg, err = l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir}); err != nil || !hasReason(cg.Partiality, reasonQueryTruncated) {
		t.Errorf("truncated: %v %v", err, cg.Partiality.Reasons)
	}

	g = cGraph()
	g.pageLen = 2
	g.version = func(tool string, page int) string {
		if tool == "search" && page > 0 {
			return "v2"
		}
		return "v1"
	}
	l = newTestLane(t, Config{}, (&fakeOpener{g: g}).open)
	if _, err = l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir}); err == nil || !strings.Contains(err.Error(), "graph changed") {
		t.Errorf("version change: err = %v", err)
	}
}

// An engine failure while indexing is a hard error, recorded so the next operation on the same
// tree replays it without opening the engine; with a native fallback configured, a wasm trap is
// retried once on it.
func TestLane_IndexFailureMemoAndFallback(t *testing.T) {
	ctx := context.Background()
	dir := copyFixture(t, "c")

	trap := &fakeGraph{indexErr: &EngineFailure{Kind: EngineMemoryLimit, Err: errors.New("out of memory")}}
	op := &fakeOpener{g: trap}
	l := newTestLane(t, Config{}, op.open)
	_, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	var f *IndexFailure
	if !errors.As(err, &f) || f.Kind != EngineMemoryLimit || !strings.HasPrefix(err.Error(), reasonIndexFailed) {
		t.Fatalf("err = %v, want an IndexFailure", err)
	}
	if _, err = l.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir}); !errors.As(err, &f) {
		t.Fatalf("second op err = %v, want the recorded failure", err)
	}
	if len(op.repos) != 1 {
		t.Errorf("engine opened %d times, want once (the failure is replayed)", len(op.repos))
	}

	// A failure that may not recur expires after FailureTTL.
	exit := &fakeGraph{indexErr: &EngineFailure{Kind: EngineExit, Err: errors.New("killed")}}
	op = &fakeOpener{g: exit}
	l = newTestLane(t, Config{FailureTTL: time.Minute}, op.open)
	t0 := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	l.now = fixedNow(t0)
	_, _ = l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	_, _ = l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	l.now = fixedNow(t0.Add(2 * time.Minute))
	_, _ = l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if len(op.repos) != 2 {
		t.Errorf("engine opened %d times, want 2 (replayed within the TTL, retried after)", len(op.repos))
	}

	ok := cGraph()
	op = &fakeOpener{}
	l = newTestLane(t, Config{Fallback: TransportNative}, func(ctx context.Context, repo string, cfg Config) (Graph, error) {
		op.cfgs = append(op.cfgs, cfg)
		if cfg.Transport == TransportWasm {
			return &fakeGraph{indexErr: &EngineFailure{Kind: EngineTrap, Err: errors.New("unreachable")}}, nil
		}
		return ok, nil
	})
	cg, err := l.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil || len(cg.Edges) != 3 {
		t.Fatalf("fallback: %v, %d edges", err, len(cg.Edges))
	}
	if len(op.cfgs) != 2 || op.cfgs[1].Transport != TransportNative {
		t.Errorf("transports tried: %+v", op.cfgs)
	}
}

// static: a name is file-local only when every definition is lexically static, the keyword on
// the definition's line or alone on the line before.
func TestStatic(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.c": "static int one(void)\n{ return 1; }\n\nstatic int\ntwo(void)\n{ return 2; }\n\nint three(void);\nint\nfour(void)\n{ return 4; }\n/* static */ int five(void) { return 5; }\n",
		"b.c": "int one(void) { return 1; }\n",
	})
	cache := map[string][]string{}
	for _, c := range []struct {
		ns   []node
		want bool
	}{
		{[]node{{File: "a.c", Line: 1}}, true},
		{[]node{{File: "a.c", Line: 5}}, true},
		{[]node{{File: "a.c", Line: 10}}, false},
		{[]node{{File: "a.c", Line: 12}}, false},
		{[]node{{File: "a.c", Line: 1}, {File: "b.c", Line: 1}}, false},
		{nil, false},
	} {
		if got := static(dir, c.ns, cache); got != c.want {
			t.Errorf("static(%+v) = %v, want %v", c.ns, got, c.want)
		}
	}
}
