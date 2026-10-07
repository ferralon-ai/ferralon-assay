package pythoncgx

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// fakeGraph answers the queries the lane sends, over a small in-memory graph. It does not
// implement cgx's selector engine: selectors maps each selector string to the FQNs cgx would
// select.
type fakeGraph struct {
	kinds          map[string]string // fqn -> kind
	edges          []fakeEdge
	selectors      map[string][]string
	rejected       map[string]bool
	truncated      map[string]bool
	resolveBatches int
	pageSize       int // 0: honour max_results
	calls          []string
	closed         bool
}

type fakeEdge struct{ from, to, conf string }

// failingIndex is a graph whose engine fails while indexing, after running before (if set).
type failingIndex struct {
	*fakeGraph
	err    error
	before func()
}

func (f failingIndex) Index(context.Context) error {
	if f.before != nil {
		f.before()
	}
	return f.err
}

var confRank = map[string]int{ConfidencePossible: 0, ConfidenceProbable: 1, ConfidenceCertain: 2}

func (f *fakeGraph) Index(context.Context) error { return nil }
func (f *fakeGraph) Stats() json.RawMessage      { return json.RawMessage(`{"fake":true}`) }
func (f *fakeGraph) Close() error                { f.closed = true; return nil }

func (f *fakeGraph) Call(_ context.Context, tool string, args map[string]any) (json.RawMessage, error) {
	f.calls = append(f.calls, tool)
	switch tool {
	case "export_edges":
		return f.export(args)
	case "resolve":
		return f.resolve(args)
	case "search":
		var hits []any
		for _, fqn := range f.sortedNodes() {
			if f.kinds[fqn] == args["kind"] {
				hits = append(hits, map[string]any{"fqn": fqn, "kind": f.kinds[fqn]})
			}
		}
		return f.page(args, "results", hits)
	case "callers":
		sink := args["symbol"].(string)
		if _, ok := f.kinds[sink]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnresolved, sink)
		}
		floor := args["confidence"].(string)
		depth := map[string]int{sink: 0}
		frontier := []string{sink}
		var out []any
		for len(frontier) > 0 {
			cur := frontier[0]
			frontier = frontier[1:]
			for _, e := range f.edges {
				if e.to != cur || confRank[e.conf] < confRank[floor] {
					continue
				}
				if _, seen := depth[e.from]; seen {
					continue
				}
				depth[e.from] = depth[cur] + 1
				frontier = append(frontier, e.from)
				out = append(out, map[string]any{"name": e.from, "depth": depth[e.from]})
			}
		}
		return f.page(args, "results", out)
	case "reaches":
		from, to, floor := args["from"].(string), args["to"].(string), args["confidence"].(string)
		prev := map[string]string{from: ""}
		frontier := []string{from}
		for len(frontier) > 0 {
			cur := frontier[0]
			frontier = frontier[1:]
			if cur == to {
				var steps []any
				for n := to; n != ""; n = prev[n] {
					steps = append([]any{map[string]any{"name": n}}, steps...)
				}
				return json.Marshal(map[string]any{"reachable": true, "witness": map[string]any{"steps": steps}})
			}
			for _, e := range f.edges {
				if e.from == cur && confRank[e.conf] >= confRank[floor] {
					if _, seen := prev[e.to]; !seen {
						prev[e.to] = cur
						frontier = append(frontier, e.to)
					}
				}
			}
		}
		return json.Marshal(map[string]any{"reachable": false})
	}
	return nil, fmt.Errorf("fake: unexpected tool %q", tool)
}

// export serves export_edges in chunks of f.pageSize edges (default: all), with each chunk's
// nodes numbered by their position in sortedNodes.
func (f *fakeGraph) export(args map[string]any) (json.RawMessage, error) {
	floor := args["confidence"].(string)
	ids := map[string]int{}
	for i, n := range f.sortedNodes() {
		ids[n] = i
	}
	var matching []fakeEdge
	for _, e := range f.edges {
		if confRank[e.conf] >= confRank[floor] {
			matching = append(matching, e)
		}
	}
	off := 0
	if c, ok := args["cursor"].(string); ok {
		off, _ = strconv.Atoi(c)
	}
	size := len(matching)
	if f.pageSize > 0 {
		size = f.pageSize
	}
	end := min(off+size, len(matching))
	var edges, nodes []any
	seen := map[string]bool{}
	for _, e := range matching[off:end] {
		edges = append(edges, map[string]any{"src": ids[e.from], "dst": ids[e.to], "confidence": e.conf})
		for _, n := range []string{e.from, e.to} {
			if !seen[n] {
				seen[n] = true
				nodes = append(nodes, map[string]any{"id": ids[n], "fqn": n})
			}
		}
	}
	body := map[string]any{"graph_version": "v1", "edges": edges, "nodes": nodes, "next_cursor": nil}
	if end < len(matching) {
		body["next_cursor"] = strconv.Itoa(end)
	}
	return json.Marshal(body)
}

// resolve serves the resolve session op from f.selectors; a selector in f.rejected gets the
// per-result error cgx reports for one that does not compile.
func (f *fakeGraph) resolve(args map[string]any) (json.RawMessage, error) {
	f.resolveBatches++
	var results []any
	for _, sel := range args["selectors"].([]string) {
		r := map[string]any{"selector": sel, "nodes": []any{}, "truncated": f.truncated[sel], "error": nil}
		if f.rejected[sel] {
			r["error"] = map[string]any{"kind": "invalid_params", "message": "bad selector"}
		}
		var nodes []any
		for _, fqn := range f.selectors[sel] {
			nodes = append(nodes, map[string]any{"id": 0, "fqn": fqn})
		}
		if nodes != nil {
			r["nodes"] = nodes
		}
		results = append(results, r)
	}
	return json.Marshal(map[string]any{"graph_version": "v1", "results": results})
}

func (f *fakeGraph) page(args map[string]any, key string, items []any) (json.RawMessage, error) {
	size := args["max_results"].(int)
	if f.pageSize > 0 {
		size = f.pageSize
	}
	off := 0
	if c, ok := args["cursor"].(string); ok {
		off, _ = strconv.Atoi(c)
	}
	end := min(off+size, len(items))
	body := map[string]any{key: items[off:end], "has_more": end < len(items), "total_matched": len(items)}
	if end < len(items) {
		body["cursor"] = strconv.Itoa(end)
	}
	return json.Marshal(body)
}

func (f *fakeGraph) sortedNodes() []string {
	var out []string
	for k := range f.kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
