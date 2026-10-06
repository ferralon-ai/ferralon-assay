package pythoncgx

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// fakeGraph answers the queries the lane sends, over a small in-memory graph. It does not
// implement cgx's selector engine: selectors maps each selector string to the FQNs cgx would
// select, and the fake applies only the call-edge anchoring the lane's CQL adds.
type fakeGraph struct {
	kinds     map[string]string // fqn -> kind
	edges     []fakeEdge
	selectors map[string][]string
	rejected  map[string]bool
	pageSize  int // 0: honour max_results
	calls     []string
	closed    bool
}

type fakeEdge struct{ from, to, conf string }

var confRank = map[string]int{ConfidencePossible: 0, ConfidenceProbable: 1, ConfidenceCertain: 2}

func (f *fakeGraph) Stats() json.RawMessage { return json.RawMessage(`{"fake":true}`) }
func (f *fakeGraph) Close() error           { f.closed = true; return nil }

func (f *fakeGraph) Call(_ context.Context, tool string, args map[string]any) (json.RawMessage, error) {
	f.calls = append(f.calls, tool)
	switch tool {
	case "graph_query":
		rows, err := f.query(args["query"].(string))
		if err != nil {
			return nil, err
		}
		return f.page(args, "rows", rows)
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

func (f *fakeGraph) query(q string) ([]any, error) {
	if strings.HasPrefix(q, "MATCH (a)-[r:CALLS {confidence:") {
		floor := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(q, "MATCH (a)-[r:CALLS {confidence:"), "}]->(b) RETURN DISTINCT a.name, b.name"), `"`)
		var rows []any
		for _, e := range f.edges {
			if confRank[e.conf] >= confRank[floor] {
				rows = append(rows, []string{e.from, e.to})
			}
		}
		return rows, nil
	}
	i := strings.Index(q, "select(n, ")
	if i < 0 {
		return nil, fmt.Errorf("fake: unexpected query %q", q)
	}
	lit := q[i+len("select(n, ") : strings.LastIndex(q, ") RETURN")]
	sel, err := strconv.Unquote(lit)
	if err != nil {
		return nil, err
	}
	if f.rejected[sel] {
		return nil, fmt.Errorf("%w: select: bad selector", ErrRejected)
	}
	caller := strings.HasPrefix(q, "MATCH (n)-[:CALLS]->(m)")
	var rows []any
	for _, fqn := range f.selectors[sel] {
		for _, e := range f.edges {
			if (caller && e.from == fqn) || (!caller && e.to == fqn) {
				rows = append(rows, []string{fqn})
				break
			}
		}
	}
	return rows, nil
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
