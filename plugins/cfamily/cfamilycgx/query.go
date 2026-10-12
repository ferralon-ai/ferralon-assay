package cfamilycgx

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// pageSize is the page size requested from cgx's list-shaped tools.
const pageSize = 500

// callEdgeQuery returns every call-family edge with its kind and confidence. A C++ name cgx
// holds as several nodes (a header prototype and its definition) returns one row per node pair;
// the rows are merged by FQN.
const callEdgeQuery = `MATCH (a)-[r]->(b) WHERE r.kind IN ["calls","calls-virtual","calls-closure","calls-callback","calls-async","calls-indirect"] RETURN a.fqn, r.kind, r.confidence, b.fqn`

// Edge kinds that are a call through a pointer or a virtual slot rather than to a named function.
const (
	edgeVirtual  = "calls-virtual"
	edgeCallback = "calls-callback"
	edgeIndirect = "calls-indirect"
)

// Reasons declared about cgx's answers.
const (
	// cgx truncated a query result, so edges are missing.
	reasonQueryTruncated = plugin.PartialReasonToolFailure + ":cgx_query_truncated"
	// A requested sink, or an advisory symbol being resolved, has no definition in the graph.
	reasonSinkUnresolved = plugin.PartialReasonToolFailure + ":cgx_sink_unresolved"
)

// node is one cgx symbol occurrence (a C++ name can have several).
type node struct {
	FQN  string `json:"fqn"`
	Kind string `json:"kind"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// graphView is the cgx graph as the operations read it: nodes keyed by FQN, edges between FQNs
// at or above the confidence floor.
type graphView struct {
	version string
	nodes   map[string][]node // FQN -> every occurrence
	files   map[string]bool   // files with at least one symbol
	edges   [][2]string       // sorted, unique, no self-loops
	kinds   map[string]bool   // call-edge kinds seen at or above the floor
	reasons map[string]bool
}

type pageInfo struct {
	GraphVersion     string  `json:"graph_version"`
	HasMore          bool    `json:"has_more"`
	Cursor           *string `json:"cursor"`
	Truncated        bool    `json:"truncated"`
	TruncationReason *string `json:"truncation_reason"`
}

// paged runs a list-shaped tool to exhaustion, handing each page's raw result to each. Every
// page must report the same graph_version, so a graph re-indexed mid-read is never stitched
// together; a truncated page is reported to the caller.
func (s *session) paged(ctx context.Context, tool string, args map[string]any, each func(json.RawMessage) error) (version string, truncated bool, err error) {
	call := make(map[string]any, len(args)+2)
	for k, v := range args {
		call[k] = v
	}
	call["max_results"] = pageSize
	for {
		raw, err := s.call(ctx, tool, call)
		if err != nil {
			return "", false, err
		}
		s.stats.Pages++
		var p pageInfo
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", false, fmt.Errorf("cfamilycgx: decode %s page: %w", tool, err)
		}
		if version == "" {
			version = p.GraphVersion
		} else if p.GraphVersion != version {
			return "", false, fmt.Errorf("cfamilycgx: %s: graph changed between pages (%s, then %s)", tool, version, p.GraphVersion)
		}
		truncated = truncated || p.Truncated
		if err := each(raw); err != nil {
			return "", false, fmt.Errorf("cfamilycgx: decode %s page: %w", tool, err)
		}
		if !p.HasMore {
			return version, truncated, nil
		}
		if p.Cursor == nil || *p.Cursor == "" {
			return "", false, fmt.Errorf("cfamilycgx: %s reported more results without a cursor", tool)
		}
		call["cursor"] = *p.Cursor
	}
}

func (s *session) call(ctx context.Context, tool string, args map[string]any) (json.RawMessage, error) {
	start := time.Now()
	raw, err := s.g.Call(ctx, tool, args)
	s.stats.ToolCalls++
	s.stats.QueryMS += time.Since(start).Milliseconds()
	return raw, err
}

// readGraph reads every symbol and every call edge from cgx.
func (s *session) readGraph(ctx context.Context, floor string) (*graphView, error) {
	gv := &graphView{nodes: map[string][]node{}, files: map[string]bool{}, kinds: map[string]bool{}, reasons: map[string]bool{}}
	nv, ntrunc, err := s.paged(ctx, "search", map[string]any{"all": true, "kind": "all"}, func(raw json.RawMessage) error {
		var page struct {
			Results []node `json:"results"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, n := range page.Results {
			if n.FQN == "" {
				continue
			}
			gv.nodes[n.FQN] = append(gv.nodes[n.FQN], n)
			if n.File != "" {
				gv.files[n.File] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	minRank := confidenceRank(floor)
	seen := map[[2]string]bool{}
	ev, etrunc, err := s.paged(ctx, "graph_query", map[string]any{"query": callEdgeQuery}, func(raw json.RawMessage) error {
		var page struct {
			Columns []string            `json:"columns"`
			Rows    [][]json.RawMessage `json:"rows"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		if len(page.Rows) > 0 && len(page.Columns) != 4 {
			return fmt.Errorf("graph_query returned %d columns, want 4", len(page.Columns))
		}
		for _, row := range page.Rows {
			if len(row) != 4 {
				return fmt.Errorf("graph_query row has %d cells, want 4", len(row))
			}
			var cells [4]string
			for i, c := range row {
				if string(c) == "null" {
					continue
				}
				if err := json.Unmarshal(c, &cells[i]); err != nil {
					return fmt.Errorf("graph_query cell %d: %w", i, err)
				}
			}
			caller, kind, conf, callee := cells[0], cells[1], cells[2], cells[3]
			if confidenceRank(conf) < minRank {
				continue
			}
			gv.kinds[kind] = true
			if caller == callee || caller == "" || callee == "" {
				continue
			}
			e := [2]string{caller, callee}
			if !seen[e] {
				seen[e] = true
				gv.edges = append(gv.edges, e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if nv != ev && nv != "" && ev != "" {
		return nil, fmt.Errorf("cfamilycgx: graph changed between symbol and edge reads (%s, then %s)", nv, ev)
	}
	gv.version = nv
	if ntrunc || etrunc {
		gv.reasons[reasonQueryTruncated] = true
	}
	sort.Slice(gv.edges, func(i, j int) bool {
		if gv.edges[i][0] != gv.edges[j][0] {
			return gv.edges[i][0] < gv.edges[j][0]
		}
		return gv.edges[i][1] < gv.edges[j][1]
	})
	s.stats.Nodes, s.stats.Edges = len(gv.nodes), len(gv.edges)
	return gv, nil
}

// callable reports whether fqn names a function or method.
func (gv *graphView) callable(fqn string) bool {
	for _, n := range gv.nodes[fqn] {
		if n.Kind == "function" || n.Kind == "method" {
			return true
		}
	}
	return false
}

// callables returns every function and method FQN, sorted.
func (gv *graphView) callables() []string {
	var out []string
	for f := range gv.nodes {
		if gv.callable(f) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// path finds a shortest call path from any of from (tried in sorted order, so the witness is
// deterministic) to sink, over the graph's edges.
func (gv *graphView) path(from []string, sink string) ([]string, bool) {
	adj := map[string][]string{}
	for _, e := range gv.edges {
		adj[e[0]] = append(adj[e[0]], e[1])
	}
	prev := map[string]string{}
	visited := map[string]bool{}
	var queue []string
	for _, f := range from {
		if !visited[f] {
			visited[f] = true
			queue = append(queue, f)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == sink {
			trace := []string{cur}
			for trace[0] != "" {
				p, ok := prev[trace[0]]
				if !ok {
					break
				}
				trace = append([]string{p}, trace...)
			}
			return trace, true
		}
		for _, n := range adj[cur] {
			if !visited[n] {
				visited[n] = true
				prev[n] = cur
				queue = append(queue, n)
			}
		}
	}
	return nil, false
}
