package pythoncgx

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// pageSize is the largest page cgx's list-shaped tools return; those results are paged.
const pageSize = 200

// maxCallerDepth bounds the transitive callers walk; deep enough to be unbounded in practice.
const maxCallerDepth = 1 << 16

type pageInfo struct {
	HasMore bool    `json:"has_more"`
	Cursor  *string `json:"cursor"`
}

// paged runs a list-shaped tool to exhaustion, handing each page's raw result to each.
func (s *session) paged(ctx context.Context, tool string, args map[string]any, each func(json.RawMessage) error) error {
	call := make(map[string]any, len(args)+2)
	for k, v := range args {
		call[k] = v
	}
	call["max_results"] = pageSize
	for {
		raw, err := s.call(ctx, tool, call)
		if err != nil {
			return err
		}
		s.stats.Pages++
		if err := each(raw); err != nil {
			return fmt.Errorf("pythoncgx: decode %s page: %w", tool, err)
		}
		var p pageInfo
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("pythoncgx: decode %s page: %w", tool, err)
		}
		if !p.HasMore {
			return nil
		}
		if p.Cursor == nil || *p.Cursor == "" {
			return fmt.Errorf("pythoncgx: %s reported more results without a cursor", tool)
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

// exportNode and exportEdge are the parts of cgx's session-op node and edge records the lane
// reads. Ids are valid for one graph_version only.
type exportNode struct {
	ID  uint32 `json:"id"`
	FQN string `json:"fqn"`
}

type exportEdge struct {
	Src uint32 `json:"src"`
	Dst uint32 `json:"dst"`
}

// exportEdges streams every call-family edge at or above the confidence floor through cgx's
// export_edges session op, one chunk per call, and returns them as (caller, callee) FQNs.
func (s *session) exportEdges(ctx context.Context, minConfidence string) ([][2]string, error) {
	var (
		out     [][2]string
		version string
		cursor  *string
	)
	for {
		args := map[string]any{"confidence": minConfidence}
		if cursor != nil {
			args["cursor"] = *cursor
		}
		raw, err := s.call(ctx, "export_edges", args)
		if err != nil {
			return nil, err
		}
		s.stats.Pages++
		var chunk struct {
			GraphVersion string       `json:"graph_version"`
			Edges        []exportEdge `json:"edges"`
			Nodes        []exportNode `json:"nodes"`
			NextCursor   *string      `json:"next_cursor"`
		}
		if err := json.Unmarshal(raw, &chunk); err != nil {
			return nil, fmt.Errorf("pythoncgx: decode export_edges chunk: %w", err)
		}
		if version == "" {
			version = chunk.GraphVersion
		} else if chunk.GraphVersion != version {
			return nil, fmt.Errorf("pythoncgx: export_edges graph changed mid-export (%s, then %s)", version, chunk.GraphVersion)
		}
		fqn := make(map[uint32]string, len(chunk.Nodes))
		for _, n := range chunk.Nodes {
			fqn[n.ID] = n.FQN
		}
		for _, e := range chunk.Edges {
			src, ok1 := fqn[e.Src]
			dst, ok2 := fqn[e.Dst]
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("pythoncgx: export_edges chunk references node %d or %d without listing it", e.Src, e.Dst)
			}
			out = append(out, [2]string{src, dst})
		}
		if chunk.NextCursor == nil {
			return out, nil
		}
		cursor = chunk.NextCursor
	}
}

// Resolution paths, recorded per looked-up name in the stats record.
const (
	pathExact      = "exact"
	pathSuffix     = "suffix"
	pathUnresolved = "unresolved"
	pathRejected   = "rejected"
)

// resolution is how one native-syntax name resolved.
type resolution struct {
	Role      string   `json:"role"` // "advisory" | "ingress"
	Name      string   `json:"name"`
	Path      string   `json:"path"`
	Nodes     int      `json:"nodes"`
	FQNs      []string `json:"-"`
	Truncated bool     `json:"truncated,omitempty"`
}

type resolveResult struct {
	Nodes     []exportNode    `json:"nodes"`
	Truncated bool            `json:"truncated"`
	Error     json.RawMessage `json:"error"`
}

// resolveBatch asks cgx's resolve session op for the nodes each selector denotes, in one call.
func (s *session) resolveBatch(ctx context.Context, selectors []string) ([]resolveResult, error) {
	if len(selectors) == 0 {
		return nil, nil
	}
	raw, err := s.call(ctx, "resolve", map[string]any{"selectors": selectors})
	if err != nil {
		return nil, err
	}
	var out struct {
		Results []resolveResult `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("pythoncgx: decode resolve: %w", err)
	}
	if len(out.Results) != len(selectors) {
		return nil, fmt.Errorf("pythoncgx: resolve answered %d of %d selectors", len(out.Results), len(selectors))
	}
	return out.Results, nil
}

// resolveNames resolves native-syntax names ("pkg.mod.func") to cgx FQNs through cgx's node
// selector, finding nodes with or without edges. Every name is tried as given; the ones that
// match nothing are retried as a suffix ("**." + name), which finds a name under a root it
// does not spell (a src/ layout, a monorepo package dir). Two calls at most, whatever the
// number of names.
func (s *session) resolveNames(ctx context.Context, role string, names []string) ([]resolution, error) {
	res := make([]resolution, len(names))
	exact, err := s.resolveBatch(ctx, names)
	if err != nil {
		return nil, err
	}
	var retry []int
	for i, r := range exact {
		res[i] = resolution{Role: role, Name: names[i]}
		switch {
		case len(r.Error) > 0 && string(r.Error) != "null":
			res[i].Path = pathRejected
		case len(r.Nodes) > 0:
			res[i].Path, res[i].FQNs, res[i].Truncated = pathExact, fqns(r.Nodes), r.Truncated
		default:
			retry = append(retry, i)
		}
	}
	sel := make([]string, len(retry))
	for j, i := range retry {
		sel[j] = "**." + names[i]
	}
	suffix, err := s.resolveBatch(ctx, sel)
	if err != nil {
		return nil, err
	}
	for j, i := range retry {
		r := suffix[j]
		if len(r.Nodes) > 0 && (len(r.Error) == 0 || string(r.Error) == "null") {
			res[i].Path, res[i].FQNs, res[i].Truncated = pathSuffix, fqns(r.Nodes), r.Truncated
		} else {
			res[i].Path = pathUnresolved
		}
	}
	for i := range res {
		res[i].Nodes = len(res[i].FQNs)
	}
	s.stats.Resolutions = append(s.stats.Resolutions, res...)
	return res, nil
}

func fqns(nodes []exportNode) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.FQN)
	}
	return sortedUnique(out)
}

func sortedUnique(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
