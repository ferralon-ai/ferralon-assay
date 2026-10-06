package pythoncgx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// pageSize is the largest page cgx's tool surface returns; every list result is paged.
const pageSize = 200

// maxCallerDepth bounds the transitive callers walk; deep enough to be unbounded in practice.
const maxCallerDepth = 1 << 16

// cqlString renders s as a CQL string literal, escaping exactly what the CQL lexer decodes.
func cqlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// side names which end of a call edge a selector lookup anchors on. CQL matches only nodes
// bound by a relationship, so a lookup sees a node only through its call edges: a sink is
// looked up among callees (a sink nobody calls cannot be reached), an ingress among callers
// (an entry point that calls nothing reaches nothing).
type side int

const (
	sideCallee side = iota
	sideCaller
)

// selectQuery asks cgx's node-selector engine, through CQL's select(), for the nodes a name
// in some language's native syntax ("pkg.mod.func") denotes.
func selectQuery(selector string, s side) string {
	pattern := "MATCH (m)-[:CALLS]->(n)"
	if s == sideCaller {
		pattern = "MATCH (n)-[:CALLS]->(m)"
	}
	return pattern + " WHERE select(n, " + cqlString(selector) + ") RETURN DISTINCT n.name"
}

// edgesQuery returns every call edge at or above the confidence floor as (caller, callee).
func edgesQuery(minConfidence string) string {
	return "MATCH (a)-[r:CALLS {confidence:" + cqlString(minConfidence) + "}]->(b) RETURN DISTINCT a.name, b.name"
}

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

// queryStrings runs a CQL query whose columns are all strings and returns its rows.
func (s *session) queryStrings(ctx context.Context, query string) ([][]string, error) {
	var rows [][]string
	err := s.paged(ctx, "graph_query", map[string]any{"query": query}, func(raw json.RawMessage) error {
		var page struct {
			Rows [][]string `json:"rows"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		rows = append(rows, page.Rows...)
		return nil
	})
	return rows, err
}

// lookup resolves a native-syntax name to cgx FQNs. The name is tried as given; when nothing
// matches it is retried as a suffix ("**." + name), which finds it under a root the name does
// not spell (a src/ layout, a monorepo package dir). viaSuffix reports that the second form
// matched; rejected reports that cgx refused the selector.
func (s *session) lookup(ctx context.Context, name string, sd side) (fqns []string, viaSuffix, rejected bool, err error) {
	for i, sel := range []string{name, "**." + name} {
		rows, err := s.queryStrings(ctx, selectQuery(sel, sd))
		if errors.Is(err, ErrRejected) {
			return nil, false, true, nil
		}
		if err != nil {
			return nil, false, false, err
		}
		for _, r := range rows {
			if len(r) == 1 && r[0] != "" {
				fqns = append(fqns, r[0])
			}
		}
		if len(fqns) > 0 {
			return sortedUnique(fqns), i == 1, false, nil
		}
	}
	return nil, false, false, nil
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
