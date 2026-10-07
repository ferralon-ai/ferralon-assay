package pythoncgx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythonanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Partiality reasons this lane declares, localising the shared bases (plugin.go) with a
// ":cgx_" suffix. A localised code is not one of the quiet inherent-limit codes, so where a
// pipeline axis harvests it the absence of a path is disclosed as undetermined rather than
// read as a refutation.
const (
	// The call graph omits edges below the configured confidence floor; the suffix names it.
	reasonConfidenceFloor = plugin.PartialReasonDynamicDispatch + ":cgx_min_confidence_"
	// A route handler found by the decorator scan matched no cgx node, so paths from it may
	// be missing.
	reasonIngressUnresolved = plugin.PartialReasonRelationshipUnexpressed + ":cgx_ingress_unresolved"
	// A name resolved only as a suffix of a cgx FQN; the match is weaker than an exact one.
	reasonSuffixMatch = plugin.PartialReasonRelationshipUnexpressed + ":cgx_suffix_match"
	// cgx refused a name as a selector, so it was not looked up.
	reasonSelectorRejected = plugin.PartialReasonToolFailure + ":cgx_selector_rejected"
	// cgx could not resolve a requested sink id.
	reasonSinkUnresolved = plugin.PartialReasonToolFailure + ":cgx_sink_unresolved"
	// cgx's selector engine hit its state cap, so a match may be incomplete.
	reasonResolveTruncated = plugin.PartialReasonToolFailure + ":cgx_resolve_truncated"
)

// taintPrecisionNote states what ComputeTaint's paths are.
const taintPrecisionNote = "call-graph path presence over the cgx call graph (edges at or above the configured confidence floor): an ingress→sink path exists, found by cgx's own caller/reaches queries. NOT variable-level dataflow and not sanitizer-aware; Python's dynamic dispatch makes the graph an under-approximation."

// Lane serves the six graph operations. One Lane serves one plugin process; each operation
// snapshots the build dir, opens the graph, answers, and closes it.
type Lane struct {
	cfg  Config
	open Opener
	// cacheKey separates indexes written by different cgx builds: cgx's fragment cache is
	// not keyed by extractor version, so an index from another build must not be reused.
	cacheKey string
	// routes finds decorator-registered route handlers; cgx's Python adapter has no web
	// framework entrypoints, so ingress detection stays the lexical scanner's.
	routes func(context.Context, string) ([]pythonanalysis.RouteHandler, plugin.Partiality, error)
	// readFailure reports an unreadable Python source, which the incumbent lane declares.
	readFailure func(string) (bool, error)
	stderr      io.Writer
}

// New returns a Lane. cacheKey identifies the cgx build behind open (see Lane.cacheKey).
func New(cfg Config, open Opener, cacheKey string) *Lane {
	if cfg.MinConfidence == "" {
		cfg.MinConfidence = DefaultMinConfidence
	}
	return &Lane{
		cfg: cfg, open: open, cacheKey: cacheKey,
		routes:      pythonanalysis.RouteHandlers,
		readFailure: pythonanalysis.SourceReadFailure,
		stderr:      os.Stderr,
	}
}

// session is one operation's open graph plus its measurements.
type session struct {
	l     *Lane
	g     Graph
	stats opStats
	start time.Time
}

// opStats is the per-operation measurement record (stderr and Config.StatsFile).
type opStats struct {
	Op            string          `json:"op"`
	BuildDir      string          `json:"build_dir"`
	Transport     Transport       `json:"transport"`
	MinConfidence string          `json:"min_confidence"`
	Tree          string          `json:"tree,omitempty"`
	WallMS        int64           `json:"wall_ms"`
	SnapshotMS    int64           `json:"snapshot_ms"`
	OpenMS        int64           `json:"open_ms"`
	QueryMS       int64           `json:"query_ms"`
	ToolCalls     int             `json:"tool_calls"`
	Pages         int             `json:"pages"`
	Items         int             `json:"items"`
	Resolutions   []resolution    `json:"resolutions,omitempty"`
	Error         string          `json:"error,omitempty"`
	SDK           json.RawMessage `json:"sdk,omitempty"`
}

func (l *Lane) begin(ctx context.Context, op, buildDir string) (*session, error) {
	s := &session{l: l, start: time.Now(), stats: opStats{Op: op, BuildDir: buildDir, Transport: l.cfg.Transport, MinConfidence: l.cfg.MinConfidence}}
	repo, tree, err := snapshot(ctx, filepath.Join(l.cfg.CacheDir, l.cacheKey), buildDir)
	s.stats.SnapshotMS = time.Since(s.start).Milliseconds()
	s.stats.Tree = tree
	if err != nil {
		s.finish(err)
		return nil, err
	}
	openStart := time.Now()
	g, err := l.open(ctx, repo, l.cfg)
	s.stats.OpenMS = time.Since(openStart).Milliseconds()
	if err != nil {
		err = fmt.Errorf("pythoncgx: open cgx graph: %w", err)
		s.finish(err)
		return nil, err
	}
	s.g = g
	return s, nil
}

// finish closes the graph and emits the stats record. A stats write failure is reported on
// stderr and never fails the operation.
func (s *session) finish(opErr error) {
	if s.g != nil {
		s.stats.SDK = s.g.Stats()
		if err := s.g.Close(); err != nil && opErr == nil {
			fmt.Fprintf(s.l.stderr, "pythoncgx: close: %v\n", err)
		}
	}
	if opErr != nil {
		s.stats.Error = opErr.Error()
	}
	s.stats.WallMS = time.Since(s.start).Milliseconds()
	line, err := json.Marshal(s.stats)
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = s.l.stderr.Write(line)
	if s.l.cfg.StatsFile == "" {
		return
	}
	f, err := os.OpenFile(s.l.cfg.StatsFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		fmt.Fprintf(s.l.stderr, "pythoncgx: stats file: %v\n", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		fmt.Fprintf(s.l.stderr, "pythoncgx: stats file: %v\n", err)
	}
}

// sym mints the plugin Symbol for a cgx FQN. Every graph-shaped result goes through it, so a
// node's Symbol is byte-identical wherever it appears (plugin.Symbol compares all fields).
func sym(fqn string) plugin.Symbol { return plugin.Symbol{SCIP: fqn, DisplayName: fqn} }

// IndexSymbols lists cgx's function, method and type nodes. Like the incumbent lane it declares
// tool_failure when a Python source in the build dir cannot be read.
func (l *Lane) IndexSymbols(ctx context.Context, req plugin.IndexSymbolsRequest) (res plugin.SymbolIndexResult, err error) {
	s, err := l.begin(ctx, plugin.OpIndexSymbols, req.BuildDir)
	if err != nil {
		return res, err
	}
	defer func() { s.finish(err) }()

	readFailed, err := l.readFailure(req.BuildDir)
	if err != nil {
		return res, err
	}
	var fqns []string
	for _, kind := range []string{"function", "method", "type"} {
		err := s.paged(ctx, "search", map[string]any{"all": true, "kind": kind}, func(raw json.RawMessage) error {
			var page struct {
				Results []struct {
					FQN string `json:"fqn"`
				} `json:"results"`
			}
			if err := json.Unmarshal(raw, &page); err != nil {
				return err
			}
			for _, r := range page.Results {
				fqns = append(fqns, r.FQN)
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	fqns = sortedUnique(fqns)
	res = plugin.SymbolIndexResult{Partiality: plugin.Complete(), Symbols: make([]plugin.Symbol, 0, len(fqns))}
	if readFailed {
		res.Partiality = plugin.Partial(plugin.PartialReasonToolFailure)
	}
	for _, f := range fqns {
		res.Symbols = append(res.Symbols, sym(f))
	}
	s.stats.Items = len(res.Symbols)
	return res, nil
}

// ResolveDependencySymbols resolves each advisory symbol — a name in Python's dotted syntax —
// through cgx's node selector, in one batch. An unresolved symbol is an empty result, as on
// the incumbent lane; a suffix-only, rejected or truncated lookup is declared, and so is an
// unreadable Python source (tool_failure, as the incumbent declares it).
func (l *Lane) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (res plugin.SymbolResolutionResult, err error) {
	s, err := l.begin(ctx, plugin.OpResolveSymbols, req.BuildDir)
	if err != nil {
		return res, err
	}
	defer func() { s.finish(err) }()

	readFailed, err := l.readFailure(req.BuildDir)
	if err != nil {
		return res, err
	}
	var names []string
	seen := map[string]bool{}
	for _, raw := range req.AdvisorySymbols {
		if name := strings.TrimSpace(raw); name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	resolved, err := s.resolveNames(ctx, "advisory", names)
	if err != nil {
		return res, err
	}
	reasons := map[string]bool{}
	if readFailed {
		reasons[plugin.PartialReasonToolFailure] = true
	}
	var fqns []string
	for _, r := range resolved {
		noteResolution(reasons, r)
		fqns = append(fqns, r.FQNs...)
	}
	fqns = sortedUnique(fqns)
	res = plugin.SymbolResolutionResult{Partiality: partiality(reasons), Resolved: make([]plugin.Symbol, 0, len(fqns))}
	for _, f := range fqns {
		res.Resolved = append(res.Resolved, sym(f))
	}
	s.stats.Items = len(res.Resolved)
	return res, nil
}

// CallGraph returns every cgx call edge at or above the confidence floor, with the resolved
// route handlers as roots. It is always partial: dynamic dispatch, plus the floor itself.
func (l *Lane) CallGraph(ctx context.Context, req plugin.CallGraphRequest) (res plugin.CallGraphResult, err error) {
	s, err := l.begin(ctx, plugin.OpCallGraph, req.BuildDir)
	if err != nil {
		return res, err
	}
	defer func() { s.finish(err) }()

	pairs, err := s.exportEdges(ctx, l.cfg.MinConfidence)
	if err != nil {
		return res, err
	}
	edges := make([]plugin.CallEdge, 0, len(pairs))
	for _, p := range pairs {
		edges = append(edges, plugin.CallEdge{Caller: sym(p[0]), Callee: sym(p[1])})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})
	edges = dedupeEdges(edges)

	ing, err := s.ingresses(ctx, req.BuildDir)
	if err != nil {
		return res, err
	}
	var roots []string
	for _, in := range ing.Ingresses {
		roots = append(roots, in.Symbol.SCIP)
	}
	roots = sortedUnique(roots)

	reasons := map[string]bool{
		plugin.PartialReasonDynamicDispatch:         true,
		reasonConfidenceFloor + l.cfg.MinConfidence: true,
	}
	for _, r := range ing.Partiality.Reasons {
		reasons[r] = true
	}
	res = plugin.CallGraphResult{
		Partiality: partiality(reasons),
		Algorithm:  "cgx(min_confidence=" + l.cfg.MinConfidence + ")",
		Edges:      edges,
		Roots:      make([]plugin.Symbol, 0, len(roots)),
	}
	for _, r := range roots {
		res.Roots = append(res.Roots, sym(r))
	}
	s.stats.Items = len(edges)
	return res, nil
}

// FindIngresses resolves the decorator scan's route handlers to cgx nodes.
func (l *Lane) FindIngresses(ctx context.Context, req plugin.FindIngressesRequest) (res plugin.IngressResult, err error) {
	s, err := l.begin(ctx, plugin.OpFindIngresses, req.BuildDir)
	if err != nil {
		return res, err
	}
	defer func() { s.finish(err) }()
	res, err = s.ingresses(ctx, req.BuildDir)
	s.stats.Items = len(res.Ingresses)
	return res, err
}

// Reachability finds, for each requested sink id, a path from a route handler to it. With no
// sinks requested (as the pipeline calls it) it returns no paths and touches no graph.
func (l *Lane) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if len(nonEmpty(req.Symbols)) == 0 {
		return plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch), Paths: []plugin.ReachPath{}}, nil
	}
	paths, part, err := l.paths(ctx, plugin.OpReachability, req.BuildDir, req.Symbols)
	return plugin.ReachabilityResult{Partiality: part, Paths: paths}, err
}

// ComputeTaint reports path presence from a route handler to each sink; see taintPrecisionNote.
func (l *Lane) ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	paths, part, err := l.paths(ctx, plugin.OpComputeTaint, req.BuildDir, req.Sinks)
	return plugin.TaintResult{Partiality: part, Paths: paths, PrecisionNote: taintPrecisionNote}, err
}

// paths is Reachability and ComputeTaint: per sink, cgx's transitive callers at the floor are
// intersected with the resolved route handlers, the nearest handler (fewest hops, then FQN)
// is chosen, and cgx's reaches supplies the witness trace. Always partial (dynamic dispatch);
// a sink with no reaching handler adds no_known_ingress — unknown, never safe.
func (l *Lane) paths(ctx context.Context, op, buildDir string, sinks []string) (paths []plugin.ReachPath, part plugin.Partiality, err error) {
	s, err := l.begin(ctx, op, buildDir)
	if err != nil {
		return nil, part, err
	}
	defer func() { s.finish(err) }()

	ing, err := s.ingresses(ctx, buildDir)
	if err != nil {
		return nil, part, err
	}
	reasons := map[string]bool{plugin.PartialReasonDynamicDispatch: true}
	for _, r := range ing.Partiality.Reasons {
		reasons[r] = true
	}
	handlers := map[string]bool{}
	for _, in := range ing.Ingresses {
		handlers[in.Symbol.SCIP] = true
	}

	paths = []plugin.ReachPath{}
	for _, sink := range nonEmpty(sinks) {
		p, ok, err := s.pathTo(ctx, sink, handlers, reasons)
		if err != nil {
			return nil, part, err
		}
		if !ok {
			reasons[plugin.PartialReasonNoIngress] = true
			continue
		}
		paths = append(paths, p)
	}
	s.stats.Items = len(paths)
	return paths, partiality(reasons), nil
}

func (s *session) pathTo(ctx context.Context, sink string, handlers, reasons map[string]bool) (plugin.ReachPath, bool, error) {
	if handlers[sink] {
		return plugin.ReachPath{Sink: sym(sink), Ingress: sym(sink), Trace: []plugin.Symbol{sym(sink)}}, true, nil
	}
	floor := s.l.cfg.MinConfidence
	best, bestDepth := "", -1
	err := s.paged(ctx, "callers", map[string]any{"symbol": sink, "depth": maxCallerDepth, "confidence": floor}, func(raw json.RawMessage) error {
		var page struct {
			Results []struct {
				Name  string `json:"name"`
				Depth int    `json:"depth"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, r := range page.Results {
			if !handlers[r.Name] {
				continue
			}
			if bestDepth < 0 || r.Depth < bestDepth || (r.Depth == bestDepth && r.Name < best) {
				best, bestDepth = r.Name, r.Depth
			}
		}
		return nil
	})
	if errors.Is(err, ErrUnresolved) {
		reasons[reasonSinkUnresolved] = true
		return plugin.ReachPath{}, false, nil
	}
	if err != nil {
		return plugin.ReachPath{}, false, err
	}
	if best == "" {
		return plugin.ReachPath{}, false, nil
	}

	raw, err := s.call(ctx, "reaches", map[string]any{"from": best, "to": sink, "confidence": floor})
	if err != nil {
		return plugin.ReachPath{}, false, err
	}
	var out struct {
		Reachable bool `json:"reachable"`
		Witness   *struct {
			Steps []struct {
				Name string `json:"name"`
			} `json:"steps"`
		} `json:"witness"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return plugin.ReachPath{}, false, fmt.Errorf("pythoncgx: decode reaches: %w", err)
	}
	if !out.Reachable || out.Witness == nil || len(out.Witness.Steps) == 0 {
		return plugin.ReachPath{}, false, fmt.Errorf("pythoncgx: cgx listed %s as a caller of %s but reaches found no path", best, sink)
	}
	trace := make([]plugin.Symbol, 0, len(out.Witness.Steps))
	for _, st := range out.Witness.Steps {
		trace = append(trace, sym(st.Name))
	}
	return plugin.ReachPath{Sink: sym(sink), Ingress: sym(best), Trace: trace}, true, nil
}

// ingresses resolves every route handler the decorator scan finds to the cgx node(s) its
// dotted name selects, in one batch. A handler cgx has no node for is declared; one whose node
// has no edges is kept and costs nothing (no path starts there).
func (s *session) ingresses(ctx context.Context, buildDir string) (plugin.IngressResult, error) {
	handlers, part, err := s.l.routes(ctx, buildDir)
	if err != nil {
		return plugin.IngressResult{}, err
	}
	reasons := map[string]bool{}
	for _, r := range part.Reasons {
		reasons[r] = true
	}
	names := make([]string, len(handlers))
	for i, h := range handlers {
		names[i] = h.QualifiedName
	}
	resolved, err := s.resolveNames(ctx, "ingress", names)
	if err != nil {
		return plugin.IngressResult{}, err
	}
	seen := map[plugin.Ingress]bool{}
	out := []plugin.Ingress{}
	for i, h := range handlers {
		r := resolved[i]
		noteResolution(reasons, r)
		if r.Path == pathUnresolved {
			reasons[reasonIngressUnresolved] = true
		}
		for _, f := range r.FQNs {
			in := plugin.Ingress{Kind: h.Kind, Symbol: sym(f), Selector: h.Selector}
			if !seen[in] {
				seen[in] = true
				out = append(out, in)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Symbol.SCIP != out[j].Symbol.SCIP {
			return out[i].Symbol.SCIP < out[j].Symbol.SCIP
		}
		return out[i].Selector < out[j].Selector
	})
	if part.Complete && len(reasons) == 0 {
		return plugin.IngressResult{Partiality: plugin.Complete(), Ingresses: out}, nil
	}
	return plugin.IngressResult{Partiality: partiality(reasons), Ingresses: out}, nil
}

// noteResolution adds the partiality reasons a name's resolution path carries.
func noteResolution(reasons map[string]bool, r resolution) {
	switch r.Path {
	case pathSuffix:
		reasons[reasonSuffixMatch] = true
	case pathRejected:
		reasons[reasonSelectorRejected] = true
	}
	if r.Truncated {
		reasons[reasonResolveTruncated] = true
	}
}

// partiality is Complete for no reasons, else Partial with the reasons sorted.
func partiality(reasons map[string]bool) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	rs := make([]string, 0, len(reasons))
	for r := range reasons {
		rs = append(rs, r)
	}
	sort.Strings(rs)
	return plugin.Partial(rs...)
}

func dedupeEdges(edges []plugin.CallEdge) []plugin.CallEdge {
	out := edges[:0]
	for i, e := range edges {
		if i == 0 || e != edges[i-1] {
			out = append(out, e)
		}
	}
	return out
}

func nonEmpty(in []string) []string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
