package cfamilycgx

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

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Engine-state and lane reasons. All are loud: each says this run's analysis did not happen
// (or happened only in part), never a property of the method.
const (
	// No engine to run: no wasm module (the pinned SDK embeds none) or native binary configured.
	reasonEngineUnconfigured = plugin.PartialReasonToolFailure + ":cgx_engine_unconfigured"
	// The native binary is unpinned or does not match its pin, so it was not run.
	reasonEngineUnverified = plugin.PartialReasonToolFailure + ":cgx_engine_unverified"
	// The engine and the SDK are not the pinned pair from one cgx commit, so it was not run.
	reasonEngineMismatch = plugin.PartialReasonToolFailure + ":cgx_engine_mismatch"
	// The cgx engine failed while indexing the tree (IndexFailure, a hard error).
	reasonIndexFailed = plugin.PartialReasonToolFailure + ":cgx_index_failed"
	// The call graph omits edges below a raised confidence floor; the suffix names it.
	reasonConfidenceFloor = plugin.PartialReasonDynamicDispatch + ":cgx_min_confidence_"
	// An advisory name matched only as the last component of a qualified C++ name.
	reasonSuffixMatch = plugin.PartialReasonRelationshipUnexpressed + ":cgx_suffix_match"
)

// Ingress kinds.
const (
	IngressMain     = "main"
	IngressExported = "exported_function"
)

// taintPrecisionNote states what ComputeTaint's paths are.
const taintPrecisionNote = "call-graph path presence over the cgx call graph (edges at or above the configured confidence floor, C++ names merged across their declarations): an ingress→sink call path exists. NOT variable-level dataflow and not sanitizer-aware; calls through function pointers, virtual slots and macros are under-approximated and named in the partiality."

// Lane serves the graph operations. One Lane serves one plugin process; each operation stages
// the build dir's sources, opens and indexes the graph, answers, and closes it.
type Lane struct {
	cfg  Config
	open Opener
	// cacheKey separates indexes written by different cgx builds: cgx's fragment cache is not
	// keyed by extractor version, so an index from another build must not be reused.
	// fallbackKey is the same for the Config.Fallback transport's build; fallbackErr is why
	// that build is not usable, when it is not.
	cacheKey, fallbackKey string
	fallbackErr           error
	// unavailable, when set, is why no engine can run; every operation declares it.
	unavailable error
	// memoryLimit names the wasm linear-memory ceiling, part of a recorded index failure's key.
	memoryLimit string
	now         func() time.Time
	sources     func(string) (cfamilyanalysis.GraphSources, error)
	stderr      io.Writer
}

// New returns a Lane over open. cacheKey identifies the cgx build behind open (see
// Lane.cacheKey); fallbackKey identifies the Config.Fallback build and is ignored without one.
func New(cfg Config, open Opener, cacheKey, fallbackKey string) *Lane {
	if cfg.MinConfidence == "" {
		cfg.MinConfidence = DefaultMinConfidence
	}
	return &Lane{
		cfg: cfg, open: open, cacheKey: cacheKey, fallbackKey: fallbackKey,
		memoryLimit: memoryLimitKey(),
		now:         time.Now,
		sources:     cfamilyanalysis.ReadGraphSources,
		stderr:      os.Stderr,
	}
}

// NewSDK returns a Lane backed by the cgx SDK after verifying the engine cfg selects. An engine
// that cannot be verified does not stop the plugin: the Lane declares why on every operation.
func NewSDK(cfg Config) *Lane {
	key, err := CacheKey(cfg)
	if err != nil {
		return Unavailable(cfg, err)
	}
	l := New(cfg, OpenSDK, key, "")
	if cfg.Fallback != "" {
		fb := cfg
		fb.Transport = cfg.Fallback
		l.fallbackKey, l.fallbackErr = CacheKey(fb)
	}
	return l
}

// Unavailable returns a Lane with no engine: every operation declares err's engine-state reason
// (tool_failure:cgx_engine_unconfigured unless err names another) and returns no graph.
func Unavailable(cfg Config, err error) *Lane {
	l := New(cfg, nil, "", "")
	l.unavailable = err
	return l
}

// engineReason is the reason an engine-state error declares, or "" for any other error.
func engineReason(err error) string {
	switch {
	case errors.Is(err, ErrEngineMismatch):
		return reasonEngineMismatch
	case errors.Is(err, ErrEngineUnverified):
		return reasonEngineUnverified
	case errors.Is(err, ErrEngineUnconfigured):
		return reasonEngineUnconfigured
	}
	return ""
}

// session is one operation's open graph, the tree it was built from, and its measurements.
type session struct {
	l    *Lane
	g    Graph
	work string // the build directory, resolved
	// repoPath is the snapshot repository cgx opens.
	repoPath string
	sel      selection
	srcs     cfamilyanalysis.GraphSources
	gv       *graphView
	// unparsed are the short names of functions the tree defines and the graph lacks.
	unparsed map[string]bool
	stats    opStats
	start    time.Time
}

// opStats is the per-operation measurement record (stderr and Config.StatsFile).
type opStats struct {
	Op              string          `json:"op"`
	BuildDir        string          `json:"build_dir"`
	Transport       Transport       `json:"transport"`
	MinConfidence   string          `json:"min_confidence"`
	Tree            string          `json:"tree,omitempty"`
	StagedFiles     int             `json:"staged_files"`
	TUs             int             `json:"tus"`
	WallMS          int64           `json:"wall_ms"`
	SnapshotMS      int64           `json:"snapshot_ms"`
	OpenMS          int64           `json:"open_ms"`
	IndexMS         int64           `json:"index_ms"`
	QueryMS         int64           `json:"query_ms"`
	FallbackFrom    Transport       `json:"fallback_from,omitempty"`
	MemoizedFailure bool            `json:"memoized_failure,omitempty"`
	ToolCalls       int             `json:"tool_calls"`
	Pages           int             `json:"pages"`
	Nodes           int             `json:"nodes"`
	Edges           int             `json:"edges"`
	Items           int             `json:"items"`
	EngineState     string          `json:"engine_state,omitempty"`
	Error           string          `json:"error,omitempty"`
	SDK             json.RawMessage `json:"sdk,omitempty"`
}

// begin stages buildDir, opens the engine and indexes. It returns a nil session and the
// engine-state reason when no verified engine can run, so the operation declares it.
func (l *Lane) begin(ctx context.Context, op, buildDir string) (*session, string, error) {
	s := &session{l: l, start: time.Now(), stats: opStats{Op: op, BuildDir: buildDir, Transport: l.cfg.Transport, MinConfidence: l.cfg.MinConfidence}}
	if l.unavailable != nil {
		reason := engineReason(l.unavailable)
		if reason == "" {
			reason = reasonEngineUnconfigured
		}
		s.stats.EngineState = reason
		s.finish(l.unavailable)
		return nil, reason, nil
	}
	err := s.attach(ctx, l.cfg, l.cacheKey, buildDir)
	var f *IndexFailure
	if errors.As(err, &f) && l.cfg.Fallback != "" && f.Transport == TransportWasm && (f.Kind == EngineMemoryLimit || f.Kind == EngineTrap) {
		if l.fallbackErr != nil {
			fmt.Fprintf(l.stderr, "cfamilycgx: %s fallback not used: %v\n", l.cfg.Fallback, l.fallbackErr)
		} else {
			fb := l.cfg
			fb.Transport = l.cfg.Fallback
			s.stats.FallbackFrom = l.cfg.Transport
			err = s.attach(ctx, fb, l.fallbackKey, buildDir)
		}
	}
	if reason := engineReason(err); reason != "" {
		s.stats.EngineState = reason
		s.finish(err)
		return nil, reason, nil
	}
	if err != nil {
		s.finish(err)
		return nil, "", err
	}
	return s, "", nil
}

// attach stages buildDir's sources under the cache key's directory, opens cfg's engine on them
// and brings the index up to date. An engine failure while indexing is recorded under the cache
// directory, and a failure already recorded for this tree, engine build and options is returned
// without opening the engine (one that may not recur only within Config.FailureTTL), so a
// failing index is paid for once rather than once per operation.
func (s *session) attach(ctx context.Context, cfg Config, key, buildDir string) error {
	s.stats.Transport = cfg.Transport
	start := time.Now()
	dir := filepath.Join(cfg.CacheDir, key)
	tree, err := s.stage(ctx, dir, buildDir)
	s.stats.SnapshotMS += time.Since(start).Milliseconds()
	s.stats.Tree = tree
	if err != nil {
		return err
	}
	mk := memoKey{Tree: tree, Engine: key, Transport: cfg.Transport, PoolSize: cfg.PoolSize, MemoryLimit: s.l.memoryLimit}
	memo := failureMemoPath(dir, mk)
	if f := readFailureMemo(memo, mk, s.l.now(), cfg.FailureTTL); f != nil {
		s.stats.MemoizedFailure = true
		return f
	}

	start = time.Now()
	g, err := s.l.open(ctx, s.repoPath, cfg)
	s.stats.OpenMS += time.Since(start).Milliseconds()
	if err != nil {
		return fmt.Errorf("cfamilycgx: open cgx graph: %w", err)
	}
	start = time.Now()
	err = g.Index(ctx)
	s.stats.IndexMS += time.Since(start).Milliseconds()
	if err == nil {
		s.g = g
		return nil
	}
	s.stats.SDK = g.Stats()
	_ = g.Close()
	var f *IndexFailure
	var ef *EngineFailure
	switch {
	case engineReason(err) != "":
		return err
	case ctx.Err() != nil:
		f = &IndexFailure{Transport: cfg.Transport, Tree: tree, Kind: EngineContext, Detail: err.Error()}
	case errors.As(err, &ef):
		f = &IndexFailure{Transport: cfg.Transport, Tree: tree, Kind: ef.Kind, Detail: ef.Err.Error()}
	default:
		return fmt.Errorf("cfamilycgx: index: %w", err)
	}
	if werr := writeFailureMemo(memo, failureMemo{Key: mk, RecordedAt: s.l.now().UTC(), Failure: f}); werr != nil {
		fmt.Fprintf(s.l.stderr, "cfamilycgx: record index failure: %v\n", werr)
	}
	return f
}

// stage reads the build context, picks the sources and commits them to the snapshot repository.
func (s *session) stage(ctx context.Context, dir, buildDir string) (string, error) {
	srcs, err := s.l.sources(buildDir)
	if err != nil {
		return "", err
	}
	snap, err := openSnapshot(ctx, dir, buildDir)
	if err != nil {
		return "", err
	}
	cands, err := snap.candidates(ctx)
	if err != nil {
		return "", err
	}
	sel := selectSources(snap.work, srcs.DB, cands)
	tree, err := snap.commit(ctx, sel.files)
	if err != nil {
		return "", err
	}
	s.srcs, s.sel, s.work, s.repoPath = srcs, sel, snap.work, snap.repo
	s.stats.StagedFiles, s.stats.TUs = len(sel.files), len(sel.tus)
	return tree, nil
}

// finish closes the graph and emits the stats record. A stats write failure is reported on
// stderr and never fails the operation.
func (s *session) finish(opErr error) {
	if s.g != nil {
		s.stats.SDK = s.g.Stats()
		if err := s.g.Close(); err != nil && opErr == nil {
			fmt.Fprintf(s.l.stderr, "cfamilycgx: close: %v\n", err)
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
		fmt.Fprintf(s.l.stderr, "cfamilycgx: stats file: %v\n", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		fmt.Fprintf(s.l.stderr, "cfamilycgx: stats file: %v\n", err)
	}
}

// analyze reads the graph and returns the reasons every operation over it declares: the build
// context's, the staging's, cgx's own (a truncated read), translation units cgx found nothing
// in, the residue the graph cannot show, and a raised confidence floor.
func (s *session) analyze(ctx context.Context) (map[string]bool, error) {
	gv, err := s.readGraph(ctx, s.l.cfg.MinConfidence)
	if err != nil {
		return nil, err
	}
	s.gv = gv
	reasons := map[string]bool{}
	for _, r := range s.srcs.Partiality.Reasons {
		reasons[r] = true
	}
	if s.srcs.DB == nil {
		reasons[plugin.PartialReasonNoManifest] = true
	}
	for r := range s.sel.reasons {
		reasons[r] = true
	}
	for r := range gv.reasons {
		reasons[r] = true
	}
	for _, tu := range s.sel.tus {
		if !gv.files[tu] {
			reasons[reasonEmptyTU] = true
			break
		}
	}
	res, unparsed := residue(s.work, s.sel.files, gv)
	for r := range res {
		reasons[r] = true
	}
	s.unparsed = unparsed
	if confidenceRank(s.l.cfg.MinConfidence) > confidenceRank(ConfidencePossible) {
		reasons[reasonConfidenceFloor+s.l.cfg.MinConfidence] = true
	}
	return reasons, nil
}

// ingresses seeds entry points from main and every exported (non-static) function, and every
// method. With no main the program's entry is not in the tree (a library, or a host that loads
// it), declared as no_known_ingress; nothing is invented in its place.
func (s *session) ingresses() ([]plugin.Ingress, map[string]bool) {
	reasons := map[string]bool{}
	cache := map[string][]string{}
	out := []plugin.Ingress{}
	hasMain := false
	for _, fqn := range s.gv.callables() {
		var fns []node
		method := false
		for _, n := range s.gv.nodes[fqn] {
			switch n.Kind {
			case "function":
				fns = append(fns, n)
			case "method":
				method = true
			}
		}
		switch {
		case fqn == "main":
			hasMain = true
			out = append(out, plugin.Ingress{Kind: IngressMain, Symbol: sym(fqn)})
		case method || !static(s.work, fns, cache):
			out = append(out, plugin.Ingress{Kind: IngressExported, Symbol: sym(fqn)})
		}
	}
	if !hasMain {
		reasons[plugin.PartialReasonNoIngress] = true
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Symbol.SCIP < out[j].Symbol.SCIP
	})
	return out, reasons
}

// sym mints the plugin Symbol for a cgx FQN. Every graph-shaped result goes through it, so a
// node's Symbol is byte-identical wherever it appears (plugin.Symbol compares all fields).
func sym(fqn string) plugin.Symbol { return plugin.Symbol{SCIP: fqn, DisplayName: fqn} }

// IndexSymbols lists every function and method, one symbol per FQN.
func (l *Lane) IndexSymbols(ctx context.Context, req plugin.IndexSymbolsRequest) (res plugin.SymbolIndexResult, err error) {
	s, engine, err := l.begin(ctx, plugin.OpIndexSymbols, req.BuildDir)
	if err != nil {
		return res, err
	}
	if engine != "" {
		return plugin.SymbolIndexResult{Partiality: plugin.Partial(engine), Symbols: []plugin.Symbol{}}, nil
	}
	defer func() { s.finish(err) }()
	reasons, err := s.analyze(ctx)
	if err != nil {
		return res, err
	}
	fqns := s.gv.callables()
	res = plugin.SymbolIndexResult{Partiality: partiality(reasons), Symbols: make([]plugin.Symbol, 0, len(fqns))}
	for _, f := range fqns {
		res.Symbols = append(res.Symbols, sym(f))
	}
	s.stats.Items = len(res.Symbols)
	return res, nil
}

// ResolveDependencySymbols resolves each advisory symbol to a function of the tree. A request
// naming no symbol is declared advisory_symbol_absent without running the engine. A name is
// matched exactly, else as the last component of a qualified C++ name (declared). A name with
// no definition in the graph is declared cgx_sink_unresolved (loud): the dependency's own code,
// where it is usually defined, is not in the graph, and a call through a macro alias or a
// function pointer names it nowhere, so its absence is never read as safe.
func (l *Lane) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (res plugin.SymbolResolutionResult, err error) {
	if !cfamilyanalysis.NamesSymbol(req) {
		return cfamilyanalysis.ResolveDependencySymbols(ctx, req)
	}
	s, engine, err := l.begin(ctx, plugin.OpResolveSymbols, req.BuildDir)
	if err != nil {
		return res, err
	}
	if engine != "" {
		return plugin.SymbolResolutionResult{Partiality: plugin.Partial(engine), Resolved: []plugin.Symbol{}}, nil
	}
	defer func() { s.finish(err) }()
	reasons, err := s.analyze(ctx)
	if err != nil {
		return res, err
	}
	var hits []string
	for _, raw := range req.AdvisorySymbols {
		name := strings.TrimSuffix(strings.TrimSpace(raw), "()")
		if name == "" {
			continue
		}
		if s.gv.callable(name) {
			hits = append(hits, name)
			continue
		}
		var suffix []string
		for _, f := range s.gv.callables() {
			if strings.HasSuffix(f, "::"+name) {
				suffix = append(suffix, f)
			}
		}
		if len(suffix) > 0 {
			reasons[reasonSuffixMatch] = true
			hits = append(hits, suffix...)
			continue
		}
		if s.unparsed[shortName(name)] {
			// defined in the tree but lost by the parse: already declared loud by analyze
			continue
		}
		reasons[reasonSinkUnresolved] = true
	}
	hits = sortedUnique(hits)
	res = plugin.SymbolResolutionResult{Partiality: partiality(reasons), Resolved: make([]plugin.Symbol, 0, len(hits))}
	for _, h := range hits {
		res.Resolved = append(res.Resolved, sym(h))
	}
	s.stats.Items = len(res.Resolved)
	return res, nil
}

// CallGraph returns every cgx call edge at or above the confidence floor, between FQNs, with
// the ingresses as roots.
func (l *Lane) CallGraph(ctx context.Context, req plugin.CallGraphRequest) (res plugin.CallGraphResult, err error) {
	algorithm := "cgx(min_confidence=" + l.cfg.MinConfidence + ")"
	s, engine, err := l.begin(ctx, plugin.OpCallGraph, req.BuildDir)
	if err != nil {
		return res, err
	}
	if engine != "" {
		return plugin.CallGraphResult{Partiality: plugin.Partial(engine), Algorithm: algorithm, Edges: []plugin.CallEdge{}, Roots: []plugin.Symbol{}}, nil
	}
	defer func() { s.finish(err) }()
	reasons, err := s.analyze(ctx)
	if err != nil {
		return res, err
	}
	ing, ir := s.ingresses()
	merge(reasons, ir)
	res = plugin.CallGraphResult{
		Partiality: partiality(reasons),
		Algorithm:  algorithm,
		Edges:      make([]plugin.CallEdge, 0, len(s.gv.edges)),
		Roots:      make([]plugin.Symbol, 0, len(ing)),
	}
	for _, e := range s.gv.edges {
		res.Edges = append(res.Edges, plugin.CallEdge{Caller: sym(e[0]), Callee: sym(e[1])})
	}
	var roots []string
	for _, in := range ing {
		roots = append(roots, in.Symbol.SCIP)
	}
	for _, r := range sortedUnique(roots) {
		res.Roots = append(res.Roots, sym(r))
	}
	s.stats.Items = len(res.Edges)
	return res, nil
}

// FindIngresses returns main and the exported functions.
func (l *Lane) FindIngresses(ctx context.Context, req plugin.FindIngressesRequest) (res plugin.IngressResult, err error) {
	s, engine, err := l.begin(ctx, plugin.OpFindIngresses, req.BuildDir)
	if err != nil {
		return res, err
	}
	if engine != "" {
		return plugin.IngressResult{Partiality: plugin.Partial(engine), Ingresses: []plugin.Ingress{}}, nil
	}
	defer func() { s.finish(err) }()
	reasons, err := s.analyze(ctx)
	if err != nil {
		return res, err
	}
	ing, ir := s.ingresses()
	merge(reasons, ir)
	s.stats.Items = len(ing)
	return plugin.IngressResult{Partiality: partiality(reasons), Ingresses: ing}, nil
}

// Reachability finds, for each requested sink, a call path from an ingress to it. With no sinks
// (as the pipeline calls it) it still runs, so its partiality states what the graph misses.
func (l *Lane) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	paths, part, err := l.paths(ctx, plugin.OpReachability, req.BuildDir, req.Symbols)
	return plugin.ReachabilityResult{Partiality: part, Paths: paths}, err
}

// ComputeTaint reports path presence from an ingress to each sink; see taintPrecisionNote.
func (l *Lane) ComputeTaint(ctx context.Context, req plugin.ComputeTaintRequest) (plugin.TaintResult, error) {
	paths, part, err := l.paths(ctx, plugin.OpComputeTaint, req.BuildDir, req.Sinks)
	return plugin.TaintResult{Partiality: part, Paths: paths, PrecisionNote: taintPrecisionNote}, err
}

// paths is Reachability and ComputeTaint: a shortest path from the ingresses to each sink. A
// sink that is not a node is declared; an unreached one is no path, under the partiality every
// result carries (dynamic dispatch and the residue), never a clean refutation.
func (l *Lane) paths(ctx context.Context, op, buildDir string, sinks []string) (paths []plugin.ReachPath, part plugin.Partiality, err error) {
	s, engine, err := l.begin(ctx, op, buildDir)
	if err != nil {
		return nil, part, err
	}
	if engine != "" {
		return []plugin.ReachPath{}, plugin.Partial(engine), nil
	}
	defer func() { s.finish(err) }()
	reasons, err := s.analyze(ctx)
	if err != nil {
		return nil, part, err
	}
	reasons[plugin.PartialReasonDynamicDispatch] = true
	ing, ir := s.ingresses()
	merge(reasons, ir)
	from := make([]string, 0, len(ing))
	for _, in := range ing {
		from = append(from, in.Symbol.SCIP)
	}
	from = sortedUnique(from)

	paths = []plugin.ReachPath{}
	for _, sink := range nonEmpty(sinks) {
		if _, ok := s.gv.nodes[sink]; !ok {
			reasons[reasonSinkUnresolved] = true
			continue
		}
		trace, ok := s.gv.path(from, sink)
		if !ok {
			continue
		}
		p := plugin.ReachPath{Sink: sym(sink), Ingress: sym(trace[0]), Trace: make([]plugin.Symbol, 0, len(trace))}
		for _, t := range trace {
			p.Trace = append(p.Trace, sym(t))
		}
		paths = append(paths, p)
	}
	s.stats.Items = len(paths)
	return paths, partiality(reasons), nil
}

func merge(dst, src map[string]bool) {
	for r := range src {
		dst[r] = true
	}
}

// partiality is Partial with the reasons sorted, never Complete (RFC 0002 §6). With no specific
// reason it declares the standing method limit: cgx reads the tree with tree-sitter and nothing
// runs the preprocessor, so no macro expansion or #if selection is in the graph. The code is
// quiet, so on its own it changes no verdict.
func partiality(reasons map[string]bool) plugin.Partiality {
	if len(reasons) == 0 {
		return plugin.Partial(reasonMacro)
	}
	rs := make([]string, 0, len(reasons))
	for r := range reasons {
		rs = append(rs, r)
	}
	sort.Strings(rs)
	return plugin.Partial(rs...)
}

func nonEmpty(in []string) []string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return sortedUnique(out)
}
