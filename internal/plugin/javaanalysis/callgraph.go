package javaanalysis

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// sym wraps a bare canonical id string into the comparable plugin.Symbol the
// contract now carries on CallEdge.Caller/Callee, Ingress.Symbol, ReachPath's
// Sink/Ingress/Trace, and CallGraphResult.Roots. EVERY site in this package that
// mints one of those fields from a string routes through sym so the id lands in
// SCIP and DisplayName identically. Symbol's == compares ALL fields, so uniform
// construction is what keeps the edge/root/ingress set dedup and the ingress→sink
// SCIP-equality reachability correct; the structured fields are deliberately left
// zero (the matching identity remains the id string, not the 2x2 structure).
func sym(s string) plugin.Symbol { return plugin.Symbol{SCIP: s, DisplayName: s} }

// program is the whole-build parse: every file's package + declarations + call
// sites + ingress markers, plus a method index keyed by (simpleName, arity) used
// to resolve lexical call sites to concrete declared methods.
type program struct {
	files      []fileParse
	readFailed bool
	skipped    bool
	// methodsByKey maps "name/arity" → the SCIP ids of every declared method with
	// that simple name and arity. A single entry resolves unambiguously; multiple
	// (or zero) entries mean the lexical callee cannot be soundly resolved.
	methodsByKey map[string][]string
	// beanData is the Java first-party (source-lexical) bean input: registered beans,
	// injection points by owner-class key, and first-party class locations. Populated
	// alongside the declaration index; consumed by the bean resolver (H2) to retire
	// dynamic_dispatch where an injection point resolves to a unique first-party impl.
	beanData sourceBeanData
}

// fileParse pairs a parsed file with its package (needed to qualify call-site
// callers/callees into SCIP ids).
type fileParse struct {
	pkg       string
	decls     []decl
	calls     []callSite
	ingresses []ingressMarker
}

// methodKey is the (simple name, arity) resolution key for a Java method.
func methodKey(name string, arity int) string {
	return fmt.Sprintf("%s/%d", name, arity)
}

// methodSCIP builds the SCIP id for a method given its package, enclosing type
// chain, name, and arity. It is identical to the id symbolsFromParse emits for the
// same declaration, so a resolved sink, a call-graph node, and an ingress symbol
// all coincide — the equality firstPartyReachPaths relies on.
func methodSCIP(pkg string, enclosing []string, name string, arity int) string {
	return scipSymbol(pkg, enclosing, methodDescriptor(name, arity))
}

// loadProgram parses every .java file under buildDir into a whole-program view and
// builds the method-resolution index. A missing/empty build dir is a hard error
// (inv.4), matching IndexSymbols; read failures and skipped constructs degrade
// partiality.
func loadProgram(buildDir string) (*program, error) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return nil, fmt.Errorf("javaanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("javaanalysis: build dir %q is not a directory", buildDir)
	}
	files, err := javaFiles(buildDir)
	if err != nil {
		return nil, fmt.Errorf("javaanalysis: scan %q: %w", buildDir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("javaanalysis: no .java sources under %q", buildDir)
	}

	prog := &program{methodsByKey: map[string][]string{}}
	var srcClasses []sourceClass
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			prog.readFailed = true
			continue
		}
		src := string(data)
		pr := parseFile(src)
		if pr.skipped {
			prog.skipped = true
		}
		fp := fileParse{pkg: pr.pkg, decls: pr.decls, calls: pr.calls, ingresses: pr.ingresses}
		prog.files = append(prog.files, fp)
		for _, d := range pr.decls {
			if d.kind != kindMethod {
				continue
			}
			scip := methodSCIP(pr.pkg, d.enclosing, d.name, d.arity)
			key := methodKey(d.name, d.arity)
			prog.methodsByKey[key] = append(prog.methodsByKey[key], scip)
		}
		// Bean scan over the same source (cleaned for structure, raw for annotation
		// values). Additive: it reads the same files but produces only the bean input,
		// never touching the declaration/call index above.
		srcClasses = append(srcClasses, scanSourceClasses([]rune(stripJava(src)), []rune(src), pr.pkg)...)
	}
	prog.beanData = buildSourceBeanData(srcClasses)
	return prog, nil
}

// CallGraph builds the source-level call graph for the Java module at
// req.BuildDir. It is a pure-Go, source-only graph: caller and callee are both
// declared methods, and a call site is connected to its callee ONLY when the
// callee's (simple name, arity) resolves to exactly one declared method in the
// program. When a callee is ambiguous (overload across types it cannot
// disambiguate) or unknown (an interface/library method with no source
// declaration), NO edge is fabricated and the result is declared partial with
// reason dynamic_dispatch — the inv.5 honesty boundary: an unresolved callee is
// never rendered as a (wrong) edge or as reachability.
func CallGraph(ctx context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}

	seen := map[plugin.CallEdge]bool{}
	var edges []plugin.CallEdge
	rootsSet := map[string]bool{}
	// unresolvedSet records WHICH call sites had no sound single edge, keyed by
	// (caller SCIP, callee name, callee arity). It replaces a program-wide bool so a
	// later overlay (the bean graph, H2) can retire dynamic_dispatch only for the keys
	// it actually resolved and leave it honest for the rest. Behavior today is
	// unchanged: dynamic_dispatch is raised iff this set is non-empty (⇔ old bool true).
	unresolvedSet := map[unresolvedCall]bool{}

	for _, f := range prog.files {
		for _, cs := range f.calls {
			caller := methodSCIP(f.pkg, cs.callerEnclosing, cs.callerName, cs.callerArity)
			candidates := prog.methodsByKey[methodKey(cs.calleeName, cs.calleeArity)]
			switch len(candidates) {
			case 1:
				e := plugin.CallEdge{Caller: sym(caller), Callee: sym(candidates[0])}
				if !seen[e] {
					seen[e] = true
					edges = append(edges, e)
				}
			default:
				// 0 candidates (library/interface/unknown) or >1 (unresolvable
				// overload): no sound single edge. Record the unresolved call key;
				// never fabricate an edge (inv.5).
				unresolvedSet[unresolvedCall{caller: caller, calleeName: cs.calleeName, calleeArity: cs.calleeArity}] = true
			}
		}
		// Servlet/route ingress methods are call-graph roots (program entry points
		// for static reachability), so the BFS can terminate at them even if no
		// caller within the source program invokes them.
		for _, in := range f.ingresses {
			rootsSet[methodSCIP(f.pkg, in.enclosing, in.name, in.arity)] = true
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})

	rootIDs := make([]string, 0, len(rootsSet))
	for r := range rootsSet {
		rootIDs = append(rootIDs, r)
	}
	sort.Strings(rootIDs)
	roots := make([]plugin.Symbol, 0, len(rootIDs))
	for _, r := range rootIDs {
		roots = append(roots, sym(r))
	}

	lexical := plugin.CallGraphResult{
		Partiality: callGraphPartiality(prog, unresolvedSet),
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      roots,
	}

	// H2 seam (edge-seam.md §5): fold any bean-overlay-resolved interface→impl edges
	// into the pure-Go lexical graph and retire dynamic_dispatch for exactly the call
	// sites the overlay resolved. No overlay supplies bean edges yet, so this is a
	// no-op that changes nothing (byte-identical to today) — the merge the bean-model
	// engineer populates. It runs on the lexical result BEFORE the depgraph/SCIP passes
	// so the Assess path (gate unset) benefits from bean resolution.
	lexical = mergeBeanResolvedEdges(lexical, nil, unresolvedSet, nil)

	// Dependency-inclusive augmentation: append the opened dependency closure's call
	// edges so the persisted graph reflects that dependency bytecode was actually
	// parsed and searched, not just the first-party sources. Their presence is what
	// distinguishes a searched-negative (COMPLETE closure, sink unreached →
	// not_exploitable) from an empty graph the refutation never ran on (→ undetermined,
	// the analysisDidNotRun arm). This is best-effort and additive: a build with no
	// resolvable/cached dependencies contributes nothing and the graph is unchanged,
	// and a dependency-resolution failure is swallowed here — the depreach completeness
	// account (surfaced through reachability partiality) is where an unopened
	// dependency becomes a Gap/hazard, never a fabricated edge (inv.5).
	if dg, derr := buildDependencyGraph(ctx, req.BuildDir); derr == nil {
		if depEdges := dg.callEdges(); len(depEdges) > 0 {
			lexical = appendCallEdges(lexical, depEdges)
		}
	}

	// Prove-path enrichment (gated by TEGRON_JAVA_ANALYZER_IMAGE). The pure-Go
	// lexical graph above is the Assess baseline AND the fallback; only when the
	// analyzer container resolves a semantic graph do we MERGE its type-resolved
	// edges (interface→impl dispatch) on top — the edges lexical declares
	// Partial(dynamic_dispatch) on. On a gated-but-failed run we keep the lexical
	// graph and declare Partial(tool_failure) (never a fabricated edge, inv.5).
	resolved, gated, ok := scipJavaResolve(ctx, req.BuildDir)
	if !gated {
		return lexical, nil
	}
	if !ok {
		return withToolFailure(lexical), nil
	}
	// scip-java/semanticdb erases method parameter types to "()" for non-overloaded
	// methods (e.g. UrlServiceImpl#fetch(String) is emitted as fetch().), so the
	// resolved graph's first-party method nodes are arity-0 while the pure-Go
	// emitter, symbol_mapping sink, and FindIngresses use the true parameter arity
	// (fetch(1).). Relabel the resolved nodes into the true-arity id space using the
	// parsed program before merging, so all four id sources share ONE space and the
	// pipeline's SCIP-equality reachability connects ingress → sink (inv.5: this only
	// renames real resolved nodes to the id the same method already carries; it
	// fabricates no edge).
	resolved = reconcileResolvedArity(prog, resolved)
	return mergeResolvedCallGraph(lexical, resolved), nil
}

// arityReconciliation maps an arity-ERASED first-party canonical SCIP id (the form
// canonicalizeSCIP produces from scip-java's parameter-erased descriptor, e.g.
// "...UrlServiceImpl#fetch().") to the TRUE-arity canonical id the pure-Go emitter
// produces for the same declared method ("...UrlServiceImpl#fetch(1)."). It is
// built from the parsed program (the authoritative source of each declared
// method's parameter count) so the container-resolved graph can be relabelled into
// the pure-Go id space the rest of the pipeline uses.
func arityReconciliation(prog *program) map[string]string {
	m := map[string]string{}
	for _, f := range prog.files {
		for _, d := range f.decls {
			if d.kind != kindMethod || d.arity == 0 {
				continue
			}
			truth := methodSCIP(f.pkg, d.enclosing, d.name, d.arity)
			erased := scipSymbol(f.pkg, d.enclosing, methodDescriptor(d.name, 0))
			// Only a 1:1 erased→truth mapping is sound. If two overloads of the same
			// method name share this enclosing type, their erased forms collide; drop
			// the entry rather than pick a wrong arity (the lexical graph already keeps
			// those overloads distinct, and scip-java would have disambiguated them).
			if existing, ok := m[erased]; ok && existing != truth {
				m[erased] = "" // poisoned: ambiguous erasure
				continue
			}
			if _, poisoned := m[erased]; !poisoned {
				m[erased] = truth
			}
		}
	}
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	return m
}

// reconcileResolvedArity relabels every first-party method node in the resolved
// graph (edges, roots, ingresses) from scip-java's arity-erased id to the pure-Go
// emitter's true-arity id, using the map built from the parsed program. Library
// nodes (java/..., com/sun/...) and any id absent from the map are left unchanged —
// the lexical graph and the advisory sink never reference them, so they cannot
// affect ingress→sink reachability.
func reconcileResolvedArity(prog *program, g scipGraph) scipGraph {
	remap := arityReconciliation(prog)
	if len(remap) == 0 {
		return g
	}
	fix := func(id string) string {
		if t, ok := remap[id]; ok {
			return t
		}
		return id
	}
	// fix operates on the canonical id STRING; the now-Symbol edge/ingress fields
	// carry that string in .SCIP, so read it in and re-wrap via sym to keep the
	// transformation (and Symbol construction) identical. g.roots stays []string.
	for i := range g.edges {
		g.edges[i].Caller = sym(fix(g.edges[i].Caller.SCIP))
		g.edges[i].Callee = sym(fix(g.edges[i].Callee.SCIP))
	}
	for i := range g.roots {
		g.roots[i] = fix(g.roots[i])
	}
	for i := range g.ingresses {
		g.ingresses[i].Symbol = sym(fix(g.ingresses[i].Symbol.SCIP))
	}
	return g
}

// appendCallEdges returns g with extra edges merged into its edge set — deduped
// against the existing edges and re-sorted for a stable payload. Partiality and
// roots are untouched: the added edges are extra reachability structure, not a
// change to what the graph declares it could not resolve.
func appendCallEdges(g plugin.CallGraphResult, extra []plugin.CallEdge) plugin.CallGraphResult {
	seen := make(map[plugin.CallEdge]bool, len(g.Edges)+len(extra))
	merged := make([]plugin.CallEdge, 0, len(g.Edges)+len(extra))
	for _, e := range g.Edges {
		if !seen[e] {
			seen[e] = true
			merged = append(merged, e)
		}
	}
	for _, e := range extra {
		if !seen[e] {
			seen[e] = true
			merged = append(merged, e)
		}
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Caller.SCIP != merged[j].Caller.SCIP {
			return merged[i].Caller.SCIP < merged[j].Caller.SCIP
		}
		return merged[i].Callee.SCIP < merged[j].Callee.SCIP
	})
	g.Edges = merged
	return g
}

// mergeResolvedCallGraph folds the container-resolved semantic graph into the
// lexical baseline: it unions edges and roots (the resolved interface→impl edges
// are the new reachability the pure-Go pass could not produce) and re-declares
// the algorithm/partiality to reflect the semantic resolution. The resolved graph
// shares the plugin's canonical SCIP id space (scipindex.canonicalizeSCIP), so its
// edges are id-equal to the lexical nodes and the resolved advisory sink —
// firstPartyReachPaths consumes the union unchanged.
func mergeResolvedCallGraph(lexical plugin.CallGraphResult, resolved scipGraph) plugin.CallGraphResult {
	seen := map[plugin.CallEdge]bool{}
	merged := make([]plugin.CallEdge, 0, len(lexical.Edges)+len(resolved.edges))
	for _, e := range lexical.Edges {
		if !seen[e] {
			seen[e] = true
			merged = append(merged, e)
		}
	}
	for _, e := range resolved.edges {
		if !seen[e] {
			seen[e] = true
			merged = append(merged, e)
		}
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Caller.SCIP != merged[j].Caller.SCIP {
			return merged[i].Caller.SCIP < merged[j].Caller.SCIP
		}
		return merged[i].Callee.SCIP < merged[j].Callee.SCIP
	})

	rootSet := map[string]bool{}
	for _, r := range lexical.Roots {
		rootSet[r.SCIP] = true
	}
	for _, r := range resolved.roots {
		rootSet[r] = true
	}
	rootIDs := make([]string, 0, len(rootSet))
	for r := range rootSet {
		rootIDs = append(rootIDs, r)
	}
	sort.Strings(rootIDs)
	roots := make([]plugin.Symbol, 0, len(rootIDs))
	for _, r := range rootIDs {
		roots = append(roots, sym(r))
	}

	// The semantic pass resolved the dynamic-dispatch hop; carry only the residual
	// partiality reasons (read/skip failures), dropping dynamic_dispatch.
	var residual []string
	for _, r := range lexical.Partiality.Reasons {
		if r != plugin.PartialReasonDynamicDispatch {
			residual = append(residual, r)
		}
	}
	part := plugin.Complete()
	if len(residual) > 0 {
		part = plugin.Partial(residual...)
	}

	return plugin.CallGraphResult{
		Partiality: part,
		Algorithm:  "scip-java-semanticdb",
		Edges:      merged,
		Roots:      roots,
	}
}

// mergeBeanResolvedEdges folds a bean-overlay's resolved interface→impl edges into
// the lexical graph and retires dynamic_dispatch for exactly the call sites the
// overlay resolved (edge-seam.md §5, H2). It is modeled on mergeResolvedCallGraph but
// runs on the PURE-GO lexical result (so the un-gated Assess path benefits), and it
// retires per-key rather than wholesale: dynamic_dispatch is dropped only when the
// residual unresolved-key set — the graph's unresolved calls minus the keys the
// overlay resolved (resolvedKeys) — is empty. Any residual keeps dynamic_dispatch
// honest. inv.5: it unions real resolved edges and never fabricates one; roots are
// unchanged (bean edges add reachability, not entry points).
//
// With no overlay data (beanEdges and resolvedKeys both empty) it is a strict no-op:
// the lexical result is returned unchanged, so today's behavior is byte-identical.
func mergeBeanResolvedEdges(lexical plugin.CallGraphResult, beanEdges []plugin.CallEdge, unresolved, resolvedKeys map[unresolvedCall]bool) plugin.CallGraphResult {
	if len(beanEdges) == 0 && len(resolvedKeys) == 0 {
		return lexical
	}

	merged := appendCallEdges(lexical, beanEdges)

	// Residual = unresolved call keys the overlay did NOT resolve. dynamic_dispatch is
	// retired iff none remain; every other reason (read/skip failure) is preserved.
	residual := 0
	for k := range unresolved {
		if !resolvedKeys[k] {
			residual++
		}
	}
	var reasons []string
	for _, r := range lexical.Partiality.Reasons {
		if r == plugin.PartialReasonDynamicDispatch && residual == 0 {
			continue
		}
		reasons = append(reasons, r)
	}
	if len(reasons) == 0 {
		merged.Partiality = plugin.Complete()
	} else {
		merged.Partiality = plugin.Partial(reasons...)
	}
	return merged
}

// withToolFailure marks a result Partial(tool_failure) (preserving any existing
// reasons) when the gated analyzer container was attempted but failed. The
// underlying lexical edges are retained — the graph degrades, it never breaks
// (inv.4), and no edge is fabricated.
func withToolFailure(r plugin.CallGraphResult) plugin.CallGraphResult {
	reasons := append([]string{}, r.Partiality.Reasons...)
	has := false
	for _, x := range reasons {
		if x == plugin.PartialReasonToolFailure {
			has = true
		}
	}
	if !has {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	r.Partiality = plugin.Partial(reasons...)
	return r
}

// unresolvedCall identifies one lexical call site the graph could not resolve to a
// single declared method: the caller's SCIP id plus the callee's simple name and
// arity. It is the key an overlay edge-source (the bean graph, H2) matches against to
// retire dynamic_dispatch only for the sites it actually resolved.
type unresolvedCall struct {
	caller      string
	calleeName  string
	calleeArity int
}

// callGraphPartiality declares the call graph's completeness. ANY unresolved
// callee, read failure, or skipped construct makes the graph declared-partial:
// the source-lexical graph never type-resolves interface dispatch or library
// calls, so partiality is the honest norm for non-trivial Java. dynamic_dispatch is
// raised iff the unresolved-call-key set is non-empty (identical to the former
// program-wide bool).
func callGraphPartiality(prog *program, unresolved map[unresolvedCall]bool) plugin.Partiality {
	var reasons []string
	if len(unresolved) > 0 {
		reasons = append(reasons, plugin.PartialReasonDynamicDispatch)
	}
	if prog.readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}
