package jsanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// program is the whole-build parse: every file's module + declarations + call sites
// + ingress markers, plus the per-module resolution index the import-scoped resolver
// (resolve.go) reads to connect a lexical call/reference to a concrete declaration.
type program struct {
	files      []fileParse
	readFailed bool
	// unreadSource records a source file that could not be read: its call sites are in no
	// list, unlike a resolver read failure, which only weakens the sites it resolves.
	unreadSource bool
	skipped      bool
	root         string // build dir (for reading package.json / tsconfig.json; never node_modules source)
	// modules indexes every in-tree module by its path-based id: its bindings, its
	// module-level functions, and its class methods. It replaces the former global
	// (name,arity) funcsByKey / funcsByName maps — resolution is now import-scoped.
	modules map[string]*moduleIndex
	// moduleSet is the set of in-tree module ids, used for extension/index resolution
	// of a relative specifier.
	moduleSet map[string]bool
	// sources maps a module id to the source files that yield it (one per extension), so
	// a walk that depends on where the file really lives can resolve the file itself.
	sources map[string][]string
	// buildCtx caches the PLAN-163 build context (bundler alias/define map with
	// provenance) the resolver injection point exposes; nil until the first resolver()
	// call computes it once. It reads the static bundler configs and executes nothing (C4).
	buildCtx *buildContext
	// styleTooling caches whether the tree holds a bundler or transform config that can change
	// what a stylesheet import loads; nil until first use.
	styleTooling *bool
	// deps is the dependency code read into the program (depgraph.go); nil when none is.
	deps *depGraph
	// dirMains caches the first-party package.json "main" lookups of directory resolution
	// (resolver.dirMain).
	dirMains map[string]dirMainEntry
}

// moduleIndex is one module's resolution surface: the names it binds (imports), the
// functions and class methods it declares, and the classes it declares.
type moduleIndex struct {
	module   string
	bindings moduleBindings
	funcs    map[string][]funcDecl            // module-level functions (enclosing empty) by name
	methods  map[string]map[string][]funcDecl // class name → method name → declarations
	classes  map[string]bool                  // declared class names
}

// funcDecl is one declared function located by its module + enclosing class chain +
// name + arity (enough to build its SCIP id).
type funcDecl struct {
	module    string
	enclosing []string
	name      string
	arity     int
}

func (d funcDecl) scip() string {
	return scipSymbol(d.module, d.enclosing, functionDescriptor(d.name, d.arity))
}

// fileParse pairs a parsed file with its module and the per-module bindings used by the
// resolver (needed to qualify call-site callers/callees and ingress handlers, and to
// resolve import-scoped calls).
type fileParse struct {
	module    string
	escapes   fileEscapes
	decls     []decl
	calls     []callSite
	ingresses []ingressMarker
	bindings  moduleBindings
}

// funcSCIP builds the SCIP id for a function given its module, enclosing class
// chain, name, and arity. It is identical to the id symbolsFromParse emits for the
// same declaration, so a resolved sink, a call-graph node, and an ingress symbol all
// coincide — the equality firstPartyReachPaths relies on.
func funcSCIP(module string, enclosing []string, name string, arity int) string {
	return scipSymbol(module, enclosing, functionDescriptor(name, arity))
}

// sym mints a plugin.Symbol from a SCIP id — the single string→Symbol construction
// point for the call graph / reachability / taint world. Every graph symbol (edge
// endpoint, root, ingress, sink, trace frame) is minted here so two references to the
// same SCIP id are byte-identical: that is the ==, map-key, and set identity the BFS
// and adjacency maps rely on, and an inconsistently-built Symbol silently breaks those
// lookups. DisplayName mirrors the SCIP id; the richer structured Symbol fields are
// deliberately left zero here — display/matching identity is owned by the
// index/resolver path (symbolsFromParse, jsSymbolForms), not the graph.
func sym(scip string) plugin.Symbol {
	return plugin.Symbol{SCIP: scip, DisplayName: scip}
}

// loadProgram parses every JS/TS file under buildDir into a whole-program view and
// builds the per-module resolution index. A missing/empty build dir is a hard error
// (inv.4), matching IndexSymbols; read failures and skipped constructs degrade partiality.
func loadProgram(buildDir string) (*program, error) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return nil, fmt.Errorf("jsanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("jsanalysis: build dir %q is not a directory", buildDir)
	}
	files, err := jsFiles(buildDir)
	if err != nil {
		return nil, fmt.Errorf("jsanalysis: scan %q: %w", buildDir, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("jsanalysis: no .js/.ts/.jsx/.tsx/.vue sources under %q", buildDir)
	}

	prog := &program{
		root:      buildDir,
		modules:   map[string]*moduleIndex{},
		moduleSet: map[string]bool{},
		sources:   map[string][]string{},
	}
	for _, f := range files {
		data, err := readRegular(f)
		if err != nil {
			prog.readFailed = true
			prog.unreadSource = true
			continue
		}
		module := moduleOf(buildDir, f)
		prog.sources[module] = append(prog.sources[module], f)
		var pr parseResult
		if filepath.Ext(f) == vueExtension {
			pr = parseVueSFC(module, string(data))
		} else {
			pr = parseFile(module, string(data))
		}
		if pr.skipped {
			prog.skipped = true
		}
		fp := fileParse{module: pr.module, escapes: pr.escapes, decls: pr.decls, calls: pr.calls, ingresses: pr.ingresses, bindings: pr.bindings}
		prog.files = append(prog.files, fp)
		prog.moduleSet[pr.module] = true
		prog.indexModule(fp)
	}
	return prog, nil
}

// indexModule folds one parsed file into its module's resolution index: module-level
// functions by name, class methods by class+name, declared classes, and the module's
// bindings.
func (prog *program) indexModule(fp fileParse) {
	mi := prog.modules[fp.module]
	if mi == nil {
		mi = &moduleIndex{
			module:  fp.module,
			funcs:   map[string][]funcDecl{},
			methods: map[string]map[string][]funcDecl{},
			classes: map[string]bool{},
		}
		prog.modules[fp.module] = mi
	}
	mi.bindings = fp.bindings
	for _, d := range fp.decls {
		switch d.kind {
		case kindClass:
			mi.classes[d.name] = true
		case kindFunc:
			fd := funcDecl{module: fp.module, enclosing: d.enclosing, name: d.name, arity: d.arity}
			if len(d.enclosing) == 0 {
				mi.funcs[d.name] = append(mi.funcs[d.name], fd)
			} else {
				class := d.enclosing[len(d.enclosing)-1]
				if mi.methods[class] == nil {
					mi.methods[class] = map[string][]funcDecl{}
				}
				mi.methods[class][d.name] = append(mi.methods[class][d.name], fd)
			}
		}
	}
}

// resolveIngressSymbol resolves an ingress marker to the SCIP id of the handler
// function it names, via the import-scoped resolver's name-only (ResolveRef) mode: a
// binding lookup in the referencing module subsumes the former "exactly one declared
// function program-wide" gate, and the handlerRefArity sentinel is retired. An
// unresolved/ambiguous handler yields "" (no ingress symbol — honest absence, never a
// fabricated node). An inline handler frame is minted by the scanner, so its id is
// built directly rather than resolved.
func (p *program) resolveIngressSymbol(module string, in ingressMarker) string {
	if in.frame {
		return funcSCIP(module, in.enclosing, in.name, in.arity)
	}
	target, _ := p.resolver().ResolveRef(module, in.name).edge()
	return target
}

// CallGraph builds the source-level import-scoped call graph for the JS/TS module at
// req.BuildDir. It is a pure-Go, source-only graph: a call site is connected to its
// callee ONLY when the importing module's bindings + the CJS/ESM/exports/imports/paths
// algorithm (resolve.go) resolve it to a UNIQUE in-tree declaration. A callee that
// resolves to a dependency (node_modules, never opened), a runtime-computed specifier,
// an ambiguous/unknown name, or a >1 declaration match yields NO edge and a declared
// partiality reason — the inv.5 honesty boundary: an unresolved callee is never rendered
// as a (wrong) edge or as reachability. Each such site is listed in Unresolved, and every
// frame a hidden call could land on in Escaped (buildGraph).
//
// With req.DependencyCache set, the lock-pinned dependency code that store holds is read
// into the graph as well (depgraph.go).
func CallGraph(ctx context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return callGraphFor(ctx, req.BuildDir, req.DependencyCache)
}

// builtGraph is one call-graph build plus the bookkeeping its completeness contract is
// tested against: declined counts every call or load the build declined to connect, each
// counted where its reason is accumulated, apart from the Unresolved entry built for it;
// unlisted records a declined site no entry can list (PartialReasonUnlistedSites).
type builtGraph struct {
	res      plugin.CallGraphResult
	prov     map[plugin.CallEdge]provenance
	declined int
	unlisted bool
}

// graphBuilt, when non-nil, sees every build. Only tests set it, to hold the completeness
// contract on every program the package's tests build.
var graphBuilt func(buildDir string, b builtGraph)

// partialFlags accumulates the call graph's declared limits across all files.
type partialFlags struct {
	unresolved    bool // an ambiguous/unknown callee (dynamic_dispatch)
	uninspectable bool // a bare specifier into a package this cycle cannot open (uninspectable_package)
	dynImport     bool // a runtime-computed ESM target import(expr) (dynamic_import_specifier)
	computedReq   bool // a runtime-computed CJS target require(var) (computed_require_specifier)
	unreadModule  bool // a relative specifier naming no in-tree source module, or process.dlopen (unresolved_module)
	evaluated     bool // eval or the Function constructor (evaluated_code)
	stylesheet    bool // a stylesheet import whose only code is the loader runtime (scoped uninspectable_package)
	unlisted      bool // a declined site Unresolved cannot list (unlisted_sites)
	toolFailure   bool // dependency code the read budget cut off with no package to attribute it to (tool_failure)
	unsupported   bool // a skipped construct in dependency code (unsupported_phase1)
	scoped        []plugin.ScopedReason
}

// callGraphInternal builds the graph and returns it alongside the per-edge provenance
// side table (§2). The wire plugin.CallEdge stays frozen — provenance lives here, in a
// jsanalysis-internal map parallel to the edge set, and C5 asserts against it via a
// package-internal test hook rather than the serialized edge.
func callGraphInternal(buildDir string) (plugin.CallGraphResult, map[plugin.CallEdge]provenance, error) {
	b, err := buildCallGraph(buildDir)
	if err != nil {
		return plugin.CallGraphResult{}, nil, err
	}
	b.report(buildDir)
	return b.res, b.prov, nil
}

// buildCallGraph is callGraphInternal's body: the first-party graph over buildDir.
func buildCallGraph(buildDir string) (builtGraph, error) {
	prog, err := loadProgram(buildDir)
	if err != nil {
		return builtGraph{}, err
	}
	g := buildGraph(prog)
	return g.built(g.result(callGraphPartiality(prog, g.flags)), g.flags.unlisted), nil
}

// graphBuild accumulates a call graph's edges, their provenance, its roots, its limits, and
// the sites it declined.
//
// Every call or load the build declines is listed in unresolved (plugin.UnresolvedCall), and
// declined counts it where its reason is accumulated. A declined site no entry can list sets
// flags.unlisted, which declares PartialReasonUnlistedSites. escaped is every escape root plus
// every module's top-level frame.
type graphBuild struct {
	seen       map[plugin.CallEdge]bool
	edges      []plugin.CallEdge
	prov       map[plugin.CallEdge]provenance
	roots      map[string]bool
	escaped    map[string]bool
	unresolved []plugin.UnresolvedCall
	declined   int
	flags      partialFlags
	// A computed read accepted for its literal receiver holds only while no module of the
	// build may set a prototype the lane does not see.
	anyExempt, anyProto bool
	// pkgLoads and pkgCalls are the first-party sites declined only because a bare specifier
	// names a package the build has not read; dependency code read afterwards may cover them
	// (coverReadPackages). entered marks a call into a package-boundary node outside pkgCalls,
	// whose uninspectable limit nothing retracts.
	pkgLoads []pkgSite
	pkgCalls []pkgSite
	entered  bool
	// depUnbounded marks a load or call in read dependency code for which some resolver may run
	// code the graph has no edge to; coverReadPackages then retracts nothing.
	depUnbounded bool
}

// pkgSite is a first-party site declined on a bare specifier: the unresolved entry at index at,
// for a load of spec, or for the call cs.
type pkgSite struct {
	at         int
	module     string
	spec       string
	viaRequire bool
	cs         callSite
	entered    bool
}

func newGraphBuild() *graphBuild {
	return &graphBuild{seen: map[plugin.CallEdge]bool{}, prov: map[plugin.CallEdge]provenance{}, roots: map[string]bool{}, escaped: map[string]bool{}}
}

func (g *graphBuild) add(e plugin.CallEdge, prov provenance) {
	if !g.seen[e] {
		g.seen[e] = true
		g.edges = append(g.edges, e)
		g.prov[e] = prov
	}
}

// decline accumulates one declined site's reason, counts the site and lists it.
func (g *graphBuild) decline(u plugin.UnresolvedCall) {
	g.declined++
	accumulateReason(&g.flags, u.Reason)
	g.unresolved = append(g.unresolved, u)
}

// built pairs res, rendered from g under flags whose unlisted is unlisted, with g's bookkeeping.
func (g *graphBuild) built(res plugin.CallGraphResult, unlisted bool) builtGraph {
	return builtGraph{res: res, prov: g.prov, declined: g.declined, unlisted: unlisted}
}

// report hands b to the graphBuilt test hook.
func (b builtGraph) report(buildDir string) {
	if graphBuilt != nil {
		graphBuilt(buildDir, b)
	}
}

// result renders the build as a sorted, deterministic CallGraphResult.
func (g *graphBuild) result(part plugin.Partiality) plugin.CallGraphResult {
	edges := append([]plugin.CallEdge(nil), g.edges...)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})
	unresolved := append([]plugin.UnresolvedCall(nil), g.unresolved...)
	sortUnresolved(unresolved)
	return plugin.CallGraphResult{
		Partiality: part,
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      sortedSymbols(g.roots),
		Unresolved: unresolved,
		Escaped:    sortedSymbols(g.escaped),
	}
}

// sortedSymbols renders a set of SCIP ids as symbols in id order.
func sortedSymbols(set map[string]bool) []plugin.Symbol {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]plugin.Symbol, 0, len(ids))
	for _, id := range ids {
		out = append(out, sym(id))
	}
	return out
}

// buildGraph builds the first-party call graph over prog.
func buildGraph(prog *program) *graphBuild {
	rs := prog.resolver()
	br := newBoundaryResolver(prog, rs)
	g := newGraphBuild()
	flags := &g.flags
	flags.unlisted = prog.unreadSource || prog.skipped

	for _, f := range prog.files {
		moduleInit := sym(moduleInitSCIP(f.module))
		// load lists a load the scan records per module, not per call, on the module's
		// top-level frame.
		load := func(loader, reason string) {
			g.decline(plugin.UnresolvedCall{Caller: moduleInit, Callee: loader, Arity: 1, Reason: reason})
		}
		// Module-level runtime-computed specifiers (import(expr) / require(var)) with no
		// static prefix are declared limits even though they emit no call site (§6).
		if f.bindings.dynImport {
			load("import", plugin.PartialReasonDynamicImportSpecifier)
		}
		if f.bindings.computedReq {
			load("require", plugin.PartialReasonComputedRequireSpecifier)
		}
		if f.bindings.nativeLoad {
			load("dlopen", plugin.PartialReasonUnresolvedModule)
		}
		if f.bindings.evaluated {
			// The evaluated code's own calls and loads are never read, so no entry lists them.
			load("eval", plugin.PartialReasonEvaluatedCode)
			flags.unlisted = true
		}
		g.anyExempt = g.anyExempt || f.bindings.literalExempt
		g.anyProto = g.anyProto || f.bindings.protoWrite
		// A module that loads an out-of-tree package runs that package's code, whatever it
		// later does with the binding, so the run executed code this lane did not open.
		for _, ls := range f.bindings.specifiers {
			loader := "import"
			if ls.viaRequire {
				loader = "require"
			}
			if rs.loadsOutOfTree(f.module, ls.spec, ls.viaRequire) {
				g.pkgLoads = append(g.pkgLoads, pkgSite{at: len(g.unresolved), module: f.module, spec: ls.spec, viaRequire: ls.viaRequire})
				load(loader, plugin.PartialReasonUninspectablePackage)
			}
			switch {
			case rs.stylesheetImport(f.module, ls.spec):
				// A scoped limit, not a site: it carries its own package Targets.
				flags.stylesheet = true
			case rs.loadsUnreadModule(f.module, ls.spec):
				load(loader, plugin.PartialReasonUnresolvedModule)
			}
			// A literal import() whose resolution meets any condition outside Node's defaults
			// keeps the limit a computed import() declares (loadMeetsUnmodeledCondition).
			if ls.dynImport && rs.loadMeetsUnmodeledCondition(f.module, ls.spec) {
				load(loader, plugin.PartialReasonDynamicImportSpecifier)
			}
		}
		// A static-prefix load whose files are all in-tree modules gets an edge to each.
		// Its suffix may still traverse out of the prefix (prefixSuffixMayTraverse), so the
		// computed limit stays run-wide beside the edges.
		for _, pl := range f.bindings.prefixLoads {
			reason, algo := plugin.PartialReasonComputedRequireSpecifier, algoCJS
			if pl.dyn {
				reason, algo = plugin.PartialReasonDynamicImportSpecifier, algoESM
			}
			kind, mods := rs.classifyPrefixLoad(f.module, pl)
			caller := sym(funcSCIP(f.module, pl.caller.enclosing, pl.caller.name, pl.caller.arity))
			if kind == prefixFirstParty {
				for _, m := range mods {
					g.add(plugin.CallEdge{Caller: caller, Callee: sym(moduleInitSCIP(m))}, provenance{Algo: algo})
				}
				if !prefixSuffixMayTraverse {
					continue
				}
			}
			// The suffix may leave the prefix, so the load stays unbounded beside its edges.
			loader := "require"
			if pl.dyn {
				loader = "import"
			}
			g.decline(plugin.UnresolvedCall{Caller: caller, Callee: loader, Arity: 1, Reason: reason})
		}
		// Module code runs when the module is loaded, and any first-party module may be
		// loaded, so every module's top-level frame is a root, and escaped: a load the lane
		// cannot see may run it.
		g.roots[moduleInitSCIP(f.module)] = true
		g.escaped[moduleInitSCIP(f.module)] = true
		// Every function opaque code could call back is a root (escape.go), and escaped.
		for _, d := range f.decls {
			if f.escapes.root(d) {
				id := funcSCIP(f.module, d.enclosing, d.name, d.arity)
				g.roots[id] = true
				g.escaped[id] = true
			}
		}
		for _, cs := range f.calls {
			caller := sym(funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity))
			if cs.calleeFrame {
				// The frame that registers an inline handler reaches it: the scanner minted
				// both ends in this file, so there is nothing to resolve.
				g.add(plugin.CallEdge{Caller: caller, Callee: sym(funcSCIP(f.module, cs.calleeEnclosing, cs.calleeName, cs.calleeArity))}, provenance{Algo: algoLocal})
				continue
			}
			if cs.opaque {
				// A callee the lane does not track may be any value, so any escaped frame.
				g.decline(plugin.UnresolvedCall{Caller: caller, Callee: cs.written, Arity: cs.calleeArity, Reason: plugin.PartialReasonDynamicDispatch})
				continue
			}
			r := rs.resolveCallSite(f.module, cs)
			// An unconnected call (an optional call, a parameter default, a heritage clause) is
			// listed, never connected: the edges stay those of the plain calls, and its target is
			// the bound of its entry instead.
			if target, ok := r.edge(); ok && !cs.unconnected {
				g.add(plugin.CallEdge{Caller: caller, Callee: sym(target)}, r.Prov)
				continue
			}
			target, prov, enters := br.callee(f.module, cs)
			if enters {
				// An edge into a package-boundary node names the dependency member the call
				// enters; it is not an inspection of the package, which stays uninspectable.
				if !cs.unconnected {
					g.add(plugin.CallEdge{Caller: caller, Callee: sym(target)}, prov)
				}
				flags.uninspectable = true
			}
			reason := plugin.PartialReasonUninspectablePackage
			if r.Kind != resolvePackage { // resolveUnresolved (or a first-party module with no unique symbol)
				reason = contributedReason(r.Reason)
				g.entered = g.entered || enters
			} else {
				g.pkgCalls = append(g.pkgCalls, pkgSite{at: len(g.unresolved), module: f.module, cs: cs, entered: enters})
			}
			// A package can call back any function value handed to it, so a call that enters a
			// package is never bounded; a declined name lists what it can denote (pickFunc), when
			// the name provably denotes what the resolver read (boundable).
			var targets []plugin.Symbol
			if r.Kind != resolvePackage && !enters && boundable(cs) {
				if t, ok := r.edge(); ok {
					targets = append(targets, sym(t))
				}
				for _, c := range r.Candidates {
					targets = append(targets, sym(c))
				}
			}
			g.decline(plugin.UnresolvedCall{Caller: caller, Callee: calleeAsWritten(cs), Arity: cs.calleeArity, Reason: reason, Targets: targets})
		}
		// Framework ingress handler functions are call-graph roots. An ingress whose
		// handler reference does not resolve to a single declared function contributes
		// no root.
		for _, in := range f.ingresses {
			if symID := prog.resolveIngressSymbol(f.module, in); symID != "" {
				g.roots[symID] = true
			}
		}
	}

	if g.anyExempt && g.anyProto {
		// A run-wide judgment, not a site: no entry can list what it hides.
		flags.evaluated = true
		flags.unlisted = true
	}
	return g
}

// boundable reports whether a declined call's candidates bound it: the callee is a bare name
// or a method of a plain receiver (recv.m), read where no other binding of that name can be in
// force (shadow.go). A this-call may run a subclass override the resolver does not read; the
// leaf of a longer chain (a.b.m), or of a chain read off another value (f().m, a?.m), is a
// property of a value the resolver does not track, though it reads the leaf as a bare name.
func boundable(cs callSite) bool {
	if cs.receiverThis || cs.rebound || cs.chain == nil {
		return false
	}
	return len(cs.chain) == 1 || len(cs.chain) == 2 && cs.receiver != ""
}

// calleeAsWritten renders a call site's callee as the source names it: its dotted chain
// ("head.name", "this.name", "a.b.name"), or the bare name.
func calleeAsWritten(cs callSite) string {
	if len(cs.chain) > 0 {
		return strings.Join(cs.chain, ".")
	}
	if cs.head != "" && cs.head != cs.calleeName {
		return cs.head + "." + cs.calleeName
	}
	return cs.calleeName
}

// sortUnresolved orders entries by caller, callee, arity and reason, so a build's output is
// deterministic.
func sortUnresolved(us []plugin.UnresolvedCall) {
	sort.SliceStable(us, func(i, j int) bool {
		a, b := us[i], us[j]
		switch {
		case a.Caller.SCIP != b.Caller.SCIP:
			return a.Caller.SCIP < b.Caller.SCIP
		case a.Callee != b.Callee:
			return a.Callee < b.Callee
		case a.Arity != b.Arity:
			return a.Arity < b.Arity
		}
		return a.Reason < b.Reason
	})
}

// contributedReason is the reason code a declined call's resolver reason contributes to the
// graph: the module-resolution codes keep their own, every other decline is dynamic_dispatch.
func contributedReason(reason string) string {
	switch reason {
	case plugin.PartialReasonUninspectablePackage, plugin.PartialReasonDynamicImportSpecifier,
		plugin.PartialReasonComputedRequireSpecifier, plugin.PartialReasonUnresolvedModule,
		plugin.PartialReasonEvaluatedCode:
		return reason
	}
	return plugin.PartialReasonDynamicDispatch
}

// accumulateReason maps a declined site's reason code onto the graph's partial flags.
func accumulateReason(flags *partialFlags, reason string) {
	switch contributedReason(reason) {
	case plugin.PartialReasonUninspectablePackage:
		flags.uninspectable = true
	case plugin.PartialReasonDynamicImportSpecifier:
		flags.dynImport = true
	case plugin.PartialReasonComputedRequireSpecifier:
		flags.computedReq = true
	case plugin.PartialReasonUnresolvedModule:
		flags.unreadModule = true
	case plugin.PartialReasonEvaluatedCode:
		flags.evaluated = true
	default:
		flags.unresolved = true
	}
}

// callGraphPartiality declares the call graph's completeness. ANY unresolved callee,
// read failure, skipped construct, uninspectable bare specifier, or runtime-computed
// specifier makes the graph declared-partial: the source-lexical graph never resolves
// prototype/dynamic dispatch, dependency source, or runtime-computed loads, so partiality
// is the honest norm for non-trivial JS/TS. The three module-resolution codes (PLAN-162
// C5) split the former blanket dynamic_dispatch into reviewer-legible conditions.
func callGraphPartiality(prog *program, flags partialFlags) plugin.Partiality {
	var reasons []string
	if flags.unresolved {
		reasons = append(reasons, plugin.PartialReasonDynamicDispatch)
	}
	if prog.readFailed || flags.toolFailure {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped || flags.unsupported {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if flags.uninspectable {
		reasons = append(reasons, plugin.PartialReasonUninspectablePackage)
	}
	if flags.dynImport {
		reasons = append(reasons, plugin.PartialReasonDynamicImportSpecifier)
	}
	if flags.computedReq {
		reasons = append(reasons, plugin.PartialReasonComputedRequireSpecifier)
	}
	if flags.unreadModule {
		reasons = append(reasons, plugin.PartialReasonUnresolvedModule)
	}
	if flags.evaluated {
		reasons = append(reasons, plugin.PartialReasonEvaluatedCode)
	}
	if flags.unlisted {
		reasons = append(reasons, plugin.PartialReasonUnlistedSites)
	}
	var scoped []plugin.ScopedReason
	if flags.stylesheet {
		scoped = append(scoped, stylesheetRuntime())
	}
	scoped = append(scoped, flags.scoped...)
	if len(reasons) == 0 && len(scoped) == 0 {
		return plugin.Complete()
	}
	part := plugin.Partial(reasons...)
	part.Scoped = scoped
	return part
}
