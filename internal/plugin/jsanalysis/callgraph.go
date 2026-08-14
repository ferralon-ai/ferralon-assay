package jsanalysis

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// program is the whole-build parse: every file's module + declarations + call sites
// + ingress markers, plus the per-module resolution index the import-scoped resolver
// (resolve.go) reads to connect a lexical call/reference to a concrete declaration.
type program struct {
	files      []fileParse
	readFailed bool
	skipped    bool
	root       string // build dir (for reading package.json / tsconfig.json; never node_modules)
	// modules indexes every in-tree module by its path-based id: its bindings, its
	// module-level functions, and its class methods. It replaces the former global
	// (name,arity) funcsByKey / funcsByName maps — resolution is now import-scoped.
	modules map[string]*moduleIndex
	// moduleSet is the set of in-tree module ids, used for extension/index resolution
	// of a relative specifier.
	moduleSet map[string]bool
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
		return nil, fmt.Errorf("jsanalysis: no .js/.ts/.jsx/.tsx sources under %q", buildDir)
	}

	prog := &program{
		root:      buildDir,
		modules:   map[string]*moduleIndex{},
		moduleSet: map[string]bool{},
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			prog.readFailed = true
			continue
		}
		module := moduleOf(buildDir, f)
		pr := parseFile(module, string(data))
		if pr.skipped {
			prog.skipped = true
		}
		fp := fileParse{module: pr.module, decls: pr.decls, calls: pr.calls, ingresses: pr.ingresses, bindings: pr.bindings}
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
// fabricated node).
func (p *program) resolveIngressSymbol(module string, in ingressMarker) string {
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
// as a (wrong) edge or as reachability.
func CallGraph(_ context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	res, _, err := callGraphInternal(req.BuildDir)
	return res, err
}

// partialFlags accumulates the call graph's declared limits across all files.
type partialFlags struct {
	unresolved    bool // an ambiguous/unknown callee (dynamic_dispatch)
	uninspectable bool // a bare specifier into a package this cycle cannot open (uninspectable_package)
	dynImport     bool // a runtime-computed ESM target import(expr) (dynamic_import_specifier)
	computedReq   bool // a runtime-computed CJS target require(var) (computed_require_specifier)
}

// callGraphInternal builds the graph and returns it alongside the per-edge provenance
// side table (§2). The wire plugin.CallEdge stays frozen — provenance lives here, in a
// jsanalysis-internal map parallel to the edge set, and C5 asserts against it via a
// package-internal test hook rather than the serialized edge.
func callGraphInternal(buildDir string) (plugin.CallGraphResult, map[plugin.CallEdge]provenance, error) {
	prog, err := loadProgram(buildDir)
	if err != nil {
		return plugin.CallGraphResult{}, nil, err
	}
	rs := prog.resolver()

	seen := map[plugin.CallEdge]bool{}
	var edges []plugin.CallEdge
	provByEdge := map[plugin.CallEdge]provenance{}
	rootsSet := map[string]bool{}
	var flags partialFlags

	for _, f := range prog.files {
		// Module-level runtime-computed specifiers (import(expr) / require(var)) are
		// declared limits even though they emit no call site (§6).
		if f.bindings.dynImport {
			flags.dynImport = true
		}
		if f.bindings.computedReq {
			flags.computedReq = true
		}
		for _, cs := range f.calls {
			caller := sym(funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity))
			r := rs.resolveCallSite(f.module, cs)
			if target, ok := r.edge(); ok {
				e := plugin.CallEdge{Caller: caller, Callee: sym(target)}
				if !seen[e] {
					seen[e] = true
					edges = append(edges, e)
					provByEdge[e] = r.Prov
				}
				continue
			}
			switch r.Kind {
			case resolvePackage:
				flags.uninspectable = true
			default: // resolveUnresolved (or a first-party module with no unique symbol)
				accumulateReason(&flags, r.Reason)
			}
		}
		// Framework ingress handler functions are call-graph roots. An ingress whose
		// handler reference does not resolve to a single declared function contributes
		// no root.
		for _, in := range f.ingresses {
			if symID := prog.resolveIngressSymbol(f.module, in); symID != "" {
				rootsSet[symID] = true
			}
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

	return plugin.CallGraphResult{
		Partiality: callGraphPartiality(prog, flags),
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      roots,
	}, provByEdge, nil
}

// accumulateReason maps a declined call's reason code onto the graph's partial flags.
func accumulateReason(flags *partialFlags, reason string) {
	switch reason {
	case plugin.PartialReasonUninspectablePackage:
		flags.uninspectable = true
	case plugin.PartialReasonDynamicImportSpecifier:
		flags.dynImport = true
	case plugin.PartialReasonComputedRequireSpecifier:
		flags.computedReq = true
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
	if prog.readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
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
	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(reasons...)
}
