package pythonanalysis

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// program is the whole-build parse: every file's module + call sites + ingress markers,
// plus the resolution index used to connect a lexical call site to the concrete declared
// function it names.
type program struct {
	files      []fileParse
	readFailed bool
	skipped    bool
	// funcsByName maps a function's simple name → every declaration of that name (across
	// modules and classes). A callee resolves to exactly one declaration by name +
	// self/cls-tolerant arity; zero or multiple matches mean the lexical callee cannot be
	// soundly resolved to a single edge (inv.5: no fabricated edge).
	funcsByName map[string][]funcDecl
	// dists maps an imported top-level module to the distribution providing it, so a call
	// through an import binding names a dependency boundary node.
	dists distResolver
	// dynamicImportOpaque records a dynamic load in runtime code whose module the scanner
	// cannot name without the load set (non-literal argument, entry-point group, package
	// walk, file loader, exec/eval/compile, getattr on a module, star import): run-wide,
	// fails closed. Reachability narrows it with the load set (loadset.go).
	dynamicImportOpaque bool
}

// resolveCallee maps a lexical call (leaf name + explicit-argument arity) to the SCIP id
// of the single declared function it names, or ("", false) when unresolvable. Arity match
// is self/cls-tolerant: a method call "obj.method(args)" carries one fewer explicit
// argument than the declaration "def method(self, args)", so a declaration of arity
// callArity OR callArity+1 matches. Zero matches (library/import/builtin) or more than one
// (an ambiguous name the lexer cannot scope-resolve) yields no edge.
func (p *program) resolveCallee(name string, callArity int) (string, bool) {
	seen := map[string]bool{}
	var matches []string
	for _, fd := range p.funcsByName[name] {
		if fd.arity == callArity || fd.arity == callArity+1 {
			s := fd.scip()
			if !seen[s] {
				seen[s] = true
				matches = append(matches, s)
			}
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	return "", false
}

// funcDecl is one declared function located by its module + enclosing class chain + name
// + arity — enough to build its SCIP id (identical to the id IndexSymbols emits for the
// same declaration, so a resolved sink, a call-graph node, and an ingress symbol coincide).
type funcDecl struct {
	module    string
	enclosing []string
	name      string
	arity     int
}

func (d funcDecl) scip() string {
	return scipSymbol(d.module, d.enclosing, functionDescriptor(d.name, d.arity))
}

// fileParse pairs a parsed file's module with its call sites, ingress markers, and import
// bindings (needed to qualify callers/callees and ingress handlers into SCIP ids and to name
// dependency boundary nodes). loadRoots are the module names the file imports dynamically
// by literal (importlib.import_module("yaml") → "yaml"); a relative name keeps its dots.
// The remaining fields feed the load set: every statically imported module, star-import
// sources, the dynamic loads, and the string literals that could name a module.
type fileParse struct {
	module    string
	calls     []callSite
	ingresses []ingressMarker
	bindings  map[string]map[string]scopedBinding
	loadRoots []string
	test      bool
	imports   []string
	stars     []string
	dyn       dynScan
	strs      []string
}

// funcSCIP builds the SCIP id for a function from its module, enclosing class chain, name,
// and arity. It is byte-identical to the id IndexSymbols emits for the same declaration,
// so a call-graph node, a resolved sink, and an ingress symbol share one identity space.
func funcSCIP(module string, enclosing []string, name string, arity int) string {
	return scipSymbol(module, enclosing, functionDescriptor(name, arity))
}

// sym wraps a minted SCIP id string into a plugin.Symbol for the graph-shaped results
// (call edges, roots, ingress symbols, reach paths). The Python lexical analyzer works in
// SCIP-id space, so both identity fields carry that id: SCIP is the canonical id and
// DisplayName mirrors it. Minting every graph Symbol through this ONE helper keeps the
// Symbol for a given id byte-identical everywhere, so map/set/== lookups over the graph
// stay sound (plugin.Symbol compares ALL fields).
func sym(s string) plugin.Symbol { return plugin.Symbol{SCIP: s, DisplayName: s} }

// loadProgram parses every Python file under buildDir into a whole-program view and builds
// the (name, arity) → SCIP resolution index. A missing/empty build dir is a hard error
// (inv.4), matching IndexSymbols; read failures and skipped constructs degrade partiality.
func loadProgram(buildDir string) (*program, error) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return nil, fmt.Errorf("pythonanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pythonanalysis: build dir %q is not a directory", buildDir)
	}
	paths, err := pythonFiles(buildDir)
	if err != nil {
		return nil, fmt.Errorf("pythonanalysis: scan %q: %w", buildDir, err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("pythonanalysis: no .py sources under %q", buildDir)
	}

	prog := &program{funcsByName: map[string][]funcDecl{}}
	for _, p := range paths {
		data, readErr := readRegular(p)
		if readErr != nil {
			prog.readFailed = true
			continue
		}
		module := moduleOf(buildDir, p)
		clean, lits := stripPythonLiterals(string(data))
		lines := logicalLines(clean)

		decls := parseDecls(lines)
		scan := parseCallsAndIngresses(lines)
		aliases, modTargets := dynamicLoadAliases(scan.bindings)
		dyn := scanDynamicLoads(clean, lits, aliases, modTargets)
		imports, stars := staticImports(lines)
		test := isTestModule(module)
		if !test && (len(dyn.opaque) > 0 || len(dyn.sites) > 0 || len(stars) > 0) {
			prog.dynamicImportOpaque = true
		}

		for _, d := range decls {
			if d.kind != kindFunc {
				continue
			}
			fd := funcDecl{module: module, enclosing: d.enclosing, name: d.name, arity: d.arity}
			prog.funcsByName[d.name] = append(prog.funcsByName[d.name], fd)
		}
		prog.files = append(prog.files, fileParse{
			module:    module,
			calls:     scan.calls,
			ingresses: scan.ingresses,
			bindings:  indexBindings(scan.bindings),
			loadRoots: dyn.roots,
			test:      test,
			imports:   imports,
			stars:     stars,
			dyn:       dyn,
			strs:      moduleLikeLiterals(lits),
		})
	}

	modules := make([]string, 0, len(prog.files))
	for _, f := range prog.files {
		modules = append(modules, f.module)
	}
	declared, read := declaredDistributions(buildDir)
	if !read {
		prog.readFailed = true
	}
	prog.dists = distResolver{
		curated:    NewDistImportMap(CuratedContributions()...),
		declared:   declared,
		firstParty: firstPartyTops(modules),
	}
	return prog, nil
}

// callerSCIP is the SCIP id of a call site's caller: its enclosing def, or the module-init
// node for a call at module or class-body level.
func (f fileParse) callerSCIP(cs callSite) string {
	if cs.callerName == "" {
		return moduleInitSCIP(f.module)
	}
	return funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity)
}

// CallGraph builds the source-level call graph for the Python module at req.BuildDir. It
// is a pure-Go, source-only lexical graph: caller and callee are both declared functions,
// and a call site is connected to its callee ONLY when the callee's (simple name, arity)
// resolves to EXACTLY ONE declared function in the program. When a callee is ambiguous (a
// name declared by multiple functions the lexer cannot scope-resolve) or unknown (a
// library/imported/builtin function with no source declaration), NO edge is fabricated and
// the partiality carries dynamic_dispatch — the inv.5 honesty boundary.
//
// Two node kinds extend the declared functions. A call through an import binding
// (`jwt.decode(t)` after `import jwt`, `Environment().from_string(x)` after `from jinja2
// import Environment`) gets an edge to a dependency boundary node "pypi:<dist>#<dotted>"
// naming the attribute by the import path the code used; the node stands for dependency
// code the lane does not read, so it is a candidate target, never a searched sink. Calls at
// module or class-body level are attributed to a module-init node per module, which is a
// root because that code runs at import time.
//
// The graph is ALWAYS declared Partial(dynamic_dispatch): a lexical Python scanner cannot
// see dynamic dispatch, getattr, decorator-rewriting, or monkeypatched edges, so it is
// structurally an under-approximation of the true call graph. Declaring partiality is the
// conservative direction (a missing edge is UNKNOWN, never a false not-affected); the
// Python plugin therefore never claims a Complete call graph. Read failures add
// tool_failure; skipped constructs add unsupported_phase1; a dynamic import whose module
// the scanner cannot name adds dynamic_import.
func CallGraph(_ context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	prog, err := loadProgram(req.BuildDir)
	if err != nil {
		return plugin.CallGraphResult{}, err
	}
	return callGraphOf(prog), nil
}

// callGraphOf builds the call graph of an already-loaded program.
func callGraphOf(prog *program) plugin.CallGraphResult {
	seen := map[plugin.CallEdge]bool{}
	var edges []plugin.CallEdge
	rootsSet := map[string]bool{}
	initCallers := map[string]bool{}
	addEdge := func(caller, callee string) {
		e := plugin.CallEdge{Caller: sym(caller), Callee: sym(callee)}
		if !seen[e] {
			seen[e] = true
			edges = append(edges, e)
		}
	}

	for _, f := range prog.files {
		for _, cs := range f.calls {
			caller := f.callerSCIP(cs)
			if cs.callerName == "" && !isTestModule(f.module) {
				initCallers[caller] = true
			}
			// A call through an import binding reaches a dependency attribute: emit a
			// boundary edge to it. The node stands for code the lane does not read, so it is
			// a candidate target only, never a searched sink.
			if dist, dotted, ok := boundaryTarget(cs.calleeChain, cs.scopes, f.bindings, prog.dists); ok {
				addEdge(caller, boundarySCIP(dist, dotted))
			}
			callee, ok := prog.resolveCallee(cs.calleeName, cs.calleeArity)
			if !ok {
				// 0 matches (library/import/builtin/unknown) or >1 (unresolvable name):
				// no sound single edge. The standing dynamic_dispatch partiality already
				// covers this; never fabricate (inv.5).
				continue
			}
			addEdge(caller, callee)
		}
		// Framework ingress handler functions are call-graph roots (static-reachability
		// entry points), so a reverse BFS can terminate at them even when no caller in the
		// source invokes them.
		for _, in := range f.ingresses {
			rootsSet[funcSCIP(f.module, in.enclosing, in.name, in.arity)] = true
		}
	}

	// Module-level code runs at import time, so a module-init caller with an outgoing edge
	// is an entry point. Test modules are excluded: test code is not a runtime root.
	for _, e := range edges {
		if initCallers[e.Caller.SCIP] {
			rootsSet[e.Caller.SCIP] = true
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})

	roots := make([]plugin.Symbol, 0, len(rootsSet))
	for r := range rootsSet {
		roots = append(roots, sym(r))
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].SCIP < roots[j].SCIP })

	return plugin.CallGraphResult{
		Partiality: callGraphPartiality(prog),
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      roots,
	}
}

// callGraphPartiality declares the call graph ALWAYS partial for Python: the lexical
// scanner categorically cannot resolve dynamic dispatch / getattr / decorator-rewriting /
// monkeypatching, so dynamic_dispatch is a standing reason. Read failures and skipped
// constructs add their own machine-readable reasons.
func callGraphPartiality(prog *program) plugin.Partiality {
	reasons := []string{plugin.PartialReasonDynamicDispatch}
	reasons = append(reasons, dynamicImportReasons(prog.dynamicImportOpaque)...)
	if prog.readFailed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	return plugin.Partial(reasons...)
}

// isTestModule reports whether a module path names test code: a test_*.py, *_test.py or
// conftest.py file, or any module under a tests/ or test/ directory.
func isTestModule(module string) bool {
	segs := strings.Split(module, "/")
	for _, s := range segs {
		if s == "tests" || s == "test" {
			return true
		}
	}
	leaf := segs[len(segs)-1]
	return strings.HasPrefix(leaf, "test_") || strings.HasSuffix(leaf, "_test") || leaf == "conftest"
}
