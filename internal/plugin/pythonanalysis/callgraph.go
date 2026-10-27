package pythonanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	// dynamicImportOpaque records a dynamic import whose module the scanner cannot name
	// (non-literal argument, entry-point group, package walk): run-wide, fails closed.
	dynamicImportOpaque bool
	// importUnattributed records that a manifest could not be read in full and an import
	// resolves to no distribution, so the name that would attribute it may be in the unread
	// part and the boundary nodes behind it are missing.
	importUnattributed bool
	// sourceUnread records a .py source the lane could not read, whose call sites are
	// therefore missing from Unresolved.
	sourceUnread bool
	// byModule maps every trailing run of a module's path segments ("src/pkg/m", "pkg/m",
	// "m") to the files whose module it is, so an import path names its module wherever the
	// import root sits under the build root. named holds every run of segments some module
	// path contains: the import paths that name a module or a package directory.
	byModule map[string][]int
	named    map[string]bool
	// leafMemo caches aliasLeaves by import path.
	leafMemo map[string][]string
}

// resolveCallee picks the SCIP id of the single declaration among decls that a call with
// callArity explicit arguments names, or ("", false) when there is none or more than one.
// Arity match is self/cls-tolerant: a method call "obj.method(args)" carries one fewer
// explicit argument than the declaration "def method(self, args)", so a declaration of
// arity callArity OR callArity+1 matches. Zero matches (library/import/builtin) or more
// than one (an ambiguous name the lexer cannot scope-resolve) yields no edge.
func resolveCallee(decls []funcDecl, callArity int) (string, bool) {
	var matches []string
	for _, fd := range decls {
		if fd.arity == callArity || fd.arity == callArity+1 {
			matches = append(matches, fd.scip())
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	return "", false
}

// declsNamed is every declaration under any of the leaf names, each once.
func (p *program) declsNamed(leaves []string) []funcDecl {
	if len(leaves) == 1 {
		return p.funcsByName[leaves[0]]
	}
	seen := map[string]bool{}
	var out []funcDecl
	for _, leaf := range leaves {
		for _, fd := range p.funcsByName[leaf] {
			if s := fd.scip(); !seen[s] {
				seen[s] = true
				out = append(out, fd)
			}
		}
	}
	return out
}

// siteLeaves is the leaf names a call site may stand for. A name always stands for the
// declarations under it. It stands for a first-party function an import binds to it under
// another name only where the caller holds that binding (aliasBound): a bare call whose
// name the caller's scopes bind by import, not shadowed by a parameter or local, or a call
// through a name bound to a first-party module that re-exports the leaf. escape is the
// wider set the escape scan uses: every alias the file binds the name to in any scope.
func (p *program) siteLeaves(f *fileParse, cs callSite) (edge, escape []string) {
	name := cs.calleeName
	if name == "" {
		return nil, nil
	}
	edge = []string{name}
	if len(cs.calleeChain) <= 1 {
		if paths, ok := f.aliasBound(name, cs.scopes); ok {
			edge = p.withAliases(edge, paths)
		}
		return edge, p.withAliases(edge, f.anyScopeBinds(name))
	}
	head := cs.calleeChain[0]
	mid := strings.Join(cs.calleeChain[1:len(cs.calleeChain)-1], "/")
	via := func(paths []string) []string {
		var out []string
		for _, path := range paths {
			if mid != "" {
				path += "/" + mid
			}
			if p.named[path] {
				out = append(out, path+"/"+name)
			}
		}
		return out
	}
	if paths, ok := f.aliasBound(head, cs.scopes); ok {
		edge = p.withAliases(edge, via(paths))
	}
	return edge, p.withAliases(edge, via(f.anyScopeBinds(head)))
}

// withAliases adds the leaf names each import path may stand for to leaves.
func (p *program) withAliases(leaves, paths []string) []string {
	for _, path := range paths {
		for _, leaf := range p.aliasLeaves(path) {
			if !slices.Contains(leaves, leaf) {
				leaves = append(leaves, leaf)
			}
		}
	}
	return leaves
}

// aliasLeaves follows an import path ("pkg/g") through re-exports to a fixpoint: its leaf
// names a function, and when the module it is imported from binds that leaf by a first-party
// import itself, the path that import names is followed in turn. Each path is visited once,
// so an import cycle ends.
func (p *program) aliasLeaves(path string) []string {
	if out, ok := p.leafMemo[path]; ok {
		return out
	}
	visited := map[string]bool{}
	var out []string
	var walk func(string)
	walk = func(path string) {
		if visited[path] {
			return
		}
		visited[path] = true
		mod, leaf := parentModule(path), path[strings.LastIndexByte(path, '/')+1:]
		if !slices.Contains(out, leaf) {
			out = append(out, leaf)
		}
		for _, i := range p.byModule[mod] {
			for _, next := range p.files[i].fpBinds[""][leaf] {
				walk(next)
			}
		}
	}
	walk(path)
	p.leafMemo[path] = out
	return out
}

// firstSegment is a dotted path's first segment.
func firstSegment(dotted string) string {
	top, _, _ := strings.Cut(dotted, ".")
	return top
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
//
// The remaining fields feed alias resolution and the escape scan: the file's declared
// functions and top-level names, the defs under a non-route decorator, the names it uses as
// values, the slash paths its first-party import bindings name (by scope, then local name),
// the names its defs bind locally, and the first-party modules a literal dynamic import or
// sys.modules lookup hands over whole. computed records computed-name access, which makes
// every function in the file escape.
type fileParse struct {
	module    string
	isPackage bool
	calls     []callSite
	ingresses []ingressMarker
	bindings  map[string]map[string]scopedBinding
	loadRoots []string
	decls     []funcDecl
	topNames  map[string]bool
	decorated []funcDecl
	refs      valueRefs
	fpBinds   map[string]map[string][]string
	depBinds  map[string]map[string]bool
	locals    map[string]map[string]bool
	modValues []string
	computed  bool
}

// aliasBound returns the first-party import paths a name stands for at a site in the given
// def scopes: the innermost scope that binds it decides, then the module. ok is true only
// when that scope binds the name by first-party import and in no other way; a local binding
// (a parameter, an assignment) or a dependency import or instance in the same scope may be
// what the name holds at the call, so ok is false.
func (f *fileParse) aliasBound(name string, scopes []string) ([]string, bool) {
	for i := len(scopes) - 1; i >= -1; i-- {
		scope := ""
		if i >= 0 {
			scope = scopes[i]
		}
		paths := f.fpBinds[scope][name]
		if f.locals[scope][name] || f.depBinds[scope][name] {
			return nil, false
		}
		if len(paths) > 0 {
			return paths, true
		}
	}
	return nil, false
}

// anyScopeBinds is every first-party import path the file binds name to, in any scope.
func (f *fileParse) anyScopeBinds(name string) []string {
	var out []string
	for _, scope := range f.fpBinds {
		out = append(out, scope[name]...)
	}
	return out
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

	prog := &program{funcsByName: map[string][]funcDecl{}, leafMemo: map[string][]string{}}
	var rawBindings [][]scopedBinding
	var relBindings [][]scopedBinding
	var modRefs [][]string
	for _, p := range paths {
		data, readErr := readRegular(p)
		if readErr != nil {
			prog.readFailed = true
			prog.sourceUnread = true
			continue
		}
		module := moduleOf(buildDir, p)
		clean, lits := stripPythonLiterals(string(data))
		lines := logicalLines(clean)

		decls := parseDecls(lines)
		scan := parseCallsAndIngresses(lines)
		scan.refs.scanFStrings(clean, lits)
		roots, opaque := dynamicImports(clean, lits)
		lookups, lookupOpaque := sysModulesLookups(clean, lits)
		if opaque || lookupOpaque {
			prog.dynamicImportOpaque = true
		}

		var fds []funcDecl
		topNames := map[string]bool{}
		for _, d := range decls {
			if len(d.enclosing) == 0 {
				topNames[d.name] = true
			}
			if d.kind != kindFunc {
				continue
			}
			fd := funcDecl{module: module, enclosing: d.enclosing, name: d.name, arity: d.arity}
			prog.funcsByName[d.name] = append(prog.funcsByName[d.name], fd)
			fds = append(fds, fd)
		}
		for name := range scan.locals[""] {
			topNames[name] = true
		}
		for _, b := range append(scan.bindings, scan.relBindings...) {
			if b.scope == "" {
				topNames[b.local] = true
			}
		}
		for i := range scan.decorated {
			scan.decorated[i].module = module
		}
		prog.files = append(prog.files, fileParse{
			module:    module,
			isPackage: strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)) == "__init__",
			calls:     scan.calls,
			ingresses: scan.ingresses,
			bindings:  indexBindings(scan.bindings),
			loadRoots: roots,
			decls:     fds,
			topNames:  topNames,
			decorated: scan.decorated,
			refs:      scan.refs,
			locals:    scan.locals,
			computed:  scan.refs.computed || opaque,
		})
		rawBindings = append(rawBindings, scan.bindings)
		relBindings = append(relBindings, scan.relBindings)
		modRefs = append(modRefs, append(roots, lookups...))
	}

	modules := make([]string, 0, len(prog.files))
	for _, f := range prog.files {
		modules = append(modules, f.module)
	}
	declared, declaredComplete, read := declaredDistributions(buildDir)
	if !read {
		prog.readFailed = true
	}
	prog.dists = distResolver{
		curated:    NewDistImportMap(CuratedContributions()...),
		declared:   declared,
		firstParty: firstPartyTops(modules),
		python:     buildInterpreter(buildDir),
	}
	prog.importUnattributed = !declaredComplete && prog.hasUndeclaredImport()
	prog.indexModules()
	for i := range prog.files {
		prog.bindFirstParty(i, rawBindings[i], relBindings[i], modRefs[i])
	}
	return prog, nil
}

// indexModules builds byModule and named over the parsed files' module paths.
func (prog *program) indexModules() {
	prog.byModule = map[string][]int{}
	prog.named = map[string]bool{}
	for i, f := range prog.files {
		if f.module == "" {
			continue
		}
		segs := strings.Split(f.module, "/")
		for a := range segs {
			prog.byModule[strings.Join(segs[a:], "/")] = append(prog.byModule[strings.Join(segs[a:], "/")], i)
			for b := a + 1; b <= len(segs); b++ {
				prog.named[strings.Join(segs[a:b], "/")] = true
			}
		}
	}
}

// bindFirstParty records what one file's import bindings say about first-party code: the
// slash path each first-party import binds a local name to, by scope, and the first-party
// modules its literal dynamic imports and sys.modules lookups name. Relative bindings are
// first-party by construction and stay out of the boundary bindings, so they never name a
// distribution.
func (prog *program) bindFirstParty(i int, raw, rel []scopedBinding, modRefs []string) {
	f := &prog.files[i]
	f.fpBinds = map[string]map[string][]string{}
	bind := func(scope, local, path string) {
		m := f.fpBinds[scope]
		if m == nil {
			m = map[string][]string{}
			f.fpBinds[scope] = m
		}
		if !slices.Contains(m[local], path) {
			m[local] = append(m[local], path)
		}
	}
	f.depBinds = map[string]map[string]bool{}
	for _, b := range raw {
		if b.target == "" || !prog.dists.firstParty[firstSegment(b.target)] {
			if f.depBinds[b.scope] == nil {
				f.depBinds[b.scope] = map[string]bool{}
			}
			f.depBinds[b.scope][b.local] = true
			continue
		}
		bind(b.scope, b.local, strings.ReplaceAll(b.target, ".", "/"))
	}
	for _, b := range rel {
		if path, ok := relativeModule(f.module, f.isPackage, b.target); ok {
			bind(b.scope, b.local, path)
		}
	}
	for _, name := range modRefs {
		switch {
		case strings.HasPrefix(name, "."):
			if path, ok := relativeModule(f.module, f.isPackage, name); ok {
				f.modValues = append(f.modValues, path)
			}
		case prog.dists.firstParty[firstSegment(name)]:
			f.modValues = append(f.modValues, strings.ReplaceAll(name, ".", "/"))
		}
	}
}

// hasUndeclaredImport reports whether any import binding names a module no distribution the
// manifests read here declare provides.
func (prog *program) hasUndeclaredImport() bool {
	for _, f := range prog.files {
		for _, scope := range f.bindings {
			for _, b := range scope {
				if prog.dists.undeclaredImport(b.target) {
					return true
				}
			}
		}
	}
	return false
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
// module or class-body level, decorator expressions, and def headers (parameter defaults,
// class bases) are attributed to a module-init node per module, or to the enclosing def.
//
// A call the scanner cannot connect is listed in Unresolved, and every frame such a call or
// code the lane does not read may land on is a root and listed in Escaped (escape.go): each
// runtime module-init node, and each function whose name escapes, that is a class member,
// sits under a non-route decorator, or lives in a file that reaches names by computed
// access. A name an import binds to a first-party function under another name resolves to
// that function, through any chain of re-exports, but only at a call site whose file holds
// the binding in scope: a parameter or local of the same name, or a dependency receiver,
// keeps the edges the name alone gives.
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
	addEdge := func(caller, callee string) {
		e := plugin.CallEdge{Caller: sym(caller), Callee: sym(callee)}
		if !seen[e] {
			seen[e] = true
			edges = append(edges, e)
		}
	}
	type siteKey struct {
		caller, callee string
		arity          int
	}
	unresolvedSeen := map[siteKey]bool{}
	var unresolved []plugin.UnresolvedCall
	escapedSet := map[string]bool{}
	// A runtime call site may land on any declaration its name stands for other than the one
	// it has an edge to, so each of those escapes; landed dedups the work per name set.
	landed := map[string]bool{}

	for fi := range prog.files {
		f := &prog.files[fi]
		for _, cs := range f.calls {
			caller := f.callerSCIP(cs)
			// A call through an import binding reaches a dependency attribute: emit a
			// boundary edge to it. The node stands for code the lane does not read, so it is
			// a candidate target only, never a searched sink.
			provides, dotted := boundaryTarget(cs.calleeChain, cs.scopes, f.bindings, prog.dists)
			for _, dist := range provides {
				addEdge(caller, boundarySCIP(dist, dotted))
			}
			edgeLeaves, escapeLeaves := prog.siteLeaves(f, cs)
			callee, ok := resolveCallee(prog.declsNamed(edgeLeaves), cs.calleeArity)
			if !isTestModule(f.module) && len(escapeLeaves) > 0 {
				if k := strings.Join(escapeLeaves, ",") + "|" + callee; !landed[k] {
					landed[k] = true
					for _, fd := range prog.declsNamed(escapeLeaves) {
						if s := fd.scip(); s != callee && !isTestModule(fd.module) {
							escapedSet[s] = true
						}
					}
				}
			}
			if !ok {
				// 0 matches (library/import/builtin/unknown) or >1 (unresolvable name):
				// no sound single edge, so never fabricate one (inv.5). The site is listed
				// with no Targets: it may reach any escaped frame.
				u := plugin.UnresolvedCall{
					Caller: sym(caller),
					Callee: cs.calleeWritten,
					Arity:  cs.calleeArity,
					Reason: plugin.PartialReasonDynamicDispatch,
				}
				if k := (siteKey{caller, u.Callee, u.Arity}); !unresolvedSeen[k] {
					unresolvedSeen[k] = true
					unresolved = append(unresolved, u)
				}
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

	prog.escapeFrames(escapedSet)
	for s := range escapedSet {
		rootsSet[s] = true
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller.SCIP != edges[j].Caller.SCIP {
			return edges[i].Caller.SCIP < edges[j].Caller.SCIP
		}
		return edges[i].Callee.SCIP < edges[j].Callee.SCIP
	})
	sort.Slice(unresolved, func(i, j int) bool {
		a, b := unresolved[i], unresolved[j]
		if a.Caller.SCIP != b.Caller.SCIP {
			return a.Caller.SCIP < b.Caller.SCIP
		}
		if a.Callee != b.Callee {
			return a.Callee < b.Callee
		}
		return a.Arity < b.Arity
	})

	return plugin.CallGraphResult{
		Partiality: callGraphPartiality(prog),
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      sortedSymbols(rootsSet),
		Escaped:    sortedSymbols(escapedSet),
		Unresolved: unresolved,
	}
}

// escapeFrames adds to out the frames code the lane does not see may call (escape.go):
// every runtime module's top-level frame and every escaping function outside test code.
// The call sites' own contribution (a declaration a site names without an edge to it) is
// added by callGraphOf.
func (prog *program) escapeFrames(out map[string]bool) {
	escape := func(fd funcDecl) {
		if !isTestModule(fd.module) {
			out[fd.scip()] = true
		}
	}
	modDone := map[string]bool{}
	// escapeModule escapes every function of the modules an import path names: the module
	// is a value, so any of its functions can be reached by attribute name.
	escapeModule := func(path string) {
		if modDone[path] {
			return
		}
		modDone[path] = true
		for _, g := range prog.files {
			if moduleNamedBy(g.module, path) {
				for _, fd := range g.decls {
					escape(fd)
				}
			}
		}
	}
	for fi := range prog.files {
		f := &prog.files[fi]
		if isTestModule(f.module) {
			continue
		}
		out[moduleInitSCIP(f.module)] = true
		for _, fd := range f.decls {
			if f.computed || len(fd.enclosing) > 0 || isDunder(fd.name) {
				escape(fd)
			}
		}
		for _, fd := range f.decorated {
			escape(fd)
		}
		for _, path := range f.modValues {
			escapeModule(path)
		}
		for name := range f.refs.names {
			for _, fd := range prog.declsNamed(prog.withAliases([]string{name}, f.anyScopeBinds(name))) {
				escape(fd)
			}
		}
		for chain := range f.refs.chains {
			segs := strings.Split(chain, ".")
			for _, base := range f.anyScopeBinds(segs[0]) {
				prog.escapeChain(base, segs[1:], escape, escapeModule)
			}
		}
	}
}

// escapeChain handles a dotted value whose head an import binds to the path base. It finds
// the longest prefix of the chain that names a module. With no attribute after it, the
// module itself is the value. An attribute the module declares is a function or class
// handed over by name, which the name scan covers; one the module binds by first-party
// import is followed through the import; anything else ("handlers.__dict__", an attribute
// the scanner cannot see) may reach any function of the module.
func (prog *program) escapeChain(base string, rest []string, escape func(funcDecl), escapeModule func(string)) {
	for k := len(rest); k >= 0; k-- {
		path := base
		if k > 0 {
			path += "/" + strings.Join(rest[:k], "/")
		}
		if !prog.named[path] {
			continue
		}
		if k == len(rest) {
			escapeModule(path)
			return
		}
		attr := rest[k]
		declared, bound := false, false
		for _, i := range prog.byModule[path] {
			g := &prog.files[i]
			declared = declared || g.topNames[attr]
			if paths := g.fpBinds[""][attr]; len(paths) > 0 {
				bound = true
				for _, fd := range prog.declsNamed(prog.withAliases([]string{attr}, paths)) {
					escape(fd)
				}
			}
		}
		if !declared && !bound {
			escapeModule(path)
		}
		return
	}
}

// sortedSymbols mints a SCIP id set into a sorted Symbol slice.
func sortedSymbols(set map[string]bool) []plugin.Symbol {
	out := make([]plugin.Symbol, 0, len(set))
	for s := range set {
		out = append(out, sym(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SCIP < out[j].SCIP })
	return out
}

// callGraphPartiality declares the call graph ALWAYS partial for Python: the lexical
// scanner categorically cannot resolve dynamic dispatch / getattr / decorator-rewriting /
// monkeypatching, so dynamic_dispatch is a standing reason. Read failures and skipped
// constructs add their own machine-readable reasons. A manifest read only in part counts as
// a read failure when some import resolves to no distribution, since the name that would
// attribute it may be in the part not read; with every import attributed, the unread part
// changes no boundary node.
//
// Unresolved lists every call site the scanner sees and does not connect. A call the
// interpreter makes with no site (a constructor, an operator, a context manager) can land
// only on a class member or a dunder, which all escape. The list is incomplete, and
// unlisted_sites is set, when a source file was not read, a construct was skipped, code is
// evaluated from a string, or an f-string substitution holds a call.
func callGraphPartiality(prog *program) plugin.Partiality {
	reasons := []string{plugin.PartialReasonDynamicDispatch}
	reasons = append(reasons, dynamicImportReasons(prog.dynamicImportOpaque)...)
	if prog.readFailed || prog.importUnattributed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if prog.sitesUnlisted() {
		reasons = append(reasons, plugin.PartialReasonUnlistedSites)
	}
	return plugin.Partial(reasons...)
}

// sitesUnlisted reports whether some declined call site is missing from Unresolved.
func (prog *program) sitesUnlisted() bool {
	if prog.sourceUnread || prog.skipped {
		return true
	}
	for _, f := range prog.files {
		if f.refs.evaluated || f.refs.hidden {
			return true
		}
	}
	return false
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
