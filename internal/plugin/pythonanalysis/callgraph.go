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
	// aliases maps a local name an import binds to a first-party function under another
	// name ("from .impl import f as g": g → f) to the original leaf names it may stand for.
	aliases map[string][]string
}

// resolveCallee maps a lexical call (leaf name + explicit-argument arity) to the SCIP id
// of the single declared function it names, or ("", false) when unresolvable. The name
// stands for every declaration of it and, through the alias table, of each first-party
// function an import binds to it under another name; the hits are unioned. Arity match
// is self/cls-tolerant: a method call "obj.method(args)" carries one fewer explicit
// argument than the declaration "def method(self, args)", so a declaration of arity
// callArity OR callArity+1 matches. Zero matches (library/import/builtin) or more than one
// (an ambiguous name the lexer cannot scope-resolve) yields no edge.
func (p *program) resolveCallee(name string, callArity int) (string, bool) {
	var matches []string
	for _, fd := range p.calleeDecls(name) {
		if fd.arity == callArity || fd.arity == callArity+1 {
			matches = append(matches, fd.scip())
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	return "", false
}

// calleeDecls is every declaration a callee name can stand for: the functions declared
// under it plus those an import alias binds to it, each once.
func (p *program) calleeDecls(name string) []funcDecl {
	if name == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []funcDecl
	add := func(leaf string) {
		for _, fd := range p.funcsByName[leaf] {
			if s := fd.scip(); !seen[s] {
				seen[s] = true
				out = append(out, fd)
			}
		}
	}
	add(name)
	for _, leaf := range p.aliases[name] {
		add(leaf)
	}
	return out
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
// The remaining fields feed the escape scan: the file's declared functions, the defs under a
// non-route decorator, the names it uses as values, and the slash paths of the first-party
// modules its import bindings name, keyed by local name. computed records computed-name
// access, which makes every function in the file escape.
type fileParse struct {
	module      string
	calls       []callSite
	ingresses   []ingressMarker
	bindings    map[string]map[string]scopedBinding
	loadRoots   []string
	decls       []funcDecl
	decorated   []funcDecl
	refs        valueRefs
	moduleBinds map[string][]string
	computed    bool
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

	prog := &program{funcsByName: map[string][]funcDecl{}, aliases: map[string][]string{}}
	var rawBindings [][]scopedBinding
	var relBindings [][]importBinding
	var packages []bool
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
		if opaque {
			prog.dynamicImportOpaque = true
		}

		var fds []funcDecl
		for _, d := range decls {
			if d.kind != kindFunc {
				continue
			}
			fd := funcDecl{module: module, enclosing: d.enclosing, name: d.name, arity: d.arity}
			prog.funcsByName[d.name] = append(prog.funcsByName[d.name], fd)
			fds = append(fds, fd)
		}
		for i := range scan.decorated {
			scan.decorated[i].module = module
		}
		prog.files = append(prog.files, fileParse{
			module:    module,
			calls:     scan.calls,
			ingresses: scan.ingresses,
			bindings:  indexBindings(scan.bindings),
			loadRoots: roots,
			decls:     fds,
			decorated: scan.decorated,
			refs:      scan.refs,
			computed:  scan.refs.computed || opaque,
		})
		rawBindings = append(rawBindings, scan.bindings)
		relBindings = append(relBindings, scan.relBindings)
		packages = append(packages, strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)) == "__init__")
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
	for i := range prog.files {
		prog.bindFirstParty(i, rawBindings[i], relBindings[i], packages[i])
	}
	return prog, nil
}

// bindFirstParty records what one file's import bindings say about first-party code: an
// alias-table entry for each name bound to a first-party function under another name, and
// the slash path of the first-party module each name may stand for. Relative bindings are
// first-party by construction and stay out of the boundary bindings, so they never name a
// distribution.
func (prog *program) bindFirstParty(i int, raw []scopedBinding, rel []importBinding, isPackage bool) {
	f := &prog.files[i]
	f.moduleBinds = map[string][]string{}
	bind := func(local, target, path string) {
		leaf := target[strings.LastIndexByte(target, '.')+1:]
		if leaf != local && !slices.Contains(prog.aliases[local], leaf) {
			prog.aliases[local] = append(prog.aliases[local], leaf)
		}
		f.moduleBinds[local] = append(f.moduleBinds[local], path)
	}
	for _, b := range raw {
		if b.target == "" {
			continue
		}
		top, _, _ := strings.Cut(b.target, ".")
		if !prog.dists.firstParty[top] {
			continue
		}
		bind(b.local, b.target, strings.ReplaceAll(b.target, ".", "/"))
	}
	for _, b := range rel {
		if path, ok := relativeModule(f.module, isPackage, b.target); ok {
			bind(b.local, b.target, path)
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
// access. A name an import binds to a first-party function under another name resolves
// through the alias table.
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
	// mayLand holds the names a runtime call site names without a single edge to a
	// declaration of them: the call may land on any of those declarations.
	mayLand := map[string]string{}

	for _, f := range prog.files {
		for _, cs := range f.calls {
			caller := f.callerSCIP(cs)
			// A call through an import binding reaches a dependency attribute: emit a
			// boundary edge to it. The node stands for code the lane does not read, so it is
			// a candidate target only, never a searched sink.
			provides, dotted := boundaryTarget(cs.calleeChain, cs.scopes, f.bindings, prog.dists)
			for _, dist := range provides {
				addEdge(caller, boundarySCIP(dist, dotted))
			}
			callee, ok := prog.resolveCallee(cs.calleeName, cs.calleeArity)
			if !isTestModule(f.module) && cs.calleeName != "" {
				if prev, named := mayLand[cs.calleeName]; !named && ok {
					mayLand[cs.calleeName] = callee
				} else if !named || !ok || prev != callee {
					mayLand[cs.calleeName] = ""
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

	escapedSet := prog.escapedFrames(mayLand)
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

// escapedFrames is the set of frames code the lane does not see may call (escape.go):
// every runtime module's top-level frame and every escaping function outside test code.
// mayLand maps each name a runtime call site names to the declaration a single edge was
// drawn to, or "" when no single edge was; every other declaration it stands for escapes.
func (prog *program) escapedFrames(mayLand map[string]string) map[string]bool {
	out := map[string]bool{}
	escape := func(fd funcDecl) {
		if !isTestModule(fd.module) {
			out[fd.scip()] = true
		}
	}
	for name, edged := range mayLand {
		for _, fd := range prog.calleeDecls(name) {
			if fd.scip() != edged {
				escape(fd)
			}
		}
	}
	for _, f := range prog.files {
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
		for name := range f.refs.names {
			for _, fd := range prog.calleeDecls(name) {
				escape(fd)
			}
		}
		for chain := range f.refs.chains {
			head, rest, _ := strings.Cut(chain, ".")
			for _, path := range f.moduleBinds[head] {
				if rest != "" {
					path += "/" + strings.ReplaceAll(rest, ".", "/")
				}
				for _, g := range prog.files {
					if moduleNamedBy(g.module, path) {
						for _, fd := range g.decls {
							escape(fd)
						}
					}
				}
			}
		}
	}
	return out
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
