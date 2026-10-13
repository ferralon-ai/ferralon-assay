package pythonanalysis

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
type fileParse struct {
	module    string
	calls     []callSite
	ingresses []ingressMarker
	bindings  map[string]map[string]scopedBinding
	loadRoots []string
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
// the (name, arity) → SCIP resolution index. Packaging build scripts (buildScripts) are
// parsed but left out of the program, so their imports never read as runtime loads. A
// missing/empty build dir is a hard error
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
	var parsed []parsedFile
	for _, p := range paths {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			prog.readFailed = true
			continue
		}
		module := moduleOf(buildDir, p)
		clean, lits := stripPythonLiterals(string(data))
		lines := logicalLines(clean)

		var funcs []funcDecl
		for _, d := range parseDecls(lines) {
			if d.kind == kindFunc {
				funcs = append(funcs, funcDecl{module: module, enclosing: d.enclosing, name: d.name, arity: d.arity})
			}
		}
		scan := parseCallsAndIngresses(lines)
		roots, opaque := dynamicImports(clean, lits)
		pf := parsedFile{
			path:   p,
			funcs:  funcs,
			opaque: opaque,
			refs:   importRefs(lines, packageOf(module, p)),
			parse: fileParse{
				module:    module,
				calls:     scan.calls,
				ingresses: scan.ingresses,
				bindings:  indexBindings(scan.bindings),
				loadRoots: roots,
			},
		}
		if _, ok := buildScriptBackends[filepath.Base(p)]; ok {
			pf.text = string(data)
		}
		parsed = append(parsed, pf)
	}

	build := buildScripts(parsed, readLoaders(buildDir))
	modules := make([]string, 0, len(parsed))
	for i, pf := range parsed {
		// A build script is still the project's own code, so its module stays first-party.
		modules = append(modules, pf.parse.module)
		if build[i] {
			continue
		}
		if pf.opaque {
			prog.dynamicImportOpaque = true
		}
		for _, fd := range pf.funcs {
			prog.funcsByName[fd.name] = append(prog.funcsByName[fd.name], fd)
		}
		prog.files = append(prog.files, pf.parse)
	}
	prog.dists = distResolver{
		curated:    NewDistImportMap(CuratedContributions()...),
		declared:   declaredDistributions(buildDir),
		firstParty: firstPartyTops(modules),
	}
	return prog, nil
}

// parsedFile is one file's parse before loadProgram decides whether it is runtime code.
type parsedFile struct {
	path   string
	funcs  []funcDecl
	opaque bool        // a dynamic import whose module the scanner cannot name
	refs   []importRef // modules its import statements may load
	text   string      // raw source, kept only for build-script candidates
	parse  fileParse
}

// buildScriptBackends maps a packaging build script's file name to the build backends one
// of which it must import to count as that script.
var buildScriptBackends = map[string][]string{
	"setup.py":       {"setuptools", "distutils"},
	"hatch_build.py": {"hatchling"},
}

// buildScripts returns the indexes of the parsed files that are packaging build scripts:
// a file named in buildScriptBackends that imports one of its backends and does not sit in
// a regular package (no __init__.py beside it). Build scripts run when the project is
// built, not when it runs, so their imports and calls are not runtime code.
//
// Leaving a file out can only make the program look like it loads less, so a script is
// left out only when nothing at runtime can reach it. It stays in when any other file
// imports it under any name it could have (absolute, dotted, relative or star import), when
// any other file imports anything dynamically, when an entry point in a config or in a
// build script names it, or when a launcher mentions it. ld is nil when a config or launcher
// could not be read, which keeps every script.
func buildScripts(parsed []parsedFile, ld *loaders) map[int]bool {
	if ld == nil {
		return nil
	}
	build := map[int]bool{}
	for i, pf := range parsed {
		backends, ok := buildScriptBackends[filepath.Base(pf.path)]
		if !ok {
			continue
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(pf.path), "__init__.py")); err == nil {
			continue
		}
		if slices.ContainsFunc(pf.refs, func(r importRef) bool {
			top, _, _ := strings.Cut(r.path, ".")
			return !r.relative && slices.Contains(backends, top)
		}) {
			build[i] = true
		}
	}
	if len(build) == 0 {
		return nil
	}
	texts := slices.Clone(ld.configs)
	for i := range build {
		texts = append(texts, parsed[i].text)
	}
	for i := range build {
		names := moduleNames(parsed[i].parse.module)
		if namedByEntryPoint(names, texts) || mentionedByLauncher(path.Base(parsed[i].parse.module), ld.launchers) {
			delete(build, i)
			continue
		}
		for j, pf := range parsed {
			if j != i && (pf.opaque || len(pf.parse.loadRoots) > 0 || reachesAny(pf.refs, names)) {
				delete(build, i)
				break
			}
		}
	}
	return build
}

// moduleNames returns every dotted name a module could be imported under: its path from
// the build root and each suffix of it, since any directory on the path may be an import
// root (a src layout, a namespace package, a sys.path entry).
func moduleNames(module string) []string {
	segs := strings.Split(module, "/")
	names := make([]string, 0, len(segs))
	for i := range segs {
		names = append(names, strings.Join(segs[i:], "."))
	}
	return names
}

// reachesAny reports whether an import in refs may load a module imported under one of
// names: the name itself or something beneath it. A relative import climbing above the
// build root reaches everything. A star import from a package above a build script never
// loads it: the script's directory has no __init__.py to list it in __all__.
func reachesAny(refs []importRef, names []string) bool {
	for _, r := range refs {
		if r.unresolved {
			return true
		}
		for _, n := range names {
			if r.path == n || strings.HasPrefix(r.path, n+".") {
				return true
			}
		}
	}
	return false
}

// namedByEntryPoint reports whether any text names one of names as an entry-point object
// reference ("module:attr", as [project.scripts], setup.cfg and setup() entry_points write
// it). The match is lexical, so a stray "name:" keeps a script in rather than leaving it out.
func namedByEntryPoint(names, texts []string) bool {
	for _, n := range names {
		re := regexp.MustCompile(`(^|[^\w.])` + regexp.QuoteMeta(n) + `\s*:\s*[A-Za-z_]`)
		for _, t := range texts {
			if re.MatchString(t) {
				return true
			}
		}
	}
	return false
}

// mentionedByLauncher reports whether a launcher's text mentions stem as a whole word, as
// "python setup.py", "python -m pkg.setup" or a CMD array would. A mention for any other
// reason (a comment, "setup.py install" at image build time) keeps the script in too.
func mentionedByLauncher(stem string, launchers []string) bool {
	re := regexp.MustCompile(`(^|\W)` + regexp.QuoteMeta(stem) + `(\W|$)`)
	return slices.ContainsFunc(launchers, re.MatchString)
}

// loaders holds the text of the non-Python files that can load a module at runtime under
// buildDir: configs declare entry points (pyproject.toml, setup.cfg), and launchers start
// processes (Procfile, Dockerfile, Containerfile, compose files, shell scripts).
type loaders struct {
	configs   []string
	launchers []string
}

// readLoaders walks buildDir, skipping the directories the source walk skips. It returns
// nil when a file cannot be read or the walk fails.
func readLoaders(buildDir string) *loaders {
	ld := &loaders{configs: []string{}, launchers: []string{}}
	err := filepath.WalkDir(buildDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) && p != buildDir {
				return filepath.SkipDir
			}
			return nil
		}
		n := d.Name()
		config := n == "pyproject.toml" || n == "setup.cfg"
		if !config && !isLauncher(n) {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if config {
			ld.configs = append(ld.configs, string(data))
		} else {
			ld.launchers = append(ld.launchers, string(data))
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return ld
}

// isLauncher reports whether a file name is one that starts processes: a Procfile, a
// Dockerfile or Containerfile (Dockerfile.prod, api.dockerfile), a compose file, or a shell
// script.
func isLauncher(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == "procfile",
		strings.HasPrefix(n, "dockerfile"), strings.HasPrefix(n, "containerfile"),
		strings.HasSuffix(n, ".dockerfile"), strings.HasSuffix(n, ".containerfile"),
		strings.HasPrefix(n, "docker-compose"),
		strings.HasPrefix(n, "compose.") && (strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml")),
		strings.HasSuffix(n, ".sh"):
		return true
	}
	return false
}

// importRef is one module an import statement may load, made absolute against the
// importing file's package.
type importRef struct {
	path       string
	relative   bool // written as a relative import
	unresolved bool // a relative import climbing above the build root
}

// packageOf returns the package a module's relative imports resolve against: the module
// itself for a package __init__, else its parent.
func packageOf(module, path string) []string {
	var segs []string
	if module != "" {
		segs = strings.Split(module, "/")
	}
	if strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) == "__init__" || len(segs) == 0 {
		return segs
	}
	return segs[:len(segs)-1]
}

// importRefs returns the modules the import statements in lines may load: `import a.b`
// loads a.b, and `from m import x` loads m and, if x is a submodule, m.x (`from m import *`
// loads m). Relative imports resolve against pkg.
func importRefs(lines []logicalLine, pkg []string) []importRef {
	var refs []importRef
	for _, ll := range lines {
		for _, stmt := range strings.Split(ll.text, ";") {
			kw, rest := firstWord(strings.TrimSpace(stmt))
			switch kw {
			case "import":
				for _, item := range splitImportList(rest) {
					if path, _ := splitAlias(item); isDottedName(path) {
						refs = append(refs, importRef{path: path})
					}
				}
			case "from":
				from, tail, ok := strings.Cut(strings.TrimSpace(rest), " ")
				kw2, names := firstWord(tail)
				if !ok || kw2 != "import" {
					continue
				}
				refs = append(refs, fromRefs(from, splitImportList(names), pkg)...)
			}
		}
	}
	return refs
}

// fromRefs returns the refs of `from <from> import <names>`.
func fromRefs(from string, names []string, pkg []string) []importRef {
	level := len(from) - len(strings.TrimLeft(from, "."))
	mod := from[level:]
	if mod != "" && !isDottedName(mod) {
		return nil
	}
	base := mod
	if level > 0 {
		if level-1 > len(pkg) {
			return []importRef{{relative: true, unresolved: true}}
		}
		parts := slices.Clone(pkg[:len(pkg)-(level-1)])
		if mod != "" {
			parts = append(parts, mod)
		}
		base = strings.Join(parts, ".")
	}
	join := func(name string) string {
		if base == "" {
			return name
		}
		return base + "." + name
	}
	var refs []importRef
	if base != "" {
		refs = append(refs, importRef{path: base, relative: level > 0})
	}
	for _, item := range names {
		name, _ := splitAlias(item)
		if isDottedName(name) {
			refs = append(refs, importRef{path: join(name), relative: level > 0})
		}
	}
	return refs
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
			provides, dotted := boundaryTarget(cs.calleeChain, cs.scopes, f.bindings, prog.dists)
			for _, dist := range provides {
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
