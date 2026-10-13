package pythonanalysis

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
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

	build := buildScripts(parsed, buildDir)
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
// a file named in buildScriptBackends at the build root that imports one of its backends,
// with no __init__.py beside it. Build scripts run when the project is built, not when it
// runs, so their imports and calls are not runtime code. Only the build root counts, since
// that is where the backend looks for them; a file of that name anywhere else is ordinary
// code to whatever loads files from its directory.
//
// Leaving a file out can only make the program look like it loads less, so a script is
// left out only when nothing in the build tree could load it. scanBuildTree reads every
// file under buildDir; the script stays in when any other file mentions its stem, when any
// Python file loads code by path or computed name, when a relative import climbs above the
// build root, or when a string in its own text names it (an entry point or py_modules entry
// it declares about itself). Any file the scan can't read keeps every script.
func buildScripts(parsed []parsedFile, buildDir string) map[int]bool {
	root := filepath.Clean(buildDir)
	build := map[int]bool{}
	for i, pf := range parsed {
		backends, ok := buildScriptBackends[filepath.Base(pf.path)]
		if !ok || filepath.Dir(pf.path) != root {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "__init__.py")); err == nil {
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
	var stems []string
	for i := range build {
		stems = append(stems, scriptStem(parsed[i].path))
	}
	scan := scanBuildTree(root, stems)
	if scan == nil {
		return nil
	}
	for i := range build {
		own := filepath.Clean(parsed[i].path)
		stem := scriptStem(own)
		if scan.mentionedOutside(stem, own) || scan.loaderOutside(own) || namesItself(parsed[i].text, stem) {
			delete(build, i)
			continue
		}
		for j, pf := range parsed {
			if j != i && climbsAboveRoot(pf.refs) {
				delete(build, i)
				break
			}
		}
	}
	return build
}

// scriptStem is the module name a build script at the build root imports and runs under,
// lower-cased for matching.
func scriptStem(p string) string {
	return strings.ToLower(strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)))
}

// climbsAboveRoot reports whether a relative import in refs climbs above the build root,
// which could reach anything.
func climbsAboveRoot(refs []importRef) bool {
	return slices.ContainsFunc(refs, func(r importRef) bool { return r.unresolved })
}

// stemPattern matches stem as a whole word, ignoring case: "python SETUP.PY" runs the script
// on a case-insensitive filesystem.
func stemPattern(stem string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(^|[^0-9A-Za-z_])` + regexp.QuoteMeta(stem) + `($|[^0-9A-Za-z_])`)
}

// namesItself reports whether a string literal in a build script's own source mentions its
// stem: an entry point it declares about itself ("x = setup:main", "x = setup"), or a
// py_modules or scripts entry. The rest of its text always says "setup", so it can't count.
func namesItself(src, stem string) bool {
	re := stemPattern(stem)
	_, lits := stripPythonLiterals(src)
	for _, l := range lits {
		if re.MatchString(l.body) {
			return true
		}
	}
	return false
}

// maxScannedFile is the largest file scanBuildTree reads; a larger one keeps every script.
var maxScannedFile int64 = 8 << 20

// fileLoaderLeafs are callables that run or import code chosen at runtime by file path or
// by a computed name, so the scanner can't tell which module they load.
var fileLoaderLeafs = map[string]bool{
	"run_path":                true, // runpy
	"run_module":              true, // runpy
	"exec":                    true,
	"execfile":                true,
	"eval":                    true, // eval(compile(src, path, "exec"))
	"spec_from_file_location": true, // importlib.util
	"spec_from_loader":        true, // importlib.util
	"module_from_spec":        true, // importlib.util
	"exec_module":             true, // a loader
	"load_module":             true, // a loader, imp
	"SourceFileLoader":        true, // importlib.machinery
	"SourcelessFileLoader":    true, // importlib.machinery
	"load_source":             true, // imp
	"load_compiled":           true, // imp
	"load_package":            true, // imp
	"iter_modules":            true, // pkgutil
	"zipimporter":             true, // zipimport
}

// buildTreeScan is what scanBuildTree found that could load a build script.
type buildTreeScan struct {
	mentions map[string][]string // lower-case stem -> files mentioning it
	loaders  []string            // Python files that load code by path or computed name
}

func (s *buildTreeScan) mentionedOutside(stem, own string) bool {
	return slices.ContainsFunc(s.mentions[stem], func(p string) bool { return filepath.Clean(p) != own })
}

func (s *buildTreeScan) loaderOutside(own string) bool {
	return slices.ContainsFunc(s.loaders, func(p string) bool { return filepath.Clean(p) != own })
}

// scanBuildTree reads every file under root through the shared build-tree walk, recording
// which files mention each stem as a whole word and which Python files (by extension, a .pth
// file, or a python shebang) name a dynamic-import or file-loader callable anywhere, aliased
// imports included. It returns nil when any file can't be read in full: unreadable, larger
// than maxScannedFile, binary, a symlink leaving root, or a symlinked directory the walk
// doesn't read through its target. Any of those could hold the mention.
func scanBuildTree(root string, stems []string) *buildTreeScan {
	scan := &buildTreeScan{mentions: map[string][]string{}}
	patterns := map[string]*regexp.Regexp{}
	for _, s := range stems {
		patterns[s] = stemPattern(s)
	}
	match := func(p string, _ []byte) (string, bool) {
		data, why := readScanned(p)
		if why != "" {
			return why, true
		}
		text := string(data)
		for s, re := range patterns {
			if re.MatchString(text) {
				scan.mentions[s] = append(scan.mentions[s], p)
			}
		}
		if pythonText(p, text) && namesLoader(text) {
			scan.loaders = append(scan.loaders, p)
		}
		return "", false
	}
	if !buildTreeAllFullyRead(buildTreeCandidates(root, match, func(string) bool { return false })) {
		return nil
	}
	return scan
}

// readScanned reads the file at p whole. why is non-empty when it can't: unreadable, too
// large, or binary (a NUL byte).
func readScanned(p string) (data []byte, why string) {
	f, err := os.Open(p)
	if err != nil {
		return nil, "unreadable"
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, "unreadable"
	}
	if info.Size() > maxScannedFile {
		return nil, "too large to scan"
	}
	data, err = io.ReadAll(io.LimitReader(f, maxScannedFile+1))
	if err != nil {
		return nil, "unreadable"
	}
	if int64(len(data)) > maxScannedFile {
		return nil, "too large to scan"
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, "binary"
	}
	return data, ""
}

// pythonText reports whether the file at p holds Python the interpreter runs: a .py or .pyw
// source, a .pth file (its import lines run at startup), or a script with a python shebang.
func pythonText(p, text string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".py", ".pyw", ".pth":
		return true
	}
	first, _, _ := strings.Cut(text, "\n")
	return strings.HasPrefix(first, "#!") && strings.Contains(first, "python")
}

// namesLoader reports whether Python source names a dynamic-import or file-loader callable
// as an identifier outside comments and strings, called or not, so an aliased import
// ("from runpy import run_path as rp") counts.
func namesLoader(src string) bool {
	r := []rune(stripPython(src))
	for i := 0; i < len(r); {
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		if fileLoaderLeafs[w] || dynamicImportLiteralLeafs[w] || dynamicImportOpaqueLeafs[w] {
			return true
		}
		i = end
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
