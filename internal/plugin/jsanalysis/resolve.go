package jsanalysis

import (
	"encoding/json"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// resolutionKind discriminates the three terminal outcomes of resolving one call/ref.
// Exactly one is valid per resolution; the zero value is INVALID and never emitted.
type resolutionKind int

const (
	resolveFirstParty resolutionKind = iota + 1 // specifier resolved to an in-tree module + a unique in-module symbol
	resolvePackage                              // bare specifier resolved to a dependency (file NOT opened)
	resolveUnresolved                           // could not resolve; carries a partiality reason, no edge
)

// resolveAlgo names the algorithm that selected a resolved target (C5 provenance).
type resolveAlgo string

const (
	algoCJS        resolveAlgo = "cjs"               // Node CommonJS require() resolution
	algoESM        resolveAlgo = "esm"               // Node ESM import resolution
	algoExports    resolveAlgo = "exports_condition" // package.json "exports" conditional map (C1)
	algoImports    resolveAlgo = "imports"           // package.json "#…" imports map (C1)
	algoPathsAlias resolveAlgo = "paths_alias"       // tsconfig paths/baseUrl alias (C2)
	algoReExport   resolveAlgo = "re_export"         // followed an `export … from '…'` chain
	// algoLocal names same-module lexical resolution: a bare call / method / `this.`
	// reference whose target is declared in the importing module itself, with NO module
	// system consulted. It is ADDITIVE to the frozen §2 algo set, which enumerates only
	// specifier-resolution algorithms and does not cover the 9-of-17 baseline edges that
	// are same-module calls. C5 requires a non-empty Prov.Algo on EVERY resolved edge, so
	// same-module edges need an honest label rather than a mislabel as cjs/esm. Flagged as
	// frozen-contract friction in the final report.
	algoLocal resolveAlgo = "local"
	// algoBundlerAlias names a target selected because a bundler alias (webpack/vite/…
	// resolve.alias, rollup/babel module-resolver, SWC jsc.paths) rewrote the specifier
	// before module resolution ran. PLAN-163 EXPOSES the alias map carrying this producer
	// label at the resolver injection point (resolver.bctx) so the bundler is recorded as
	// the resolution's producer; PLAN-162 stamps this algo when it APPLIES an alias.
	// PLAN-163 does not apply aliases and so emits no edge under this algo this cycle.
	algoBundlerAlias resolveAlgo = "bundler_alias"
)

// provenance is the named rule that produced a resolved result (§2, C5).
type provenance struct {
	Algo       resolveAlgo // which algorithm selected the target; REQUIRED non-empty on every resolved edge
	Conditions []string    // the condition set applied, in order consulted; nil when none consulted
	Tsconfig   string      // path to the governing tsconfig.json when Algo==algoPathsAlias; "" otherwise
}

// resolution is the outcome of resolving ONE call/reference from ONE importing module.
type resolution struct {
	Kind       resolutionKind
	Module     string // resolved in-tree module id (informational); the edge endpoint is Target
	Target     string // callee SCIP id to connect the edge to; empty ⇒ no edge. Never synthesized.
	InstanceID string // PLAN-160 DependencyNode.ID a bare specifier resolves TO ("" when unknown)
	Subpath    string // selected subpath within a package ("." | "./client" | …)
	Reason     string // a PartialReason* code; non-empty for resolvePackage and resolveUnresolved
	Prov       provenance
}

// edge reports whether this resolution emits a call-graph edge and to which target.
func (r resolution) edge() (string, bool) {
	return r.Target, r.Kind == resolveFirstParty && r.Target != ""
}

func unresolvedWith(reason string) resolution {
	return resolution{Kind: resolveUnresolved, Reason: reason}
}

// Resolver resolves lexical names in a module's scope to concrete in-tree declarations,
// using that module's bindings + the CJS/ESM/exports/imports/paths algorithm over the
// whole-program index. It never opens node_modules source (it reads an installed
// package.json for its exports map) and never executes source.
type Resolver interface {
	// ResolveCall resolves a bare call `name(arity)` occurring in fromModule.
	ResolveCall(fromModule string, name string, arity int) resolution
	// ResolveRef resolves a handler REFERENCE `name` (no call, no arity) in fromModule.
	ResolveRef(fromModule string, name string) resolution
}

// resolver is the concrete Resolver over a parsed program.
type resolver struct {
	prog *program
	// bctx is the PLAN-163 build context exposed at this injection point: the bundler
	// alias/define map (each entry carrying its producing tool + config file, §3.5),
	// declared cross-config conflicts (C5), entry points, and server-side roots. It is
	// the field/hook PLAN-162's resolver consults to apply an alias before module
	// resolution and to stamp algoBundlerAlias as the producer. PLAN-163 PRODUCES and
	// EXPOSES it; it does NOT apply it — the resolution methods below are unchanged this
	// cycle. Consult it via lookupAlias.
	bctx *buildContext
	// packageOnly keeps every bare specifier a package resolution even when dependency code is
	// read, so boundary nodes are still traced through it.
	packageOnly bool
}

// resolver constructs the resolver at PLAN-162's injection point, wiring in the exposed
// PLAN-163 build context (bundler alias/define map with provenance and declared
// conflicts). The build context is computed once per program and cached: reading the
// static bundler configs is idempotent and executes nothing (C4).
func (p *program) resolver() *resolver {
	if p.buildCtx == nil {
		bc := buildContextFor(p.root)
		p.buildCtx = &bc
	}
	return &resolver{prog: p, bctx: p.buildCtx}
}

// ResolveCall implements the contract's name+arity entry point (a receiver-less bare
// call). Receiver-based method calls run through resolveCallSite, which the call graph
// uses directly (the contract's ResolveCall signature does not carry receiver context;
// see the final report's frozen-contract friction note).
func (rs *resolver) ResolveCall(fromModule, name string, arity int) resolution {
	return rs.resolveName(fromModule, name, arity)
}

// ResolveRef implements the contract's name-only entry point: an arity-free reference,
// resolved against the module's bindings then its local declarations.
func (rs *resolver) ResolveRef(fromModule, name string) resolution {
	return rs.resolveName(fromModule, name, -1)
}

// resolveCallSite resolves one call site, dispatching on receiver context: `this.m()`
// to an enclosing-class method, `recv.m()` to a method of recv's instantiated class,
// and a bare `m()` to a binding or a same-module declaration.
func (rs *resolver) resolveCallSite(fromModule string, cs callSite) resolution {
	var r resolution
	switch {
	case cs.receiverThis:
		r = rs.resolveThisMethod(fromModule, cs.callerEnclosing, cs.calleeName, cs.calleeArity)
	case cs.receiver != "":
		r = rs.resolveReceiverMethod(fromModule, cs.receiver, cs.calleeName, cs.calleeArity)
	default:
		r = rs.resolveName(fromModule, cs.calleeName, cs.calleeArity)
	}
	if r.Kind == resolveUnresolved && cs.head != "" {
		if pkg, ok := rs.packageHead(fromModule, cs.head); ok {
			return pkg
		}
	}
	return r
}

// packageHead reports whether head (the first segment of a member-call chain such as
// JSON5.parse) is an import binding to a package outside the tree. Such a call enters
// code this lane does not open, so it is attributed as an uninspectable package rather
// than an unresolved name: the call runs dependency code even though no edge is drawn.
func (rs *resolver) packageHead(fromModule, head string) (resolution, bool) {
	mi := rs.prog.modules[fromModule]
	if mi == nil || mi.bindings.ambiguous[head] {
		return resolution{}, false
	}
	b, ok := mi.bindings.imports[head]
	if !ok || strings.HasPrefix(b.Specifier, "#") || isRelativeLoad(b.Specifier) {
		return resolution{}, false
	}
	algo := algoESM
	if b.Kind == bindRequire {
		algo = algoCJS
	}
	r := rs.resolveBareSpecifier(fromModule, b.Specifier, b.Imported, -1, algo)
	return r, r.Kind == resolvePackage
}

// loadsOutOfTree reports whether a literal specifier written in fromModule loads code from
// outside the tree: a bare specifier that no tsconfig paths alias or workspace member claims,
// one a paths alias claims but Node resolves elsewhere (pathsShadowed), or a `#…` subpath import or workspace member whose selectable targets are not all the
// in-tree module call edges are built into (edgeModule). viaRequire marks a require() load (see loadConditions). Loading a module runs its
// top-level code, so the run executes code this lane does not open however the binding, if
// any, is used afterwards.
func (rs *resolver) loadsOutOfTree(fromModule, spec string, viaRequire bool) bool {
	conds := loadConditions(viaRequire)
	switch {
	case isRelativeLoad(spec):
		return false
	case strings.HasPrefix(spec, "#"):
		pkg, pkgDir := rs.governingPackageJSON(fromModule)
		if pkg == nil || pkg.imports == nil {
			return true
		}
		targets := exportsTargets(pkg.imports, spec, conds)
		edge := rs.edgeModule(pkg.imports, spec, pkgDir)
		for _, t := range targets {
			if !isRelativeTarget(t) {
				// a `#…` chain or a package: edges are never built through either
				// (resolveImportsSubpath), so its calls are missed even when it is in-tree
				return true
			}
			if m := rs.moduleFromDirRelative(pkgDir, t); m == "" || m != edge {
				return true
			}
		}
		return len(targets) == 0
	}
	if _, _, ok := rs.resolveTsPaths(fromModule, spec); ok {
		return rs.pathsShadowed(fromModule, spec)
	}
	dir, mm, sub, ok := rs.workspaceMember(spec)
	if !ok || rs.memberShadowed(fromModule, mm.name, dir) {
		return true
	}
	var targets []string
	edge, _, _ := rs.resolveWorkspaceMember(fromModule, spec)
	switch {
	case mm.exports != nil:
		targets = exportsTargets(mm.exports, sub, conds)
	case sub != ".":
		return true
	case mm.main != "":
		targets = []string{mm.main}
	default:
		targets = []string{"index"}
	}
	for _, t := range targets {
		if m := rs.moduleFromDirRelative(dir, t); m == "" || m != edge {
			return true
		}
	}
	return len(targets) == 0
}

// pathsShadowed reports whether Node loads something other than the in-tree target of the
// tsconfig `paths` alias that claims bare specifier spec. tsc does not rewrite the specifier
// and Node ignores `paths`, so at run time Node resolves it itself: to a core module, to the
// governing package's own exports (self-reference), or to whatever its node_modules walk
// finds. Any of those, or a node_modules candidate that cannot be stat'ed, keeps the limit.
func (rs *resolver) pathsShadowed(fromModule, spec string) bool {
	if isNodeBuiltin(spec) {
		return true
	}
	name, _ := splitBareSpecifier(spec)
	if self, _ := rs.governingPackageJSON(fromModule); self != nil && self.name != "" && self.name == name && self.exports != nil {
		return true
	}
	return rs.nodeModulesHas(fromModule, name)
}

// nodeModulesHas reports whether Node's node_modules walk from fromModule's directory to the
// filesystem root finds any candidate for package name: the package directory (with or
// without a package.json) or a file Node's CommonJS LOAD_AS_FILE would try. Node walks the
// ancestors of the importer's real path, or of its path as given under
// --preserve-symlinks(-main), so both chains are walked: they differ when an ancestor of the
// build root, or the importer file itself, is a symlink. Above the build root (a workspace member whose node_modules is
// hoisted to the repository root) only Lstat runs; nothing there is read. A stat or
// symlink-resolution error other than a missing path counts as found.
func (rs *resolver) nodeModulesHas(fromModule, name string) bool {
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `\:`) {
		return true
	}
	has := func(dir string) bool {
		if filepath.Base(dir) == "node_modules" {
			return false
		}
		base := filepath.Join(dir, "node_modules", filepath.FromSlash(name))
		for _, cand := range []string{base, base + ".js", base + ".json", base + ".node"} {
			if _, err := os.Lstat(cand); err == nil || !absent(err) {
				return true
			}
		}
		return false
	}
	dir := path.Dir(fromModule)
	for {
		if dir == "." {
			dir = ""
		}
		if has(filepath.Join(rs.prog.root, filepath.FromSlash(dir))) {
			return true
		}
		if dir == "" {
			break
		}
		dir = path.Dir(dir)
	}
	root, err := filepath.Abs(rs.prog.root)
	if err != nil {
		return true
	}
	ancestorsHave := func(dir string) bool {
		for ; ; dir = filepath.Dir(dir) {
			if has(dir) {
				return true
			}
			if dir == filepath.Dir(dir) {
				return false
			}
		}
	}
	if ancestorsHave(filepath.Dir(root)) {
		return true
	}
	files := rs.prog.sources[fromModule]
	if len(files) == 0 {
		return true
	}
	for _, f := range files {
		abs, err := filepath.Abs(f)
		if err != nil {
			return true
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			if !absent(err) {
				return true
			}
			continue
		}
		if ancestorsHave(filepath.Dir(real)) {
			return true
		}
	}
	return false
}

// loadMeetsUnmodeledCondition reports whether resolving a literal specifier passes through an
// exports/imports conditions map with any key outside loadConditions, "types" included: a
// `#…` subpath import (and any package it maps to), or the exports of the package a bare
// specifier names (a workspace member, the governing package itself, or the installed
// package Node's node_modules walk finds). Node can select that branch (`node
// --conditions=development`), loading a file whose calls the lane did not follow. This is
// stricter than loadsOutOfTree, which declares only when such a branch selects a module other
// than edgeModule, ignores a declaration-only "types" branch, and stops at a tsconfig `paths`
// alias. A `paths` alias does not end this check: tsc does not rewrite the specifier, so at
// run time Node resolves it itself. Only the manifest is read; an uninstalled package has
// none, and one that cannot be read safely keeps the limit.
func (rs *resolver) loadMeetsUnmodeledCondition(fromModule, spec string) bool {
	conds := loadConditions(false)
	switch {
	case isRelativeLoad(spec):
		return false
	case strings.HasPrefix(spec, "#"):
		pkg, _ := rs.governingPackageJSON(fromModule)
		if pkg == nil || pkg.imports == nil {
			return false
		}
		if subpathHasUnmodeledCondition(pkg.imports, spec, conds) {
			return true
		}
		for _, t := range exportsTargets(pkg.imports, spec, conds) {
			if !isRelativeTarget(t) && !strings.HasPrefix(t, "#") && rs.loadMeetsUnmodeledCondition(fromModule, t) {
				return true
			}
		}
		return false
	}
	if _, mm, sub, ok := rs.workspaceMember(spec); ok {
		return mm.exports != nil && subpathHasUnmodeledCondition(mm.exports, sub, conds)
	}
	name, sub := splitBareSpecifier(spec)
	if self, _ := rs.governingPackageJSON(fromModule); self != nil && self.name != "" && self.name == name && self.exports != nil {
		return subpathHasUnmodeledCondition(self.exports, sub, conds)
	}
	mm, unsafe := rs.installedManifest(fromModule, name)
	if unsafe {
		return true
	}
	return mm != nil && mm.exports != nil && subpathHasUnmodeledCondition(mm.exports, sub, conds)
}

// maxInstalledManifest bounds the read of an installed package.json.
const maxInstalledManifest = 1 << 20

// installedManifest returns the package.json of npm package name that Node's node_modules
// walk from fromModule's directory finds, or nil when none is installed. unsafe reports a
// candidate it will not read: one whose real path leaves the build root, that is not a
// regular file, or that exceeds maxInstalledManifest, and one whose stat fails with an error
// other than a missing path.
func (rs *resolver) installedManifest(fromModule, name string) (mm *pkgManifest, unsafe bool) {
	if name == "" || strings.ContainsAny(name, `\:`) || strings.Count(name, "/") > 1 || strings.Contains(name, "..") ||
		(strings.Contains(name, "/") && !strings.HasPrefix(name, "@")) {
		return nil, false
	}
	dir := path.Dir(fromModule)
	for {
		if dir == "." {
			dir = ""
		}
		if path.Base(dir) != "node_modules" {
			full := filepath.Join(rs.prog.root, filepath.FromSlash(dir), "node_modules", filepath.FromSlash(name), "package.json")
			_, err := os.Lstat(full)
			switch {
			case err == nil:
				data, ok := readInRoot(rs.prog.root, full, maxInstalledManifest)
				if !ok {
					return nil, true
				}
				return parsePkgManifest(data), false
			case !absent(err):
				return nil, true
			}
		}
		if dir == "" {
			return nil, false
		}
		dir = path.Dir(dir)
	}
}

// subpathHasUnmodeledCondition reports whether any conditions map exportsTargets would walk
// for subpath has a key outside conds.
func subpathHasUnmodeledCondition(field interface{}, subpath string, conds map[string]bool) bool {
	for _, e := range subpathEntries(field, subpath) {
		if hasUnmodeledCondition(e.node, conds) {
			return true
		}
	}
	return false
}

func hasUnmodeledCondition(node interface{}, conds map[string]bool) bool {
	switch v := node.(type) {
	case []interface{}:
		for _, e := range v {
			if hasUnmodeledCondition(e, conds) {
				return true
			}
		}
	case map[string]interface{}:
		for k, sub := range v {
			if !conds[k] || hasUnmodeledCondition(sub, conds) {
				return true
			}
		}
	}
	return false
}

// edgeModule is the in-tree module call edges are built into for subpath of an imports or
// exports field under the resolver's fixed conditions (rs.conditions), or "" when there is
// none. A load whose selectable target is another module runs code this lane reads but
// builds no edges into, so loadsOutOfTree declares it.
func (rs *resolver) edgeModule(field interface{}, subpath, dir string) string {
	rel, _, ok := resolveExportsField(field, subpath, rs.conditions())
	if !ok || !isRelativeTarget(rel) {
		return ""
	}
	return rs.moduleFromDirRelative(dir, rel)
}

// loadConditions is the set of Node's default exports/imports conditions a load can match.
// Node's defaults are "node", "import", "require", "default", "module-sync" and, unless
// --no-addons, "node-addons" (nodejs.org/api/packages.html#conditional-exports); this lane
// treats all of them as matching. A require() load matches "require"; any other form may
// match "require" or "import", because a transpiler can emit ESM syntax as require(). Any
// condition outside Node's defaults ("development", "browser", "worker", a bundler's or a
// framework's own) is selectable too (see conditionSelectable).
func loadConditions(viaRequire bool) map[string]bool {
	conds := map[string]bool{"node": true, "node-addons": true, "module-sync": true, "default": true, "require": true}
	if !viaRequire {
		conds["import"] = true
	}
	return conds
}

// exportsTargets returns every target an exports/imports field can select for subpath under
// conds. Node takes the first matching key in the JSON object's order, which parsing loses,
// so every branch whose condition is in conds counts, as does each matching pattern and each
// fallback-array entry. A subpath the field does not expose yields no target.
func exportsTargets(field interface{}, subpath string, conds map[string]bool) []string {
	var out []string
	for _, e := range subpathEntries(field, subpath) {
		for _, t := range conditionTargets(e.node, conds, nil) {
			if e.pattern {
				t = strings.ReplaceAll(t, "*", e.star)
			}
			out = append(out, t)
		}
	}
	return out
}

// subpathEntry is one node of an exports/imports field that a subpath selects; star is the
// text a pattern key's "*" stands for.
type subpathEntry struct {
	node    interface{}
	pattern bool
	star    string
}

// subpathEntries returns the nodes of an exports/imports field that subpath selects: the
// whole field for "." when it is a target or a conditions map, else the exact key, else every
// matching pattern key.
func subpathEntries(field interface{}, subpath string) []subpathEntry {
	m, isMap := field.(map[string]interface{})
	if !isMap || isConditionsMap(m) {
		if subpath != "." {
			return nil
		}
		return []subpathEntry{{node: field}}
	}
	if node, ok := m[subpath]; ok {
		return []subpathEntry{{node: node}}
	}
	var out []subpathEntry
	for key, node := range m {
		prefix, suffix, ok := strings.Cut(key, "*")
		if !ok || len(subpath) < len(prefix)+len(suffix) || !strings.HasPrefix(subpath, prefix) || !strings.HasSuffix(subpath, suffix) {
			continue
		}
		out = append(out, subpathEntry{node: node, pattern: true, star: subpath[len(prefix) : len(subpath)-len(suffix)]})
	}
	return out
}

// conditionSelectable reports whether the branch under condition key k can be the one a load
// runs. A key in conds matches by default. A key outside Node's defaults matches whenever the
// run sets it (node --conditions, a bundler, a test runner), which the build tree does not
// record, so it counts as selectable too and each of its targets must be in-tree. A "types"
// branch naming only declaration files is read by type checkers and never loaded.
func conditionSelectable(k string, sub interface{}, conds map[string]bool) bool {
	switch k {
	case "node", "node-addons", "module-sync", "default", "require", "import":
		return conds[k]
	case "types":
		return !declarationOnly(sub)
	}
	return true
}

// declarationOnly reports whether node names at least one target, under any condition, and
// every one is a TypeScript declaration file.
func declarationOnly(node interface{}) bool {
	switch v := node.(type) {
	case string:
		return strings.HasSuffix(v, ".d.ts") || strings.HasSuffix(v, ".d.mts") || strings.HasSuffix(v, ".d.cts")
	case []interface{}:
		for _, e := range v {
			if !declarationOnly(e) {
				return false
			}
		}
		return len(v) > 0
	case map[string]interface{}:
		for _, sub := range v {
			if !declarationOnly(sub) {
				return false
			}
		}
		return len(v) > 0
	}
	return false
}

func conditionTargets(node interface{}, conds map[string]bool, out []string) []string {
	switch v := node.(type) {
	case string:
		out = append(out, v)
	case []interface{}:
		for _, e := range v {
			out = conditionTargets(e, conds, out)
		}
	case map[string]interface{}:
		for k, sub := range v {
			if conditionSelectable(k, sub, conds) {
				out = conditionTargets(sub, conds, out)
			}
		}
	}
	return out
}

// loadsUnreadModule reports whether a relative specifier names no in-tree source module: a
// native addon, a file generated at build time, anything outside the parsed source set. Its
// code runs on load and can itself load packages, yet this lane never reads it. A JSON file
// is data and runs nothing, and so, under stock tooling, is a stylesheet in the build tree.
func (rs *resolver) loadsUnreadModule(fromModule, spec string) bool {
	if !isRelativeLoad(spec) || rs.resolveRelative(fromModule, spec) != "" {
		return false
	}
	ext := path.Ext(spec)
	if ext == ".json" {
		return false
	}
	if rs.stylesheetRunsNoCode(fromModule, path.Join(path.Dir(fromModule), spec)) {
		return false
	}
	// TS sources import siblings by their emitted name ("./util.js" for util.ts).
	return !jsExtensions[ext] || rs.resolveRelative(fromModule, strings.TrimSuffix(spec, ext)) == ""
}

// stylesheetImport reports whether spec is a relative import of a stylesheet that
// stylesheetRunsNoCode exempts from unresolved_module; the caller declares its loader runtime.
func (rs *resolver) stylesheetImport(fromModule, spec string) bool {
	return isRelativeLoad(spec) && stylesheetExtensions[path.Ext(spec)] &&
		rs.resolveRelative(fromModule, spec) == "" &&
		rs.stylesheetRunsNoCode(fromModule, path.Join(path.Dir(fromModule), spec))
}

// resolveName resolves a bare name (arity<0 means arity-free reference) via the module's
// import bindings, then its local module-level declarations.
func (rs *resolver) resolveName(fromModule, name string, arity int) resolution {
	mi := rs.prog.modules[fromModule]
	if mi == nil {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	if mi.bindings.ambiguous[name] {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	if b, ok := mi.bindings.imports[name]; ok {
		return rs.resolveBinding(fromModule, b, arity)
	}
	if decls, ok := mi.funcs[name]; ok {
		return rs.pickFunc(fromModule, decls, arity, provenance{Algo: algoLocal})
	}
	return unresolvedWith(plugin.PartialReasonDynamicDispatch)
}

// resolveThisMethod resolves `this.name(arity)` to a method of the caller's innermost
// enclosing class in fromModule.
func (rs *resolver) resolveThisMethod(fromModule string, callerEnclosing []string, name string, arity int) resolution {
	if len(callerEnclosing) == 0 {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	class := callerEnclosing[len(callerEnclosing)-1]
	return rs.lookupMethod(fromModule, class, name, arity, provenance{Algo: algoLocal})
}

// resolveReceiverMethod resolves `recv.name(arity)` where recv is a local variable bound
// to `new Class()`. The class may be declared locally (algoLocal) or imported (algoCJS/
// algoESM). A receiver that is not a tracked instance declines (fail-closed).
func (rs *resolver) resolveReceiverMethod(fromModule, receiver, name string, arity int) resolution {
	mi := rs.prog.modules[fromModule]
	if mi == nil {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	class, ok := mi.bindings.instances[receiver]
	if !ok {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	if mi.classes[class] {
		return rs.lookupMethod(fromModule, class, name, arity, provenance{Algo: algoLocal})
	}
	if b, ok := mi.bindings.imports[class]; ok {
		target, algo := rs.resolveModuleOfBinding(fromModule, b)
		if target != "" {
			return rs.lookupMethod(target, b.Imported, name, arity, provenance{Algo: algo})
		}
	}
	return unresolvedWith(plugin.PartialReasonDynamicDispatch)
}

// lookupMethod resolves method name(arity) of className within module.
func (rs *resolver) lookupMethod(module, className, name string, arity int, prov provenance) resolution {
	mi := rs.prog.modules[module]
	if mi == nil {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	methods, ok := mi.methods[className]
	if !ok {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	decls, ok := methods[name]
	if !ok {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	return rs.pickFunc(module, decls, arity, prov)
}

// resolveBinding turns one import/require binding into a resolution: relative specifiers
// resolve first-party (extension/index), `#…` specifiers via the local imports map, and
// bare specifiers via tsconfig paths / workspace exports, else declined-but-attributed
// as an uninspectable package.
func (rs *resolver) resolveBinding(fromModule string, b binding, arity int) resolution {
	spec := b.Specifier
	algo := algoESM
	if b.Kind == bindRequire {
		algo = algoCJS
	}
	switch {
	case strings.HasPrefix(spec, "#"):
		return rs.resolveImportsSubpath(fromModule, spec, b.Imported, arity)
	case isRelativeLoad(spec):
		target := rs.resolveRelative(fromModule, spec)
		if target == "" {
			return unresolvedWith(plugin.PartialReasonDynamicDispatch)
		}
		return rs.lookupImportedName(target, b.Imported, arity, provenance{Algo: algo})
	default:
		return rs.resolveBareSpecifier(fromModule, spec, b.Imported, arity, algo)
	}
}

// resolveBareSpecifier resolves a bare (package) specifier: first a governing tsconfig
// paths alias (first-party), then a workspace member's exports (first-party), else a
// declined-but-attributed uninspectable package (never an edge).
func (rs *resolver) resolveBareSpecifier(fromModule, spec, imported string, arity int, algo resolveAlgo) resolution {
	if target, tsPath, ok := rs.resolveTsPaths(fromModule, spec); ok {
		return rs.lookupImportedName(target, imported, arity, provenance{Algo: algoPathsAlias, Tsconfig: tsPath})
	}
	if target, conds, ok := rs.resolveWorkspaceMember(fromModule, spec); ok {
		return rs.lookupImportedName(target, imported, arity, provenance{Algo: algoExports, Conditions: conds})
	}
	if rs.prog.deps != nil && !rs.packageOnly {
		return rs.resolveDepBare(fromModule, spec, imported, arity, algo)
	}
	return resolution{
		Kind:    resolvePackage,
		Subpath: bareSubpath(spec),
		Reason:  plugin.PartialReasonUninspectablePackage,
		Prov:    provenance{Algo: algo},
	}
}

// resolveImportsSubpath resolves a `#…` specifier against the governing package.json
// "imports" map, then looks up the imported name in the resolved first-party module.
func (rs *resolver) resolveImportsSubpath(fromModule, spec, imported string, arity int) resolution {
	pkg, pkgDir := rs.governingPackageJSON(fromModule)
	if pkg == nil || pkg.imports == nil {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	rel, conds, ok := resolveExportsField(pkg.imports, spec, rs.conditions())
	if !ok {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	target := rs.moduleFromDirRelative(pkgDir, rel)
	if target == "" {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	return rs.lookupImportedName(target, imported, arity, provenance{Algo: algoImports, Conditions: conds})
}

// lookupImportedName resolves the imported member `name` within a resolved first-party
// module, following `export … from` re-exports. A default/namespace import has no single
// named target this cycle and declines (fail-closed).
func (rs *resolver) lookupImportedName(module, imported string, arity int, prov provenance) resolution {
	if imported == "default" || imported == "*" || imported == "" {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	return rs.lookupInModule(module, imported, arity, prov, 0)
}

// lookupInModule finds a function `name`(arity) declared in module, following re-export
// chains up to a small depth bound.
func (rs *resolver) lookupInModule(module, name string, arity int, prov provenance, depth int) resolution {
	mi := rs.prog.modules[module]
	if mi == nil {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	if decls, ok := mi.funcs[name]; ok {
		return rs.pickFunc(module, decls, arity, prov)
	}
	if depth < 8 {
		if re, ok := mi.bindings.reExports[name]; ok {
			if t := rs.resolveModuleOfSpecifier(module, re.Specifier); t != "" {
				return rs.lookupInModule(t, re.Imported, arity, provenance{Algo: algoReExport}, depth+1)
			}
		}
		for _, star := range mi.bindings.reExportStars {
			if t := rs.resolveModuleOfSpecifier(module, star); t != "" {
				if r := rs.lookupInModule(t, name, arity, provenance{Algo: algoReExport}, depth+1); r.Kind == resolveFirstParty {
					return r
				}
			}
		}
	}
	return unresolvedWith(plugin.PartialReasonDynamicDispatch)
}

// pickFunc selects the single declaration matching arity (arity<0 matches any). Zero or
// more-than-one matches decline (fail-closed), preserving the soundness invariant.
func (rs *resolver) pickFunc(module string, decls []funcDecl, arity int, prov provenance) resolution {
	var match *funcDecl
	count := 0
	for i := range decls {
		if arity < 0 || decls[i].arity == arity {
			match = &decls[i]
			count++
		}
	}
	if count != 1 {
		return unresolvedWith(plugin.PartialReasonDynamicDispatch)
	}
	return resolution{Kind: resolveFirstParty, Module: module, Target: match.scip(), Prov: prov}
}

// resolveModuleOfBinding resolves the target MODULE of a binding (used for a class import
// in receiver-based method resolution), returning the module and the algo that applies.
func (rs *resolver) resolveModuleOfBinding(fromModule string, b binding) (string, resolveAlgo) {
	algo := algoESM
	if b.Kind == bindRequire {
		algo = algoCJS
	}
	if isRelativeLoad(b.Specifier) {
		return rs.resolveRelative(fromModule, b.Specifier), algo
	}
	if target, _, ok := rs.resolveWorkspaceMember(fromModule, b.Specifier); ok {
		return target, algoExports
	}
	if target, _, ok := rs.resolveTsPaths(fromModule, b.Specifier); ok {
		return target, algoPathsAlias
	}
	return rs.depModuleOfSpecifier(fromModule, b.Specifier, b.Kind == bindRequire), algo
}

// resolveModuleOfSpecifier resolves a specifier (relative or bare-first-party) to an
// in-tree module, for re-export following.
func (rs *resolver) resolveModuleOfSpecifier(fromModule, spec string) string {
	if isRelativeLoad(spec) {
		return rs.resolveRelative(fromModule, spec)
	}
	if target, _, ok := rs.resolveWorkspaceMember(fromModule, spec); ok {
		return target
	}
	if target, _, ok := rs.resolveTsPaths(fromModule, spec); ok {
		return target
	}
	return rs.depModuleOfSpecifier(fromModule, spec, false)
}

// resolveRelative resolves a relative specifier against fromModule's directory the way Node's
// CommonJS loader does: a file first (the module set is extension-stripped), then the directory
// (dirModule). A specifier Node treats as naming a directory (".", "..", or one ending in "/",
// "/." or "/..") skips the file step. A candidate above the build root resolves to nothing.
func (rs *resolver) resolveRelative(fromModule, spec string) string {
	dir := path.Dir(fromModule)
	if dir == "." {
		dir = ""
	}
	cand := path.Join(dir, spec)
	cand = strings.TrimPrefix(cand, "./")
	if cand == ".." || strings.HasPrefix(cand, "../") {
		return ""
	}
	if cand == "." {
		cand = ""
	}
	if !namesDirectory(spec) {
		// Vue SFC specifiers are, by tooling convention, always written with the extension
		// ("./App.vue"); strip it so the candidate matches the `.vue`-stripped module id.
		// Extensionless specifiers (the JS/TS norm) are unaffected.
		file := cand
		if path.Ext(file) == vueExtension {
			file = strings.TrimSuffix(file, vueExtension)
		}
		if rs.prog.moduleSet[file] {
			return file
		}
		// Package code commonly requires a sibling by its file name ("./lib/parse.js").
		if stripped := stripJSExt(file); rs.prog.deps.owns(fromModule) && rs.prog.moduleSet[stripped] {
			return stripped
		}
	}
	return rs.dirModule(cand)
}

// namesDirectory reports whether Node's CommonJS loader resolves spec as a directory only,
// never trying it as a file: ".", "..", or a specifier ending in "/", "/." or "/..".
func namesDirectory(spec string) bool {
	return spec == "." || spec == ".." || strings.HasSuffix(spec, "/") ||
		strings.HasSuffix(spec, "/.") || strings.HasSuffix(spec, "/..")
}

// dirModule is the module Node's LOAD_AS_DIRECTORY selects for build-root-relative dir: the
// file its package.json "main" names, else dir/index. A main that selects no parsed module
// resolves to nothing rather than falling back to index: Node falls back only when the main
// file is missing, which the module set cannot tell apart from a main naming a file the lane
// did not parse. So does a directory whose package.json cannot be read (dirMain).
func (rs *resolver) dirModule(dir string) string {
	main, ok := rs.dirMain(dir)
	switch {
	case !ok:
		return ""
	case main != "":
		return rs.depModuleAt(dir, main)
	}
	idx := path.Join(dir, "index")
	if rs.prog.moduleSet[idx] {
		return idx
	}
	return ""
}

// dirMain returns the "main" of the package.json in build-root-relative dir ("" when there is
// none, or it names no main). ok is false when the lane cannot know it: a package.json inside a
// read dependency package below its root (the tarball's file list shows it, but only the root
// manifest is kept), any directory under node_modules that is not a read package's root (whose
// files the lane never reads from disk), or a first-party package.json that cannot be read or
// parsed.
func (rs *resolver) dirMain(dir string) (string, bool) {
	if d := rs.prog.deps; d != nil {
		if p := d.pkgs[dir]; p != nil {
			if p.manifest == nil {
				return "", false
			}
			return p.manifest.main, true
		}
		if ip := installPathOf(dir + "/x"); ip != "" {
			p := d.pkgs[ip]
			if p == nil || p.files[strings.TrimPrefix(dir, ip+"/")+"/package.json"] {
				return "", false
			}
			return "", true
		}
	}
	if underNodeModules(dir) {
		return "", false
	}
	if rs.prog.dirMains == nil {
		rs.prog.dirMains = map[string]dirMainEntry{}
	}
	if e, ok := rs.prog.dirMains[dir]; ok {
		return e.main, e.ok
	}
	e := dirMainEntry{ok: true}
	data, err := readRegular(filepath.Join(rs.prog.root, filepath.FromSlash(dir), "package.json"))
	switch {
	case err == nil:
		if m := parsePkgManifest(data); m != nil {
			e.main = m.main
		} else {
			e.ok = false
		}
	case !absent(err):
		rs.prog.readFailed = true
		e.ok = false
	}
	rs.prog.dirMains[dir] = e
	return e.main, e.ok
}

// dirMainEntry caches one first-party directory's dirMain answer.
type dirMainEntry struct {
	main string
	ok   bool
}

// underNodeModules reports whether build-root-relative dir is a node_modules directory or lies
// inside one.
func underNodeModules(dir string) bool {
	return dir == "node_modules" || strings.HasPrefix(dir, "node_modules/") ||
		strings.HasSuffix(dir, "/node_modules") || strings.Contains(dir, "/node_modules/")
}

// matchModule returns the module path when cand (or cand/index) is an in-tree module.
func (rs *resolver) matchModule(cand string) string {
	if rs.prog.moduleSet[cand] {
		return cand
	}
	if idx := path.Join(cand, "index"); rs.prog.moduleSet[idx] {
		return idx
	}
	return ""
}

// moduleFromDirRelative resolves a path relative to a package/tsconfig directory (a
// build-root-relative dir) into an in-tree module.
func (rs *resolver) moduleFromDirRelative(baseDir, rel string) string {
	rel = strings.TrimPrefix(rel, "./")
	cand := path.Join(baseDir, rel)
	cand = stripJSExt(cand)
	return rs.matchModule(cand)
}

// conditions is the declared condition set the resolver evaluates exports/imports maps
// under. It is a fixed, declared set (never derived by running Node); C1's control flips
// it in-test via the exported resolveExportsField.
func (rs *resolver) conditions() []string {
	return []string{"import", "node", "default"}
}

// isRelativeLoad reports whether a specifier written in source resolves against the loading
// file's directory: ".", "..", or a "./" or "../" prefix. This is Node's ESM rule, and its
// CommonJS rule except for a specifier such as "..foo", which CommonJS loads as a file and ESM
// rejects as an invalid package name (see validNPMName for how dependency code accounts for it).
func isRelativeLoad(spec string) bool {
	return spec == "." || spec == ".." || isRelativeTarget(spec)
}

// isRelativeTarget reports whether a package.json exports, imports or browser target is a path
// inside the package. Node requires such a target to start with "./" and rejects "." and "..",
// so this is stricter than isRelativeLoad.
func isRelativeTarget(spec string) bool {
	return strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../")
}

// bareSubpath returns the subpath a bare specifier addresses within its package:
// "lodash" → ".", "lodash/fp" → "./fp", "@scope/pkg/sub" → "./sub".
func bareSubpath(spec string) string {
	parts := strings.SplitN(spec, "/", 2)
	if strings.HasPrefix(spec, "@") {
		parts = strings.SplitN(spec, "/", 3)
		if len(parts) < 3 || parts[2] == "" {
			return "."
		}
		return "./" + parts[2]
	}
	if len(parts) < 2 || parts[1] == "" {
		return "."
	}
	return "./" + parts[1]
}

func stripJSExt(p string) string {
	if ext := path.Ext(p); isSourceExt(ext) {
		return strings.TrimSuffix(p, ext)
	}
	return p
}

// --- package.json / tsconfig loading (metadata only; never node_modules source, which
// installedManifest reads only for an installed package.json's exports map) ---

// pkgManifest is the resolver's view of a package.json: identity, module type, and the
// raw exports/imports maps (interpreted by resolveExportsField).
type pkgManifest struct {
	name       string
	typ        string
	main       string
	workspaces []string
	exports    interface{}
	imports    interface{}
	// frontEntries are the module and browser field targets a bundler building for the
	// browser may load in place of main: the module field, a string browser field, and every
	// path an object browser field maps to.
	frontEntries []string
}

type rawPkg struct {
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Main       string          `json:"main"`
	Workspaces json.RawMessage `json:"workspaces"`
	Exports    json.RawMessage `json:"exports"`
	Imports    json.RawMessage `json:"imports"`
	Module     string          `json:"module"`
	Browser    json.RawMessage `json:"browser"`
}

func parsePkgManifest(data []byte) *pkgManifest {
	var rp rawPkg
	if err := json.Unmarshal(data, &rp); err != nil {
		return nil
	}
	m := &pkgManifest{name: rp.Name, typ: rp.Type, main: rp.Main}
	if rp.Module != "" {
		m.frontEntries = append(m.frontEntries, rp.Module)
	}
	if len(rp.Browser) > 0 {
		var one string
		var byPath map[string]any
		if json.Unmarshal(rp.Browser, &one) == nil && one != "" {
			m.frontEntries = append(m.frontEntries, one)
		} else if json.Unmarshal(rp.Browser, &byPath) == nil {
			for _, k := range slices.Sorted(maps.Keys(byPath)) {
				if t, ok := byPath[k].(string); ok && isRelativeTarget(t) {
					m.frontEntries = append(m.frontEntries, t)
				}
			}
		}
	}
	if len(rp.Exports) > 0 {
		_ = json.Unmarshal(rp.Exports, &m.exports)
	}
	if len(rp.Imports) > 0 {
		_ = json.Unmarshal(rp.Imports, &m.imports)
	}
	if len(rp.Workspaces) > 0 {
		// workspaces is either ["a","b"] or {"packages":["a","b"]}
		var arr []string
		if json.Unmarshal(rp.Workspaces, &arr) == nil {
			m.workspaces = arr
		} else {
			var obj struct {
				Packages []string `json:"packages"`
			}
			if json.Unmarshal(rp.Workspaces, &obj) == nil {
				m.workspaces = obj.Packages
			}
		}
	}
	return m
}

// governingPackageJSON finds the nearest package.json up-tree from fromModule's file,
// returning its parsed manifest and its build-root-relative directory.
func (rs *resolver) governingPackageJSON(fromModule string) (*pkgManifest, string) {
	if p := rs.prog.deps.pkgOf(fromModule); p != nil {
		return p.manifest, p.entry.path
	}
	dir := path.Dir(fromModule)
	if dir == "." {
		dir = ""
	}
	for {
		full := filepath.Join(rs.prog.root, filepath.FromSlash(dir), "package.json")
		if data, err := readRegular(full); err == nil {
			if m := parsePkgManifest(data); m != nil {
				return m, dir
			}
		} else if !absent(err) {
			rs.prog.readFailed = true
		}
		if dir == "" {
			return nil, ""
		}
		dir = path.Dir(dir)
		if dir == "." {
			dir = ""
		}
	}
}

// resolveWorkspaceMember resolves a bare specifier that names another workspace member
// (by that member's package.json name) to a first-party module through the member's own
// exports/main. Returns the target module and the condition set consulted.
func (rs *resolver) resolveWorkspaceMember(fromModule, spec string) (string, []string, bool) {
	if rs.prog.deps.owns(fromModule) {
		return "", nil, false
	}
	root, ok := rs.rootManifest()
	if !ok || len(root.workspaces) == 0 {
		return "", nil, false
	}
	pkgName, sub := splitBareSpecifier(spec)
	for _, member := range rs.workspaceMemberDirs(root.workspaces) {
		mm := rs.memberManifest(member)
		if mm == nil || mm.name != pkgName {
			continue
		}
		if mm.exports != nil {
			rel, conds, ok := resolveExportsField(mm.exports, sub, rs.conditions())
			if !ok {
				return "", nil, false // exports declared but subpath not exported (encapsulation)
			}
			if t := rs.moduleFromDirRelative(member, rel); t != "" {
				return t, conds, true
			}
			return "", nil, false
		}
		// no exports: main/index fallback for the "." subpath only
		if sub == "." {
			if t := rs.matchModule(path.Join(member, "index")); t != "" {
				return t, nil, true
			}
		}
		return "", nil, false
	}
	return "", nil, false
}

// workspaceMember finds the workspace member a bare specifier names, returning its directory,
// manifest, and the subpath within it.
func (rs *resolver) workspaceMember(spec string) (string, *pkgManifest, string, bool) {
	root, ok := rs.rootManifest()
	if !ok || len(root.workspaces) == 0 {
		return "", nil, "", false
	}
	pkgName, sub := splitBareSpecifier(spec)
	for _, member := range rs.workspaceMemberDirs(root.workspaces) {
		if mm := rs.memberManifest(member); mm != nil && mm.name == pkgName {
			return member, mm, sub, true
		}
	}
	return "", nil, "", false
}

// memberShadowed reports whether Node's node_modules walk for package name, from the importing
// module fromModule, finds something other than the workspace member at memberDir. Node walks
// from the importing file's real path, so the walk runs from its logical directory and again
// from the real directory of each source file the module can be. Each walk climbs past the
// build root to the filesystem root, as Node's does, and runs twice: once skipping
// node_modules/node_modules as CommonJS require does, once checking it as ESM import does.
// In each run the first directory holding a candidate decides: a file Node's CommonJS
// LOAD_AS_FILE would try, or a real directory, is different code; a symlink is the member only
// when its target's real path is the member directory's. A path that cannot be stat'ed or
// followed, for any reason but a missing path, counts as shadowing. The member stands only
// when no run finds anything else.
func (rs *resolver) memberShadowed(fromModule, name, memberDir string) bool {
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `\:`) {
		return true
	}
	root := filepath.Clean(rs.prog.root)
	memberReal, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(memberDir)))
	if err != nil {
		return true
	}
	// decides reports whether dir's node_modules holds a candidate for name, and if so whether
	// it shadows the member.
	decides := func(dir string) (bool, bool) {
		base := filepath.Join(dir, "node_modules", filepath.FromSlash(name))
		for _, ext := range []string{".js", ".json", ".node"} {
			if _, err := os.Lstat(base + ext); err == nil || !absent(err) {
				return true, true
			}
		}
		fi, err := os.Lstat(base)
		switch {
		case err != nil:
			return !absent(err), true
		case fi.Mode()&os.ModeSymlink == 0:
			return true, true
		}
		real, err := filepath.EvalSymlinks(base)
		if err != nil {
			return !absent(err), true
		}
		return true, real != memberReal
	}
	// walk runs Node's walk from dir to the filesystem root. CommonJS require skips
	// node_modules/node_modules (skipNested); ESM import does not.
	walk := func(dir string, skipNested bool) bool {
		for {
			if !skipNested || filepath.Base(dir) != "node_modules" {
				if decided, shadowed := decides(dir); decided {
					return shadowed
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return false
			}
			dir = parent
		}
	}
	// either is shadowed when the walk of either loader finds a copy: the importer's kind is
	// not tracked here.
	either := func(dir string) bool {
		return walk(dir, true) || walk(dir, false)
	}
	if either(filepath.Join(root, filepath.FromSlash(path.Dir(fromModule)))) {
		return true
	}
	exts := []string{vueExtension}
	for ext := range jsExtensions {
		exts = append(exts, ext)
	}
	for _, ext := range exts {
		file := filepath.Join(root, filepath.FromSlash(fromModule)+ext)
		if _, err := os.Lstat(file); err != nil {
			if absent(err) {
				continue
			}
			return true
		}
		real, err := filepath.EvalSymlinks(file)
		if err != nil {
			if absent(err) {
				continue
			}
			return true
		}
		if either(filepath.Dir(real)) {
			return true
		}
	}
	return false
}

func (rs *resolver) rootManifest() (*pkgManifest, bool) {
	full := filepath.Join(rs.prog.root, "package.json")
	data, err := readRegular(full)
	if err != nil {
		if !absent(err) {
			rs.prog.readFailed = true
		}
		return nil, false
	}
	m := parsePkgManifest(data)
	return m, m != nil
}

// workspaceMemberDirs expands workspace globs to build-root-relative member dirs. Only a
// single trailing "/*" glob is expanded (the common form); literal entries pass through.
func (rs *resolver) workspaceMemberDirs(patterns []string) []string {
	var dirs []string
	for _, p := range patterns {
		p = strings.TrimSuffix(p, "/")
		if strings.HasSuffix(p, "/*") {
			base := strings.TrimSuffix(p, "/*")
			entries, err := os.ReadDir(filepath.Join(rs.prog.root, filepath.FromSlash(base)))
			if err != nil {
				if !absent(err) {
					rs.prog.readFailed = true
				}
				continue
			}
			for _, e := range entries {
				if e.IsDir() {
					dirs = append(dirs, path.Join(base, e.Name()))
				}
			}
			continue
		}
		dirs = append(dirs, p)
	}
	return dirs
}

func (rs *resolver) memberManifest(memberDir string) *pkgManifest {
	full := filepath.Join(rs.prog.root, filepath.FromSlash(memberDir), "package.json")
	data, err := readRegular(full)
	if err != nil {
		if !absent(err) {
			rs.prog.readFailed = true
		}
		return nil
	}
	return parsePkgManifest(data)
}

func splitBareSpecifier(spec string) (pkg, subpath string) {
	if strings.HasPrefix(spec, "@") {
		parts := strings.SplitN(spec, "/", 3)
		if len(parts) < 2 {
			return spec, "."
		}
		pkg = parts[0] + "/" + parts[1]
		if len(parts) == 3 && parts[2] != "" {
			return pkg, "./" + parts[2]
		}
		return pkg, "."
	}
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) == 2 && parts[1] != "" {
		return parts[0], "./" + parts[1]
	}
	return parts[0], "."
}

// --- tsconfig paths / baseUrl / extends (C2) ---

type tsCompilerOptions struct {
	BaseURL string              `json:"baseUrl"`
	Paths   map[string][]string `json:"paths"`
	Module  string              `json:"module"`
}

type rawTsconfig struct {
	Extends         string            `json:"extends"`
	CompilerOptions tsCompilerOptions `json:"compilerOptions"`
}

// tsconfigResolved is a tsconfig after its extends chain has been merged.
type tsconfigResolved struct {
	dir     string // build-root-relative dir of the OWNING tsconfig (baseUrl resolves against it)
	path    string // build-root-relative path to the owning tsconfig.json
	baseURL string
	paths   map[string][]string
	module  string
}

// governingTsconfig finds and resolves (through extends) the nearest tsconfig.json
// up-tree from fromModule.
func (rs *resolver) governingTsconfig(fromModule string) *tsconfigResolved {
	dir := path.Dir(fromModule)
	if dir == "." {
		dir = ""
	}
	for {
		rel := path.Join(dir, "tsconfig.json")
		if _, err := os.Stat(filepath.Join(rs.prog.root, filepath.FromSlash(rel))); err == nil {
			return rs.loadTsconfig(dir, rel, 0)
		} else if !absent(err) {
			rs.prog.readFailed = true
			return nil
		}
		if dir == "" {
			return nil
		}
		dir = path.Dir(dir)
		if dir == "." {
			dir = ""
		}
	}
}

// loadTsconfig parses tsconfig at rel (owning dir dir) and merges its extends parent.
// The child's compilerOptions win; baseUrl/paths stay anchored to the tsconfig that
// DECLARED them (governing-member scoping — C2's cross-member negative depends on this).
func (rs *resolver) loadTsconfig(dir, rel string, depth int) *tsconfigResolved {
	data, err := readRegular(filepath.Join(rs.prog.root, filepath.FromSlash(rel)))
	if err != nil {
		if !absent(err) {
			rs.prog.readFailed = true
		}
		return nil
	}
	var raw rawTsconfig
	if json.Unmarshal(data, &raw) != nil {
		return nil
	}
	res := &tsconfigResolved{dir: dir, path: rel}
	if raw.Extends != "" && depth < 8 {
		parentRel := path.Join(dir, raw.Extends)
		if !strings.HasSuffix(parentRel, ".json") {
			parentRel += ".json"
		}
		parentDir := path.Dir(parentRel)
		if parentDir == "." {
			parentDir = ""
		}
		if parent := rs.loadTsconfig(parentDir, parentRel, depth+1); parent != nil {
			res.baseURL = parent.baseURL
			res.paths = parent.paths
			res.module = parent.module
			res.dir = parent.dir // inherited paths anchor to the declaring (parent) dir
		}
	}
	if raw.CompilerOptions.BaseURL != "" {
		res.baseURL = raw.CompilerOptions.BaseURL
		res.dir = dir
	}
	if raw.CompilerOptions.Paths != nil {
		res.paths = raw.CompilerOptions.Paths
		res.dir = dir
	}
	if raw.CompilerOptions.Module != "" {
		res.module = raw.CompilerOptions.Module
	}
	return res
}

// resolveTsPaths applies the governing tsconfig's paths alias to a bare specifier and
// resolves the mapped location to an in-tree module. Returns the module and the governing
// tsconfig path.
func (rs *resolver) resolveTsPaths(fromModule, spec string) (string, string, bool) {
	if rs.prog.deps.owns(fromModule) {
		return "", "", false
	}
	ts := rs.governingTsconfig(fromModule)
	if ts == nil || len(ts.paths) == 0 {
		return "", "", false
	}
	rel, ok := matchTsPaths(ts.paths, spec)
	if !ok {
		return "", "", false
	}
	base := ts.dir
	if ts.baseURL != "" && ts.baseURL != "." {
		base = path.Join(ts.dir, ts.baseURL)
	}
	target := rs.moduleFromDirRelative(base, rel)
	if target == "" {
		return "", "", false
	}
	return target, ts.path, true
}

// matchTsPaths matches a specifier against a tsconfig paths map (exact, then a single
// trailing "*" wildcard), returning the first mapped location with "*" substituted.
func matchTsPaths(paths map[string][]string, spec string) (string, bool) {
	if targets, ok := paths[spec]; ok && len(targets) > 0 {
		return targets[0], true
	}
	for key, targets := range paths {
		if !strings.HasSuffix(key, "*") || len(targets) == 0 {
			continue
		}
		prefix := strings.TrimSuffix(key, "*")
		if strings.HasPrefix(spec, prefix) {
			star := strings.TrimPrefix(spec, prefix)
			return strings.ReplaceAll(targets[0], "*", star), true
		}
	}
	return "", false
}

// --- exports / imports conditional maps (C1) ---

// resolveExportsField resolves a subpath against a parsed package.json "exports" (or
// "imports") field under an ordered condition set. It returns the selected target, the
// conditions actually consulted (in order), and ok. A declared exports map that does not
// expose the subpath returns ok=false — the encapsulation NEGATIVE C1 asserts.
func resolveExportsField(field interface{}, subpath string, conditions []string) (string, []string, bool) {
	switch v := field.(type) {
	case string:
		// A bare string exports only the "." subpath.
		if subpath == "." {
			return v, nil, true
		}
		return "", nil, false
	case map[string]interface{}:
		if isConditionsMap(v) {
			if subpath != "." {
				return "", nil, false
			}
			var used []string
			target, ok := selectCondition(v, conditions, &used)
			return target, used, ok
		}
		// subpaths map
		if node, ok := v[subpath]; ok {
			var used []string
			target, ok := selectCondition(node, conditions, &used)
			return target, used, ok
		}
		// pattern subpaths ("./*")
		for key, node := range v {
			if !strings.HasSuffix(key, "*") {
				continue
			}
			prefix := strings.TrimSuffix(key, "*")
			if strings.HasPrefix(subpath, prefix) {
				star := strings.TrimPrefix(subpath, prefix)
				var used []string
				target, ok := selectCondition(node, conditions, &used)
				if ok {
					return strings.ReplaceAll(target, "*", star), used, true
				}
			}
		}
		return "", nil, false
	}
	return "", nil, false
}

// selectCondition walks a possibly-nested conditions object, choosing the first branch
// whose condition is in the declared set (then "default"), recording each consulted
// condition in order.
func selectCondition(node interface{}, conditions []string, used *[]string) (string, bool) {
	switch v := node.(type) {
	case string:
		return v, true
	case map[string]interface{}:
		for _, c := range conditions {
			if sub, ok := v[c]; ok {
				*used = append(*used, c)
				if target, ok := selectCondition(sub, conditions, used); ok {
					return target, true
				}
			}
		}
		if sub, ok := v["default"]; ok {
			*used = append(*used, "default")
			return selectCondition(sub, conditions, used)
		}
		return "", false
	}
	return "", false
}

// isConditionsMap reports whether an exports/imports object is a conditions map (keys
// like "import"/"require"/"node"/"default") rather than a subpaths map (keys starting
// with "." or "#").
func isConditionsMap(m map[string]interface{}) bool {
	for k := range m {
		if strings.HasPrefix(k, ".") || strings.HasPrefix(k, "#") {
			return false
		}
	}
	return true
}

// --- module mode (C4) ---

// determineModuleMode computes a file's module mode from (in precedence) its extension's
// hard rule (.mjs/.cjs), the tsconfig module setting (.ts/.tsx), and the nearest
// package.json "type". Returns "esm" or "cjs".
func determineModuleMode(pkgType, ext, tsModule string) string {
	switch ext {
	case ".mjs":
		return "esm"
	case ".cjs":
		return "cjs"
	case ".ts", ".tsx", ".mts", ".cts":
		if ext == ".mts" {
			return "esm"
		}
		if ext == ".cts" {
			return "cjs"
		}
		if tsModule != "" {
			m := strings.ToLower(tsModule)
			switch {
			case m == "commonjs":
				return "cjs"
			case strings.HasPrefix(m, "es") || m == "node16" || m == "nodenext":
				return "esm"
			}
		}
		if pkgType == "module" {
			return "esm"
		}
		return "cjs"
	default: // .js, .jsx
		if pkgType == "module" {
			return "esm"
		}
		return "cjs"
	}
}

// moduleModeOf determines the mode of an in-tree module by locating its source extension
// and consulting the governing package.json type and tsconfig module setting.
func (rs *resolver) moduleModeOf(module, ext string) string {
	pkg, _ := rs.governingPackageJSON(module)
	pkgType := ""
	if pkg != nil {
		pkgType = pkg.typ
	}
	tsModule := ""
	if ts := rs.governingTsconfig(module); ts != nil {
		tsModule = ts.module
	}
	return determineModuleMode(pkgType, ext, tsModule)
}
