package jsanalysis

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
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
// whole-program index. It never opens node_modules and never executes source.
type Resolver interface {
	// ResolveCall resolves a bare call `name(arity)` occurring in fromModule.
	ResolveCall(fromModule string, name string, arity int) resolution
	// ResolveRef resolves a handler REFERENCE `name` (no call, no arity) in fromModule.
	ResolveRef(fromModule string, name string) resolution
}

// resolver is the concrete Resolver over a parsed program.
type resolver struct {
	prog *program
}

func (p *program) resolver() *resolver { return &resolver{prog: p} }

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
	if cs.receiverThis {
		return rs.resolveThisMethod(fromModule, cs.callerEnclosing, cs.calleeName, cs.calleeArity)
	}
	if cs.receiver != "" {
		return rs.resolveReceiverMethod(fromModule, cs.receiver, cs.calleeName, cs.calleeArity)
	}
	return rs.resolveName(fromModule, cs.calleeName, cs.calleeArity)
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
	case isRelativeSpecifier(spec):
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
	if isRelativeSpecifier(b.Specifier) {
		return rs.resolveRelative(fromModule, b.Specifier), algo
	}
	if target, _, ok := rs.resolveWorkspaceMember(fromModule, b.Specifier); ok {
		return target, algoExports
	}
	if target, _, ok := rs.resolveTsPaths(fromModule, b.Specifier); ok {
		return target, algoPathsAlias
	}
	return "", algo
}

// resolveModuleOfSpecifier resolves a specifier (relative or bare-first-party) to an
// in-tree module, for re-export following.
func (rs *resolver) resolveModuleOfSpecifier(fromModule, spec string) string {
	if isRelativeSpecifier(spec) {
		return rs.resolveRelative(fromModule, spec)
	}
	if target, _, ok := rs.resolveWorkspaceMember(fromModule, spec); ok {
		return target
	}
	if target, _, ok := rs.resolveTsPaths(fromModule, spec); ok {
		return target
	}
	return ""
}

// resolveRelative resolves a relative specifier against fromModule's directory and
// selects an in-tree module by extension/index rules (module set is extension-stripped).
func (rs *resolver) resolveRelative(fromModule, spec string) string {
	dir := path.Dir(fromModule)
	if dir == "." {
		dir = ""
	}
	cand := path.Join(dir, spec)
	cand = strings.TrimPrefix(cand, "./")
	return rs.matchModule(cand)
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

func isRelativeSpecifier(spec string) bool {
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
	if ext := path.Ext(p); jsExtensions[ext] {
		return strings.TrimSuffix(p, ext)
	}
	return p
}

// --- package.json / tsconfig loading (metadata only; never node_modules) ---

// pkgManifest is the resolver's view of a package.json: identity, module type, and the
// raw exports/imports maps (interpreted by resolveExportsField).
type pkgManifest struct {
	name       string
	typ        string
	workspaces []string
	exports    interface{}
	imports    interface{}
}

type rawPkg struct {
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Workspaces json.RawMessage `json:"workspaces"`
	Exports    json.RawMessage `json:"exports"`
	Imports    json.RawMessage `json:"imports"`
}

func parsePkgManifest(data []byte) *pkgManifest {
	var rp rawPkg
	if err := json.Unmarshal(data, &rp); err != nil {
		return nil
	}
	m := &pkgManifest{name: rp.Name, typ: rp.Type}
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
	dir := path.Dir(fromModule)
	if dir == "." {
		dir = ""
	}
	for {
		full := filepath.Join(rs.prog.root, filepath.FromSlash(dir), "package.json")
		if data, err := os.ReadFile(full); err == nil {
			if m := parsePkgManifest(data); m != nil {
				return m, dir
			}
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

func (rs *resolver) rootManifest() (*pkgManifest, bool) {
	full := filepath.Join(rs.prog.root, "package.json")
	data, err := os.ReadFile(full)
	if err != nil {
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
	data, err := os.ReadFile(full)
	if err != nil {
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
	data, err := os.ReadFile(filepath.Join(rs.prog.root, filepath.FromSlash(rel)))
	if err != nil {
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
