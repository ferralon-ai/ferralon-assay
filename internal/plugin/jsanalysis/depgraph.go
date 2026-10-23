package jsanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depReadBudget bounds reading, parsing and linking every dependency package of one run.
const depReadBudget = 5 * time.Minute

// Provenance of the edges dependency code adds.
const (
	// algoModuleLoad links a module's top-level frame to the top-level frame of a module it
	// loads: loading runs that module's code.
	algoModuleLoad resolveAlgo = "module_load"
	// algoLoadedEscape links a dependency module's top-level frame to a function its escape
	// rules mark: once the module has run, opaque code can call the function.
	algoLoadedEscape resolveAlgo = "loaded_escape"
)

// depGraph is the dependency code a program reads: the lock layout and every package read
// from the store, by install path.
type depGraph struct {
	layout *depLayout
	pkgs   map[string]*depPackage
}

// installPathOf returns the install directory of the package a dependency module belongs to
// ("node_modules/a/node_modules/@s/b" for "node_modules/a/node_modules/@s/b/lib/x"), or "".
func installPathOf(module string) string {
	const marker = "node_modules/"
	i := strings.LastIndex(module, marker)
	if i < 0 || (i > 0 && module[i-1] != '/') {
		return ""
	}
	rest := module[i+len(marker):]
	segs := 1
	if strings.HasPrefix(rest, "@") {
		segs = 2
	}
	parts := strings.SplitN(rest, "/", segs+1)
	if len(parts) < segs+1 {
		return ""
	}
	return module[:i+len(marker)] + strings.Join(parts[:segs], "/")
}

// pkgOf returns the read package module belongs to, or nil for a first-party module.
func (d *depGraph) pkgOf(module string) *depPackage {
	if d == nil {
		return nil
	}
	return d.pkgs[installPathOf(module)]
}

// owns reports whether module is dependency code.
func (d *depGraph) owns(module string) bool {
	return d.pkgOf(module) != nil
}

// depTargets resolves a bare specifier loaded from fromModule over the lock layout: the entry
// Node's walk finds and, when that package was read, the modules the specifier can select.
func (rs *resolver) depTargets(fromModule, spec string, viaRequire bool) (*depEntry, []string) {
	d := rs.prog.deps
	name, sub := splitBareSpecifier(spec)
	e := d.layout.lookup(moduleDir(fromModule), name)
	if e == nil {
		return nil, nil
	}
	pkg := d.pkgs[e.path]
	if pkg == nil {
		return e, nil
	}
	return e, rs.entryModules(pkg, sub, viaRequire)
}

// entryModules selects the modules a subpath of a read package resolves to: its exports under
// Node's conditions, else main then index for the package itself, else the file the subpath
// names.
func (rs *resolver) entryModules(pkg *depPackage, sub string, viaRequire bool) []string {
	dir := pkg.entry.path
	var out []string
	add := func(m string) {
		if m != "" && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	switch {
	case pkg.manifest.exports != nil:
		for _, t := range exportsTargets(pkg.manifest.exports, sub, loadConditions(viaRequire)) {
			if isRelativeTarget(t) {
				add(rs.depModuleAt(dir, t))
			}
		}
	case sub == ".":
		if pkg.manifest.main != "" {
			add(rs.depModuleAt(dir, pkg.manifest.main))
		}
		if len(out) == 0 {
			add(rs.matchModule(path.Join(dir, "index")))
		}
	default:
		add(rs.matchModule(stripJSExt(path.Join(dir, sub))))
	}
	sort.Strings(out)
	return out
}

// depModuleAt resolves a path a read package's manifest names: the file itself when it is parsed
// as its own module (a dual package's .mjs beside its .js), else the module it resolves to.
func (rs *resolver) depModuleAt(dir, rel string) string {
	if exact := path.Join(dir, strings.TrimPrefix(rel, "./")); rs.prog.moduleSet[exact] && rs.prog.deps.owns(exact) {
		return exact
	}
	return rs.moduleFromDirRelative(dir, rel)
}

// frontEntryModules selects the modules a bundler building for the browser may load for a bare
// load of a read package itself: its module and browser field targets.
func (rs *resolver) frontEntryModules(fromModule, spec string) []string {
	name, sub := splitBareSpecifier(spec)
	if sub != "." {
		return nil
	}
	e := rs.prog.deps.layout.lookup(moduleDir(fromModule), name)
	if e == nil || rs.prog.deps.pkgs[e.path] == nil {
		return nil
	}
	return rs.frontEntriesAt(e.path)
}

// frontEntriesAt is frontEntryModules for the read package installed at pkgPath: the modules
// its module and browser entries select. It is nil when no read package has its root there.
func (rs *resolver) frontEntriesAt(pkgPath string) []string {
	p := rs.prog.deps.pkgs[pkgPath]
	if p == nil || p.manifest == nil {
		return nil
	}
	var out []string
	for _, t := range p.manifest.frontEntries {
		if m := rs.depModuleAt(pkgPath, t); m != "" && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// resolveDepBare resolves a bare specifier over the dependency layout: a single selected module
// of a read package resolves the imported name in it; anything else stays a package
// resolution, uninspectable when the package was not read.
func (rs *resolver) resolveDepBare(fromModule, spec, imported string, arity int, algo resolveAlgo) resolution {
	base := resolution{
		Kind:    resolvePackage,
		Subpath: bareSubpath(spec),
		Reason:  plugin.PartialReasonUninspectablePackage,
		Prov:    provenance{Algo: algo},
	}
	if isNodeBuiltin(spec) {
		return base
	}
	e, mods := rs.depTargets(fromModule, spec, algo == algoCJS)
	if e == nil {
		return base
	}
	base.InstanceID = e.purl
	if rs.prog.deps.pkgs[e.path] == nil {
		return base
	}
	if len(mods) == 1 {
		if r := rs.lookupImportedName(mods[0], imported, arity, provenance{Algo: algo}); r.Kind == resolveFirstParty {
			return r
		}
	}
	base.Reason = plugin.PartialReasonDynamicDispatch
	return base
}

// depModuleOfSpecifier resolves a bare specifier to the single module it selects in a read
// package, or "".
func (rs *resolver) depModuleOfSpecifier(fromModule, spec string, viaRequire bool) string {
	if rs.prog.deps == nil || rs.packageOnly || isNodeBuiltin(spec) || strings.HasPrefix(spec, "#") || strings.HasPrefix(spec, "/") {
		return ""
	}
	if _, mods := rs.depTargets(fromModule, spec, viaRequire); len(mods) == 1 {
		return mods[0]
	}
	return ""
}

// depParse is the outcome of reading one package.
type depParse struct {
	pkg    *depPackage
	files  []parseResult
	err    error
	budget bool // the read budget ran out before the package was read
	capped bool // the run's parsed-source cap was reached before the package was parsed
}

// readDeps reads and parses every readable layout entry from store across GOMAXPROCS workers.
// It returns when every entry is done or ctx ends, whichever is first: an entry not done by
// then is marked budget, and a worker still parsing it runs on with its result dropped.
func readDeps(ctx context.Context, store artifactcache.Store, entries []*depEntry) []depParse {
	out := make([]depParse, len(entries))
	type result struct {
		i int
		p depParse
	}
	work := make(chan int, len(entries))
	pending := map[int]bool{}
	for i, e := range entries {
		if !e.unreadable {
			work <- i
			pending[i] = true
		}
	}
	close(work)
	results := make(chan result, len(entries))
	var parsed atomic.Int64
	for range max(1, runtime.GOMAXPROCS(0)) {
		go func() {
			for i := range work {
				results <- result{i, readOneDep(ctx, store, entries[i], &parsed)}
			}
		}()
	}
	for len(pending) > 0 {
		select {
		case r := <-results:
			out[r.i] = r.p
			delete(pending, r.i)
		case <-ctx.Done():
			for i := range pending {
				out[i] = depParse{budget: true}
			}
			return out
		}
	}
	return out
}

// readOneDep reads and parses one package. parsed counts the source bytes the run has parsed;
// a package that would take it past depRunSourceCap is left unparsed, marked capped.
func readOneDep(ctx context.Context, store artifactcache.Store, e *depEntry, parsed *atomic.Int64) depParse {
	if ctx.Err() != nil {
		return depParse{budget: true}
	}
	pkg, err := readDepPackage(ctx, store, e)
	if err != nil {
		return depParse{err: err, budget: ctx.Err() != nil}
	}
	var size int64
	for _, f := range pkg.sources {
		size += int64(len(f.data))
	}
	if parsed.Add(size) > depRunSourceCap {
		return depParse{capped: true}
	}
	files := make([]parseResult, 0, len(pkg.sources))
	for _, f := range pkg.sources {
		pr, ok := parseDepSource(ctx, e.path+"/"+f.module, f)
		if !ok {
			return depParse{budget: true}
		}
		files = append(files, pr)
	}
	pkg.sources = nil
	return depParse{pkg: pkg, files: files}
}

// callGraphFor builds the call graph for buildDir, with the dependency code depCache holds
// when it names a store. The dependency graph is built once per scan through the run cache.
func callGraphFor(ctx context.Context, buildDir, depCache string) (plugin.CallGraphResult, error) {
	if depCache == "" {
		res, _, err := callGraphInternal(buildDir)
		return res, err
	}
	b, err := runCached(ctx, "callgraph", []string{buildDir, depCache}, func() ([]byte, error) {
		res, _, err := callGraphWithDeps(ctx, buildDir, artifactcache.NewDiskStore(depCache), depReadBudget)
		if err != nil {
			return nil, err
		}
		return json.Marshal(res)
	})
	if err != nil {
		return plugin.CallGraphResult{}, err
	}
	var res plugin.CallGraphResult
	if err := json.Unmarshal(b, &res); err != nil {
		return plugin.CallGraphResult{}, fmt.Errorf("jsanalysis: decode cached call graph: %w", err)
	}
	return res, nil
}

// callGraphWithDeps builds the call graph with the lock-pinned dependency code store holds
// read into it. First-party analysis is exactly callGraphInternal's; dependency code only adds
// edges and limits. A cancelled ctx is an error, never a partial graph.
func callGraphWithDeps(ctx context.Context, buildDir string, store artifactcache.Store, budget time.Duration) (plugin.CallGraphResult, map[plugin.CallEdge]provenance, error) {
	prog, err := loadProgram(buildDir)
	if err != nil {
		return plugin.CallGraphResult{}, nil, err
	}
	g := buildGraph(prog)
	baseFlags := g.flags
	baseRoots := make([]string, 0, len(g.roots))
	for r := range g.roots {
		baseRoots = append(baseRoots, r)
	}

	layout := buildDepLayout(buildDir)
	bctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	entries := layout.entries()
	parsed := readDeps(bctx, store, entries)
	if err := ctx.Err(); err != nil {
		return plugin.CallGraphResult{}, nil, err
	}

	dflags := partialFlags{}
	if layout.berry || layout.incomplete {
		dflags.uninspectable = true
	}
	addScoped := func(reason, pkg, target string) {
		dflags.scoped = append(dflags.scoped, plugin.ScopedReason{Reason: reason, Package: pkg, Targets: []string{target}})
	}
	d := &depGraph{layout: layout, pkgs: map[string]*depPackage{}}
	var depFiles []fileParse
	// An unread package whose lock marks or may mark an install script withholds run-wide: the
	// script runs at install whether or not anything loads the package.
	unread := func(reason string, e *depEntry) {
		addScoped(reason, e.purl, e.purl)
		if e.lockInstallScript || e.scriptsUnknown {
			dflags.uninspectable = true
		}
	}
	for _, e := range layout.unplaced {
		unread(plugin.PartialReasonUninspectablePackage, e)
	}
	for i, e := range entries {
		p := parsed[i]
		switch {
		case e.unreadable || p.err != nil && !p.budget:
			unread(plugin.PartialReasonUninspectablePackage, e)
			continue
		case p.budget || p.capped:
			unread(plugin.PartialReasonToolFailure, e)
			continue
		}
		d.pkgs[e.path] = p.pkg
		switch {
		case p.pkg.installScript:
			dflags.uninspectable = true
		case p.pkg.native:
			addScoped(plugin.PartialReasonUninspectablePackage, e.purl, e.purl)
		}
		for _, pr := range p.files {
			if pr.skipped {
				dflags.unsupported = true
			}
			fp := fileParse{module: pr.module, escapes: pr.escapes, decls: pr.decls, calls: pr.calls, ingresses: pr.ingresses, bindings: pr.bindings}
			depFiles = append(depFiles, fp)
			prog.files = append(prog.files, fp)
			prog.moduleSet[pr.module] = true
			prog.indexModule(fp)
		}
	}
	prog.deps = d

	firstParty := prog.files[:len(prog.files)-len(depFiles)]
	aug := newGraphBuild()
	if !augment(bctx, prog, firstParty, depFiles, g, aug, &dflags) {
		if err := ctx.Err(); err != nil {
			return plugin.CallGraphResult{}, nil, err
		}
		flags := baseFlags
		flags.toolFailure = true
		flags.scoped = sortedScoped(dflags.scoped)
		return g.result(callGraphPartiality(prog, flags)), g.prov, nil
	}

	reached := reachedFrom(baseRoots, g.edges, aug.edges)
	versions := map[string]int{}
	for _, p := range d.pkgs {
		versions[p.entry.name+"@"+p.entry.version]++
	}
	rewrite := func(s string) string { return d.rewriteSCIP(s, versions) }
	for _, e := range aug.edges {
		if !reached[e.Caller.SCIP] {
			continue
		}
		g.add(plugin.CallEdge{Caller: sym(rewrite(e.Caller.SCIP)), Callee: sym(rewrite(e.Callee.SCIP))}, aug.prov[e])
	}

	flags := mergeFlags(baseFlags, dflags)
	flags.scoped = sortedScoped(flags.scoped)
	if g.anyExempt && g.anyProto {
		flags.evaluated = true
	}
	return g.result(callGraphPartiality(prog, flags)), g.prov, nil
}

// augment adds the edges dependency code contributes to aug: module loads, calls resolved
// through the layout, versioned boundary edges and conditional roots. It reports false when
// ctx ends first.
func augment(ctx context.Context, prog *program, firstParty, depFiles []fileParse, g, aug *graphBuild, flags *partialFlags) bool {
	rs := prog.resolver()
	pkgRS := &resolver{prog: prog, bctx: rs.bctx, packageOnly: true}
	br := newBoundaryResolver(prog, pkgRS)
	d := prog.deps

	loadEdges := func(f fileParse, mods []string, algo resolveAlgo) {
		for _, m := range mods {
			aug.add(plugin.CallEdge{Caller: sym(moduleInitSCIP(f.module)), Callee: sym(moduleInitSCIP(m))}, provenance{Algo: algoModuleLoad, Conditions: []string{string(algo)}})
		}
	}
	loadAlgo := func(viaRequire bool) resolveAlgo {
		if viaRequire {
			return algoCJS
		}
		return algoESM
	}
	boundary := func(module string, cs callSite, caller plugin.Symbol) bool {
		id, prov, ok := br.callee(module, cs)
		if !ok {
			return false
		}
		if v := d.versionedBoundary(id, module); v != "" {
			aug.add(plugin.CallEdge{Caller: caller, Callee: sym(v)}, prov)
		}
		return true
	}

	// A first-party module a stock Create React App builds for the browser also loads its
	// packages' module and browser entries; once any does, so may every dependency load.
	craDirs := map[string]bool{}
	frontend, anyFrontend := func(module string) bool {
		dir := path.Dir(module)
		v, ok := craDirs[dir]
		if !ok {
			v = stockCRAPackage(prog.root, module)
			craDirs[dir] = v
		}
		return v
	}, false

	for i, f := range firstParty {
		if i%256 == 0 && ctx.Err() != nil {
			return false
		}
		for _, ls := range f.bindings.specifiers {
			if !isDepSpecifier(ls.spec) {
				continue
			}
			if _, _, ok := rs.resolveTsPaths(f.module, ls.spec); ok {
				continue
			}
			if _, _, ok := rs.resolveWorkspaceMember(f.module, ls.spec); ok {
				continue
			}
			_, mods := rs.depTargets(f.module, ls.spec, ls.viaRequire)
			loadEdges(f, mods, loadAlgo(ls.viaRequire))
			if frontend(f.module) {
				anyFrontend = true
				loadEdges(f, rs.frontEntryModules(f.module, ls.spec), loadAlgo(ls.viaRequire))
			}
		}
		for _, cs := range f.calls {
			if cs.calleeFrame {
				continue
			}
			caller := sym(funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity))
			r := rs.resolveCallSite(f.module, cs)
			if target, ok := r.edge(); ok {
				if e := (plugin.CallEdge{Caller: caller, Callee: sym(target)}); !g.seen[e] {
					aug.add(e, r.Prov)
				}
				continue
			}
			boundary(f.module, cs, caller)
		}
	}

	for i, f := range depFiles {
		if i%256 == 0 && ctx.Err() != nil {
			return false
		}
		pkg := d.pkgOf(f.module)
		b := f.bindings
		flags.dynImport = flags.dynImport || b.dynImport
		flags.computedReq = flags.computedReq || b.computedReq
		flags.unreadModule = flags.unreadModule || b.nativeLoad
		flags.evaluated = flags.evaluated || b.evaluated
		g.anyExempt = g.anyExempt || b.literalExempt
		g.anyProto = g.anyProto || b.protoWrite
		for _, pl := range b.prefixLoads {
			if pl.dyn {
				flags.dynImport = true
			} else {
				flags.computedReq = true
			}
		}
		init := sym(moduleInitSCIP(f.module))
		for _, ls := range b.specifiers {
			algo := loadAlgo(ls.viaRequire)
			switch {
			case isRelativeLoad(ls.spec):
				m, dir, viaDir := rs.resolveRelativeDir(f.module, ls.spec)
				if viaDir && anyFrontend {
					// A bundler loading a package root ("require('..')" from inside it) takes its
					// module and browser entries, as for a load by name.
					loadEdges(f, rs.frontEntriesAt(dir), algo)
				}
				if m != "" {
					loadEdges(f, []string{m}, algo)
					continue
				}
				switch ext := path.Ext(ls.spec); {
				case ext == ".json":
				case stylesheetExtensions[ext]:
					flags.stylesheet = true
				default:
					flags.unreadModule = true
				}
			case strings.HasPrefix(ls.spec, "#"):
				mods, ok := rs.depImportsTargets(pkg, f.module, ls.spec, ls.viaRequire)
				if !ok {
					flags.unreadModule = true
				}
				loadEdges(f, mods, algo)
			case strings.HasPrefix(ls.spec, "/"):
				flags.unreadModule = true
			case isNodeBuiltin(ls.spec):
				flags.uninspectable = true
			default:
				e, mods := rs.depTargets(f.module, ls.spec, ls.viaRequire)
				if e == nil {
					name, _ := splitBareSpecifier(ls.spec)
					if !validNPMName(name) {
						// No package can carry this name, so nothing bounds what the load runs:
						// CommonJS loads "..foo" as a file beside the caller.
						flags.unreadModule = true
						continue
					}
					flags.scoped = append(flags.scoped, plugin.ScopedReason{Reason: plugin.PartialReasonUninspectablePackage, Package: pkg.entry.purl, Targets: []string{originPURL(name)}})
					continue
				}
				if len(mods) == 0 && d.pkgs[e.path] != nil {
					// A read package whose entry selects no parsed module: what the load runs
					// is not read.
					switch ext := path.Ext(ls.spec); {
					case ext == ".json":
					case stylesheetExtensions[ext]:
						flags.stylesheet = true
					default:
						flags.unreadModule = true
					}
				}
				loadEdges(f, mods, algo)
				if anyFrontend {
					loadEdges(f, rs.frontEntryModules(f.module, ls.spec), algo)
				}
			}
		}
		for _, cs := range f.calls {
			caller := sym(funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity))
			if cs.calleeFrame {
				aug.add(plugin.CallEdge{Caller: caller, Callee: sym(funcSCIP(f.module, cs.calleeEnclosing, cs.calleeName, cs.calleeArity))}, provenance{Algo: algoLocal})
				continue
			}
			r := rs.resolveCallSite(f.module, cs)
			if target, ok := r.edge(); ok {
				aug.add(plugin.CallEdge{Caller: caller, Callee: sym(target)}, r.Prov)
			}
			if boundary(f.module, cs, caller) {
				continue
			}
			switch {
			case r.Kind == resolveFirstParty:
			case r.Kind == resolvePackage && r.Reason == plugin.PartialReasonUninspectablePackage && r.InstanceID != "":
				// An unread package: its scoped limit already covers the call.
			default:
				accumulateReason(flags, r.Reason)
			}
		}
		for _, dc := range f.decls {
			if f.escapes.root(dc) {
				aug.add(plugin.CallEdge{Caller: init, Callee: sym(funcSCIP(f.module, dc.enclosing, dc.name, dc.arity))}, provenance{Algo: algoLoadedEscape})
			}
		}
		for _, in := range f.ingresses {
			if s := prog.resolveIngressSymbol(f.module, in); s != "" {
				aug.add(plugin.CallEdge{Caller: init, Callee: sym(s)}, provenance{Algo: algoLoadedEscape})
			}
		}
	}
	return ctx.Err() == nil
}

// validNPMName reports whether name, the package part of a bare specifier, can be bounded to
// pkg:npm/<name>. It rejects only the names a resolver could read as something other than a
// package: empty, a leading "." or "_", a scoped part starting with ".", or a ".." anywhere
// (which deplayout.lookup also refuses). It is not full npm name validation: the other names
// npm forbids are MODULE_NOT_FOUND in Node, so a limit bounded to them stays sound.
func validNPMName(name string) bool {
	if name == "" || strings.Contains(name, "..") {
		return false
	}
	if scope, part, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		return part != "" && !strings.HasPrefix(part, ".")
	}
	return !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "_") && !strings.HasPrefix(name, "@")
}

// isDepSpecifier reports whether a load names an npm package: bare, and not a Node built-in.
func isDepSpecifier(spec string) bool {
	return spec != "" && !isRelativeLoad(spec) && !strings.HasPrefix(spec, "#") && !strings.HasPrefix(spec, "/") && !isNodeBuiltin(spec)
}

// depImportsTargets resolves a `#…` load from a dependency module through its package's imports
// map. ok is false when the map selects nothing the layout holds.
func (rs *resolver) depImportsTargets(pkg *depPackage, fromModule, spec string, viaRequire bool) ([]string, bool) {
	if pkg.manifest.imports == nil {
		return nil, false
	}
	targets := exportsTargets(pkg.manifest.imports, spec, loadConditions(viaRequire))
	var out []string
	for _, t := range targets {
		if isRelativeTarget(t) {
			m := rs.moduleFromDirRelative(pkg.entry.path, t)
			if m == "" {
				return nil, false
			}
			out = append(out, m)
			continue
		}
		if !isDepSpecifier(t) {
			return nil, false
		}
		e, mods := rs.depTargets(fromModule, t, viaRequire)
		if e == nil {
			return nil, false
		}
		out = append(out, mods...)
	}
	return out, len(targets) > 0
}

// versionedBoundary returns the boundary id naming the installed copy a call from module
// enters: npm:<name>@<version>[/<subpath>]#<chain>, or "" when the layout has no such package.
func (d *depGraph) versionedBoundary(id, module string) string {
	spec := strings.TrimPrefix(id, boundaryScheme)
	i := strings.IndexByte(spec, '#')
	if i < 0 {
		return ""
	}
	spec, chain := spec[:i], spec[i:]
	name, sub := splitBareSpecifier(spec)
	e := d.layout.lookup(moduleDir(module), name)
	if e == nil || e.version == "" {
		return ""
	}
	return boundaryScheme + name + "@" + e.version + strings.TrimPrefix(sub, ".") + chain
}

// rewriteSCIP gives a dependency symbol its package coordinate: "scip-typescript npm <name>
// <version> <path-in-package>/…". A name@version installed more than once keeps its install
// path so the copies stay distinct.
func (d *depGraph) rewriteSCIP(s string, versions map[string]int) string {
	const local = scipManager + " " + localCoordinate + " " + localCoordinate + " "
	rest, ok := strings.CutPrefix(s, local)
	if !ok {
		return s
	}
	slash := strings.LastIndexByte(rest, '/')
	if slash < 0 {
		return s
	}
	ip := installPathOf(rest[:slash])
	p := d.pkgs[ip]
	if p == nil {
		return s
	}
	inner := rest[len(ip)+1:]
	if versions[p.entry.name+"@"+p.entry.version] > 1 {
		inner = ip + "/" + inner
	}
	return scipManager + " " + p.entry.name + " " + p.entry.version + " " + inner
}

// reachedFrom returns every node reachable from roots over both edge sets.
func reachedFrom(roots []string, edgeSets ...[]plugin.CallEdge) map[string]bool {
	adj := map[string][]string{}
	for _, es := range edgeSets {
		for _, e := range es {
			adj[e.Caller.SCIP] = append(adj[e.Caller.SCIP], e.Callee.SCIP)
		}
	}
	reached := map[string]bool{}
	queue := append([]string(nil), roots...)
	for _, r := range roots {
		reached[r] = true
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, m := range adj[n] {
			if !reached[m] {
				reached[m] = true
				queue = append(queue, m)
			}
		}
	}
	return reached
}

// sortedScoped dedups scoped reasons and orders them deterministically.
func sortedScoped(in []plugin.ScopedReason) []plugin.ScopedReason {
	key := func(r plugin.ScopedReason) string {
		return r.Reason + "\x00" + r.Package + "\x00" + r.Path + "\x00" + strings.Join(r.Targets, "\x00")
	}
	seen := map[string]bool{}
	var out []plugin.ScopedReason
	for _, r := range in {
		if k := key(r); !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}

func mergeFlags(a, b partialFlags) partialFlags {
	return partialFlags{
		unresolved:    a.unresolved || b.unresolved,
		uninspectable: a.uninspectable || b.uninspectable,
		dynImport:     a.dynImport || b.dynImport,
		computedReq:   a.computedReq || b.computedReq,
		unreadModule:  a.unreadModule || b.unreadModule,
		evaluated:     a.evaluated || b.evaluated,
		stylesheet:    a.stylesheet || b.stylesheet,
		toolFailure:   a.toolFailure || b.toolFailure,
		unsupported:   a.unsupported || b.unsupported,
		scoped:        append(append([]plugin.ScopedReason(nil), a.scoped...), b.scoped...),
	}
}
