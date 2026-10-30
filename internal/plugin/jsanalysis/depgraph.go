package jsanalysis

import (
	"context"
	"encoding/json"
	"errors"
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
// Node's conditions, else Node's LOAD_AS_DIRECTORY for the package itself, else Node's
// LOAD_AS_FILE then LOAD_AS_DIRECTORY for the path the subpath names. With anyResolver set it is
// loadCandidates instead, nil when that cannot bound the load.
func (rs *resolver) entryModules(pkg *depPackage, sub string, viaRequire bool) []string {
	if rs.anyResolver {
		mods, ok := rs.loadCandidates(pkg, sub, viaRequire)
		if !ok {
			return nil
		}
		return mods
	}
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
		m, _ := rs.nodeDir(pkg, "")
		add(m)
	default:
		if rel, ok := pkgJoin("", sub); ok {
			m, _ := rs.nodePath(pkg, rel)
			add(m)
		}
	}
	sort.Strings(out)
	return out
}

// depModuleAt resolves a path a read package's manifest names: inside a read package, the module
// of the file Node loads for it (nodeFile, else its index); elsewhere the file itself when it is
// parsed as its own module, else the module it resolves to.
func (rs *resolver) depModuleAt(dir, rel string) string {
	if p, base := rs.prog.deps.readPkgRel(dir); p != nil {
		r, ok := pkgJoin(base, rel)
		if !ok {
			return ""
		}
		if m, found := rs.nodeFile(p, r); found {
			return m
		}
		m, _ := rs.nodeFile(p, path.Join(r, "index"))
		return m
	}
	if exact := path.Join(dir, strings.TrimPrefix(rel, "./")); rs.prog.moduleSet[exact] && rs.prog.deps.owns(exact) {
		return exact
	}
	return rs.moduleFromDirRelative(dir, rel)
}

// readPkgRel returns the read package whose files hold build-root-relative dir, with dir
// relative to that package's root ("" for the root itself); nil when no read package does.
func (d *depGraph) readPkgRel(dir string) (*depPackage, string) {
	if d == nil {
		return nil, ""
	}
	if p := d.pkgs[dir]; p != nil {
		return p, ""
	}
	ip := installPathOf(dir + "/x")
	if p := d.pkgs[ip]; ip != "" && p != nil {
		return p, strings.TrimPrefix(dir, ip+"/")
	}
	return nil, ""
}

// pkgJoin joins a package-relative directory and a path a manifest or specifier names, reporting
// false when the result leaves the package.
func pkgJoin(base, rel string) (string, bool) {
	j := path.Join(base, strings.TrimPrefix(rel, "./"))
	switch {
	case j == ".":
		return "", true
	case j == ".." || strings.HasPrefix(j, "../") || strings.HasPrefix(j, "/"):
		return "", false
	}
	return j, true
}

// moduleOf is the module read package p's file rel is parsed as, or "" for a file the lane did
// not parse (JSON, a native addon, an extensionless file, a source a sibling shadows).
func (rs *resolver) moduleOf(p *depPackage, rel string) string {
	if m, ok := p.modules[rel]; ok {
		if id := p.entry.path + "/" + m; rs.prog.moduleSet[id] {
			return id
		}
	}
	return ""
}

// nodeFileExts are the extensions Node's LOAD_AS_FILE tries, in order, followed by the source
// extensions a bundler also tries, which Node-mode resolution falls back to.
var nodeFileExts = []string{".js", ".json", ".node", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", vueExtension}

// nodeFile is LOAD_AS_FILE over read package p's files for package-relative rel: the exact file
// first, then rel with each of nodeFileExts. found reports a file it selects; mod is that file's
// module, "" when the lane did not parse it.
func (rs *resolver) nodeFile(p *depPackage, rel string) (mod string, found bool) {
	if rel != "" && p.files[rel] {
		return rs.moduleOf(p, rel), true
	}
	for _, ext := range nodeFileExts {
		if p.files[rel+ext] {
			return rs.moduleOf(p, rel+ext), true
		}
	}
	return "", false
}

// nodePath is LOAD_AS_FILE, then LOAD_AS_DIRECTORY, for package-relative rel.
func (rs *resolver) nodePath(p *depPackage, rel string) (string, bool) {
	if rel != "" {
		if m, found := rs.nodeFile(p, rel); found {
			return m, true
		}
	}
	return rs.nodeDir(p, rel)
}

// nodeDir is LOAD_AS_DIRECTORY for package-relative directory rel: the file its package.json main
// names (or that file's index), else its index. A package.json the lane cannot parse selects a
// file it cannot name: found with no module.
func (rs *resolver) nodeDir(p *depPackage, rel string) (string, bool) {
	m, ok := p.manifestAt(rel)
	if !ok {
		return "", true
	}
	if m != nil && m.main != "" {
		if r, inside := pkgJoin(rel, m.main); inside {
			if mod, found := rs.nodeFile(p, r); found {
				return mod, true
			}
			if mod, found := rs.nodeFile(p, path.Join(r, "index")); found {
				return mod, true
			}
		}
	}
	return rs.nodeFile(p, path.Join(rel, "index"))
}

// manifestAt is the package.json of package-relative directory rel in read package p: nil when
// the directory has none, ok false when it has one that does not parse.
func (p *depPackage) manifestAt(rel string) (*pkgManifest, bool) {
	if rel == "" {
		return p.manifest, p.manifest != nil
	}
	if !p.files[rel+"/package.json"] {
		return nil, true
	}
	m := p.nested[rel]
	return m, m != nil
}

// loadExts are the extensions any resolver may append to a path a load names: Node's, and those
// a bundler's resolve.extensions commonly lists.
var loadExts = []string{".js", ".json", ".node", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".wasm", vueExtension}

// loadCandidates is every module Node or a bundler may load for a bare load of subpath sub of
// read package p: the exports targets under the load's conditions, plus what a resolver ignoring
// exports selects (main, module, a browser string, index, or the file or directory the subpath
// names, with a directory's own package.json read the same way), plus every path the browser
// field maps a file to. ok is false when any of those is a file the lane did not parse, a
// package.json it cannot parse, a browser mapping to another package, a path outside the
// package, or when nothing at all is selected: what the load runs is then not bounded by what
// was read.
func (rs *resolver) loadCandidates(p *depPackage, sub string, viaRequire bool) ([]string, bool) {
	c := &loadSet{rs: rs, p: p}
	if ex := p.manifest.exports; ex != nil {
		targets := exportsTargets(ex, sub, loadConditions(viaRequire))
		if len(targets) == 0 {
			return nil, false
		}
		for _, t := range targets {
			r, ok := pkgJoin("", t)
			if !isRelativeTarget(t) || !ok || !p.files[r] {
				return nil, false
			}
			c.take(r)
		}
	}
	if sub == "." {
		c.dir("")
	} else if r, ok := pkgJoin("", sub); ok {
		c.path(r)
	} else {
		c.hidden = true
	}
	c.browserMap("", p.manifest)
	if !c.found || c.hidden {
		return nil, false
	}
	sort.Strings(c.mods)
	return c.mods, true
}

// loadSet accumulates loadCandidates.
type loadSet struct {
	rs     *resolver
	p      *depPackage
	mods   []string
	found  bool
	hidden bool
}

// take adds package-relative file rel: JSON runs no code, and any other file the lane did not
// parse hides what the load runs.
func (c *loadSet) take(rel string) {
	c.found = true
	if path.Ext(rel) == ".json" {
		return
	}
	m := c.rs.moduleOf(c.p, rel)
	if m == "" {
		c.hidden = true
		return
	}
	if !slices.Contains(c.mods, m) {
		c.mods = append(c.mods, m)
	}
}

// file adds what any resolver loads for rel as a file: the exact file, else every file rel names
// with one of loadExts. It reports whether there was one.
func (c *loadSet) file(rel string) bool {
	if rel != "" && c.p.files[rel] {
		c.take(rel)
		return true
	}
	any := false
	for _, ext := range loadExts {
		if c.p.files[rel+ext] {
			c.take(rel + ext)
			any = true
		}
	}
	return any
}

// path adds what any resolver loads for rel: the file, else the directory.
func (c *loadSet) path(rel string) {
	if !c.file(rel) {
		c.dir(rel)
	}
}

// entry adds a path a package.json field names, as a file or else that path's index, and reports
// whether there was one.
func (c *loadSet) entry(base, t string) bool {
	r, ok := pkgJoin(base, t)
	if !ok {
		c.hidden = true
		return false
	}
	return c.file(r) || c.file(path.Join(r, "index"))
}

// dir adds what any resolver loads for directory rel: its package.json's main, module and
// browser entries, and its index unless main selects a file.
func (c *loadSet) dir(rel string) {
	m, ok := c.p.manifestAt(rel)
	if !ok {
		c.hidden = true
		return
	}
	mainFound := false
	if m != nil {
		if m.main != "" {
			mainFound = c.entry(rel, m.main)
		}
		for _, t := range []string{m.module, m.browserMain} {
			if t != "" {
				c.entry(rel, t)
			}
		}
		if rel != "" {
			c.browserMap(rel, m)
		}
	}
	if !mainFound {
		c.file(path.Join(rel, "index"))
	}
}

// browserMap adds every path a browser object field in directory rel maps a file to; one mapping
// to another package hides what the load runs.
func (c *loadSet) browserMap(rel string, m *pkgManifest) {
	if m.browserBare {
		c.hidden = true
	}
	for _, t := range m.browserMap {
		c.entry(rel, t)
	}
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
	if rs.prog.deps.pkgs[e.path] == nil || rs.anyResolver && len(mods) == 0 {
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
	pkg     *depPackage
	files   []parseResult
	err     error
	budget  bool // the read budget ran out before the package was read
	capped  bool // the run's parsed-source cap was reached before the package was parsed
	overran bool // a file's parse ran past depFileParseBackstop
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
		pr, err := parseDepSource(ctx, e.path+"/"+f.module, f)
		if errors.Is(err, errParseBackstop) {
			return depParse{overran: true}
		}
		if err != nil {
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
// read into it. First-party analysis is callGraphInternal's, less the declines read dependency
// code covers (coverReadPackages); dependency code adds edges and limits. A cancelled ctx is an
// error, never a partial graph.
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

	layout := buildDepLayout(ctx, buildDir)
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
	// A package whose code is hidden (unread, rewritten by a patch, or compiled) can load any
	// package Node's walk finds from it, declared or not: npm, yarn classic and pnpm's default
	// hoisting put every installed package within reach, so its limit is unbounded.
	addScoped := func(reason, pkg string) {
		dflags.scoped = append(dflags.scoped, plugin.ScopedReason{Reason: reason, Package: pkg})
	}
	d := &depGraph{layout: layout, pkgs: map[string]*depPackage{}}
	var depFiles []fileParse
	// An unread package whose lock marks or may mark an install script withholds run-wide: the
	// script runs at install whether or not anything loads the package.
	unread := func(reason string, e *depEntry) {
		addScoped(reason, e.purl)
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
		case p.budget || p.capped || p.overran:
			unread(plugin.PartialReasonToolFailure, e)
			if p.overran {
				dflags.toolFailure = true
			}
			continue
		}
		switch {
		case p.pkg.installScript:
			dflags.uninspectable = true
		case p.pkg.native:
			addScoped(plugin.PartialReasonUninspectablePackage, e.purl)
		}
		if e.deps != nil {
			// A pnpm or yarn classic package: a copy bundled in its tarball is not in the lock,
			// and its install scripts run unseen, patched or not.
			e.bundles = bundledNames(p.pkg.files)
			if len(e.bundles) > 0 {
				dflags.uninspectable = true
			}
		}
		if e.patched {
			// The install rewrites this package's code; only its verified manifest facts hold.
			addScoped(plugin.PartialReasonUninspectablePackage, e.purl)
			continue
		}
		d.pkgs[e.path] = p.pkg
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
		b := g.built(g.result(callGraphPartiality(prog, flags)), flags.unlisted)
		b.report(buildDir)
		return b.res, b.prov, nil
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

	if !layout.berry && !layout.incomplete && !g.depUnbounded {
		coverReadPackages(prog, g, rewrite)
	}
	flags := mergeFlags(g.flags, dflags)
	flags.scoped = sortedScoped(flags.scoped)
	if g.anyExempt && g.anyProto {
		flags.evaluated = true
		flags.unlisted = true
	}
	// Unresolved and Escaped list first-party code only: dependency code's declined sites, the
	// dependency frames a declined site anywhere can land on, and a run-wide dependency limit
	// are in neither. Dependency code read with nothing declined anywhere hides no site.
	if dflags.uninspectable || len(depFiles) > 0 && (g.declined > 0 || depDeclined(dflags)) {
		flags.unlisted = true
	}
	b := g.built(g.result(callGraphPartiality(prog, flags)), flags.unlisted)
	b.report(buildDir)
	return b.res, b.prov, nil
}

// coverReadPackages retracts the first-party declines that dependency code read into prog
// covers. It runs only when augment bounded every load and call in dependency code
// (graphBuild.depUnbounded). A load is covered when every module any resolver may load for it is read (readLoad)
// and its load edge is in g; augment links each one. A call is resolved again with dependency
// code attached and every resolver's candidates in play: one that now resolves to a function
// whose edge is in g is no longer declined, and one into a read package that names no single
// function, or whose edge is unconnected or absent, stays declined as dynamic dispatch. Every
// other site keeps its decline, and g.flags.uninspectable is recomputed from what stays.
func coverReadPackages(prog *program, g *graphBuild, rewrite func(string) string) {
	rs := prog.resolver()
	rs.anyResolver = true
	linked := func(caller, callee string) bool {
		return g.seen[plugin.CallEdge{Caller: sym(caller), Callee: sym(callee)}] ||
			g.seen[plugin.CallEdge{Caller: sym(rewrite(caller)), Callee: sym(rewrite(callee))}]
	}
	drop := map[int]bool{}
	for _, s := range g.pkgLoads {
		mods, ok := rs.readLoad(s.module, s.spec, s.viaRequire)
		for _, m := range mods {
			ok = ok && linked(moduleInitSCIP(s.module), moduleInitSCIP(m))
		}
		if ok {
			drop[s.at] = true
		}
	}
	entered := g.entered
	for _, s := range g.pkgCalls {
		r := rs.resolveCallSite(s.module, s.cs)
		target, ok := r.edge()
		caller := funcSCIP(s.module, s.cs.callerEnclosing, s.cs.callerName, s.cs.callerArity)
		switch {
		case ok && !s.cs.unconnected && linked(caller, target):
			drop[s.at] = true
		case ok, r.Kind == resolvePackage && r.Reason == plugin.PartialReasonDynamicDispatch:
			// Code the program read: the call may land on any of its functions, none listed.
			g.unresolved[s.at].Reason = plugin.PartialReasonDynamicDispatch
			g.unresolved[s.at].Targets = nil
		default:
			entered = entered || s.entered
		}
	}
	kept := g.unresolved[:0]
	for i, u := range g.unresolved {
		if drop[i] {
			g.declined--
			continue
		}
		kept = append(kept, u)
	}
	g.unresolved = kept
	g.flags.uninspectable = entered
	for _, u := range g.unresolved {
		accumulateReason(&g.flags, u.Reason)
	}
}

// readLoad returns the modules a first-party load of bare specifier spec may run and whether
// those are all of them: no paths alias, workspace member, self-reference or bundler alias claims
// it, no browser field of the loader's package.json remaps, the layout resolves it to a read
// package (read, SRI-verified and unpatched: d.pkgs holds no other), and loadCandidates bounds it.
// augment skips the same specifiers, so the edge check in coverReadPackages also keeps those
// declines; the guards here keep the gate right if augment changes.
func (rs *resolver) readLoad(fromModule, spec string, viaRequire bool) ([]string, bool) {
	if !isDepSpecifier(spec) {
		return nil, false
	}
	if _, _, ok := rs.resolveTsPaths(fromModule, spec); ok {
		return nil, false
	}
	if _, _, _, ok := rs.workspaceMember(spec); ok {
		return nil, false
	}
	name, sub := splitBareSpecifier(spec)
	own, _ := rs.governingPackageJSON(fromModule)
	if own != nil && own.name == name && own.exports != nil {
		return nil, false
	}
	// A browser field in the loader's own package.json may map the specifier elsewhere.
	if remaps(own) || rs.aliased(spec) {
		return nil, false
	}
	d := rs.prog.deps
	e := d.layout.lookup(moduleDir(fromModule), name)
	if e == nil {
		return nil, false
	}
	p := d.pkgs[e.path]
	if p == nil || p.manifest == nil {
		return nil, false
	}
	return rs.loadCandidates(p, sub, viaRequire)
}

// aliased reports whether a bundler alias the build configures may replace bare specifier spec.
func (rs *resolver) aliased(spec string) bool {
	if rs.bctx == nil {
		return false
	}
	name, _ := splitBareSpecifier(spec)
	for _, k := range []string{spec, name, name + "$"} {
		if _, found, _ := rs.bctx.lookupAlias(k); found {
			return true
		}
	}
	return false
}

// remaps reports whether package.json m has a browser object field mapping a path or package to
// another file or package.
func remaps(m *pkgManifest) bool {
	return m != nil && (m.browserBare || len(m.browserMap) > 0)
}

// remapsAlong reports whether a bundler may remap a load from package-relative directory rel of
// read package p: a package.json from rel up to the package root has a browser object field, or
// does not parse.
func (p *depPackage) remapsAlong(rel string) bool {
	if rel == "." {
		rel = ""
	}
	for {
		if m, ok := p.manifestAt(rel); !ok || remaps(m) {
			return true
		}
		if rel == "" {
			return false
		}
		if rel = path.Dir(rel); rel == "." {
			rel = ""
		}
	}
}

// relativeLoadBounded reports whether m, the module Node loads for relative load spec from module
// fromModule of read package p, is every module any resolver may load for it (loadSet). A target
// outside the package is not bounded.
func (rs *resolver) relativeLoadBounded(p *depPackage, fromModule, spec, m string) bool {
	cand := path.Join(moduleDir(fromModule), spec)
	rel, ok := strings.CutPrefix(cand, p.entry.path+"/")
	if cand == p.entry.path {
		rel, ok = "", true
	}
	if !ok {
		return false
	}
	if p.remapsAlong(path.Dir(rel)) {
		return false
	}
	c := &loadSet{rs: rs, p: p}
	if namesDirectory(spec) {
		c.dir(rel)
	} else {
		c.path(rel)
	}
	return !c.hidden && len(c.mods) == 1 && c.mods[0] == m
}

// augment adds the edges dependency code contributes to aug: module loads, calls resolved
// through the layout, versioned boundary edges and conditional roots. It reports false when
// ctx ends first.
func augment(ctx context.Context, prog *program, firstParty, depFiles []fileParse, g, aug *graphBuild, flags *partialFlags) bool {
	rs := prog.resolver()
	pkgRS := &resolver{prog: prog, bctx: rs.bctx, packageOnly: true}
	// anyRS links, besides what Node loads, every module a bundler may load for a bare load
	// (loadCandidates), so coverReadPackages finds each one linked.
	anyRS := &resolver{prog: prog, bctx: rs.bctx, anyResolver: true}
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
			_, mods = anyRS.depTargets(f.module, ls.spec, ls.viaRequire)
			loadEdges(f, mods, loadAlgo(ls.viaRequire))
			if frontend(f.module) {
				anyFrontend = true
				loadEdges(f, rs.frontEntryModules(f.module, ls.spec), loadAlgo(ls.viaRequire))
			}
		}
		for _, cs := range f.calls {
			// An opaque or unconnected call is listed, never connected (callgraph.go).
			if cs.calleeFrame || cs.opaque || cs.unconnected {
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
		if len(b.specifiers) > 0 && pkg.remapsAlong(moduleDir(strings.TrimPrefix(f.module, pkg.entry.path+"/"))) {
			g.depUnbounded = true
		}
		for _, ls := range b.specifiers {
			algo := loadAlgo(ls.viaRequire)
			switch {
			case isRelativeLoad(ls.spec):
				m, dir, viaDir := rs.resolveRelativeDir(f.module, ls.spec)
				if m != "" && !rs.relativeLoadBounded(pkg, f.module, ls.spec, m) {
					g.depUnbounded = true
				}
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
					targets := []string{originPURL(name)}
					for _, c := range d.layout.lookupCandidates(moduleDir(f.module), name) {
						if t := originPURL(c.name); !slices.Contains(targets, t) {
							targets = append(targets, t)
						}
					}
					flags.scoped = append(flags.scoped, plugin.ScopedReason{Reason: plugin.PartialReasonUninspectablePackage, Package: pkg.entry.purl, Targets: targets})
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
				if p := d.pkgs[e.path]; p != nil {
					// Every module any resolver may load is linked; one that cannot be bounded
					// leaves the run's first-party declines in place.
					_, sub := splitBareSpecifier(ls.spec)
					all, ok := anyRS.loadCandidates(p, sub, ls.viaRequire)
					if !ok || rs.aliased(ls.spec) {
						g.depUnbounded = true
					}
					loadEdges(f, all, algo)
				}
			}
		}
		for _, cs := range f.calls {
			caller := sym(funcSCIP(f.module, cs.callerEnclosing, cs.callerName, cs.callerArity))
			if cs.calleeFrame {
				aug.add(plugin.CallEdge{Caller: caller, Callee: sym(funcSCIP(f.module, cs.calleeEnclosing, cs.calleeName, cs.calleeArity))}, provenance{Algo: algoLocal})
				continue
			}
			if cs.opaque {
				// A callee the lane does not track may be any value.
				accumulateReason(flags, plugin.PartialReasonDynamicDispatch)
				continue
			}
			r := rs.resolveCallSite(f.module, cs)
			// An unconnected call draws no edge, as in first-party code (callgraph.go).
			target, connected := r.edge()
			connected = connected && !cs.unconnected
			if connected {
				aug.add(plugin.CallEdge{Caller: caller, Callee: sym(target)}, r.Prov)
				// With every resolver's candidates in play the call may land elsewhere: into a
				// read package naming no single function it is dynamic dispatch, as for
				// first-party calls (coverReadPackages); anything else is not bounded.
				if ar := anyRS.resolveCallSite(f.module, cs); ar.Target != target || ar.Kind != resolveFirstParty {
					if ar.Kind == resolvePackage && ar.Reason == plugin.PartialReasonDynamicDispatch {
						accumulateReason(flags, plugin.PartialReasonDynamicDispatch)
					} else {
						g.depUnbounded = true
					}
				}
			}
			if !cs.unconnected && boundary(f.module, cs, caller) {
				// A boundary edge names the member the call enters, not what it runs: a call
				// resolved to nothing else is declined, and no list carries it.
				if !connected {
					flags.unlisted = true
				}
				continue
			}
			switch {
			case r.Kind == resolveFirstParty && !cs.unconnected:
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

// depDeclined reports whether f, the limits dependency code contributed, declares any: every
// site dependency code declines sets one.
func depDeclined(f partialFlags) bool {
	return f.unresolved || f.uninspectable || f.dynImport || f.computedReq || f.unreadModule || f.evaluated ||
		f.stylesheet || f.unlisted || f.toolFailure || f.unsupported || len(f.scoped) > 0
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
		unlisted:      a.unlisted || b.unlisted,
		toolFailure:   a.toolFailure || b.toolFailure,
		unsupported:   a.unsupported || b.unsupported,
		scoped:        append(append([]plugin.ScopedReason(nil), a.scoped...), b.scoped...),
	}
}

// bundledNames returns the package names a tarball ships under its own top-level node_modules.
func bundledNames(files map[string]bool) map[string]bool {
	out := map[string]bool{}
	for f := range files {
		rest, ok := strings.CutPrefix(f, "node_modules/")
		if !ok {
			continue
		}
		segs := strings.SplitN(rest, "/", 3)
		name := segs[0]
		if strings.HasPrefix(name, "@") && len(segs) > 1 {
			name += "/" + segs[1]
		}
		out[name] = true
	}
	return out
}
