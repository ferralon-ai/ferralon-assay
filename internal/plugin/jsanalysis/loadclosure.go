package jsanalysis

import (
	"bytes"
	"cmp"
	"encoding/json"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The load closure is every module that can run: the first-party modules, the modules a launch
// text starts (a package.json script, a process, container, deployment or CI file, a shell
// script), and everything those load, to a fixed point. It is complete only
// when nothing in it can load code the lane cannot name. A package with no module in a complete
// closure, and which no closure module names in a load, never runs.

// scriptRoot is an entry point a launch text starts, and the module it starts. Kind is
// plugin.EntryKindBin (an installed package's binary a launch text names) or
// plugin.EntryKindScript (a module a launch text's word loads by specifier, as in
// `node -r dotenv/config`). Origin is "<dir>/package.json#scripts.<name>",
// "<dir>/package.json#<key>", or the launch file's path.
type scriptRoot struct {
	plugin.EntryRoot
	module string
}

// loadClosure is what one build's closure says about its packages.
type loadClosure struct {
	// Complete reports that the closure holds every module that can run. Vetoes says why not.
	Complete bool     `json:"complete"`
	Vetoes   []string `json:"vetoes,omitempty"`
	// Installed and Loaded are npm PURLs without a version: every package the lockfiles place,
	// and every one with a module in the closure or named by a load in it.
	Installed []string `json:"installed,omitempty"`
	Loaded    []string `json:"loaded,omitempty"`
	// Assumptions are the disclosed assumptions a refutation from this closure rests on.
	Assumptions []string `json:"assumptions,omitempty"`
	// hiddenLoaded are the packages with unread code in the closure.
	hiddenLoaded []plugin.ScopedReason
	// Roots are the entry points other than first-party modules that stand: the inferred ones less
	// those an override removed.
	Roots []plugin.EntryRoot `json:"roots,omitempty"`
	// Entry is the lane's record of the inferred roots, for the report; Removed names the roots an
	// override took out, which the closure does not hold.
	Entry   *plugin.EntryRootRecord `json:"entry,omitempty"`
	Removed []string                `json:"removed,omitempty"`

	modules map[string]bool
}

// modLimits is what one dependency module declares.
type modLimits struct {
	flags partialFlags
	// unbounded marks a load or call some resolver may run code the graph has no edge to.
	unbounded     bool
	exempt, proto bool
	// loadsCode marks a load of a Node built-in that can load or run other code.
	loadsCode bool
	// loads are the lock entries its bare loads resolve to; mayLoad the packages (PURLs without
	// a version) a load the layout does not place may still reach.
	loads   []*depEntry
	mayLoad []string
	// prefixes are the literal prefixes of its prefix loads.
	prefixes []string
}

// prefixSite is one first-party prefix load.
type prefixSite struct{ module, prefix string }

// loadRecord collects, while the dependency graph is built, what decides the closure.
type loadRecord struct {
	mods map[string]*modLimits
	// first are the lock entries first-party loads resolve to.
	first []*depEntry
	// hidden are the packages whose code, or part of it, the lane does not read, each with
	// what bounds the loads of the code it hides.
	hidden map[*depEntry]hiddenBound
	// scripted are the read packages that run an install script.
	scripted []scriptedPackage
	vetoes   map[string]bool
	// entry follows the inferred entry points and the override on them; nil follows none.
	entry *entryTrack
}

// hiddenBound is what the unread code of a package is taken to load. known is false when the
// package's declared dependencies are not read, and nothing bounds it. compiled marks a package
// whose JavaScript is read and whose compiled addon is not.
type hiddenBound struct {
	reason   string // the partiality reason its limit is declared under
	declared []string
	known    bool
	compiled bool
}

type scriptedPackage struct {
	e   *depEntry
	pkg *depPackage
}

func newLoadRecord() *loadRecord {
	return &loadRecord{mods: map[string]*modLimits{}, hidden: map[*depEntry]hiddenBound{}, vetoes: map[string]bool{}}
}

// hide records e as a package with unread code.
func (lr *loadRecord) hide(e *depEntry, reason string, declared []string, known, compiled bool) {
	lr.hidden[e] = hiddenBound{reason: reason, declared: declared, known: known, compiled: compiled}
}

func (lr *loadRecord) veto(cond bool, why string) {
	if cond {
		lr.vetoes[why] = true
	}
}

func (lr *loadRecord) module(m string) *modLimits {
	ml := lr.mods[m]
	if ml == nil {
		ml = &modLimits{}
		lr.mods[m] = ml
	}
	return ml
}

func (lr *loadRecord) load(e *depEntry) {
	if e != nil {
		lr.first = append(lr.first, e)
	}
}

// merged folds into base the limits of the dependency modules in only, or of all when only is
// nil.
func (lr *loadRecord) merged(base partialFlags, only map[string]bool) partialFlags {
	out := base
	for m, ml := range lr.mods {
		if only == nil || only[m] {
			out = mergeFlags(out, ml.flags)
		}
	}
	return out
}

func (lr *loadRecord) any(only map[string]bool, f func(*modLimits) bool) bool {
	for m, ml := range lr.mods {
		if (only == nil || only[m]) && f(ml) {
			return true
		}
	}
	return false
}

func (lr *loadRecord) anyUnbounded() bool {
	return lr.any(nil, func(ml *modLimits) bool { return ml.unbounded })
}

func (lr *loadRecord) anyExempt(only map[string]bool) bool {
	return lr.any(only, func(ml *modLimits) bool { return ml.exempt })
}

func (lr *loadRecord) anyProto(only map[string]bool) bool {
	return lr.any(only, func(ml *modLimits) bool { return ml.proto })
}

func installedOrigins(entries []*depEntry) []string {
	seen := map[string]bool{}
	for _, e := range entries {
		seen[originPURL(e.name)] = true
	}
	return slices.Sorted(maps.Keys(seen))
}

// incomplete is the closure of a build that could not be closed, for why.
func (lr *loadRecord) incomplete(entries []*depEntry, why string) *loadClosure {
	lr.veto(true, why)
	return &loadClosure{Vetoes: slices.Sorted(maps.Keys(lr.vetoes)), Installed: installedOrigins(entries)}
}

// loadCapableBuiltin reports whether spec names a Node built-in through which a module can load
// or run code no load specifier names: another process, a worker, a VM context, a loader hook.
func loadCapableBuiltin(spec string) bool {
	name, _ := splitBareSpecifier(strings.TrimPrefix(spec, "node:"))
	return slices.Contains(loadCapableBuiltins, name)
}

var loadCapableBuiltins = []string{"module", "child_process", "worker_threads", "vm", "cluster", "repl", "inspector", "test", "wasi", "sqlite"}

// close computes the closure from the first-party roots and the inferred script roots over the
// first-party edges in g and the dependency edges in aug. kept are the first-party loads no
// read package covers.
func (lr *loadRecord) close(prog *program, g, aug *graphBuild, baseRoots []string, entries []*depEntry, kept []pkgSite) *loadClosure {
	d := prog.deps
	lc := &loadClosure{Installed: installedOrigins(entries)}
	loaded := map[string]bool{}
	var queue []string
	// A computed load names its module at run time, and unread code names its loads nowhere.
	// Each is taken to stay inside its bound (computedLoadBound, hiddenBound), so every module
	// of every package in the bound may run.
	bound := map[*depEntry]bool{}
	computed, unread, compiled := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var admit func(e *depEntry)
	var project []*depEntry
	projectRead := false
	admitProject := func() {
		if !projectRead {
			projectRead, project = true, projectDirectDeps(prog, lr)
		}
		for _, e := range project {
			admit(e)
		}
	}
	opened := map[*depEntry]bool{}
	loads := func(e *depEntry) {
		loaded[originPURL(e.name)] = true
		h, hidden := lr.hidden[e]
		if !hidden || opened[e] {
			return
		}
		opened[e] = true
		lc.hiddenLoaded = append(lc.hiddenLoaded, plugin.ScopedReason{Reason: h.reason, Package: e.purl})
		if !h.known {
			lr.veto(true, "package "+e.name+" loads, its code is not all read and its declared dependencies are not known")
			return
		}
		// The hidden code may run any module of its own package.
		admit(e)
		for _, x := range resolveDeclared(d, e.path, h.declared) {
			admit(x)
		}
		if h.compiled {
			compiled[e.name] = true
			return
		}
		// Unread JavaScript may hold a computed load, which reaches what computedLoadBound says.
		unread[e.name] = true
		admitProject()
	}
	admit = func(e *depEntry) {
		if bound[e] {
			return
		}
		bound[e] = true
		loads(e)
		pkg := d.pkgs[e.path]
		if pkg == nil {
			return
		}
		for _, id := range slices.Sorted(maps.Values(pkg.modules)) {
			queue = append(queue, moduleInitSCIP(e.path+"/"+id))
		}
	}

	for _, e := range entries {
		// A local or linked package is code of the tree, wherever it is installed from.
		if e.digest == "" {
			loaded[originPURL(e.name)] = true
		}
	}
	roots, rooted := inferScriptRoots(prog, entries, lr)
	for _, r := range roots {
		lc.Roots = append(lc.Roots, r.EntryRoot)
	}
	if lr.entry != nil {
		lc.Entry, lc.Removed = lr.entry.record(), lr.entry.removedNames()
	}
	for _, e := range rooted {
		loads(e)
	}
	scripted := map[string]bool{}
	for _, s := range lr.scripted {
		scripted[s.e.name] = true
		loads(s.e)
	}

	// A module with any reached frame has loaded, so its top level runs too.
	owner := map[string]string{}
	for _, f := range prog.files {
		owner[moduleInitSCIP(f.module)] = f.module
		for _, dc := range f.decls {
			owner[funcSCIP(f.module, dc.enclosing, dc.name, dc.arity)] = f.module
		}
	}
	adj := map[string][]string{}
	for _, es := range [][]plugin.CallEdge{g.edges, aug.edges} {
		for _, e := range es {
			adj[e.Caller.SCIP] = append(adj[e.Caller.SCIP], e.Callee.SCIP)
		}
	}
	reached := map[string]bool{}
	lc.modules = map[string]bool{}
	queue = append(queue, baseRoots...)
	for _, r := range roots {
		queue = append(queue, moduleInitSCIP(r.module))
	}
	whole := map[string]bool{}
	// A prefix load is a computed load whose literal prefix names more than the bound does.
	prefixed := func(pkgPath, module, prefix string) {
		named, ok := prefixTargets(d, entries, pkgPath, module, prefix)
		lr.veto(!ok, "a computed load in "+module+" starts with "+strconv.Quote(prefix)+", which can name code outside its package")
		for _, e := range named {
			admit(e)
		}
	}
	if g.flags.dynImport || g.flags.computedReq {
		computed["first-party code"] = true
		admitProject()
	}
	for _, ps := range g.prefixes {
		prefixed("", ps.module, ps.prefix)
	}
	for _, e := range lr.first {
		loads(e)
	}
	for _, s := range kept {
		if isNodeBuiltin(s.spec) {
			continue
		}
		// A load of an unread package is covered by that package's bound.
		name, _ := splitBareSpecifier(s.spec)
		if e := d.layout.lookup(moduleDir(s.module), name); e != nil && d.pkgs[e.path] == nil && lr.hidden[e].known {
			loads(e)
			continue
		}
		lr.veto(true, "first-party load of "+s.spec+" is not covered by read code")
	}
	// Marking a loaded module's packages can open a hidden one, whose bound adds modules: the
	// walk and the marking repeat until neither adds anything.
	marked := map[string]bool{}
	for len(queue) > 0 {
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if reached[n] {
				continue
			}
			if m, ok := owner[n]; ok && !whole[m] {
				whole[m] = true
				ml, pkg := lr.mods[m], d.pkgOf(m)
				if ml != nil && pkg != nil && (ml.flags.dynImport || ml.flags.computedReq) {
					computed[pkg.entry.name] = true
					lr.veto(pkg.manifest == nil || pkg.manifest.declaredOpen, "a computed load in "+m+" is in a package whose declared dependencies are not read")
					admit(pkg.entry)
					for _, e := range computedLoadBound(d, pkg) {
						admit(e)
					}
					admitProject()
					for _, p := range ml.prefixes {
						prefixed(pkg.entry.path, m, p)
					}
				}
			}
			reached[n] = true
			if m, ok := owner[n]; ok && !lc.modules[m] {
				lc.modules[m] = true
				queue = append(queue, moduleInitSCIP(m))
			}
			queue = append(queue, adj[n]...)
		}
		for _, m := range slices.Sorted(maps.Keys(lc.modules)) {
			if marked[m] {
				continue
			}
			marked[m] = true
			if pkg := d.pkgOf(m); pkg != nil {
				loads(pkg.entry)
			}
			ml := lr.mods[m]
			if ml == nil {
				continue
			}
			for _, e := range ml.loads {
				loads(e)
			}
			for _, t := range ml.mayLoad {
				loaded[t] = true
			}
			f := ml.flags
			lr.veto(f.unreadModule, "loaded module "+m+" loads a module that is not read")
			lr.veto(f.evaluated, "loaded module "+m+" evaluates code")
			lr.veto(f.loaderEscape, "loaded module "+m+" hands a module loader on")
			lr.veto(f.toolFailure || f.unsupported, "loaded module "+m+" is not fully parsed")
			lr.veto(ml.loadsCode, "loaded module "+m+" loads a built-in that can load or run other code")
		}
	}
	lr.veto((g.anyExempt || lr.anyExempt(lc.modules)) && (g.anyProto || lr.anyProto(lc.modules)),
		"a loaded module sets a prototype while a computed read is accepted for its literal receiver")

	lr.veto(g.flags.unreadModule, "first-party code loads a module that is not read")
	lr.veto(g.flags.evaluated, "first-party code evaluates code")
	lr.veto(g.flags.loaderEscape, "first-party code hands a module loader on")
	lr.veto(prog.readFailed || prog.skipped || prog.unreadSource, "first-party code is not fully read")

	if len(computed) > 0 {
		lc.Assumptions = append(lc.Assumptions, computedLoadAssumption(slices.Sorted(maps.Keys(computed))))
	}
	if len(unread) > 0 {
		lc.Assumptions = append(lc.Assumptions, "the code of "+strings.Join(slices.Sorted(maps.Keys(unread)), ", ")+
			", which is not read, is assumed to load only its own package's modules, its declared dependencies and the project's direct dependencies")
	}
	if len(scripted) > 0 {
		lc.Assumptions = append(lc.Assumptions, "the install scripts of "+strings.Join(slices.Sorted(maps.Keys(scripted)), ", ")+
			" are assumed to run only the files of their own package and the commands they name, and to leave the installed tree as locked")
	}
	if len(compiled) > 0 {
		lc.Assumptions = append(lc.Assumptions, "the compiled code of "+strings.Join(slices.Sorted(maps.Keys(compiled)), ", ")+
			" is assumed to load only its own package's modules and its declared dependencies")
	}
	lc.Loaded = slices.Sorted(maps.Keys(loaded))
	lc.Vetoes = slices.Sorted(maps.Keys(lr.vetoes))
	lc.Complete = len(lc.Vetoes) == 0
	return lc
}

// computedLoadAssumption is the assumption a clear rests on when the closure holds a computed
// load: packages are the packages whose loaded code holds one.
func computedLoadAssumption(packages []string) string {
	return "computed module loads in " + strings.Join(packages, ", ") +
		" are assumed to resolve only to that code's own modules, its declared dependencies, the project's direct dependencies and any package a literal prefix names"
}

// prefixTargets returns what the literal prefix of a computed load in module adds to the load's
// bound: the installed packages the prefix names, in whole (`idle/locale/`) or by the start of
// a name (`eslint-plugin-`). pkgPath is the loading package's directory, empty for first-party
// code. It reports false when the prefix can name code no bound describes: a directory outside
// the loading package or inside a node_modules, an absolute path, a URL, a package alias, or a
// built-in that loads or runs other code.
func prefixTargets(d *depGraph, entries []*depEntry, pkgPath, module, prefix string) ([]*depEntry, bool) {
	// Whatever the prefix names, its path must not enter a node_modules, and the runtime part
	// must not be able to complete its last segment into `..` or `node_modules`. A backslash
	// separates paths where the scanned code runs on Windows; import() decodes a percent sign
	// and drops a tab or line break. Names are compared without case, as a file system that
	// folds case resolves them; a prefix whose letters outside ASCII change under that fold
	// is not bounded, so the folded text lines up with the written text byte for byte.
	written := prefix
	prefix = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, written)
	segs := strings.Split(prefix, "/")
	if prefix != strings.ToLower(written) || strings.ContainsAny(prefix, "\\%\t\n\r") || slices.Contains(segs, "node_modules") || opensSegment(segs[len(segs)-1], "..", "node_modules") {
		return nil, false
	}
	if strings.HasPrefix(prefix, "./") || strings.HasPrefix(prefix, "../") {
		slash := strings.LastIndexByte(prefix, '/')
		dir := path.Join(moduleDir(module), written[:slash])
		rel, inside := dir, dir != ".." && !strings.HasPrefix(dir, "../")
		if pkgPath != "" {
			rel, inside = strings.CutPrefix(dir+"/", pkgPath+"/")
		}
		return nil, inside && !strings.Contains("/"+strings.ToLower(rel)+"/", "/node_modules/")
	}
	p := strings.TrimPrefix(prefix, "node:")
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "#") || strings.HasPrefix(p, ".") || strings.Contains(p, ":") || strings.Contains("/"+p+"/", "/../") {
		return nil, false // a dot-leading name is a directory of node_modules itself (.bin, .pnpm)
	}
	parts, n := strings.Split(p, "/"), 1
	if strings.HasPrefix(p, "@") {
		n = 2
	}
	if len(parts) > n {
		name := strings.Join(parts[:n], "/")
		if slices.Contains(loadCapableBuiltins, name) {
			return nil, false
		}
		// The copy Node resolves the name as written to (an alias included), and every
		// package of that name under another case.
		asWritten := strings.Join(strings.Split(written[len(written)-len(p):], "/")[:n], "/")
		e, named := d.layout.walk(moduleDir(module), asWritten)
		if e != nil {
			named = []*depEntry{e}
		}
		for _, x := range entries {
			if strings.EqualFold(x.name, name) && !slices.Contains(named, x) {
				named = append(named, x)
			}
		}
		return named, true
	}
	if slices.ContainsFunc(loadCapableBuiltins, func(b string) bool { return strings.HasPrefix(b, p) }) || opensSegment(p, loadSchemes...) {
		return nil, false
	}
	var named []*depEntry
	for _, e := range entries {
		if strings.HasPrefix(strings.ToLower(e.name), p) {
			named = append(named, e)
		}
	}
	return named, true
}

// loadSchemes are the specifier schemes a load can name code through without naming a package.
var loadSchemes = []string{"node:", "data:", "file:", "http:", "https:"}

// opensSegment reports whether part, the literal text a computed load's runtime part continues,
// can be completed to one of names.
func opensSegment(part string, names ...string) bool {
	return part != "" && slices.ContainsFunc(names, func(n string) bool { return strings.HasPrefix(n, part) })
}

// computedLoadBound returns the installed packages a computed load in pkg is taken to reach
// beyond pkg itself and the project's direct dependencies: the copies Node resolves pkg's
// declared dependencies, peer and optional ones included, to. A name with no single copy on the
// walk admits every candidate.
func computedLoadBound(d *depGraph, pkg *depPackage) []*depEntry {
	if pkg.manifest == nil {
		return nil
	}
	return resolveDeclared(d, pkg.entry.path, pkg.manifest.declared)
}

func resolveDeclared(d *depGraph, fromDir string, names []string) []*depEntry {
	var out []*depEntry
	for _, name := range names {
		e, candidates := d.layout.walk(fromDir, name)
		if e != nil {
			candidates = []*depEntry{e}
		}
		out = append(out, candidates...)
	}
	return out
}

// projectDirectDeps returns the installed copies of every dependency a first-party
// package.json declares, development ones included, resolved from its directory.
func projectDirectDeps(prog *program, lr *loadRecord) []*depEntry {
	var out []*depEntry
	for _, mp := range firstPartyManifests(prog, lr) {
		data, err := os.ReadFile(mp)
		rel, rerr := filepath.Rel(prog.root, filepath.Dir(mp))
		m := parsePkgManifest(data)
		if err != nil || rerr != nil || m == nil || m.declaredOpen {
			lr.veto(true, "a first-party package.json could not be read for its dependencies")
			continue
		}
		dir := filepath.ToSlash(rel)
		out = append(out, resolveDeclared(prog.deps, dir, m.declared)...)
		out = append(out, resolveDeclared(prog.deps, dir, m.devDeclared)...)
	}
	return out
}

// firstPartyManifests returns every first-party package.json, sorted.
func firstPartyManifests(prog *program, lr *loadRecord) []string {
	var manifests []string
	_ = filepath.WalkDir(prog.root, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			lr.veto(true, "a first-party directory could not be read")
			return nil //nolint:nilerr // keep walking: the other manifests are still read.
		}
		if de.IsDir() {
			if de.Name() == "node_modules" || de.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if de.Name() == "package.json" {
			manifests = append(manifests, p)
		}
		return nil
	})
	slices.Sort(manifests)
	return manifests
}

// scopeCalls bounds the limits that hide calls, and the computed loads taken to stay inside
// their bound, to what a complete closure loads: a call the lane does not list, one into code
// it does not open, or a bounded computed load lands only on code that has loaded.
func (lc *loadClosure) scopeCalls(flags partialFlags) partialFlags {
	targets := append(append([]string(nil), lc.Loaded...), "")
	bound := func(reason string) {
		flags.scoped = append(flags.scoped, plugin.ScopedReason{Reason: reason, Targets: targets})
	}
	if flags.uninspectable {
		flags.uninspectable = false
		bound(plugin.PartialReasonUninspectablePackage)
	}
	// The calls a loaded hidden package makes are not read; they land on loaded code.
	for _, s := range lc.hiddenLoaded {
		s.Targets = targets
		flags.scoped = append(flags.scoped, s)
	}
	if flags.unlisted {
		flags.unlisted = false
		bound(plugin.PartialReasonUnlistedSites)
	}
	if flags.dynImport {
		flags.dynImport = false
		bound(plugin.PartialReasonDynamicImportSpecifier)
	}
	if flags.computedReq {
		flags.computedReq = false
		bound(plugin.PartialReasonComputedRequireSpecifier)
	}
	flags.scoped = sortedScoped(flags.scoped)
	return flags
}

// refutes reports whether the closure proves no installed copy of the npm package purl names
// loads: the closure is complete, the lockfiles place at least one copy, and none is loaded.
func (lc *loadClosure) refutes(purl string) bool {
	origin, ok := npmOrigin(purl)
	if lc == nil || !ok || !lc.Complete {
		return false
	}
	return slices.Contains(lc.Installed, origin) && !slices.Contains(lc.Loaded, origin)
}

// npmOrigin returns the version-less npm PURL of purl in the lane's own spelling.
func npmOrigin(purl string) (string, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:npm/")
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest = rest[:i]
	}
	name, err := url.PathUnescape(rest)
	if err != nil || !validNPMName(name) {
		return "", false
	}
	return originPURL(name), true
}

// launchText is one text the lane reads for the commands that start the project.
type launchText struct {
	rel    string // the file, relative to the tree root
	origin string // rel, plus "#scripts.<name>" or "#<key>" inside a package.json
	text   string
	// dep is set for an installed package's install script: its words name files of that
	// package, and rel is the package's own package.json.
	dep *scriptedPackage
}

// installerWords are the commands that install or rewrite packages: an install script that
// names one can leave a tree no lockfile describes.
var installerWords = map[string]bool{
	"npm": true, "npx": true, "pnpm": true, "pnpx": true, "yarn": true, "yarnpkg": true,
	"bun": true, "bunx": true, "corepack": true, "patch-package": true,
	"npm_execpath": true, // $npm_execpath: whichever package manager is running
}

// nodeEvalFlags are Node's options that run their argument as code.
var nodeEvalFlags = map[string]bool{"-e": true, "--eval": true, "-p": true, "--print": true, "-pe": true, "-ep": true}

// shellFlagCommands are the commands whose own flags share a spelling with nodeEvalFlags and run
// no code. After any other word the flag is taken as an interpreter's.
var shellFlagCommands = map[string]bool{"mkdir": true, "test": true, "set": true, "cp": true, "rm": true, "echo": true}

// inlineBuiltins are the built-ins through which code piped or handed to an interpreter starts
// other code. An install script that names one outside a parsed file is not followed.
var inlineBuiltins = map[string]bool{"child_process": true, "worker_threads": true, "vm": true}

// inlineRequires matches an install script that is one `node -e` whose code only requires files
// of its own package by literal relative path, the form a package uses to make its install step
// optional (`node -e "try{require('./postinstall')}catch(e){}"`). The word scan roots each file.
var inlineRequires = regexp.MustCompile(`^\s*node\s+(?:-e|--eval)\s+"\s*(?:try\s*\{\s*)?(?:require\('\./[A-Za-z0-9_./-]+'\)\s*;?\s*)+(?:\}\s*catch\s*\(\s*\w*\s*\)\s*\{\s*\}\s*;?\s*)?"\s*(?:\|\|\s*(?:exit\s+0|true)\s*)?$`)

// namesFile reports whether an install-script word reads as a file path rather than a command,
// a flag or a package name.
func namesFile(w string) bool {
	if strings.HasPrefix(w, "//") || strings.HasPrefix(w, "@") || strings.HasPrefix(w, "/dev/") {
		return false
	}
	switch path.Ext(w) {
	case ".js", ".cjs", ".mjs", ".ts", ".json", ".node", ".sh", ".bash", ".py", ".gyp", ".cmd", ".bat", ".ps1":
		return true
	}
	return w == "." || w == ".." || strings.HasPrefix(w, "./") || strings.HasPrefix(w, "../") || strings.Contains(w, "/")
}

// scriptFile returns the module of pkg that the install-script word w runs as `node <w>`, and
// whether w names a file of the package at all, resolved as Node does: the path as written, with
// an extension, then as a directory (its package.json main, else its index). file is the
// package-relative path of the module, or the word when the file is one the lane does not parse.
func (rs *resolver) scriptFile(pkg *depPackage, w string) (module string, file string, named bool) {
	rel, inside := pkgJoin("", w)
	if !inside {
		return "", "", false
	}
	m, found := rs.nodePath(pkg, rel)
	if !found {
		return "", "", false
	}
	for f, id := range pkg.modules {
		if m != "" && pkg.entry.path+"/"+id == m {
			return m, f, true
		}
	}
	return "", w, true
}

// maxLaunchText bounds one launch file; a larger one is not read and vetoes.
const maxLaunchText = 16 << 20

// unparsedSourceExt are source extensions Node or a bundler runs and the lane does not parse.
var unparsedSourceExt = map[string]bool{".mts": true, ".cts": true, ".svelte": true, ".astro": true, ".mdx": true}

// manifestProse are the package.json keys that hold names and prose, never a command or a module
// the project starts: dependency names would root every dependency.
var manifestProse = map[string]bool{
	"name": true, "version": true, "description": true, "keywords": true, "author": true, "contributors": true,
	"maintainers": true, "license": true, "repository": true, "bugs": true, "homepage": true, "funding": true,
	"engines": true, "packageManager": true, "workspaces": true, "private": true, "publishConfig": true,
	"dependencies": true, "devDependencies": true, "peerDependencies": true, "peerDependenciesMeta": true,
	"optionalDependencies": true, "bundledDependencies": true, "bundleDependencies": true,
	"overrides": true, "resolutions": true, "pnpm": true, "scripts": true,
}

// launchFile reports whether a first-party file's name marks it as one that starts processes:
// a process file, a container or compose file, a process-manager config, an npm or environment
// config, a shell or make script, a git hook or a CI workflow.
func launchFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	ext := path.Ext(base)
	switch {
	// A lockfile names every installed package and starts nothing.
	case base == "pnpm-lock.yaml":
		return false
	// Every YAML and TOML file: compose, Kubernetes and Helm manifests, CI and platform
	// configs all carry start commands and NODE_OPTIONS, under no fixed name.
	case ext == ".yml", ext == ".yaml", ext == ".toml",
		base == "procfile", strings.HasPrefix(base, "procfile."),
		strings.HasPrefix(base, "dockerfile"), strings.HasPrefix(base, "containerfile"), ext == ".dockerfile",
		strings.HasPrefix(base, "ecosystem."), strings.HasPrefix(base, "pm2."),
		base == ".npmrc", base == ".yarnrc", strings.HasPrefix(base, ".env"),
		ext == ".sh", ext == ".bash", ext == ".zsh", ext == ".cmd", ext == ".bat", ext == ".ps1",
		base == "makefile", base == "justfile", base == "jenkinsfile",
		base == "nodemon.json", base == "app.json":
		return true
	}
	for _, dir := range []string{".husky/", ".github/workflows/", ".circleci/", ".devcontainer/"} {
		if strings.HasPrefix(rel, dir) || strings.Contains(rel, "/"+dir) {
			return true
		}
	}
	return false
}

// readLaunchText reads the first-party file rel, vetoing on lr when it cannot be read whole.
func readLaunchText(root, rel string, lr *loadRecord) (string, bool) {
	p := filepath.Join(root, filepath.FromSlash(rel))
	fi, err := os.Stat(p)
	if err == nil && fi.Size() <= maxLaunchText {
		if data, rerr := os.ReadFile(p); rerr == nil {
			return string(data), true
		}
	}
	lr.veto(true, rel+" could not be read for the commands it starts")
	return "", false
}

// setsNodeOptions reports whether the file at p names NODE_OPTIONS, the variable every node
// process reads its preloads from: a file of any kind but prose that sets it starts a module.
// A file it cannot read is taken not to.
func setsNodeOptions(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".md", ".markdown", ".txt", ".rst", ".adoc":
		return false
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Size() > maxLaunchText {
		return false
	}
	data, err := os.ReadFile(p)
	return err == nil && bytes.Contains(data, []byte("NODE_OPTIONS"))
}

// launchTexts returns every text of the first-party tree that can start the project: each
// package.json script, every other package.json value outside manifestProse, every launchFile,
// and every file that opens with an interpreter line. It walks the whole tree but installed
// packages, and vetoes on lr for a source file the lane does not parse: such a file is a root
// the closure cannot follow.
func launchTexts(prog *program, lr *loadRecord) []launchText {
	var out []launchText
	read := func(_, rel string) (string, bool) { return readLaunchText(prog.root, rel, lr) }
	_ = filepath.WalkDir(prog.root, func(p string, de os.DirEntry, err error) error {
		if err != nil {
			lr.veto(true, "a first-party directory could not be read")
			return nil //nolint:nilerr // keep walking: the other files are still read.
		}
		r, rerr := filepath.Rel(prog.root, p)
		if rerr != nil {
			return nil //nolint:nilerr // WalkDir only yields paths under its root.
		}
		rel := filepath.ToSlash(r)
		if de.IsDir() {
			if de.Name() == "node_modules" || de.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !de.Type().IsRegular() {
			return nil
		}
		name := de.Name()
		ext := filepath.Ext(name)
		declaration := strings.HasSuffix(name, ".d.ts") || strings.HasSuffix(name, ".d.mts") || strings.HasSuffix(name, ".d.cts")
		switch {
		case declaration:
			return nil
		case isSourceExt(ext) || unparsedSourceExt[ext]:
			parsed := isSourceExt(ext)
			for _, dir := range strings.Split(path.Dir(rel), "/") {
				parsed = parsed && (dir == "." || !skipDir(dir))
			}
			lr.veto(!parsed, "first-party source "+rel+" is not parsed")
			if launchFile(rel) || setsNodeOptions(p) {
				if text, ok := read(p, rel); ok {
					out = append(out, launchText{rel: rel, origin: rel, text: text})
				}
			}
		case name == "package.json":
			text, ok := read(p, rel)
			var keys map[string]json.RawMessage
			var pj packageJSON
			if !ok || json.Unmarshal([]byte(text), &keys) != nil || json.Unmarshal([]byte(text), &pj) != nil {
				lr.veto(true, rel+" could not be read for its scripts")
				return nil
			}
			for _, script := range slices.Sorted(maps.Keys(pj.Scripts)) {
				out = append(out, launchText{rel: rel, origin: rel + "#scripts." + script, text: pj.Scripts[script]})
			}
			for _, key := range slices.Sorted(maps.Keys(keys)) {
				if !manifestProse[key] {
					out = append(out, launchText{rel: rel, origin: rel + "#" + key, text: string(keys[key])})
				}
			}
		case launchFile(rel):
			if text, ok := read(p, rel); ok {
				out = append(out, launchText{rel: rel, origin: rel, text: text})
			}
		default:
			f, err := os.Open(p)
			if err != nil {
				lr.veto(true, rel+" could not be read for the commands it starts")
				return nil
			}
			var head [2]byte
			n, _ := io.ReadFull(f, head[:])
			_ = f.Close()
			if n == 2 && string(head[:]) == "#!" || setsNodeOptions(p) {
				if text, ok := read(p, rel); ok {
					out = append(out, launchText{rel: rel, origin: rel, text: text})
				}
			}
		}
		return nil
	})
	return out
}

// scriptLoadWords splits a launch text into the words that can name a file, a binary or a
// module specifier.
func scriptLoadWords(script string) []string {
	return strings.FieldsFunc(script, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return false
		}
		return !strings.ContainsRune("@/._-", r)
	})
}

// inferScriptRoots returns the entry points the tree's launch texts (launchTexts) start inside
// installed packages, and the lock entries they run. A script is a shell line the lane does not
// interpret: every word that names an installed package's binary roots that binary, and every
// word that resolves as a module specifier from the script's directory roots what it loads. A
// word that may start code the lane cannot name vetoes the closure on lr.
func inferScriptRoots(prog *program, entries []*depEntry, lr *loadRecord) ([]scriptRoot, []*depEntry) {
	d := prog.deps
	type bin struct {
		e   *depEntry
		pkg *depPackage
		rel string
	}
	bins := map[string][]bin{}
	read := map[*depEntry]bool{}
	for _, e := range entries {
		pkg := d.pkgs[e.path]
		if pkg == nil {
			if !e.binsKnown {
				lr.veto(true, "unread package "+e.name+" may provide a script binary")
			}
			for _, name := range e.bins {
				bins[name] = append(bins[name], bin{e: e})
			}
			continue
		}
		read[e] = true
		lr.veto(pkg.manifest.binUnread, "package "+e.name+" declares binaries the lane cannot read")
		named := map[string]bool{}
		for name, rel := range pkg.manifest.bin {
			named[name] = true
			bins[name] = append(bins[name], bin{e: e, pkg: pkg, rel: rel})
		}
		// npm installs every file of directories.bin as a command named after the file.
		if dir := pkg.manifest.binDir; dir != "" {
			for _, f := range slices.Sorted(maps.Keys(pkg.modules)) {
				if path.Dir(f) == path.Clean(dir) {
					named[path.Base(f)] = true
					bins[path.Base(f)] = append(bins[path.Base(f)], bin{e: e, pkg: pkg, rel: f})
				}
			}
		}
		// A command the lock records and the manifest places nowhere has no file to root.
		for _, name := range e.bins {
			if !named[name] {
				bins[name] = append(bins[name], bin{e: e, pkg: pkg})
			}
		}
	}

	texts := launchTexts(prog, lr)
	for i := range lr.scripted {
		s := &lr.scripted[i]
		for _, name := range slices.Sorted(maps.Keys(s.pkg.installTexts)) {
			rel := s.e.path + "/package.json"
			texts = append(texts, launchText{rel: rel, origin: rel + "#scripts." + name, text: s.pkg.installTexts[name], dep: s})
		}
	}
	scanned := map[string]bool{}
	for _, lt := range texts {
		scanned[lt.rel] = true
	}
	// named returns each first-party file with no extension that w may name and that is not
	// yet a launch text: `node ./server` runs it, and the lane parses no such file, so its
	// words are scanned as a launch text's are.
	named := func(from, w string) []string {
		var files []string
		if w == "" || strings.HasPrefix(w, "-") || path.Ext(w) != "" {
			return nil
		}
		for _, base := range []string{path.Dir(from), "."} {
			rel := path.Join(base, w)
			if strings.HasPrefix(rel, "..") || strings.Contains(rel, "node_modules/") || scanned[rel] || slices.Contains(files, rel) {
				continue
			}
			if fi, err := os.Stat(filepath.Join(prog.root, filepath.FromSlash(rel))); err == nil && fi.Mode().IsRegular() {
				files = append(files, rel)
			}
		}
		return files
	}

	rs := prog.resolver()
	var roots []scriptRoot
	var rooted []*depEntry
	seen := map[scriptRoot]bool{}
	add := func(r scriptRoot, e *depEntry) {
		// The override removes a root here, before it roots anything: Loaded is the closure of
		// what stays.
		if lr.entry.deny(r.EntryRoot) {
			return
		}
		rooted = append(rooted, e)
		if r.module != "" && !seen[r] {
			seen[r] = true
			roots = append(roots, r)
		}
	}
	for i := 0; i < len(texts); i++ {
		lt := texts[i]
		rel, origin := lt.rel, lt.origin
		fetches, manager, cmd := false, false, ""
		for _, w := range scriptLoadWords(lt.text) {
			// A runner that fetches a command the install does not hold runs code no
			// lockfile names, which may load anything installed.
			if fetches && !strings.HasPrefix(w, "-") {
				fetches = false
				if i := strings.LastIndex(w, "@"); i > 0 {
					w = w[:i]
				}
				lr.veto(len(bins[w]) == 0, origin+" runs "+w+" through a package runner and no installed package provides it")
			}
			// exec and dlx are package-runner verbs only after a package manager: a shell's
			// own exec runs a command already on the line.
			switch w {
			case "npx", "pnpx", "bunx":
				fetches = true
			case "dlx", "exec":
				fetches = manager
			}
			manager = w == "npm" || w == "pnpm" || w == "yarn" || w == "bun"
			if s := lt.dep; s != nil {
				lr.veto(installerWords[w] || strings.HasSuffix(w, ".npm_execpath"), origin+" runs "+w+", which can install code no lockfile names")
				// Code given on the command line is JavaScript the lane does not parse.
				// The flag belongs to the last word that is not itself a flag: `mkdir -p` and
				// `test -e` are not code, and a runtime may be named any way.
				if !strings.HasPrefix(w, "-") {
					cmd = w
				}
				lr.veto(nodeEvalFlags[w] && !shellFlagCommands[cmd] && !inlineRequires.MatchString(lt.text), origin+" runs inline code that is more than a require of its package's own files")
				lr.veto(inlineBuiltins[w], origin+" names "+w+", a built-in that can run other code, outside a file the lane parses")
				// A patched package's files are not what runs: its hidden bound stands in.
				// A directory change moves what every later path names, and a path that ends in
				// a slash is the start of a computed one: neither is a file the lane can name.
				lr.veto(w == "cd" || w == "pushd", origin+" changes directory, so the files it names are not placed")
				if m, file, ok := rs.scriptFile(s.pkg, w); strings.HasPrefix(w, "-") || d.pkgs[s.e.path] == nil {
				} else if strings.HasSuffix(w, "/") {
					lr.veto(true, origin+" names "+w+", the start of a path it completes when it runs")
				} else if ok {
					lr.veto(m == "", origin+" names "+file+", a file the lane does not parse")
					if m != "" {
						add(scriptRoot{EntryRoot: plugin.EntryRoot{Lane: plugin.EntryLaneJS, Kind: plugin.EntryKindScript, Selector: "npm:" + s.e.name + "/" + file, Name: w, Origin: origin}, module: m}, s.e)
					}
				} else if e, _ := rs.depTargets(rel, w, true); e == nil && namesFile(w) {
					lr.veto(true, origin+" names "+w+", which is not a file of its package")
				}
			} else {
				for _, f := range named(rel, w) {
					scanned[f] = true
					if text, ok := readLaunchText(prog.root, f, lr); ok {
						texts = append(texts, launchText{rel: f, origin: f, text: text})
					}
				}
			}
			if i := strings.LastIndex(w, "node_modules/"); i >= 0 {
				w = w[i+len("node_modules/"):]
			}
			name := w
			if b, ok := strings.CutPrefix(w, ".bin/"); ok {
				name = b
			}
			for _, b := range bins[name] {
				r := scriptRoot{EntryRoot: plugin.EntryRoot{Lane: plugin.EntryLaneJS, Kind: plugin.EntryKindBin, Name: name, Origin: origin}}
				if b.pkg == nil {
					add(r, b.e)
					continue
				}
				// A bin the caller removed raises none of the vetoes its own file would.
				if b.rel == "" {
					if !lr.entry.deny(r.EntryRoot) {
						lr.veto(true, "script binary "+name+" of package "+b.e.name+" names no file in its package.json")
					}
					add(r, b.e)
					continue
				}
				target := path.Clean(b.rel)
				m, ok := b.pkg.modules[target]
				if !ok {
					if !lr.entry.deny(r.EntryRoot) {
						lr.veto(true, "script binary "+name+" of package "+b.e.name+" is not a source file the lane parses")
					}
					add(r, b.e)
					continue
				}
				r.Selector = "npm:" + b.e.name + "/" + target
				r.module = b.e.path + "/" + m
				add(r, b.e)
			}
			pkgName, _ := splitBareSpecifier(w)
			if strings.HasPrefix(w, ".") || strings.HasPrefix(w, "-") || strings.HasPrefix(w, "/") || !validNPMName(pkgName) {
				continue
			}
			for _, viaRequire := range []bool{true, false} {
				e, mods := rs.depTargets(rel, w, viaRequire)
				if e == nil {
					continue
				}
				if len(mods) == 0 {
					if read[e] {
						lr.veto(true, "script word "+w+" names package "+e.name+" and selects no module the lane parses")
					}
					add(scriptRoot{}, e)
				}
				for _, m := range mods {
					id := strings.TrimPrefix(m, e.path+"/")
					file := id
					for _, f := range slices.Sorted(maps.Keys(d.pkgs[e.path].modules)) {
						if d.pkgs[e.path].modules[f] == id {
							file = f
							break
						}
					}
					add(scriptRoot{EntryRoot: plugin.EntryRoot{Lane: plugin.EntryLaneJS, Kind: plugin.EntryKindScript, Selector: "npm:" + e.name + "/" + file, Name: w, Origin: origin}, module: m}, e)
				}
			}
		}
	}
	slices.SortStableFunc(roots, func(a, b scriptRoot) int {
		return cmp.Or(strings.Compare(a.Selector, b.Selector), strings.Compare(a.Origin, b.Origin))
	})
	return roots, rooted
}
