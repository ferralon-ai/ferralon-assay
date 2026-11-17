package jsanalysis

import (
	"cmp"
	"encoding/json"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The load closure is every module that can run: the first-party modules, the modules a launch
// text starts (a package.json script, a process, container, deployment or CI file, a shell
// script), and everything those load, to a fixed point. It is complete only
// when nothing in it can load code the lane cannot name. A package with no module in a complete
// closure, and which no closure module names in a load, never runs.

// entryRoot is one inferred entry point of the build.
type entryRoot struct {
	Lane string `json:"lane"`
	// Kind is "module" (a first-party source file's top level), "bin" (an installed package's
	// binary a launch text names) or "script" (a module a launch text's word loads by
	// specifier, as in `node -r dotenv/config`).
	Kind string `json:"kind"`
	// Selector is the root file: a path relative to the scanned tree, or
	// "npm:<package>/<path in package>" for a file of an installed package.
	Selector string `json:"selector"`
	Name     string `json:"name,omitempty"`
	// Origin is where the root was inferred from: "<dir>/package.json#scripts.<name>",
	// "<dir>/package.json#<key>", or the launch file's path.
	Origin string `json:"origin,omitempty"`

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
	// Roots are the inferred entry points other than first-party modules.
	Roots []entryRoot `json:"roots,omitempty"`

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
}

// loadRecord collects, while the dependency graph is built, what decides the closure.
type loadRecord struct {
	mods map[string]*modLimits
	// first are the lock entries first-party loads resolve to.
	first []*depEntry
	// hidden are the packages whose code, or part of it, the lane does not read.
	hidden []*depEntry
	vetoes map[string]bool
}

func newLoadRecord() *loadRecord {
	return &loadRecord{mods: map[string]*modLimits{}, vetoes: map[string]bool{}}
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
	switch name {
	case "module", "child_process", "worker_threads", "vm", "cluster", "repl", "inspector", "test", "wasi", "sqlite":
		return true
	}
	return false
}

// close computes the closure from the first-party roots and the inferred script roots over the
// first-party edges in g and the dependency edges in aug. kept are the first-party loads no
// read package covers.
func (lr *loadRecord) close(prog *program, g, aug *graphBuild, baseRoots []string, entries []*depEntry, kept []pkgSite) *loadClosure {
	d := prog.deps
	lc := &loadClosure{Installed: installedOrigins(entries)}
	loaded := map[string]bool{}
	hidden := map[*depEntry]bool{}
	for _, e := range lr.hidden {
		hidden[e] = true
	}
	loads := func(e *depEntry) {
		loaded[originPURL(e.name)] = true
		lr.veto(hidden[e], "package "+e.name+" loads and its code is not all read")
	}

	for _, e := range entries {
		// A local or linked package is code of the tree, wherever it is installed from.
		if e.digest == "" {
			loaded[originPURL(e.name)] = true
		}
	}
	roots, rooted := inferScriptRoots(prog, entries, lr)
	lc.Roots = roots
	for _, e := range rooted {
		loads(e)
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
	queue := append([]string(nil), baseRoots...)
	for _, r := range roots {
		queue = append(queue, moduleInitSCIP(r.module))
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if reached[n] {
			continue
		}
		reached[n] = true
		if m, ok := owner[n]; ok && !lc.modules[m] {
			lc.modules[m] = true
			queue = append(queue, moduleInitSCIP(m))
		}
		queue = append(queue, adj[n]...)
	}

	for _, e := range lr.first {
		loads(e)
	}
	for m := range lc.modules {
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
		lr.veto(f.dynImport, "loaded module "+m+" imports a computed specifier")
		lr.veto(f.computedReq, "loaded module "+m+" requires a computed specifier")
		lr.veto(f.unreadModule, "loaded module "+m+" loads a module that is not read")
		lr.veto(f.evaluated, "loaded module "+m+" evaluates code")
		lr.veto(f.toolFailure || f.unsupported, "loaded module "+m+" is not fully parsed")
		lr.veto(ml.loadsCode, "loaded module "+m+" loads a built-in that can load or run other code")
	}
	lr.veto((g.anyExempt || lr.anyExempt(lc.modules)) && (g.anyProto || lr.anyProto(lc.modules)),
		"a loaded module sets a prototype while a computed read is accepted for its literal receiver")

	lr.veto(g.flags.dynImport, "first-party code imports a computed specifier")
	lr.veto(g.flags.computedReq, "first-party code requires a computed specifier")
	lr.veto(g.flags.unreadModule, "first-party code loads a module that is not read")
	lr.veto(g.flags.evaluated, "first-party code evaluates code")
	lr.veto(prog.readFailed || prog.skipped || prog.unreadSource, "first-party code is not fully read")
	for _, s := range kept {
		lr.veto(!isNodeBuiltin(s.spec), "first-party load of "+s.spec+" is not covered by read code")
	}

	lc.Loaded = slices.Sorted(maps.Keys(loaded))
	lc.Vetoes = slices.Sorted(maps.Keys(lr.vetoes))
	lc.Complete = len(lc.Vetoes) == 0
	return lc
}

// scopeCalls bounds the limits that hide calls, not loads, to what a complete closure loads: a
// call the lane does not list, or one into code it does not open, lands only on code that has
// loaded.
func (lc *loadClosure) scopeCalls(flags partialFlags) partialFlags {
	targets := append(append([]string(nil), lc.Loaded...), "")
	bound := func(reason string) {
		flags.scoped = append(flags.scoped, plugin.ScopedReason{Reason: reason, Targets: targets})
	}
	if flags.uninspectable {
		flags.uninspectable = false
		bound(plugin.PartialReasonUninspectablePackage)
	}
	if flags.unlisted {
		flags.unlisted = false
		bound(plugin.PartialReasonUnlistedSites)
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
}

// maxLaunchText bounds one launch file; a larger one is not read and vetoes.
const maxLaunchText = 1 << 20

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
		base == ".npmrc", base == ".yarnrc", base == ".env", strings.HasPrefix(base, ".env."), base == ".envrc",
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

// launchTexts returns every text of the first-party tree that can start the project: each
// package.json script, every other package.json value outside manifestProse, every launchFile,
// and every file that opens with an interpreter line. It walks the whole tree but installed
// packages, and vetoes on lr for a source file the lane does not parse: such a file is a root
// the closure cannot follow.
func launchTexts(prog *program, lr *loadRecord) []launchText {
	var out []launchText
	read := func(p, rel string) (string, bool) {
		data, err := os.ReadFile(p)
		if err != nil || len(data) > maxLaunchText {
			lr.veto(true, rel+" could not be read for the commands it starts")
			return "", false
		}
		return string(data), true
	}
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
			if launchFile(rel) {
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
			if n == 2 && string(head[:]) == "#!" {
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
func inferScriptRoots(prog *program, entries []*depEntry, lr *loadRecord) ([]entryRoot, []*depEntry) {
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
	scanned := map[string]bool{}
	for _, lt := range texts {
		scanned[lt.rel] = true
	}
	// runsUnread reports whether w names a first-party file with no extension that is no launch
	// text: `node ./server` runs it as a module, and the lane parses no such file.
	runsUnread := func(from, w string) bool {
		if w == "" || strings.HasPrefix(w, "-") || path.Ext(w) != "" {
			return false
		}
		for _, base := range []string{path.Dir(from), "."} {
			rel := path.Join(base, w)
			if strings.HasPrefix(rel, "..") || strings.Contains(rel, "node_modules/") || scanned[rel] {
				continue
			}
			if fi, err := os.Lstat(filepath.Join(prog.root, filepath.FromSlash(rel))); err == nil && fi.Mode().IsRegular() {
				return true
			}
		}
		return false
	}

	rs := prog.resolver()
	var roots []entryRoot
	var rooted []*depEntry
	seen := map[entryRoot]bool{}
	add := func(r entryRoot, e *depEntry) {
		rooted = append(rooted, e)
		if r.module != "" && !seen[r] {
			seen[r] = true
			roots = append(roots, r)
		}
	}
	for _, lt := range texts {
		rel, origin := lt.rel, lt.origin
		fetches, manager := false, false
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
			lr.veto(runsUnread(rel, w), origin+" names "+w+", a file the lane does not read")
			if i := strings.LastIndex(w, "node_modules/"); i >= 0 {
				w = w[i+len("node_modules/"):]
			}
			name := w
			if b, ok := strings.CutPrefix(w, ".bin/"); ok {
				name = b
			}
			for _, b := range bins[name] {
				r := entryRoot{Lane: "js", Kind: "bin", Name: name, Origin: origin}
				if b.pkg == nil {
					add(r, b.e)
					continue
				}
				if b.rel == "" {
					lr.veto(true, "script binary "+name+" of package "+b.e.name+" names no file in its package.json")
					add(r, b.e)
					continue
				}
				target := path.Clean(b.rel)
				m, ok := b.pkg.modules[target]
				if !ok {
					lr.veto(true, "script binary "+name+" of package "+b.e.name+" is not a source file the lane parses")
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
					add(entryRoot{}, e)
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
					add(entryRoot{Lane: "js", Kind: "script", Selector: "npm:" + e.name + "/" + file, Name: w, Origin: origin, module: m}, e)
				}
			}
		}
	}
	slices.SortStableFunc(roots, func(a, b entryRoot) int {
		return cmp.Or(strings.Compare(a.Selector, b.Selector), strings.Compare(a.Origin, b.Origin))
	})
	return roots, rooted
}
