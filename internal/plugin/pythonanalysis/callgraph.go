package pythonanalysis

import (
	"context"
	"fmt"
	"maps"
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
	// nsDirs holds the paths that name, in some root, a directory with no __init__ file,
	// keyed like byModule.
	nsDirs map[string]bool
	// dirStores holds the names a store through a module object binds in a package with no
	// __init__ file (markModuleStores), keyed like named.
	dirStores map[string]map[string]bool
	// leafMemo caches aliasLeaves by import path, reboundMemo aliasRebound, attrMemo
	// attrTargets.
	leafMemo    map[string][]string
	reboundMemo map[string]bool
	// modVals holds the modules each module attribute may hold (attrModules) and modDeps,
	// per attribute, the attributes whose modules read it.
	modVals map[modKey][]string
	modDeps map[modKey][]modKey
	// launchers are the entry points the build's manifests declare (launchers.go) and the
	// ones its launch files declare (entrypoints.go); launchersUnread records a manifest
	// whose entry points could not be read in full, so ingress discovery may miss a script;
	// launchersUnsupported one that declares entry points in a form the readers do not
	// model.
	launchers            []launchTarget
	launchersUnread      bool
	launchersUnsupported bool
	attrMemo             map[attrKey][]string
	// entryModules holds the modules a declared entrypoint runs (entrypoints.go), which
	// are production code whatever their name.
	entryModules map[string]bool
}

// testCode reports whether a module is test code: named as a test (isTestModule) and run
// by no declared entrypoint.
func (prog *program) testCode(module string) bool {
	return isTestModule(module) && !prog.entryModules[module]
}

// resolveCallee picks the SCIP id of the single declaration among decls that a call with
// callArity explicit arguments names, or ("", false) when there is none or more than one.
// A declaration matches when its parameter list accepts callArity arguments, defaults and
// *args/**kwargs counted (paramShape), and the match is self/cls-tolerant: a method call
// "obj.method(args)" carries one fewer explicit argument than the declaration
// "def method(self, args)", so a list accepting callArity+1 matches too. Zero matches (library/import/builtin) or more
// than one (an ambiguous name the lexer cannot scope-resolve) yields no edge. star of the
// callArity arguments expand into any number, so with star > 0 a declaration matches when
// it takes at least the other callArity-star.
func resolveCallee(decls []funcDecl, callArity, star int) (string, bool) {
	var matches []string
	for _, fd := range decls {
		if star > 0 && (fd.params.variadic || fd.params.max >= callArity-star) ||
			star == 0 && (fd.params.accepts(callArity) || fd.params.accepts(callArity+1)) {
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

// siteCallee resolves a call site to the one declaration its edge ends at, if any, and
// returns the leaf names the escape scan uses for it (siteLeaves).
func (p *program) siteCallee(f *fileParse, cs callSite) (callee string, ok bool, escape []string) {
	edge, escape := p.siteLeaves(f, cs)
	callee, ok = resolveCallee(p.siteDecls(f, cs, edge), cs.calleeArity, cs.calleeStar)
	return callee, ok, escape
}

// siteLeaves is the leaf names a call site may stand for. A name stands for the
// declarations under it unless the scope that decides it binds it only by dependency import
// (depOnly). It stands for a first-party function an import binds to it under another name
// only where the caller holds that binding (aliasBound): a bare call whose name the caller's
// scopes bind by import, not shadowed by a parameter or local, or a call through a name
// bound to a first-party module that re-exports the leaf, along a path whose attributes may
// themselves hold modules. Where no scope decides a chain's head, the paths the file's star
// imports may bind it to stand beside those (starImportPaths). escape is the wider set the
// escape scan uses: every alias the file binds the name to in any scope, and the star
// imports' paths.
func (p *program) siteLeaves(f *fileParse, cs callSite) (edge, escape []string) {
	name := cs.calleeName
	if name == "" {
		return nil, nil
	}
	if !f.depOnly(cs) {
		edge = []string{name}
	}
	if len(cs.calleeChain) <= 1 {
		if paths, ok := f.aliasBound(name, cs.scopes); ok && !cs.inner {
			edge = p.withAliases(edge, paths)
		}
		return edge, p.withAliases(p.withAliases([]string{name}, edge), f.anyScopeBinds(name))
	}
	head := cs.calleeChain[0]
	mid := strings.Join(cs.calleeChain[1:len(cs.calleeChain)-1], "/")
	via := func(paths []string) []string {
		var out []string
		for _, path := range paths {
			if mid != "" {
				path += "/" + mid
			}
			out = append(out, path+"/"+name)
		}
		return out
	}
	if paths, ok := f.aliasBound(head, cs.scopes); ok && !cs.inner {
		edge = p.withAliases(edge, via(paths))
	}
	stars := p.starImportPaths(f, head)
	if _, decided := f.deciding(cs); !decided && !cs.inner && !cs.shadowed {
		edge = p.withAliases(edge, via(stars))
	}
	return edge, p.withAliases(p.withAliases([]string{name}, edge), via(append(f.anyScopeBinds(head), stars...)))
}

// starImportPaths is the paths the file's first-party star imports may bind name to: the name in
// each star-imported module that may bind it other than by the star imports followed here
// (starMayBindBesides) or has a submodule by the name, which a package's star import binds once
// something has loaded it. The star-imported modules' own star imports are followed in turn,
// each module once.
func (p *program) starImportPaths(f *fileParse, name string) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(stars []string)
	walk = func(stars []string) {
		for _, star := range stars {
			if seen[star] {
				continue
			}
			seen[star] = true
			if path := star + "/" + name; p.starMayBindBesides(star, name, true) || len(p.byModule[path]) > 0 {
				out = append(out, path)
			}
			for _, i := range p.byModule[star] {
				walk(p.files[i].starPaths)
			}
		}
	}
	walk(f.starPaths)
	return out
}

// deciding finds the scope that decides the name a site calls (a chain's head): the
// innermost of the site's def scopes, then the module, that binds it at all. ok is false
// when no binding the scanner sees decides it: a lambda or comprehension variable, a class
// attribute, computed-name access or a module-scope star import may bind it, or nothing in
// the file does.
func (f *fileParse) deciding(cs callSite) (scope string, ok bool) {
	if cs.inner || cs.shadowed || f.computed {
		return "", false
	}
	head := cs.calleeName
	if len(cs.calleeChain) > 1 {
		head = cs.calleeChain[0]
	}
	for i := len(cs.scopes) - 1; i >= -1; i-- {
		scope := ""
		if i >= 0 {
			scope = cs.scopes[i]
		}
		if scope == "" && len(f.stars) > 0 {
			return "", false
		}
		if len(f.fpBinds[scope][head])+f.binders[scope][head]+f.depImports[scope][head] > 0 || f.defs[scope][head] {
			return scope, true
		}
	}
	return "", false
}

// depOnly reports whether the scope that decides a site's name binds it only by dependency
// import. The call then runs dependency code, or a class member or a function handed over
// as a value, which escape anyway, so no first-party declaration is named by the leaf
// alone: `json.loads(x)` is not a call to a first-party loads.
func (f *fileParse) depOnly(cs callSite) bool {
	scope, ok := f.deciding(cs)
	if !ok {
		return false
	}
	head := cs.calleeName
	if len(cs.calleeChain) > 1 {
		head = cs.calleeChain[0]
	}
	return f.depImports[scope][head] > 0 && len(f.fpBinds[scope][head]) == 0 &&
		f.binders[scope][head] == 0 && !f.defs[scope][head] && !f.depNamed[scope][head]
}

// siteDecls is the declarations a site's edge may name. Where the deciding scope binds the
// name by first-party import, they are the functions the import path names (declsAt); a
// chain's head names a module, so the path runs on through the chain to its leaf, and a
// module on the way that binds the leaf by a class, an assignment or a dependency import
// names nothing (declsAt's decided), nor does a path whose modules bind no function by the
// name. Where the module binds a bare name by def, the module-level defs are candidates
// beside any import of the name, unless a class or an assignment of the name may replace
// them (ownDefs); a def inside a function body is never one. Otherwise, or when a path
// leaves the modules the lane reads (declsAt's open), they are every declaration under the
// leaves (declsNamed).
func (p *program) siteDecls(f *fileParse, cs callSite, leaves []string) []funcDecl {
	if len(leaves) == 0 {
		return nil
	}
	scope, ok := f.deciding(cs)
	if !ok {
		return p.declsNamed(leaves)
	}
	var out []funcDecl
	head, rest := cs.calleeName, ""
	if len(cs.calleeChain) > 1 {
		head, rest = cs.calleeChain[0], "/"+strings.Join(cs.calleeChain[1:], "/")
	}
	if paths, bound := f.aliasBound(head, cs.scopes); bound {
		for _, path := range paths {
			at, decided, open := p.declsAt(path + rest)
			if !decided || len(at) == 0 && !open {
				return nil
			}
			if len(at) == 0 || open {
				return appendDecls(p.declsNamed(leaves), at)
			}
			out = appendDecls(out, at)
		}
	}
	if len(cs.calleeChain) <= 1 && f.defs[scope][head] {
		if scope == "" {
			return appendDecls(out, f.ownDefs(head))
		}
		return p.declsNamed(leaves)
	}
	if len(out) == 0 {
		return p.declsNamed(leaves)
	}
	return out
}

// ownDefs is the module-level defs of name in the file when the module scope binds the name
// by no class and no assignment; an import of the name beside them is a further candidate
// the caller adds. A def inside a function body is no candidate.
func (f *fileParse) ownDefs(name string) []funcDecl {
	if !f.topFuncs[name] || f.binders[""][name] > 0 {
		return nil
	}
	var out []funcDecl
	for _, fd := range f.decls {
		if fd.name == name && len(fd.enclosing) == 0 && !fd.inDef {
			out = append(out, fd)
		}
	}
	return out
}

// topDefs is the module-level defs of name in the file when the module scope binds the name
// by def alone: not by a class, an import, an assignment or another value binding (a later
// "f = other.f" replaces the def). A def inside a function body binds the name there, not
// at module level, and is no candidate.
func (f *fileParse) topDefs(scope, name string) []funcDecl {
	if scope != "" || f.depImports[""][name] > 0 || len(f.fpBinds[""][name]) > 0 {
		return nil
	}
	return f.ownDefs(name)
}

// declsAt is the top-level functions an import path ("pkg/m/f") names: the defs of f at
// module level in the modules pkg/m names (topDefs), and what each such module's own
// first-party imports and star imports bind f to, followed in turn. A path through a
// module's attribute ("pkg/x/f", pkg binding x) follows what the module binds x to the same
// way. Each path is visited once, so an import cycle ends, and a re-export through the cycle
// is still followed to its def. A path that meets a module's binding the walk is following,
// with a longer path left after the attribute, is not followed: the path only lengthens
// through an import whose module part names no parsed module (from pkg.hooks.after import
// after, with no pkg/hooks/after), read as an attribute path that leads back to the binding
// itself. decided is false then, and when a module on the way binds f, the attribute by
// anything but defs at module level,
// first-party imports and star imports (bindsOtherwise), or a package on the way rebinds its
// submodule's name (rebound): what it holds there is not a declaration the walk can name.
// open is true when the path leaves the modules the lane reads: a module no file is, or a
// class's member; the name then decides the candidates, beside any the walk found.
func (p *program) declsAt(path string) (decls []funcDecl, decided, open bool) {
	visited := map[string]bool{}
	// follows holds, for each (module, attribute) binding being followed, the length of the
	// path left after the attribute at its outermost follow.
	follows := map[string]int{}
	following := func(mod, attr, rest string) (ok bool, done func()) {
		key, left := mod+"|"+attr, strings.Count(rest, "/")
		if rest != "" {
			left++
		}
		if n, on := follows[key]; on {
			return left <= n, func() {}
		}
		follows[key] = left
		return true, func() { delete(follows, key) }
	}
	var out []funcDecl
	decided = true
	var walk func(string)
	walk = func(path string) {
		if visited[path] {
			return
		}
		visited[path] = true
		mod, leaf := parentModule(path), path[strings.LastIndexByte(path, '/')+1:]
		if mod == "" {
			return
		}
		if len(p.byModule[mod]) == 0 {
			segs := strings.Split(path, "/")
			k := len(segs) - 2
			for k > 0 && len(p.byModule[strings.Join(segs[:k], "/")]) == 0 {
				k--
			}
			if k == 0 {
				open = true
				return
			}
			if p.rebound(segs[:k]) {
				decided = false
				return
			}
			attr, rest := segs[k], strings.Join(segs[k+1:], "/")
			ok, done := following(strings.Join(segs[:k], "/"), attr, rest)
			defer done()
			if !ok {
				decided = false
				return
			}
			for _, i := range p.byModule[strings.Join(segs[:k], "/")] {
				g := &p.files[i]
				switch {
				case g.defs[""][attr] && !g.topFuncs[attr]:
					open = true // a class's member
				case g.bindsOtherwise(attr):
					decided = false
					return
				}
				for _, next := range g.fpBinds[""][attr] {
					walk(next + "/" + rest)
				}
				for _, star := range g.starPaths {
					walk(star + "/" + attr + "/" + rest)
				}
			}
			return
		}
		if p.rebound(strings.Split(mod, "/")) {
			decided = false
			return
		}
		ok, done := following(mod, leaf, "")
		defer done()
		if !ok {
			decided = false
			return
		}
		for _, i := range p.byModule[mod] {
			g := &p.files[i]
			if g.bindsOtherwise(leaf) {
				decided = false
				return
			}
			out = appendDecls(out, g.topDefs("", leaf))
			for _, next := range g.fpBinds[""][leaf] {
				walk(next)
			}
			for _, star := range g.starPaths {
				walk(star + "/" + leaf)
			}
		}
	}
	walk(path)
	return out, decided, open
}

// rebound reports whether a package on a module path binds the name of the next segment, its
// submodule, to anything but that submodule: by a value (bindsOtherwise), by a first-party
// import of another path, or so through first-party star imports, followed transitively.
func (p *program) rebound(segs []string) bool {
	for j := 1; j < len(segs); j++ {
		pkg, sub := strings.Join(segs[:j], "/"), segs[j]
		self := pkg + "/" + sub
		for _, i := range p.byModule[pkg] {
			g := &p.files[i]
			// A relative import in the package, or in a module it star-imports, resolves
			// against the package file's own module path.
			own := g.module + "/" + sub
			seen := map[string]bool{}
			var binds func(h *fileParse) bool
			binds = func(h *fileParse) bool {
				if h.bindsOtherwise(sub) || slices.ContainsFunc(h.fpBinds[""][sub], func(b string) bool { return b != self && b != own }) {
					return true
				}
				for _, star := range h.starPaths {
					if seen[star] {
						continue
					}
					seen[star] = true
					for _, k := range p.byModule[star] {
						if binds(&p.files[k]) {
							return true
						}
					}
				}
				return false
			}
			if binds(g) {
				return true
			}
		}
	}
	return false
}

// bindsOtherwise reports whether the module scope binds name by something besides defs
// topDefs names, first-party imports and star imports: an assignment, a dependency import, a
// class, or a def beside an import of the name.
func (f *fileParse) bindsOtherwise(name string) bool {
	return f.binders[""][name] > 0 || f.depImports[""][name] > 0 ||
		(f.defs[""][name] && len(f.topDefs("", name)) == 0)
}

// appendDecls adds each of add not already in out.
func appendDecls(out, add []funcDecl) []funcDecl {
	for _, fd := range add {
		s := fd.scip()
		if !slices.ContainsFunc(out, func(o funcDecl) bool { return o.scip() == s }) {
			out = append(out, fd)
		}
	}
	return out
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
// names a function, and when a module the path's prefix may hold binds that leaf by a
// first-party import itself, the path that import names is followed in turn. The prefix is
// an attribute chain from the top package, so the modules it may hold come from attrModules,
// segment by segment. Each module and leaf is visited once, so the walk ends.
func (p *program) aliasLeaves(path string) []string {
	if out, ok := p.leafMemo[path]; ok {
		return out
	}
	visited := map[modKey]bool{}
	var out []string
	var walk func(mods []string, leaf string)
	walk = func(mods []string, leaf string) {
		if !slices.Contains(out, leaf) {
			out = append(out, leaf)
		}
		for _, mod := range mods {
			if visited[modKey{mod, leaf}] {
				continue
			}
			visited[modKey{mod, leaf}] = true
			for _, i := range p.byModule[mod] {
				f := &p.files[i]
				for _, next := range f.attrBinds(leaf) {
					walk(p.bindPrefix(f, leaf, next, p.attrModules), next[strings.LastIndexByte(next, '/')+1:])
				}
			}
		}
	}
	segs := strings.Split(path, "/")
	walk(p.chainModules(segs[:len(segs)-1], p.attrModules), segs[len(segs)-1])
	p.leafMemo[path] = out
	return out
}

// modKey names the attribute name of module mod.
type modKey struct{ mod, name string }

// chainModules is the modules the attribute chain segs may hold, from the top package segs[0]
// on, reading each attribute's modules through get.
func (p *program) chainModules(segs []string, get func(modKey) []string) []string {
	if len(segs) == 0 {
		return nil
	}
	mods := []string{segs[0]}
	for _, s := range segs[1:] {
		var next []string
		for _, m := range mods {
			for _, v := range get(modKey{m, s}) {
				if !slices.Contains(next, v) {
					next = append(next, v)
				}
			}
		}
		mods = next
	}
	return mods
}

// bindPrefix is the modules whose attribute a first-party import in file f binding name to
// path reads. A from-import finds its module in sys.modules whatever a package binds, so that
// is the path's own prefix; a dotted `import a.b.c as d` binds an attribute chain from the top
// package instead, so its prefix holds whatever that chain may hold, the prefix's own module
// among them.
func (p *program) bindPrefix(f *fileParse, name, path string, get func(modKey) []string) []string {
	mod := parentModule(path)
	if mod == "" {
		return nil
	}
	if f.chainBinds[name+"\x00"+path] {
		return p.chainModules(strings.Split(mod, "/"), get)
	}
	return []string{mod}
}

// attrModules is the modules attribute k.name of module k.mod may hold, whichever binding
// ran last: the submodule of that name, a top-level module a first-party import binds the
// name to, and the modules the path of each other first-party import of the name in the
// package, itself or through its star imports, may hold. It is the least fixpoint over the
// attributes those imports read, solved by worklist and kept, so import-as chains that read
// one another end; every module in it is a named path, so the sets are bounded.
func (p *program) attrModules(k modKey) []string {
	if _, ok := p.modVals[k]; ok {
		return p.modVals[k]
	}
	p.modVals[k] = nil
	queue, queued := []modKey{k}, map[modKey]bool{k: true}
	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]
		queued[at] = false
		get := func(dep modKey) []string {
			if _, ok := p.modVals[dep]; !ok {
				p.modVals[dep] = nil
				queue, queued[dep] = append(queue, dep), true
			}
			if !slices.Contains(p.modDeps[dep], at) {
				p.modDeps[dep] = append(p.modDeps[dep], at)
			}
			return p.modVals[dep]
		}
		vals, grew := p.modVals[at], false
		add := func(m string) {
			if !slices.Contains(vals, m) {
				vals, grew = append(vals, m), true
			}
		}
		if self := at.mod + "/" + at.name; p.named[self] {
			add(self)
		}
		for _, i := range p.byModule[at.mod] {
			p.subBinds(&p.files[i], at.mod, at.name, func(h *fileParse, b string) {
				if !strings.Contains(b, "/") {
					if p.named[b] {
						add(b)
					}
					return
				}
				leaf := b[strings.LastIndexByte(b, '/')+1:]
				for _, m := range p.bindPrefix(h, at.name, b, get) {
					for _, v := range get(modKey{m, leaf}) {
						add(v)
					}
				}
			})
		}
		if grew {
			p.modVals[at] = vals
			for _, d := range p.modDeps[at] {
				if !queued[d] {
					queue, queued[d] = append(queue, d), true
				}
			}
		}
	}
	return p.modVals[k]
}

// subBinds calls bind with each path a package file g binds its submodule's name sub to by
// first-party import, itself or through its star imports followed transitively, other than
// that submodule, and the file whose import binds it.
func (p *program) subBinds(g *fileParse, pkg, sub string, bind func(h *fileParse, path string)) {
	self, own := pkg+"/"+sub, g.module+"/"+sub
	seen := map[string]bool{}
	var binds func(h *fileParse)
	binds = func(h *fileParse) {
		for _, b := range h.attrBinds(sub) {
			if b != self && b != own {
				bind(h, b)
			}
		}
		for _, star := range h.starPaths {
			if seen[star] {
				continue
			}
			seen[star] = true
			for _, k := range p.byModule[star] {
				binds(&p.files[k])
			}
		}
	}
	binds(g)
}

// aliasRebound reports whether a module that aliasLeaves follows an import path through may
// bind the leaf some other way than the import or star import it follows, so the name may hold something
// else when another module imports it (markModuleStores must have run).
func (p *program) aliasRebound(path string) bool {
	if r, ok := p.reboundMemo[path]; ok {
		return r
	}
	visited := map[string]bool{}
	var walk func(string) bool
	walk = func(path string) bool {
		if visited[path] || !strings.Contains(path, "/") {
			return false
		}
		visited[path] = true
		mod, leaf := parentModule(path), path[strings.LastIndexByte(path, '/')+1:]
		if p.moduleRebinds(mod, leaf) {
			return true
		}
		for _, i := range p.byModule[mod] {
			for _, next := range p.files[i].fpBinds[""][leaf] {
				if walk(next) {
					return true
				}
			}
			for _, star := range p.files[i].starPaths {
				if walk(star + "/" + leaf) {
					return true
				}
			}
		}
		return false
	}
	r := walk(path)
	p.reboundMemo[path] = r
	return r
}

// moduleRebinds reports whether module mod's namespace may hold more than one binding of
// name, or one that is a value: a value or dependency binding at module scope, two
// first-party imports or defs, a star import that may bind it, computed-name access, or a
// store through a module object. A literal None binding is no alternative.
func (p *program) moduleRebinds(mod, name string) bool {
	segs := strings.Split(mod, "/")
	for a := range segs {
		if p.dirStores[strings.Join(segs[a:], "/")][name] {
			return true
		}
	}
	for _, i := range p.byModule[mod] {
		g := &p.files[i]
		if g.computed || g.storedAny || g.storedNames[name] || g.binders[""][name] > 0 || g.depImports[""][name] > 0 {
			return true
		}
		n := len(g.fpBinds[""][name]) + len(g.stars) - len(g.starPaths)
		if g.defs[""][name] {
			n++
		}
		for _, path := range g.starPaths {
			if p.starMayBind(path, name) {
				n++
			}
		}
		if n > 1 {
			return true
		}
	}
	return false
}

// starMayBind reports whether a star import of a first-party module may bind name: the
// module declares or imports it at top level, star-imports or computes names itself, or is
// not a module the lane reads.
func (p *program) starMayBind(path, name string) bool {
	return p.starMayBindBesides(path, name, false)
}

// starMayBindBesides is starMayBind, except that with walked set the module's first-party
// star imports don't count: the caller follows those itself.
func (p *program) starMayBindBesides(path, name string, walked bool) bool {
	if len(p.byModule[path]) == 0 {
		return true
	}
	for _, i := range p.byModule[path] {
		g := &p.files[i]
		stars := len(g.stars)
		if walked {
			stars -= len(g.starPaths)
		}
		if g.topNames[name] || stars > 0 || g.computed || g.storedAny || g.storedNames[name] {
			return true
		}
	}
	return false
}

// siteRebound reports whether a site's edge follows an import through a module that may
// bind the name another way (aliasRebound): the name it calls, for a bare call, or the
// chain's head, each module the chain reads through it, and the attribute it calls.
func (p *program) siteRebound(f *fileParse, cs callSite) bool {
	if cs.calleeName == "" || cs.inner {
		return false
	}
	head := cs.calleeName
	if len(cs.calleeChain) > 1 {
		head = cs.calleeChain[0]
	}
	paths, ok := f.aliasBound(head, cs.scopes)
	if !ok {
		return false
	}
	mid := ""
	if len(cs.calleeChain) > 2 {
		mid = "/" + strings.Join(cs.calleeChain[1:len(cs.calleeChain)-1], "/")
	}
	for _, path := range paths {
		if p.aliasRebound(path) {
			return true
		}
		if len(cs.calleeChain) > 1 && p.named[path+mid] && p.aliasRebound(path+mid+"/"+cs.calleeName) {
			return true
		}
		for k := 2; k < len(cs.calleeChain); k++ {
			if pre := path + "/" + strings.Join(cs.calleeChain[1:k], "/"); p.named[pre] && p.aliasRebound(pre) {
				return true
			}
		}
	}
	return false
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
	params    paramShape // the argument counts a call may pass
	inDef     bool
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
// every function in the file escape. opaque records a dynamic import whose module the
// scanner cannot name (non-literal argument, entry-point group, package walk), and
// importPaths every slash path, and each package above it, that the file's imports, star
// imports, literal dynamic imports and sys.modules lookups name, first-party or not;
// imports holds the dotted modules the file's import statements name (importedModules).
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
	// globalBinds holds the first-party paths defs' imports bind to module attributes they
	// declare global, by name.
	globalBinds map[string][]string
	// chainBinds holds, keyed name+"\x00"+path, the first-party paths a dotted
	// `import a.b as c` in the file binds a name to.
	chainBinds map[string]bool
	depBinds   map[string]map[string]bool
	locals     map[string]map[string]bool
	// storedNames and storedAny are what stores through a module object may rebind in the
	// file's namespace (markModuleStores): those names, or any name.
	storedNames map[string]bool
	storedAny   bool
	// own is what the file may bind in its own namespace by computed access, which
	// markModuleStores applies as stores through its own module.
	own ownStores
	// plain holds the names a scope rebinds on every path: parameters, straight-line
	// assignments and straight-line dependency imports or instances.
	plain map[string]map[string]bool
	// binders, defs and depImports count a name's other bindings per scope (fileScan's
	// binders and defs, and the dependency imports), for siteComplete.
	binders    map[string]map[string]int
	defs       map[string]map[string]bool
	depImports map[string]map[string]int
	// reads, opaque and unreadValue are fileScan's (see recordReads and markOpaque).
	reads       map[string][]string
	opaque      map[string]bool
	unreadValue map[string]bool
	modValues   []string
	computed    bool
	// wrapped lists the defs under a decorator that may replace them with other code.
	wrapped []funcDecl
	// stars are the modules the file star-imports; starPaths the first-party ones' paths.
	stars     []string
	starPaths []string
	// settings and urlViews are the launchers the file writes (launchers.go): its Django
	// application settings and the views its URL patterns register.
	settings []launchTarget
	urlViews []urlView
	// classes maps each class the file declares outside a def, by its dotted class path, to
	// its base expressions.
	classes map[string][]string
	// topFuncs holds the names the file defines by a module-level def and no class of the
	// same name; depNamed the dependency imports, by scope, whose path a first-party module
	// path contains (a first-party package the distribution scan does not see as one).
	topFuncs map[string]bool
	depNamed map[string]map[string]bool
	// importOpaque records a dynamic import whose module the file does not name (#348's
	// opaque, renamed beside fileScan's opaque map).
	importOpaque bool
	imports      []string
	importPaths  []string
	// packages are the dotted packages a star import or an __import__ with a fromlist may
	// load submodules of; packagePaths their slash paths. importsUnread records an import
	// statement importedModules could not read.
	packages      []string
	packagePaths  []string
	importsUnread bool
}

// aliasBound returns the first-party import paths a name stands for at a site in the given
// def scopes: the innermost scope that binds it decides, then the module. When that scope
// binds the name by first-party import, the paths stand beside an alternative binding in an
// if or try block (an import fallback, "try: from .impl import f as g / except ImportError:
// g = None", binds both). A parameter, or an assignment, dependency import or instance on
// the scope's straight-line path, rebinds the name on every path, so ok is false, as it is
// when the scope binds the name only locally or by a dependency: the name may hold
// something else. The paths still escape (anyScopeBinds).
func (f *fileParse) aliasBound(name string, scopes []string) ([]string, bool) {
	for i := len(scopes) - 1; i >= -1; i-- {
		scope := ""
		if i >= 0 {
			scope = scopes[i]
		}
		if paths := f.fpBinds[scope][name]; len(paths) > 0 && !f.plain[scope][name] {
			return paths, true
		}
		if f.locals[scope][name] || f.depBinds[scope][name] {
			return nil, false
		}
	}
	return nil, false
}

// siteComplete reports whether a site's edges are all it can reach: the name it calls (a
// chain's head) has at most one binding that can reach it, in the innermost scope that binds
// the name. A literal None binding is no alternative, and neither is a dependency import
// whose boundary edge the site draws (depDrawn). A bare call through a name only a value
// binds (a parameter, assignment or instance) has no edge to that value, so it is never
// complete; nor is a call through a lambda or comprehension variable, nor any site in a file
// with computed-name access, which may rebind any name (globals()["g"] = ...). A name the
// module scope decides is never complete in a file with a star import, which may bind any
// name, nor when a store through a module object may rebind it (markModuleStores).
func (f *fileParse) siteComplete(cs callSite, depDrawn bool) bool {
	if cs.inner || cs.shadowed || f.computed {
		return false
	}
	head := cs.calleeName
	if len(cs.calleeChain) > 1 {
		head = cs.calleeChain[0]
	}
	for i := len(cs.scopes) - 1; i >= -1; i-- {
		scope := ""
		if i >= 0 {
			scope = cs.scopes[i]
		}
		fp, vals, dep := len(f.fpBinds[scope][head]), f.binders[scope][head], f.depImports[scope][head]
		def := 0
		if f.defs[scope][head] {
			def = 1
		}
		if scope == "" && (len(f.stars) > 0 || f.storedAny || f.storedNames[head]) {
			return false
		}
		if fp+vals+dep+def == 0 {
			continue
		}
		if depDrawn && dep > 0 {
			dep--
		}
		if vals > 0 && len(cs.calleeChain) <= 1 {
			return false
		}
		return fp+vals+dep+def <= 1
	}
	return true
}

// attrBinds is the first-party import paths the module binds its attribute name to: by an
// import at module level, or in a def that declares the name global.
func (f *fileParse) attrBinds(name string) []string {
	if len(f.globalBinds[name]) == 0 {
		return f.fpBinds[""][name]
	}
	return append(slices.Clone(f.fpBinds[""][name]), f.globalBinds[name]...)
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

	prog := &program{funcsByName: map[string][]funcDecl{}, leafMemo: map[string][]string{}, modVals: map[modKey][]string{}, modDeps: map[modKey][]modKey{}, reboundMemo: map[string]bool{}, attrMemo: map[attrKey][]string{}}
	var rawBindings [][]scopedBinding
	var relBindings [][]scopedBinding
	var modRefs [][]string
	eps, epsUnread := declaredEntrypoints(buildDir)
	if epsUnread {
		prog.readFailed = true
	}
	for _, p := range paths {
		src, readErr := readPythonSource(p)
		if readErr != nil {
			prog.readFailed = true
			prog.sourceUnread = true
			continue
		}
		module := moduleOf(buildDir, p)
		clean, lits := stripPythonLiterals(src)
		clean, lits, unread := spliceFStrings(clean, lits)
		lines := logicalLines(clean)

		decls := parseDecls(lines)
		scan := parseCallsAndIngresses(lines)
		for _, text := range unread {
			scan.refs.scanRunes([]rune(text), false, true)
			// The literal's text after an unclosed substitution goes unread, whatever it holds.
			scan.refs.hidden = true
			scan.refs.hiddenImport = scan.refs.hiddenImport || namesDynamicImport([]rune(text))
		}
		roots, opaque := dynamicImports(clean, lits)
		lookupRoots, lookups, lookupPackages, moduleVals, lookupOpaque, lookupComputed, own := moduleLookups(clean, lits, scan.bindings)
		loaderRoots, loaderOpaque := stringLoaderImports(clean, lits, scan.bindings, moduleVals)
		roots = sortedDedup(append(append(roots, lookupRoots...), loaderRoots...))
		opaque = opaque || lookupOpaque || loaderOpaque || scan.refs.hiddenImport

		var fds []funcDecl
		topNames := map[string]bool{}
		classes := map[string][]string{}
		topFuncs, classNames := map[string]bool{}, map[string]bool{}
		for _, d := range decls {
			if len(d.enclosing) == 0 {
				topNames[d.name] = true
			}
			if d.kind == kindClass && !d.inDef {
				classes[strings.Join(append(slices.Clone(d.enclosing), d.name), ".")] = d.bases
			}
			if d.kind != kindFunc {
				if len(d.enclosing) == 0 {
					classNames[d.name] = true
				}
				continue
			}
			if len(d.enclosing) == 0 && !d.inDef {
				topFuncs[d.name] = true
			}
			fd := funcDecl{module: module, enclosing: d.enclosing, name: d.name, arity: d.arity, params: d.params, inDef: d.inDef}
			prog.funcsByName[d.name] = append(prog.funcsByName[d.name], fd)
			fds = append(fds, fd)
		}
		for name := range classNames {
			delete(topFuncs, name)
		}
		for name := range scan.locals[""] {
			topNames[name] = true
		}
		for _, b := range append(scan.bindings, scan.relBindings...) {
			if b.scope == "" || b.global {
				topNames[b.local] = true
			}
		}
		for i := range scan.decorated {
			scan.decorated[i].module = module
		}
		spans, stars := importStatements([]rune(clean))
		var imports, packages []string
		importsUnread := false
		for _, sp := range spans {
			mods, pkgs, ok := importedModules(string([]rune(clean)[sp[0]:sp[1]]))
			imports = append(imports, mods...)
			packages = append(packages, pkgs...)
			importsUnread = importsUnread || !ok
		}
		if len(stars) > 0 {
			// A star import may bind any decorator's name.
			scan.wrapped = slices.Clone(scan.decorated)
		}
		for i := range scan.wrapped {
			scan.wrapped[i].module = module
		}
		bindings := indexBindings(scan.bindings)
		if filepath.Base(p) == "setup.py" && !inTestDir(module) {
			ts, supported := setupPyLaunchers(clean, lits)
			prog.launchers = append(prog.launchers, ts...)
			prog.launchersUnsupported = prog.launchersUnsupported || !supported
		}
		prog.files = append(prog.files, fileParse{
			module:        module,
			isPackage:     strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)) == "__init__",
			calls:         scan.calls,
			ingresses:     scan.ingresses,
			bindings:      bindings,
			loadRoots:     roots,
			decls:         fds,
			topNames:      topNames,
			topFuncs:      topFuncs,
			decorated:     scan.decorated,
			wrapped:       scan.wrapped,
			stars:         slices.Sorted(maps.Keys(stars)),
			refs:          scan.refs,
			locals:        scan.locals,
			plain:         scan.plain,
			binders:       scan.binders,
			reads:         scan.reads,
			opaque:        scan.opaque,
			unreadValue:   scan.unreadValue,
			defs:          scan.defs,
			computed:      scan.refs.computed || opaque || lookupComputed || slices.Contains(lookups, strings.ReplaceAll(module, "/", ".")),
			own:           own,
			settings:      append(settingsLaunchers(clean, lits), settingTargets(clean, lits)...),
			urlViews:      djangoURLViews(clean, lits, bindings),
			classes:       classes,
			importOpaque:  opaque,
			imports:       imports,
			packages:      append(packages, lookupPackages...),
			importsUnread: importsUnread,
		})
		rawBindings = append(rawBindings, scan.bindings)
		relBindings = append(relBindings, scan.relBindings)
		modRefs = append(modRefs, append(slices.Clone(roots), lookups...))
	}

	modules := make([]string, 0, len(prog.files))
	for _, f := range prog.files {
		modules = append(modules, f.module)
	}
	declared, declaredComplete, read := declaredDistributions(buildDir)
	if !read {
		prog.readFailed = true
	}
	manifestLaunchers, launchersRead, launchersModeled := readManifestLaunchers(buildDir)
	prog.launchers = append(prog.launchers, manifestLaunchers...)
	prog.launchersUnread = !launchersRead
	prog.launchersUnsupported = prog.launchersUnsupported || !launchersModeled
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
	prog.resolveEntrypoints(eps)
	return prog, nil
}

// indexModules builds byModule and named over the parsed files' module paths.
func (prog *program) indexModules() {
	prog.byModule = map[string][]int{}
	prog.named = map[string]bool{}
	prog.nsDirs = map[string]bool{}
	modules := map[string]bool{}
	for _, f := range prog.files {
		modules[f.module] = true
	}
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
		for b := 1; b < len(segs); b++ {
			if dir := strings.Join(segs[:b], "/"); !modules[dir] {
				for a := 0; a < b; a++ {
					prog.nsDirs[strings.Join(segs[a:b], "/")] = true
				}
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
	imported := func(path string) {
		segs := strings.Split(path, "/")
		for k := 1; k <= len(segs); k++ {
			f.importPaths = append(f.importPaths, strings.Join(segs[:k], "/"))
		}
	}
	for _, name := range slices.Concat(f.imports, modRefs) {
		if !strings.HasPrefix(name, ".") {
			imported(strings.ReplaceAll(name, ".", "/"))
		} else if path, ok := relativeModule(f.module, f.isPackage, name); ok {
			imported(path)
		}
	}
	for _, name := range f.packages {
		if !strings.HasPrefix(name, ".") {
			f.packagePaths = append(f.packagePaths, strings.ReplaceAll(name, ".", "/"))
		} else if path, ok := relativeModule(f.module, f.isPackage, name); ok {
			f.packagePaths = append(f.packagePaths, path)
		}
	}
	f.fpBinds = map[string]map[string][]string{}
	f.globalBinds = map[string][]string{}
	f.chainBinds = map[string]bool{}
	bind := func(b scopedBinding, path string) {
		m := f.fpBinds[b.scope]
		if m == nil {
			m = map[string][]string{}
			f.fpBinds[b.scope] = m
		}
		if !slices.Contains(m[b.local], path) {
			m[b.local] = append(m[b.local], path)
		}
		if b.chain {
			f.chainBinds[b.local+"\x00"+path] = true
		}
		if b.global && !slices.Contains(f.globalBinds[b.local], path) {
			f.globalBinds[b.local] = append(f.globalBinds[b.local], path)
		}
		// A class attribute leaves through the class, its subclasses and instances, as a
		// module assigned to one does ("class R: mod = a"): the module is a value.
		if b.classBody {
			f.modValues = append(f.modValues, path)
		}
	}
	f.depBinds = map[string]map[string]bool{}
	for _, b := range raw {
		if b.target == "" || !prog.dists.firstParty[firstSegment(b.target)] {
			if f.depBinds[b.scope] == nil {
				f.depBinds[b.scope] = map[string]bool{}
			}
			f.depBinds[b.scope][b.local] = true
			if b.target != "" {
				if f.depImports == nil {
					f.depImports = map[string]map[string]int{}
				}
				if f.depImports[b.scope] == nil {
					f.depImports[b.scope] = map[string]int{}
				}
				f.depImports[b.scope][b.local]++
				if prog.named[strings.ReplaceAll(b.target, ".", "/")] && !prog.dists.knownTop(b.target) {
					addNames(&f.depNamed, b.scope, []string{b.local})
				}
			}
			if !b.guarded {
				addNames(&f.plain, b.scope, []string{b.local})
			}
			continue
		}
		bind(b, strings.ReplaceAll(b.target, ".", "/"))
	}
	for _, b := range rel {
		if path, ok := relativeModule(f.module, f.isPackage, b.target); ok {
			bind(b, path)
		}
	}
	for _, name := range f.stars {
		switch {
		case strings.HasPrefix(name, "."):
			if path, ok := relativeModule(f.module, f.isPackage, name); ok {
				f.starPaths = append(f.starPaths, path)
			}
		case prog.dists.firstParty[firstSegment(name)]:
			f.starPaths = append(f.starPaths, strings.ReplaceAll(name, ".", "/"))
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
// and a call site is connected to its callee ONLY when its candidates hold EXACTLY ONE
// declared function that accepts the call's arguments. A name the deciding scope binds by
// first-party import names the functions that import path reaches, through its module's
// re-exports and star imports (`pkg.f(1)` after `import pkg` is pkg's f, never another
// module's); a bare name it binds by def names that scope's def; otherwise the candidates
// are every function of the name in the program. When a callee is ambiguous (a name declared by multiple
// functions the lexer cannot scope-resolve) or unknown (a library/imported/builtin function
// with no source declaration), NO edge is fabricated and the partiality carries
// dynamic_dispatch — the inv.5 honesty boundary.
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
// the binding in scope. A parameter or local that is the deciding scope's only binding of
// the name, a lambda parameter or comprehension variable in the same statement, or an
// instance receiver keeps the edges the name alone gives. A name the deciding scope binds
// only by dependency import names no first-party function: `json.loads(x)` has its boundary
// edge and none to a first-party loads.
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
	prog.markModuleStores()
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
	// A call to a def under a decorator that may replace it runs the decorator's result,
	// which no edge names.
	wrapped := map[string]bool{}
	for _, f := range prog.files {
		for _, fd := range f.wrapped {
			wrapped[fd.scip()] = true
		}
	}
	// calls holds, per caller file, the files declaring a function one of its edges ends at.
	declFile := map[string]int{}
	for fi, f := range prog.files {
		for _, fd := range f.decls {
			declFile[fd.scip()] = fi
		}
	}
	calls := make([][]int, len(prog.files))

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
			callee, ok, escapeLeaves := prog.siteCallee(f, cs)
			if !prog.testCode(f.module) && len(escapeLeaves) > 0 {
				if k := strings.Join(escapeLeaves, ",") + "|" + callee; !landed[k] {
					landed[k] = true
					for _, fd := range prog.declsNamed(escapeLeaves) {
						if s := fd.scip(); s != callee && !prog.testCode(fd.module) {
							escapedSet[s] = true
						}
					}
				}
			}
			// 0 matches (library/import/builtin/unknown) or >1 (unresolvable name): no sound
			// single edge, so never fabricate one (inv.5). A site whose edge is not provably
			// all it reaches is listed too. Listed with no Targets, it may reach any escaped
			// frame.
			if !ok || wrapped[callee] || !f.siteComplete(cs, len(provides) > 0) || prog.storedThrough(f, cs) || prog.siteRebound(f, cs) {
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
			}
			if ok {
				addEdge(caller, callee)
				calls[fi] = append(calls[fi], declFile[callee])
			}
		}
	}

	// Framework ingress handler functions are call-graph roots (static-reachability entry
	// points), so a reverse BFS can terminate at them even when no caller in the source
	// invokes them. A handler in test code production never runs (productionReached) is
	// registered by no production app, so it is no entry point.
	reached := prog.productionReached(calls)
	for fi, f := range prog.files {
		if !reached[fi] {
			continue
		}
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
		Partiality: callGraphPartiality(prog, reached),
		Algorithm:  "source-lexical",
		Edges:      edges,
		Roots:      sortedSymbols(rootsSet),
		Escaped:    sortedSymbols(escapedSet),
		Unresolved: unresolved,
	}
}

// escapeFrames adds to out the frames code the lane does not see may call (escape.go):
// every runtime module's top-level frame, every escaping function outside test code, and
// every callable a declared entrypoint names.
// The call sites' own contribution (a declaration a site names without an edge to it) is
// added by callGraphOf.
func (prog *program) escapeFrames(out map[string]bool) {
	escape := func(fd funcDecl) {
		if !prog.testCode(fd.module) {
			out[fd.scip()] = true
		}
	}
	modDone, chainDone := map[string]bool{}, map[string]bool{}
	// escapeModule escapes every function of the modules an import path names: the module
	// is a value, so any of its functions can be reached by attribute name, and so can what
	// its first-party imports and star imports bind as its attributes, and everything of a
	// module so bound. A star import binds the same names, so it escapes the same set.
	var escapeModule func(path string)
	escapeModule = func(path string) {
		if modDone[path] {
			return
		}
		modDone[path] = true
		for i := range prog.files {
			g := &prog.files[i]
			if !moduleNamedBy(g.module, path) {
				continue
			}
			for _, fd := range g.decls {
				escape(fd)
			}
			for _, binds := range []map[string][]string{g.fpBinds[""], g.globalBinds} {
				for attr, paths := range binds {
					for _, fd := range prog.declsNamed(prog.withAliases([]string{attr}, paths)) {
						escape(fd)
					}
					for _, p := range paths {
						if prog.named[p] {
							escapeModule(p)
						}
					}
				}
			}
			for _, p := range g.starPaths {
				escapeModule(p)
			}
		}
	}
	for fi := range prog.files {
		f := &prog.files[fi]
		if prog.testCode(f.module) {
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
		for _, path := range f.starPaths {
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
				prog.escapeChain(base, segs[1:], chainDone, escape, escapeModule)
			}
		}
	}
	for _, t := range prog.launchTargets() {
		decls, module, whole, missing := prog.launchDecls(t)
		for _, fd := range decls {
			escape(fd)
		}
		if module != "" && (whole || missing) && !t.loadOnly {
			escapeModule(module)
		}
	}
}

// escapeChain handles a dotted value whose head an import binds to the path base. It finds
// the longest prefix of the chain that names a module. With no attribute after it, the
// module itself is the value. An attribute the module declares is a function or class
// handed over by name; the name scan sees only the chain's last segment, so one read
// further ("m.vuln.__call__") escapes it here. One the module binds by first-party import
// is followed through the import, and the rest of the chain with it ("a.g.h" where a binds
// g to a module); anything else ("handlers.__dict__", an attribute the scanner cannot see)
// may reach any function of the module. A base that names no module names a function
// ("x.__call__" where x is an imported function), and reading any attribute of it hands it
// over. done holds the chains already followed, so an import cycle ends.
func (prog *program) escapeChain(base string, rest []string, done map[string]bool, escape func(funcDecl), escapeModule func(string)) {
	key := base + "\x00" + strings.Join(rest, "/")
	if done[key] {
		return
	}
	done[key] = true
	for k := len(rest); k >= 0; k-- {
		path := strings.Join(append([]string{base}, rest[:k]...), "/")
		if base == "" {
			path = strings.Join(rest[:k], "/")
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
			if paths := g.attrBinds(attr); len(paths) > 0 {
				bound = true
				for _, fd := range prog.declsNamed(prog.withAliases([]string{attr}, paths)) {
					escape(fd)
				}
				for _, p := range paths {
					leaf := p[strings.LastIndexByte(p, '/')+1:]
					prog.escapeChain(parentModule(p), append([]string{leaf}, rest[k+1:]...), done, escape, escapeModule)
				}
			}
		}
		if !declared && !bound {
			escapeModule(path)
		}
		if declared && k+1 < len(rest) {
			for _, fd := range prog.declsNamed([]string{attr}) {
				escape(fd)
			}
		}
		return
	}
	if base != "" {
		leaf := base[strings.LastIndexByte(base, '/')+1:]
		for _, fd := range prog.declsNamed(prog.withAliases([]string{leaf}, []string{base})) {
			escape(fd)
		}
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
//
// A dynamic import, evaluated code or an f-string call counts only in a file production
// code may run (reached, from productionReached); an unread file or a skipped construct
// counts wherever it is.
func callGraphPartiality(prog *program, reached []bool) plugin.Partiality {
	reasons := []string{plugin.PartialReasonDynamicDispatch}
	opaque := false
	for i, f := range prog.files {
		opaque = opaque || reached[i] && f.importOpaque
	}
	reasons = append(reasons, dynamicImportReasons(opaque)...)
	if prog.readFailed || prog.importUnattributed {
		reasons = append(reasons, plugin.PartialReasonToolFailure)
	}
	if prog.skipped {
		reasons = append(reasons, plugin.PartialReasonUnsupported)
	}
	if prog.sitesUnlisted(reached) {
		reasons = append(reasons, plugin.PartialReasonUnlistedSites)
	}
	return plugin.Partial(reasons...)
}

// sitesUnlisted reports whether some declined call site in a reached file is missing from
// Unresolved.
func (prog *program) sitesUnlisted(reached []bool) bool {
	if prog.sourceUnread || prog.skipped {
		return true
	}
	for i, f := range prog.files {
		if reached[i] && (f.refs.evaluated || f.refs.hidden) {
			return true
		}
	}
	return false
}

// productionReached reports, per file, whether production code may run it: every file
// outside test code (testCode), every file a manifest launcher names (production by
// construction: the file declaring the function it names, or the module's own file when it
// names the module whole or a function the lane does not find), the same for each launch
// target a reached file names (its settings and URL views; an unreached test urlconf seeds
// nothing), and every file a reached file imports (importPaths, matched like any import
// path through byModule) or has an edge into (calls, per caller file). A star import or an
// __import__ fromlist may load any submodule of its package (packagePaths), so it reaches
// every file under that package, and a file with an import statement importedModules could
// not read reaches every file. Test code runs in production only that way: no escape names
// a test function, so a test module only test modules import or call stays unreached, and
// its dynamic imports and evaluated code withhold nothing.
func (prog *program) productionReached(calls [][]int) []bool {
	reached := make([]bool, len(prog.files))
	var work []int
	reach := func(i int) {
		if !reached[i] {
			reached[i] = true
			work = append(work, i)
		}
	}
	for i, f := range prog.files {
		if !prog.testCode(f.module) {
			reach(i)
		}
	}
	declFile := map[string]int{}
	for fi, f := range prog.files {
		for _, fd := range f.decls {
			declFile[fd.scip()] = fi
		}
	}
	launch := func(t launchTarget) {
		decls, module, whole, missing := prog.launchDecls(t)
		for _, fd := range decls {
			if fi, ok := declFile[fd.scip()]; ok {
				reach(fi)
			}
		}
		if module != "" && (whole || missing) {
			for _, j := range prog.byModule[module] {
				if !t.exact || prog.files[j].module == module {
					reach(j)
				}
			}
		}
	}
	for _, t := range prog.launchers {
		launch(t)
	}
	for len(work) > 0 {
		i := work[len(work)-1]
		work = work[:len(work)-1]
		f := prog.files[i]
		for _, t := range prog.fileLaunchTargets(&f) {
			launch(t)
		}
		for _, path := range f.importPaths {
			for _, j := range prog.byModule[path] {
				reach(j)
			}
		}
		if f.importsUnread || len(f.packagePaths) > 0 {
			for j, g := range prog.files {
				if f.importsUnread || slices.ContainsFunc(f.packagePaths, func(p string) bool {
					return strings.Contains("/"+g.module+"/", "/"+p+"/")
				}) {
					reach(j)
				}
			}
		}
		for _, j := range calls[i] {
			reach(j)
		}
	}
	return reached
}

// resolvedCallFiles lists, per caller file, the files declaring the function each call site
// with an edge resolves to (siteCallee): the calls argument productionReached takes, for a
// caller that does not build the graph. callGraphOf collects the same lists as it adds the
// edges.
func (prog *program) resolvedCallFiles() [][]int {
	declFile := map[string]int{}
	for fi, f := range prog.files {
		for _, fd := range f.decls {
			declFile[fd.scip()] = fi
		}
	}
	calls := make([][]int, len(prog.files))
	for fi := range prog.files {
		f := &prog.files[fi]
		for _, cs := range f.calls {
			if callee, ok, _ := prog.siteCallee(f, cs); ok {
				calls[fi] = append(calls[fi], declFile[callee])
			}
		}
	}
	return calls
}

// isTestModule reports whether a module path names test code: a test_*.py, *_test.py or
// conftest.py file, or any module under a tests/ or test/ directory.
func isTestModule(module string) bool {
	leaf := module[strings.LastIndexByte(module, '/')+1:]
	return inTestDir(module) || strings.HasPrefix(leaf, "test_") || strings.HasSuffix(leaf, "_test") || leaf == "conftest"
}

// inTestDir reports whether a slash path names, or lies under, a tests/ or test/
// directory.
func inTestDir(p string) bool {
	return slices.ContainsFunc(strings.Split(p, "/"), func(s string) bool { return s == "tests" || s == "test" })
}
