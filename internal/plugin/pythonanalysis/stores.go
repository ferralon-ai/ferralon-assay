package pythonanalysis

import "strings"

// markModuleStores records, on each parsed module, the names a store through a module object
// may rebind in its namespace: an assignment to an attribute of the module ("import pkg.a;
// pkg.a.g = h", "import pkg.a as me; me.g = h") binds that name, and a module handed over
// whole (passed or stored as a value, named by a literal dynamic import or sys.modules
// lookup, or its __dict__ or __setattr__ reached) may have any name rebound, and so may every
// module reachable from it as an attribute: its submodules and the modules it binds by a
// first-party import, transitively. Stores in test code are left out, as escape leaves test
// code out.
func (prog *program) markModuleStores() {
	var exposed []int
	prog.dirStores = map[string]map[string]bool{}
	mark := func(path, name string) {
		if prog.nsDirs[path] {
			// A package with no __init__ file in some root: a store lands in its namespace,
			// and handing it over whole hands over every module under it. A regular package
			// at the same path in another root (tests/pkg/ns/__init__.py beside src/pkg/ns/)
			// is marked below as well.
			if name != "" {
				// Keyed under every trailing segment run, as byModule is, so a store written
				// through one root (src/pkg/ns) meets a site read through another (pkg/ns).
				segs := strings.Split(path, "/")
				for a := range segs {
					run := strings.Join(segs[a:], "/")
					if prog.dirStores[run] == nil {
						prog.dirStores[run] = map[string]bool{}
					}
					prog.dirStores[run][name] = true
				}
			} else {
				for j := range prog.files {
					if strings.Contains("/"+prog.files[j].module+"/", "/"+path+"/") {
						exposed = append(exposed, j)
					}
				}
			}
		}
		for _, i := range prog.byModule[path] {
			g := &prog.files[i]
			if name == "" {
				exposed = append(exposed, i)
				continue
			}
			if g.storedNames == nil {
				g.storedNames = map[string]bool{}
			}
			g.storedNames[name] = true
		}
	}
	for fi := range prog.files {
		f := &prog.files[fi]
		if isTestModule(f.module) {
			continue
		}
		for _, path := range f.modValues {
			mark(path, "")
		}
		for _, runs := range []map[string]bool{f.refs.chains, f.refs.exposed} {
			for chain := range runs {
				segs := strings.Split(chain, ".")
				for _, base := range f.anyScopeBinds(segs[0]) {
					for _, path := range prog.modulesAt(base, segs[1:]) {
						mark(path, "")
					}
				}
			}
		}
		for chain := range f.refs.stores {
			segs := strings.Split(chain, ".")
			for _, base := range f.anyScopeBinds(segs[0]) {
				for _, path := range prog.modulesAt(base, segs[1:len(segs)-1]) {
					mark(path, segs[len(segs)-1])
				}
			}
		}
	}
	for len(exposed) > 0 {
		i := exposed[len(exposed)-1]
		exposed = exposed[:len(exposed)-1]
		g := &prog.files[i]
		if g.storedAny {
			continue
		}
		g.storedAny = true
		for j := range prog.files {
			if strings.HasPrefix(prog.files[j].module, g.module+"/") {
				exposed = append(exposed, j)
			}
		}
		for _, p := range prog.attrTargets(i, nil, map[int]bool{}) {
			for _, q := range prog.modulesAt(p, nil) {
				exposed = append(exposed, prog.byModule[q]...)
			}
		}
	}
}

// attrTargets is the first-party paths a parsed module's import bindings give the module
// attributes along a dotted chain, or along every chain when attr is nil: its module-scope
// imports, a def's import of a name it declares global, an import in a module-level class
// body, and the same in each first-party module it star-imports, which may rebind the name.
func (prog *program) attrTargets(i int, attr []string, seen map[int]bool) []string {
	if seen[i] {
		return nil
	}
	seen[i] = true
	f := &prog.files[i]
	var out []string
	for name, paths := range f.fpBinds[""] {
		if attr == nil || len(attr) == 1 && attr[0] == name {
			out = append(out, paths...)
		}
	}
	for chain, paths := range f.attrBinds {
		if attr == nil || chain == strings.Join(attr, ".") {
			out = append(out, paths...)
		}
	}
	for _, star := range f.starPaths {
		for _, j := range prog.byModule[star] {
			out = append(out, prog.attrTargets(j, attr, seen)...)
		}
	}
	return out
}

// modulesAt is the parsed modules a dotted chain names whole, given the path base an import
// binds its head to: the longest prefix of the chain that names a module, followed on
// through an attribute chain the module binds by a first-party import (attrTargets). A base
// that names no module
// ("from pkg import mod" where pkg binds mod by import) is read as an attribute chain from
// its first segment.
func (prog *program) modulesAt(base string, rest []string) []string {
	return prog.modulesAtSeen(base, rest, map[string]bool{})
}

// modulesAtSeen is modulesAt, skipping a (base, chain) already being resolved: suffix-indexed
// paths let a module re-export from itself (scripts/app/models.py importing app.models), and
// the re-split above lengthens the chain, so without it a cycle never ends.
func (prog *program) modulesAtSeen(base string, rest []string, seen map[string]bool) []string {
	key := base + "|" + strings.Join(rest, "/")
	if seen[key] {
		return nil
	}
	seen[key] = true
	for k := len(rest); k >= 0; k-- {
		path := base
		if k > 0 {
			path += "/" + strings.Join(rest[:k], "/")
		}
		if !prog.named[path] {
			if k == 0 && strings.Contains(base, "/") {
				segs := strings.Split(base, "/")
				return prog.modulesAtSeen(segs[0], append(segs[1:], rest...), seen)
			}
			continue
		}
		if k == len(rest) {
			return []string{path}
		}
		var out []string
		for _, i := range prog.byModule[path] {
			for j := k + 1; j <= len(rest); j++ {
				for _, p := range prog.attrTargets(i, rest[k:j], map[int]bool{}) {
					out = append(out, prog.modulesAtSeen(p, rest[j:], seen)...)
				}
			}
		}
		return out
	}
	return nil
}

// storedThrough reports whether a store through a module object may rebind an attribute a
// qualified site's chain reads from a module ("a.g(1)" after "a.g = h" anywhere), so the
// site's edges may not be all it reaches.
func (prog *program) storedThrough(f *fileParse, cs callSite) bool {
	chain := cs.calleeChain
	for k := 1; k < len(chain); k++ {
		for _, base := range f.anyScopeBinds(chain[0]) {
			for _, path := range prog.modulesAt(base, chain[1:k]) {
				segs := strings.Split(path, "/")
				for a := range segs {
					if prog.dirStores[strings.Join(segs[a:], "/")][chain[k]] {
						return true
					}
				}
				for _, i := range prog.byModule[path] {
					if g := &prog.files[i]; g.storedAny || g.storedNames[chain[k]] {
						return true
					}
				}
			}
		}
	}
	return false
}
