package pythonanalysis

import (
	"slices"
	"strings"
)

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
		if f.own.any {
			exposed = append(exposed, fi)
		}
		for _, name := range f.own.names {
			if f.storedNames == nil {
				f.storedNames = map[string]bool{}
			}
			f.storedNames[name] = true
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
		for _, p := range prog.attrTargets(i, "") {
			for _, q := range prog.modulesAt(p, nil) {
				exposed = append(exposed, prog.byModule[q]...)
			}
		}
	}
}

// attrTargets is the first-party paths a parsed module's import bindings give its attribute
// name, or every attribute when name is empty: its module-scope imports, a def's import of a
// name it declares global, and the same in each first-party module it star-imports, which
// may rebind the name.
func (prog *program) attrTargets(i int, name string) []string {
	k := attrKey{i, name}
	if out, ok := prog.attrMemo[k]; ok {
		return out
	}
	out := prog.attrTargetsSeen(i, name, map[int]bool{})
	prog.attrMemo[k] = out
	return out
}

type attrKey struct {
	file int
	name string
}

func (prog *program) attrTargetsSeen(i int, name string, seen map[int]bool) []string {
	if seen[i] {
		return nil
	}
	seen[i] = true
	f := &prog.files[i]
	var out []string
	if name != "" {
		out = append(slices.Clone(f.fpBinds[""][name]), f.globalBinds[name]...)
	} else {
		for _, binds := range []map[string][]string{f.fpBinds[""], f.globalBinds} {
			for _, paths := range binds {
				out = append(out, paths...)
			}
		}
	}
	for _, star := range f.starPaths {
		for _, j := range prog.byModule[star] {
			out = append(out, prog.attrTargetsSeen(j, name, seen)...)
		}
	}
	return out
}

// modulesAt is the parsed modules a dotted chain names whole, given the path base an import
// binds its head to: the longest prefix of the chain that names a module, followed on
// through an attribute the module binds by a first-party import (attrTargets). A base that
// names no module ("from pkg import mod" where pkg binds mod by import) is read as an
// attribute chain from its first segment.
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
			for _, p := range prog.attrTargets(i, rest[k]) {
				out = append(out, prog.modulesAtSeen(p, rest[k+1:], seen)...)
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

// ownStores is what a file may bind in its own namespace by computed access: through its
// module object (sys.modules[__name__], import_module(__name__)) or the dict globals()
// returns, and vars() or locals() at module scope. names holds the names a store by a
// literal key binds; any reports a use that may bind any name.
type ownStores struct {
	names []string
	any   bool
}

// ownModuleEnd returns the index just past a subscript or .get of __name__ on sys.modules,
// whose name ends at r[end], or -1 when none follows.
func ownModuleEnd(r []rune, end int) int {
	p := skipAllSpace(r, end)
	switch {
	case p < len(r) && r[p] == '[' && ownModuleArg(r, p+1, "]"):
		return matchingClose(r, p) + 1
	case p < len(r) && r[p] == '.':
		g, e := readWordRunes(r, skipAllSpace(r, p+1))
		if q := skipAllSpace(r, e); g == "get" && q < len(r) && r[q] == '(' && ownModuleArg(r, q+1, "),") {
			return callClose(r, q)
		}
	}
	return -1
}

// readOnlyWrappers are the builtins that only read the namespace passed as their one argument.
var readOnlyWrappers = map[string]bool{
	"len": true, "list": true, "set": true, "frozenset": true, "sorted": true, "tuple": true,
	"iter": true, "dict": true, "repr": true, "str": true, "id": true, "type": true,
}

// readOnlyMethods are the dict methods that bind no name.
var readOnlyMethods = map[string]bool{
	"get": true, "keys": true, "items": true, "values": true, "copy": true, "pop": true,
	"popitem": true, "clear": true, "__contains__": true,
}

// use records one use of the file's namespace, the expression running from r[start] to
// r[end]: its module object when module is set, else its dict. It reads an allow-list: a
// literal-named attribute store on the module or a setattr of it by literal name, a
// literal-key store into the dict, a .update of keyword arguments or a .setdefault by literal
// key, bind those names; an attribute or subscript read, a getattr, hasattr or delattr, a
// del, a membership test, a ** unpacking, readOnlyWrappers and readOnlyMethods bind none.
// Any other use may bind any name: a store by a key the scanner cannot read, a dunder of the
// module, the module replaced in sys.modules, or the namespace handed on as a value.
func (s *ownStores) use(r []rune, start, end int, lits map[int]strLiteral, module bool) {
	n := len(r)
	p := skipAllSpace(r, end)
	j := skipSpaceBack(r, start-1)
	switch {
	case j >= 1 && r[j] == '*' && r[j-1] == '*', precededByWord(r, start, "in"):
		return
	case j >= 0 && r[j] == '(' && p < n && (r[p] == ',' || r[p] == ')'):
		k := skipSpaceBack(r, j-1)
		e := k + 1
		for k >= 0 && isIdentPart(r[k]) {
			k--
		}
		switch fn := string(r[k+1 : e]); {
		case module && fn == "setattr" && r[p] == ',':
			if name, ok := literalSubscript(r, p+1, lits, ","); ok {
				s.names = append(s.names, name)
				return
			}
		case module && r[p] == ',' && (fn == "getattr" || fn == "hasattr" || fn == "delattr"),
			r[p] == ')' && readOnlyWrappers[fn]:
			return
		}
	case module && p < n && r[p] == '.':
		attr, aend := readWordRunes(r, skipAllSpace(r, p+1))
		switch {
		case attr == "" || strings.HasPrefix(attr, "__"):
		case rebound(r, aend):
			s.names = append(s.names, attr)
			return
		default:
			return
		}
	case module && rebound(r, end):
	case module:
		if precededByWord(r, start, "del") {
			return
		}
	case p < n && r[p] == '[':
		c := matchingClose(r, p)
		if c < 0 {
			break
		}
		if !rebound(r, c+1) {
			return
		}
		if name, ok := literalSubscript(r, p+1, lits, "]"); ok {
			s.names = append(s.names, name)
			return
		}
	case p < n && r[p] == '.':
		m, mend := readWordRunes(r, skipAllSpace(r, p+1))
		q := skipAllSpace(r, mend)
		if q >= n || r[q] != '(' {
			break
		}
		switch {
		case readOnlyMethods[m]:
			return
		case m == "setdefault":
			if name, ok := literalSubscript(r, q+1, lits, ",)"); ok {
				s.names = append(s.names, name)
				return
			}
		case m == "update":
			args, ok := callArgs(r, q)
			var names []string
			for _, a := range args {
				w, e := readWordRunes(r, skipAllSpace(r, a[0]))
				if w == "" || !assignedTo(r, e) {
					ok = false
					break
				}
				names = append(names, w)
			}
			if ok {
				s.names = append(s.names, names...)
				return
			}
		}
	}
	s.any = true
}

// rebound reports whether the target ending at r[end] is assigned or augmented.
func rebound(r []rune, end int) bool {
	if assignedTo(r, end) {
		return true
	}
	k := skipAllSpace(r, end)
	op := string(r[k:min(k+4, len(r))])
	for _, o := range []string{"+=", "-=", "*=", "/=", "//=", "%=", "@=", "&=", "|=", "^=", ">>=", "<<=", "**="} {
		if strings.HasPrefix(op, o) {
			return true
		}
	}
	return false
}

// moduleScope reports, for each rune index of a cleaned source, whether the code there runs
// in the module's own frame rather than a def or class body. A def or class header line, and
// a line its brackets or a backslash continue, belong to the enclosing scope.
func moduleScope(clean string) func(i int) bool {
	r := []rune(clean)
	var bodies [][2]int
	var stack []int
	depth, from, start := 0, -1, 0
	for i := 0; i <= len(r); i++ {
		if i < len(r) && r[i] != '\n' {
			switch r[i] {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
			}
			continue
		}
		line := r[start:i]
		logical := depth <= 0 && (start == 0 || !continuedBreak(r, start-1))
		if t := strings.TrimLeft(string(line), " \t"); logical && t != "" {
			indent := len(line) - len([]rune(t))
			for len(stack) > 0 && indent <= stack[len(stack)-1] {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 && from >= 0 {
				bodies = append(bodies, [2]int{from, start})
				from = -1
			}
			w, rest := firstWord(t)
			if w == "async" {
				w, _ = firstWord(strings.TrimSpace(rest))
			}
			if w == "def" || w == "class" {
				if len(stack) == 0 {
					from = i
				}
				stack = append(stack, indent)
			}
		}
		start = i + 1
	}
	if from >= 0 {
		bodies = append(bodies, [2]int{from, len(r)})
	}
	return func(i int) bool {
		for _, b := range bodies {
			if i >= b[0] && i < b[1] {
				return false
			}
		}
		return true
	}
}
