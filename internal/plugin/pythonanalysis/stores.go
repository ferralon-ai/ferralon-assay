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
// literal-named attribute stored on the module or a setattr of it by literal name, a store
// into the dict by literal key, a .update of keyword arguments or a .setdefault by literal key,
// bind those names. An attribute or subscript that is not a target (see target), a getattr
// by a literal name that is not a dunder, a hasattr, delattr or del, a membership test, a **
// unpacking, an argument to __import__, readOnlyWrappers and readOnlyMethods bind none; a
// call counts only for a builtin the file never rebinds (shadowed). Any other use may bind
// any name: a store by a key the scanner cannot read, a dunder of the module, the module
// replaced in sys.modules, or the namespace handed on as a value.
func (s *ownStores) use(r []rune, start, end int, lits map[int]strLiteral, module bool, shadowed func(string, int) bool) {
	n := len(r)
	p := skipAllSpace(r, end)
	j := skipSpaceBack(r, start-1)
	switch {
	case j >= 1 && r[j] == '*' && r[j-1] == '*', precededByWord(r, start, "in"):
		return
	case j >= 0 && (r[j] == '(' || r[j] == ',') && p < n && (r[p] == ',' || r[p] == ')') && importArg(r, start, shadowed):
		return
	case j >= 0 && r[j] == '(' && p < n && (r[p] == ',' || r[p] == ')'):
		fn, k := wordBefore(r, j)
		if fn == "" || k >= 0 && r[k] == '.' || shadowed(fn, j) {
			break
		}
		switch {
		case module && fn == "setattr" && r[p] == ',':
			if name, ok := literalSubscript(r, p+1, lits, ","); ok {
				s.names = append(s.names, name)
				return
			}
		case module && fn == "getattr" && r[p] == ',':
			if name, ok := literalSubscript(r, p+1, lits, ",)"); ok && !strings.HasPrefix(name, "__") {
				return
			}
		case module && r[p] == ',' && (fn == "hasattr" || fn == "delattr"),
			r[p] == ')' && readOnlyWrappers[fn]:
			return
		}
	case module && p < n && r[p] == '.':
		attr, aend := readWordRunes(r, skipAllSpace(r, p+1))
		switch {
		case attr == "" || strings.HasPrefix(attr, "__"):
		case target(r, start, aend):
			s.names = append(s.names, attr)
			return
		default:
			return
		}
	case module && target(r, start, end):
	case module:
		if precededByWord(r, start, "del") {
			return
		}
	case p < n && r[p] == '[':
		c := matchingClose(r, p)
		if c < 0 {
			break
		}
		if !target(r, start, c+1) {
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

// importArg reports whether the argument starting at r[start] is passed to a bare
// __import__ call the file never rebinds, which reads the globals and locals it is handed
// only for the importing package's name.
func importArg(r []rune, start int, shadowed func(string, int) bool) bool {
	open := enclosingOpen(r, start)
	if open < 0 || r[open] != '(' {
		return false
	}
	w, k := wordBefore(r, open)
	return w == "__import__" && (k < 0 || r[k] != '.') && !shadowed(w, start)
}

// target reports whether the expression from r[start] to r[end] is bound rather than read:
// assigned or augmented, alone or inside a tuple, list, parenthesised or annotated target
// (a statement-level '=' or augmented operator after it), the target of a for, in a
// statement or a comprehension (the nearest for or in before it is a for), or of a with's
// as. A trailer after it (an attribute, subscript or call) reads it.
func target(r []rune, start, end int) bool {
	if p := skipAllSpace(r, end); p < len(r) && strings.ContainsRune(".[(", r[p]) {
		return false
	}
	s := start
	for s > 0 && r[s-1] != ';' {
		s--
	}
	depth, kw, with, colon := 0, "", false, false
	for i := s; i < len(r) && r[i] != ';'; i++ {
		switch c := r[i]; {
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case i >= end && depth == 0 && c == '=' && (i+1 >= len(r) || r[i+1] != '=') &&
			(i == 0 || !strings.ContainsRune("=!<>:", r[i-1]) || i >= 2 && r[i-1] == r[i-2] && (r[i-1] == '<' || r[i-1] == '>')):
			return true
		case i < start && isIdentStartRune(c) && (i == 0 || !isIdentPart(r[i-1])):
			w, e := readWordRunes(r, i)
			switch {
			case w == "for" || w == "in":
				kw = w
			case w == "with" && strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(r[s:i])), "async")) == "":
				with = true
			case w == "as" && with:
				kw, colon = "as", false
			}
			i = e - 1
		case i < start && c == ':' && depth == 0:
			colon = true
		}
	}
	return kw == "for" || kw == "as" && !colon
}

// classScope returns, for each rune index of a cleaned source, the class body the code there
// sits directly in, as an id, or -1 when its innermost scope is a def body or the module. A
// def or class header belongs to the enclosing scope. Lines are read as moduleScope reads them.
func classScope(clean string) func(i int) int {
	r := []rune(clean)
	type block struct {
		indent, id int
		class      bool
	}
	var spans [][3]int
	var stack []block
	depth, start := 0, 0
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
		if i < len(r) && (depth > 0 || continuedBreak(r, i)) {
			continue
		}
		line := r[start:i]
		if nl := slices.Index(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		if t := strings.TrimLeft(string(line), " \t"); t != "" {
			indent := len(line) - len([]rune(t))
			for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
				stack = stack[:len(stack)-1]
			}
			if len(stack) > 0 && stack[len(stack)-1].class {
				spans = append(spans, [3]int{start, i, stack[len(stack)-1].id})
			}
			w, rest := firstWord(t)
			if w == "async" {
				w, _ = firstWord(strings.TrimSpace(rest))
			}
			if w == "def" || w == "class" {
				stack = append(stack, block{indent, i, w == "class"})
			}
		}
		start = i + 1
	}
	return func(i int) int {
		for _, s := range spans {
			if i >= s[0] && i < s[1] {
				return s[2]
			}
		}
		return -1
	}
}

// moduleScope reports, for each rune index of a cleaned source, whether the code there runs
// in the module's own frame rather than a def or class body. Lines are read logically, a line
// its brackets or a backslash continue joined to the one it continues, and a def or class
// header belongs to the enclosing scope.
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
		if i < len(r) && (depth > 0 || continuedBreak(r, i)) {
			continue
		}
		line := r[start:i]
		if nl := slices.Index(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		if t := strings.TrimLeft(string(line), " \t"); t != "" {
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
