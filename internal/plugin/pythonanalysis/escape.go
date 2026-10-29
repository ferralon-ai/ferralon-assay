package pythonanalysis

import (
	"strings"
	"unicode"
)

// Escape roots.
//
// Code this lane does not see call into can call back into first-party code: a function
// passed to a dependency or a builtin, stored in a registry, reached through getattr, or
// invoked by the interpreter itself (a constructor, a context manager's __enter__). Such an
// edge is hidden, and a sink behind it would look unreached. The lane closes that gap by
// making every function a hidden edge could land on a call-graph root, so it is searched
// whether or not any visible edge reaches it.
//
// The rule over-approximates escape rather than tracking it. A declared function outside
// test code escapes when:
//   - it is a class member: an instance can escape through any value, and the interpreter
//     calls dunders (__init__, __enter__, __call__, operators) with no call site at all;
//   - its name is a dunder (a module-level __getattr__ or __dir__ the interpreter calls);
//   - it sits under a decorator other than a recognised route registration, which receives
//     the function as a value;
//   - its name, or a name some file binds to it by import alias (followed through
//     re-exports to the original), appears anywhere other than as the callee of a direct
//     call, its own def, or an import statement: passed, assigned, returned, stored,
//     compared, or used inside an f- or t-string substitution. Escape is name-global and
//     ignores shadowing, so it is always at least as wide as the edges resolveCallee draws;
//   - a call site names it but no single edge was drawn to it: the name matched more than
//     one declaration, or none with the call's arity (a defaulted parameter), so the call
//     may land on it;
//   - its module is used as a value: passed or stored whole, named by a literal
//     importlib.import_module, __import__ or sys.modules lookup, or read for an attribute
//     the module does not define (handlers.__dict__). A dotted chain is matched to the
//     module named by its longest prefix, so any of its functions can be reached by
//     attribute name;
//   - its file reaches names by computed access: getattr, globals(), vars(), locals(),
//     __dict__, eval/exec, __import__, operator.attrgetter/methodcaller, inspect.getmembers,
//     sys.modules, or an import whose module the scanner cannot name. Module lookups are
//     read by an allow-list of literal forms (moduleLookups); any other reference to
//     sys.modules, import_module or __import__, under whatever name the file binds them to,
//     adds dynamic_import, which withholds the verdict, rather than escaping every module.
//
// Every module's top-level frame outside test code escapes too, since any import may run it.
// A function that matches none of these can only run through a visible direct call.

// valueRefs is what the escape scan records for one file.
type valueRefs struct {
	// names are identifiers used as values; the leaf of an attribute chain counts, since
	// "mod.f" passed as a callback hands f over.
	names map[string]bool
	// chains are dotted runs used whole as values ("handlers", "pkg.handlers"): a module
	// used this way hands every function in it over.
	chains map[string]bool
	// computed records computed-name access anywhere in the file.
	computed bool
	// evaluated records eval/exec: the evaluated code's call sites are never seen.
	evaluated bool
	// hidden records a call inside an f-string substitution, which the call scanner does not
	// list as a site.
	hidden bool
}

func newValueRefs() valueRefs {
	return valueRefs{names: map[string]bool{}, chains: map[string]bool{}}
}

// computedNameCalls reach names by computed access when used unqualified.
var computedNameCalls = map[string]bool{
	"getattr": true, "globals": true, "vars": true, "locals": true,
	"eval": true, "exec": true, "__import__": true,
}

// computedNameAttrs reach names by computed access wherever they appear.
var computedNameAttrs = map[string]bool{
	"__dict__": true, "attrgetter": true, "methodcaller": true, "getmembers": true,
	"f_globals": true, "f_locals": true,
}

// scan records the value uses and computed-name access in one cleaned statement or header.
// params marks a def header's parameter list, whose parameter names are bindings, not uses.
func (vr *valueRefs) scan(text string, params bool) {
	vr.scanRunes([]rune(text), params, false)
}

// scanRunes is scan over runes; allValues counts every name as a value use, call position
// included, for text the call scanner never reads (an f-string substitution).
func (vr *valueRefs) scanRunes(r []rune, params, allValues bool) {
	n := len(r)
	for i := 0; i < n; {
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		start := i
		var segs []string
		pos := i
		for {
			var w string
			w, pos = readWordRunes(r, pos)
			segs = append(segs, w)
			if pos+1 < n && r[pos] == '.' && isIdentStartRune(r[pos+1]) {
				pos++
				continue
			}
			break
		}
		prev := prevSignificantRune(r, start)
		attr := prev >= 0 && r[prev] == '.'
		for k, seg := range segs {
			switch {
			case computedNameAttrs[seg]:
				vr.computed = true
			case k == 0 && !attr && computedNameCalls[seg]:
				vr.computed = true
				if seg == "eval" || seg == "exec" {
					vr.evaluated = true
				}
			}
		}
		p := skipSpaceRunes(r, pos)
		called := p < n && r[p] == '('
		assigned := p < n && r[p] == '=' && !(p+1 < n && r[p+1] == '=')
		param := params && len(segs) == 1 && (prev < 0 || strings.ContainsRune("(,*", r[prev])) &&
			(p >= n || strings.ContainsRune(",)=:", r[p]))
		if allValues || !(called || assigned || param) {
			vr.names[segs[len(segs)-1]] = true
			if !attr {
				vr.chains[strings.Join(segs, ".")] = true
			}
		}
		i = pos
	}
}

// scanFStrings records the names used inside the substitutions of every f-string and
// t-string literal in a file, given its cleaned source and the literals stripPythonLiterals
// blanked. The call scanner reads only cleaned text, so a substitution's calls are not sites:
// every name in one counts as a value use, and a call there marks the file's site list
// incomplete.
func (vr *valueRefs) scanFStrings(clean string, lits map[int]strLiteral) {
	r := []rune(clean)
	for start, lit := range lits {
		if !fStringPrefix(r, start) {
			continue
		}
		body := []rune(lit.body)
		for i := 0; i < len(body); i++ {
			if body[i] != '{' {
				continue
			}
			if i+1 < len(body) && body[i+1] == '{' {
				i++
				continue
			}
			end := matchingClose(body, i)
			if end < 0 {
				end = len(body)
			}
			expr := body[i+1 : end]
			vr.scanRunes(expr, false, true)
			if strings.ContainsRune(string(expr), '(') {
				vr.hidden = true
			}
			i = end
		}
	}
}

// fStringPrefix reports whether the literal opening at r[start] carries an f prefix or a
// t prefix (PEP 750 template strings, whose substitutions are evaluated the same way): f,
// F, rf, fR, t, Tr, ...
func fStringPrefix(r []rune, start int) bool {
	j := start - 1
	f := false
	for k := 0; k < 2 && j >= 0 && unicode.IsLetter(r[j]); k++ {
		switch r[j] {
		case 'f', 'F', 't', 'T':
			f = true
		case 'r', 'R', 'b', 'B':
		default:
			return false
		}
		j--
	}
	return f && (j < 0 || !isIdentPart(r[j]))
}

// isDunder reports whether name is a dunder ("__init__", "__getattr__").
func isDunder(name string) bool {
	return len(name) > 4 && strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__")
}

// relativeModule resolves a relative import target (".m.f", "..x") imported by module
// (a package's __init__ when isPackage) to a slash path ("pkg/m/f"); ok is false when the
// dots climb above the build root.
func relativeModule(module string, isPackage bool, target string) (string, bool) {
	dots := len(target) - len(strings.TrimLeft(target, "."))
	base := module
	if !isPackage {
		base = parentModule(base)
	}
	for k := 1; k < dots; k++ {
		if base == "" {
			return "", false
		}
		base = parentModule(base)
	}
	rest := strings.ReplaceAll(target[dots:], ".", "/")
	switch {
	case base == "":
		return rest, rest != ""
	case rest == "":
		return base, true
	}
	return base + "/" + rest, true
}

// parentModule is a module path's containing package ("a/b" → "a", "a" → "").
func parentModule(m string) string {
	if i := strings.LastIndexByte(m, '/'); i >= 0 {
		return m[:i]
	}
	return ""
}

// moduleNamedBy reports whether a module path is, or lies inside, the module a dotted
// import path names once turned into a slash path: the import root may sit below the build
// root ("src/pkg/m" for "pkg/m").
func moduleNamedBy(module, path string) bool {
	if path == "" {
		return false
	}
	return module == path || strings.HasPrefix(module, path+"/") ||
		strings.HasSuffix(module, "/"+path) || strings.Contains(module, "/"+path+"/")
}
