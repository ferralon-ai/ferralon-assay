package pythonanalysis

import (
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Launcher entry points.
//
// A launcher starts first-party code that nothing in the source calls, naming it by dotted
// path rather than by a decorator on the def:
//   - an entry point a manifest declares: [project.scripts], [project.gui-scripts] and
//     [project.entry-points.<group>] in pyproject.toml, [tool.poetry.scripts] and
//     [tool.poetry.plugins.<group>], [options.entry_points] in setup.cfg, and the
//     "name = module:attr" specs a setup.py passes as entry_points;
//   - a Django WSGI_APPLICATION or ASGI_APPLICATION setting ("myapp.wsgi.application");
//   - a Django URL pattern's view: path(), re_path() or url() imported from django, whose
//     second argument names a view function ("views.index") or a class-based view
//     ("views.Index.as_view()").
//
// Every function a launcher names is a call-graph root. A console or GUI script is a
// "main" ingress, a setting a "http_server" ingress and a URL pattern a "http_route"
// ingress; another entry-point group (a pytest plugin, a CLI command) is loaded by the
// tool that reads it and is a root only. A script or entry point whose module is
// first-party but whose attribute names no function the lane sees (an instance, an
// attribute set at run time) makes ingress discovery partial and every function of that
// module a root; one that names a module alone loads it, and every function of the module
// is a root. A setting naming a value is Django's own handler, which dispatches to the
// URL patterns, and a class-based view's request methods may be inherited from a
// dependency, so neither does.

// launchTarget is one function a launcher names by dotted path. segs is the path split into
// segments; mod is how many of them name the module when the launcher says so (an entry
// point's "module:attr"), else 0 and the longest prefix that names a module is taken.
// optional marks a target whose absence is expected (see above).
type launchTarget struct {
	segs     []string
	mod      int
	kind     string
	selector string
	optional bool
}

// urlView is a Django URL pattern's view as its file writes it: the dotted name, whether it
// is a class-based view's as_view(), and the route literal when the first argument is one.
type urlView struct {
	chain    []string
	asView   bool
	selector string
}

// djangoViewMethods are the request methods a class-based view's as_view() dispatches to.
var djangoViewMethods = []string{"get", "post", "put", "patch", "delete", "head", "options", "trace"}

// scriptGroups are the entry-point groups an installer turns into commands.
var scriptGroups = map[string]bool{"console_scripts": true, "gui_scripts": true}

// entrySpec matches an entry-point object reference, "module:attr.attr" or a bare module,
// with an optional [extras] suffix.
var entrySpec = regexp.MustCompile(`^\s*([A-Za-z_][\w]*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*(?::\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*))?\s*(?:\[[^\]]*\])?\s*$`)

// entryTarget reads one entry-point object reference into a target of the given kind.
func entryTarget(spec, kind, selector string) (launchTarget, bool) {
	m := entrySpec.FindStringSubmatch(spec)
	if m == nil {
		return launchTarget{}, false
	}
	mod := dottedSegs(m[1])
	segs := append(mod, dottedSegs(m[2])...)
	return launchTarget{segs: segs, mod: len(mod), kind: kind, selector: selector}, true
}

// dottedSegs splits a dotted name, spaces around the dots allowed, into its segments.
func dottedSegs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, seg := range strings.Split(s, ".") {
		out = append(out, strings.TrimSpace(seg))
	}
	return out
}

// entryKind is the ingress kind of an entry point in group: "main" for a script, "" for a
// root that is no ingress.
func entryKind(group string) string {
	if scriptGroups[group] {
		return "main"
	}
	return ""
}

// readManifestLaunchers reads the entry points the build's pyproject.toml and setup.cfg
// files declare. ok is false when one of them cannot be read or parsed.
func readManifestLaunchers(buildDir string) (targets []launchTarget, ok bool) {
	manifests, ok := walkManifests(buildDir, func(path string) bool {
		base := filepath.Base(path)
		return base == "pyproject.toml" || base == "setup.cfg"
	})
	for _, f := range manifests {
		var read func([]byte) ([]launchTarget, bool)
		switch filepath.Base(f) {
		case "pyproject.toml":
			read = pyprojectLaunchers
		case "setup.cfg":
			read = setupCfgLaunchers
		default:
			continue
		}
		data, err := readRegular(f)
		if err != nil {
			ok = false
			continue
		}
		ts, parsed := read(data)
		ok = ok && parsed
		targets = append(targets, ts...)
	}
	return targets, ok
}

// pyprojectLaunchers reads a pyproject.toml's PEP 621 and Poetry entry points.
func pyprojectLaunchers(data []byte) ([]launchTarget, bool) {
	var doc struct {
		Project struct {
			Scripts     map[string]any            `toml:"scripts"`
			GUIScripts  map[string]any            `toml:"gui-scripts"`
			EntryPoints map[string]map[string]any `toml:"entry-points"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Scripts map[string]any            `toml:"scripts"`
				Plugins map[string]map[string]any `toml:"plugins"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	var out []launchTarget
	ok := true
	add := func(group string, entries map[string]any) {
		for _, name := range slices.Sorted(mapKeys(entries)) {
			spec, isString := entries[name].(string)
			if table, isTable := entries[name].(map[string]any); isTable {
				// Poetry's table form: {reference = "...", type = "console"} or {callable = "..."}.
				spec, isString = table["callable"].(string)
				if !isString {
					spec, isString = table["reference"].(string)
				}
				if kind, _ := table["type"].(string); isString && kind != "" && kind != "console" {
					continue // a "file" script is a path, not an object reference
				}
			}
			t, parsed := entryTarget(spec, entryKind(group), name)
			if !isString || !parsed {
				ok = false
				continue
			}
			out = append(out, t)
		}
	}
	add("console_scripts", doc.Project.Scripts)
	add("gui_scripts", doc.Project.GUIScripts)
	add("console_scripts", doc.Tool.Poetry.Scripts)
	for _, group := range slices.Sorted(mapKeys(doc.Project.EntryPoints)) {
		add(group, doc.Project.EntryPoints[group])
	}
	for _, group := range slices.Sorted(mapKeys(doc.Tool.Poetry.Plugins)) {
		add(group, doc.Tool.Poetry.Plugins[group])
	}
	return out, ok
}

// mapKeys returns m's keys.
func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// setupCfgLaunchers reads a setup.cfg's [options.entry_points] section: each option is a
// group whose value lines are "name = spec".
func setupCfgLaunchers(data []byte) ([]launchTarget, bool) {
	sections, ok := readCfg(data)
	if !ok {
		return nil, false
	}
	var out []launchTarget
	for _, s := range sections {
		if s.name != "options.entry_points" {
			continue
		}
		for _, o := range s.options {
			ts, parsed := entryLines(o.key, o.value())
			ok = ok && parsed
			out = append(out, ts...)
		}
	}
	return out, ok
}

// entryLines reads the "name = spec" lines of one entry-point group, skipping blank lines.
func entryLines(group, text string) ([]launchTarget, bool) {
	var out []launchTarget
	ok := true
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, spec, found := strings.Cut(line, "=")
		t, parsed := entryTarget(spec, entryKind(group), strings.TrimSpace(name))
		if !found || !parsed {
			ok = false
			continue
		}
		out = append(out, t)
	}
	return out, ok
}

// setupPyLaunchers reads the entry points a setup.py passes as string literals: a group key
// ("console_scripts": [...]) followed by its "name = spec" strings, or an ini-style string
// with [group] headers. A string that is no spec is ignored; setup.py carries many others.
func setupPyLaunchers(clean string, lits map[int]strLiteral) []launchTarget {
	r := []rune(clean)
	starts := slices.Sorted(mapIntKeys(lits))
	var out []launchTarget
	group := ""
	for _, at := range starts {
		lit := lits[at]
		if k := skipAllSpace(r, lit.end); k < len(r) && r[k] == ':' {
			group = lit.body
			continue
		}
		if strings.Contains(lit.body, "\n") {
			section := ""
			for _, line := range strings.Split(lit.body, "\n") {
				line = strings.TrimSpace(line)
				if h, found := strings.CutPrefix(line, "["); found && strings.HasSuffix(h, "]") {
					section = strings.TrimSpace(strings.TrimSuffix(h, "]"))
					continue
				}
				if t, ok := setupPySpec(section, line); ok {
					out = append(out, t)
				}
			}
			continue
		}
		if t, ok := setupPySpec(group, lit.body); ok {
			out = append(out, t)
		}
	}
	return out
}

// setupPySpec reads one "name = module:attr" string. It must name an attribute: a bare
// dotted string beside an "=" is too common in a setup.py to be read as an entry point.
func setupPySpec(group, s string) (launchTarget, bool) {
	name, spec, found := strings.Cut(s, "=")
	if !found || !strings.Contains(spec, ":") || strings.TrimSpace(name) == "" {
		return launchTarget{}, false
	}
	return entryTarget(spec, entryKind(group), strings.TrimSpace(name))
}

// mapIntKeys returns m's keys.
func mapIntKeys[V any](m map[int]V) func(func(int) bool) {
	return func(yield func(int) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// settingsLaunchers reads a Django WSGI_APPLICATION or ASGI_APPLICATION assignment of a
// string literal.
func settingsLaunchers(clean string, lits map[int]strLiteral) []launchTarget {
	r := []rune(clean)
	var out []launchTarget
	for i := 0; i < len(r); {
		if !isIdentStartRune(r[i]) || (i > 0 && (isIdentPart(r[i-1]) || r[i-1] == '.')) {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		i = end
		if w != "WSGI_APPLICATION" && w != "ASGI_APPLICATION" {
			continue
		}
		eq := skipSpaceRunes(r, end)
		if eq >= len(r) || r[eq] != '=' || (eq+1 < len(r) && r[eq+1] == '=') {
			continue
		}
		at := skipSpaceRunes(r, eq+1)
		lit, ok := lits[at]
		if !ok || !isDottedName(lit.body) {
			continue
		}
		if k := skipSpaceRunes(r, lit.end); k < len(r) && r[k] != '\n' && r[k] != ';' {
			continue
		}
		out = append(out, launchTarget{segs: strings.Split(lit.body, "."), kind: "http_server", selector: w, optional: true})
	}
	return out
}

// urlRegistrars are the Django URL-pattern functions whose second argument is the view.
var urlRegistrars = map[string]bool{"path": true, "re_path": true, "url": true}

// djangoURLViews reads the views a file's URL patterns register. A registrar counts when
// the file binds it, or the module it is read from, by an import from django.
func djangoURLViews(clean string, lits map[int]strLiteral, bindings map[string]map[string]scopedBinding) []urlView {
	fromDjango := func(local string) bool {
		b, ok := bindings[""][local]
		return ok && (b.target == "django" || strings.HasPrefix(b.target, "django."))
	}
	r := []rune(clean)
	var out []urlView
	for i := 0; i < len(r); {
		if !isIdentStartRune(r[i]) || (i > 0 && (isIdentPart(r[i-1]) || r[i-1] == '.')) {
			i++
			continue
		}
		start := i
		var chain []string
		for {
			w, end := readWordRunes(r, i)
			chain = append(chain, w)
			i = end
			if i+1 < len(r) && r[i] == '.' && isIdentStartRune(r[i+1]) {
				i++
				continue
			}
			break
		}
		open := skipSpaceRunes(r, i)
		leaf := chain[len(chain)-1]
		if open >= len(r) || r[open] != '(' || !urlRegistrars[leaf] || precededByDef(r, start) {
			continue
		}
		if !fromDjango(chain[0]) {
			continue
		}
		args, closed := callArgs(r, open)
		if !closed || len(args) < 2 {
			continue
		}
		v, ok := viewRef(strings.TrimSpace(string(r[args[1][0]:args[1][1]])))
		if !ok {
			continue
		}
		if route, isLit := literalSpan(r, args[0], lits); isLit {
			v.selector = route
		}
		out = append(out, v)
	}
	return out
}

// viewRef reads a URL pattern's view argument: a dotted name, or a dotted name's
// as_view() call. include() and any other expression name no view.
func viewRef(arg string) (urlView, bool) {
	if isDottedName(arg) {
		return urlView{chain: strings.Split(arg, ".")}, true
	}
	head, call, found := strings.Cut(arg, "(")
	head = strings.TrimSpace(head)
	if !found || !strings.HasSuffix(head, ".as_view") || !strings.HasSuffix(strings.TrimSpace(call), ")") {
		return urlView{}, false
	}
	cls := strings.TrimSuffix(head, ".as_view")
	if !isDottedName(cls) {
		return urlView{}, false
	}
	return urlView{chain: strings.Split(cls, "."), asView: true}, true
}

// launchTargets is every launcher target of the build: the manifests', and each file's
// settings and URL patterns, its view names read through the file's module-level imports.
// A view the file neither defines nor imports from first-party code is a dependency's.
func (prog *program) launchTargets() []launchTarget {
	out := slices.Clone(prog.launchers)
	for _, f := range prog.files {
		out = append(out, f.settings...)
		for _, v := range f.urlViews {
			var bases [][]string
			if paths := f.fpBinds[""][v.chain[0]]; len(paths) > 0 {
				for _, p := range paths {
					bases = append(bases, append(strings.Split(p, "/"), v.chain[1:]...))
				}
			} else if f.topNames[v.chain[0]] && f.module != "" {
				bases = append(bases, append(strings.Split(f.module, "/"), v.chain...))
			}
			for _, segs := range bases {
				if !v.asView {
					out = append(out, launchTarget{segs: segs, kind: "http_route", selector: v.selector})
					continue
				}
				for _, m := range djangoViewMethods {
					out = append(out, launchTarget{segs: append(slices.Clone(segs), m), kind: "http_route", selector: v.selector, optional: true})
				}
			}
		}
	}
	return out
}

// launchDecls resolves a target to the functions it names. module is the first-party module
// the target's path reaches, "" when it reaches none (a dependency's); whole is true when
// the path names that module and no attribute of it (an entry point that loads a module).
// The attribute is followed through first-party re-exports of the module it is read from;
// a path is tried once, so a re-export cycle ends.
func (prog *program) launchDecls(t launchTarget) (decls []funcDecl, module string, whole bool) {
	seen := map[string]bool{}
	visited := map[string]bool{}
	var walk func(segs []string, mod int)
	walk = func(segs []string, mod int) {
		key := strings.Join(segs, "/")
		if visited[key] {
			return
		}
		visited[key] = true
		k := mod
		if k == 0 {
			for k = len(segs); k > 0 && len(prog.byModule[strings.Join(segs[:k], "/")]) == 0; k-- {
			}
		}
		path := strings.Join(segs[:k], "/")
		if k == 0 || len(prog.byModule[path]) == 0 {
			return
		}
		attrs := segs[k:]
		if module == "" {
			module, whole = path, len(attrs) == 0
		}
		if len(attrs) == 0 {
			return
		}
		for _, i := range prog.byModule[path] {
			g := &prog.files[i]
			for _, fd := range g.decls {
				if fd.name == attrs[len(attrs)-1] && !fd.inDef && slices.Equal(fd.enclosing, attrs[:len(attrs)-1]) && !seen[fd.scip()] {
					seen[fd.scip()] = true
					decls = append(decls, fd)
				}
			}
			for _, next := range g.fpBinds[""][attrs[0]] {
				walk(append(strings.Split(next, "/"), attrs[1:]...), 0)
			}
		}
	}
	walk(t.segs, t.mod)
	sort.Slice(decls, func(i, j int) bool { return decls[i].scip() < decls[j].scip() })
	return decls, module, whole
}

// unresolved reports whether a target that must name a first-party function names none.
func (prog *program) unresolved(t launchTarget) bool {
	decls, module, whole := prog.launchDecls(t)
	return !t.optional && module != "" && !whole && len(decls) == 0
}
