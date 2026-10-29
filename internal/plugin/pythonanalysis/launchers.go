package pythonanalysis

import (
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

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
//     second argument (or view=) names a view function ("views.index"), a class-based view
//     ("views.Index.as_view()"), or either wrapped in a decorator call
//     ("login_required(views.index)", "cache_page(60)(views.index)").
//
// Every function a launcher names is a call-graph root. A console or GUI script is a
// "main" ingress, a setting a "http_server" ingress and a URL pattern a "http_route"
// ingress; another entry-point group (a pytest plugin, a CLI command) is loaded by the
// tool that reads it and is a root only. A script or entry point whose module is
// first-party but whose attribute names no function the lane sees (an instance, an
// attribute set at run time) makes ingress discovery partial and every function of that
// module a root; one that names a module alone loads it, and every function of the module
// is a root. A setting naming a value is Django's own handler, which dispatches to the
// URL patterns, so it does not. A class-based view's as_view() dispatches to the methods
// the class and its first-party bases define (a request method, or a hook such as
// get_queryset that a dependency base calls), and each is an ingress; a class or base the
// lane cannot find makes discovery partial. So does a view argument the lane cannot read,
// or a wrapper, that names first-party code, and a launcher construct it does not model.

// launchTarget is one function a launcher names by dotted path. segs is the path split into
// segments; mod is how many of them name the module when the launcher says so (an entry
// point's "module:attr"), else 0 and the longest prefix that names a module is taken.
// optional marks a target whose absence is expected (see above); view one whose path names a
// class-based view, its methods the functions; unread one the lane cannot read that may
// name first-party code, which names no function and makes discovery partial.
type launchTarget struct {
	segs     []string
	mod      int
	kind     string
	selector string
	optional bool
	view     bool
	unread   bool
}

// urlView is a Django URL pattern's view as its file writes it: the dotted name (nil when
// the argument names no view the lane can read), whether it is a class-based view's
// as_view(), the route literal when the first argument is one, and the names the argument
// reads besides the view: a wrapper's, or every name of an argument read as no view.
type urlView struct {
	chain    []string
	asView   bool
	selector string
	heads    []string
}

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
// files declare. ok is false when one of them cannot be read or parsed, supported false
// when one declares entry points in a form the reader does not model.
func readManifestLaunchers(buildDir string) (targets []launchTarget, ok, supported bool) {
	supported = true
	manifests, ok := walkManifests(buildDir, func(path string) bool {
		base := filepath.Base(path)
		return base == "pyproject.toml" || base == "setup.cfg"
	})
	for _, f := range manifests {
		data, err := readRegular(f)
		if err != nil {
			ok = false
			continue
		}
		var ts []launchTarget
		parsed, modeled := true, true
		switch filepath.Base(f) {
		case "pyproject.toml":
			ts, parsed = pyprojectLaunchers(data)
		case "setup.cfg":
			ts, modeled = setupCfgLaunchers(data)
		}
		ok = ok && parsed
		supported = supported && modeled
		targets = append(targets, ts...)
	}
	return targets, ok, supported
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
// group whose value lines are "name = spec". ok is false when the file declares the
// section but readCfg refuses it (an interpolation, a duplicate) or a line is no spec; a
// refused file that declares no such section declares no entry points.
func setupCfgLaunchers(data []byte) ([]launchTarget, bool) {
	sections, ok := readCfg(data)
	if !ok {
		return nil, !declaresEntryPoints(data)
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

// declaresEntryPoints reports whether a setup.cfg's text has an [options.entry_points]
// section header.
func declaresEntryPoints(data []byte) bool {
	for _, line := range strings.Split(universalNewlines(string(data)), "\n") {
		if name, header := cfgHeader(strings.Trim(line, " \t")); header && name == "options.entry_points" {
			return true
		}
	}
	return false
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
// supported is false when a spec comes before any group (a list built elsewhere and passed
// by name): it is a root, but whether it is a script is unknown.
func setupPyLaunchers(clean string, lits map[int]strLiteral) (out []launchTarget, supported bool) {
	r := []rune(clean)
	starts := slices.Sorted(mapIntKeys(lits))
	supported = true
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
					supported = supported && section != ""
				}
			}
			continue
		}
		if t, ok := setupPySpec(group, lit.body); ok {
			out = append(out, t)
			supported = supported && group != ""
		}
	}
	return out, supported
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
		if !closed {
			continue
		}
		view, found := "", false
		for n, a := range args {
			s := strings.TrimSpace(string(r[a[0]:a[1]]))
			if k, val, kw := keywordArg(s); kw {
				if k == "view" {
					view, found = val, true
				}
			} else if n == 1 {
				view, found = s, true
			}
		}
		if !found {
			continue
		}
		v, ok := viewRef(view)
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

// viewRef reads a URL pattern's view argument: a dotted name, a dotted name's as_view()
// call, or a call wrapping either (a decorator applied in place, its calls chained), whose
// first argument that names a view is the view and whose head is kept. include() names a
// URL module and no view (ok false); any other expression is read as no view, its names
// kept.
func viewRef(arg string) (urlView, bool) {
	arg = strings.TrimSpace(arg)
	if isDottedName(arg) {
		return urlView{chain: dottedSegs(arg)}, true
	}
	r := []rune(arg)
	opaque := urlView{heads: identHeads(r)}
	end := dottedEnd(r, 0)
	open := skipSpaceRunes(r, end)
	if end == 0 || open >= len(r) || r[open] != '(' {
		return opaque, true
	}
	segs := dottedSegs(string(r[:end]))
	switch leaf := segs[len(segs)-1]; {
	case leaf == "include":
		return urlView{}, false
	case leaf == "as_view" && len(segs) > 1 && matchingClose(r, open) == len(r)-1:
		return urlView{chain: segs[:len(segs)-1], asView: true}, true
	}
	for open < len(r) && r[open] == '(' {
		args, closed := callArgs(r, open)
		if !closed {
			break
		}
		for _, a := range args {
			if v, ok := viewRef(string(r[a[0]:a[1]])); ok && v.chain != nil {
				v.heads = append(v.heads, segs[0])
				return v, true
			}
		}
		open = skipSpaceRunes(r, matchingClose(r, open)+1)
	}
	return opaque, true
}

// dottedEnd returns the end of the dotted name (spaces around the dots allowed) starting at
// i, or i when none starts there.
func dottedEnd(r []rune, i int) int {
	end := i
	for j := i; j < len(r) && isIdentStartRune(r[j]); {
		_, end = readWordRunes(r, j)
		k := skipSpaceRunes(r, end)
		if k >= len(r) || r[k] != '.' {
			break
		}
		j = skipSpaceRunes(r, k+1)
	}
	return end
}

// identHeads returns the names an expression reads: each identifier that is no attribute.
func identHeads(r []rune) []string {
	var out []string
	for i := 0; i < len(r); i++ {
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			continue
		}
		w, end := readWordRunes(r, i)
		if j := lastNonSpace(r, i); j < 0 || r[j] != '.' {
			out = append(out, w)
		}
		i = end - 1
	}
	return out
}

// lastNonSpace returns the index of the last non-space rune before i, or -1.
func lastNonSpace(r []rune, i int) int {
	for i--; i >= 0 && unicode.IsSpace(r[i]); i-- {
	}
	return i
}

// keywordArg splits a call argument "name=value" into its name and value; kw is false for a
// positional argument (including a comparison "a == b").
func keywordArg(s string) (name, value string, kw bool) {
	r := []rune(s)
	if len(r) == 0 || !isIdentStartRune(r[0]) {
		return "", "", false
	}
	name, end := readWordRunes(r, 0)
	eq := skipSpaceRunes(r, end)
	if eq >= len(r) || r[eq] != '=' || (eq+1 < len(r) && r[eq+1] == '=') {
		return "", "", false
	}
	return name, strings.TrimSpace(string(r[eq+1:])), true
}

// launchTargets is every launcher target of the build: the manifests', and each file's
// settings and URL patterns, its view names read through the file's module-level imports.
// A view the file neither defines nor imports from first-party code is a dependency's; a
// wrapper or unread argument naming first-party code is an unread target.
func (prog *program) launchTargets() []launchTarget {
	out := slices.Clone(prog.launchers)
	for i := range prog.files {
		f := &prog.files[i]
		out = append(out, f.settings...)
		for _, v := range f.urlViews {
			if slices.ContainsFunc(v.heads, f.definesFirstParty) {
				out = append(out, launchTarget{kind: "http_route", selector: v.selector, unread: true})
			}
			if v.chain == nil {
				continue
			}
			var bases [][]string
			if paths := f.fpBinds[""][v.chain[0]]; len(paths) > 0 {
				for _, p := range paths {
					bases = append(bases, append(strings.Split(p, "/"), v.chain[1:]...))
				}
			} else if f.definesFirstParty(v.chain[0]) {
				bases = append(bases, append(strings.Split(f.module, "/"), v.chain...))
			}
			for _, segs := range bases {
				out = append(out, launchTarget{segs: segs, kind: "http_route", selector: v.selector, view: v.asView})
			}
		}
	}
	return out
}

// definesFirstParty reports whether the file's module scope binds name to first-party code:
// by a first-party import, or by its own def, class or assignment rather than an import.
func (f *fileParse) definesFirstParty(name string) bool {
	if len(f.fpBinds[""][name]) > 0 {
		return true
	}
	_, imported := f.bindings[""][name]
	return f.topNames[name] && f.module != "" && !imported && f.depImports[""][name] == 0
}

// pathHit is a place a dotted path reaches: a file of the module it names, and the attribute
// path read in that file.
type pathHit struct {
	file  int
	attrs []string
}

// launchDecls resolves a target to the functions it names. module is the first-party module
// the target's path reaches, "" when it reaches none (a dependency's); whole is true when
// the path names that module and no attribute of it (an entry point that loads a module);
// missing is true when the path reaches first-party code the lane cannot name in full (no
// function or class by the name, or a class-based view's base it cannot find).
func (prog *program) launchDecls(t launchTarget) (decls []funcDecl, module string, whole, missing bool) {
	hits, module, whole := prog.resolvePath(t.segs, t.mod)
	seen := map[string]bool{}
	add := func(fd funcDecl) {
		if !seen[fd.scip()] {
			seen[fd.scip()] = true
			decls = append(decls, fd)
		}
	}
	found, complete := false, true
	visited := map[string]bool{}
	for _, h := range hits {
		if t.view {
			f, c := prog.viewMethods(h, add, visited)
			found, complete = found || f, complete && c
			continue
		}
		if len(h.attrs) == 0 {
			continue
		}
		for _, fd := range prog.files[h.file].decls {
			if fd.name == h.attrs[len(h.attrs)-1] && !fd.inDef && slices.Equal(fd.enclosing, h.attrs[:len(h.attrs)-1]) {
				add(fd)
			}
		}
	}
	sort.Slice(decls, func(i, j int) bool { return decls[i].scip() < decls[j].scip() })
	if t.view {
		missing = module != "" && !whole && (!found || !complete)
	} else {
		missing = module != "" && !whole && len(decls) == 0
	}
	return decls, module, whole, missing
}

// viewMethods adds the methods a class-based view at h dispatches to: those its class and
// each first-party base define. found is false when h's file declares no such class;
// complete false when a base that names first-party code resolves to no class the lane
// sees. visited ends an inheritance cycle.
func (prog *program) viewMethods(h pathHit, add func(funcDecl), visited map[string]bool) (found, complete bool) {
	g := &prog.files[h.file]
	cls := strings.Join(h.attrs, ".")
	bases, ok := g.classes[cls]
	if len(h.attrs) == 0 || !ok {
		return false, true
	}
	key := g.module + "\x00" + cls
	if visited[key] {
		return true, true
	}
	visited[key] = true
	for _, fd := range g.decls {
		if !fd.inDef && slices.Equal(fd.enclosing, h.attrs) {
			add(fd)
		}
	}
	complete = true
	for _, b := range bases {
		r := []rune(b)
		segs := dottedSegs(string(r[:dottedEnd(r, 0)]))
		if len(segs) == 0 {
			complete = complete && !slices.ContainsFunc(identHeads(r), g.definesFirstParty)
			continue
		}
		var next []pathHit
		if paths := g.fpBinds[""][segs[0]]; len(paths) > 0 {
			for _, p := range paths {
				hs, _, _ := prog.resolvePath(append(strings.Split(p, "/"), segs[1:]...), 0)
				next = append(next, hs...)
			}
		} else if g.definesFirstParty(segs[0]) {
			next = []pathHit{{file: h.file, attrs: segs}}
		} else {
			continue // a dependency's base
		}
		baseFound := false
		for _, nh := range next {
			f, c := prog.viewMethods(nh, add, visited)
			baseFound, complete = baseFound || f, complete && c
		}
		complete = complete && baseFound
	}
	return true, complete
}

// resolvePath finds the places a dotted path reaches. mod is how many segments name the
// module, or 0 for the longest prefix that names one; module and whole are as for
// launchDecls. The attribute is followed through first-party re-exports of the module it
// is read from; a path is tried once, so a re-export cycle ends.
func (prog *program) resolvePath(segs []string, mod int) (hits []pathHit, module string, whole bool) {
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
			hits = append(hits, pathHit{file: i, attrs: attrs})
			for _, next := range prog.files[i].fpBinds[""][attrs[0]] {
				walk(append(strings.Split(next, "/"), attrs[1:]...), 0)
			}
		}
	}
	walk(segs, mod)
	return hits, module, whole
}

// unresolved reports whether a target that must name first-party code names it only in
// part, or is a launcher the lane cannot read.
func (prog *program) unresolved(t launchTarget) bool {
	_, _, _, missing := prog.launchDecls(t)
	return t.unread || !t.optional && missing
}
