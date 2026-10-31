package pythonanalysis

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// importBinding is one name an import statement binds: `import a.b` binds a → "a",
// `import a.b as c` binds c → "a.b", `from a.b import d as e` binds e → "a.b.d".
type importBinding struct {
	local  string
	target string
}

// parseImportStatement parses a cleaned logical line that starts with `import` or `from`
// into the names it binds. Relative imports (`from . import x`, `from .m import y`) bind
// first-party names, so they never yield a binding here (a binding here can name a
// dependency boundary); parseRelativeImport reads them. Star imports bind names the scanner
// cannot list; the call graph's standing dynamic_dispatch partiality covers what they hide.
func parseImportStatement(text string) []importBinding {
	kw, rest := firstWord(text)
	switch kw {
	case "import":
		var out []importBinding
		for _, item := range splitImportList(rest) {
			path, alias := splitAlias(item)
			if !isDottedName(path) {
				continue
			}
			if alias != "" {
				out = append(out, importBinding{local: alias, target: path})
				continue
			}
			top := path
			if i := strings.IndexByte(path, '.'); i >= 0 {
				top = path[:i]
			}
			out = append(out, importBinding{local: top, target: top})
		}
		return out
	case "from":
		rest = strings.TrimSpace(rest)
		i := strings.Index(rest, " import ")
		if i < 0 {
			return nil
		}
		from := strings.TrimSpace(rest[:i])
		if strings.HasPrefix(from, ".") || !isDottedName(from) {
			return nil
		}
		var out []importBinding
		for _, item := range splitImportList(rest[i+len(" import "):]) {
			name, alias := splitAlias(item)
			if name == "*" || !isDottedName(name) || strings.Contains(name, ".") {
				continue
			}
			local := name
			if alias != "" {
				local = alias
			}
			out = append(out, importBinding{local: local, target: from + "." + name})
		}
		return out
	}
	return nil
}

// parseRelativeImport parses a cleaned `from .m import f as g` statement into the names it
// binds, each target keeping its leading dots (".m.f", "..pkg.f", ".x" for
// `from . import x`). A relative target is first-party by construction, so these bindings
// feed only the first-party alias table and the escape scan, never a dependency boundary.
// Star imports bind names the scanner cannot list and yield nothing.
func parseRelativeImport(text string) []importBinding {
	kw, rest := firstWord(text)
	if kw != "from" {
		return nil
	}
	rest = strings.TrimSpace(rest)
	i := strings.Index(rest, " import ")
	if i < 0 {
		return nil
	}
	from := strings.TrimSpace(rest[:i])
	dots := len(from) - len(strings.TrimLeft(from, "."))
	if dots == 0 {
		return nil
	}
	if mod := from[dots:]; mod != "" && !isDottedName(mod) {
		return nil
	}
	prefix := from
	if dots < len(from) {
		prefix += "."
	}
	var out []importBinding
	for _, item := range splitImportList(rest[i+len(" import "):]) {
		name, alias := splitAlias(item)
		if name == "*" || !isDottedName(name) || strings.Contains(name, ".") {
			continue
		}
		local := name
		if alias != "" {
			local = alias
		}
		out = append(out, importBinding{local: local, target: prefix + name})
	}
	return out
}

// splitImportList splits an import list ("a, b as c", "(a,\n b)") into its items.
func splitImportList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(strings.TrimSpace(s), ")")
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitAlias splits "name as alias" into its parts; alias is "" when absent.
func splitAlias(item string) (name, alias string) {
	fields := strings.Fields(item)
	if len(fields) == 3 && fields[1] == "as" {
		return fields[0], fields[2]
	}
	if len(fields) == 1 {
		return fields[0], ""
	}
	return "", ""
}

// isDottedName reports whether s is a dotted Python identifier path ("a", "a.b_c").
func isDottedName(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" {
			return false
		}
		for i, c := range seg {
			if i == 0 && !isIdentStartRune(c) {
				return false
			}
			if !isIdentPart(c) {
				return false
			}
		}
	}
	return true
}

// instanceAssignment recognizes `name = Chain.Cls(...)...` where the right-hand side starts
// with a call whose leaf is CapWords (a class instantiation by Python convention) and
// returns the bound name and that call's chain, so `env = Environment(); env.render()`
// reaches the same dependency attribute as `Environment().render()`. Tuple targets,
// attribute targets, and annotated assignments are not recognized.
func instanceAssignment(text string) (string, []string, bool) {
	local, rest := readIdent(text)
	if local == "" || pyCallKeywords[local] {
		return "", nil, false
	}
	rest = strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "==") {
		return "", nil, false
	}
	rhs := strings.TrimSpace(rest[1:])
	calls := scanCalls(rhs)
	if len(calls) == 0 {
		return "", nil, false
	}
	first := calls[0]
	if len(first.chain) == 0 || !strings.HasPrefix(rhs, first.chain[0]) {
		return "", nil, false
	}
	leaf := []rune(first.name)
	if len(leaf) == 0 || !unicode.IsUpper(leaf[0]) {
		return "", nil, false
	}
	return local, first.chain, true
}

// distResolver maps an imported top-level module to the PyPI distribution that provides
// it: a curated DistImportMap row first, then PEP 503 equality against the distributions
// the build's manifests declare. A first-party top-level module never maps: the build's
// own code shadows any installed distribution of the same name.
type distResolver struct {
	curated    DistImportMap
	declared   map[string]bool // PEP 503 names from the build's manifests
	firstParty map[string]bool // top-level import names the build's own sources provide
	python     interpreterRange
}

// distsFor returns the distributions that may provide the dotted import path. The longest
// curated package that is the path or a whole-segment prefix of it names every curated
// distribution shipping it, declared or not: they install into the same directory, so the
// code the path names can come from any of them, and azure.identity.X reaches azure-identity
// even though several distributions share the azure namespace. With no curated package on the
// path, a top-level name exactly one curated distribution provides names that distribution.
// A declared distribution whose PEP 503 name is the top-level name is always among the
// result, so a declared dotenv or the legacy azure monolith keeps its edge beside any curated
// shipper. A namespace root several distributions share names nothing else.
func (d distResolver) distsFor(path string) []string {
	top, _, _ := strings.Cut(path, ".")
	if top == "" || d.firstParty[top] {
		return nil
	}
	dists := d.curatedShippers(path)
	if len(dists) == 0 {
		if r := d.curated.Reverse(top); len(r) == 1 {
			dists = r
		}
	}
	if n := normalizePyCoordinate(top); d.declared[n] {
		dists = sortedDedup(append(dists, n))
	}
	return dists
}

// importDeclared reports whether the build's manifests declare a distribution providing the
// dotted import path: one of the distributions distsFor names. A declared distribution
// shipping a different package (azure-core for azure.identity) never covers the path. A
// top-level name exactly one curated distribution provides decides on its own either way, and
// first-party imports count as declared.
func (d distResolver) importDeclared(path string) bool {
	top, _, _ := strings.Cut(path, ".")
	if top == "" || d.firstParty[top] || len(d.curated.Reverse(top)) == 1 {
		return true
	}
	return slices.ContainsFunc(d.distsFor(path), func(s string) bool { return d.declared[s] })
}

// curatedShippers returns the curated distributions shipping exactly the longest curated
// package that is path or a whole-segment prefix of it, or nil when none is.
func (d distResolver) curatedShippers(path string) []string {
	for prefix := path; prefix != ""; {
		if owners := d.curated.Owners(prefix); len(owners) > 0 {
			return owners
		}
		i := strings.LastIndexByte(prefix, '.')
		if i < 0 {
			return nil
		}
		prefix = prefix[:i]
	}
	return nil
}

// undeclaredImport reports whether the import binding target names a module no distribution
// the manifests read here declare provides: not an instance binding (empty target), not a
// standard-library module every interpreter the build may run on ships, and not importDeclared.
func (d distResolver) undeclaredImport(target string) bool {
	top, _, _ := strings.Cut(target, ".")
	if top == "" || d.python.ships(top) {
		return false
	}
	return !d.importDeclared(target)
}

// importTops returns the top-level import names distribution dist provides: its curated
// rows, else its own name read as an import name (the PEP 503 fallback distsFor applies in
// reverse).
func (d distResolver) importTops(dist string) []string {
	var tops []string
	for _, pkg := range d.curated.Forward(dist) {
		if i := strings.IndexByte(pkg, '.'); i >= 0 {
			pkg = pkg[:i]
		}
		tops = append(tops, pkg)
	}
	if len(tops) == 0 {
		tops = append(tops, strings.ReplaceAll(dist, "-", "_"))
	}
	return sortedDedup(tops)
}

// providesFirstParty reports whether dist names the build's own code: one of its import
// names is a first-party top-level module (an advisory on the project itself).
func (d distResolver) providesFirstParty(dist string) bool {
	for top := range d.firstParty {
		if normalizePyCoordinate(top) == dist {
			return true
		}
	}
	for _, top := range d.importTops(dist) {
		if d.firstParty[top] {
			return true
		}
	}
	return false
}

// firstPartyTops returns the top-level import names the build's own modules provide: each
// module path's first segment, plus the segment after a "src" directory (src layout).
func firstPartyTops(modules []string) map[string]bool {
	tops := map[string]bool{}
	for _, m := range modules {
		segs := strings.Split(m, "/")
		if segs[0] != "" {
			tops[segs[0]] = true
		}
		for i := 0; i+1 < len(segs); i++ {
			if segs[i] == "src" {
				tops[segs[i+1]] = true
			}
		}
	}
	return tops
}

// declaredDistributions returns the PEP 503 names every recognized manifest under buildDir
// declares, and each distribution a script surface's self-upgrade installs. complete is false
// when a manifest fails to parse, a file declares dependencies version resolution does not
// read (the same surfaces that leave a version unresolved), or an install surface is not fully
// read by the coverage check (ManifestCandidates): a name only that file holds is missing, so
// an import of it reaches no boundary node. read is false when a manifest cannot be read at
// all.
func declaredDistributions(buildDir string) (names map[string]bool, complete, read bool) {
	names, complete, read = map[string]bool{}, true, true
	add := func(deps []plugin.ResolvedDependency) {
		for _, d := range deps {
			if n := normalizePyCoordinate(d.Coordinate); n != "" {
				names[n] = true
			}
		}
	}
	manifests, unread, _, _, tooling := versionSurfaces(buildDir)
	complete = !unread && buildtree.AllFullyRead(ManifestCandidates(buildDir))
	for n := range tooling {
		names[n] = true // a self-upgrade installs it as surely as a manifest declares it
	}
	for _, f := range manifests {
		data, err := readRegular(f)
		if err != nil {
			complete, read = false, false
			continue
		}
		deps, _, ok := parseManifestData(f, data)
		if !ok {
			complete = false
		}
		add(deps)
		if filepath.Base(f) == "pyproject.toml" {
			// The lexical [project] reader still yields names from a file TOML rejects.
			lexical, _ := parsePyprojectLexical(data)
			add(lexical)
		}
	}
	return names, complete, read
}

// boundaryPrefix marks a dependency boundary node: a dependency attribute the build's code
// calls through an import binding, whose own code the lane does not read.
const boundaryPrefix = "pypi:"

// boundarySCIP mints the boundary node id for a call reaching dotted (the import path the
// code named, e.g. "jwt.decode", "jinja2.Environment.from_string") in distribution dist.
func boundarySCIP(dist, dotted string) string {
	return boundaryPrefix + dist + "#" + dotted
}

// parseBoundarySCIP splits a boundary node id into its distribution and dotted path.
func parseBoundarySCIP(id string) (dist, dotted string, ok bool) {
	rest, found := strings.CutPrefix(id, boundaryPrefix)
	if !found {
		return "", "", false
	}
	dist, dotted, ok = strings.Cut(rest, "#")
	if !ok || dist == "" || dotted == "" {
		return "", "", false
	}
	return dist, dotted, true
}

// pypiPURL is the version-less package URL for a PEP 503-normalized distribution name.
func pypiPURL(dist string) string { return "pkg:pypi/" + dist }

// pypiDistFromPURL returns the PEP 503 name a pkg:pypi PURL names, or "" for any other PURL.
func pypiDistFromPURL(purl string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:pypi/")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		rest = rest[:i]
	}
	return normalizePyCoordinate(rest)
}

// boundaryTarget resolves a call chain against the bindings visible at the call (its def
// scopes inner→outer, then the module) to the dotted dependency path it reaches and the
// distributions that may provide it. It returns no distributions when the chain's first
// segment is not bound to a non-first-party import the resolver can map.
func boundaryTarget(chain, scopes []string, bindings map[string]map[string]scopedBinding, dists distResolver) (provides []string, dotted string) {
	if len(chain) == 0 {
		return nil, ""
	}
	b, found := lookupBinding(chain[0], scopes, bindings)
	if !found {
		return nil, ""
	}
	target := b.target
	if b.inst != nil {
		// An instance of an imported class: resolve the instantiation chain once (no
		// recursion through further instance bindings).
		ib, ifound := lookupBinding(b.inst[0], scopes, bindings)
		if !ifound || ib.target == "" {
			return nil, ""
		}
		target = strings.Join(append([]string{ib.target}, b.inst[1:]...), ".")
	}
	dotted = strings.Join(append([]string{target}, chain[1:]...), ".")
	return dists.distsFor(dotted), dotted
}

// lookupBinding finds the binding for name visible from the innermost def scope outward,
// then at module scope.
func lookupBinding(name string, scopes []string, bindings map[string]map[string]scopedBinding) (scopedBinding, bool) {
	for i := len(scopes) - 1; i >= 0; i-- {
		if b, ok := bindings[scopes[i]][name]; ok {
			return b, true
		}
	}
	b, ok := bindings[""][name]
	return b, ok
}

// indexBindings groups a file's bindings by scope then local name. A later binding of the
// same name in the same scope replaces an earlier one only when the earlier one is an
// instance binding: an import target is the stronger fact for boundary naming.
func indexBindings(bs []scopedBinding) map[string]map[string]scopedBinding {
	out := map[string]map[string]scopedBinding{}
	for _, b := range bs {
		m := out[b.scope]
		if m == nil {
			m = map[string]scopedBinding{}
			out[b.scope] = m
		}
		if prev, ok := m[b.local]; ok && prev.target != "" {
			continue
		}
		m[b.local] = b
	}
	return out
}

// moduleInitSCIP is the synthetic caller for a module's top-level and class-body code,
// which runs when the module is imported. It follows scip-python's module-init descriptor
// ("<module>/__init__:"), distinct from any def's "name(n)." descriptor.
func moduleInitSCIP(module string) string {
	return scipSymbol(module, nil, "__init__:")
}

// dynamicImportLiteralLeafs are callables, other than the ones moduleLookups reads, that
// import the module their first argument names. A literal argument is a load root; anything
// else is an import the scanner cannot name. Each is a stringLoaders entry as well, which
// reads it under the names the file's imports bind it to and as a value.
var dynamicImportLiteralLeafs = map[string]bool{
	"resolve_name": true, // pkgutil.resolve_name("pkg.mod:attr")
}

// dynamicImportOpaqueLeafs load or run modules named by installed metadata, a file path or
// a loader object rather than by a module name the calling code spells out. moduleLookups
// treats every use of one, called or not, and every name the file's imports bind to one, as
// opaque.
var dynamicImportOpaqueLeafs = map[string]bool{
	"entry_points":            true, // importlib.metadata.entry_points
	"iter_entry_points":       true, // pkg_resources
	"load_entry_point":        true, // pkg_resources
	"walk_packages":           true, // pkgutil
	"iter_modules":            true, // pkgutil
	"spec_from_file_location": true, // importlib.util
	"spec_from_loader":        true, // importlib.util
	"module_from_spec":        true, // importlib.util
	"exec_module":             true, // a loader's method
	"load_module":             true, // imp, and a loader's legacy method
	"load_source":             true, // imp
	"load_compiled":           true, // imp
	"SourceFileLoader":        true, // importlib.machinery
	"SourcelessFileLoader":    true, // importlib.machinery
	"ExtensionFileLoader":     true, // importlib.machinery
	"run_path":                true, // runpy
	"run_module":              true, // runpy
	"zipimport":               true, // the zipimport module
	"zipimporter":             true, // zipimport
	"__loader__":              true, // a module's loader
}

// dynamicImports scans one file's cleaned source for the dynamic imports moduleLookups does
// not read (pkgutil.resolve_name, entry points, package walks). It returns the
// literal module names imported (load roots; a pkgutil "mod:attr" spec keeps the module
// part) and whether any dynamic import names its module by a non-literal expression.
// clean and lits come from stripPythonLiterals over the same source, so rune positions in
// clean index the literal table.
func dynamicImports(clean string, lits map[int]strLiteral) (roots []string, opaque bool) {
	r := []rune(clean)
	n := len(r)
	for i := 0; i < n; {
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		if !dynamicImportLiteralLeafs[w] && !dynamicImportOpaqueLeafs[w] {
			i = end
			continue
		}
		open := skipAllSpace(r, end)
		if open >= n || r[open] != '(' || precededByDef(r, i) {
			i = end
			continue
		}
		if dynamicImportOpaqueLeafs[w] {
			opaque = true
			i = end
			continue
		}
		name, ok := literalArg(r, open+1, lits)
		if !ok {
			opaque = true
		} else if name != "" {
			if w == "resolve_name" {
				name, _, _ = strings.Cut(name, ":")
			}
			roots = append(roots, name)
		}
		i = end
	}
	return sortedDedup(roots), opaque
}

// stringLoaderArg says what a string loader's name argument may be.
type stringLoaderArg int

const (
	// loaderNameOnly: the argument is always a dotted name, so a computed one is a dynamic
	// import the scanner cannot name.
	loaderNameOnly stringLoaderArg = iota
	// loaderNameOrObject: the argument may be the object itself (an app, a config class),
	// so a computed one is a dynamic import only when it is provably a string.
	loaderNameOrObject
)

// stringLoaders are library callables that import the module a dotted-name argument
// ("pkg.mod.attr" or "pkg.mod:attr") names, keyed by the full dotted name the file's
// imports resolve the call to, so an unrelated run() or import_string() is not one.
var stringLoaders = map[string]stringLoaderArg{
	"werkzeug.import_string":                    loaderNameOnly,
	"werkzeug.utils.import_string":              loaderNameOnly,
	"django.utils.module_loading.import_string": loaderNameOnly,
	"uvicorn.run":                               loaderNameOrObject,
	"uvicorn.Config":                            loaderNameOrObject,
	"uvicorn.main.run":                          loaderNameOrObject,
	"uvicorn.config.Config":                     loaderNameOrObject,
	"pkgutil.resolve_name":                      loaderNameOnly,
	"pkgutil_resolve_name.resolve_name":         loaderNameOnly, // the PyPI backport
}

// stringLoaderMethods are loader methods called on an instance the scanner cannot type,
// keyed by the attribute chain that ends the call: Flask's app.config.from_object and
// Celery's app.config_from_object, which both take a dotted name or the object itself.
var stringLoaderMethods = map[string]bool{
	"config.from_object": true,
	"config_from_object": true,
}

// loaderKeywords are the parameter names string loaders give the argument that names the
// module: uvicorn's app, werkzeug's and django's import_name and dotted_path, Flask's and
// Celery's obj.
var loaderKeywords = map[string]bool{"app": true, "import_name": true, "dotted_path": true, "obj": true}

// loaderOwnKeywords are name-argument keywords only one loader takes, keyed by the
// stringLoaders entry: name is too common a parameter to read as the module name of every
// loader's call.
var loaderOwnKeywords = map[string]string{
	"pkgutil.resolve_name":              "name",
	"pkgutil_resolve_name.resolve_name": "name",
}

// stringLoaderImports scans one file's cleaned source for calls to stringLoaders and
// stringLoaderMethods. It returns the module names literal arguments import and whether a
// loader may import a module the scanner cannot name: a computed argument, or a loader
// used as a value (map(import_string, paths)), whose calls it cannot see. bindings resolve
// the head of each dotted call to the module the file imported it from.
func stringLoaderImports(clean string, lits map[int]strLiteral, bindings []scopedBinding) (roots []string, opaque bool) {
	r := []rune(clean)
	n := len(r)
	spans, stars := importStatements(r)
	targets := map[string][]string{}
	for _, b := range bindings {
		if b.target != "" && !slices.Contains(targets[b.local], b.target) {
			targets[b.local] = append(targets[b.local], b.target)
		}
	}
	for name := range stringLoaders {
		if mod, leaf, _ := cutLast(name, "."); stars[mod] && !definesName(r, leaf) {
			targets[leaf] = append(targets[leaf], name)
		}
	}
	si := 0
	for i := 0; i < n; {
		if si < len(spans) && i >= spans[si][0] {
			i = max(i, spans[si][1])
			si++
			continue
		}
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		qualified := i > 0 && r[i-1] == '.'
		var segs []string
		end := i
		for {
			var w string
			w, end = readWordRunes(r, end)
			segs = append(segs, w)
			if end+1 < n && r[end] == '.' && isIdentStartRune(r[end+1]) {
				end++
				continue
			}
			break
		}
		kind, name, ok := stringLoaderKind(segs, qualified, targets)
		fetchEnd := end
		if !ok && !qualified && !assignedTo(r, end) {
			var fetched bool
			name, fetchEnd, fetched = loaderFetch(r, i, end, segs, targets, lits)
			if !fetched {
				opaque = true
			}
			kind, ok = stringLoaders[name]
		}
		if !ok || precededByDef(r, i) || precededByWord(r, i, "class") || assignedTo(r, fetchEnd) {
			i = end
			continue
		}
		open := skipAllSpace(r, fetchEnd)
		if open >= n || r[open] != '(' {
			// A loader passed or bound as a value may be called anywhere. A Config class
			// named as a type (an annotation, isinstance) is no call.
			opaque = opaque || !strings.HasSuffix(name, ".Config") || !typePosition(r, i)
			i = end
			continue
		}
		arg, known := loaderNameArg(r, open, loaderOwnKeywords[name])
		switch {
		case !known:
			opaque = opaque || kind == loaderNameOnly
		case arg[0] < arg[1]:
			c := classifyLoaderArg(r, arg[0], arg[1], lits)
			roots = append(roots, c.roots...)
			opaque = opaque || c.computed || c.other && kind == loaderNameOnly
		}
		i = end
	}
	return sortedDedup(roots), opaque
}

// loaderHosts are the modules that hold a stringLoaders entry as an attribute.
var loaderHosts = func() map[string]bool {
	hosts := map[string]bool{}
	for name := range stringLoaders {
		mod, _, _ := cutLast(name, ".")
		hosts[mod] = true
	}
	return hosts
}()

// fetchDunders are the module attributes that fetch another attribute by a computed name.
var fetchDunders = map[string]bool{"__dict__": true, "__getattribute__": true, "__getattr__": true}

// loaderFetch reads a use of a loaderHosts module, named by the dotted name segs running from
// r[i] to r[end], that may fetch one of its loaders by name: a getattr of it, a vars() or
// __dict__ subscript or .get. A literal attribute naming a loader returns that stringLoaders
// entry as name and the index just past the fetch, so the caller reads the fetched loader as
// it reads one spelled out. A fetch by a name the scanner cannot read, a computed-access
// dunder, or the module passed or bound as a value reports fetched false. Any other use
// (hasattr, setattr, a plain attribute), and a dotted name that is not such a module, is
// neither.
func loaderFetch(r []rune, i, end int, segs []string, targets map[string][]string, lits map[int]strLiteral) (name string, after int, fetched bool) {
	host, rest := "", segs
	for _, t := range targets[segs[0]] {
		for k := len(segs); k >= 1; k-- {
			full := strings.Join(append([]string{t}, segs[1:k]...), ".")
			if loaderHosts[full] && len(full) > len(host) {
				host, rest = full, segs[k:]
				break
			}
		}
	}
	if host == "" {
		return "", end, true
	}
	leaf := func(attr string, after int) (string, int, bool) {
		if _, ok := stringLoaders[host+"."+attr]; ok {
			return host + "." + attr, after, true
		}
		// moduleLookups reads these by their spelled name, which a fetch by literal hides.
		return "", end, !fetchDunders[attr] && !dynamicImportOpaqueLeafs[attr] && !dynamicImportLiteralLeafs[attr]
	}
	switch {
	case len(rest) == 0:
	case rest[0] == "__dict__" && len(rest) == 1:
		return subscriptFetch(r, end, lits, end, leaf)
	case rest[0] == "__dict__" && len(rest) == 2 && rest[1] == "get":
		p := skipAllSpace(r, end)
		if p >= len(r) || r[p] != '(' {
			return "", end, false
		}
		attr, ok := literalSubscript(r, p+1, lits, "),")
		if !ok {
			return "", end, false
		}
		return leaf(attr, callClose(r, p))
	default:
		return "", end, !fetchDunders[rest[0]]
	}
	j := i - 1
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	k := skipAllSpace(r, end)
	if k < len(r) && r[k] == '(' && !strings.ContainsRune(string(r[end:k]), '\n') {
		// A module is not callable: the name is bound to something else here. A '(' on a
		// later line may open the next statement instead.
		return "", end, true
	}
	if presenceTest(r, i, end, k) {
		return "", end, true
	}
	if j < 0 || r[j] != '(' || k >= len(r) {
		return "", end, false
	}
	switch {
	case precededByWord(r, j, "getattr") && r[k] == ',':
		attr, ok := literalSubscript(r, k+1, lits, "),")
		if !ok {
			return "", end, false
		}
		return leaf(attr, callClose(r, j))
	case precededByWord(r, j, "vars") && r[k] == ')':
		return subscriptFetch(r, k+1, lits, end, leaf)
	case precededByWord(r, j, "hasattr") && r[k] == ',', precededByWord(r, j, "type") && r[k] == ')':
		return "", end, true
	case (precededByWord(r, j, "setattr") || precededByWord(r, j, "delattr") || patchObject(r, j)) && r[k] == ',':
		// A store or delete (monkeypatch.setattr(uvicorn, "run", spy), mock.patch.object(uvicorn,
		// "run")) hands no loader over.
		return "", end, true
	}
	return "", end, false
}

// presenceTest reports whether the name at r[i], ending at r[end] and followed by r[k], is
// only tested for presence, as an optional import is (if uvicorn is None:, if not werkzeug,
// HAS = uvicorn is not None). It must be a whole operand: in reg + uvicorn == 0 or not
// uvicorn in reg the module is handed to another object's operator, and so it is in
// uvicorn == reg, through reg's reflected __eq__, and as an and/or operand.
func presenceTest(r []rune, i, end, k int) bool {
	next, wend := readWordRunes(r, k)
	op := string(r[k:min(k+2, len(r))])
	switch {
	case next == "is" && operandStart(r, i):
		p := skipAllSpace(r, wend)
		if w, e := readWordRunes(r, p); w == "not" {
			p = skipAllSpace(r, e)
		}
		return noneAt(r, p)
	case (op == "==" || op == "!=") && operandStart(r, i):
		return noneAt(r, skipAllSpace(r, k+2))
	case precededByWord(r, i, "not") && operandEnd(r, k):
		return true
	case precededByWord(r, i, "if") && (next == "else" || op != "" && op[0] == ':'),
		(precededByWord(r, i, "elif") || precededByWord(r, i, "while")) && op != "" && op[0] == ':':
		return true
	}
	return false
}

// noneAt reports whether the word at r[p] is None.
func noneAt(r []rune, p int) bool {
	w, _ := readWordRunes(r, p)
	return w == "None"
}

// operandStart reports whether nothing that binds tighter than a comparison precedes r[i].
// A newline is not a boundary: inside brackets the expression runs on.
func operandStart(r []rune, i int) bool {
	j := i - 1
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	switch {
	case j >= 0 && strings.ContainsRune("([,:", r[j]):
		return true
	case j >= 0 && r[j] == '=':
		return j == 0 || !strings.ContainsRune("=!<>", r[j-1])
	}
	for _, w := range []string{"if", "elif", "while", "and", "or", "not", "return", "assert", "else"} {
		if precededByWord(r, i, w) {
			return true
		}
	}
	return false
}

// operandEnd reports whether r[k], the next non-space rune after an operand, starts nothing
// that binds tighter than not. A newline is not a boundary: inside brackets the expression
// runs on.
func operandEnd(r []rune, k int) bool {
	if k >= len(r) || strings.ContainsRune(":),]};", r[k]) {
		return true
	}
	w, _ := readWordRunes(r, k)
	return w == "and" || w == "or" || w == "if" || w == "else"
}

// patchObject reports whether the '(' at r[j] opens a patch.object call.
func patchObject(r []rune, j int) bool {
	if !precededByWord(r, j, "object") {
		return false
	}
	q := j - 1
	for q >= 0 && unicode.IsSpace(r[q]) {
		q--
	}
	for q >= 0 && isIdentPart(r[q]) {
		q--
	}
	return q >= 0 && r[q] == '.' && precededByWord(r, q, "patch")
}

// subscriptFetch reads the namespace mapping ending at r[p] (vars(m), m.__dict__): a literal
// subscript or .get key is handed to leaf, and any other use may fetch any attribute.
func subscriptFetch(r []rune, p int, lits map[int]strLiteral, end int, leaf func(string, int) (string, int, bool)) (string, int, bool) {
	p = skipAllSpace(r, p)
	switch {
	case p < len(r) && r[p] == '[':
		if attr, close, ok := literalCloser(r, p+1, lits, "]"); ok {
			return leaf(attr, close+1)
		}
	case p < len(r) && r[p] == '.':
		w, wend := readWordRunes(r, skipAllSpace(r, p+1))
		q := skipAllSpace(r, wend)
		if w == "get" && q < len(r) && r[q] == '(' {
			if attr, ok := literalSubscript(r, q+1, lits, "),"); ok {
				return leaf(attr, callClose(r, q))
			}
		}
	}
	return "", end, false
}

// callClose returns the index just past the ')' that closes the call whose '(' is r[open].
func callClose(r []rune, open int) int {
	spans := callArgSpans(r, open)
	return min(spans[len(spans)-1][1]+1, len(r))
}

// stringLoaderKind reports whether the dotted call segs is a string loader: its head
// resolved through the file's import targets names a stringLoaders entry, returned as
// name, or its trailing attributes are a stringLoaderMethods chain on some receiver (name
// empty). qualified says segs follow a '.' (a call or subscript receiver), so the head is
// an attribute, not a name to resolve.
func stringLoaderKind(segs []string, qualified bool, targets map[string][]string) (kind stringLoaderArg, name string, ok bool) {
	k := len(segs)
	if k >= 2 && segs[k-2] == "config" && stringLoaderMethods["config."+segs[k-1]] && (k >= 3 || qualified) ||
		stringLoaderMethods[segs[k-1]] && (k >= 2 || qualified) {
		return loaderNameOrObject, "", true
	}
	if qualified {
		return 0, "", false
	}
	rest := strings.Join(segs[1:], ".")
	for _, t := range targets[segs[0]] {
		full := t
		if rest != "" {
			full += "." + rest
		}
		if kind, ok := stringLoaders[full]; ok {
			return kind, full, true
		}
	}
	return 0, "", false
}

// loaderNameArg returns the span of a loader call's name argument, given the index of its
// '(': a loaderKeywords keyword argument, or the loader's own keyword when own is not
// empty, anywhere, else the first positional one. The span is empty when the call passes
// neither; known is false when an unpacking (*args, **kw) may pass it.
func loaderNameArg(r []rune, open int, own string) (arg [2]int, known bool) {
	var positional [2]int
	found, unpacked := false, false
	for _, sp := range callArgSpans(r, open) {
		s := skipAllSpace(r, sp[0])
		switch {
		case s >= sp[1]:
		case r[s] == '*':
			unpacked = true
		case isIdentStartRune(r[s]) && assignedTo(r, wordEnd(r, s)):
			if w, end := readWordRunes(r, s); loaderKeywords[w] || own != "" && w == own {
				return [2]int{skipAllSpace(r, end) + 1, sp[1]}, true
			}
		case !found && !unpacked:
			positional, found = [2]int{s, sp[1]}, true
		}
	}
	return positional, found || !unpacked
}

// wordEnd returns the index just past the identifier starting at r[i].
func wordEnd(r []rune, i int) int {
	_, end := readWordRunes(r, i)
	return end
}

// callArgSpans splits the arguments of the call whose '(' is at r[open] at its top-level
// commas, up to the matching ')' (or the end of the source).
func callArgSpans(r []rune, open int) [][2]int {
	var spans [][2]int
	depth, start := 0, open+1
	for j := open + 1; j < len(r); j++ {
		switch r[j] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return append(spans, [2]int{start, j})
			}
			depth--
		case ',':
			if depth == 0 {
				spans = append(spans, [2]int{start, j})
				start = j + 1
			}
		}
	}
	return append(spans, [2]int{start, len(r)})
}

// loaderArgClass is what a loader's name argument may evaluate to.
type loaderArgClass struct {
	roots    []string // modules its literal names import
	computed bool     // it may be a string the scanner cannot read
	other    bool     // it may be any value: a name, a call, an object
}

// classifyLoaderArg classifies the argument expression r[s:e]. Each branch of a conditional
// ("pkg.asgi:app" if prod else app) is classified on its own; a parenthesised expression
// is classified by its contents.
func classifyLoaderArg(r []rune, s, e int, lits map[int]strLiteral) loaderArgClass {
	s = skipAllSpace(r, s)
	for e > s && unicode.IsSpace(r[e-1]) {
		e--
	}
	if s < e && r[s] == '(' && closingBracket(r, s) == e-1 {
		return classifyLoaderArg(r, s+1, e-1, lits)
	}
	if s >= e {
		return loaderArgClass{other: true}
	}
	if ifAt, elseAt, ok := conditionalSplit(r, s, e, lits); ok {
		return classifyLoaderArg(r, s, ifAt, lits).or(classifyLoaderArg(r, elseAt+len("else"), e, lits))
	}
	// Either operand of a boolean operator may be the value (path or "pkg.asgi:app").
	for _, op := range []string{"or", "and"} {
		if at := topLevelKeyword(r, s, e, op, lits); at >= 0 {
			return classifyLoaderArg(r, s, at, lits).or(classifyLoaderArg(r, at+len(op), e, lits))
		}
	}
	if body, ok := wholeLiteral(r, s, e, lits); ok {
		return loaderArgClass{roots: loaderNameRoots(body)}
	}
	if provablyString(r, s, lits) {
		return loaderArgClass{computed: true}
	}
	return loaderArgClass{other: true}
}

// or combines the classes of two expressions the argument may evaluate to either of.
func (c loaderArgClass) or(d loaderArgClass) loaderArgClass {
	return loaderArgClass{roots: append(c.roots, d.roots...), computed: c.computed || d.computed, other: c.other || d.other}
}

// closingBracket returns the index of the bracket closing the one at r[i], or -1.
func closingBracket(r []rune, i int) int {
	depth := 0
	for j := i; j < len(r); j++ {
		switch r[j] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// conditionalSplit finds the top-level if and else keywords of a conditional expression
// in r[s:e].
func conditionalSplit(r []rune, s, e int, lits map[int]strLiteral) (ifAt, elseAt int, ok bool) {
	ifAt = topLevelKeyword(r, s, e, "if", lits)
	if ifAt < 0 {
		return 0, 0, false
	}
	elseAt = topLevelKeyword(r, ifAt+len("if"), e, "else", lits)
	return ifAt, elseAt, elseAt >= 0
}

// topLevelKeyword returns the index of the first keyword kw outside brackets in r[s:e], or
// -1. A blanked literal right after it ('_' in else'pkg') does not extend the word.
func topLevelKeyword(r []rune, s, e int, kw string, lits map[int]strLiteral) int {
	depth := 0
	for j := s; j < e; j++ {
		switch c := r[j]; {
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case isIdentStartRune(c) && (j == s || !isIdentPart(r[j-1])):
			end := j + 1
			for end < e && isIdentPart(r[end]) {
				if _, lit := lits[end]; lit {
					break
				}
				end++
			}
			if depth == 0 && string(r[j:end]) == kw {
				return j
			}
			j = end - 1
		}
	}
	return -1
}

// typePosition reports whether the expression starting at r[i] is a type, not a value: a
// return annotation (-> T), a parameter or annotated-assignment annotation (x: T), a type
// subscript (Optional[T]), or an isinstance, issubclass or cast argument, directly or in a
// tuple. Any other position, a class base among them, is a value.
func typePosition(r []rune, i int) bool {
	p := i - 1
	for p >= 0 && unicode.IsSpace(r[p]) {
		p--
	}
	if p >= 1 && r[p] == '>' && r[p-1] == '-' {
		return true
	}
	open := enclosingOpen(r, i)
	if p >= 0 && r[p] == ':' {
		// The annotated name starts its statement, or is a def parameter.
		q := p - 1
		for q >= 0 && (r[q] == ' ' || r[q] == '\t') {
			q--
		}
		e := q + 1
		for q >= 0 && isIdentPart(r[q]) {
			q--
		}
		if q+1 == e {
			return false
		}
		if open < 0 {
			for q >= 0 && (r[q] == ' ' || r[q] == '\t') {
				q--
			}
			return q < 0 || r[q] == '\n' || r[q] == ';'
		}
		// A parameter follows '(', ',' or '*'; a lambda's parameters do not open a def's.
		for q >= 0 && unicode.IsSpace(r[q]) {
			q--
		}
		return r[open] == '(' && isDefParams(r, open) && q >= 0 && strings.ContainsRune("(,*", r[q])
	}
	for open >= 0 {
		w, before := wordBefore(r, open)
		switch {
		case r[open] == '[':
			return w != "" && !pyCallKeywords[w] || w == "" && before >= 0 && r[before] == ']'
		case r[open] != '(':
			return false
		case w == "isinstance" || w == "issubclass" || w == "cast":
			return true
		case w == "" && before >= 0 && (r[before] == ',' || r[before] == '('):
			open = enclosingOpen(r, open) // a tuple argument
		default:
			return false
		}
	}
	return false
}

// enclosingOpen returns the index of the innermost unclosed bracket before r[i], or -1.
func enclosingOpen(r []rune, i int) int {
	depth := 0
	for j := i - 1; j >= 0; j-- {
		switch r[j] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				return j
			}
			depth--
		}
	}
	return -1
}

// wordBefore returns the identifier ending just before r[open] (spaces skipped), and the
// index of the last non-space rune before that word, or -1.
func wordBefore(r []rune, open int) (string, int) {
	j := open - 1
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	end := j + 1
	for j >= 0 && isIdentPart(r[j]) {
		j--
	}
	w := string(r[j+1 : end])
	if w != "" {
		for j >= 0 && unicode.IsSpace(r[j]) {
			j--
		}
	}
	return w, j
}

// isDefParams reports whether the '(' at r[open] opens a def's parameter list.
func isDefParams(r []rune, open int) bool {
	j := open
	for j > 0 && unicode.IsSpace(r[j-1]) {
		j--
	}
	k := j
	for k > 0 && isIdentPart(r[k-1]) {
		k--
	}
	return k < j && precededByDef(r, k)
}

// definesName reports whether the file defines a module-level function or class named
// name, which shadows a star import's binding of it. A method or nested definition does not.
func definesName(r []rune, name string) bool {
	for i := 0; i < len(r); {
		if i > 0 && r[i-1] != '\n' {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		if w == "async" {
			w, end = readWordRunes(r, skipAllSpace(r, end))
		}
		if w == "def" || w == "class" {
			if n, _ := readWordRunes(r, skipAllSpace(r, end)); n == name {
				return true
			}
		}
		i = max(end, i+1)
	}
	return false
}

// wholeLiteral returns the value of r[s:e] when it is one plain string literal
// (optionally r/b/u-prefixed).
func wholeLiteral(r []rune, s, e int, lits map[int]strLiteral) (string, bool) {
	i := s
	for i < e && i-s < 2 && strings.ContainsRune("rRbBuU", r[i]) {
		i++
	}
	lit, ok := lits[i]
	if !ok || skipAllSpace(r, lit.end) < e {
		return "", false
	}
	return lit.body, true
}

// provablyString reports whether the call argument starting at r[i] is a string even
// though it is not a plain literal: it opens with a string literal (an f-string, a
// concatenation, a %-format, a .format call) or reads the environment (os.environ[...],
// os.environ.get(...), os.getenv(...)).
func provablyString(r []rune, i int, lits map[int]strLiteral) bool {
	i = skipAllSpace(r, i)
	for j := i; j < len(r) && j-i < 2 && strings.ContainsRune("rRbBuUfFtT", r[j]); j++ {
		if _, ok := lits[j+1]; ok {
			return true
		}
	}
	if _, ok := lits[i]; ok {
		return true
	}
	var segs []string
	end := i
	for end < len(r) && isIdentStartRune(r[end]) {
		var w string
		w, end = readWordRunes(r, end)
		segs = append(segs, w)
		if end+1 < len(r) && r[end] == '.' && isIdentStartRune(r[end+1]) {
			end++
			continue
		}
		break
	}
	chain := strings.TrimPrefix(strings.Join(segs, "."), "os.")
	p := skipAllSpace(r, end)
	switch chain {
	case "environ":
		return p < len(r) && r[p] == '['
	case "environ.get", "getenv":
		return p < len(r) && r[p] == '('
	}
	return false
}

// loaderNameRoots returns the modules a loader's dotted name may import: the part before a
// ':' ("pkg.mod:attr"), or else the name and, since its last part may be an attribute, its
// parent ("pkg.mod.Class").
func loaderNameRoots(name string) []string {
	if mod, _, ok := strings.Cut(name, ":"); ok {
		if mod == "" {
			return nil
		}
		return []string{mod}
	}
	if k := strings.LastIndexByte(name, '.'); k > 0 {
		return []string{name, name[:k]}
	}
	if name == "" {
		return nil
	}
	return []string{name}
}

// cutLast slices s around the last instance of sep.
func cutLast(s, sep string) (before, after string, found bool) {
	if k := strings.LastIndex(s, sep); k >= 0 {
		return s[:k], s[k+len(sep):], true
	}
	return s, "", false
}

// lookupKind classifies a name moduleLookups watches.
type lookupKind int

const (
	lookupNone      lookupKind = iota
	lookupImport               // importlib.import_module or a name bound to it
	lookupDunder               // __import__ or a name bound to it
	lookupSys                  // the sys module
	lookupModules              // sys.modules
	lookupNamespace            // importlib or builtins, whose attributes include the above
	lookupLoader               // a dynamicImportOpaqueLeafs loader or a name bound to one
	lookupNamer                // builtins.globals, vars or locals bound under another name
)

// moduleLookups scans one file's cleaned source for the ways code fetches a module object
// by name: importlib.import_module and __import__ calls and sys.modules lookups. It reads
// an allow-list of literal forms only: a call whose first argument is a string literal, a
// sys.modules subscript or .get whose key is a string literal or __name__ (the file's own
// module, which the computed-name rule covers), and a sys.modules membership test, store
// or delete, which hand no module over. Every other reference to these names is opaque: a
// computed key or argument, iteration, .values() and the like, the name passed or assigned
// as a value, or a dunder attribute of sys or importlib. Any use of a loader that takes no
// module name (dynamicImportOpaqueLeafs: file-path specs, runpy, imp, zipimport, a
// module's __loader__, package walks, entry points) is opaque as well.
//
// A name counts by what the file's import bindings bind it to, in any scope: "import sys as
// s" (or "from os import sys as s") makes s the sys module, "from sys import modules"
// makes modules sys.modules, "from
// importlib import import_module as load" makes load import_module, "from runpy import
// run_path as rp" makes rp a loader. The words sys, importlib, import_module, __import__
// and the loader names always count, since the scanner cannot tell what else they are
// bound to. It returns the literal module names called for (load roots), the
// module names whose objects the code receives (an __import__ call receives each package
// on the way down), whether any reference is opaque, and whether the file reaches names by
// computed access through these modules: a sys.modules use other than a literal key naming
// another module (the file's own module by __name__ or by its literal name, a membership
// test, a store or a delete), or globals, vars or locals reached through builtins or
// __builtins__.
// lookupTarget reads an import binding's target from its last sys, importlib or builtins
// segment on, so "from os import sys" binds the sys module and "from os.sys import modules"
// binds sys.modules: what another module re-exports under those names is that module.
func lookupTarget(target string) string {
	segs := strings.Split(target, ".")
	for i := len(segs) - 1; i >= 0; i-- {
		switch segs[i] {
		case "sys", "importlib", "builtins":
			return strings.Join(segs[i:], ".")
		}
	}
	return target
}

func moduleLookups(clean string, lits map[int]strLiteral, bindings []scopedBinding) (roots, values []string, opaque, computed bool) {
	r := []rune(clean)
	n := len(r)
	spans, stars := importStatements(r)
	names := map[string]lookupKind{}
	for _, b := range bindings {
		switch lookupTarget(b.target) {
		case "sys":
			names[b.local] = lookupSys
		case "sys.modules":
			names[b.local] = lookupModules
		case "importlib", "builtins":
			names[b.local] = lookupNamespace
		case "importlib.import_module":
			names[b.local] = lookupImport
		case "importlib.__import__", "builtins.__import__":
			names[b.local] = lookupDunder
		case "builtins.globals", "builtins.vars", "builtins.locals":
			names[b.local] = lookupNamer
		default:
			if dynamicImportOpaqueLeafs[b.target[strings.LastIndex(b.target, ".")+1:]] {
				names[b.local] = lookupLoader
			}
		}
	}
	if stars["sys"] {
		names["modules"] = lookupModules
	}
	kindOf := func(w string, dotted bool) lookupKind {
		switch w {
		case "import_module":
			return lookupImport
		case "__import__":
			return lookupDunder
		case "sys":
			return lookupSys
		case "importlib", "builtins", "__builtins__":
			return lookupNamespace
		}
		if dynamicImportOpaqueLeafs[w] {
			return lookupLoader
		}
		if dotted {
			return lookupNone
		}
		return names[w]
	}
	si := 0
	for i := 0; i < n; {
		if si < len(spans) && i >= spans[si][0] {
			i = max(i, spans[si][1])
			si++
			continue
		}
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		dotted := i > 0 && r[i-1] == '.'
		kind := kindOf(w, dotted)
		if kind == lookupNone || precededByDef(r, i) || assignedTo(r, end) {
			i = end
			continue
		}
		switch kind {
		case lookupImport, lookupDunder:
			name, ok := importCallTarget(r, end, lits, kind == lookupDunder)
			switch {
			case !ok:
				opaque = true
			case kind == lookupDunder:
				roots = append(roots, name)
				for k := range strings.Split(name, ".") {
					values = append(values, strings.Join(strings.Split(name, ".")[:k+1], "."))
				}
			default:
				roots = append(roots, name)
				values = append(values, name)
			}
			// The module object it returns reaches every name through sys.modules or
			// builtins.globals, wherever the value goes next.
			if ok && (name == "sys" || name == "builtins") {
				computed = true
			}
		case lookupSys, lookupNamespace:
			attr, aend, ok := attributeAfter(r, end)
			switch {
			case !ok:
				opaque = opaque || !inspectedOnly(r, i, end, lits)
			case strings.HasPrefix(attr, "__") && !plainDunders[attr]:
				opaque = true
			case kind == lookupNamespace && namerAttrs[attr]:
				computed = true
			case kind == lookupSys && attr == "modules":
				name, ok := modulesUse(r, i, aend, lits)
				switch {
				case !ok:
					opaque = true
				case name == "":
					computed = true
				default:
					values = append(values, name)
				}
				end = aend
			}
		case lookupLoader:
			opaque = true
		case lookupNamer:
			computed = true
		case lookupModules:
			name, ok := modulesUse(r, i, end, lits)
			switch {
			case !ok:
				opaque = true
			case name == "":
				computed = true
			default:
				values = append(values, name)
			}
		}
		i = end
	}
	return sortedDedup(roots), sortedDedup(values), opaque, computed
}

// namerAttrs are the builtins that reach a namespace's names by computed access.
var namerAttrs = map[string]bool{"globals": true, "vars": true, "locals": true}

// plainDunders are the dunder attributes of sys and importlib that hold an ordinary value
// (the original streams and hooks) or that moduleLookups reads itself (__import__); any
// other dunder (__dict__, __getattribute__) can fetch an attribute by computed name.
var plainDunders = map[string]bool{
	"__import__": true, "__name__": true, "__doc__": true,
	"__stdin__": true, "__stdout__": true, "__stderr__": true,
	"__displayhook__": true, "__excepthook__": true, "__breakpointhook__": true,
	"__unraisablehook__": true, "__interactivehook__": true,
}

// lookupAttrs are the attributes through which sys, importlib or builtins hand over a module
// or a module importer.
var lookupAttrs = map[string]bool{"modules": true, "import_module": true, "__import__": true, "__dict__": true}

// inspectedOnly reports whether the module name running from r[start] to r[end] is the first
// argument of a call that only inspects it: hasattr(sys, ...), type(sys), or getattr(sys,
// "attr") with a literal attribute that is not a lookup attribute.
func inspectedOnly(r []rune, start, end int, lits map[int]strLiteral) bool {
	j := start - 1
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	if j < 0 || r[j] != '(' {
		return false
	}
	k := skipAllSpace(r, end)
	switch {
	case precededByWord(r, j, "hasattr"):
		return k < len(r) && r[k] == ','
	case precededByWord(r, j, "type"):
		return k < len(r) && r[k] == ')'
	case precededByWord(r, j, "getattr"):
		if k >= len(r) || r[k] != ',' {
			return false
		}
		attr, ok := literalSubscript(r, k+1, lits, "),")
		return ok && !lookupAttrs[attr]
	}
	return false
}

// importStatements finds the import statements in a cleaned source as rune spans, so the
// names they bind are not read as uses, and the modules a star import ("from sys import
// *") pours into the file's namespace.
func importStatements(r []rune) (spans [][2]int, stars map[string]bool) {
	stars = map[string]bool{}
	for i := 0; i < len(r); {
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		if (w != "import" && w != "from") || !statementStart(r, i) {
			i = end
			continue
		}
		stop := statementEnd(r, end)
		spans = append(spans, [2]int{i, stop})
		if w == "from" {
			fields := strings.Fields(string(r[end:stop]))
			if len(fields) >= 3 && fields[1] == "import" && strings.Trim(fields[2], "()") == "*" {
				stars[fields[0]] = true
			}
		}
		i = stop
	}
	return spans, stars
}

// statementStart reports whether the word at r[i] begins a statement: only spaces lie
// between it and the start of the source, a newline, a ';', or a ':' that opens a block on
// the same line.
func statementStart(r []rune, i int) bool {
	j := i - 1
	for j >= 0 && (r[j] == ' ' || r[j] == '\t') {
		j--
	}
	return j < 0 || r[j] == '\n' || r[j] == ';' || r[j] == ':'
}

// statementEnd is the index of the ';' or newline that ends the statement running from
// r[i], outside brackets and not after a line-continuation backslash.
func statementEnd(r []rune, i int) int {
	depth := 0
	for ; i < len(r); i++ {
		switch r[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ';':
			if depth <= 0 {
				return i
			}
		case '\n':
			if depth <= 0 && (i == 0 || r[i-1] != '\\') {
				return i
			}
		}
	}
	return len(r)
}

// assignedTo reports whether the word ending at r[end] is the target of a plain assignment
// or a keyword argument ("sys = ...", "f(sys=...)"): it binds the name rather than using it.
func assignedTo(r []rune, end int) bool {
	k := skipAllSpace(r, end)
	return k+1 < len(r) && r[k] == '=' && r[k+1] != '='
}

// attributeAfter reads the attribute name after the word ending at r[end] ("sys.path" →
// "path"), reporting false when the word is not followed by an attribute access.
func attributeAfter(r []rune, end int) (string, int, bool) {
	k := skipAllSpace(r, end)
	if k >= len(r) || r[k] != '.' {
		return "", end, false
	}
	a, aend := readWordRunes(r, skipAllSpace(r, k+1))
	return a, aend, a != ""
}

// modulesUse reads one use of sys.modules, whose name runs from r[start] to r[end]. A
// literal subscript or .get names a module; a subscript or .get of __name__, a membership
// test, a store and a delete hand no other module over. Anything else is not allow-listed.
func modulesUse(r []rune, start, end int, lits map[int]strLiteral) (string, bool) {
	n := len(r)
	p := skipAllSpace(r, end)
	switch {
	case p < n && r[p] == '[':
		if name, ok := literalSubscript(r, p+1, lits, "]"); ok {
			return name, true
		}
		if ownModuleArg(r, p+1, "]") {
			return "", true
		}
		closeAt := matchingClose(r, p)
		if closeAt < 0 {
			return "", false
		}
		return "", assignedTo(r, closeAt+1) || precededByWord(r, start, "del")
	case p < n && r[p] == '.':
		g, e := readWordRunes(r, skipAllSpace(r, p+1))
		q := skipAllSpace(r, e)
		if g != "get" || q >= n || r[q] != '(' {
			return "", false
		}
		if name, ok := literalSubscript(r, q+1, lits, "),"); ok {
			return name, true
		}
		return "", ownModuleArg(r, q+1, "),")
	}
	return "", precededByWord(r, start, "in")
}

// importCallTarget reads the module an import_module or __import__ call (the name ending at
// r[end]) imports, reporting false unless the name is called with a string-literal module.
// A relative import_module name resolves against a literal package argument, or stays
// relative to the file for __package__. An __import__ call that passes a level is not read.
func importCallTarget(r []rune, end int, lits map[int]strLiteral, dunder bool) (string, bool) {
	open := skipAllSpace(r, end)
	if open >= len(r) || r[open] != '(' {
		return "", false
	}
	args, ok := callArgs(r, open)
	if !ok || len(args) == 0 {
		return "", false
	}
	name, ok := literalSpan(r, args[0], lits)
	if !ok {
		return "", false
	}
	if dunder {
		for k, a := range args {
			if w, _ := readWordRunes(r, skipAllSpace(r, a[0])); k >= 4 || (w == "level" && assignedTo(r, skipAllSpace(r, a[0])+len("level"))) {
				return "", false
			}
		}
		return name, !strings.HasPrefix(name, ".")
	}
	if !strings.HasPrefix(name, ".") {
		return name, true
	}
	var pkg [2]int
	switch {
	case len(args) >= 2:
		pkg = args[1]
		if s := skipAllSpace(r, pkg[0]); strings.HasPrefix(string(r[s:pkg[1]]), "package") {
			if e := s + len("package"); assignedTo(r, e) {
				pkg[0] = skipAllSpace(r, e) + 1
			}
		}
	default:
		return "", false
	}
	if w, e := readWordRunes(r, skipAllSpace(r, pkg[0])); w == "__package__" && skipAllSpace(r, e) == pkg[1] {
		return name, true
	}
	base, ok := literalSpan(r, pkg, lits)
	if !ok {
		return "", false
	}
	return resolveRelativeName(name, base)
}

// resolveRelativeName resolves a relative module name (".m", "..m") against a package.
func resolveRelativeName(name, pkg string) (string, bool) {
	rest := strings.TrimLeft(name, ".")
	up := len(name) - len(rest) - 1
	segs := strings.Split(pkg, ".")
	if pkg == "" || up >= len(segs) {
		return "", false
	}
	base := strings.Join(segs[:len(segs)-up], ".")
	if rest == "" {
		return base, true
	}
	return base + "." + rest, true
}

// callArgs splits the arguments of the call whose '(' is at r[open] into rune spans at
// bracket depth zero, reporting false when the call is not closed.
func callArgs(r []rune, open int) ([][2]int, bool) {
	var out [][2]int
	depth, from := 0, open+1
	for i := open + 1; i < len(r); i++ {
		switch r[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				if skipAllSpace(r, from) < i {
					out = append(out, [2]int{from, i})
				}
				return out, true
			}
			depth--
		case ',':
			if depth == 0 {
				out = append(out, [2]int{from, i})
				from = i + 1
			}
		}
	}
	return nil, false
}

// literalSpan reports the value of a string literal (optionally r/b/u-prefixed) that forms
// the whole of the span.
func literalSpan(r []rune, span [2]int, lits map[int]strLiteral) (string, bool) {
	i := skipAllSpace(r, span[0])
	if i < span[1] && r[i] != '_' {
		j := i
		for j < span[1] && j-i < 2 && strings.ContainsRune("rRbBuU", r[j]) {
			j++
		}
		i = j
	}
	lit, ok := lits[i]
	if !ok || skipAllSpace(r, lit.end) != span[1] {
		return "", false
	}
	return lit.body, true
}

// precededByWord reports whether the word before r[i], across whitespace, is w.
func precededByWord(r []rune, i int, w string) bool {
	j := i - 1
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	end := j + 1
	for j >= 0 && isIdentPart(r[j]) {
		j--
	}
	return string(r[j+1:end]) == w
}

// ownModuleArg reports whether the argument at r[i] is exactly __name__, closed by one of
// closers.
func ownModuleArg(r []rune, i int, closers string) bool {
	w, e := readWordRunes(r, skipAllSpace(r, i))
	e = skipAllSpace(r, e)
	return w == "__name__" && e < len(r) && strings.ContainsRune(closers, r[e])
}

// literalSubscript is literalArg for a subscript or call argument closed by one of closers.
func literalSubscript(r []rune, i int, lits map[int]strLiteral, closers string) (string, bool) {
	body, _, ok := literalCloser(r, i, lits, closers)
	return body, ok
}

// literalCloser is literalSubscript that also returns the index of the closer.
func literalCloser(r []rune, i int, lits map[int]strLiteral, closers string) (string, int, bool) {
	i = skipAllSpace(r, i)
	if i < len(r) && r[i] != '_' {
		j := i
		for j < len(r) && j-i < 2 && strings.ContainsRune("rRbBuU", r[j]) {
			j++
		}
		i = j
	}
	lit, ok := lits[i]
	if !ok {
		return "", 0, false
	}
	k := skipAllSpace(r, lit.end)
	if k >= len(r) || !strings.ContainsRune(closers, r[k]) {
		return "", 0, false
	}
	return lit.body, k, true
}

// precededByDef reports whether the identifier at r[i] is the name in a def statement.
func precededByDef(r []rune, i int) bool {
	j := i - 1
	for j >= 0 && unicode.IsSpace(r[j]) {
		j--
	}
	end := j + 1
	for j >= 0 && isIdentPart(r[j]) {
		j--
	}
	return string(r[j+1:end]) == "def"
}

// skipAllSpace returns the first index at or after i that is not whitespace (newlines
// included: the cleaned source is not joined into logical lines here).
func skipAllSpace(r []rune, i int) int {
	for i < len(r) && unicode.IsSpace(r[i]) {
		i++
	}
	return i
}

// literalArg reads the first call argument starting at r[i] and returns its value when it
// is a plain string literal (optionally r/b/u-prefixed) that forms the whole argument. An
// f-string, a concatenation, a name, or any other expression is not literal.
func literalArg(r []rune, i int, lits map[int]strLiteral) (string, bool) {
	i = skipAllSpace(r, i)
	if i < len(r) && r[i] != '_' {
		j := i
		for j < len(r) && j-i < 2 && strings.ContainsRune("rRbBuU", r[j]) {
			j++
		}
		i = j
	}
	lit, ok := lits[i]
	if !ok {
		return "", false
	}
	k := skipAllSpace(r, lit.end)
	if k >= len(r) || (r[k] != ',' && r[k] != ')') {
		return "", false
	}
	return lit.body, true
}

// dynamicImportReasons is the run-wide partiality a non-literal dynamic import forces: the
// lane cannot name the module, so it cannot bound what was loaded.
func dynamicImportReasons(opaque bool) []string {
	if opaque {
		return []string{plugin.PartialReasonDynamicImportSpecifier}
	}
	return nil
}
