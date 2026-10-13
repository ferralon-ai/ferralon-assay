package pythonanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"unicode"

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
// first-party names and star imports bind names the scanner cannot list, so neither yields
// a binding; the call graph's standing dynamic_dispatch partiality covers what they hide.
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
}

// distFor returns the distribution providing the top-level import name top.
func (d distResolver) distFor(top string) (string, bool) {
	if top == "" || d.firstParty[top] {
		return "", false
	}
	if dists := d.curated.Reverse(top); len(dists) == 1 {
		return dists[0], true
	} else if len(dists) > 1 {
		return "", false
	}
	if n := normalizePyCoordinate(top); d.declared[n] {
		return n, true
	}
	return "", false
}

// importTops returns the top-level import names distribution dist provides: its curated
// rows, else its own name read as an import name (the PEP 503 fallback distFor applies in
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
// declares. complete is false when a manifest fails to parse or a file declares
// dependencies version resolution does not read (the same surfaces that leave a version
// unresolved): a name only that file holds is missing, so an import of it reaches no
// boundary node, and the call graph's partiality has to say so.
func declaredDistributions(buildDir string) (names map[string]bool, complete bool) {
	names, complete = map[string]bool{}, true
	add := func(deps []plugin.ResolvedDependency) {
		for _, d := range deps {
			if n := normalizePyCoordinate(d.Coordinate); n != "" {
				names[n] = true
			}
		}
	}
	for _, f := range walkManifests(buildDir, isVersionCandidate) {
		if !isManifest(filepath.Base(f)) {
			if unreadSurfaceVetoes(f) {
				complete = false
			}
			continue
		}
		deps, _, ok := parseManifest(f)
		if !ok {
			complete = false
		}
		add(deps)
		if filepath.Base(f) == "pyproject.toml" {
			// The lexical [project] reader still yields names from a file TOML rejects.
			if data, err := os.ReadFile(f); err == nil {
				lexical, _ := parsePyproject(data)
				add(lexical)
			}
		}
	}
	return names, complete
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
// providing distribution. ok is false when the chain's first segment is not bound to a
// non-first-party import the resolver can map.
func boundaryTarget(chain, scopes []string, bindings map[string]map[string]scopedBinding, dists distResolver) (dist, dotted string, ok bool) {
	if len(chain) == 0 {
		return "", "", false
	}
	b, found := lookupBinding(chain[0], scopes, bindings)
	if !found {
		return "", "", false
	}
	target := b.target
	if b.inst != nil {
		// An instance of an imported class: resolve the instantiation chain once (no
		// recursion through further instance bindings).
		ib, ifound := lookupBinding(b.inst[0], scopes, bindings)
		if !ifound || ib.target == "" {
			return "", "", false
		}
		target = strings.Join(append([]string{ib.target}, b.inst[1:]...), ".")
	}
	top := target
	if i := strings.IndexByte(top, '.'); i >= 0 {
		top = top[:i]
	}
	dist, ok = dists.distFor(top)
	if !ok {
		return "", "", false
	}
	return dist, strings.Join(append([]string{target}, chain[1:]...), "."), true
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

// dynamicImportLiteralLeafs are callables that import the module their first argument
// names. A literal argument is a load root; anything else is an import the scanner cannot
// name.
var dynamicImportLiteralLeafs = map[string]bool{
	"import_module": true, // importlib.import_module
	"__import__":    true,
	"resolve_name":  true, // pkgutil.resolve_name("pkg.mod:attr")
}

// dynamicImportOpaqueLeafs load modules named only by installed metadata or the
// filesystem (entry-point groups, package walks), never by the calling code.
var dynamicImportOpaqueLeafs = map[string]bool{
	"entry_points":      true, // importlib.metadata.entry_points
	"iter_entry_points": true, // pkg_resources
	"load_entry_point":  true, // pkg_resources
	"walk_packages":     true, // pkgutil
}

// dynamicImports scans one file's cleaned source for dynamic imports. It returns the
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
