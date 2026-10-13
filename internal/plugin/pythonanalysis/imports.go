package pythonanalysis

import (
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
// declares. read is false when a manifest cannot be read: it may declare a distribution an
// import maps to.
func declaredDistributions(buildDir string) (out map[string]bool, read bool) {
	out, read = map[string]bool{}, true
	for _, m := range manifestFiles(buildDir) {
		data, err := readRegular(m)
		if err != nil {
			read = false
			continue
		}
		deps, _ := parseManifestData(m, data)
		for _, d := range deps {
			if n := normalizePyCoordinate(d.Coordinate); n != "" {
				out[n] = true
			}
		}
	}
	return out, read
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
// names. A literal argument is a load root; a literal dotted prefix followed by a computed
// tail is a site the load set scopes to a package; anything else is an import the scanner
// cannot name.
var dynamicImportLiteralLeafs = map[string]bool{
	"import_module": true, // importlib.import_module
	"__import__":    true,
	"resolve_name":  true, // pkgutil.resolve_name("pkg.mod:attr")
	"run_module":    true, // runpy.run_module("pkg.mod")
}

// dynamicImportOpaqueLeafs load modules named only by installed metadata or the
// filesystem (entry-point groups, package walks), never by the calling code.
var dynamicImportOpaqueLeafs = map[string]bool{
	"entry_points":      true, // importlib.metadata.entry_points
	"iter_entry_points": true, // pkg_resources
	"load_entry_point":  true, // pkg_resources
	"walk_packages":     true, // pkgutil
}

// dynamicFileLoaderLeafs load a module from a file path or a loader object, so the module
// (and the package that provides it) is never named by the calling code.
var dynamicFileLoaderLeafs = map[string]bool{
	"spec_from_file_location": true, // importlib.util
	"spec_from_loader":        true, // importlib.util
	"module_from_spec":        true, // importlib.util
	"exec_module":             true, // importlib loaders
	"load_module":             true, // importlib loaders, imp
	"load_source":             true, // imp
	"load_compiled":           true, // imp
	"load_dynamic":            true, // imp
	"load_package":            true, // imp
	"run_path":                true, // runpy
	"SourceFileLoader":        true, // importlib.machinery
	"SourcelessFileLoader":    true, // importlib.machinery
	"ExtensionFileLoader":     true, // importlib.machinery
	"zipimporter":             true, // zipimport
}

// codeExecLeafs run source text, which can import anything. Only a bare builtin counts:
// re.compile and friends carry a receiver.
var codeExecLeafs = map[string]bool{"exec": true, "eval": true, "compile": true, "execfile": true}

// dynSiteKind classifies a dynamic load the scanner can bound only with the load set: by a
// static dotted prefix, by the module a getattr reads from, or by a star import's source.
type dynSiteKind int

const (
	dynPrefix  dynSiteKind = iota // import_module("pkg.plugins." + n): the dotted prefix is static
	dynGetattr                    // getattr(mod, name) on an import-bound module, name not literal
	dynStar                       // from mod import *
)

// dynSite is one boundable dynamic load. module is the dotted prefix, the module getattr
// reads from, or the star import's source; a leading "." marks a first-party relative name.
type dynSite struct {
	kind   dynSiteKind
	module string
}

// dynScan is every dynamic load one file's source holds.
type dynScan struct {
	roots  []string  // literal module names; a relative name keeps its leading dots
	sites  []dynSite // loads the load set can scope to a package
	opaque []string  // loads nothing bounds, by the leaf that made them (sorted, deduped)
}

// scanDynamicLoads scans one file's cleaned source for dynamic loads. aliases maps a local
// name bound by an import to the loader leaf it aliases (`from importlib import
// import_module as im` → im: import_module); modTargets maps an import-bound local to the
// dotted paths it may name, for getattr. clean and lits come from stripPythonLiterals over
// the same source, so rune positions in clean index the literal table.
//
// A loader referenced without being called (passed or assigned as a value) is opaque: the
// call that uses it is out of sight. Mentions inside import statements are not uses.
func scanDynamicLoads(clean string, lits map[int]strLiteral, aliases map[string]string, modTargets map[string][]string) dynScan {
	r := []rune(clean)
	n := len(r)
	inImport := importStatementMask(r)
	var sc dynScan
	for i := 0; i < n; {
		if !isIdentStartRune(r[i]) || (i > 0 && isIdentPart(r[i-1])) {
			i++
			continue
		}
		w, end := readWordRunes(r, i)
		receiver := prevNonSpaceRune(r, i) == '.'
		leaf := w
		if a, ok := aliases[w]; ok && !receiver {
			leaf = a
		}
		literalLeaf := dynamicImportLiteralLeafs[leaf]
		opaqueLeaf := dynamicImportOpaqueLeafs[leaf] || dynamicFileLoaderLeafs[leaf]
		execLeaf := codeExecLeafs[leaf] && !receiver
		getattrLeaf := leaf == "getattr" && !receiver
		if (!literalLeaf && !opaqueLeaf && !execLeaf && !getattrLeaf) || inImport[i] || precededByDef(r, i) {
			i = end
			continue
		}
		open := skipAllSpace(r, end)
		if open >= n || r[open] != '(' {
			// A value reference: `loader = importlib.import_module`, `map(eval, xs)`. An
			// assignment target or keyword argument (`eval = ...`, `f(compile=True)`) is not.
			if !getattrLeaf && !(open < n && r[open] == '=' && (open+1 >= n || r[open+1] != '=')) {
				sc.opaque = append(sc.opaque, leaf)
			}
			i = end
			continue
		}
		switch {
		case opaqueLeaf || execLeaf:
			sc.opaque = append(sc.opaque, leaf)
		case getattrLeaf:
			sc.sites = append(sc.sites, getattrSites(r, open, lits, modTargets)...)
		default:
			root, site, ok := literalLoad(r, open, lits, leaf)
			switch {
			case !ok:
				sc.opaque = append(sc.opaque, leaf)
			case root != "":
				sc.roots = append(sc.roots, root)
			case site != "":
				sc.sites = append(sc.sites, dynSite{kind: dynPrefix, module: site})
			}
		}
		i = end
	}
	sc.roots = sortedDedup(sc.roots)
	sc.opaque = sortedDedup(sc.opaque)
	return sc
}

// literalLoad reads the module a literal-capable loader call at r[open] names. It returns
// the literal module (root), or the static dotted prefix of a computed one (site), or ok
// false when neither is static. A relative import_module(".x", package=...) resolves against
// a literal package; package=__package__/__name__ (or none) keeps it first-party relative.
func literalLoad(r []rune, open int, lits map[int]strLiteral, leaf string) (root, site string, ok bool) {
	if name, isLit := literalArg(r, open+1, lits); isLit {
		if name == "" {
			return "", "", true
		}
		if leaf == "resolve_name" {
			name, _, _ = strings.Cut(name, ":")
		}
		if strings.HasPrefix(name, ".") {
			abs, rok := resolveRelativeArg(r, open, lits, name)
			if !rok {
				return "", "", false
			}
			name = abs
		}
		return name, "", true
	}
	prefix, pok := staticPrefixArg(r, open+1, lits)
	if !pok {
		return "", "", false
	}
	if strings.HasPrefix(prefix, ".") {
		abs, rok := resolveRelativeArg(r, open, lits, prefix+".x")
		if !rok {
			return "", "", false
		}
		prefix = strings.TrimSuffix(abs, ".x")
		if prefix == "" {
			prefix = "."
		}
	}
	return "", prefix, true
}

// resolveRelativeArg resolves a relative module name against the call's package argument
// (second positional or package=). A literal package yields an absolute name; none, or
// __package__/__name__/__spec__.parent, keeps the name first-party relative; any other
// expression names an unknown package and fails.
func resolveRelativeArg(r []rune, open int, lits map[int]strLiteral, name string) (string, bool) {
	args := callArgs(r, open)
	var pkgArg []int
	for k, a := range args {
		if k == 0 {
			continue
		}
		text := strings.TrimSpace(string(r[a[0]:a[1]]))
		if rest, found := strings.CutPrefix(text, "package"); found && strings.HasPrefix(strings.TrimSpace(rest), "=") {
			eq := a[0] + strings.Index(string(r[a[0]:a[1]]), "=")
			pkgArg = []int{eq + 1, a[1]}
			break
		}
		if k == 1 && !strings.Contains(text, "=") {
			pkgArg = a
			break
		}
	}
	if pkgArg == nil {
		return name, true
	}
	text := strings.TrimSpace(string(r[pkgArg[0]:pkgArg[1]]))
	switch text {
	case "__package__", "__name__", "__spec__.parent":
		return name, true
	}
	pkg, isLit := literalArg(r, pkgArg[0], lits)
	if !isLit || !isDottedName(pkg) {
		return "", false
	}
	dots := len(name) - len(strings.TrimLeft(name, "."))
	segs := strings.Split(pkg, ".")
	if dots-1 >= len(segs) {
		return "", false
	}
	base := strings.Join(segs[:len(segs)-(dots-1)], ".")
	if rest := name[dots:]; rest != "" {
		return base + "." + rest, true
	}
	return base, true
}

// staticPrefixArg reads a first call argument that starts with a string literal and
// continues with a computed tail ("pkg.plugins." + n, f"pkg.plugins.{n}", "pkg.%s" % n,
// "pkg.{}".format(n)) and returns the dotted module prefix the literal fixes: the text
// before its last '.'. The prefix must name at least one whole segment (or be relative).
func staticPrefixArg(r []rune, i int, lits map[int]strLiteral) (string, bool) {
	i = skipAllSpace(r, i)
	fstring := false
	for j := 0; j < 2 && i < len(r) && strings.ContainsRune("rRbBuUfF", r[i]); j++ {
		if _, isLit := lits[i]; isLit {
			break
		}
		fstring = fstring || r[i] == 'f' || r[i] == 'F'
		i++
	}
	lit, ok := lits[i]
	if !ok {
		return "", false
	}
	body := lit.body
	k := skipAllSpace(r, lit.end)
	switch {
	case fstring:
		body, _, _ = strings.Cut(body, "{")
	case k < len(r) && r[k] == '+':
	case k < len(r) && r[k] == '%':
		body, _, _ = strings.Cut(body, "%")
	case k+7 <= len(r) && string(r[k:k+7]) == ".format":
		body, _, _ = strings.Cut(body, "{")
	default:
		return "", false
	}
	dot := strings.LastIndexByte(body, '.')
	if dot < 0 {
		return "", false
	}
	prefix := body[:dot]
	if lead := strings.TrimLeft(prefix, "."); lead != prefix {
		if lead == "" || isDottedName(lead) {
			return prefix, true
		}
		return "", false
	}
	if !isDottedName(prefix) {
		return "", false
	}
	return prefix, true
}

// getattrSites reads getattr(mod, name) at r[open]: when mod is an import-bound name and
// name is not a literal, every module the binding may name is a site (a module-level
// __getattr__ can import on attribute access).
func getattrSites(r []rune, open int, lits map[int]strLiteral, modTargets map[string][]string) []dynSite {
	args := callArgs(r, open)
	if len(args) < 2 {
		return nil
	}
	obj := strings.TrimSpace(string(r[args[0][0]:args[0][1]]))
	if !isDottedName(obj) {
		return nil
	}
	if _, isLit := literalArg(r, args[1][0], lits); isLit {
		return nil
	}
	head, rest, _ := strings.Cut(obj, ".")
	var out []dynSite
	for _, t := range modTargets[head] {
		if rest != "" {
			t += "." + rest
		}
		out = append(out, dynSite{kind: dynGetattr, module: t})
	}
	return out
}

// callArgs splits the call whose '(' is r[open] into its top-level arguments, as
// [start, end) rune ranges. An unclosed call yields what was read.
func callArgs(r []rune, open int) [][]int {
	var out [][]int
	depth := 0
	start := open + 1
	for i := open + 1; i < len(r); i++ {
		switch r[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				if strings.TrimSpace(string(r[start:i])) != "" {
					out = append(out, []int{start, i})
				}
				return out
			}
			depth--
		case ',':
			if depth == 0 {
				out = append(out, []int{start, i})
				start = i + 1
			}
		}
	}
	return out
}

// importStatementMask marks every rune of the cleaned source that belongs to an import
// statement (`import ...` / `from ... import ...`, continuations included).
func importStatementMask(r []rune) []bool {
	mask := make([]bool, len(r))
	inStmt, isImport := false, false
	depth := 0
	lineStart := 0
	for i := 0; i <= len(r); i++ {
		if i < len(r) && r[i] != '\n' {
			continue
		}
		line := string(r[lineStart:i])
		if !inStmt {
			kw, _ := firstWord(strings.TrimSpace(line))
			isImport = kw == "import" || kw == "from"
			depth = 0
		}
		depth += bracketDelta(line)
		cont := strings.HasSuffix(strings.TrimRight(line, " \t\r"), "\\")
		if isImport {
			for k := lineStart; k < i; k++ {
				mask[k] = true
			}
		}
		inStmt = depth > 0 || cont
		lineStart = i + 1
	}
	return mask
}

// prevNonSpaceRune returns the rune before r[i], skipping whitespace, or 0 at the start.
func prevNonSpaceRune(r []rune, i int) rune {
	for j := i - 1; j >= 0; j-- {
		if !unicode.IsSpace(r[j]) {
			return r[j]
		}
	}
	return 0
}

// dynamicLoadAliases returns the locals a file's import bindings alias to a loader leaf,
// and every import-bound local with the dotted paths it may name.
func dynamicLoadAliases(bs []scopedBinding) (aliases map[string]string, modTargets map[string][]string) {
	aliases = map[string]string{}
	modTargets = map[string][]string{}
	for _, b := range bs {
		if b.target == "" {
			continue
		}
		modTargets[b.local] = append(modTargets[b.local], b.target)
		leaf := b.target
		if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
			leaf = leaf[i+1:]
		}
		if leaf != b.local && (dynamicImportLiteralLeafs[leaf] || dynamicImportOpaqueLeafs[leaf] ||
			dynamicFileLoaderLeafs[leaf] || codeExecLeafs[leaf] || leaf == "getattr") {
			aliases[b.local] = leaf
		}
	}
	for k, v := range modTargets {
		modTargets[k] = sortedDedup(v)
	}
	return aliases, modTargets
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
