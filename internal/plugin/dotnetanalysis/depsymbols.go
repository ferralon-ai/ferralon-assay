package dotnetanalysis

// depsymbols.go — resolving a NuGet advisory's symbols inside the package's own restored
// assemblies. The advisory names code in the package (Newtonsoft.Json's
// JsonConvert.DeserializeObject); a first-party method that happens to share a leaf name is
// not that code, so for a dependency advisory nothing is matched against first-party source.
//
// The package's dlls come from the build's restore (project.assets.json → the NuGet package
// folder, the same locator the IL reachability tier loads its spanning set with), so every
// resolved symbol is a method of bytes this run read, and its SCIP is the id
// buildReconcileIndex keys that method by.

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/depreach"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// partialReasonNoDependencyArtifact: a dependency's implementation assembly is not on disk
// in the build's restore output (or only as a stub reference assembly), so its code was not
// read.
const partialReasonNoDependencyArtifact = plugin.PartialReasonToolFailure + ":no_dependency_artifact"

// partialReasonAdvisorySymbolUnresolved: the package's assemblies were read, but an advisory
// symbol named no method in them. Absence never refutes.
const partialReasonAdvisorySymbolUnresolved = plugin.PartialReasonAdvisorySymbolUnresolved

// partialReasonAdvisorySymbolAmbiguous: a shortened advisory symbol named methods of more
// than one qualified type in the package, so which one is vulnerable is unknown.
const partialReasonAdvisorySymbolAmbiguous = "advisory_symbol_ambiguous"

// methodAttrSpecialName marks property/event accessors (get_X, set_X, add_X, remove_X).
const methodAttrSpecialName = 0x0800

// resolveInDependency resolves wanted (verbatim advisory symbols) against the restored
// assemblies of NuGet package id (at version, when non-empty), in the restore target the
// first-party build binds to. Every limit is disclosed twice: as a scoped reason bounded by
// the package's restore closure, and as a run-wide reason for consumers that read only
// Reasons. A package that is provably not present in the build (absentFromBuild) gets only
// dependency_not_in_build, scoped to its own PURL.
func resolveInDependency(buildDir, id, version string, wanted []string) plugin.SymbolResolutionResult {
	if absentFromBuild(buildDir, id) {
		// Intake already settles this advisory as no_manifest_entry; a lookup that reaches here
		// gets the same answer, bounded to this package.
		return plugin.SymbolResolutionResult{Partiality: notInBuild(id)}
	}
	purl := nugetPackageURL(id)
	build := locateFirstPartyBuild(buildDir)
	reasons := map[string]bool{}
	for _, r := range build.reasons {
		reasons[r] = true
	}
	var scoped []plugin.ScopedReason
	miss := func(reason, pkg, path string, targets []string) {
		reasons[reason] = true
		scoped = append(scoped, plugin.ScopedReason{Reason: reason, Package: pkg, Path: path, Targets: targets})
	}
	finish := func(res plugin.SymbolResolutionResult) plugin.SymbolResolutionResult {
		if len(reasons) == 0 && len(scoped) == 0 {
			res.Partiality = plugin.Complete()
			return res
		}
		res.Partiality = plugin.Partiality{Reasons: sortedKeys(reasons), Scoped: scoped}
		return res
	}

	if build.assets == nil {
		// No restore output: neither the package's code nor its dependency closure is known.
		miss(partialReasonNoDependencyArtifact, purl, "project.assets.json", nil)
		return finish(plugin.SymbolResolutionResult{})
	}
	locator, _ := assembly.ParseAssetsLocator(build.assets)
	graph := parseAssetsGraph(build.assets)
	var occurrences []assembly.DepRef
	for _, d := range graph.occurrences(id, version) {
		if build.target == "" || d.Target == build.target {
			d.Runtime = build.runtime
			occurrences = append(occurrences, d)
		}
	}
	if len(occurrences) == 0 {
		coord := id
		if version != "" {
			coord += "@" + version
		}
		where := "project.assets.json"
		if build.target != "" {
			where += " target " + build.target
		}
		miss(partialReasonNoDependencyArtifact, purl, coord+" not in "+where, nil)
		return finish(plugin.SymbolResolutionResult{})
	}

	var loaded []loadedPackage
	readAny := false
	for _, d := range occurrences {
		pkgID, _ := splitPkgKey(d.PkgKey)
		asms, why := assembly.ReadDependency(buildDir, d, locator)
		if why == assembly.MissNotLocated && locator.HasNoAssemblies(d.Target, d.PkgKey) {
			readAny = true // restore recorded no assembly and none is on disk: nothing to match
			continue
		}
		if why != "" {
			miss(missReason(why), nugetPackageURL(pkgID), d.PkgKey+" ("+d.Target+"): "+why, graph.closure(d.Target, d.PkgKey))
			continue
		}
		readAny = true
		loaded = append(loaded, loadedPackage{id: pkgID, asms: asms})
	}

	res, ambiguous := matchDependencySymbols(loaded, wanted)
	if ambiguous {
		reasons[partialReasonAdvisorySymbolAmbiguous] = true
	}
	if readAny && len(res.Matched) < len(wanted) {
		reasons[partialReasonAdvisorySymbolUnresolved] = true
	}
	return finish(res)
}

// loadedPackage is one package's read assemblies, under the NuGet id restore recorded.
type loadedPackage struct {
	id   string
	asms []*assembly.Assembly
}

// matchDependencySymbols matches each wanted advisory symbol against every method of the
// loaded packages and fills Resolved, Origins and Matched. Matched is keyed by the advisory
// symbol verbatim. A fully qualified advisory symbol matches its own name only. A shortened
// one ("JsonConvert.DeserializeObject") matches only when every method it names shares one
// qualified name: a lookalike type in another namespace makes it ambiguous, so it is left
// out of Matched (its candidates stay in Resolved, where they can only add paths) and
// ambiguous is true.
func matchDependencySymbols(pkgs []loadedPackage, wanted []string) (res plugin.SymbolResolutionResult, ambiguous bool) {
	norm := make([]string, len(wanted))
	for i, w := range wanted {
		norm[i] = normalizeAdvisorySymbol(w)
	}
	type hit struct {
		sym    plugin.Symbol
		origin string
	}
	syms := map[string]hit{}
	exact := make([]map[string]bool, len(wanted))
	suffix := make([]map[string]map[string]bool, len(wanted)) // qualified form -> SCIPs
	for _, pkg := range pkgs {
		for _, a := range pkg.asms {
			for i := range a.Types {
				td := &a.Types[i]
				ns, chain := sourceTypePath(a, td)
				for _, m := range td.Methods {
					if m == nil {
						continue
					}
					forms := methodForms(ns, chain, m)
					var scip string
					for wi, w := range norm {
						form, full, ok := matchForm(w, forms)
						if !ok {
							continue
						}
						if scip == "" {
							_, scip = methodIdentity(a, td, m)
							if _, seen := syms[scip]; !seen {
								syms[scip] = hit{dependencySymbol(a, td, m, pkg.id, ns, chain, scip), nugetPackageURL(pkg.id)}
							}
						}
						if full {
							if exact[wi] == nil {
								exact[wi] = map[string]bool{}
							}
							exact[wi][scip] = true
							continue
						}
						if suffix[wi] == nil {
							suffix[wi] = map[string]map[string]bool{}
						}
						if suffix[wi][form] == nil {
							suffix[wi][form] = map[string]bool{}
						}
						suffix[wi][form][scip] = true
					}
				}
			}
		}
	}

	resolved := map[string]bool{}
	for wi, w := range wanted {
		var accepted map[string]bool
		switch {
		case len(exact[wi]) > 0:
			accepted = exact[wi]
		case len(suffix[wi]) == 1:
			for _, set := range suffix[wi] {
				accepted = set
			}
		case len(suffix[wi]) > 1:
			ambiguous = true
			for _, set := range suffix[wi] {
				for scip := range set {
					resolved[scip] = true
				}
			}
			continue
		default:
			continue
		}
		if res.Matched == nil {
			res.Matched = map[string][]string{}
		}
		res.Matched[w] = sortedKeys(accepted)
		for scip := range accepted {
			resolved[scip] = true
		}
	}
	for _, scip := range sortedKeys(resolved) {
		h := syms[scip]
		res.Resolved = append(res.Resolved, h.sym)
		if res.Origins == nil {
			res.Origins = map[string]string{}
		}
		res.Origins[scip] = h.origin
	}
	return res, ambiguous
}

// dependencySymbol is the resolved plugin.Symbol for a dependency method: Package is the
// NuGet id, Enclosing the namespace-qualified type chain, SCIP the reconcile identity.
func dependencySymbol(a *assembly.Assembly, td *assembly.TypeDef, m *assembly.MethodDef, id, ns string, chain []string, scip string) plugin.Symbol {
	s := depreach.SymbolFor(a, td, m)
	s.Package = id
	s.Enclosing = ownerDisplay(ns, strings.Join(chain, "."))
	s.DisplayName = s.Enclosing + "." + m.Name
	s.SCIP = scip
	return s
}

// methodForms returns the lower-cased dotted names an advisory may use for m: the fully
// qualified "namespace.Outer.Type.Method", plus the C# spellings of special members — a
// constructor as the type's own name, an accessor as its property/event name.
func methodForms(ns string, chain []string, m *assembly.MethodDef) []string {
	prefix := strings.ToLower(strings.Join(chain, "."))
	if ns != "" {
		prefix = strings.ToLower(ns) + "." + prefix
	}
	names := []string{m.Name}
	switch {
	case m.Name == ".ctor":
		names = append(names, chain[len(chain)-1])
	case m.Flags&methodAttrSpecialName != 0:
		for _, p := range []string{"get_", "set_", "add_", "remove_"} {
			if rest, ok := strings.CutPrefix(m.Name, p); ok && rest != "" {
				names = append(names, rest)
				break
			}
		}
	}
	forms := make([]string, len(names))
	for i, n := range names {
		forms[i] = prefix + "." + strings.ToLower(n)
	}
	return forms
}

// matchForm reports whether the normalized advisory symbol w names one of forms, and
// which: the whole qualified name (full), or a trailing run of it that still carries at
// least a type and a member ("JsonConvert.DeserializeObject",
// "Json.JsonConvert.DeserializeObject"). A bare member name never matches: it does not say
// which type's code is vulnerable.
func matchForm(w string, forms []string) (form string, full, ok bool) {
	if w == "" || !strings.Contains(strings.TrimPrefix(w, "."), ".") {
		return "", false, false
	}
	for _, f := range forms {
		if f == w {
			return f, true, true
		}
	}
	for _, f := range forms {
		if strings.HasSuffix(f, "."+w) {
			return f, false, true
		}
	}
	return "", false, false
}

// normalizeAdvisorySymbol lower-cases an advisory symbol and strips what metadata names do
// not carry: a trailing parameter list or arity marker, generic argument lists, backtick
// arity, and "::" member separators.
func normalizeAdvisorySymbol(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "::", ".")
	s = stripArity(s)
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '<':
			depth++
		case c == '>':
			if depth > 0 {
				depth--
			}
		case depth > 0:
		case c == '`':
			for i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				i++
			}
		default:
			b.WriteByte(c)
		}
	}
	return strings.ToLower(b.String())
}

// nugetCoordinate parses a NuGet PURL ("pkg:nuget/Newtonsoft.Json@12.0.3") into id and
// version. ok is false for any other ecosystem or a malformed PURL.
func nugetCoordinate(purl string) (id, version string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !found {
		return "", "", false
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, name, found := strings.Cut(rest, "/")
	if !found || !strings.EqualFold(typ, "nuget") {
		return "", "", false
	}
	name, version, _ = strings.Cut(name, "@")
	if dec, err := url.PathUnescape(name); err == nil {
		name = dec
	}
	if dec, err := url.PathUnescape(version); err == nil {
		version = dec
	}
	if name == "" || strings.Contains(name, "/") {
		return "", "", false
	}
	return name, version, true
}

// nugetPackageURL is the version-less PURL of a NuGet package, as Origins and scoped limits
// carry it; the id is lower-cased like the inventory's PURLs (NuGet ids are case-insensitive).
func nugetPackageURL(id string) string { return "pkg:nuget/" + strings.ToLower(id) }

// isFirstPartyProject reports whether id names a project in the build (a project file of
// that name): an advisory against the repo's own package resolves against its source.
func isFirstPartyProject(buildDir, id string) bool {
	found := false
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil //nolint:nilerr // an unreadable subtree holds no project; keep walking.
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch ext := filepath.Ext(d.Name()); strings.ToLower(ext) {
		case ".csproj", ".fsproj", ".vbproj":
			if strings.EqualFold(strings.TrimSuffix(d.Name(), ext), id) {
				found = true
			}
		}
		return nil
	})
	return found
}

// readAssetsFile reads the build's project.assets.json — the same file the IL tier loads its
// spanning set from, so resolution and reachability see one restore.
func readAssetsFile(buildDir string) (string, []byte, bool) {
	path, ok := findFile(buildDir, "project.assets.json", true)
	if !ok {
		return "", nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, false
	}
	return path, data, true
}

// assetsGraph is project.assets.json's resolved package graph: per target, each library
// key ("<id>/<version>") with its type and declared dependency ids.
type assetsGraph struct {
	targets map[string]map[string]assetsLib
}

type assetsLib struct {
	Type         string            `json:"type"`
	Dependencies map[string]string `json:"dependencies"`
}

// parseAssetsGraph parses the graph; nil on malformed input (every lookup on a nil graph
// then answers "unknown").
func parseAssetsGraph(data []byte) *assetsGraph {
	var af struct {
		Targets map[string]map[string]assetsLib `json:"targets"`
	}
	if err := json.Unmarshal(data, &af); err != nil {
		return nil
	}
	return &assetsGraph{targets: af.Targets}
}

// occurrences returns every (target, library key) restore resolved package id to, matching
// the id case-insensitively and, when version is non-empty, the version exactly. Sorted.
func (g *assetsGraph) occurrences(id, version string) []assembly.DepRef {
	if g == nil {
		return nil
	}
	var out []assembly.DepRef
	for target, libs := range g.targets {
		for key, lib := range libs {
			if strings.EqualFold(lib.Type, "project") {
				continue
			}
			kid, kver := splitPkgKey(key)
			if !strings.EqualFold(kid, id) || (version != "" && !strings.EqualFold(kver, version)) {
				continue
			}
			out = append(out, assembly.DepRef{Target: target, PkgKey: key})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].PkgKey < out[j].PkgKey
	})
	return out
}

// closure returns the version-less PURLs of library pkgKey and everything it transitively
// depends on in target: every package a hidden edge out of pkgKey's code could reach. nil
// (unbounded) when the graph does not record pkgKey in target.
func (g *assetsGraph) closure(target, pkgKey string) []string {
	if g == nil {
		return nil
	}
	libs := g.targets[target]
	if _, ok := libs[pkgKey]; !ok {
		return nil
	}
	byID := make(map[string]string, len(libs))
	for key := range libs {
		id, _ := splitPkgKey(key)
		byID[strings.ToLower(id)] = key
	}
	seen := map[string]bool{pkgKey: true}
	queue := []string{pkgKey}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for dep := range libs[cur].Dependencies {
			key, ok := byID[strings.ToLower(dep)]
			if !ok {
				// A dependency restore did not resolve in this target: its code is unknown,
				// so the closure cannot be bounded.
				return nil
			}
			if !seen[key] {
				seen[key] = true
				queue = append(queue, key)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for key := range seen {
		id, _ := splitPkgKey(key)
		out = append(out, nugetPackageURL(id))
	}
	sort.Strings(out)
	return out
}
