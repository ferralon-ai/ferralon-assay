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
const partialReasonAdvisorySymbolUnresolved = "advisory_symbol_unresolved"

// methodAttrSpecialName marks property/event accessors (get_X, set_X, add_X, remove_X).
const methodAttrSpecialName = 0x0800

// resolveInDependency resolves wanted (verbatim advisory symbols) against the restored
// assemblies of NuGet package id (at version, when non-empty).
func resolveInDependency(buildDir, id, version string, wanted []string) plugin.SymbolResolutionResult {
	purl := nugetPackageURL(id)
	data, ok := readAssetsFile(buildDir)
	if !ok {
		// No restore output: neither the package's code nor its dependency closure is known.
		return plugin.SymbolResolutionResult{Partiality: plugin.Partiality{Scoped: []plugin.ScopedReason{{
			Reason: partialReasonNoDependencyArtifact, Package: purl, Path: "project.assets.json",
		}}}}
	}
	locator, _ := assembly.ParseAssetsLocator(data)
	graph := parseAssetsGraph(data)
	occurrences := graph.occurrences(id, version)
	if len(occurrences) == 0 {
		coord := id
		if version != "" {
			coord += "@" + version
		}
		return plugin.SymbolResolutionResult{Partiality: plugin.Partiality{Scoped: []plugin.ScopedReason{{
			Reason: partialReasonNoDependencyArtifact, Package: purl, Path: coord + " not in project.assets.json",
		}}}}
	}

	var scoped []plugin.ScopedReason
	var loaded []loadedPackage
	readAny := false
	for _, d := range occurrences {
		pkgID, _ := splitPkgKey(d.PkgKey)
		asms, miss := assembly.ReadDependency(buildDir, d, locator)
		if miss == assembly.MissNotLocated && locator.HasNoAssemblies(d.Target, d.PkgKey) {
			readAny = true // restore recorded no assembly and none is on disk: nothing to match
			continue
		}
		if miss != "" {
			scoped = append(scoped, plugin.ScopedReason{
				Reason:  missReason(miss),
				Package: nugetPackageURL(pkgID),
				Path:    d.PkgKey + " (" + d.Target + "): " + miss,
				Targets: graph.closure(d.Target, d.PkgKey),
			})
			continue
		}
		readAny = true
		loaded = append(loaded, loadedPackage{id: pkgID, asms: asms})
	}

	res := matchDependencySymbols(loaded, wanted)
	reasons := map[string]bool{}
	if readAny && len(res.Matched) < len(wanted) {
		reasons[partialReasonAdvisorySymbolUnresolved] = true
	}
	if len(reasons) > 0 || len(scoped) > 0 {
		res.Partiality = plugin.Partiality{Scoped: scoped}
		if len(reasons) > 0 {
			res.Partiality.Reasons = sortedKeys(reasons)
		}
	} else {
		res.Partiality = plugin.Complete()
	}
	return res
}

// loadedPackage is one package's read assemblies, under the NuGet id restore recorded.
type loadedPackage struct {
	id   string
	asms []*assembly.Assembly
}

// matchDependencySymbols matches each wanted advisory symbol against every method of the
// loaded packages and fills Resolved, Origins and Matched. Matched is keyed by the advisory
// symbol verbatim; an advisory symbol that matched nothing is absent from it.
func matchDependencySymbols(pkgs []loadedPackage, wanted []string) plugin.SymbolResolutionResult {
	norm := make([]string, len(wanted))
	for i, w := range wanted {
		norm[i] = normalizeAdvisorySymbol(w)
	}
	res := plugin.SymbolResolutionResult{}
	seenSym := map[string]bool{}
	matched := map[string]map[string]bool{}
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
					var hits []string
					for i, w := range norm {
						if matchesAnyForm(w, forms) {
							hits = append(hits, wanted[i])
						}
					}
					if len(hits) == 0 {
						continue
					}
					_, scip := methodIdentity(a, td, m)
					if !seenSym[scip] {
						seenSym[scip] = true
						res.Resolved = append(res.Resolved, dependencySymbol(a, td, m, pkg.id, ns, chain, scip))
						if res.Origins == nil {
							res.Origins = map[string]string{}
						}
						res.Origins[scip] = nugetPackageURL(pkg.id)
					}
					for _, w := range hits {
						if matched[w] == nil {
							matched[w] = map[string]bool{}
						}
						matched[w][scip] = true
					}
				}
			}
		}
	}
	if len(matched) > 0 {
		res.Matched = make(map[string][]string, len(matched))
		for w, set := range matched {
			res.Matched[w] = sortedKeys(set)
		}
	}
	return res
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

// matchesAnyForm reports whether the normalized advisory symbol w names one of forms: the
// whole qualified name, or a trailing run of it that still carries at least a type and a
// member ("JsonConvert.DeserializeObject", "Json.JsonConvert.DeserializeObject"). A bare
// member name never matches: it does not say which type's code is vulnerable.
func matchesAnyForm(w string, forms []string) bool {
	if w == "" || !strings.Contains(strings.TrimPrefix(w, "."), ".") {
		return false
	}
	for _, f := range forms {
		if f == w || strings.HasSuffix(f, "."+w) {
			return true
		}
	}
	return false
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
func readAssetsFile(buildDir string) ([]byte, bool) {
	path, ok := findFile(buildDir, "project.assets.json", true)
	if !ok {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
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
