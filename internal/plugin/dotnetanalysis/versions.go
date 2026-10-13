package dotnetanalysis

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions reads the .NET codebase's INSTALLED (pinned) dependency versions
// from its manifests — packages.lock.json (preferred: exact + transitive), .csproj
// PackageReference pins, and packages.config — and returns the resolved version for the
// advisory's requested coordinate (the NuGet package id). It is the cheap Assess-tier input
// to the disqualification predicate, the .NET mirror of jsanalysis / pythonanalysis
// ResolveDependencyVersions.
//
// SOUNDNESS (inv.5): this NEVER guesses a version. A .csproj PackageReference may carry a
// RANGE ("[1.0,2.0)") or a floating version ("1.2.*") rather than an exact pin, and
// transitive dependencies are unknown without a lockfile or a full restore. Only an EXACT
// pin (a packages.lock.json "resolved" version, a packages.config "version", or a .csproj
// exact "Version") yields Resolved=true; a range, a float, or an unreadable entry is an
// UNRESOLVED marker (Resolved=false) the predicate fails OPEN on, never fabricating a
// not-affected. Transitive resolution without a lockfile is OUT of MVP (scope §3, risk R3):
// unresolved transitives stay UNRESOLVED, never assumed not-affected.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir is a hard error.
//   - A build dir with NO recognized manifest degrades Partiality to declared-partial
//     (no_manifest) rather than hard-failing the run: a repo that carries no project file is a
//     normal shape, not a tool failure. The recognized set already includes the DECLARED
//     manifests (.csproj/.fsproj/.vbproj, packages.config), so unlike JS there is nothing left
//     to seed — All is legitimately empty. Soundness rests entirely on the declared
//     partiality: the result is Complete=false, so a consumer must not read the empty All as
//     proof the dependency is absent and fabricate a not-affected.
//   - An unparseable manifest degrades Partiality to declared-partial (tool_failure); the
//     coordinate it would have carried becomes UNRESOLVED, not absent.
//
// "plugin resolves, pipeline ranges" symmetry: this op resolves only the concrete installed
// literal version. Advisory RANGE matching (NuGet interval ordering) is applied by the
// pipeline disqualification predicate (pipeline/nuget_version.go), never here.
//
// Several copies of one package (two projects, two target frameworks, a lockfile beside a
// project file): Match is chosen by matchNuGet, which never picks one copy out of several
// distinct versions. See its doc comment for the rule.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("dotnetanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("dotnetanalysis: build dir %q is not a directory", req.BuildDir)
	}

	manifests := manifestFiles(req.BuildDir)

	var (
		all         []plugin.ResolvedDependency
		copies      []nugetCopy
		parseFailed bool
	)
	for _, m := range manifests {
		deps, ok := parseManifest(m)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
		kind := manifestKind(filepath.Base(m))
		for _, d := range deps {
			copies = append(copies, nugetCopy{dep: d, dir: filepath.Dir(m), kind: kind})
		}
	}

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{Partiality: part, All: all}
	res.Match, res.Found = matchNuGet(copies, normalizeNuGetCoordinate(req.Coordinate))
	return res, nil
}

// nugetCopy is one manifest entry together with where it came from, which matchNuGet needs
// to tell a project file's own lockfile from another project's.
type nugetCopy struct {
	dep  plugin.ResolvedDependency
	dir  string
	kind string
}

const (
	kindLock    = "lock"
	kindProject = "project"
	kindConfig  = "config"
)

func manifestKind(base string) string {
	switch base {
	case "packages.lock.json":
		return kindLock
	case "packages.config":
		return kindConfig
	default:
		return kindProject
	}
}

// matchNuGet selects the Match for the normalized coordinate want across every manifest
// entry: every project, every target framework of every packages.lock.json. The predicate
// reads a single Match, so the rule is:
//
//   - every matching copy resolved to the SAME version (N copies of one version count as one):
//     Match is that version, Resolved=true;
//   - two or more distinct resolved versions, or any matching copy whose version is unknown:
//     Match is UNRESOLVED (Resolved=false, Version empty).
//
// One exception to "any unknown copy": a project file's range, float or version-less
// (Central Package Management) PackageReference is covered when the packages.lock.json in
// the same directory pins the same id, because that lockfile is restore's resolution of that
// project. A lockfile anywhere else does not cover it.
//
// Picking one copy would let a range that straddles the installed set rule the advisory
// not-affected on the copy that happens to sit outside it while a vulnerable copy still
// ships. UNRESOLVED makes the predicate fail OPEN instead. Versions compare as exact strings:
// two spellings of one version ("12.0" and "12.0.0") read as distinct, which can only fail
// open.
func matchNuGet(copies []nugetCopy, want string) (plugin.ResolvedDependency, bool) {
	if want == "" {
		return plugin.ResolvedDependency{}, false
	}
	locked := make(map[string]bool)
	for _, c := range copies {
		if c.kind == kindLock && c.dep.Resolved && normalizeNuGetCoordinate(c.dep.Coordinate) == want {
			locked[c.dir] = true
		}
	}
	var (
		match    plugin.ResolvedDependency
		found    bool
		unknown  bool
		versions = make(map[string]struct{})
	)
	for _, c := range copies {
		if normalizeNuGetCoordinate(c.dep.Coordinate) != want {
			continue
		}
		if !found {
			match, found = c.dep, true
		}
		if !c.dep.Resolved {
			if c.kind == kindProject && locked[c.dir] {
				continue
			}
			unknown = true
			continue
		}
		if len(versions) == 0 {
			match = c.dep
		}
		versions[c.dep.Version] = struct{}{}
	}
	if found && (unknown || len(versions) != 1) {
		match.Version = ""
		match.Resolved = false
	}
	return match, found
}

// manifestFiles returns every recognized .NET manifest under root, skipping build-output /
// package / VCS trees so a restored copy does not shadow the project's own manifest.
func manifestFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no manifests; keep walking.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isManifest(d.Name()) {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// isManifest reports whether name is a recognized .NET dependency manifest.
func isManifest(name string) bool {
	if name == "packages.lock.json" || name == "packages.config" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".csproj" || ext == ".fsproj" || ext == ".vbproj"
}

// parseManifest dispatches on the manifest's name to the format-specific parser. The bool is
// false when the file cannot be read or is structurally unparseable (the caller degrades
// partiality).
func parseManifest(path string) ([]plugin.ResolvedDependency, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	base := filepath.Base(path)
	switch {
	case base == "packages.lock.json":
		return parsePackagesLock(data)
	case base == "packages.config":
		return parsePackagesConfig(data)
	default: // *.csproj / *.fsproj / *.vbproj
		return parseProjectFile(data)
	}
}

// --- packages.lock.json (JSON) -----------------------------------------------

// packagesLock is the subset of packages.lock.json we read: a per-framework map of package
// name → entry with the exact "resolved" version (present for both Direct and Transitive).
type packagesLock struct {
	Dependencies map[string]map[string]packagesLockEntry `json:"dependencies"`
}

type packagesLockEntry struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// parsePackagesLock parses packages.lock.json. Every entry (Direct or Transitive) carries an
// exact "resolved" version, so a present resolved field resolves; a missing one is
// UNRESOLVED. A "Project" reference (a sibling project, not a NuGet package) has no resolved
// version and is skipped.
//
// Each target framework (and each <tfm>/<rid> target) is its own resolution, and they can
// disagree (net6.0 → 13.0.1, net8.0 → 13.0.3). Every distinct (id, version) across them is
// kept so matchNuGet sees the split; only exact repeats collapse. Frameworks and ids are
// walked in sorted order so All is identical across runs.
func parsePackagesLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var pl packagesLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, false
	}
	type idVersion struct{ id, version string }
	seen := make(map[idVersion]bool)
	var out []plugin.ResolvedDependency
	for _, tfm := range slices.Sorted(maps.Keys(pl.Dependencies)) {
		pkgs := pl.Dependencies[tfm]
		for _, name := range slices.Sorted(maps.Keys(pkgs)) {
			e := pkgs[name]
			if strings.EqualFold(e.Type, "Project") {
				continue
			}
			d := nugetResolved(name, e.Resolved, e.Resolved != "", "packages.lock.json")
			k := idVersion{normalizeNuGetCoordinate(name), d.Version}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, d)
		}
	}
	return out, true
}

// --- .csproj / .fsproj / .vbproj (XML) ---------------------------------------

// csprojProject is the subset of an SDK-style project file we read: PackageReference items
// under any ItemGroup, each with an Include (the package id) and a Version given either as an
// attribute or a child element.
type csprojProject struct {
	ItemGroups []struct {
		PackageRefs []struct {
			Include     string `xml:"Include,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
		} `xml:"PackageReference"`
	} `xml:"ItemGroup"`
}

// parseProjectFile parses a .csproj/.fsproj/.vbproj for PackageReference pins. An exact
// literal Version (e.g. "1.2.3" or the exact-bracket "[1.2.3]") resolves; a range, a
// floating version, an empty Version (Central Package Management — the version lives in
// Directory.Packages.props, out of MVP), or a "Project"/framework reference is UNRESOLVED.
func parseProjectFile(data []byte) ([]plugin.ResolvedDependency, bool) {
	var proj csprojProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	for _, ig := range proj.ItemGroups {
		for _, pr := range ig.PackageRefs {
			name := strings.TrimSpace(pr.Include)
			if name == "" {
				continue
			}
			raw := strings.TrimSpace(pr.VersionAttr)
			if raw == "" {
				raw = strings.TrimSpace(pr.VersionElem)
			}
			ver, resolved := exactNuGetPin(raw)
			out = append(out, nugetResolved(name, ver, resolved, "csproj"))
		}
	}
	return out, true
}

// --- packages.config (XML) ---------------------------------------------------

// packagesConfigDoc is the legacy packages.config format: a flat list of <package
// id="X" version="1.2.3" /> entries, always exact versions.
type packagesConfigDoc struct {
	Packages []struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	} `xml:"package"`
}

// parsePackagesConfig parses packages.config. Every entry carries an exact version, so a
// present version resolves; a missing one is UNRESOLVED.
func parsePackagesConfig(data []byte) ([]plugin.ResolvedDependency, bool) {
	var doc packagesConfigDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	for _, p := range doc.Packages {
		name := strings.TrimSpace(p.ID)
		if name == "" {
			continue
		}
		ver, resolved := exactNuGetPin(strings.TrimSpace(p.Version))
		out = append(out, nugetResolved(name, ver, resolved, "packages.config"))
	}
	return out, true
}

// --- shared helpers ----------------------------------------------------------

// exactNuGetPin reports whether raw is an EXACT NuGet version pin and returns the concrete
// version. A plain version ("1.2.3", "1.2.3.4") is exact; the exact-bracket form ("[1.2.3]")
// is exact (unwrapped). A range/interval (contains ',' or an unmatched bracket), a floating
// version (contains '*'), or an empty string is NOT an exact pin → UNRESOLVED.
func exactNuGetPin(raw string) (version string, resolved bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "*,") {
		return "", false
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		inner := strings.TrimSpace(raw[1 : len(raw)-1])
		if inner == "" || strings.ContainsAny(inner, "[](),*") {
			return "", false
		}
		return inner, true
	}
	// Any other bracketed/parenthesised form is a range, not an exact pin.
	if strings.ContainsAny(raw, "[]()") {
		return "", false
	}
	return raw, true
}

// nugetResolved builds a ResolvedDependency for a NuGet package. An empty/unresolved version
// is UNRESOLVED (Resolved=false), never guessed.
func nugetResolved(name, version string, resolved bool, source string) plugin.ResolvedDependency {
	version = strings.TrimSpace(version)
	if name == "" || version == "" || !resolved {
		return plugin.ResolvedDependency{Coordinate: name, Resolved: false, Source: source}
	}
	return plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: source}
}

// normalizeNuGetCoordinate normalizes a NuGet package id for comparison: NuGet ids are
// case-insensitive but keep their dots ("Newtonsoft.Json"), so this only lowercases and
// trims (unlike PyPI's dash/dot collapsing).
func normalizeNuGetCoordinate(c string) string {
	return strings.ToLower(strings.TrimSpace(c))
}
