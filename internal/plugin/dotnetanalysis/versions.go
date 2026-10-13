package dotnetanalysis

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
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
// exact-bracket "Version" such as "[1.2.3]") yields Resolved=true; a plain .csproj "Version" is a
// minimum, not a pin; a range, a float, or an unreadable entry is an
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
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("dotnetanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("dotnetanalysis: build dir %q is not a directory", req.BuildDir)
	}

	manifests, sealed := manifestFiles(req.BuildDir)
	want := normalizeNuGetCoordinate(req.Coordinate)
	locked := make(map[string]bool)
	for _, m := range manifests {
		if filepath.Base(m) == "packages.lock.json" {
			locked[filepath.Dir(m)] = true
		}
	}

	var (
		all         []plugin.ResolvedDependency
		matches     []plugin.ResolvedDependency
		parseFailed bool
	)
	for _, m := range manifests {
		deps, ok := parseManifest(m)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
		if isProjectFile(filepath.Base(m)) && locked[filepath.Dir(m)] {
			continue // the packages.lock.json beside it pins what this references
		}
		for _, d := range deps {
			if want != "" && normalizeNuGetCoordinate(d.Coordinate) == want {
				matches = append(matches, d)
			}
		}
	}

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{Partiality: part, All: all, Matches: matches}
	res.MatchesComplete = len(matches) > 0 && sealed && !parseFailed &&
		!msbuildWideInAncestors(req.BuildDir) && projectsCovered(manifests, locked, want)
	if want != "" {
		for _, d := range all {
			if normalizeNuGetCoordinate(d.Coordinate) == want {
				res.Found = true
				res.Match = d
				// A resolved match wins over an UNRESOLVED one for the same coordinate — this
				// is how packages.lock.json's exact pin is preferred over a .csproj range.
				if d.Resolved {
					break
				}
			}
		}
	}
	return res, nil
}

// manifestFiles returns every recognized .NET manifest under root, skipping build-output /
// package / VCS trees so a restored copy does not shadow the project's own manifest. sealed is
// false when part of the tree could not be walked or an MSBuild-wide file
// (Directory.Build.props/.targets, Directory.Packages.props) sits in it: those inject or
// override PackageReference versions this reader does not evaluate.
func manifestFiles(root string) (files []string, sealed bool) {
	sealed = true
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			sealed = false
			return nil //nolint:nilerr // an unreadable subtree yields no manifests; keep walking.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if isMSBuildWide(d.Name()) {
			sealed = false
		}
		if isManifest(d.Name()) {
			files = append(files, path)
		}
		return nil
	})
	return files, sealed
}

// isMSBuildWide reports whether name is an MSBuild file every project beneath it imports
// implicitly, one that can add PackageReference items or set their versions centrally.
func isMSBuildWide(name string) bool {
	switch strings.ToLower(name) {
	case "directory.build.props", "directory.build.targets", "directory.packages.props":
		return true
	}
	return false
}

// msbuildWideInAncestors reports whether an MSBuild-wide file sits in a directory above root:
// MSBuild searches upward from each project, so one there applies to the whole build.
func msbuildWideInAncestors(root string) bool {
	abs, err := filepath.Abs(root)
	if err != nil {
		return true
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return true
		}
		for _, e := range entries {
			if isMSBuildWide(e.Name()) {
				return true
			}
		}
		if filepath.Dir(dir) == dir {
			return false
		}
	}
}

// projectsCovered reports whether every project file pins the coordinate in a form NuGet
// restores as written, so Matches can hold every version the build installs. A project beside
// packages.lock.json is covered by the lock, which enumerates its whole graph, unless it declares
// the coordinate and the lock omits it (a stale lock). A project beside packages.config with no
// PackageReference is covered by that file's flat list, transitives included. Any other project
// is covered only when it references nothing, or references the coordinate directly at an
// exact-bracket pin with no condition: the direct reference wins NuGet's resolution, and only
// "[1.2.3]" means exactly 1.2.3 ("1.2.3" is a minimum, and restore takes a higher version when
// the feed lacks it).
func projectsCovered(manifests []string, locked map[string]bool, want string) bool {
	if want == "" {
		return false
	}
	configured := make(map[string]bool)
	lockHas := make(map[string]bool)
	for _, m := range manifests {
		switch filepath.Base(m) {
		case "packages.config":
			configured[filepath.Dir(m)] = true
		case "packages.lock.json":
			deps, _ := parseManifest(m)
			for _, d := range deps {
				if normalizeNuGetCoordinate(d.Coordinate) == want {
					lockHas[filepath.Dir(m)] = true
				}
			}
		}
	}
	for _, m := range manifests {
		if !isProjectFile(filepath.Base(m)) {
			continue
		}
		data, err := os.ReadFile(m)
		if err != nil {
			return false
		}
		refs, ok := coordinateReferences(data, want)
		if !ok {
			return false
		}
		dir := filepath.Dir(m)
		switch {
		case locked[dir]:
			if refs.declares && !lockHas[dir] {
				return false
			}
		case configured[dir] && !refs.packages:
			// packages.config lists the project's whole package graph.
		case refs.imports:
			return false
		case refs.pinned:
		case refs.packages || refs.projects:
			return false
		}
	}
	return true
}

// coordinateRefs summarises the references one project file makes, as projectsCovered reads them.
type coordinateRefs struct {
	packages bool // any PackageReference
	projects bool // any ProjectReference
	imports  bool // any explicit <Import>, which can add references of its own
	declares bool // a PackageReference to the coordinate (Include or Update)
	pinned   bool // the coordinate is referenced directly, every reference unconditional and exact-bracket
}

// refFile is the subset of a project file coordinateReferences reads.
type refFile struct {
	Imports []struct {
		Project string `xml:"Project,attr"`
	} `xml:"Import"`
	ItemGroups []struct {
		Condition   string `xml:"Condition,attr"`
		PackageRefs []struct {
			Include     string `xml:"Include,attr"`
			Update      string `xml:"Update,attr"`
			Condition   string `xml:"Condition,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
		} `xml:"PackageReference"`
		ProjectRefs []struct {
			Include string `xml:"Include,attr"`
		} `xml:"ProjectReference"`
	} `xml:"ItemGroup"`
}

// coordinateReferences reads a project file's references to want. The bool is false when the file
// is unparseable.
func coordinateReferences(data []byte, want string) (coordinateRefs, bool) {
	var proj refFile
	if err := xml.Unmarshal(data, &proj); err != nil {
		return coordinateRefs{}, false
	}
	refs := coordinateRefs{imports: len(proj.Imports) > 0}
	exact := true
	for _, ig := range proj.ItemGroups {
		refs.projects = refs.projects || len(ig.ProjectRefs) > 0
		for _, pr := range ig.PackageRefs {
			refs.packages = true
			name := pr.Include
			if name == "" {
				name = pr.Update
			}
			if normalizeNuGetCoordinate(name) != want {
				continue
			}
			refs.declares = true
			raw := strings.TrimSpace(pr.VersionAttr)
			if raw == "" {
				raw = strings.TrimSpace(pr.VersionElem)
			}
			bracketed := strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]")
			_, pin := exactNuGetPin(raw)
			if pr.Update != "" || strings.TrimSpace(ig.Condition) != "" || strings.TrimSpace(pr.Condition) != "" || !bracketed || !pin {
				exact = false
			}
		}
	}
	refs.pinned = refs.declares && exact
	return refs, true
}

// isManifest reports whether name is a recognized .NET dependency manifest.
func isManifest(name string) bool {
	return name == "packages.lock.json" || name == "packages.config" || isProjectFile(name)
}

// isProjectFile reports whether name is an SDK-style project file.
func isProjectFile(name string) bool {
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
func parsePackagesLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var pl packagesLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, false
	}
	seen := make(map[string]bool)
	var out []plugin.ResolvedDependency
	for _, pkgs := range pl.Dependencies {
		for name, e := range pkgs {
			if strings.EqualFold(e.Type, "Project") {
				continue
			}
			// The same package across target frameworks needs one entry per distinct version:
			// each framework can restore its own.
			key := normalizeNuGetCoordinate(name) + "@" + e.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, nugetResolved(name, e.Resolved, e.Resolved != "", "packages.lock.json"))
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

// parseProjectFile parses a .csproj/.fsproj/.vbproj for PackageReference pins. Only the
// exact-bracket Version "[1.2.3]" resolves. A plain Version "1.2.3" is a minimum (NuGet restores
// the lowest available version at or above it, NU1603), so it is UNRESOLVED like a range, a
// floating version, an empty Version (Central Package Management — the version lives in
// Directory.Packages.props, out of MVP), or a "Project"/framework reference.
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
			ver, resolved := packageReferencePin(raw)
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
// version. A plain version ("1.2.3", "1.2.3.4") is exact where the format makes it so
// (packages.config, packages.lock.json); the exact-bracket form ("[1.2.3]") is exact (unwrapped). A range/interval (contains ',' or an unmatched bracket), a floating
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

// packageReferencePin reports whether a PackageReference Version is an exact pin. Only the
// exact-bracket form is: a plain version is a minimum the restore may raise.
func packageReferencePin(raw string) (version string, resolved bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") {
		return "", false
	}
	return exactNuGetPin(raw)
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
