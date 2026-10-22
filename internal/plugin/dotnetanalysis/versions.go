package dotnetanalysis

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
// not-affected. A project that could pull the package in transitively, with neither restore
// output nor a current lockfile to say which version, contributes an UNRESOLVED copy.
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
//   - An unparseable manifest degrades Partiality to declared-partial (tool_failure), and
//     every requested coordinate becomes Found and UNRESOLVED: the broken file could declare
//     any package at any version.
//
// "plugin resolves, pipeline ranges" symmetry: this op resolves only the concrete installed
// literal version. Advisory RANGE matching (NuGet interval ordering) is applied by the
// pipeline disqualification predicate (pipeline/nuget_version.go), never here.
//
// Several copies of one package (two projects, two target frameworks, a lockfile beside a
// project file): installedCopies decides which copies each project actually installs. See
// its doc comment for the rules.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	res, copies, parseFailed, err := installedSet(req)
	if err != nil {
		return plugin.DependencyVersionResult{}, err
	}
	want := normalizeNuGetCoordinate(req.Coordinate)
	if want == "" {
		return res, nil
	}
	res.Match, res.Found = agreeNuGet(copies, want)
	// Presence keeps the first resolved copy, agreement or not: a malicious-package advisory
	// is affected by any copy at a listed version.
	for _, d := range res.All {
		if d.Resolved && normalizeNuGetCoordinate(d.Coordinate) == want {
			res.Presence = &d
			break
		}
	}
	if parseFailed {
		// A manifest that doesn't parse could declare want at any version.
		if !res.Found {
			res.Match = plugin.ResolvedDependency{Coordinate: strings.TrimSpace(req.Coordinate)}
		}
		res.Found = true
		res.Match.Version = ""
		res.Match.Resolved = false
	}
	return res, nil
}

// installedSet reads every manifest under req.BuildDir and returns the result without a
// Match (Partiality, All and Matches), the copies of the requested package installedCopies kept, and
// whether a manifest or restore output failed to parse.
func installedSet(req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, []nugetCopy, bool, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, nil, false, fmt.Errorf("dotnetanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, nil, false, fmt.Errorf("dotnetanalysis: build dir %q is not a directory", req.BuildDir)
	}

	manifests, walkFailed := manifestFiles(req.BuildDir)
	rootReal := realRoot(req.BuildDir)
	want := normalizeNuGetCoordinate(req.Coordinate)
	locked := make(map[string]bool)
	for _, m := range manifests {
		if manifestKind(filepath.Base(m)) == kindLock {
			locked[filepath.Dir(m)] = true
		}
	}

	var (
		all         []plugin.ResolvedDependency
		matches     []plugin.ResolvedDependency
		copies      []nugetCopy
		locks       = make(map[string]*lockFile)
		projectList []string
		projects    = make(map[string]*projectDir)
		configs     = make(map[string]bool)
		// A subtree the walk couldn't list could hold a manifest declaring any package at any
		// version, as a manifest that doesn't parse could.
		parseFailed = walkFailed
	)
	for _, m := range manifests {
		entries, lock, ok := parseManifest(rootReal, m)
		if !ok {
			parseFailed = true
		}
		dir := filepath.Dir(m)
		kind := manifestKind(filepath.Base(m))
		switch kind {
		case kindLock:
			if ok {
				locks[dir] = lock
			}
		case kindConfig:
			configs[dir] = true
		case kindProject:
			if projects[dir] == nil {
				projects[dir] = &projectDir{}
			}
			projects[dir].files = append(projects[dir].files, m)
			projectList = append(projectList, m)
		}
		for _, e := range entries {
			all = append(all, e.dep)
			copies = append(copies, nugetCopy{dep: e.dep, dir: dir, kind: kind})
			// Matches is the evidence as declared: every manifest's copy of want, except a
			// project file's beside the packages.lock.json that pins what it references.
			if want != "" && normalizeNuGetCoordinate(e.dep.Coordinate) == want && (kind != kindProject || !locked[dir]) {
				matches = append(matches, e.dep)
			}
		}
	}

	var reasons []string
	if want != "" && !parseFailed {
		var ok bool
		ev := newEvaluator(req.BuildDir, projectList)
		copies, reasons, ok = installedCopies(ev, copies, locks, projects, configs, want, strings.TrimSpace(req.Coordinate))
		if !ok {
			parseFailed = true
		}
	}

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	case len(reasons) > 0:
		part = plugin.Partial(reasons...)
	}

	// MatchesComplete stays false. MSBuild can add or re-version a PackageReference from inputs
	// this reader does not model (an SDK's props and targets, a build-time property), so no set
	// of copies it reads is known to be the whole build.
	return plugin.DependencyVersionResult{Partiality: part, All: all, Matches: matches}, copies, parseFailed, nil
}

// nugetCopy is one manifest entry together with where it came from, which installedCopies
// needs to tell a project file's own lockfile from another project's.
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

// agreeNuGet selects the Match for the normalized coordinate want from the copies
// installedCopies kept, the unknown copies included. The Match is resolved only when every copy
// is resolved and all name the same version: a build with one patched project and one affected
// one must not be ruled not-affected on the copy that happens to sit outside the range.
func agreeNuGet(copies []nugetCopy, want string) (plugin.ResolvedDependency, bool) {
	var (
		match    plugin.ResolvedDependency
		found    bool
		unknown  bool
		versions = map[string]struct{}{}
	)
	for _, c := range copies {
		d := c.dep
		if normalizeNuGetCoordinate(d.Coordinate) != want {
			continue
		}
		if !found {
			match, found = d, true
		}
		if !d.Resolved {
			unknown = true
			continue
		}
		if len(versions) == 0 {
			match = d
		}
		versions[d.Version] = struct{}{}
	}
	if found && (unknown || len(versions) != 1) {
		match.Version = ""
		match.Resolved = false
	}
	return match, found
}

// manifestFiles returns every recognized .NET manifest under root, skipping build-output /
// package / VCS trees so a restored copy does not shadow the project's own manifest. failed is
// set when some part of the tree couldn't be listed or examined.
func manifestFiles(root string) (out []string, failed bool) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if !os.IsNotExist(err) {
				failed = true
			}
			return nil //nolint:nilerr // keep walking; the caller reports the subtree as unread.
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
	return out, failed
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

// manifestEntry is one parsed manifest entry and, for a project file, its declared version.
type manifestEntry struct {
	dep  plugin.ResolvedDependency
	spec string
}

// parseManifest dispatches on the manifest's name to the format-specific parser. The lock is
// set only for packages.lock.json. The bool is false when the file cannot be read (readInput:
// a regular file inside the build tree) or is structurally unparseable (the caller degrades
// partiality and vetoes).
func parseManifest(rootReal, path string) ([]manifestEntry, *lockFile, bool) {
	data, _, st := readInput(rootReal, path)
	if st != inputRead {
		return nil, nil, false
	}
	base := filepath.Base(path)
	switch {
	case base == "packages.lock.json":
		deps, lock, ok := parsePackagesLock(data)
		return entriesOf(deps), lock, ok
	case base == "packages.config":
		deps, ok := parsePackagesConfig(data)
		return entriesOf(deps), nil, ok
	default: // *.csproj / *.fsproj / *.vbproj
		entries, ok := parseProjectFile(data)
		return entries, nil, ok
	}
}

func entriesOf(deps []plugin.ResolvedDependency) []manifestEntry {
	out := make([]manifestEntry, 0, len(deps))
	for _, d := range deps {
		out = append(out, manifestEntry{dep: d})
	}
	return out
}

// --- .csproj / .fsproj / .vbproj (XML) ---------------------------------------

// specUnread is the declared version of a reference this reader can't pin down. It never
// normalizes, so no lockfile covers it.
const specUnread = "unread"

// csprojRefs is every PackageReference Include and Version of a project file, read without
// judging anything else in it.
type csprojRefs struct {
	ItemGroups []struct {
		Refs []struct {
			Include     string `xml:"Include,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
		} `xml:"PackageReference"`
	} `xml:"ItemGroup"`
}

// parseProjectFile parses a .csproj/.fsproj/.vbproj with parseMSBuild. Only the exact-bracket
// Version "[1.2.3]" resolves. A plain Version "1.2.3" is a minimum (NuGet restores the lowest
// available version at or above it, NU1603), so it is UNRESOLVED unless a current lock covers
// it, like a range, a floating version, an empty Version (Central Package Management — the version lives in
// Directory.Packages.props) or a reference parseMSBuild reads as specUnread is UNRESOLVED.
// Each entry carries the declared version (Version, else VersionOverride) for the lock
// staleness check. A file parseMSBuild can't model still lists its PackageReferences, each with
// its pin as written for evidence (Matches) and its declared version specUnread; installedCopies
// never keeps a project file's copy, and reports why for the requested package. The bool is false only
// when the XML doesn't parse.
func parseProjectFile(data []byte) ([]manifestEntry, bool) {
	if mf, ok := parseMSBuild(data, roleProject, "csproj"); ok {
		return slices.Concat(mf.refs, mf.globals), true
	}
	var proj csprojRefs
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, false
	}
	var out []manifestEntry
	for _, ig := range proj.ItemGroups {
		for _, r := range ig.Refs {
			if name := strings.TrimSpace(r.Include); name != "" && !strings.ContainsAny(name, ";*?$@%") {
				raw := strings.TrimSpace(r.VersionAttr)
				if raw == "" {
					raw = strings.TrimSpace(r.VersionElem)
				}
				ver, resolved := packageReferencePin(raw)
				out = append(out, manifestEntry{dep: nugetResolved(name, ver, resolved, "csproj"), spec: specUnread})
			}
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

func withinDir(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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

// nugetRange puts a PackageReference version, or a lock entry's "requested", in one form so the
// two compare: a plain version is the minimum "[v, )", an exact pin "[v]" is "[v, v]", and each
// version is normalized (nugetVersion). ok is false for a spec it can't put in that form, such as
// a floating version.
func nugetRange(spec string) (string, bool) {
	s := strings.ReplaceAll(strings.TrimSpace(spec), " ", "")
	if s == "" || strings.Contains(s, "*") {
		return "", false
	}
	if s[0] != '[' && s[0] != '(' {
		v, ok := nugetVersion(s)
		if !ok {
			return "", false
		}
		return "[" + v + ", )", true
	}
	if len(s) < 2 || s[len(s)-1] != ']' && s[len(s)-1] != ')' {
		return "", false
	}
	lower, upper, interval := strings.Cut(s[1:len(s)-1], ",")
	if !interval {
		if s[0] != '[' || s[len(s)-1] != ']' {
			return "", false
		}
		v, ok := nugetVersion(lower)
		if !ok {
			return "", false
		}
		return "[" + v + ", " + v + "]", true
	}
	if lower == "" && upper == "" {
		return "", false
	}
	var lo, hi string
	for _, b := range []struct {
		raw string
		out *string
	}{{lower, &lo}, {upper, &hi}} {
		if b.raw == "" {
			continue
		}
		v, ok := nugetVersion(b.raw)
		if !ok {
			return "", false
		}
		*b.out = v
	}
	return s[:1] + lo + ", " + hi + s[len(s)-1:], true
}

// nugetVersion normalizes a NuGet version the way NuGet writes one: at least three numeric parts,
// a fourth only when it isn't zero, a lowercased release label and no build metadata.
func nugetVersion(v string) (string, bool) {
	v, _, _ = strings.Cut(v, "+")
	core, label, prerelease := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 4 || prerelease && label == "" {
		return "", false
	}
	nums := make([]string, 0, 4)
	for _, part := range parts {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return "", false
		}
		nums = append(nums, strconv.FormatUint(n, 10))
	}
	for len(nums) < 3 {
		nums = append(nums, "0")
	}
	if len(nums) == 4 && nums[3] == "0" {
		nums = nums[:3]
	}
	out := strings.Join(nums, ".")
	if prerelease {
		out += "-" + strings.ToLower(label)
	}
	return out, true
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
