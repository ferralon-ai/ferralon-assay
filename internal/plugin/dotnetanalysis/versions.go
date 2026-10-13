package dotnetanalysis

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"maps"
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
	res.Match, res.Found = matchNuGet(copies, want)
	if parseFailed && want != "" {
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
// Match (Partiality and All), the copies of the requested package installedCopies kept, and
// whether a manifest or restore output failed to parse.
func installedSet(req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, []nugetCopy, bool, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, nil, false, fmt.Errorf("dotnetanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, nil, false, fmt.Errorf("dotnetanalysis: build dir %q is not a directory", req.BuildDir)
	}

	manifests := manifestFiles(req.BuildDir)

	var (
		all         []plugin.ResolvedDependency
		copies      []nugetCopy
		locks       = make(map[string]lockRequests)
		projects    = make(map[string]*projectDir)
		configs     = make(map[string]bool)
		parseFailed bool
	)
	for _, m := range manifests {
		entries, requested, ok := parseManifest(m)
		if !ok {
			parseFailed = true
		}
		dir := filepath.Dir(m)
		kind := manifestKind(filepath.Base(m))
		switch kind {
		case kindLock:
			if ok {
				locks[dir] = requested
			}
		case kindConfig:
			configs[dir] = true
		case kindProject:
			if projects[dir] == nil {
				projects[dir] = &projectDir{}
			}
			projects[dir].files = append(projects[dir].files, m)
		}
		for _, e := range entries {
			all = append(all, e.dep)
			copies = append(copies, nugetCopy{dep: e.dep, dir: dir, kind: kind})
		}
	}

	want := normalizeNuGetCoordinate(req.Coordinate)
	var reasons []string
	if want != "" && !parseFailed {
		var ok bool
		copies, reasons, ok = installedCopies(req.BuildDir, copies, locks, projects, configs, want, strings.TrimSpace(req.Coordinate))
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

	return plugin.DependencyVersionResult{Partiality: part, All: all}, copies, parseFailed, nil
}

// nugetCopy is one manifest entry together with where it came from, which installedCopies
// needs to tell a project file's own lockfile from another project's.
type nugetCopy struct {
	dep  plugin.ResolvedDependency
	dir  string
	kind string
}

// lockRequests maps a normalized package id to the "requested" range of each Direct entry for
// it in one packages.lock.json, one per target, and likewise for each CentralTransitive entry
// (a transitive package pinned by a central PackageVersion); "" records an entry with no
// requested.
type lockRequests struct {
	direct, transitive map[string][]string
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

// matchNuGet selects the Match for the normalized coordinate want from the copies
// installedCopies kept. A resolved copy wins over an unresolved one for the same id.
//
// SEAM(agreement): whether several copies of one package agree (distinct versions, or any
// unresolved copy beside a resolved one) is the shared agreement rule's call, not this
// lane's. Once that predicate is on main, this selection hands it the copies installedCopies
// kept, the unknown copies included, instead of picking one here.
func matchNuGet(copies []nugetCopy, want string) (plugin.ResolvedDependency, bool) {
	var (
		match plugin.ResolvedDependency
		found bool
	)
	if want == "" {
		return match, found
	}
	for _, c := range copies {
		if normalizeNuGetCoordinate(c.dep.Coordinate) == want {
			match, found = c.dep, true
			if c.dep.Resolved {
				break
			}
		}
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

// manifestEntry is one parsed manifest entry and, for a project file, its declared version.
type manifestEntry struct {
	dep  plugin.ResolvedDependency
	spec string
}

// parseManifest dispatches on the manifest's name to the format-specific parser. The lock
// requests are set only for packages.lock.json. The bool is false when the file cannot be
// read or is structurally unparseable (the caller degrades partiality and vetoes).
func parseManifest(path string) ([]manifestEntry, lockRequests, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, lockRequests{}, false
	}
	base := filepath.Base(path)
	switch {
	case base == "packages.lock.json":
		deps, requested, ok := parsePackagesLock(data)
		return entriesOf(deps), requested, ok
	case base == "packages.config":
		deps, ok := parsePackagesConfig(data)
		return entriesOf(deps), lockRequests{}, ok
	default: // *.csproj / *.fsproj / *.vbproj
		entries, ok := parseProjectFile(data)
		return entries, lockRequests{}, ok
	}
}

func entriesOf(deps []plugin.ResolvedDependency) []manifestEntry {
	out := make([]manifestEntry, 0, len(deps))
	for _, d := range deps {
		out = append(out, manifestEntry{dep: d})
	}
	return out
}

// --- packages.lock.json (JSON) -----------------------------------------------

// packagesLock is the subset of packages.lock.json we read: a per-framework map of package
// name → entry with the exact "resolved" version (present for both Direct and Transitive).
type packagesLock struct {
	Dependencies map[string]map[string]packagesLockEntry `json:"dependencies"`
}

type packagesLockEntry struct {
	Type      string `json:"type"`
	Requested string `json:"requested"`
	Resolved  string `json:"resolved"`
}

// parsePackagesLock parses packages.lock.json. Every entry (Direct or Transitive) carries an
// exact "resolved" version, so a present resolved field resolves; a missing one is
// UNRESOLVED. A "Project" reference (a sibling project, not a NuGet package) has no resolved
// version and is skipped.
//
// Each target framework (and each <tfm>/<rid> target) is its own resolution, and they can
// disagree (net6.0 → 13.0.1, net8.0 → 13.0.3). Every distinct (id, version) across them is
// kept so the split reaches the Match; only exact repeats collapse. Frameworks and ids are
// walked in sorted order so All is identical across runs. The "requested" range of every
// Direct entry is returned per id, one per target, for installedCopies' staleness check.
func parsePackagesLock(data []byte) ([]plugin.ResolvedDependency, lockRequests, bool) {
	var pl packagesLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, lockRequests{}, false
	}
	type idVersion struct{ id, version string }
	seen := make(map[idVersion]bool)
	requested := lockRequests{direct: make(map[string][]string), transitive: make(map[string][]string)}
	var out []plugin.ResolvedDependency
	for _, tfm := range slices.Sorted(maps.Keys(pl.Dependencies)) {
		pkgs := pl.Dependencies[tfm]
		for _, name := range slices.Sorted(maps.Keys(pkgs)) {
			e := pkgs[name]
			if strings.EqualFold(e.Type, "Project") {
				continue
			}
			id := normalizeNuGetCoordinate(name)
			switch {
			case strings.EqualFold(e.Type, "Direct"):
				requested.direct[id] = append(requested.direct[id], strings.TrimSpace(e.Requested))
			case strings.EqualFold(e.Type, "CentralTransitive"):
				requested.transitive[id] = append(requested.transitive[id], strings.TrimSpace(e.Requested))
			}
			d := nugetResolved(name, e.Resolved, e.Resolved != "", "packages.lock.json")
			k := idVersion{id, d.Version}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, d)
		}
	}
	return out, requested, true
}

// --- .csproj / .fsproj / .vbproj (XML) ---------------------------------------

// specUnread is the declared version of a reference this reader can't pin down. It never
// normalizes, so no lockfile covers it.
const specUnread = "unread"

// csprojRefs is every PackageReference Include of a project file, read without judging
// anything else in it.
type csprojRefs struct {
	ItemGroups []struct {
		Refs []struct {
			Include string `xml:"Include,attr"`
		} `xml:"PackageReference"`
	} `xml:"ItemGroup"`
}

// parseProjectFile parses a .csproj/.fsproj/.vbproj with parseMSBuild. Only the exact-bracket
// Version "[1.2.3]" resolves. A plain Version "1.2.3" is a minimum (NuGet restores the lowest
// available version at or above it, NU1603), so it is UNRESOLVED unless a current lock covers
// it, like a range, a floating version, an empty Version (Central Package Management — the version lives in
// Directory.Packages.props) or a reference parseMSBuild reads as specUnread is UNRESOLVED.
// Each entry carries the declared version (Version, else VersionOverride) for the lock
// staleness check. A file parseMSBuild can't model still lists its PackageReference ids, all
// UNRESOLVED; installedCopies reports why for the requested package. The bool is false only
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
				out = append(out, manifestEntry{dep: nugetResolved(name, "", false, "csproj"), spec: specUnread})
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

// centralVersions returns a lookup of the Central Package Management versions that apply to
// a project directory: the PackageVersion entries of the nearest Directory.Packages.props at
// or above it, bounded by root. MSBuild imports only that nearest file. The bool is false when
// there is no such file or readCentralVersions can't read all of it. An id given conflicting versions in the
// file maps to "" so it covers nothing.
func centralVersions(root string) func(dir string) (map[string]string, bool) {
	root = filepath.Clean(root)
	return func(dir string) (map[string]string, bool) {
		for dir = filepath.Clean(dir); ; {
			p := filepath.Join(dir, "Directory.Packages.props")
			if _, err := os.Stat(p); err == nil {
				return readCentralVersions(p)
			}
			if dir == root {
				return nil, false
			}
			parent := filepath.Dir(dir)
			if parent == dir || !withinDir(root, parent) {
				return nil, false
			}
			dir = parent
		}
	}
}

// readCentralVersions reads the PackageVersion entries of one Directory.Packages.props. It
// models only a plain file: a Project holding ItemGroups of PackageVersion Include/Version
// items and PropertyGroups of literal properties. GlobalPackageReference Include/Version
// items are allowed and skipped; declaredRefs reads them as references every project gets.
// Anything else can change which version ships without this reader seeing it: an Update or Remove item, an Import, a Condition, an
// SDK, an Include that expands to several items, another item type, or an explicit
// ManagePackageVersionsCentrally of false. Any of those, or any element or attribute not
// listed here, makes the whole file unreadable, so it covers nothing. A property-valued
// version is kept as written; it never equals the range restore records, so it covers nothing
// either.
func readCentralVersions(path string) (map[string]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	out := make(map[string]string)
	d := xml.NewDecoder(strings.NewReader(string(data)))
	var stack []string
	var item string
	var version, text strings.Builder
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			allowed := map[string]bool{"Label": true}
			switch path := strings.Join(stack, "/"); {
			case path == "Project":
				allowed = map[string]bool{"xmlns": true, "ToolsVersion": true}
			case path == "Project/ItemGroup", path == "Project/PropertyGroup":
			case path == "Project/ItemGroup/PackageVersion":
				allowed["Include"], allowed["Version"] = true, true
				item = ""
				version.Reset()
			case path == "Project/ItemGroup/PackageVersion/Version":
			case path == "Project/ItemGroup/GlobalPackageReference":
				allowed["Include"], allowed["Version"] = true, true
			case len(stack) == 3 && stack[1] == "PropertyGroup":
				text.Reset()
			default:
				return nil, false
			}
			for _, a := range t.Attr {
				if a.Name.Space != "xmlns" && (a.Name.Space != "" || !allowed[a.Name.Local]) {
					return nil, false
				}
				switch {
				case len(stack) == 3 && a.Name.Local == "Include":
					item = a.Value
				case len(stack) == 3 && a.Name.Local == "Version":
					version.WriteString(a.Value)
				}
			}
		case xml.CharData:
			switch {
			case len(stack) == 4:
				version.Write(t)
			case len(stack) == 3 && stack[1] == "PropertyGroup":
				text.Write(t)
			case strings.TrimSpace(string(t)) != "":
				return nil, false
			}
		case xml.EndElement:
			switch {
			case len(stack) == 3 && stack[2] == "PackageVersion":
				if strings.ContainsAny(item, ";*?$@%") {
					return nil, false
				}
				id := normalizeNuGetCoordinate(item)
				v := strings.TrimSpace(version.String())
				if prev, seen := out[id]; seen && prev != v {
					v = ""
				}
				out[id] = v
			case len(stack) == 3 && stack[2] == "ManagePackageVersionsCentrally":
				if strings.EqualFold(strings.TrimSpace(text.String()), "false") {
					return nil, false
				}
			}
			stack = stack[:len(stack)-1]
		case xml.Directive:
			return nil, false
		}
	}
	return out, true
}

func withinDir(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// nugetRange is a NuGet version range in comparable form.
type nugetRange struct {
	minIncl, maxIncl bool
	min, max         string
}

// normalizeNuGetRange parses a NuGet version spec into comparable form, so a project's
// declaration and a lockfile's "requested" ("13.0.3" vs "[13.0.3, )") compare equal when they
// mean the same range. A bare version is a minimum, inclusive. Versions are padded to three
// parts with a zero fourth part dropped; floating versions are kept literally, so they match
// only the same float. The bool is false for anything else it can't parse, including MSBuild
// property references.
func normalizeNuGetRange(spec string) (nugetRange, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nugetRange{}, false
	}
	lb, rb := spec[0], spec[len(spec)-1]
	if lb != '[' && lb != '(' {
		v, ok := normalizeNuGetVersion(spec)
		return nugetRange{minIncl: true, min: v}, ok
	}
	if len(spec) < 2 || (rb != ']' && rb != ')') {
		return nugetRange{}, false
	}
	inner := spec[1 : len(spec)-1]
	lo, hi, isRange := strings.Cut(inner, ",")
	if !isRange {
		if lb != '[' || rb != ']' {
			return nugetRange{}, false
		}
		v, ok := normalizeNuGetVersion(inner)
		return nugetRange{minIncl: true, maxIncl: true, min: v, max: v}, ok
	}
	r := nugetRange{minIncl: lb == '[', maxIncl: rb == ']'}
	lo, hi = strings.TrimSpace(lo), strings.TrimSpace(hi)
	if lo == "" && hi == "" {
		return nugetRange{}, false
	}
	var ok bool
	if lo != "" {
		if r.min, ok = normalizeNuGetVersion(lo); !ok {
			return nugetRange{}, false
		}
	}
	if hi != "" {
		if r.max, ok = normalizeNuGetVersion(hi); !ok {
			return nugetRange{}, false
		}
	}
	return r, true
}

func normalizeNuGetVersion(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "", false
	}
	if strings.Contains(v, "*") {
		return v, true
	}
	v, _, _ = strings.Cut(v, "+")
	core, pre, hasPre := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 4 {
		return "", false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return "", false
		}
		parts[i] = strconv.FormatUint(n, 10)
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	if len(parts) == 4 && parts[3] == "0" {
		parts = parts[:3]
	}
	out := strings.Join(parts, ".")
	if hasPre {
		if pre == "" {
			return "", false
		}
		out += "-" + pre
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
