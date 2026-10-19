package dotnetanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/html/charset"

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

	manifests, walkFailed := manifestFiles(req.BuildDir)

	var (
		all []plugin.ResolvedDependency
		// A subtree the walk couldn't list could hold a manifest declaring any package at any
		// version, as a manifest that doesn't parse could.
		parseFailed = walkFailed
	)
	for _, m := range manifests {
		deps, ok := parseManifest(m)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
	}

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	res := plugin.DependencyVersionResult{Partiality: part, All: all}
	if want := normalizeNuGetCoordinate(req.Coordinate); want != "" {
		res.Match, res.Found = matchCoordinate(manifests, want)
		// Presence keeps the first resolved copy, agreement or not: a malicious-package advisory
		// is affected by any copy at a listed version.
		for _, d := range all {
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
	}
	return res, nil
}

// matchCoordinate selects the Match for the normalized package id want across every copy of it
// in manifests. A packages.config version and every packages.lock.json entry for want, in each
// target framework, count as written. A lock stands for the one project file beside it only while
// it is current (lockCurrent); a packages.config stands for the legacy project beside it
// (packagesConfigGoverns), and counts only when one is there or no project is. Any other
// project file contributes through readProject. The Match is resolved only when every copy is
// resolved, every manifest in scope parses, every project file not stood for is one this reader
// models, and all the copies name the same version: a build with one patched project and one
// affected one must not be ruled not-affected on the copy that happens to sit outside the range.
// A modeled project that references packages but not want directly could restore want
// transitively at any version, so it leaves the Match unresolved too.
func matchCoordinate(manifests []string, want string) (plugin.ResolvedDependency, bool) {
	var (
		match    plugin.ResolvedDependency
		found    bool
		unknown  bool
		opaque   bool
		versions = map[string]struct{}{}
	)
	add := func(d plugin.ResolvedDependency) {
		if normalizeNuGetCoordinate(d.Coordinate) != want {
			return
		}
		if !found {
			match, found = d, true
		}
		if !d.Resolved {
			unknown = true
			return
		}
		if len(versions) == 0 {
			match = d
		}
		versions[d.Version] = struct{}{}
	}
	projects, configs, locks := map[string]int{}, map[string][]plugin.ResolvedDependency{}, map[string]lockRead{}
	for _, m := range manifests {
		switch dir := filepath.Dir(m); filepath.Base(m) {
		case "packages.config":
			deps, ok := parseManifest(m)
			opaque = opaque || !ok
			configs[dir] = deps
		case "packages.lock.json":
			lr, ok := readLock(m, want)
			opaque = opaque || !ok
			for _, d := range lr.copies {
				add(d)
			}
			locks[dir] = lr
		default:
			projects[dir]++
		}
	}
	imports, governed := map[string]bool{}, map[string]bool{}
	for _, m := range manifests {
		dir := filepath.Dir(m)
		_, configured := configs[dir]
		switch base := filepath.Base(m); {
		case base == "packages.lock.json" || base == "packages.config":
		case configured && packagesConfigGoverns(m):
			// A packages.config project restores from packages.config, unless a Directory file
			// or an imported file gives it a PackageReference, which would make NuGet ignore
			// packages.config.
			governed[dir] = true
			opaque = opaque || implicitImport(m, imports) || !stockImportsOnly(m)
		default:
			p := readProject(m, want, imports)
			if lr, ok := locks[dir]; ok && projects[dir] == 1 && lockCurrent(lr, p) {
				continue
			}
			for _, d := range p.copies {
				add(d)
			}
			opaque = opaque || !p.modeled || (len(p.copies) == 0 && len(p.specs) > 0)
		}
	}
	for _, m := range manifests {
		if dir := filepath.Dir(m); filepath.Base(m) == "packages.config" && (governed[dir] || projects[dir] == 0) {
			for _, d := range configs[dir] {
				add(d)
			}
		}
	}
	if found && (unknown || opaque || len(versions) != 1) {
		match.Version = ""
		match.Resolved = false
	}
	return match, found
}

// packagesConfigGoverns reports whether the project at path restores from the packages.config
// beside it: a legacy project, with no SDK and no PackageReference anywhere in the file. NuGet
// ignores packages.config for an SDK-style project or one that uses PackageReference, so such a
// project is read as any other. A project that can't be read counts as one that doesn't, so it is
// read as any other too, and readProject leaves it unmodeled.
func packagesConfigGoverns(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || bytes.Contains(bytes.ToLower(data), []byte("packagereference")) {
		return false
	}
	var proj msbuildProject
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&proj); err != nil || proj.SDK != "" {
		return false
	}
	for _, c := range proj.Children {
		if c.SDK != "" || strings.EqualFold(c.XMLName.Local, "Sdk") {
			return false
		}
	}
	return true
}

// stockLegacyImports lists the imports a legacy project template carries, lowercased with
// backslash separators. Each is a file MSBuild ships, which adds no PackageReference.
var stockLegacyImports = map[string]bool{
	`$(msbuildextensionspath)\$(msbuildtoolsversion)\microsoft.common.props`: true,
	`$(msbuildtoolspath)\microsoft.csharp.targets`:                           true,
	`$(msbuildbinpath)\microsoft.csharp.targets`:                             true,
	`$(msbuildtoolspath)\microsoft.visualbasic.targets`:                      true,
	`$(msbuildbinpath)\microsoft.visualbasic.targets`:                        true,
}

// stockImportsOnly reports whether every <Import> in the project at path is one MSBuild ships
// (stockLegacyImports). Any other import, or an ImportGroup, could add a PackageReference this
// reader doesn't see, and then NuGet ignores packages.config. A project that can't be read
// doesn't count.
func stockImportsOnly(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var proj msbuildProject
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&proj); err != nil {
		return false
	}
	for _, c := range proj.Children {
		switch {
		case strings.EqualFold(c.XMLName.Local, "ImportGroup"):
			return false
		case strings.EqualFold(c.XMLName.Local, "Import"):
			if !stockLegacyImports[strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.Project), "/", `\`))] {
				return false
			}
		}
	}
	return true
}

// lockRead is a packages.lock.json read for matchCoordinate: every entry for want, one per target
// framework, and what the lock records as requested.
type lockRead struct {
	copies []plugin.ResolvedDependency
	// frameworks holds each target framework section, keyed lowercased, with its Direct ids mapped
	// to their "requested" range; a runtime-specific section ("net8.0/win-x64") is keyed whole.
	frameworks map[string]map[string]string
	// central is set when the lock records a CentralTransitive entry or another kind this reader
	// doesn't compare against the project.
	central bool
}

func readLock(path, want string) (lockRead, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return lockRead{}, false
	}
	var pl packagesLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return lockRead{}, false
	}
	lr := lockRead{frameworks: map[string]map[string]string{}}
	for _, tfm := range slices.Sorted(maps.Keys(pl.Dependencies)) {
		direct := map[string]string{}
		for _, name := range slices.Sorted(maps.Keys(pl.Dependencies[tfm])) {
			e := pl.Dependencies[tfm][name]
			switch {
			case strings.EqualFold(e.Type, "Project"):
				continue
			case strings.EqualFold(e.Type, "Direct"):
				direct[normalizeNuGetCoordinate(name)] = e.Requested
			case !strings.EqualFold(e.Type, "Transitive"):
				lr.central = true
			}
			if normalizeNuGetCoordinate(name) == want {
				lr.copies = append(lr.copies, nugetResolved(name, e.Resolved, e.Resolved != "", "packages.lock.json"))
			}
		}
		lr.frameworks[strings.ToLower(strings.TrimSpace(tfm))] = direct
	}
	return lr, true
}

// lockCurrent reports whether lr is what restore would write for the project p today, so that its
// entries are the project's installed set. NuGet re-locks a project whose lock no longer matches
// it, so lr is current only when: p is modeled with an exact declared set and no ProjectReference;
// the lock's framework sections are exactly p's target frameworks; each section's Direct ids are
// exactly p's PackageReference ids, and a runtime-specific section's are among them; and every
// Direct "requested" equals the declaration of its id (nugetRange).
func lockCurrent(lr lockRead, p projectRead) bool {
	if !p.modeled || !p.exact || p.projectRefs || lr.central || len(p.frameworks) == 0 {
		return false
	}
	sections := 0
	for tfm, direct := range lr.frameworks {
		base, _, rid := strings.Cut(tfm, "/")
		if !slices.Contains(p.frameworks, base) {
			return false
		}
		if !rid {
			sections++
			if len(direct) != len(p.specs) {
				return false
			}
		}
		for id, requested := range direct {
			got, ok := nugetRange(requested)
			if !ok {
				return false
			}
			specs := p.specs[id]
			if len(specs) == 0 {
				return false
			}
			for _, spec := range specs {
				if declared, ok := nugetRange(spec); !ok || declared != got {
					return false
				}
			}
		}
	}
	return sections == len(p.frameworks)
}

// projectRead is a project file read for matchCoordinate.
type projectRead struct {
	// copies holds each PackageReference to want, resolved when its version is an exact-bracket pin
	// and the project is modeled.
	copies []plugin.ResolvedDependency
	// modeled is set when this reader models the project whole: it parses, it uses a stock SDK, its
	// top level is only unconditional PropertyGroup and ItemGroup elements whose properties steer no
	// import (inertProperty), every PackageReference names its packages literally and none updates
	// or removes one, no reference to want carries a Condition or VersionOverride, and MSBuild
	// imports nothing beside it (implicitImport). A project that isn't modeled could add to or
	// rewrite a reference where this reader doesn't look.
	modeled bool
	// specs maps every package id the project references to each version it declares for it, and
	// exact is set when those are all the project declares: no reference carries a Condition, a
	// VersionOverride or a version this reader doesn't read whole.
	specs map[string][]string
	exact bool
	// frameworks lists the project's target frameworks, lowercased.
	frameworks  []string
	projectRefs bool
}

func readProject(path, want string, imports map[string]bool) projectRead {
	p := projectRead{specs: map[string][]string{}, exact: true}
	data, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	var proj msbuildProject
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&proj); err != nil {
		return p
	}
	p.modeled = stockSDK.MatchString(proj.SDK) && !implicitImport(path, imports)
	var tf, tfs string
	for _, g := range proj.Children {
		if g.Condition != "" {
			p.modeled = false
		}
		switch g.XMLName.Local {
		case "PropertyGroup":
			for _, prop := range g.Elems {
				p.modeled = p.modeled && inertProperty[prop.XMLName.Local]
				switch prop.XMLName.Local {
				case "TargetFramework":
					tf = prop.Value
				case "TargetFrameworks":
					tfs = prop.Value
				}
			}
		case "ItemGroup":
			for _, r := range g.Elems {
				if strings.EqualFold(r.XMLName.Local, "ProjectReference") {
					p.projectRefs = true
				}
				if !strings.EqualFold(r.XMLName.Local, "PackageReference") {
					continue
				}
				names, literal := packageNames(r.Include)
				if !literal || r.Update != "" || r.Remove != "" {
					p.modeled = false
				}
				raw := strings.TrimSpace(r.VersionAttr)
				plain := len(r.VersionElems) == 0 || raw == "" && len(r.VersionElems) == 1 && r.VersionElems[0].Condition == ""
				if len(r.VersionElems) > 0 {
					raw = strings.TrimSpace(r.VersionElems[0].Value)
				}
				if !plain || r.Condition != "" || r.VersionOverride != "" {
					p.exact = false
				}
				for n := range names {
					p.specs[n] = append(p.specs[n], raw)
				}
				if !names[want] {
					continue
				}
				if !plain || r.Condition != "" || r.VersionOverride != "" {
					p.modeled = false
				}
				ver, resolved := packageReferencePin(raw)
				p.copies = append(p.copies, nugetResolved(want, ver, resolved, "csproj"))
			}
		default:
			p.modeled = false
		}
	}
	if tfs == "" {
		tfs = tf
	}
	for _, f := range strings.Split(tfs, ";") {
		if f = strings.ToLower(strings.TrimSpace(f)); f != "" {
			p.frameworks = append(p.frameworks, f)
		}
	}
	if !p.modeled {
		for i := range p.copies {
			p.copies[i] = nugetResolved(p.copies[i].Coordinate, "", false, p.copies[i].Source)
		}
	}
	return p
}

// msbuildProject is a project file read for readProject: the SDK and every top-level element, with
// the properties, PackageReference and ProjectReference items of each group.
type msbuildProject struct {
	SDK      string `xml:"Sdk,attr"`
	Children []struct {
		XMLName   xml.Name
		Condition string `xml:"Condition,attr"`
		SDK       string `xml:"Sdk,attr"`
		Project   string `xml:"Project,attr"`
		// Elems holds a PropertyGroup's properties or an ItemGroup's items. MSBuild matches item
		// types without regard to case, so items are told apart with strings.EqualFold.
		Elems []struct {
			XMLName         xml.Name
			Value           string `xml:",chardata"`
			Include         string `xml:"Include,attr"`
			Update          string `xml:"Update,attr"`
			Remove          string `xml:"Remove,attr"`
			Condition       string `xml:"Condition,attr"`
			VersionAttr     string `xml:"Version,attr"`
			VersionOverride string `xml:"VersionOverride,attr"`
			VersionElems    []struct {
				Condition string `xml:"Condition,attr"`
				Value     string `xml:",chardata"`
			} `xml:"Version"`
		} `xml:",any"`
	} `xml:",any"`
}

// stockSDK matches the SDKs the .NET SDK ships (Microsoft.NET.Sdk, Microsoft.NET.Sdk.Web, ...). A
// project with no Sdk attribute is a legacy project, which needs an <Import> this reader rejects.
var stockSDK = regexp.MustCompile(`^Microsoft\.NET\.Sdk(\.[A-Za-z]+)*$`)

// inertProperty lists the project properties readProject accepts: each sets build or
// package metadata and names no file MSBuild imports. Any other property could point an import
// such as CustomAfterMicrosoftCommonTargets at a file that rewrites a PackageReference.
var inertProperty = map[string]bool{
	"TargetFramework": true, "TargetFrameworks": true, "OutputType": true, "Nullable": true,
	"ImplicitUsings": true, "RootNamespace": true, "AssemblyName": true, "LangVersion": true,
	"IsPackable": true, "IsTestProject": true, "IsPublishable": true, "Version": true,
	"VersionPrefix": true, "VersionSuffix": true, "AssemblyVersion": true, "FileVersion": true,
	"InformationalVersion": true, "PackageId": true, "Authors": true, "Company": true,
	"Product": true, "Description": true, "Copyright": true, "PackageLicenseExpression": true,
	"PackageProjectUrl": true, "RepositoryUrl": true, "RepositoryType": true, "PackageTags": true,
	"GenerateDocumentationFile": true, "TreatWarningsAsErrors": true, "WarningsAsErrors": true,
	"NoWarn": true, "WarningLevel": true, "Deterministic": true, "Optimize": true,
	"DebugType": true, "DebugSymbols": true, "PlatformTarget": true, "Platforms": true,
	"RuntimeIdentifier": true, "RuntimeIdentifiers": true, "SelfContained": true,
	"PublishSingleFile": true, "PublishTrimmed": true, "InvariantGlobalization": true,
	"AllowUnsafeBlocks": true, "CheckForOverflowUnderflow": true, "AnalysisLevel": true,
	"EnforceCodeStyleInBuild": true, "UserSecretsId": true, "ServerGarbageCollection": true,
	"ConcurrentGarbageCollection": true, "TieredPGO": true, "RollForward": true,
	"EnablePreviewFeatures": true, "UseWPF": true, "UseWindowsForms": true, "ProjectGuid": true,
}

// packageNames splits an item attribute into the normalized package ids it names. literal is
// false when the attribute could name an id this reader can't see: a property, item or metadata
// reference, or a wildcard.
func packageNames(attr string) (names map[string]bool, literal bool) {
	if strings.ContainsAny(attr, "$@%*?") {
		return nil, false
	}
	names = map[string]bool{}
	for _, n := range strings.Split(attr, ";") {
		if n = normalizeNuGetCoordinate(n); n != "" {
			names[n] = true
		}
	}
	return names, true
}

// implicitImport reports whether MSBuild imports, or reads arguments from, a file this reader
// doesn't model when it evaluates the project at path: a Directory.Build.props/.targets/.rsp or
// Directory.Packages.props in the project's directory or any ancestor, the project's .user file,
// or a <project>.*.props/.targets under its obj directory. imports caches the per-directory answer
// for the Directory files; a directory that can't be listed counts as one that holds them.
func implicitImport(path string, imports map[string]bool) bool {
	base := filepath.Base(path)
	if _, err := os.Lstat(path + ".user"); err == nil || !os.IsNotExist(err) {
		return true
	}
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(path), "obj"))
	if err != nil && !os.IsNotExist(err) {
		return true
	}
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, strings.ToLower(base)+".") && (strings.HasSuffix(n, ".props") || strings.HasSuffix(n, ".targets")) {
			return true
		}
	}
	for dir := filepath.Dir(path); ; {
		held, ok := imports[dir]
		if !ok {
			held = directoryImports(dir)
			imports[dir] = held
		}
		if held {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// directoryImports reports whether dir holds a file MSBuild picks up from every project at or
// below it, matched without regard to case, or can't be listed.
func directoryImports(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return !os.IsNotExist(err)
	}
	for _, e := range entries {
		for _, name := range []string{"Directory.Build.props", "Directory.Build.targets", "Directory.Build.rsp", "Directory.Packages.props"} {
			if strings.EqualFold(e.Name(), name) {
				return true
			}
		}
	}
	return false
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
	Type      string `json:"type"`
	Requested string `json:"requested"`
	Resolved  string `json:"resolved"`
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
			key := normalizeNuGetCoordinate(name)
			if seen[key] {
				continue // the same package across target frameworks — one entry suffices.
			}
			seen[key] = true
			out = append(out, nugetResolved(name, e.Resolved, e.Resolved != "", "packages.lock.json"))
		}
	}
	return out, true
}

// --- .csproj / .fsproj / .vbproj (XML) ---------------------------------------

// csprojProject is the subset of an SDK-style project file we read: the items under any
// ItemGroup, each with an Include (the package id) and a Version given either as an attribute or
// a child element. Only PackageReference items, matched without regard to case, are read.
type csprojProject struct {
	ItemGroups []struct {
		Items []struct {
			XMLName     xml.Name
			Include     string `xml:"Include,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
		} `xml:",any"`
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
		for _, pr := range ig.Items {
			name := strings.TrimSpace(pr.Include)
			if name == "" || !strings.EqualFold(pr.XMLName.Local, "PackageReference") {
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
