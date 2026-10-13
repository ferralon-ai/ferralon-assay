package dotnetanalysis

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Lane-local reasons for a project whose installed copy of the requested package can't be
// read, so the version resolver reports it unresolved.
const (
	// reasonLockfileStale: the project's packages.lock.json no longer matches what the project
	// declares, so restore re-locks it and the lock's pins are not what ships.
	reasonLockfileStale = "lockfile_stale"

	// reasonPackageReferenceUnmodeled: a file that declares the project's package references
	// (the project file, a file it imports, a Directory.Build.props/.targets or
	// Directory.Packages.props) holds something readMSBuild doesn't model, so the declared set
	// is not fully known.
	reasonPackageReferenceUnmodeled = "package_reference_unmodeled"
)

// projectDir is the project file(s) found in one directory.
type projectDir struct {
	files []string
}

// installedCopies replaces each project's declared copies of want with what restore installs
// for that project, where the tree records it, and adds an unknown copy for every project
// whose installed copy can't be read. A version the tree doesn't fully determine never
// reaches matchNuGet as a resolved copy. Per project directory:
//
//   - obj/project.assets.json, when present, is restore's output: its packages are the
//     installed set, and the directory's project and lockfile copies are dropped. An
//     unreadable assets file returns ok=false (the caller vetoes).
//   - Otherwise a packages.lock.json is the installed set only while it is current: its
//     Direct ids are exactly the ids the project declares (its own PackageReferences plus
//     those injected through Directory.Build.props/.targets, followed imports and
//     GlobalPackageReference), and every Direct entry's "requested" equals the declared
//     range. A version-less reference declares the nearest Directory.Packages.props
//     PackageVersion, and every CentralTransitive entry's "requested" must equal the
//     PackageVersion that pins it. Restore re-locks a project that no longer matches, so a stale lock's
//     copies are dropped.
//   - Otherwise only a direct declaration of want decides (NuGet's direct-dependency-wins); a
//     project that declares other packages but not want, or declares want only under a
//     Condition, may pull any version of it transitively, so it adds an unknown copy.
//   - A project whose declarations can't all be read adds an unknown copy.
//   - A packages.config project (no PackageReference) keeps its packages.config, the complete
//     legacy set. A lockfile or packages.config with no project file beside it counts as is.
//
// Two project files in one directory share obj/ and the lock, so neither is attributed.
// The reasons name every unknown copy added.
func installedCopies(root string, copies []nugetCopy, locks map[string]lockRequests, projects map[string]*projectDir, configs map[string]bool, want, coordinate string) ([]nugetCopy, []string, bool) {
	central := centralVersions(root)
	var (
		extra   []nugetCopy
		reasons []string
		current = make(map[string]bool)
	)
	unknown := func(dir, reason string) {
		extra = append(extra, nugetCopy{dep: plugin.ResolvedDependency{Coordinate: coordinate, Source: reason}, dir: dir, kind: kindProject})
		if !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
	for _, dir := range slices.Sorted(maps.Keys(projects)) {
		p := projects[dir]
		single := len(p.files) == 1
		if single {
			deps, present, ok := assetsCopies(dir, want)
			if !ok {
				return nil, nil, false
			}
			if present {
				for _, d := range deps {
					extra = append(extra, nugetCopy{dep: d, dir: dir, kind: kindAssets})
				}
				continue
			}
		}
		decl, tractable := declaredRefs(root, dir, p.files, configs[dir])
		if !tractable {
			unknown(dir, reasonPackageReferenceUnmodeled)
			continue
		}
		for _, e := range slices.Concat(decl.own, decl.injected) {
			if normalizeNuGetCoordinate(e.dep.Coordinate) == want {
				extra = append(extra, nugetCopy{dep: e.dep, dir: dir, kind: kindProject})
			}
		}
		lr, hasLock := locks[dir]
		if hasLock && single {
			versions, _ := central(dir)
			if lockCurrent(lr, decl.specs, versions) {
				current[dir] = true
				continue
			}
		}
		if decl.unconditional[want] || len(decl.specs) == 0 {
			continue
		}
		if hasLock {
			unknown(dir, reasonLockfileStale)
		} else {
			unknown(dir, reasonNoLockfile)
		}
	}

	out := make([]nugetCopy, 0, len(copies)+len(extra))
	for _, c := range copies {
		switch {
		case c.kind == kindProject:
			continue
		case c.kind == kindLock && projects[c.dir] != nil && !current[c.dir]:
			continue
		}
		out = append(out, c)
	}
	for _, c := range extra {
		if c.kind == kindProject && current[c.dir] {
			continue
		}
		out = append(out, c)
	}
	return out, reasons, true
}

// kindAssets marks a copy read from a project's obj/project.assets.json.
const kindAssets = "assets"

// assetsCopies reads dir/obj/project.assets.json and returns every package copy of want it
// records, one per distinct version across targets. present is false when there is no such
// file; ok is false when it exists but can't be read or has no targets.
func assetsCopies(dir, want string) (deps []plugin.ResolvedDependency, present, ok bool) {
	data, err := os.ReadFile(filepath.Join(dir, "obj", "project.assets.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, true
	}
	if err != nil {
		return nil, true, false
	}
	g := parseAssetsGraph(data)
	if g == nil || g.targets == nil {
		return nil, true, false
	}
	seen := make(map[string]bool)
	for _, target := range slices.Sorted(maps.Keys(g.targets)) {
		libs := g.targets[target]
		for _, key := range slices.Sorted(maps.Keys(libs)) {
			if strings.EqualFold(libs[key].Type, "project") {
				continue
			}
			id, ver := splitPkgKey(key)
			if normalizeNuGetCoordinate(id) != want || seen[ver] {
				continue
			}
			seen[ver] = true
			deps = append(deps, nugetResolved(id, ver, ver != "", "project.assets.json"))
		}
	}
	return deps, true, true
}

// lockCurrent reports whether a project's lockfile still matches what the project declares:
// the Direct ids are exactly the declared ids, every Direct "requested" equals each
// declaration of its id, and every CentralTransitive "requested" equals the central
// PackageVersion of its id. A version-less declaration reads central (the nearest
// Directory.Packages.props; nil when there is none or it can't be read, which matches nothing).
func lockCurrent(lr lockRequests, specs map[string][]string, central map[string]string) bool {
	if len(lr.direct) != len(specs) {
		return false
	}
	for id, reqs := range lr.transitive {
		if !sameRanges(central[id], reqs) {
			return false
		}
	}
	for id, declared := range specs {
		for _, spec := range declared {
			if spec == "" {
				spec = central[id]
			}
			if !sameRanges(spec, lr.direct[id]) {
				return false
			}
		}
	}
	return true
}

// sameRanges reports whether reqs is non-empty and every range in it equals spec.
func sameRanges(spec string, reqs []string) bool {
	want, ok := normalizeNuGetRange(spec)
	if !ok || len(reqs) == 0 {
		return false
	}
	for _, r := range reqs {
		if got, ok := normalizeNuGetRange(r); !ok || got != want {
			return false
		}
	}
	return true
}

// declaration is everything a project declares: the declared version spec of each id
// (normalized), the ids declared without any Condition, and the entries that reach it from
// a file other than the project itself.
type declaration struct {
	specs         map[string][]string
	unconditional map[string]bool
	own           []manifestEntry
	injected      []manifestEntry
}

// declaredRefs gathers what the project files in dir declare, the way MSBuild assembles it:
// each project file, the files it imports, the nearest Directory.Build.props and
// Directory.Build.targets (and the parents they chain to), and the nearest
// Directory.Packages.props, reading PackageReference and GlobalPackageReference items from
// each. tractable is false when any part of that can't be read completely, or a file other
// than Directory.Packages.props declares a PackageVersion (which can move a central version
// this read doesn't follow); the declared set is then unknown. A reference under a Condition, or in a file imported
// under one, is declared but not unconditional. A packages.config project's own imports are
// not followed: they are the legacy toolset and package build targets, and its packages
// come from packages.config.
func declaredRefs(root, dir string, files []string, legacy bool) (declaration, bool) {
	decl := declaration{specs: make(map[string][]string), unconditional: make(map[string]bool)}
	add := func(mf msbuildFile, injected, conditioned bool) {
		for _, e := range slices.Concat(mf.refs, mf.globals) {
			if conditioned {
				e = manifestEntry{dep: nugetResolved(e.dep.Coordinate, "", false, e.dep.Source), spec: specUnread}
			}
			id := normalizeNuGetCoordinate(e.dep.Coordinate)
			decl.specs[id] = append(decl.specs[id], e.spec)
			if e.spec != specUnread {
				decl.unconditional[id] = true
			}
			if injected {
				decl.injected = append(decl.injected, e)
			} else {
				decl.own = append(decl.own, e)
			}
		}
	}
	for _, f := range files {
		mf, ok := readMSBuild(f, roleProject)
		if !ok {
			return decl, false
		}
		add(mf, false, false)
		if legacy && len(mf.refs) == 0 && len(mf.globals) == 0 {
			continue
		}
		for _, imp := range mf.imports {
			if toolsetImport(imp.project) {
				continue
			}
			path := filepath.Join(dir, filepath.FromSlash(strings.ReplaceAll(imp.project, `\`, "/")))
			if !withinDir(root, path) {
				return decl, false
			}
			in, ok := readMSBuild(path, roleProject)
			if !ok || len(in.imports) > 0 {
				return decl, false
			}
			add(in, true, imp.conditioned)
		}
	}
	for _, name := range []string{"Directory.Build.props", "Directory.Build.targets"} {
		conditioned := false
		for from := dir; ; {
			path, found := nearestAbove(root, from, name)
			if !found {
				break
			}
			mf, ok := readMSBuild(path, roleProject)
			if !ok {
				return decl, false
			}
			add(mf, true, conditioned)
			chains := false
			for _, imp := range mf.imports {
				if !chainsToParent(imp.project, name) {
					return decl, false
				}
				chains = true
				conditioned = conditioned || imp.conditioned
			}
			if !chains {
				break
			}
			parent := filepath.Dir(filepath.Dir(path))
			if parent == filepath.Dir(path) || !withinDir(root, parent) {
				break
			}
			from = parent
		}
	}
	if path, found := nearestAbove(root, dir, "Directory.Packages.props"); found {
		mf, ok := readMSBuild(path, roleCentral)
		if !ok || len(mf.imports) > 0 {
			return decl, false
		}
		add(mf, true, false)
	}
	return decl, true
}

// nearestAbove returns the nearest file called name at or above dir, bounded by root.
func nearestAbove(root, dir, name string) (string, bool) {
	root = filepath.Clean(root)
	for dir = filepath.Clean(dir); ; {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
		if dir == root {
			return "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir || !withinDir(root, parent) {
			return "", false
		}
		dir = parent
	}
}

// toolsetImport reports whether an Import names a file of the MSBuild/SDK installation,
// which declares no package references of the project's own.
func toolsetImport(project string) bool {
	for _, prefix := range []string{"$(MSBuildExtensionsPath", "$(MSBuildToolsPath", "$(MSBuildBinPath", "$(MSBuildSDKsPath", "$(VSToolsPath"} {
		if strings.HasPrefix(project, prefix) {
			return true
		}
	}
	return false
}

// chainsToParent reports whether a Directory.Build.* Import is the documented way of
// importing the same-named file above it.
func chainsToParent(project, name string) bool {
	p := strings.ReplaceAll(project, " ", "")
	return strings.Contains(p, "GetPathOfFileAbove('"+name+"'") || strings.Contains(p, "GetPathOfFileAbove(\""+name+"\"")
}

// msbuildFile is what readMSBuild reads from one MSBuild file.
type msbuildFile struct {
	refs    []manifestEntry
	globals []manifestEntry
	imports []msbuildImport
}

type msbuildImport struct {
	project     string
	conditioned bool
}

// msbuildRole is which kind of file readMSBuild reads, which decides what it may declare.
type msbuildRole int

const (
	// roleProject is a project file, a Directory.Build.props/.targets, or a file one of them
	// imports. None of them may declare a PackageVersion.
	roleProject msbuildRole = iota
	// roleCentral is Directory.Packages.props. Its PackageVersion items are skipped here;
	// readCentralVersions reads them.
	roleCentral
)

// restoreProperties are the properties (lowercased prefixes) that move where restore looks
// for versions, which central file or Directory.Build.* applies, or where its outputs live.
var restoreProperties = []string{
	"managepackageversionscentrally", "centralpackage", "importdirectory",
	"directorypackagesprops", "directorybuild", "custombeforedirectory", "customafterdirectory",
	"importprojectextension", "msbuildprojectextensionspath", "baseintermediateoutputpath",
	"projectassetsfile", "restoreoutputpath", "nugetlockfilepath",
	"restorepackageswithlockfile", "restorelockedmode",
}

// restoreToggles are the restore properties a file may set to a literal true or false without
// moving any version this reader reads.
var restoreToggles = []string{
	"centralpackagetransitivepinningenabled", "centralpackageversionoverrideenabled",
	"restorepackageswithlockfile", "restorelockedmode",
}

// readMSBuild reads the package references of one MSBuild file. It models only what it
// knows: a Project of PropertyGroups, ItemGroups, Imports and ImportGroups, with
// PackageReference and GlobalPackageReference items declared by Include (one literal
// package id) with Version and VersionOverride as attributes or metadata elements. Other item
// types, and Targets, UsingTasks, ItemDefinitionGroups and ProjectExtensions, are skipped,
// but only while nothing inside them names a package item. ok is false, and the file's
// declarations are unknown, for anything else that can change a reference:
//
//   - a Choose, or any element outside the shapes above;
//   - an Update, Remove or Exclude on a package item, or an Include that is empty, lists
//     several ids, or holds a wildcard or a $(property), @(item) or %(metadata) reference;
//   - a PackageVersion outside Directory.Packages.props;
//   - an SDK other than Microsoft.NET.Sdk*, which can bring references of its own;
//   - a restore property (restoreProperties), unless it is set without a Condition to a
//     literal true for ManagePackageVersionsCentrally or true/false for a restoreToggles one;
//   - a DOCTYPE, or text or attributes where none belong.
//
// Item types are matched without case, as MSBuild does. A reference under a Condition (on
// the item, its ItemGroup, or its Version or VersionOverride element) applies only sometimes,
// and one with more than one Version or VersionOverride is decided by evaluation order; both
// are read as unresolved with the declared version specUnread. A Condition on a property or
// on an item of another type can't move a package version, since a version or Include that
// refers to a property is never read as a literal.
func readMSBuild(path string, role msbuildRole) (msbuildFile, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return msbuildFile{}, false
	}
	return parseMSBuild(data, role, "msbuild")
}

func parseMSBuild(data []byte, role msbuildRole, source string) (msbuildFile, bool) {
	var (
		mf        msbuildFile
		stack     []string
		groupCond bool
		item      *msbuildPkgItem
		prop      string
		meta      string
		propCond  bool
		metaCond  bool
		text      strings.Builder
		skip      int
	)
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return msbuildFile{}, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			name, depth := t.Name.Local, len(stack)
			if skip > 0 || inertSubtree(depth, stack) {
				if skip == 0 {
					skip = depth
				}
				if packageItem(name) && !(role == roleCentral && depth == 3 && strings.EqualFold(name, "PackageVersion")) {
					return msbuildFile{}, false
				}
				for _, a := range t.Attr {
					v := strings.ToLower(a.Value)
					if strings.Contains(v, "packagereference") || strings.Contains(v, "packageversion") {
						return msbuildFile{}, false
					}
				}
				continue
			}
			attrs, ok := msbuildAttrs(t.Attr)
			if !ok {
				return msbuildFile{}, false
			}
			parent := ""
			if depth > 1 {
				parent = stack[depth-2]
			}
			switch {
			case depth == 1 && name == "Project":
				if !onlyAttrs(attrs, "sdk", "toolsversion", "defaulttargets", "initialtargets", "treataslocalproperty") {
					return msbuildFile{}, false
				}
				if sdk, set := attrs["sdk"]; set && !knownSDK(sdk) {
					return msbuildFile{}, false
				}
			case depth == 2 && (name == "PropertyGroup" || name == "ItemGroup" || name == "ImportGroup"):
				if !onlyAttrs(attrs, "label", "condition") {
					return msbuildFile{}, false
				}
				_, groupCond = attrs["condition"]
			case depth == 2 && name == "Sdk":
				if !onlyAttrs(attrs, "name", "version", "minimumversion") || !knownSDK(attrs["name"]) {
					return msbuildFile{}, false
				}
			case name == "Import" && (depth == 2 || depth == 3 && parent == "ImportGroup"):
				if !onlyAttrs(attrs, "project", "condition", "sdk", "label", "version", "minimumversion") {
					return msbuildFile{}, false
				}
				if sdk, set := attrs["sdk"]; set {
					if !knownSDK(sdk) {
						return msbuildFile{}, false
					}
					continue
				}
				project := strings.TrimSpace(attrs["project"])
				if project == "" {
					return msbuildFile{}, false
				}
				_, cond := attrs["condition"]
				mf.imports = append(mf.imports, msbuildImport{project: project, conditioned: cond || depth == 3 && groupCond})
			case depth == 3 && parent == "PropertyGroup":
				if !onlyAttrs(attrs, "condition") {
					return msbuildFile{}, false
				}
				_, cond := attrs["condition"]
				prop, propCond = strings.ToLower(name), cond || groupCond
				text.Reset()
			case depth == 3 && parent == "ItemGroup" && (strings.EqualFold(name, "PackageReference") || strings.EqualFold(name, "GlobalPackageReference")):
				item = &msbuildPkgItem{global: strings.EqualFold(name, "GlobalPackageReference"), conditioned: groupCond}
				for k, v := range attrs {
					switch k {
					case "update", "remove", "exclude":
						return msbuildFile{}, false
					case "include":
						item.include = v
					case "version":
						item.versions = append(item.versions, strings.TrimSpace(v))
					case "versionoverride":
						item.overrides = append(item.overrides, strings.TrimSpace(v))
					case "condition":
						item.conditioned = true
					}
				}
			case depth == 4 && item != nil:
				if !onlyAttrs(attrs, "condition") {
					return msbuildFile{}, false
				}
				_, metaCond = attrs["condition"]
				meta = strings.ToLower(name)
				text.Reset()
			default:
				return msbuildFile{}, false
			}
		case xml.CharData:
			switch {
			case skip > 0:
			case len(stack) == 3 && prop != "", len(stack) == 4 && item != nil:
				text.Write(t)
			case strings.TrimSpace(string(t)) != "":
				return msbuildFile{}, false
			}
		case xml.EndElement:
			depth := len(stack)
			stack = stack[:depth-1]
			switch {
			case skip > 0:
				if depth == skip {
					skip = 0
				}
			case depth == 4 && item != nil:
				v := strings.TrimSpace(text.String())
				switch meta {
				case "version":
					item.versions = append(item.versions, v)
				case "versionoverride":
					item.overrides = append(item.overrides, v)
				default:
					continue
				}
				if metaCond {
					item.conditioned = true
				}
			case depth == 3 && prop != "":
				if !restoreSafe(prop, propCond, strings.ToLower(strings.TrimSpace(text.String()))) {
					return msbuildFile{}, false
				}
				prop = ""
			case depth == 3 && item != nil:
				e, ok := item.entry(source)
				if !ok {
					return msbuildFile{}, false
				}
				if item.global {
					mf.globals = append(mf.globals, e)
				} else {
					mf.refs = append(mf.refs, e)
				}
				item = nil
			case depth == 2:
				groupCond = false
			}
		case xml.Directive:
			return msbuildFile{}, false
		}
	}
	return mf, true
}

// msbuildPkgItem is one PackageReference or GlobalPackageReference item as written.
type msbuildPkgItem struct {
	global              bool
	include             string
	versions, overrides []string
	conditioned         bool
}

// entry is the manifest entry the item declares; ok is false when its Include isn't one
// literal package id.
func (it *msbuildPkgItem) entry(source string) (manifestEntry, bool) {
	name := strings.TrimSpace(it.include)
	if name == "" || strings.ContainsAny(name, ";*?$@%") {
		return manifestEntry{}, false
	}
	if it.conditioned || len(it.versions) > 1 || len(it.overrides) > 1 {
		return manifestEntry{dep: nugetResolved(name, "", false, source), spec: specUnread}, true
	}
	var raw, override string
	if n := len(it.versions); n > 0 {
		raw = it.versions[n-1]
	}
	if n := len(it.overrides); n > 0 {
		override = it.overrides[n-1]
	}
	ver, resolved := exactNuGetPin(raw)
	spec := raw
	if spec == "" {
		spec = override
	}
	return manifestEntry{dep: nugetResolved(name, ver, resolved, source), spec: spec}, true
}

// inertSubtree reports whether the element at the top of stack starts a subtree that can't
// declare a package reference unless it names a package item: an item of another type, or a
// Target, UsingTask, ItemDefinitionGroup or ProjectExtensions.
func inertSubtree(depth int, stack []string) bool {
	name := stack[depth-1]
	switch {
	case depth == 2:
		return name == "Target" || name == "UsingTask" || name == "ItemDefinitionGroup" || name == "ProjectExtensions"
	case depth == 3 && stack[1] == "ItemGroup":
		return !strings.EqualFold(name, "PackageReference") && !strings.EqualFold(name, "GlobalPackageReference")
	}
	return false
}

// packageItem reports whether an element name is a package item type.
func packageItem(name string) bool {
	for _, t := range []string{"PackageReference", "GlobalPackageReference", "PackageVersion"} {
		if strings.EqualFold(name, t) {
			return true
		}
	}
	return false
}

// msbuildAttrs returns an element's attributes keyed by lowercased name. Namespace
// declarations are dropped; ok is false for any other prefixed attribute or a repeat.
func msbuildAttrs(attrs []xml.Attr) (map[string]string, bool) {
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
			continue
		}
		k := strings.ToLower(a.Name.Local)
		if _, dup := out[k]; dup || a.Name.Space != "" {
			return nil, false
		}
		out[k] = a.Value
	}
	return out, true
}

// onlyAttrs reports whether every key of attrs is one of allowed.
func onlyAttrs(attrs map[string]string, allowed ...string) bool {
	for k := range attrs {
		if !slices.Contains(allowed, k) {
			return false
		}
	}
	return true
}

// knownSDK reports whether every SDK an Sdk value names is a Microsoft.NET.Sdk flavor, which
// adds no package references of its own beyond the implicit ones restore records.
func knownSDK(sdk string) bool {
	for part := range strings.SplitSeq(sdk, ";") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "/")
		if !strings.HasPrefix(strings.ToLower(name), "microsoft.net.sdk") {
			return false
		}
	}
	return true
}

// restoreSafe reports whether setting the lowercased property name to value (lowercased,
// trimmed) leaves every version this reader reads in place.
func restoreSafe(name string, conditioned bool, value string) bool {
	restore := false
	for _, prefix := range restoreProperties {
		if strings.HasPrefix(name, prefix) {
			restore = true
		}
	}
	switch {
	case !restore:
		return true
	case conditioned:
		return false
	case name == "managepackageversionscentrally":
		return value == "true"
	case slices.Contains(restoreToggles, name):
		return value == "true" || value == "false"
	}
	return false
}
