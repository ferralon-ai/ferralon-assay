package dotnetanalysis

import (
	"bytes"
	"encoding/xml"
	"io"
	"maps"
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

	// reasonPackageReferenceUnmodeled: an MSBuild file read for the project (the project file,
	// a file it imports, a Directory.Build.props/.targets or Directory.Packages.props) holds
	// something parseMSBuild doesn't model, so the declared set is not fully known.
	reasonPackageReferenceUnmodeled = "package_reference_unmodeled"
)

// projectDir is the project file(s) found in one directory.
type projectDir struct {
	files []string
}

// installedCopies replaces each project's declared copies of want with what restore installs
// for that project, where the tree records it, and adds an unknown copy for every project
// whose installed copy can't be read. A version the tree doesn't fully determine never
// reaches the Match as a resolved copy. Each project is evaluated first (evaluator.evaluate);
// any input it doesn't model adds an unknown copy. Then, per project directory:
//
//   - obj/project.assets.json is restore's output. When checkAssets trusts it, its packages
//     are the installed set, and the directory's project and lockfile copies are dropped.
//     When it doesn't match the project as it stands, the project adds an unknown copy. An
//     assets file that can't be parsed returns ok=false (the caller vetoes). Restore-generated
//     imports in obj/ without an assets file add an unknown copy.
//   - Otherwise a packages.lock.json is the installed set only while lockCurrent holds.
//     Restore re-locks a project that no longer matches, so a stale lock's copies are dropped.
//   - Otherwise only a direct, unconditioned declaration of want decides (NuGet's
//     direct-dependency-wins). A project that declares other packages or references other
//     projects but not want, or declares want only under a Condition, may pull any version of
//     it transitively, so it adds an unknown copy.
//   - A project that declares no package and references only projects whose own copies
//     decide want (refsCover) adds nothing: what it restores of want is what they pin.
//   - A packages.config restores the project beside it only when packagesConfigGoverns holds;
//     beside any other project NuGet ignores it, and its copies are dropped. A governed
//     project keeps its packages.config, the complete legacy set; its project references
//     don't flow packages. A governed project the evaluator doesn't model adds nothing when
//     it is the classic template alone (legacyTemplateOnly) with no file MSBuild imports
//     implicitly (implicitImport); otherwise it adds an unknown copy. A lockfile or
//     packages.config with no project file beside it counts as is.
//
// Two project files in one directory share obj/ and the lock, so neither is attributed.
// The reasons name every unknown copy added. The first bool (settled) is true when every
// project directory's installed set is restore's own record: a trusted assets file or a
// current lockfile. The second is false when an assets file can't be parsed.
func installedCopies(ev *evaluator, copies []nugetCopy, locks map[string]*lockFile, projects map[string]*projectDir, configs map[string]bool, want, coordinate string) ([]nugetCopy, []string, bool, bool) {
	var (
		recorded int
		extra    []nugetCopy
		reasons  []string
		current  = make(map[string]bool)
		governed = make(map[string]bool)
		imports  = make(map[string]bool)
	)
	unknown := func(dir, reason string) {
		extra = append(extra, nugetCopy{dep: plugin.ResolvedDependency{Coordinate: coordinate, Source: reason}, dir: dir, kind: kindProject})
		if !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
dirs:
	for _, dir := range slices.Sorted(maps.Keys(projects)) {
		files := projects[dir].files
		gov := configs[dir] && packagesConfigGoverns(ev.rootReal, files)
		governed[dir] = gov
		var evals []*projectEval
		for _, f := range files {
			pe := ev.evalPath(f)
			if pe.reason != "" {
				if gov && legacyTemplateOnly(ev.rootReal, f) && !implicitImport(f, imports) {
					continue
				}
				unknown(dir, pe.reason)
				continue dirs
			}
			evals = append(evals, pe)
		}
		if len(evals) == 0 {
			continue
		}
		single := len(files) == 1
		if single {
			ac := ev.checkAssets(evals[0])
			switch ac.status {
			case assetsUnparsable:
				return nil, nil, false, false
			case assetsTrusted:
				for _, d := range assetsCopiesOf(ac.graph, want) {
					extra = append(extra, nugetCopy{dep: d, dir: dir, kind: kindAssets})
				}
				recorded++
				continue
			case assetsUntrusted:
				unknown(dir, ac.reason)
				continue
			}
		}
		var unconditional, declares, refs bool
		for _, pe := range evals {
			if pe.generated {
				unknown(dir, reasonRestoreOutputStale)
				continue dirs
			}
			for _, e := range slices.Concat(pe.decl.own, pe.decl.injected) {
				if normalizeNuGetCoordinate(e.dep.Coordinate) == want {
					extra = append(extra, nugetCopy{dep: e.dep, dir: dir, kind: kindProject})
				}
			}
			unconditional = unconditional || pe.decl.unconditional[want]
			declares = declares || len(pe.decl.specs) > 0
			refs = refs || len(pe.refs) > 0
		}
		lf, hasLock := locks[dir]
		if hasLock && single && ev.lockCurrent(lf, evals[0]) {
			current[dir] = true
			recorded++
			continue
		}
		if unconditional || !declares && (!refs || gov || ev.refsCover(evals, want)) {
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
		case c.kind == kindConfig && projects[c.dir] != nil && !governed[c.dir]:
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
	return out, reasons, len(projects) > 0 && recorded == len(projects), true
}

// refsCover reports whether every ProjectReference of evals leads only to projects whose
// copies of want decide what a referencing project restores: an unconditioned, exact pin of
// want (the nearest declaration wins), or no package at all and references that cover in turn.
// A referenced project that isn't modeled, or declares other packages, could bring any version
// of want transitively.
func (ev *evaluator) refsCover(evals []*projectEval, want string) bool {
	seen := make(map[string]bool)
	var cover func(refs []projectRef) bool
	cover = func(refs []projectRef) bool {
		for _, r := range refs {
			if r.conditioned {
				return false
			}
			if seen[r.path] {
				continue
			}
			seen[r.path] = true
			t := ev.eval(r.path)
			if t.reason != "" || t.generated {
				return false
			}
			if t.decl.unconditional[want] {
				pinned := false
				for _, e := range slices.Concat(t.decl.own, t.decl.injected) {
					if normalizeNuGetCoordinate(e.dep.Coordinate) != want {
						continue
					}
					if !e.dep.Resolved {
						return false
					}
					pinned = true
				}
				if pinned {
					continue
				}
				return false
			}
			if len(t.decl.specs) > 0 || !cover(t.refs) {
				return false
			}
		}
		return true
	}
	for _, pe := range evals {
		if !cover(pe.refs) {
			return false
		}
	}
	return true
}

// kindAssets marks a copy read from a project's obj/project.assets.json.
const kindAssets = "assets"

// assetsCopiesOf returns every package copy of want a restore output graph records, one per
// distinct version across targets.
func assetsCopiesOf(g *assetsGraph, want string) []plugin.ResolvedDependency {
	var deps []plugin.ResolvedDependency
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
	return deps
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

func newDeclaration() declaration {
	return declaration{specs: make(map[string][]string), unconditional: make(map[string]bool)}
}

// add records entries declared by one file. A conditioned entry (under a Condition, or in a
// file imported under one) is declared but unread: its spec is specUnread and it is not
// unconditional.
func (d *declaration) add(entries []manifestEntry, injected, conditioned bool) {
	for _, e := range entries {
		if conditioned {
			e = manifestEntry{dep: nugetResolved(e.dep.Coordinate, "", false, e.dep.Source), spec: specUnread}
		}
		id := normalizeNuGetCoordinate(e.dep.Coordinate)
		d.specs[id] = append(d.specs[id], e.spec)
		if e.spec != specUnread {
			d.unconditional[id] = true
		}
		if injected {
			d.injected = append(d.injected, e)
		} else {
			d.own = append(d.own, e)
		}
	}
}

// msbuildFile is what parseMSBuild reads from one MSBuild file.
type msbuildFile struct {
	refs        []manifestEntry
	globals     []manifestEntry
	imports     []msbuildImport
	props       []msbuildProp
	projectRefs []msbuildProjectRef
	versions    map[string]string // PackageVersion by normalized id (roleCentral only)
	// opaque is set when a skipped subtree could bring code into the build outside restore
	// (inertOpaque); assemblyRefs are the simple names of its Reference and FrameworkReference
	// items. Neither changes what restore installs; both limit what completeBuild may claim.
	opaque       bool
	assemblyRefs []string
}

type msbuildImport struct {
	project          string
	condition        string
	groupConditioned bool
}

type msbuildProp struct {
	name        string // lowercased
	value       string // trimmed
	conditioned bool
}

type msbuildProjectRef struct {
	include     string
	conditioned bool
}

// msbuildRole is which kind of file parseMSBuild reads, which decides what it may declare.
type msbuildRole int

const (
	// roleProject is a project file, a Directory.Build.props/.targets, or a file one of them
	// imports. None of them may declare a PackageVersion.
	roleProject msbuildRole = iota
	// roleCentral is Directory.Packages.props or a file it imports. Its PackageVersion items
	// are read into versions.
	roleCentral
)

// restoreProperties are the properties (lowercased prefixes, matched with any leading
// underscore removed) that move where restore looks for versions, which central file,
// Directory.Build.* or extension imports apply, where restore's inputs and outputs live, or
// how the project is restored.
var restoreProperties = []string{
	"managepackageversionscentrally", "centralpackage", "importdirectory",
	"directorypackagesprops", "directorybuild", "custombefore", "customafter",
	"importprojectextension", "importbywildcard", "importuserlocations",
	"msbuildprojectextensionspath", "msbuilduserextensionspath", "msbuildextensionspath",
	"baseintermediateoutputpath", "projectassetsfile", "nugetlockfilepath", "restore",
}

// restoreToggles are the restore properties a file may set to a literal true or false without
// moving any version this reader reads.
var restoreToggles = []string{
	"centralpackagetransitivepinningenabled", "centralpackageversionoverrideenabled",
	"restorepackageswithlockfile", "restorelockedmode",
}

// packageRefMetadata is the metadata a PackageReference or GlobalPackageReference may carry,
// as an attribute or an element. Anything else could change what restore does with it.
var packageRefMetadata = []string{
	"version", "versionoverride", "privateassets", "includeassets", "excludeassets",
	"generatepathproperty", "aliases", "nowarn",
}

// projectRefMetadata is the metadata a ProjectReference may carry.
var projectRefMetadata = []string{
	"privateassets", "includeassets", "excludeassets", "referenceoutputassembly", "private",
	"name", "project", "aliases",
}

// restoreItems are the item types that decide what restore installs.
var restoreItems = []string{"PackageReference", "GlobalPackageReference", "PackageVersion", "ProjectReference"}

// parseMSBuild reads the declarations of one MSBuild file. It models only what it knows: a
// Project of PropertyGroups, ItemGroups, Imports and ImportGroups, with PackageReference,
// GlobalPackageReference and ProjectReference items declared by Include and carrying only the
// metadata listed above, and in Directory.Packages.props PackageVersion items. Other item
// types, and Targets, UsingTasks, ItemDefinitionGroups and ProjectExtensions, are skipped,
// but only while nothing inside them names one of restoreItems. ok is false, and the file's
// declarations are unknown, for anything else:
//
//   - a Choose, or any element outside the shapes above;
//   - an Update, Remove or Exclude on one of those items, any other metadata, or a package
//     Include that is empty, lists several ids, or holds a wildcard or a $(property), @(item)
//     or %(metadata) reference;
//   - a PackageVersion outside Directory.Packages.props, or one under a Condition;
//   - an SDK outside bundledSDKs, or any SDK version;
//   - a restore property (restoreProperties), unless it is set without a Condition to a
//     literal true for ManagePackageVersionsCentrally or true/false for a restoreToggles one;
//   - a DOCTYPE, or text or attributes where none belong.
//
// Item types are matched without case, as MSBuild does. A reference under a Condition (on
// the item, its ItemGroup, or a metadata element) applies only sometimes, and one with more
// than one Version or VersionOverride, or with both, is decided by evaluation order; both are read as
// unresolved with the declared version specUnread. Every property is recorded, with whether
// a Condition applies, for the evaluator.
func parseMSBuild(data []byte, role msbuildRole, source string) (msbuildFile, bool) {
	var (
		mf        msbuildFile
		stack     []string
		groupCond bool
		item      *msbuildPkgItem
		pref      *msbuildProjectRef
		pver      *msbuildPkgVersion
		prop      string
		meta      string
		propCond  bool
		metaCond  bool
		text      strings.Builder
		skip      int
		inert     string // lowercased name of the skipped subtree's root
	)
	d := xml.NewDecoder(bytes.NewReader(stripBOM(data)))
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
					inert = strings.ToLower(name)
					switch {
					case depth == 2 && inert != "projectextensions", depth == 3 && !slices.Contains(inertItems, inert):
						mf.opaque = true
					case assemblyItem(inert):
						include, _, _ := strings.Cut(attrValue(t.Attr, "include"), ",")
						if !simpleAssemblyName(include) || inert == "reference" && !frameworkAssembly(include) {
							mf.opaque = true
						}
						mf.assemblyRefs = append(mf.assemblyRefs, normalizeNuGetCoordinate(include))
					}
				} else if assemblyItem(inert) && !slices.Contains(referenceMetadata, strings.ToLower(name)) {
					mf.opaque = true
				}
				for _, a := range t.Attr {
					if k := strings.ToLower(a.Name.Local); k != "condition" && (k != "include" || !assemblyItem(inert)) && inertOpaque(inert, a.Value) {
						mf.opaque = true
					}
				}
				if restoreItem(name) {
					return msbuildFile{}, false
				}
				for _, a := range t.Attr {
					v := strings.ToLower(a.Value)
					for _, it := range restoreItems {
						if strings.Contains(v, strings.ToLower(it)) {
							return msbuildFile{}, false
						}
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
				if !onlyAttrs(attrs, "name") || !knownSDK(attrs["name"]) {
					return msbuildFile{}, false
				}
			case name == "Import" && (depth == 2 || depth == 3 && parent == "ImportGroup"):
				if !onlyAttrs(attrs, "project", "condition", "sdk", "label") {
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
				mf.imports = append(mf.imports, msbuildImport{project: project, condition: attrs["condition"], groupConditioned: depth == 3 && groupCond})
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
					switch {
					case k == "include":
						item.include = v
					case k == "condition":
						item.conditioned = true
					case k == "version":
						item.versions = append(item.versions, strings.TrimSpace(v))
					case k == "versionoverride":
						item.overrides = append(item.overrides, strings.TrimSpace(v))
					case !slices.Contains(packageRefMetadata, k):
						return msbuildFile{}, false
					}
				}
			case depth == 3 && parent == "ItemGroup" && strings.EqualFold(name, "ProjectReference"):
				pref = &msbuildProjectRef{conditioned: groupCond}
				for k, v := range attrs {
					switch {
					case k == "include":
						pref.include = strings.TrimSpace(v)
					case k == "condition":
						pref.conditioned = true
					case !slices.Contains(projectRefMetadata, k):
						return msbuildFile{}, false
					}
				}
			case depth == 3 && parent == "ItemGroup" && strings.EqualFold(name, "PackageVersion"):
				if role != roleCentral || groupCond || !onlyAttrs(attrs, "include", "version") {
					return msbuildFile{}, false
				}
				pver = &msbuildPkgVersion{include: attrs["include"]}
				if v, set := attrs["version"]; set {
					pver.versions = append(pver.versions, strings.TrimSpace(v))
				}
			case depth == 4 && (item != nil || pref != nil || pver != nil):
				if !onlyAttrs(attrs, "condition") {
					return msbuildFile{}, false
				}
				_, metaCond = attrs["condition"]
				meta = strings.ToLower(name)
				switch {
				case item != nil && !slices.Contains(packageRefMetadata, meta),
					pref != nil && !slices.Contains(projectRefMetadata, meta),
					pver != nil && (meta != "version" || metaCond):
					return msbuildFile{}, false
				}
				text.Reset()
			default:
				return msbuildFile{}, false
			}
		case xml.CharData:
			switch {
			case skip > 0:
				if inertOpaque(inert, string(t)) {
					mf.opaque = true
				}
			case len(stack) == 3 && prop != "", len(stack) == 4 && (item != nil || pref != nil || pver != nil):
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
					skip, inert = 0, ""
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
			case depth == 4 && pref != nil:
				if metaCond {
					pref.conditioned = true
				}
			case depth == 4 && pver != nil:
				pver.versions = append(pver.versions, strings.TrimSpace(text.String()))
			case depth == 3 && prop != "":
				value := strings.TrimSpace(text.String())
				if !restoreSafe(prop, propCond, strings.ToLower(value)) {
					return msbuildFile{}, false
				}
				mf.props = append(mf.props, msbuildProp{name: prop, value: value, conditioned: propCond})
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
			case depth == 3 && pref != nil:
				if pref.include == "" {
					return msbuildFile{}, false
				}
				mf.projectRefs = append(mf.projectRefs, *pref)
				pref = nil
			case depth == 3 && pver != nil:
				id := strings.TrimSpace(pver.include)
				if id == "" || strings.ContainsAny(id, ";*?$@%") || len(pver.versions) != 1 {
					return msbuildFile{}, false
				}
				if mf.versions == nil {
					mf.versions = make(map[string]string)
				}
				key, v := normalizeNuGetCoordinate(id), pver.versions[0]
				if prev, seen := mf.versions[key]; seen && prev != v {
					v = ""
				}
				mf.versions[key] = v
				pver = nil
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

// msbuildPkgVersion is one PackageVersion item as written.
type msbuildPkgVersion struct {
	include  string
	versions []string
}

// entry is the manifest entry the item declares; ok is false when its Include isn't one
// literal package id.
func (it *msbuildPkgItem) entry(source string) (manifestEntry, bool) {
	name := strings.TrimSpace(it.include)
	if name == "" || strings.ContainsAny(name, ";*?$@%") {
		return manifestEntry{}, false
	}
	// A Version beside a VersionOverride is NU1008 under central management, and without it
	// which one restore takes isn't modeled, so neither is read.
	if it.conditioned || len(it.versions) > 1 || len(it.overrides) > 1 || len(it.versions) > 0 && len(it.overrides) > 0 {
		return manifestEntry{dep: nugetResolved(name, "", false, source), spec: specUnread}, true
	}
	var raw, override string
	if n := len(it.versions); n > 0 {
		raw = it.versions[n-1]
	}
	if n := len(it.overrides); n > 0 {
		override = it.overrides[n-1]
	}
	ver, resolved := packageReferencePin(raw)
	spec := raw
	if spec == "" {
		spec = override
	}
	return manifestEntry{dep: nugetResolved(name, ver, resolved, source), spec: spec}, true
}

// inertSubtree reports whether the element at the top of stack starts a subtree that can't
// declare what restore installs unless it names one of restoreItems: an item of another
// type, or a Target, UsingTask, ItemDefinitionGroup or ProjectExtensions.
func inertSubtree(depth int, stack []string) bool {
	name := stack[depth-1]
	switch {
	case depth == 2:
		return name == "Target" || name == "UsingTask" || name == "ItemDefinitionGroup" || name == "ProjectExtensions"
	case depth == 3 && stack[1] == "ItemGroup":
		return !restoreItem(name)
	}
	return false
}

// restoreItem reports whether an element name is one of restoreItems, without case.
func restoreItem(name string) bool {
	for _, t := range restoreItems {
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

// knownSDK reports whether every SDK an Sdk value names is one of bundledSDKs, with no
// version.
func knownSDK(sdk string) bool {
	for part := range strings.SplitSeq(sdk, ";") {
		if !slices.Contains(bundledSDKs, strings.ToLower(strings.TrimSpace(part))) {
			return false
		}
	}
	return true
}

// restoreSafe reports whether setting the lowercased property name to value (lowercased,
// trimmed) leaves every version this reader reads in place.
func restoreSafe(name string, conditioned bool, value string) bool {
	name = strings.TrimLeft(name, "_")
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
