package dotnetanalysis

// restoreoutput.go — when restore's outputs (obj/project.assets.json and packages.lock.json)
// still describe the project as it stands. Each is trusted only when every field that records
// an input is compared to the evaluated project and agrees; a field this lane doesn't know, or
// can't compare, withholds.

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

type assetsStatus uint8

const (
	assetsAbsent assetsStatus = iota
	assetsTrusted
	assetsUntrusted
	assetsUnparsable
)

// assetsCheck is checkAssets' verdict on one project's obj/project.assets.json.
type assetsCheck struct {
	status assetsStatus
	reason string // set when untrusted
	graph  *assetsGraph
}

// checkAssets reads pe's obj/project.assets.json and decides whether it is what restoring pe
// as it now stands produces (assetsMatch). A file that isn't valid JSON or records no targets
// is unparsable.
func (e *evaluator) checkAssets(pe *projectEval) assetsCheck {
	data, _, st := readInput(e.rootReal, filepath.Join(pe.dir, "obj", "project.assets.json"))
	switch st {
	case inputAbsent:
		return assetsCheck{status: assetsAbsent}
	case inputRead:
	default:
		return assetsCheck{status: assetsUntrusted, reason: reasonBuildInputUnmodeled}
	}
	g := parseAssetsGraph(data)
	if g == nil || g.targets == nil {
		return assetsCheck{status: assetsUnparsable}
	}
	if pe.reason != "" {
		return assetsCheck{status: assetsUntrusted, reason: pe.reason}
	}
	if !e.assetsMatch(pe, data) {
		return assetsCheck{status: assetsUntrusted, reason: reasonRestoreOutputStale}
	}
	return assetsCheck{status: assetsTrusted, graph: g}
}

// AssetsTrusted reports whether the project.assets.json at assetsPath is the restore output
// of a project file of the tree under buildDir that checkAssets trusts: it sits in that
// project's obj/, every input of the project is modeled, and every field recording an input
// agrees with the project as it stands. This is the one predicate the version resolver and
// the IL tier share. reason says why not.
func AssetsTrusted(buildDir, assetsPath string) (bool, string) {
	files := manifestFiles(buildDir)
	ev := newEvaluator(buildDir, files)
	assetsReal, err := filepath.EvalSymlinks(assetsPath)
	if err != nil {
		return false, reasonBuildInputUnmodeled
	}
	var owner []string
	for _, f := range files {
		if manifestKind(filepath.Base(f)) != kindProject {
			continue
		}
		dirReal, err := filepath.EvalSymlinks(filepath.Dir(f))
		if err == nil && filepath.Join(dirReal, "obj", "project.assets.json") == assetsReal {
			owner = append(owner, f)
		}
	}
	if len(owner) != 1 {
		return false, reasonRestoreOutputStale
	}
	pe := ev.evalPath(owner[0])
	if pe.reason != "" {
		return false, pe.reason
	}
	ac := ev.checkAssets(pe)
	if ac.status != assetsTrusted {
		if ac.reason == "" {
			return false, reasonRestoreOutputStale
		}
		return false, ac.reason
	}
	return true, ""
}

// Keys the lane knows in project.assets.json and the specs it embeds. A key outside these
// records something the lane can't compare, so it withholds.
var (
	assetsTopKeys       = []string{"version", "targets", "libraries", "projectFileDependencyGroups", "packageFolders", "project", "logs"}
	assetsProjectKeys   = []string{"version", "restore", "frameworks", "runtimes", "supports"}
	assetsRestoreKeys   = []string{"projectUniqueName", "projectName", "projectPath", "packagesPath", "outputPath", "projectStyle", "crossTargeting", "configFilePaths", "fallbackFolders", "originalTargetFrameworks", "sources", "frameworks", "warningProperties", "restoreLockProperties", "restoreAuditProperties", "SdkAnalysisLevel", "centralPackageVersionsManagementEnabled", "centralPackageTransitivePinningEnabled", "centralPackageVersionOverrideDisabled", "centralPackageFloatingVersionsEnabled", "UsingMicrosoftNETSdk", "restoreUseLegacyDependencyResolver"}
	assetsRestoreFwKeys = []string{"framework", "targetAlias", "projectReferences"}
	assetsProjRefKeys   = []string{"projectPath", "includeAssets", "excludeAssets", "privateAssets"}
	assetsFrameworkKeys = []string{"framework", "targetAlias", "dependencies", "imports", "assetTargetFallback", "warn", "downloadDependencies", "frameworkReferences", "runtimeIdentifierGraphPath", "centralPackageVersions", "packagesToPrune"}
	assetsDepKeys       = []string{"target", "version", "autoReferenced", "versionCentrallyManaged", "include", "exclude", "suppressParent", "noWarn", "generatePathProperty", "aliases"}
	assetsLockPropKeys  = []string{"restorePackagesWithLockFile", "restoreLockedMode"}
	nugetCacheKeys      = []string{"version", "dgSpecHash", "success", "projectFilePath", "expectedPackageFiles", "logs"}
)

type assetsDep struct {
	Target                  string `json:"target"`
	Version                 string `json:"version"`
	AutoReferenced          bool   `json:"autoReferenced"`
	VersionCentrallyManaged bool   `json:"versionCentrallyManaged"`
}

// assetsMatch reports whether data, pe's project.assets.json, records a restore of pe as it
// now stands:
//
//   - every object key is one the lane knows (the lists above), the file format is 3 or 4,
//     and the logs hold no error;
//   - the project spec names pe's path, obj/ and a PackageReference style, no lockfile path
//     override, and pe's Central Package Management and transitive pinning settings;
//   - its target frameworks and runtime identifiers are pe's, and the targets are exactly
//     each framework and each framework/runtime pair;
//   - in every framework, the direct package dependencies (other than ones the SDK adds
//     implicitly) are exactly the ids pe declares with the same ranges, a version-less one
//     centrally managed at pe's PackageVersion, the central versions recorded are exactly
//     pe's, and the project references are exactly pe's;
//   - every target lists each project of pe's reference closure, each with exactly the
//     packages and projects it declares, at the ranges it declares;
//   - obj/project.nuget.cache, when present, records a successful restore of pe, and
//     obj/<project>.nuget.dgspec.json, when present, holds a spec of pe equal to this one.
//
// pe must declare no conditioned reference and no property that renames it as a reference.
func (e *evaluator) assetsMatch(pe *projectEval, data []byte) bool {
	top, ok := jsonObject(data, assetsTopKeys...)
	if !ok {
		return false
	}
	var version int
	if json.Unmarshal(top["version"], &version) != nil || version != 3 && version != 4 {
		return false
	}
	if raw, set := top["logs"]; set {
		var logs []struct {
			Level string `json:"level"`
		}
		if json.Unmarshal(raw, &logs) != nil {
			return false
		}
		for _, l := range logs {
			if strings.EqualFold(l.Level, "error") {
				return false
			}
		}
	}
	project, ok := jsonObject(top["project"], assetsProjectKeys...)
	if !ok || !e.restoreMatches(pe, project["restore"]) {
		return false
	}
	if pe.tfms == nil || !pe.ridsKnown || pe.identity || conditionedRefs(pe) {
		return false
	}

	var runtimes map[string]json.RawMessage
	if raw, set := project["runtimes"]; set && json.Unmarshal(raw, &runtimes) != nil {
		return false
	}
	if !slices.Equal(slices.Sorted(maps.Keys(runtimes)), pe.rids) {
		return false
	}

	var frameworks map[string]json.RawMessage
	if json.Unmarshal(project["frameworks"], &frameworks) != nil {
		return false
	}
	var tfms []string
	for alias, raw := range frameworks {
		tfm, ok := canonicalTFM(alias)
		if !ok || slices.Contains(tfms, tfm) || !frameworkMatches(pe, raw) {
			return false
		}
		tfms = append(tfms, tfm)
	}
	slices.Sort(tfms)
	if !slices.Equal(tfms, pe.tfms) {
		return false
	}

	var targets map[string]map[string]assetsLib
	var libraries map[string]struct {
		Type string `json:"type"`
		Path string `json:"path"`
	}
	if json.Unmarshal(top["targets"], &targets) != nil || json.Unmarshal(top["libraries"], &libraries) != nil {
		return false
	}
	if !sectionKeysMatch(slices.Collect(maps.Keys(targets)), pe) {
		return false
	}
	closure := e.closure(pe)
	byPath := make(map[string]*projectEval, len(closure))
	for _, q := range closure {
		if q.identity || conditionedRefs(q) {
			return false
		}
		byPath[q.path] = q
	}
	for _, libs := range targets {
		listed := make(map[string]bool)
		for key, lib := range libs {
			if !strings.EqualFold(lib.Type, "project") {
				continue
			}
			l, ok := libraries[key]
			if !ok || !strings.EqualFold(l.Type, "project") {
				return false
			}
			real, err := filepath.EvalSymlinks(filepath.Join(pe.dir, filepath.FromSlash(l.Path)))
			q := byPath[real]
			if err != nil || q == nil || listed[real] || !projectDepsMatch(q, lib.Dependencies) {
				return false
			}
			listed[real] = true
		}
		if len(listed) != len(closure) {
			return false
		}
	}

	return e.cacheMatches(pe) && e.dgspecMatches(pe, top["project"])
}

// restoreMatches compares the project spec's restore metadata to pe.
func (e *evaluator) restoreMatches(pe *projectEval, raw json.RawMessage) bool {
	restore, ok := jsonObject(raw, assetsRestoreKeys...)
	if !ok {
		return false
	}
	var r struct {
		ProjectUniqueName string   `json:"projectUniqueName"`
		ProjectPath       string   `json:"projectPath"`
		OutputPath        string   `json:"outputPath"`
		ProjectStyle      string   `json:"projectStyle"`
		OriginalTFMs      []string `json:"originalTargetFrameworks"`
		CPM               bool     `json:"centralPackageVersionsManagementEnabled"`
		Pinning           bool     `json:"centralPackageTransitivePinningEnabled"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return false
	}
	if !samePath(r.ProjectPath, pe.path) || !samePath(r.ProjectUniqueName, pe.path) ||
		!samePath(r.OutputPath, filepath.Join(pe.dir, "obj")) || r.ProjectStyle != "PackageReference" ||
		r.CPM != pe.cpm || r.Pinning != pe.pinning {
		return false
	}
	if lp, set := restore["restoreLockProperties"]; set {
		if _, ok := jsonObject(lp, assetsLockPropKeys...); !ok {
			return false
		}
	}
	var tfms []string
	for _, t := range r.OriginalTFMs {
		c, ok := canonicalTFM(t)
		if !ok || slices.Contains(tfms, c) {
			return false
		}
		tfms = append(tfms, c)
	}
	slices.Sort(tfms)
	if !slices.Equal(tfms, pe.tfms) {
		return false
	}
	var fws map[string]json.RawMessage
	if json.Unmarshal(restore["frameworks"], &fws) != nil {
		return false
	}
	want := make([]string, 0, len(pe.refs))
	for _, ref := range pe.refs {
		want = append(want, ref.path)
	}
	slices.Sort(want)
	var seen []string
	for alias, fw := range fws {
		tfm, ok := canonicalTFM(alias)
		if !ok || slices.Contains(seen, tfm) {
			return false
		}
		seen = append(seen, tfm)
		obj, ok := jsonObject(fw, assetsRestoreFwKeys...)
		if !ok {
			return false
		}
		var refs map[string]json.RawMessage
		if raw, set := obj["projectReferences"]; set && json.Unmarshal(raw, &refs) != nil {
			return false
		}
		var got []string
		for p, rr := range refs {
			if _, ok := jsonObject(rr, assetsProjRefKeys...); !ok {
				return false
			}
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				return false
			}
			got = append(got, real)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			return false
		}
	}
	slices.Sort(seen)
	return slices.Equal(seen, pe.tfms)
}

// frameworkMatches compares one framework of the project spec to what pe declares.
func frameworkMatches(pe *projectEval, raw json.RawMessage) bool {
	fw, ok := jsonObject(raw, assetsFrameworkKeys...)
	if !ok {
		return false
	}
	var deps map[string]json.RawMessage
	if r, set := fw["dependencies"]; set && json.Unmarshal(r, &deps) != nil {
		return false
	}
	got := make(map[string]assetsDep)
	for id, r := range deps {
		if _, ok := jsonObject(r, assetsDepKeys...); !ok {
			return false
		}
		var d assetsDep
		if json.Unmarshal(r, &d) != nil {
			return false
		}
		if d.AutoReferenced {
			continue
		}
		key := normalizeNuGetCoordinate(id)
		if _, dup := got[key]; dup || d.Target != "Package" {
			return false
		}
		got[key] = d
	}
	if len(got) != len(pe.decl.specs) {
		return false
	}
	for id, specs := range pe.decl.specs {
		d, ok := got[id]
		if !ok {
			return false
		}
		for _, spec := range specs {
			if spec == "" {
				if !pe.cpm || !d.VersionCentrallyManaged {
					return false
				}
				spec = pe.central[id]
			}
			if !sameRanges(spec, []string{d.Version}) {
				return false
			}
		}
	}
	var central map[string]string
	if r, set := fw["centralPackageVersions"]; set && json.Unmarshal(r, &central) != nil {
		return false
	}
	if pe.cpm != (central != nil) || len(central) != len(pe.central) {
		return false
	}
	for id, v := range central {
		want, ok := pe.central[normalizeNuGetCoordinate(id)]
		if !ok || !sameRanges(want, []string{v}) {
			return false
		}
	}
	return true
}

// projectDepsMatch compares the dependencies a restore output or lockfile records for a
// referenced project q to what q declares: its packages at their declared ranges, and its
// project references by name (their recorded range is a placeholder, so only presence is
// compared).
func projectDepsMatch(q *projectEval, deps map[string]string) bool {
	want := make(map[string]bool)
	for id := range q.decl.specs {
		want[id] = true
	}
	for _, ref := range q.refs {
		want[projectName(ref.path)] = true
	}
	if len(deps) != len(want) {
		return false
	}
	for name, rng := range deps {
		key := normalizeNuGetCoordinate(name)
		if !want[key] {
			return false
		}
		specs, pkg := q.decl.specs[key]
		if !pkg {
			continue
		}
		for _, spec := range specs {
			if spec == "" {
				if !q.cpm {
					return false
				}
				spec = q.central[key]
			}
			if !sameRanges(spec, []string{rng}) {
				return false
			}
		}
	}
	return true
}

// cacheMatches checks obj/project.nuget.cache, when present: a successful restore of pe.
func (e *evaluator) cacheMatches(pe *projectEval) bool {
	data, _, st := readInput(e.rootReal, filepath.Join(pe.dir, "obj", "project.nuget.cache"))
	switch st {
	case inputAbsent:
		return true
	case inputRead:
	default:
		return false
	}
	if _, ok := jsonObject(data, nugetCacheKeys...); !ok {
		return false
	}
	var c struct {
		Success         bool   `json:"success"`
		ProjectFilePath string `json:"projectFilePath"`
	}
	return json.Unmarshal(data, &c) == nil && c.Success && samePath(c.ProjectFilePath, pe.path)
}

// dgspecMatches checks obj/<project>.nuget.dgspec.json, when present: restore's input spec
// for pe must equal the spec the assets file records. Its dgSpecHash is not recomputed.
func (e *evaluator) dgspecMatches(pe *projectEval, spec json.RawMessage) bool {
	data, _, st := readInput(e.rootReal, filepath.Join(pe.dir, "obj", filepath.Base(pe.path)+".nuget.dgspec.json"))
	switch st {
	case inputAbsent:
		return true
	case inputRead:
	default:
		return false
	}
	top, ok := jsonObject(data, "format", "restore", "projects")
	if !ok {
		return false
	}
	var projects map[string]json.RawMessage
	if json.Unmarshal(top["projects"], &projects) != nil {
		return false
	}
	var entry json.RawMessage
	for p, raw := range projects {
		if samePath(p, pe.path) {
			if entry != nil {
				return false
			}
			entry = raw
		}
	}
	var a, b any
	return entry != nil && json.Unmarshal(entry, &a) == nil && json.Unmarshal(spec, &b) == nil && reflect.DeepEqual(a, b)
}

// samePath reports whether the absolute path p, once its symlinks are resolved, is real.
func samePath(p, real string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	r, err := filepath.EvalSymlinks(p)
	return err == nil && r == real
}

func conditionedRefs(pe *projectEval) bool {
	for _, r := range pe.refs {
		if r.conditioned {
			return true
		}
	}
	return false
}

// sectionKeysMatch reports whether keys (restore targets, or lockfile sections) are exactly
// each of pe's frameworks and each framework/runtime pair.
func sectionKeysMatch(keys []string, pe *projectEval) bool {
	want := make(map[string]bool)
	for _, t := range pe.tfms {
		want[t] = true
		for _, rid := range pe.rids {
			want[t+"/"+rid] = true
		}
	}
	got := make(map[string]bool)
	for _, k := range keys {
		fw, rid, hasRID := strings.Cut(k, "/")
		c, ok := canonicalTFM(fw)
		if !ok {
			return false
		}
		if hasRID {
			c += "/" + rid
		}
		if got[c] {
			return false
		}
		got[c] = true
	}
	return maps.Equal(got, want)
}

// --- packages.lock.json ------------------------------------------------------

// lockFile is what a packages.lock.json records per target section. bad is set when it holds
// something the lane doesn't model, which makes it never current.
type lockFile struct {
	sections map[string]*lockSection
	bad      bool
}

// lockSection is one target's section: the requested range of each Direct and each
// CentralTransitive entry by normalized id, and each Project entry's dependencies by
// lowercased project name.
type lockSection struct {
	direct, transitive map[string]string
	projects           map[string]map[string]string
}

var lockEntryKeys = []string{"type", "requested", "resolved", "contentHash", "dependencies"}

// parsePackagesLock parses packages.lock.json. Every package entry (Direct, Transitive or
// CentralTransitive) carries an exact "resolved" version, so a present resolved field
// resolves; a missing one is UNRESOLVED. A Project entry (a project reference, not a
// package) is recorded for lockCurrent and has no copy.
//
// Each target framework (and each <tfm>/<rid> target) is its own resolution, and they can
// disagree (net6.0 → 13.0.1, net8.0 → 13.0.3). Every distinct (id, version) across them is
// kept so the split reaches the Match; only exact repeats collapse. Sections and ids are
// walked in sorted order so All is identical across runs. ok is false only when the JSON
// doesn't parse.
func parsePackagesLock(data []byte) ([]plugin.ResolvedDependency, *lockFile, bool) {
	var raw struct {
		Dependencies map[string]map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(stripBOM(data), &raw); err != nil {
		return nil, nil, false
	}
	lf := &lockFile{sections: make(map[string]*lockSection)}
	top, ok := jsonObject(stripBOM(data), "version", "dependencies")
	var version int
	if !ok || json.Unmarshal(top["version"], &version) != nil || version != 1 && version != 2 {
		lf.bad = true
	}
	type idVersion struct{ id, version string }
	seen := make(map[idVersion]bool)
	var out []plugin.ResolvedDependency
	for _, section := range slices.Sorted(maps.Keys(raw.Dependencies)) {
		ls := &lockSection{direct: make(map[string]string), transitive: make(map[string]string), projects: make(map[string]map[string]string)}
		lf.sections[section] = ls
		ids := make(map[string]bool)
		pkgs := raw.Dependencies[section]
		for _, name := range slices.Sorted(maps.Keys(pkgs)) {
			var e struct {
				Type         string            `json:"type"`
				Requested    string            `json:"requested"`
				Resolved     string            `json:"resolved"`
				Dependencies map[string]string `json:"dependencies"`
			}
			if _, ok := jsonObject(pkgs[name], lockEntryKeys...); !ok || json.Unmarshal(pkgs[name], &e) != nil {
				lf.bad = true
				continue
			}
			id := normalizeNuGetCoordinate(name)
			if ids[id] {
				lf.bad = true
			}
			ids[id] = true
			switch e.Type {
			case "Project":
				deps := make(map[string]string, len(e.Dependencies))
				for d, r := range e.Dependencies {
					deps[normalizeNuGetCoordinate(d)] = r
				}
				ls.projects[strings.ToLower(name)] = deps
				continue
			case "Direct":
				ls.direct[id] = strings.TrimSpace(e.Requested)
			case "CentralTransitive":
				ls.transitive[id] = strings.TrimSpace(e.Requested)
			case "Transitive":
			default:
				lf.bad = true
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
	return out, lf, true
}

// lockCurrent reports whether pe's lockfile still records a restore of pe as it now stands:
// its sections are exactly each framework and framework/runtime pair of pe, and in every
// section the Direct ids are exactly the ids pe declares, each at its declared range (a
// version-less one at pe's PackageVersion), every CentralTransitive range is pe's
// PackageVersion of that id, and the Project entries are exactly pe's reference closure,
// each with exactly the packages (at their declared ranges) and projects it declares.
func (e *evaluator) lockCurrent(lf *lockFile, pe *projectEval) bool {
	if lf == nil || lf.bad || pe.tfms == nil || !pe.ridsKnown || pe.identity || conditionedRefs(pe) {
		return false
	}
	if !sectionKeysMatch(slices.Collect(maps.Keys(lf.sections)), pe) {
		return false
	}
	closure := e.closure(pe)
	for _, q := range closure {
		if q.identity || conditionedRefs(q) {
			return false
		}
	}
	for _, ls := range lf.sections {
		if len(ls.direct) != len(pe.decl.specs) {
			return false
		}
		for id, specs := range pe.decl.specs {
			req, ok := ls.direct[id]
			if !ok {
				return false
			}
			for _, spec := range specs {
				if spec == "" {
					if !pe.cpm {
						return false
					}
					spec = pe.central[id]
				}
				if !sameRanges(spec, []string{req}) {
					return false
				}
			}
		}
		if len(ls.transitive) > 0 && !pe.cpm {
			return false
		}
		for id, req := range ls.transitive {
			if !sameRanges(pe.central[id], []string{req}) {
				return false
			}
		}
		if len(ls.projects) != len(closure) {
			return false
		}
		for _, q := range closure {
			deps, ok := ls.projects[projectName(q.path)]
			if !ok || !projectDepsMatch(q, deps) {
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
