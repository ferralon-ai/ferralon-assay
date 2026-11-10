package dotnetanalysis

// build.go — which first-party program a run analyzes, and which restore target its
// dependencies come from. Symbol resolution and the IL reachability tier both read through
// locateFirstPartyBuild, so they see the same assembly bound to the same target.
//
// One project and one entry assembly are supported. A build directory with more than one
// project file the build compiled, or a project built for more than one target framework, is
// analyzed from the first one for candidate paths, but the run carries
// multiple_projects_unsupported and no sink is searched: the others were never traced. A project
// the build never compiled is not counted (compiledProjects).

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// partialReasonMultipleProjects: the build holds more than one project or entry assembly, and
// only one was traced.
const partialReasonMultipleProjects = "multiple_projects_unsupported"

// partialReasonTargetUnbound: the first-party assembly could not be tied to exactly one
// restore target, so the dependency bytes read may not be the ones it runs against.
const partialReasonTargetUnbound = "reachability_undetermined:restore_target_unbound"

// partialReasonRIDUnknown: a dependency ships a separate implementation per runtime and the
// build records no runtime restore resolved, so the bytes that run are not known.
const partialReasonRIDUnknown = "reachability_undetermined:runtime_identifier_unknown"

// partialReasonRIDAmbiguous: a dependency ships a separate implementation per runtime and the
// build's outputs record more than one runtime.
const partialReasonRIDAmbiguous = "reachability_undetermined:runtime_identifier_ambiguous"

// partialReasonRuntimeTargetAbsent: the build's outputs name a runtime restore wrote no
// "<tfm>/<rid>" target for, so the packages that runtime's graph adds or re-versions are not
// known.
const partialReasonRuntimeTargetAbsent = "reachability_undetermined:runtime_target_absent"

// partialReasonRestoreUntrusted: the restore output the IL tier loads dependencies from isn't
// trusted for the project it sits beside (AssetsTrusted), so the dependency bytes may not be
// the ones the next restore installs.
const partialReasonRestoreUntrusted = "reachability_undetermined:restore_output_untrusted"

// Why the IL tier did not run. Each is a first-party limit with no Targets: the lexical tier that
// runs instead cannot see the dispatch the IL resolves, so the gap counts against every advisory.
const (
	partialReasonFirstPartyILAbsent     = plugin.PartialReasonToolFailure + ":first_party_il_absent"
	partialReasonFirstPartyILUnreadable = plugin.PartialReasonToolFailure + ":first_party_il_unreadable"
)

// ilAbsent names why b has no first-party assembly for the IL tier, with where it looked.
func (b firstPartyBuild) ilAbsent(buildDir string) plugin.ScopedReason {
	if b.project == "" {
		return plugin.ScopedReason{Reason: partialReasonFirstPartyILAbsent, Path: "no project file under the build dir"}
	}
	if len(b.unreadable) > 0 {
		return plugin.ScopedReason{Reason: partialReasonFirstPartyILUnreadable, Path: relSlash(buildDir, b.unreadable[0])}
	}
	name := strings.TrimSuffix(filepath.Base(b.project), filepath.Ext(b.project))
	if len(b.refOnly) > 0 {
		return plugin.ScopedReason{
			Reason: partialReasonFirstPartyILAbsent,
			Path:   "only a reference assembly " + relSlash(buildDir, b.refOnly[0]) + " for " + relSlash(buildDir, b.project),
		}
	}
	return plugin.ScopedReason{
		Reason: partialReasonFirstPartyILAbsent,
		Path:   "no built " + name + ".dll under bin/ or publish/ for " + relSlash(buildDir, b.project),
	}
}

// relSlash is path relative to base with forward slashes, or its base name when it is not below
// base, so a local absolute path never reaches the Report.
func relSlash(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

// firstPartyBuild is the first-party program a run analyzes.
type firstPartyBuild struct {
	project    string             // project file; "" when the build has none
	fp         *assembly.Assembly // the built assembly; nil when not located or unreadable
	unreadable []string           // built copies of the assembly, or directories under bin/ or publish/, that could not be read
	refOnly    []string           // reference-assembly copies of the project's assembly, skipped as stubs
	assets     []byte             // project.assets.json; nil when absent
	assetsPath string             // where assets was read from
	target     string             // the assets targets key fp binds to; "" when unbound or no assets
	runtime    assembly.Runtime   // the runtime fp's copies were built for
	rids       []string           // every runtime fp's copies record, sorted; none for a portable build
	reasons    []string           // run-wide limits from the layout
}

// locateFirstPartyBuild finds the build's project, its built assembly and restore output,
// and binds the assembly to the restore target matching the framework it was compiled for.
func locateFirstPartyBuild(buildDir string) firstPartyBuild {
	var b firstPartyBuild
	projects := compiledProjects(buildDir, findProjectFiles(buildDir))
	if len(projects) == 0 {
		return b
	}
	b.project = projects[0]
	multiple := len(projects) > 1

	name := strings.TrimSuffix(filepath.Base(b.project), filepath.Ext(b.project))
	var fpTFM string
	entries := map[string]bool{}
	ridOf := map[string]string{} // path -> RID, for each readable program copy
	tfmOf := map[string]string{}
	built, unreadableDirs := builtAssemblies(buildDir, name)
	b.unreadable = unreadableDirs
	for _, dir := range unreadableDirs {
		entries["unreadable:"+dir] = true // it may hold another build, as an unreadable copy may
	}
	for _, path := range built {
		a, ok := assembly.ReadAssembly(path)
		if !ok || a == nil || a.Failed {
			entries["unreadable:"+path] = true
			b.unreadable = append(b.unreadable, path)
			continue
		}
		if a.IsReferenceAssembly() {
			b.refOnly = append(b.refOnly, path)
			continue // a ref/ copy of the build: a stub surface, not a program
		}
		tfm := assemblyTFM(a, path)
		entries[tfm] = true
		tfmOf[path], ridOf[path] = tfm, builtRID(path, name)
		if b.fp == nil {
			b.fp, fpTFM = a, tfm
		}
	}
	if len(entries) > 1 {
		multiple = true
	}
	rids := map[string]bool{}
	for path, tfm := range tfmOf {
		if b.fp != nil && tfm == fpTFM {
			rids[ridOf[path]] = true
		}
	}
	for rid := range rids {
		b.runtime.RID = rid
		if rid != "" {
			b.rids = append(b.rids, rid)
		}
	}
	sort.Strings(b.rids)
	if len(rids) > 1 {
		b.runtime = assembly.Runtime{Ambiguous: true}
	}
	if multiple {
		b.reasons = append(b.reasons, partialReasonMultipleProjects)
	}

	path, data, ok := projectAssetsFile(buildDir, b.project)
	if !ok {
		return b
	}
	b.assets, b.assetsPath = data, path
	if t, bound := bindTarget(assetsTargetKeys(data), fpTFM); bound {
		b.target = t
	} else {
		b.reasons = append(b.reasons, partialReasonTargetUnbound)
	}
	return b
}

// findProjectFiles returns every project file under buildDir, sorted.
func findProjectFiles(buildDir string) []string {
	var found []string
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree yields no project; keep walking.
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".csproj", ".fsproj", ".vbproj":
			found = append(found, path)
		}
		return nil
	})
	sort.Strings(found)
	return found
}

// compiledProjects drops from projects (sorted, as findProjectFiles returns them) every one this
// build never compiled, so a tool project kept in the repo but outside the build, such as an
// installer the Dockerfile never publishes, is not a second program the run failed to trace.
//
// The SDK always writes a project's intermediate assembly to obj/<cfg>/<tfm>[/<rid>]/<name>.dll,
// whatever output path the build redirects to, so a project with no <name>.dll under its obj/,
// bin/ or publish/ was not compiled here. A project counts as compiled when any of those trees
// can't be read. The drop holds only while that convention is the one in force: every compiled
// project shows its intermediate assembly, nothing relocates obj/ (intermediateRelocated), and
// no compiled project references a dropped one. Otherwise, or when nothing was compiled, every
// project is kept.
func compiledProjects(buildDir string, projects []string) []string {
	if len(projects) < 2 || intermediateRelocated(buildDir, projects) {
		return projects
	}
	var kept, dropped []string
	for _, p := range projects {
		switch projectCompiled(p) {
		case compiledIntermediate:
			kept = append(kept, p)
		case compiledElsewhere:
			return projects // compiled, but not where the convention puts it
		default:
			dropped = append(dropped, p)
		}
	}
	if len(kept) == 0 || len(dropped) == 0 {
		return projects
	}
	for _, p := range kept {
		if referencesAny(p, dropped) {
			return projects
		}
	}
	return kept
}

type compiledState int

const (
	notCompiled          compiledState = iota
	compiledIntermediate               // obj/<cfg>/<tfm>[/<rid>]/<name>.dll, or an unreadable tree
	compiledElsewhere                  // a <name>.dll only outside the conventional obj/ path
)

// projectCompiled reports whether the project at path was compiled by this build, from the
// <name>.dll copies under its directory's obj/, bin/ and publish/.
func projectCompiled(path string) compiledState {
	dir := filepath.Dir(path)
	want := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) + ".dll"
	state := notCompiled
	for _, sub := range []string{"obj", "bin", "publish"} {
		root := filepath.Join(dir, sub)
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				if !(p == root && errors.Is(err, fs.ErrNotExist)) {
					state = compiledIntermediate // unreadable: it may hold the build
					return filepath.SkipAll
				}
				return nil
			}
			if d.IsDir() || d.Name() != want {
				return nil
			}
			if sub == "obj" {
				if rel, rerr := filepath.Rel(root, p); rerr == nil {
					if n := len(strings.Split(filepath.ToSlash(rel), "/")); n == 3 || n == 4 {
						state = compiledIntermediate
						return filepath.SkipAll
					}
				}
			}
			state = compiledElsewhere
			return nil
		})
		if state == compiledIntermediate {
			return state
		}
	}
	return state
}

// intermediateRelocated reports whether the build may write intermediate assemblies somewhere
// other than each project's obj/: an artifacts/ directory at the build root, or a project file
// or Directory.Build.props/.targets under it that sets one of the properties that move them.
// A file that can't be read counts as setting one.
func intermediateRelocated(buildDir string, projects []string) bool {
	if fi, err := os.Stat(filepath.Join(buildDir, "artifacts")); err == nil && fi.IsDir() {
		return true
	}
	files := append([]string(nil), projects...)
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree holds no project findProjectFiles saw.
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(d.Name()) {
		case "directory.build.props", "directory.build.targets":
			files = append(files, path)
		}
		return nil
	})
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil || intermediateProperty.Match(data) {
			return true
		}
	}
	return false
}

// intermediateProperty matches an MSBuild element setting a property that moves a project's
// intermediate output out of obj/<cfg>/<tfm>/.
var intermediateProperty = regexp.MustCompile(`(?i)<\s*(?:BaseIntermediateOutputPath|IntermediateOutputPath|MSBuildProjectExtensionsPath|UseArtifactsOutput|ArtifactsPath)\b`)

// projectReference matches a ProjectReference's Include path.
var projectReference = regexp.MustCompile(`(?i)<\s*ProjectReference\b[^>]*?\bInclude\s*=\s*["']([^"']+)["']`)

// referencesAny reports whether the project file at path references one of targets. A file
// that can't be read counts as referencing one.
func referencesAny(path string, targets []string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	for _, m := range projectReference.FindAllSubmatch(data, -1) {
		ref := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(strings.ReplaceAll(string(m[1]), `\`, "/"))))
		for _, t := range targets {
			if strings.EqualFold(ref, filepath.Clean(t)) {
				return true
			}
		}
	}
	return false
}

// projectAssetsFile reads the restore output for project: its own obj/project.assets.json when
// present, else the build's (readAssetsFile).
func projectAssetsFile(buildDir, project string) (string, []byte, bool) {
	own := filepath.Join(filepath.Dir(project), "obj", "project.assets.json")
	if data, err := os.ReadFile(own); err == nil {
		return own, data, true
	}
	return readAssetsFile(buildDir)
}

// builtAssemblies returns every "<name>.dll" under buildDir/bin then buildDir/publish, each
// tree in lexical order: one per configuration, target framework and publish copy. It also
// returns the directories under those trees it could not read, which may hold a copy.
func builtAssemblies(buildDir, name string) (out, unreadable []string) {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return nil, nil
	}
	want := name + ".dll"
	for _, sub := range []string{"bin", "publish"} {
		root := filepath.Join(buildDir, sub)
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if !(path == root && errors.Is(err, fs.ErrNotExist)) {
					unreadable = append(unreadable, path)
				}
				return nil //nolint:nilerr // an unreadable subtree yields no match; keep walking.
			}
			if !d.IsDir() && d.Name() == want {
				out = append(out, path)
			}
			return nil
		})
	}
	return out, unreadable
}

// builtRID is the runtime identifier a program copy was built for, from the <name>.deps.json
// the SDK writes beside it: its runtimeTarget.name is ".NETCoreApp,Version=v8.0/linux-x64"
// for a runtime-specific build and has no "/<rid>" for a portable one. "" when the file is
// absent, unreadable, or portable.
func builtRID(path, name string) string {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(path), name+".deps.json"))
	if err != nil {
		return ""
	}
	var deps struct {
		RuntimeTarget struct {
			Name string `json:"name"`
		} `json:"runtimeTarget"`
	}
	if json.Unmarshal(data, &deps) != nil {
		return ""
	}
	_, rid, _ := strings.Cut(deps.RuntimeTarget.Name, "/")
	if !validRID(rid) {
		return ""
	}
	return rid
}

// validRID admits a runtime identifier as a single assets-key segment ("linux-x64",
// "win10-x64", "linux-musl-arm64").
func validRID(rid string) bool {
	if rid == "" {
		return false
	}
	for _, r := range rid {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return false
		}
	}
	return !strings.Contains(rid, "..")
}

// assemblyTFM is the canonical framework a built assembly targets: its TargetFramework
// attribute, else the output directory's name (bin/Release/net8.0/App.dll). "" when neither
// names one.
func assemblyTFM(a *assembly.Assembly, path string) string {
	if s, ok := a.TargetFramework(); ok {
		if t, ok := canonicalTFM(s); ok {
			return t
		}
	}
	if t, ok := canonicalTFM(filepath.Base(filepath.Dir(path))); ok {
		return t
	}
	return ""
}

// assetsTargetKeys returns project.assets.json's targets keys.
func assetsTargetKeys(data []byte) []string {
	g := parseAssetsGraph(data)
	if g == nil {
		return nil
	}
	keys := make([]string, 0, len(g.targets))
	for k := range g.targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// bindTarget picks the restore target a build of framework tfm ran against. Runtime-specific
// keys ("net8.0/linux-x64") are not candidates. With tfm known, exactly one key must name the
// same framework; with tfm unknown, the restore must hold exactly one target.
func bindTarget(keys []string, tfm string) (string, bool) {
	var plain []string
	for _, k := range keys {
		if !strings.Contains(k, "/") {
			plain = append(plain, k)
		}
	}
	if tfm == "" {
		if len(plain) == 1 {
			return plain[0], true
		}
		return "", false
	}
	var match []string
	for _, k := range plain {
		if c, ok := canonicalTFM(k); ok && sameFramework(c, tfm) {
			match = append(match, k)
		}
	}
	if len(match) == 1 {
		return match[0], true
	}
	return "", false
}

// sameFramework compares canonical frameworks. A side without a platform ("netcoreapp|8.0",
// as the TargetFramework attribute spells net8.0-windows) matches any platform of the same
// framework and version; bindTarget's exactly-one rule rejects the resulting ambiguity.
func sameFramework(a, b string) bool {
	if a == b {
		return true
	}
	ab, ap, _ := strings.Cut(a, "#")
	bb, bp, _ := strings.Cut(b, "#")
	return ab == bb && (ap == "" || bp == "")
}

// canonicalTFM normalizes a target framework, in either the long form
// (".NETCoreApp,Version=v8.0") or the short folder form ("net8.0", "netcoreapp3.1",
// "netstandard2.0", "net472", "net8.0-windows"), to "identifier|version[#platform]".
func canonicalTFM(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if ident, rest, ok := strings.Cut(s, ",version="); ok {
		ident = strings.TrimPrefix(ident, ".")
		v, _, _ := strings.Cut(rest, ",")
		ver, ok := canonicalVersion(strings.TrimPrefix(v, "v"))
		if ident == "" || !ok {
			return "", false
		}
		return ident + "|" + ver, true
	}
	s, platform, _ := strings.Cut(s, "-")
	var ident, ver string
	switch {
	case strings.HasPrefix(s, "netcoreapp"):
		ident, ver = "netcoreapp", strings.TrimPrefix(s, "netcoreapp")
	case strings.HasPrefix(s, "netstandard"):
		ident, ver = "netstandard", strings.TrimPrefix(s, "netstandard")
	case strings.HasPrefix(s, "net"):
		ver = strings.TrimPrefix(s, "net")
		if major, _, dotted := strings.Cut(ver, "."); dotted {
			n, err := strconv.Atoi(major)
			if err != nil || n < 5 {
				return "", false
			}
			ident = "netcoreapp"
		} else {
			if ver == "" || strings.Trim(ver, "0123456789") != "" {
				return "", false
			}
			ident, ver = "netframework", strings.Join(strings.Split(ver, ""), ".")
		}
	default:
		return "", false
	}
	v, ok := canonicalVersion(ver)
	if !ok {
		return "", false
	}
	out := ident + "|" + v
	if platform != "" {
		out += "#" + platform
	}
	return out, true
}

// canonicalVersion renders a dotted numeric version with at least two components and no
// trailing zero components beyond them ("8" -> "8.0", "5.0.0" -> "5.0").
func canonicalVersion(v string) (string, bool) {
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return "", false
		}
	}
	for len(parts) > 2 && strings.Trim(parts[len(parts)-1], "0") == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 1 {
		parts = append(parts, "0")
	}
	return strings.Join(parts, "."), true
}
