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
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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
// The SDK always writes a project's intermediate assembly to obj/<cfg>/<tfm>[/<rid>]/, whatever
// output path the build redirects to, while restore alone writes no assembly there. So a project
// with no .dll under its obj/, bin/ or publish/ was not compiled here; the assembly's name is not
// consulted, since AssemblyName can differ from the project file's. A project counts as compiled
// when any of those trees can't be read. The drop holds only while that convention is the one in
// force: every compiled project shows an intermediate assembly no older than its restore output,
// nothing relocates obj/ (intermediateRelocated), and no compiled project references a dropped
// one. Otherwise, or when nothing was compiled, every project is kept.
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
	compiledIntermediate               // a fresh obj/<cfg>/<tfm>[/<rid>]/*.dll, or an unreadable tree
	compiledElsewhere                  // a .dll only outside the conventional obj/ path, or a stale one
)

// projectCompiled reports whether the project at path was compiled by this build, from the
// assemblies under its directory's obj/, bin/ and publish/. An intermediate assembly older than
// obj/project.assets.json predates the last restore, so it may be a cached or committed leftover
// rather than this build's.
func projectCompiled(path string) compiledState {
	dir := filepath.Dir(path)
	var restored time.Time
	if fi, err := os.Stat(filepath.Join(dir, "obj", "project.assets.json")); err == nil {
		restored = fi.ModTime()
	}
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
			if d.IsDir() || !strings.EqualFold(filepath.Ext(d.Name()), ".dll") {
				return nil
			}
			if sub == "obj" {
				if rel, rerr := filepath.Rel(root, p); rerr == nil {
					if n := len(strings.Split(filepath.ToSlash(rel), "/")); n == 3 || n == 4 {
						if fi, ierr := d.Info(); ierr != nil || !fi.ModTime().Before(restored) {
							state = compiledIntermediate
							return filepath.SkipAll
						}
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
// other than each project's obj/. It reads every MSBuild input that can set a property moving
// them: the project files and their .user files; every .props and .targets file and
// Directory.Build.rsp under buildDir (outside the directories skipDir skips, which hold no input
// the build reads unless imported); Directory.Build.props, .targets and .rsp in buildDir's
// ancestors; and, transitively, every file those import. It reports true when one of them sets
// such a property, when an artifacts/ directory sits at the build root, or when an input can't
// be read or an import path can't be resolved.
func intermediateRelocated(buildDir string, projects []string) bool {
	if fi, err := os.Stat(filepath.Join(buildDir, "artifacts")); err == nil && fi.IsDir() {
		return true
	}
	var queue []string
	for _, p := range projects {
		queue = append(queue, p)
		if _, err := os.Stat(p + ".user"); err == nil {
			queue = append(queue, p+".user")
		}
	}
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
		switch name := strings.ToLower(d.Name()); {
		case strings.HasSuffix(name, ".props"), strings.HasSuffix(name, ".targets"), name == "directory.build.rsp":
			queue = append(queue, path)
		}
		return nil
	})
	for dir := filepath.Dir(filepath.Clean(buildDir)); ; dir = filepath.Dir(dir) {
		for _, n := range []string{"Directory.Build.props", "Directory.Build.targets", "Directory.Build.rsp"} {
			if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
				queue = append(queue, filepath.Join(dir, n))
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		f := filepath.Clean(queue[0])
		queue = queue[1:]
		if seen[f] {
			continue
		}
		seen[f] = true
		data, err := os.ReadFile(f)
		if err != nil || intermediateProperty.Match(data) {
			return true
		}
		imports, ok := importedFiles(f, data, projects)
		if !ok {
			return true
		}
		queue = append(queue, imports...)
	}
	return false
}

// importElement matches an MSBuild <Import> element's attributes; importAttr one attribute.
var (
	importElement = regexp.MustCompile(`(?is)<\s*Import\b((?:[^>"']|"[^"]*"|'[^']*')*)>`)
	importAttr    = regexp.MustCompile(`(?is)\b(Project|Sdk)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	importProp    = regexp.MustCompile(`\$\(\s*([A-Za-z0-9_]+)\s*\)`)
)

// toolchainRoots are the properties that root an import in the MSBuild or Visual Studio install,
// not in the repository.
var toolchainRoots = map[string]bool{
	"msbuildtoolspath": true, "msbuildbinpath": true, "msbuildextensionspath": true,
	"msbuildextensionspath32": true, "msbuildextensionspath64": true, "vstoolspath": true,
	"msbuildsdkspath": true,
}

// importedFiles returns the repository files the MSBuild file f imports. Each <Import Project>
// outside an XML comment or CDATA section is entity-decoded and unescaped, the MSBuildThisFile*
// properties are expanded for f and $(MSBuildProjectDirectory) to the directory of each project that
// may import f (f's own directory for a project or .user file), [MSBuild]::GetPathOfFileAbove and
// GetDirectoryNameOfFileAbove are evaluated, and the result is resolved against f's directory. A
// relative start directory for those functions is tried against f's directory and each project
// directory, since which one MSBuild uses depends on the evaluating process. Sdk imports and imports rooted in
// the toolchain are skipped, and so is a path that names no existing file, since the build would
// have failed had it been required. It reports false when a path depends on anything else.
func importedFiles(f string, data []byte, projects []string) ([]string, bool) {
	dir := filepath.Dir(f)
	projDirs := []string{dir}
	if ext := strings.ToLower(filepath.Ext(f)); ext != ".csproj" && ext != ".fsproj" && ext != ".vbproj" && ext != ".user" {
		projDirs = projDirs[:0]
		for _, p := range projects {
			projDirs = append(projDirs, filepath.Dir(p))
		}
	}
	var out []string
	for _, el := range importElement.FindAllSubmatch(xmlInert.ReplaceAll(data, nil), -1) {
		var project string
		sdk := false
		for _, a := range importAttr.FindAllSubmatch(el[1], -1) {
			if strings.EqualFold(string(a[1]), "Sdk") {
				sdk = true
			} else {
				project = string(a[2]) + string(a[3])
			}
		}
		project = strings.TrimSpace(msbuildUnescape(html.UnescapeString(project)))
		if sdk || project == "" {
			continue
		}
		if m := importProp.FindStringSubmatch(project); m != nil && strings.HasPrefix(project, m[0]) && toolchainRoots[strings.ToLower(m[1])] {
			continue
		}
		var expansions []string
		perProject := strings.Contains(strings.ToLower(project), "msbuildprojectdirectory")
		if !perProject {
			expansions = append(expansions, expandImport(project, f, dir))
		}
		if perProject || strings.Contains(strings.ToLower(project), "fileabove") {
			for _, pd := range projDirs {
				expansions = append(expansions, expandImport(project, f, pd))
			}
		}
		for _, e := range expansions {
			paths, ok := resolveImport(e, dir)
			if !ok {
				return nil, false
			}
			out = append(out, paths...)
		}
	}
	return out, true
}

var (
	xmlInert         = regexp.MustCompile(`(?s)<!--.*?-->|<!\[CDATA\[.*?\]\]>`) // one pass: whichever opens first wins
	msbuildEscape    = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	fileAboveFunc    = regexp.MustCompile(`(?i)\$\(\s*\[MSBuild\]::(GetPathOfFileAbove|GetDirectoryNameOfFileAbove)\(\s*([^,()]*?)\s*(?:,\s*([^,()]*?)\s*)?\)\s*\)`)
	unresolvedSyntax = regexp.MustCompile(`[$@%]\(`)
)

// msbuildUnescape decodes MSBuild's %XX escapes.
func msbuildUnescape(s string) string {
	return msbuildEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[1:], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

// expandImport expands the properties importedFiles models in an import path: the
// MSBuildThisFile* properties for thisFile and projDir for $(MSBuildProjectDirectory), then the
// file-above property functions, whose relative start directory is taken against projDir. Anything
// else is left in place for resolveImport to refuse.
func expandImport(project, thisFile, projDir string) string {
	thisDir := filepath.Dir(thisFile)
	base := filepath.Base(thisFile)
	s := importProp.ReplaceAllStringFunc(project, func(m string) string {
		switch strings.ToLower(importProp.FindStringSubmatch(m)[1]) {
		case "msbuildthisfiledirectory":
			return thisDir + "/"
		case "msbuildthisfile":
			return base
		case "msbuildthisfilename":
			return strings.TrimSuffix(base, filepath.Ext(base))
		case "msbuildthisfileextension":
			return filepath.Ext(base)
		case "msbuildthisfilefullpath":
			return thisFile
		case "msbuildprojectdirectory":
			return projDir
		}
		return m
	})
	return fileAboveFunc.ReplaceAllStringFunc(s, func(m string) string {
		g := fileAboveFunc.FindStringSubmatch(m)
		unq := func(a string) string { return strings.Trim(strings.TrimSpace(a), `'"`) }
		name, start := unq(g[2]), thisDir
		if strings.EqualFold(g[1], "GetDirectoryNameOfFileAbove") {
			start, name = unq(g[2]), unq(g[3])
		} else if g[3] != "" {
			start = unq(g[3])
		}
		if name == "" || start == "" || unresolvedSyntax.MatchString(name+start) {
			return m
		}
		start = filepath.FromSlash(strings.ReplaceAll(start, `\`, "/"))
		name = filepath.FromSlash(strings.ReplaceAll(name, `\`, "/"))
		if !filepath.IsAbs(start) {
			start = filepath.Join(projDir, start)
		}
		for d := filepath.Clean(start); ; d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, name)); err == nil {
				if strings.EqualFold(g[1], "GetDirectoryNameOfFileAbove") {
					return d
				}
				return filepath.Join(d, name)
			}
			if filepath.Dir(d) == d {
				return "" // not found: MSBuild evaluates both functions to the empty string
			}
		}
	})
}

// resolveImport resolves an expanded import path against dir, reporting false when it still
// depends on a property, item or metadata reference. A path with a wildcard is globbed; any
// other names at most the one file that exists.
func resolveImport(expanded, dir string) ([]string, bool) {
	if unresolvedSyntax.MatchString(expanded) {
		return nil, false
	}
	rel := filepath.FromSlash(strings.ReplaceAll(strings.TrimSpace(expanded), `\`, "/"))
	if rel == "" {
		return nil, true
	}
	if strings.Contains(rel, "**") {
		return nil, false // a recursive wildcard; filepath.Glob would match one segment
	}
	if !strings.ContainsAny(rel, "*?") {
		path := rel
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		if _, err := os.Stat(path); err != nil {
			return nil, true
		}
		return []string{path}, true
	}
	pattern := rel
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(globEscape(dir), rel)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, false
	}
	return matches, true
}

// globEscape escapes the filepath.Match metacharacters in a literal path.
func globEscape(p string) string {
	if filepath.Separator == '\\' {
		return strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]").Replace(p)
	}
	return strings.NewReplacer(`\`, `\\`, "[", `\[`, "*", `\*`, "?", `\?`).Replace(p)
}

// intermediateProperty matches an MSBuild element, or a response-file -p:/-property: assignment,
// setting a property that moves a project's intermediate output out of obj/<cfg>/<tfm>/, or the
// --artifacts-path switch.
var intermediateProperty = regexp.MustCompile(`(?i)(?:<|[:;,])\s*(?:BaseIntermediateOutputPath|IntermediateOutputPath|MSBuildProjectExtensionsPath|UseArtifactsOutput|ArtifactsPath)\b|artifacts-path`)

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
