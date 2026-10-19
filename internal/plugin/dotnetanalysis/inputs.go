package dotnetanalysis

// inputs.go — the inputs MSBuild and NuGet consult when they evaluate and restore a project,
// and which of them this lane models. A project's installed versions, and the restore output
// the IL tier loads its dependencies from, are trusted only when every input that could move
// them is enumerated, read and compared. buildInputs is that list for files; the evaluator
// applies it, together with the rules for properties, imports, SDKs and project references
// documented on evaluate. An input that is present but not modeled, or that can't be ruled
// absent, withholds: the project's versions are reported unresolved with a reason.
//
// What the lane does not see, and treats as run conditions the CI build provides: the
// environment and global properties (/p:) of the build, the toolset's own MSBuild.rsp, the
// user- and machine-level NuGet.Config, the installed SDK and the files it imports implicitly,
// the contents of the global packages folder, and changes CI steps make to the tree before
// the build. An environment variable can't reach a version this lane reads, because any
// $(Property) that isn't computed from a file path withholds wherever it appears in an import,
// a reference, a version or a property this lane acts on.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
)

const (
	// reasonBuildInputUnmodeled: a file MSBuild or NuGet would consult for the project is
	// present and not modeled (or can't be ruled absent), so what restore installs is unknown.
	reasonBuildInputUnmodeled = "build_input_unmodeled"

	// reasonRestoreOutputStale: obj/project.assets.json (or the lockfile's shape) doesn't match
	// the project as it now stands, so it is not what the next restore installs.
	reasonRestoreOutputStale = "restore_output_stale"
)

// inputScope is where MSBuild or NuGet looks for an input, relative to a project.
type inputScope uint8

const (
	// scopeWalkUp: the project's directory and every directory above it, to the filesystem root.
	scopeWalkUp inputScope = 1 << iota
	// scopeProjectDir: the project's own directory.
	scopeProjectDir
	// scopeObj: the project's obj/ directory (MSBuildProjectExtensionsPath).
	scopeObj
	// scopeTree: anywhere in the build tree (an entry point other than the project, such as a
	// solution, can sit anywhere).
	scopeTree
)

// inputID names one buildInputs entry.
type inputID uint8

const (
	inDirectoryBuildProps inputID = iota
	inDirectoryBuildTargets
	inDirectoryPackagesProps
	inGlobalJSON
	inNuGetConfig
	inResponseFile
	inUserFile
	inLockfile
	inPackagesConfig
	inOtherRestoreManifest
	inAssets
	inNuGetCache
	inDgspec
	inRestoreGenerated
	inProjectExtension
	inSolutionHook
)

// buildInput is one file input. withholds is true when its presence alone withholds the
// project's versions; otherwise how says what reads it and what it is compared to.
type buildInput struct {
	id        inputID
	scope     inputScope
	names     []string // exact-case file names; "<proj>" is the project file's name, "*" any run of characters
	withholds bool
	how       string
}

// buildInputs is every file input this lane knows MSBuild or NuGet consults for a project.
// Within a scope the first entry whose name matches exactly decides; a name that matches an
// entry only without regard to case withholds (a case-sensitive build host ignores it, a
// case-insensitive one reads it). In walk-up scope, any match in a directory above the build
// tree withholds.
var buildInputs = []buildInput{
	{inDirectoryBuildProps, scopeWalkUp, []string{"Directory.Build.props"}, false,
		"the nearest one is read with the project; its imports are followed"},
	{inDirectoryBuildTargets, scopeWalkUp, []string{"Directory.Build.targets"}, false,
		"the nearest one is read with the project; its imports are followed"},
	{inDirectoryPackagesProps, scopeWalkUp, []string{"Directory.Packages.props"}, false,
		"the nearest one is read for PackageVersion and GlobalPackageReference; its versions are compared to the lockfile's and the restore output's"},
	{inGlobalJSON, scopeWalkUp | scopeTree, []string{"global.json"}, false,
		"validated: only sdk.version, sdk.rollForward, sdk.allowPrerelease and sdk.errorMessage, which pick the SDK (a run condition); msbuild-sdks, paths or anything else withholds"},
	{inNuGetConfig, scopeWalkUp | scopeTree, []string{"nuget.config", "NuGet.config", "NuGet.Config"}, false,
		"validated: only the documented sections, which choose sources, folders and credentials, never a requested range; compared ranges come from the project"},
	{inResponseFile, scopeWalkUp | scopeTree, []string{"Directory.Build.rsp"}, true,
		"MSBuild command-line switches; -p: can set any property"},
	{inUserFile, scopeProjectDir, []string{"<proj>.user"}, true,
		"imported after the project by Microsoft.Common.targets"},
	{inLockfile, scopeProjectDir, []string{"packages.lock.json"}, false,
		"each target's section is compared to the evaluated project (lockCurrent)"},
	{inPackagesConfig, scopeProjectDir, []string{"packages.config"}, false,
		"a legacy project's complete package set, exact versions"},
	{inOtherRestoreManifest, scopeProjectDir, []string{"packages.*.lock.json", "packages.*.config", "project.json"}, true,
		"a per-project lockfile or packages.config name, or project.json restore"},
	{inAssets, scopeObj, []string{"project.assets.json"}, false,
		"trusted only when it matches the evaluated project (checkAssets)"},
	{inNuGetCache, scopeObj, []string{"project.nuget.cache"}, false,
		"must record a successful restore of this project file"},
	{inDgspec, scopeObj, []string{"<proj>.nuget.dgspec.json"}, false,
		"its entry for this project must equal the restore output's project spec"},
	{inRestoreGenerated, scopeObj, []string{"<proj>.nuget.g.props", "<proj>.nuget.g.targets"}, false,
		"written by restore with the assets file; trusted only alongside a trusted assets file"},
	{inProjectExtension, scopeObj, []string{"<proj>.*.props", "<proj>.*.targets"}, true,
		"imported into the project from MSBuildProjectExtensionsPath"},
	{inSolutionHook, scopeTree, []string{"Directory.Solution.props", "Directory.Solution.targets", "before.*.sln.targets", "after.*.sln.targets"}, true,
		"imported when a solution is the build's entry point"},
}

// computedProperties are the properties MSBuild computes from the path of the project or the
// file being evaluated; the environment can't set them. Every other $(Property) withholds.
var computedProperties = map[string]func(project, thisFile string) string{
	"msbuildprojectdirectory": func(p, _ string) string { return filepath.Dir(p) },
	"msbuildprojectfullpath":  func(p, _ string) string { return p },
	"msbuildprojectfile":      func(p, _ string) string { return filepath.Base(p) },
	"msbuildprojectname":      func(p, _ string) string { return strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)) },
	"msbuildprojectextension": func(p, _ string) string { return filepath.Ext(p) },
	"msbuildthisfiledirectory": func(_, f string) string {
		return filepath.Dir(f) + string(filepath.Separator)
	},
	"msbuildthisfile":          func(_, f string) string { return filepath.Base(f) },
	"msbuildthisfilefullpath":  func(_, f string) string { return f },
	"msbuildthisfilename":      func(_, f string) string { return strings.TrimSuffix(filepath.Base(f), filepath.Ext(f)) },
	"msbuildthisfileextension": func(_, f string) string { return filepath.Ext(f) },
}

// toolsetPrefixes are the reserved properties an Import may start with to name a file of the
// MSBuild installation. MSBuild refuses to let the environment or a project set them
// (MSB4004), so they are a run condition, not a project input.
var toolsetPrefixes = []string{"$(msbuildtoolspath)", "$(msbuildbinpath)"}

// bundledSDKs is the exact set of SDKs the .NET SDK ships. They add no package references of
// their own beyond the implicit ones restore records. Any other SDK, or any version on one
// (which routes resolution through an SDK resolver), withholds.
var bundledSDKs = []string{
	"microsoft.net.sdk", "microsoft.net.sdk.blazorwebassembly", "microsoft.net.sdk.publish",
	"microsoft.net.sdk.razor", "microsoft.net.sdk.staticwebassets", "microsoft.net.sdk.web",
	"microsoft.net.sdk.web.projectsystem", "microsoft.net.sdk.webassembly",
	"microsoft.net.sdk.windowsdesktop", "microsoft.net.sdk.worker",
}

// identityProperties change how a project appears as a reference in another project's
// lockfile or restore output.
var identityProperties = []string{"packageid", "assemblyname", "version", "versionprefix", "versionsuffix", "packageversion"}

// parentImport is the one property function an Import may use: the documented way of
// chaining to the same-named file above the importing one.
var parentImport = regexp.MustCompile(`(?i)^\$\(\[MSBuild\]::GetPathOfFileAbove\(\s*'([^'/\\$@%*?;]+)'\s*,\s*'\$\(MSBuildThisFileDirectory\)\.\.[/\\]?'\s*\)\)$`)

// existsCondition matches a Condition of the form Exists('<path>').
var existsCondition = regexp.MustCompile(`(?i)^\s*exists\s*\(\s*'([^']*)'\s*\)\s*$`)

var propertyRef = regexp.MustCompile(`\$\(([A-Za-z_][A-Za-z0-9_.\-]*)\)`)

// inputStatus is the outcome of readInput.
type inputStatus uint8

const (
	inputRead inputStatus = iota
	inputAbsent
	// inputUnmodeled: outside the build tree once symlinks are resolved, not a regular file, or
	// found only by a case-insensitive lookup.
	inputUnmodeled
	inputUnreadable
)

// readInput reads one input file. It is read only when, once symlinks are resolved, it is a
// regular file inside rootReal whose name matches exactly; a FIFO or device is never opened.
// A leading byte-order mark is stripped. real is the resolved path.
func readInput(rootReal, path string) (data []byte, real string, status inputStatus) {
	if _, err := os.Lstat(path); err != nil {
		if absent(err) {
			return nil, "", inputAbsent
		}
		return nil, "", inputUnreadable
	}
	if !exactName(path) {
		return nil, "", inputUnmodeled
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, "", inputUnreadable
	}
	if !withinDir(rootReal, real) {
		return nil, "", inputUnmodeled
	}
	fi, err := os.Stat(real)
	if err != nil {
		return nil, "", inputUnreadable
	}
	if !fi.Mode().IsRegular() {
		return nil, "", inputUnmodeled
	}
	// Non-blocking, so a file swapped for a FIFO after the Stat can't hang the open; the
	// SameFile check then rejects anything but the regular file that was checked.
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", inputUnreadable
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !os.SameFile(fi, opened) {
		return nil, "", inputUnmodeled
	}
	data, err = io.ReadAll(f)
	if err != nil {
		return nil, "", inputUnreadable
	}
	return stripBOM(data), real, inputRead
}

// absent reports whether err says the path isn't there (a missing entry, or a parent that
// is a file).
func absent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// exactName reports whether path's directory lists an entry with exactly path's base name.
func exactName(path string) bool {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return false
	}
	base := filepath.Base(path)
	for _, e := range entries {
		if e.Name() == base {
			return true
		}
	}
	return false
}

func stripBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
}

// realRoot resolves the build directory's symlinks; withinDir checks run against it.
func realRoot(root string) string {
	if r, err := filepath.EvalSymlinks(root); err == nil {
		return r
	}
	return filepath.Clean(root)
}

// matchInput returns the buildInputs entry name matches in scope, for project file proj.
// exact is false when the name matches only without regard to case.
func matchInput(scope inputScope, name, proj string) (in *buildInput, exact bool) {
	var folded *buildInput
	for i := range buildInputs {
		b := &buildInputs[i]
		if b.scope&scope == 0 {
			continue
		}
		for _, pat := range b.names {
			if namePattern(pat, proj, false).MatchString(name) {
				return b, true
			}
			if folded == nil && namePattern(pat, proj, true).MatchString(name) {
				folded = b
			}
		}
	}
	return folded, false
}

func namePattern(pat, proj string, fold bool) *regexp.Regexp {
	var b strings.Builder
	if fold {
		b.WriteString("(?i)")
	}
	b.WriteString("^")
	for i, part := range strings.Split(pat, "<proj>") {
		if i > 0 {
			b.WriteString(regexp.QuoteMeta(proj))
		}
		for j, lit := range strings.Split(part, "*") {
			if j > 0 {
				b.WriteString(".*")
			}
			b.WriteString(regexp.QuoteMeta(lit))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// projectEval is what evaluating one project file established.
type projectEval struct {
	path   string // resolved path of the project file
	dir    string
	reason string // non-empty when an input isn't modeled; nothing below is then trusted

	decl      declaration
	tfms      []string // canonical target frameworks; nil when not one literal assignment
	rids      []string
	ridsKnown bool
	refs      []projectRef      // direct ProjectReferences
	central   map[string]string // PackageVersion by normalized id; nil when no Directory.Packages.props
	cpm       bool              // ManagePackageVersionsCentrally is true
	identity  bool              // sets a property that names it as a reference
	pinning   bool              // CentralPackageTransitivePinningEnabled is true
	generated bool              // obj/ holds restore-generated imports for it
}

type projectRef struct {
	path        string // resolved
	conditioned bool
}

// msbuildRead is one MSBuild file read while evaluating a project.
type msbuildRead struct {
	mf          msbuildFile
	path        string
	role        msbuildRole
	injected    bool // a file other than the project itself
	conditioned bool // imported under a Condition
}

// evaluator evaluates the projects of one build tree, memoizing each.
type evaluator struct {
	root, rootReal string
	projects       map[string]bool // resolved paths of the tree's project files
	evals          map[string]*projectEval
	inFlight       map[string]bool
	configs        map[string]bool // validated global.json / nuget.config, by path
	treeReason     string
}

func newEvaluator(root string, projectFiles []string) *evaluator {
	e := &evaluator{
		root:     root,
		rootReal: realRoot(root),
		projects: make(map[string]bool),
		evals:    make(map[string]*projectEval),
		inFlight: make(map[string]bool),
		configs:  make(map[string]bool),
	}
	for _, p := range projectFiles {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			e.projects[r] = true
		}
	}
	e.treeReason = e.scanTree()
	return e
}

// scanTree applies the tree-scope entries: a solution hook or response file anywhere in the
// tree withholds every project, and every global.json and nuget.config must validate.
func (e *evaluator) scanTree() string {
	reason := ""
	err := filepath.WalkDir(e.rootReal, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			reason = reasonBuildInputUnmodeled
			return filepath.SkipAll
		}
		if d.IsDir() {
			if path != e.rootReal && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		in, exact := matchInput(scopeTree, d.Name(), "")
		switch {
		case in == nil:
		case in.withholds:
			reason = reasonBuildInputUnmodeled
		case !exact:
		case !e.validConfig(path, in.id):
			reason = reasonBuildInputUnmodeled
		}
		if reason != "" {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return reasonBuildInputUnmodeled
	}
	return reason
}

// validConfig validates a global.json or nuget.config once.
func (e *evaluator) validConfig(path string, id inputID) bool {
	if ok, seen := e.configs[path]; seen {
		return ok
	}
	data, _, st := readInput(e.rootReal, path)
	ok := false
	if st == inputRead {
		switch id {
		case inGlobalJSON:
			ok = validGlobalJSON(data)
		case inNuGetConfig:
			ok = validNuGetConfig(data)
		}
	}
	e.configs[path] = ok
	return ok
}

// evalPath evaluates the project file at path (as found in the tree).
func (e *evaluator) evalPath(path string) *projectEval {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !e.projects[real] {
		return &projectEval{path: path, dir: filepath.Dir(path), reason: reasonBuildInputUnmodeled}
	}
	return e.eval(real)
}

func (e *evaluator) eval(real string) *projectEval {
	if pe, ok := e.evals[real]; ok {
		return pe
	}
	if e.inFlight[real] {
		return &projectEval{path: real, dir: filepath.Dir(real), reason: reasonBuildInputUnmodeled}
	}
	e.inFlight[real] = true
	pe := e.evaluate(real)
	delete(e.inFlight, real)
	e.evals[real] = pe
	return pe
}

// evaluate establishes what a project declares, the way MSBuild assembles it, from inputs
// this lane models; pe.reason is set at the first input it doesn't:
//
//   - the file inputs of buildInputs, in the project's directory, its obj/, every directory
//     above it and the whole tree;
//   - the project file, the nearest Directory.Build.props and Directory.Build.targets, the
//     nearest Directory.Packages.props, and every file they import, each read by parseMSBuild;
//   - an Import of a bundled SDK, or of a toolset file ($(MSBuildToolsPath)…), is the
//     installation's and is skipped; the canonical GetPathOfFileAbove('<name>',
//     '$(MSBuildThisFileDirectory)../') resolves to the nearest such file above the importing
//     one; any other Import path may use only computedProperties, and must resolve to a file
//     in the tree, or be absent under exactly Exists('<the same path>');
//   - every ProjectReference must be one literal path to a project file of the tree, which is
//     evaluated in turn; its limits are the referencing project's.
func (e *evaluator) evaluate(real string) *projectEval {
	pe := &projectEval{path: real, dir: filepath.Dir(real), decl: newDeclaration()}
	fail := func(reason string) *projectEval {
		pe.reason = reason
		return pe
	}
	if e.treeReason != "" {
		return fail(e.treeReason)
	}
	nearest, reason := e.scanInputs(pe)
	if reason != "" {
		return fail(reason)
	}
	var reads []msbuildRead
	seen := make(map[string]bool)
	read := func(path string, role msbuildRole, injected bool) string {
		return e.readMSBuildTree(pe, &reads, seen, path, role, injected, false, 0)
	}
	if r := read(real, roleProject, false); r != "" {
		return fail(r)
	}
	for _, id := range []inputID{inDirectoryBuildProps, inDirectoryBuildTargets, inDirectoryPackagesProps} {
		path := nearest[id]
		if path == "" {
			continue
		}
		role := roleProject
		if id == inDirectoryPackagesProps {
			role = roleCentral
		}
		if r := read(path, role, true); r != "" {
			return fail(r)
		}
	}
	if r := e.finalize(pe, reads); r != "" {
		return fail(r)
	}
	return pe
}

// scanInputs applies the project-directory, obj and walk-up entries of buildInputs, and
// returns the nearest Directory.Build.props, Directory.Build.targets and
// Directory.Packages.props.
func (e *evaluator) scanInputs(pe *projectEval) (map[inputID]string, string) {
	proj := filepath.Base(pe.path)
	nearest := make(map[inputID]string)
	for _, sc := range []struct {
		dir   string
		scope inputScope
	}{{pe.dir, scopeProjectDir}, {filepath.Join(pe.dir, "obj"), scopeObj}} {
		entries, err := os.ReadDir(sc.dir)
		if err != nil {
			if absent(err) && sc.scope == scopeObj {
				continue
			}
			return nil, reasonBuildInputUnmodeled
		}
		for _, ent := range entries {
			in, exact := matchInput(sc.scope, ent.Name(), proj)
			switch {
			case in == nil:
			case in.withholds || !exact:
				return nil, reasonBuildInputUnmodeled
			case in.id == inRestoreGenerated:
				pe.generated = true
			}
		}
	}
	for dir := pe.dir; ; {
		above := !withinDir(e.rootReal, dir)
		names, ok := walkUpNames(dir)
		if !ok {
			return nil, reasonBuildInputUnmodeled
		}
		for _, name := range names {
			in, exact := matchInput(scopeWalkUp, name, proj)
			switch {
			case in == nil:
				continue
			case above || in.withholds || !exact:
				return nil, reasonBuildInputUnmodeled
			}
			path := filepath.Join(dir, name)
			switch in.id {
			case inDirectoryBuildProps, inDirectoryBuildTargets, inDirectoryPackagesProps:
				if nearest[in.id] == "" {
					nearest[in.id] = path
				}
			case inGlobalJSON, inNuGetConfig:
				if !e.validConfig(path, in.id) {
					return nil, reasonBuildInputUnmodeled
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nearest, ""
		}
		dir = parent
	}
}

// walkUpNames lists dir. When dir can be searched but not listed, it reports the walk-up
// names present by looking each up; any other failure is not ok.
func walkUpNames(dir string) ([]string, bool) {
	entries, err := os.ReadDir(dir)
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, ent := range entries {
			names = append(names, ent.Name())
		}
		return names, true
	}
	var names []string
	for _, b := range buildInputs {
		if b.scope&scopeWalkUp == 0 {
			continue
		}
		for _, n := range b.names {
			_, err := os.Lstat(filepath.Join(dir, n))
			switch {
			case err == nil:
				names = append(names, n)
			case !absent(err):
				return nil, false
			}
		}
	}
	return names, true
}

// readMSBuildTree reads one MSBuild file and, recursively, what it imports.
func (e *evaluator) readMSBuildTree(pe *projectEval, reads *[]msbuildRead, seen map[string]bool, path string, role msbuildRole, injected, conditioned bool, depth int) string {
	if depth > 16 {
		return reasonBuildInputUnmodeled
	}
	data, real, st := readInput(e.rootReal, path)
	if st != inputRead || seen[real] {
		return reasonBuildInputUnmodeled
	}
	seen[real] = true
	mf, ok := parseMSBuild(data, role, "msbuild")
	if !ok {
		return reasonPackageReferenceUnmodeled
	}
	*reads = append(*reads, msbuildRead{mf: mf, path: real, role: role, injected: injected, conditioned: conditioned})
	for _, imp := range mf.imports {
		target, cond, skip, reason := e.resolveImport(pe, real, imp)
		if reason != "" {
			return reason
		}
		if skip {
			continue
		}
		if r := e.readMSBuildTree(pe, reads, seen, target, role, true, conditioned || cond, depth+1); r != "" {
			return r
		}
	}
	return ""
}

// resolveImport decides one Import of the file at from: the file it names, whether its
// contents apply only under a Condition, or that it is skipped (a toolset file, or absent
// under Exists of the same path).
func (e *evaluator) resolveImport(pe *projectEval, from string, imp msbuildImport) (target string, conditioned, skip bool, reason string) {
	raw := imp.project
	lower := strings.ToLower(raw)
	for _, prefix := range toolsetPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return "", false, true, ""
		}
	}
	if m := parentImport.FindStringSubmatch(raw); m != nil {
		found, ok := fileAbove(filepath.Dir(filepath.Dir(from)), m[1])
		if !ok {
			return "", false, false, reasonBuildInputUnmodeled
		}
		target = found
	} else {
		p, ok := expandComputed(raw, pe.path, from)
		if !ok {
			return "", false, false, reasonBuildInputUnmodeled
		}
		p = filepath.FromSlash(strings.ReplaceAll(p, `\`, "/"))
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(from), p)
		}
		target = filepath.Clean(p)
	}
	existsSame := false
	if m := existsCondition.FindStringSubmatch(imp.condition); m != nil && strings.TrimSpace(m[1]) == raw {
		existsSame = true
	}
	present := false
	if target != "" {
		_, err := os.Lstat(target)
		switch {
		case err == nil:
			present = true
		case !absent(err):
			return "", false, false, reasonBuildInputUnmodeled
		}
	}
	if !present {
		if existsSame {
			return "", false, true, ""
		}
		return "", false, false, reasonBuildInputUnmodeled
	}
	conditioned = imp.groupConditioned || imp.condition != "" && !existsSame
	return target, conditioned, false, ""
}

// fileAbove is GetPathOfFileAbove: the nearest file called name in start or a directory
// above it, "" when there is none. ok is false when it can't be ruled absent somewhere.
func fileAbove(start, name string) (string, bool) {
	for dir := start; ; {
		p := filepath.Join(dir, name)
		_, err := os.Lstat(p)
		switch {
		case err == nil:
			return p, true
		case !absent(err):
			return "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", true
		}
		dir = parent
	}
}

// expandComputed substitutes the computedProperties in s, for the project at project and the
// file thisFile. ok is false when anything else MSBuild would expand remains: another
// $(Property), a property function, an @(item) or %(metadata) reference, or a wildcard.
func expandComputed(s, project, thisFile string) (string, bool) {
	out := propertyRef.ReplaceAllStringFunc(s, func(ref string) string {
		name := strings.ToLower(ref[2 : len(ref)-1])
		if f, ok := computedProperties[name]; ok {
			return f(project, thisFile)
		}
		return ref
	})
	if strings.Contains(out, "$(") || strings.Contains(out, "@(") || strings.Contains(out, "%(") || strings.ContainsAny(out, "*?") {
		return "", false
	}
	return out, true
}

// finalize folds what the files declared into pe.
func (e *evaluator) finalize(pe *projectEval, reads []msbuildRead) string {
	type assignment struct {
		value       string
		conditioned bool
	}
	assigned := make(map[string][]assignment)
	for _, r := range reads {
		for _, p := range r.mf.props {
			assigned[p.name] = append(assigned[p.name], assignment{p.value, p.conditioned || r.conditioned})
		}
	}
	for _, a := range assigned["managepackageversionscentrally"] {
		if a.conditioned {
			return reasonPackageReferenceUnmodeled
		}
		pe.cpm = true
	}
	if a := assigned["centralpackagetransitivepinningenabled"]; len(a) > 0 {
		pe.pinning = strings.EqualFold(a[len(a)-1].value, "true")
	}
	for _, name := range identityProperties {
		if len(assigned[name]) > 0 {
			pe.identity = true
		}
	}
	single := func(names ...string) (string, bool, bool) {
		var all []assignment
		for _, n := range names {
			all = append(all, assigned[n]...)
		}
		switch {
		case len(all) == 0:
			return "", false, true
		case len(all) > 1 || all[0].conditioned || strings.Contains(all[0].value, "$("):
			return "", false, false
		}
		return all[0].value, true, true
	}
	if v, set, ok := single("targetframework", "targetframeworks"); set && ok {
		var tfms []string
		for part := range strings.SplitSeq(v, ";") {
			if part = strings.TrimSpace(part); part == "" {
				continue
			}
			c, ok := canonicalTFM(part)
			if !ok {
				tfms = nil
				break
			}
			if !slices.Contains(tfms, c) {
				tfms = append(tfms, c)
			}
		}
		slices.Sort(tfms)
		pe.tfms = tfms
	}
	if v, set, ok := single("runtimeidentifier", "runtimeidentifiers"); ok {
		pe.ridsKnown = true
		if set {
			for part := range strings.SplitSeq(v, ";") {
				if part = strings.TrimSpace(part); part != "" && !slices.Contains(pe.rids, part) {
					pe.rids = append(pe.rids, part)
				}
			}
			slices.Sort(pe.rids)
		}
	}

	for _, r := range reads {
		if r.role != roleCentral {
			continue
		}
		if pe.central == nil {
			pe.central = make(map[string]string)
		}
		for id, v := range r.mf.versions {
			if prev, seen := pe.central[id]; r.conditioned || seen && prev != v {
				v = ""
			}
			pe.central[id] = v
		}
	}
	for _, r := range reads {
		pe.decl.add(r.mf.refs, r.injected, r.conditioned)
		pe.decl.add(r.mf.globals, true, r.conditioned || !pe.cpm)
	}

	for _, r := range reads {
		for _, ref := range r.mf.projectRefs {
			p, ok := expandComputed(ref.include, pe.path, r.path)
			if !ok || strings.Contains(p, ";") {
				return reasonBuildInputUnmodeled
			}
			p = filepath.FromSlash(strings.ReplaceAll(p, `\`, "/"))
			if !filepath.IsAbs(p) {
				p = filepath.Join(pe.dir, p)
			}
			real, err := filepath.EvalSymlinks(p)
			if err != nil || !e.projects[real] || !withinDir(e.rootReal, real) {
				return reasonBuildInputUnmodeled
			}
			if sub := e.eval(real); sub.reason != "" {
				return sub.reason
			}
			pe.refs = append(pe.refs, projectRef{path: real, conditioned: ref.conditioned || r.conditioned})
		}
	}
	return ""
}

// closure is every project pe references, directly or through another reference.
func (e *evaluator) closure(pe *projectEval) []*projectEval {
	var out []*projectEval
	seen := map[string]bool{pe.path: true}
	var walk func(p *projectEval)
	walk = func(p *projectEval) {
		for _, r := range p.refs {
			if seen[r.path] {
				continue
			}
			seen[r.path] = true
			q := e.eval(r.path)
			out = append(out, q)
			walk(q)
		}
	}
	walk(pe)
	return out
}

// projectName is the name a project goes by in a lockfile: its file name without extension,
// lowercased.
func projectName(path string) string {
	base := filepath.Base(path)
	return strings.ToLower(strings.TrimSuffix(base, filepath.Ext(base)))
}

// jsonObject decodes a JSON object whose keys are all in allowed (exact case), rejecting a
// key repeated in any case and trailing data.
func jsonObject(raw []byte, allowed ...string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	out := make(map[string]json.RawMessage)
	folded := make(map[string]bool)
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, false
		}
		key, _ := tok.(string)
		if !slices.Contains(allowed, key) || folded[strings.ToLower(key)] {
			return nil, false
		}
		folded[strings.ToLower(key)] = true
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, false
		}
		out[key] = v
	}
	if _, err := d.Token(); err != nil {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return out, true
}

// validGlobalJSON admits a global.json that only picks the SDK.
func validGlobalJSON(data []byte) bool {
	top, ok := jsonObject(data, "sdk")
	if !ok {
		return false
	}
	if raw, set := top["sdk"]; set {
		if _, ok := jsonObject(raw, "version", "rollForward", "allowPrerelease", "errorMessage"); !ok {
			return false
		}
	}
	return true
}

// nugetConfigSections are the documented top-level sections of a nuget.config.
var nugetConfigSections = []string{
	"packageSources", "packageSourceMapping", "disabledPackageSources", "activePackageSource",
	"packageSourceCredentials", "apikeys", "config", "fallbackPackageFolders", "trustedSigners",
	"packageRestore", "bindingRedirects", "packageManagement", "auditSources", "solution",
}

// validNuGetConfig admits a nuget.config whose root is configuration and whose sections are
// all documented ones.
func validNuGetConfig(data []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	root := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return root
		}
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch depth {
			case 1:
				if t.Name.Local != "configuration" || root {
					return false
				}
				root = true
			case 2:
				if !slices.Contains(nugetConfigSections, t.Name.Local) {
					return false
				}
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return false
		case xml.CharData:
			if depth < 2 && strings.TrimSpace(string(t)) != "" {
				return false
			}
		}
	}
}
