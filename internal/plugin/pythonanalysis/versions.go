package pythonanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions reads the Python codebase's INSTALLED (pinned) dependency
// versions from its manifests — requirements.txt (pip freeze / hashed pins), poetry.lock,
// pdm.lock, uv.lock, Pipfile.lock, and the declared-specifier build definitions (PEP 621
// pyproject.toml, setup.cfg, setup.py, hatch_build.py) — and returns the resolved version for the
// advisory's requested coordinate (the PyPI project name). It is the cheap Assess-tier
// input to the disqualification predicate, the Python mirror of jsanalysis /
// javaanalysis ResolveDependencyVersions.
//
// SOUNDNESS (inv.5): this NEVER guesses a version. Python's packaging zoo often carries a
// RANGE ("flask>=2.0") rather than a pinned install, or several inconsistent manifests, or
// none. Only an EXACT pin (poetry.lock/Pipfile.lock version, a requirements.txt "=="
// pin, or a PEP 621 "==" pin) yields Resolved=true; a range, a prefix ("==1.4.*"), or an
// unreadable entry is an UNRESOLVED marker (Resolved=false) the predicate fails OPEN on,
// never fabricating a not-affected. A declared range is carried as Constraint (evidence only).
//
// Exhaustive is set only when a complete lockfile covers every manifest found (exhaustive.go)
// and no script surface may install a package outside them (versionSurfaces), so a coordinate
// absent from All is provably not installed; otherwise absence proves nothing.
//
// Hard error vs. partiality (inv.4 / inv.5):
//   - A missing/unreadable build dir is a hard error.
//   - A build dir with NO recognized manifest degrades Partiality to declared-partial
//     (no_manifest) rather than hard-failing the run: a repo that declares no Python
//     dependencies anywhere is a normal shape, not a tool failure. The recognized set
//     already includes the DECLARED manifests (pyproject.toml, requirements*.txt), so unlike
//     JS there is nothing left to seed — All is legitimately empty. Soundness rests entirely
//     on the declared partiality: the result is Complete=false, so a consumer must not read
//     the empty All as proof the dependency is absent and fabricate a not-affected.
//   - An unparseable manifest degrades Partiality to declared-partial (tool_failure), and
//     every Found Match is UNRESOLVED: the broken file may hold another copy of any
//     coordinate, so the readable manifests cannot decide its version. A coordinate no
//     readable manifest holds stays not found.
//   - Any other install surface under the build dir, matched by name or content anywhere the
//     shared walk reaches (everything but node_modules and site-packages), is treated exactly
//     like an unparseable manifest unless it is read and found to declare nothing; so is a
//     pyproject.toml whose dynamic dependencies name no readable file, or whose dependency
//     groups or tool dependency tables hold an entry that cannot be read.
//     See versions_surfaces.go and versions_declared.go.
//   - A script surface that runs a pip self-upgrade (pipSelfUpgrade) is treated the same way
//     for the pip coordinate alone: it installs pip and nothing else.
//   - A distribution installed in a site-packages directory under the build dir is another
//     copy of its project: it takes part in Match like a pin, without joining All.
//
// Several pinned versions of one project: Match is chosen by matchCoordinate, which never
// picks one pin out of several distinct versions. See its doc comment for the rule.
//
// "plugin resolves, pipeline ranges" symmetry: this op resolves only the concrete installed
// literal version. Advisory RANGE matching (PEP 440 specifiers, ordering) is applied by the
// pipeline disqualification predicate (pipeline/pypi_version.go), never here.
func ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.DependencyVersionResult{}, fmt.Errorf("pythonanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.DependencyVersionResult{}, fmt.Errorf("pythonanalysis: build dir %q is not a directory", req.BuildDir)
	}

	var (
		all     []plugin.ResolvedDependency
		origins []manifestOrigin
	)
	want := normalizePyCoordinate(req.Coordinate)
	manifests, parseFailed, scriptWithheld, installs, tooling := versionSurfaces(req.BuildDir)
	if tooling[want] {
		parseFailed, scriptWithheld = true, true
	}
	copies, copyOrigins, copiesRead := installedCopies(req.BuildDir)
	parseFailed = parseFailed || !copiesRead
	for _, m := range manifests {
		deps, o, ok := parseManifest(m)
		if !ok {
			parseFailed = true
		}
		all = append(all, deps...)
		origins = append(origins, o...)
	}

	part := plugin.Complete()
	switch {
	case len(manifests) == 0:
		part = plugin.Partial(plugin.PartialReasonNoManifest)
	case parseFailed:
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}

	covers := coverageCovers(req.BuildDir, req.Coordinate, manifests, installs)
	res := plugin.DependencyVersionResult{
		Partiality: part,
		All:        all,
		Exhaustive: covers && !installedCopyPresent(req.BuildDir, want, true) && !scriptWithheld,
	}
	res.Match, res.Found = matchCoordinate(append(all[:len(all):len(all)], copies...),
		append(origins[:len(origins):len(origins)], copyOrigins...), want)
	if parseFailed && res.Found {
		res.Match.Version = ""
		res.Match.Resolved = false
	}
	// Under coverage every other manifest's declaration is one its governing lock pins at a version
	// the declaration admits, so the lock entries and the installed copies are every version.
	for i, d := range all {
		if want != "" && origins[i].lock != "" && normalizePyCoordinate(d.Coordinate) == want {
			res.Matches = append(res.Matches, d)
		}
	}
	for _, d := range copies {
		if want != "" && normalizePyCoordinate(d.Coordinate) == want {
			res.Matches = append(res.Matches, d)
		}
	}
	res.MatchesComplete = len(res.Matches) > 0 && covers && !parseFailed && !installedCopyPresent(req.BuildDir, want, false)
	return res, nil
}

// manifestOrigin records where an entry of All was read: its manifest's directory, the
// lock it came from ("" when it is not a lock), and, for a declaration, the locks that
// resolve it when they sit in the same directory, with the specifier a lock's pin must
// satisfy (spec) or whether the declaration is a direct reference no lock covers.
type manifestOrigin struct {
	dir       string
	lock      string
	lockedBy  []string
	spec      string
	directRef bool
}

// projectLocks are the locks that resolve a [project] declaration.
var projectLocks = []string{"poetry.lock", "pdm.lock", "uv.lock"}

// groupLocks are the locks that resolve a [dependency-groups] declaration. poetry.lock is not
// one: Poetry reads PEP 735 groups only from 2.2.0, so a poetry.lock written by an earlier
// Poetry left the groups unresolved.
var groupLocks = []string{"pdm.lock", "uv.lock"}

// originsFor repeats one origin for every entry of deps.
func originsFor(deps []plugin.ResolvedDependency, o manifestOrigin) []manifestOrigin {
	out := make([]manifestOrigin, len(deps))
	for i := range out {
		out[i] = o
	}
	return out
}

// matchCoordinate selects the Match for the PEP 503-normalized coordinate want across every
// manifest's entries; origins[i] is where all[i] was read. The rule:
//
//   - every resolved entry pins the SAME version (one pin repeated across requirements.txt,
//     poetry.lock, ... counts once) and no entry's version is unknown: Match is that
//     version, Resolved=true;
//   - two or more distinct pinned versions (e.g. services in one repo locking different
//     versions): Match is UNRESOLVED (Resolved=false, Version empty), so the predicate fails
//     OPEN rather than ruling the advisory on whichever pin was read first;
//   - any UNRESOLVED entry (a range, an unpinned requirement): Match is UNRESOLVED, because
//     that install surface may hold any version;
//   - no resolved entry: Match is the first entry, UNRESOLVED.
//
// One exception to the third case: a pyproject.toml range does not veto when a lock in the
// SAME directory that resolves its table (manifestOrigin.lockedBy: projectLocks for
// [project], groupLocks for [dependency-groups], only the tool's own lock for a [tool.*]
// table) pins the coordinate at a version that satisfies the range. That lock is the
// project's own resolution of the declared range, so both describe one environment. A pin
// outside the range is a stale lock, and a direct reference ("name @ url") is never covered.
// A range in any other manifest or directory, or beside a lock of another tool, is a
// separate install surface and still vetoes.
// Versions compare as exact strings: "2.3" and "2.3.0" read as distinct, which can only fail
// open.
func matchCoordinate(all []plugin.ResolvedDependency, origins []manifestOrigin, want string) (plugin.ResolvedDependency, bool) {
	if want == "" {
		return plugin.ResolvedDependency{}, false
	}
	lockPins := make(map[[2]string][]string) // {dir, lock basename} → versions pinned
	for i, d := range all {
		if d.Resolved && origins[i].lock != "" && normalizePyCoordinate(d.Coordinate) == want {
			k := [2]string{origins[i].dir, origins[i].lock}
			lockPins[k] = append(lockPins[k], d.Version)
		}
	}
	lockedHere := func(o manifestOrigin) bool {
		for _, l := range o.lockedBy {
			for _, v := range lockPins[[2]string{o.dir, l}] {
				if lockPinSatisfies(o, v) {
					return true
				}
			}
		}
		return false
	}
	var (
		match    plugin.ResolvedDependency
		found    bool
		unknown  bool
		versions = make(map[string]struct{})
	)
	for i, d := range all {
		if normalizePyCoordinate(d.Coordinate) != want {
			continue
		}
		if !found {
			match, found = d, true
		}
		if !d.Resolved {
			if !lockedHere(origins[i]) {
				unknown = true
			}
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

// manifestFiles returns every recognized Python manifest under root, skipping
// build-output / virtualenv / VCS trees so a vendored install does not shadow the
// project's own top-level manifest. read is false when part of the tree could not be read,
// so a manifest there may be missing from the list.
func manifestFiles(root string) (paths []string, read bool) {
	return walkManifests(root, func(path string) bool { return isManifest(filepath.Base(path)) })
}

// walkManifests returns every file under root whose path satisfies match, skipping the
// same trees as manifestFiles. read is false when the walk met an error other than a path
// that is not there, a symlink that does not resolve, or a symlinked directory whose target
// it does not itself read: one that resolves outside root, or to a directory the walk skips
// or could not list. WalkDir never follows the link, so a target inside the walk is matched
// once, at its real path.
func walkManifests(root string, match func(string) bool) (out []string, read bool) {
	read = true
	realRoot, rootErr := filepath.EvalSymlinks(root)
	// walked holds the real path of every directory the walk entered and listed.
	walked := map[string]bool{}
	realOf := func(path string) string {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return ""
		}
		return filepath.Join(realRoot, rel)
	}
	var linkedDirs []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			delete(walked, realOf(path))
			if !absent(err) {
				read = false
			}
			return nil //nolint:nilerr // keep walking; the rest of the tree is still read.
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			walked[realOf(path)] = true
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 && !skipDir(d.Name()) {
			fi, serr := os.Stat(path)
			switch {
			case serr != nil:
				read = false
			case fi.IsDir():
				linkedDirs = append(linkedDirs, path)
				return nil
			}
		}
		if match(path) {
			out = append(out, path)
		}
		return nil
	})
	for _, link := range linkedDirs {
		target, err := filepath.EvalSymlinks(link)
		if rootErr != nil || err != nil || !walked[target] {
			read = false
		}
	}
	return out, read
}

// isManifest reports whether name is a recognized Python dependency manifest: the lockfiles,
// the declared-specifier build definitions (pyproject.toml, setup.cfg, setup.py,
// hatch_build.py), hatch.toml, and the requirements*.txt family (requirements.txt, requirements-dev.txt,
// ...), so split requirement files still resolve.
func isManifest(name string) bool {
	switch name {
	case "poetry.lock", "Pipfile.lock", "pyproject.toml", "pdm.lock", "uv.lock",
		"setup.cfg", "setup.py", "hatch_build.py", "hatch.toml":
		return true
	}
	return isRequirementsName(name)
}

func isRequirementsName(name string) bool {
	return strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
}

// parseManifest dispatches on the manifest's name to the format-specific parser and
// returns each entry's origin alongside it. The bool is false when the file cannot be
// read or is structurally unparseable, or holds an install whose project cannot be known
// (the caller degrades partiality and leaves every Found match unresolved).
func parseManifest(path string) ([]plugin.ResolvedDependency, []manifestOrigin, bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, nil, false
	}
	return parseManifestData(path, data)
}

// parseManifestData is parseManifest over contents already read from path.
func parseManifestData(path string, data []byte) ([]plugin.ResolvedDependency, []manifestOrigin, bool) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	var (
		deps []plugin.ResolvedDependency
		ok   bool
	)
	switch base {
	case "poetry.lock":
		deps, ok = parsePoetryLock(data)
	case "Pipfile.lock":
		deps, ok = parsePipfileLock(data)
	case "pdm.lock":
		deps, ok = parsePDMLockAdvisory(data)
	case "uv.lock":
		deps, ok = parseUVLockAdvisory(data)
	case "pyproject.toml":
		return parsePyprojectVersions(path, data, dir)
	case "setup.cfg":
		// setup.cfg's own reader, file: values included. No lock covers it, so an unpinned
		// entry vetoes.
		deps, ok = parseSetupCfg(path, data)
		deps = append(deps, buildRequires(path, data)...)
		return deps, originsFor(deps, manifestOrigin{dir: dir}), ok
	case "setup.py":
		// Only literal declarations are read; anything computed or splatted may install any
		// project, so it takes the parse-failure path, setup_requires and tests_require included.
		deps, ok = parseSetupPy(data)
		deps = append(deps, buildRequires(path, data)...)
		_, buildComplete := scanSetupPyKeys(string(data), setupPyBuildKeys)
		return deps, originsFor(deps, manifestOrigin{dir: dir}), ok && setupPyComplete(data) && buildComplete
	case "hatch_build.py":
		// A build hook can add dependencies at run time: its literals are read, and a hook that
		// mentions dependencies still takes the parse-failure path.
		deps, ok = parseHatchBuild(data)
		return deps, originsFor(deps, manifestOrigin{dir: dir}), ok && !bytes.Contains(data, []byte("dependencies"))
	case "hatch.toml":
		// hatch reads its environments from here as well as from pyproject.toml's [tool.hatch].
		var h hatchConfig
		if toml.Unmarshal(data, &h) != nil {
			return nil, nil, false
		}
		return hatchEnvDeps(h, dir)
	default: // requirements*.txt
		deps, ok = parseRequirementLines(data, dir)
		return deps, originsFor(deps, manifestOrigin{dir: dir}), ok
	}
	return deps, originsFor(deps, manifestOrigin{dir: dir, lock: base}), ok
}

// buildRequires returns the build- and test-time requirements a build definition declares
// ([build-system].requires in pyproject.toml, setup_requires and tests_require in setup.cfg and
// setup.py) as declared dependencies of the advisory path, so a coordinate a build installs is
// found rather than read as absent. They are not runtime installs: the inventory does not carry
// them and no lockfile is expected to cover them (exhaustive.go). Entries that are not
// well-formed PEP 508 requirements, and a setup_requires or tests_require value that is not
// literal, are skipped.
func buildRequires(path string, data []byte) []plugin.ResolvedDependency {
	var specs []string
	source := filepath.Base(path)
	switch source {
	case "pyproject.toml":
		var pp struct {
			BuildSystem struct {
				Requires []string `toml:"requires"`
			} `toml:"build-system"`
		}
		if toml.Unmarshal(data, &pp) == nil {
			specs = pp.BuildSystem.Requires
		}
	case "setup.cfg":
		specs = scanSetupCfg(path, data).buildSpecs
	case "setup.py":
		specs, _ = scanSetupPyKeys(string(data), setupPyBuildKeys)
	}
	var out []plugin.ResolvedDependency
	for _, spec := range specs {
		if d, ok := declaredDependency(spec, source); ok {
			out = append(out, d)
		}
	}
	return out
}

// --- requirements.txt --------------------------------------------------------

// parseRequirementLines parses a pip requirements file located in dir. Only an EXACT "=="
// pin yields a resolved version; a range/compatible/prefix spec is UNRESOLVED, and so is a
// URL or VCS requirement that names its project ("pkg @ https://...",
// "git+https://...#egg=pkg", editable or not), since it installs a version nobody can read
// here.
//
// The file reports false, exactly as an unparseable one does, when it can install a
// distribution whose name or version cannot be read here: a URL or VCS requirement that
// names no project, a local path or file: install other than the project's own directory
// ("-e ./vendor/x", "./dist/x.whl"; "-e ." and "." are the project itself), or any -r/-c
// include, which is not followed. The caller then leaves every Found match unresolved; the
// entries that were read are still returned. Other option lines are skipped. Continuation lines ("\") and hashed pins
// ("pkg==1.2.3 --hash=sha256:...") are handled; environment markers (";...") and inline
// comments ("#...") are stripped.
func parseRequirementLines(data []byte, dir string) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	readable := true
	for _, req := range joinContinuations(string(data)) {
		line := stripReqComment(req)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if isInclude(line) {
			readable = false
			continue
		}
		target, editable := trimEditable(line)
		if strings.HasPrefix(line, "-") && !editable { // --index-url and other options
			continue
		}
		if loc, isFile := fileURLPath(target); isFile {
			if !isProjectDir(loc, dir) {
				readable = false
			}
			continue
		}
		if isDirectReference(target) {
			if name := directReferenceName(req); name != "" {
				out = append(out, pyResolved(name, "", false, "requirements.txt"))
			} else {
				readable = false
			}
			continue
		}
		if loc := localInstallPath(target); editable || loc != "" {
			if editable && loc == "" {
				loc = firstField(target)
			}
			if !isProjectDir(loc, dir) {
				readable = false
			}
			continue
		}
		// Drop an environment marker ("; python_version < '3.8'") and any --hash tokens.
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "--hash"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		name, version, resolved, _ := parseRequirementSpec(line) // advisory path ignores extras
		if name == "" {
			continue
		}
		d := pyResolved(name, version, resolved, "requirements.txt")
		if !d.Resolved {
			d.Constraint = requirementConstraint(line)
		}
		out = append(out, d)
	}
	return out, readable
}

// isInclude reports whether line is a -r/--requirement or -c/--constraint include
// ("-r base.txt", "-rbase.txt", "--requirement=base.txt").
func isInclude(line string) bool {
	for _, flag := range []string{"--requirement", "--constraint"} {
		if rest, ok := strings.CutPrefix(line, flag); ok && (rest == "" || rest[0] == '=' || rest[0] == ' ' || rest[0] == '\t') {
			return true
		}
	}
	return strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "-c")
}

// fileURLPath reports whether a requirement installs from a file: URL, bare or as the
// target of a PEP 508 "name @ file:..." reference, and returns the local path it names.
func fileURLPath(target string) (string, bool) {
	loc := firstField(target)
	if i := strings.IndexByte(target, '@'); i > 0 {
		head := strings.TrimSpace(target[:i])
		if j := strings.IndexByte(head, '['); j >= 0 {
			head = strings.TrimSpace(head[:j])
		}
		if isProjectName(head) {
			loc = firstField(target[i+1:])
		}
	}
	if len(loc) < 5 || !strings.EqualFold(loc[:5], "file:") {
		return "", false
	}
	loc = loc[5:]
	if rest, ok := strings.CutPrefix(loc, "//"); ok { // file://host/path; only an empty host is local
		if !strings.HasPrefix(rest, "/") {
			return "", true
		}
		loc = rest
	}
	if i := strings.IndexAny(loc, "#?"); i >= 0 {
		loc = loc[:i]
	}
	return loc, true
}

// localInstallPath returns the local path a requirement installs from, or "" when it is a
// project name. pip treats a requirement as a path when it contains a path separator or
// starts with "." or "~", and installs an archive file by its file name.
func localInstallPath(target string) string {
	loc := firstField(target)
	if loc == "" {
		return ""
	}
	if strings.ContainsAny(loc, "/\\") || loc[0] == '.' || loc[0] == '~' {
		return loc
	}
	lower := strings.ToLower(loc)
	for _, ext := range []string{".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip"} {
		if strings.HasSuffix(lower, ext) {
			return loc
		}
	}
	return ""
}

// isProjectDir reports whether a local install path names the directory holding the file
// that installs it: ".", "./", ".[extras]", or a path that resolves there. With no file
// context only the literal forms qualify.
func isProjectDir(loc, dir string) bool {
	if isSelfPath(loc) {
		return true
	}
	if dir == "" || loc == "" {
		return false
	}
	if i := strings.IndexByte(loc, '['); i >= 0 {
		loc = loc[:i]
	}
	if !filepath.IsAbs(loc) {
		loc = filepath.Join(dir, loc)
	}
	return filepath.Clean(loc) == filepath.Clean(dir)
}

// firstField returns the requirement's location token: the text before any marker (";")
// and the first whitespace.
func firstField(target string) string {
	if i := strings.IndexByte(target, ';'); i >= 0 {
		target = target[:i]
	}
	if f := strings.Fields(target); len(f) > 0 {
		return f[0]
	}
	return ""
}

// trimEditable strips a leading "-e"/"--editable" option, reporting whether it was there.
func trimEditable(line string) (string, bool) {
	for _, p := range []string{"--editable=", "--editable ", "-e "} {
		if rest, ok := strings.CutPrefix(line, p); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return line, false
}

// isDirectReference reports whether a requirement installs from a URL or VCS checkout.
func isDirectReference(line string) bool {
	if strings.Contains(line, "://") {
		return true
	}
	for _, p := range []string{"git+", "hg+", "svn+", "bzr+"} {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

// directReferenceName returns the project a URL or VCS requirement installs: the PEP 508
// "name[extras] @ url" form, else a "#egg=name" fragment. Empty when the line names none.
func directReferenceName(req string) string {
	line, _ := trimEditable(strings.TrimSpace(req))
	if i := strings.IndexByte(line, '@'); i > 0 {
		head := strings.TrimSpace(line[:i])
		if j := strings.IndexByte(head, '['); j >= 0 {
			head = strings.TrimSpace(head[:j])
		}
		if isProjectName(head) {
			return head
		}
	}
	if _, frag, ok := strings.Cut(line, "#egg="); ok {
		end := len(frag)
		for i, c := range frag {
			if !isProjectNameRune(c) {
				end = i
				break
			}
		}
		if isProjectName(frag[:end]) {
			return frag[:end]
		}
	}
	return ""
}

func isProjectName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !isProjectNameRune(c) {
			return false
		}
	}
	return true
}

func isProjectNameRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// parseRequirementSpec extracts (name, version, resolved, extras) from a single requirement
// spec. It resolves ONLY an exact "==X.Y.Z" pin (not a "==1.4.*" prefix); anything else
// (range, compatible, bare name) is UNRESOLVED. The extras group "[a,b]" is CAPTURED (PLAN-170
// E2, replacing the old unconditional skip) and returned normalized; the advisory path
// (parseRequirementLines, parsePyproject) ignores it, while the selected-set path resolves it
// against the declared extras selection.
func parseRequirementSpec(spec string) (name, version string, resolved bool, extras []string) {
	// Name runs up to the first operator/extras/space, or the "(" of a parenthesized specifier.
	end := len(spec)
	for i, c := range spec {
		if c == '=' || c == '<' || c == '>' || c == '!' || c == '~' || c == '[' || c == '(' || c == ' ' || c == '\t' {
			end = i
			break
		}
	}
	name = strings.TrimSpace(spec[:end])
	// A Jinja2-templated line is not a requirement (finding F9). airflow (and
	// others) ship requirements files rendered through Jinja at build time; read
	// literally, a "{% if … %}" control statement tokenizes to a package named
	// "{%" and a "pkg=={{ ver }}" line to a version of "{{" — junk nodes that
	// pollute the SBOM. A templated NAME carries no recoverable identity, so the
	// line is dropped (empty name → caller skips); a templated VERSION is handled
	// below, leaving the real name pinned to an UNRESOLVED version rather than a
	// garbage literal. A pinned requirement that merely SITS inside a template
	// block (e.g. "funcsigs==1.0.2" between "{% if %}"/"{% endif %}") carries no
	// delimiters of its own and still parses normally.
	if name == "" || containsJinja(name) {
		return "", "", false, nil
	}
	rest := strings.TrimSpace(spec[end:])
	// Capture an extras group "[a,b]" (E2) instead of discarding it.
	if strings.HasPrefix(rest, "[") {
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			extras = parseExtrasGroup(rest[1:j])
			rest = strings.TrimSpace(rest[j+1:])
		}
	}
	if !strings.HasPrefix(rest, "==") {
		return name, "", false, extras // not an exact pin → UNRESOLVED
	}
	ver := strings.TrimSpace(rest[2:])
	// A version with a further comma-clause or a "*" prefix is not a single exact pin.
	if i := strings.IndexAny(ver, ", \t"); i >= 0 {
		ver = ver[:i]
	}
	if ver == "" || strings.Contains(ver, "*") || containsJinja(ver) {
		return name, "", false, extras // "*" prefix or a Jinja-templated version → UNRESOLVED
	}
	return name, ver, true, extras
}

// containsJinja reports whether s carries a Jinja2 template delimiter, including a
// bare "{", "}", or "%" left after tokenizing a "{% … %}" / "{{ … }}" construct.
// PyPI project names and PEP 440 versions never contain these characters, so their
// presence marks a token as template syntax rather than a real coordinate.
func containsJinja(s string) bool {
	return strings.ContainsAny(s, "{}%")
}

// parseExtrasGroup splits the body of an extras group "a, b" into normalized extra names in
// declared order (PEP 503-style normalization, so the group matches a declared selection the
// same way regardless of case or separator). Empty entries are dropped.
func parseExtrasGroup(body string) []string {
	var out []string
	for _, e := range strings.Split(body, ",") {
		if n := normalizePyCoordinate(e); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// joinContinuations splits a requirements file into logical lines the way pip's requirement
// file reader does before it strips comments (req_file.join_lines over str.splitlines). Lines
// break where Python's str.splitlines breaks them. A line ending in a backslash is joined to the
// next, with every backslash at either end of it removed and nothing put in their place. The
// exception is a comment line (first non-blank character '#'), which never continues and gets
// one leading space. A backslash followed by trailing blanks does not continue a line.
func joinContinuations(data string) []string {
	var out []string
	var cur strings.Builder
	pending := false
	for _, line := range pySplitLines(data) {
		comment := strings.HasPrefix(strings.TrimLeftFunc(line, pyIsSpace), "#")
		if !strings.HasSuffix(line, "\\") || comment {
			if comment {
				line = " " + line
			}
			if pending {
				cur.WriteString(line)
				out = append(out, cur.String())
				cur.Reset()
				pending = false
			} else {
				out = append(out, line)
			}
			continue
		}
		pending = true
		cur.WriteString(strings.Trim(line, "\\"))
	}
	if pending {
		out = append(out, cur.String())
	}
	return out
}

// pySplitLines splits s at every line boundary Python's str.splitlines recognises, dropping the
// boundaries. A trailing boundary yields no empty last line.
func pySplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		case '\r':
			if strings.HasPrefix(s[i+1:], "\n") {
				n = 2
			}
		default:
			i += n
			continue
		}
		out = append(out, s[start:i])
		i += n
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// pyIsSpace reports whether r is whitespace to Python's str.isspace, which a regular expression's
// \s matches.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f
}

// stripReqComment removes a "# ..." inline comment (a '#' that starts a token).
func stripReqComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// --- poetry.lock (TOML) ------------------------------------------------------

// parsePoetryLock parses poetry.lock lexically (no TOML library — pure-Go,
// dependency-free, matching the scanner ethos). Each resolved package is a
// "[[package]]" block carrying `name = "x"` and `version = "1.2.3"`. A block missing a
// version is UNRESOLVED.
func parsePoetryLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	var name, version string
	inPackage := false

	flush := func() {
		if inPackage && name != "" {
			out = append(out, pyResolved(name, version, version != "", "poetry.lock"))
		}
		name, version = "", ""
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "[[package]]" {
			flush()
			inPackage = true
			continue
		}
		if strings.HasPrefix(line, "[") { // any other table closes the package block
			flush()
			inPackage = false
			continue
		}
		if !inPackage {
			continue
		}
		if v, ok := tomlString(line, "name"); ok {
			name = v
		}
		if v, ok := tomlString(line, "version"); ok {
			version = v
		}
	}
	flush()
	return out, true
}

// tomlString matches a `key = "value"` line for the given key and returns the unquoted
// value. It is deliberately minimal (the only shape poetry.lock/pyproject use for these
// scalar fields).
func tomlString(line, key string) (string, bool) {
	prefix := key + " ="
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := strings.TrimSpace(line[len(prefix):])
	rest = strings.Trim(rest, `"'`)
	return rest, rest != ""
}

// --- Pipfile.lock (JSON) -----------------------------------------------------

// pipfileLock is the subset of Pipfile.lock we read: the "default" and "develop"
// dependency maps, each package → {"version": "==1.2.3", ...}.
type pipfileLock struct {
	Default map[string]pipfileEntry `json:"default"`
	Develop map[string]pipfileEntry `json:"develop"`
}

type pipfileEntry struct {
	Version string `json:"version"`
}

// parsePipfileLock parses Pipfile.lock. Pipenv pins every dependency with an exact
// "==X.Y.Z" version, so a present version field resolves; a missing one is UNRESOLVED.
// Each section is walked in sorted key order so All is identical across runs.
func parsePipfileLock(data []byte) ([]plugin.ResolvedDependency, bool) {
	var pl pipfileLock
	if err := json.Unmarshal(data, &pl); err != nil {
		return nil, false
	}
	var out []plugin.ResolvedDependency
	collect := func(m map[string]pipfileEntry) {
		for _, name := range slices.Sorted(maps.Keys(m)) {
			e := m[name]
			ver := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(e.Version), "=="))
			out = append(out, pyResolved(name, ver, ver != "" && !strings.Contains(ver, "*"), "Pipfile.lock"))
		}
	}
	collect(pl.Default)
	collect(pl.Develop)
	return out, true
}

// --- pyproject.toml (PEP 621) ------------------------------------------------

// pyprojectDeps is the subset read here: [project].dependencies and
// [project].optional-dependencies, and the requirement files that supply them when they are
// dynamic ([tool.setuptools.dynamic], or hatch-requirements-txt's
// [tool.hatch.metadata.hooks.requirements_txt]).
type pyprojectDeps struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		Dynamic              []string            `toml:"dynamic"`
	} `toml:"project"`
	Tool struct {
		Setuptools struct {
			Dynamic map[string]any `toml:"dynamic"`
		} `toml:"setuptools"`
		Hatch struct {
			Metadata struct {
				Hooks map[string]any `toml:"hooks"`
			} `toml:"metadata"`
		} `toml:"hatch"`
	} `toml:"tool"`
}

// parsePyproject reads a PEP 621 pyproject.toml's [project].dependencies and every
// [project].optional-dependencies group, plus every requirement file a dynamic-metadata table
// names for them (pyprojectDynamicFiles), read relative to the pyproject. Each entry is a
// declared PEP 508 requirement: an exact "==" pin resolves, a range rides in Constraint with
// Resolved=false (the authoritative pins live in a lockfile). ok is false when an entry ends in
// a backslash (setuptoolsJoins), or a dynamic table has a shape not read here or a file it names
// fails readRequirementFiles. A file the TOML
// decoder rejects (a templated pyproject, say) falls back to the lexical [project] dependencies
// reader, so such a file still contributes the names it visibly declares.
func parsePyproject(path string, data []byte) ([]plugin.ResolvedDependency, bool) {
	var pp pyprojectDeps
	if err := toml.Unmarshal(data, &pp); err != nil {
		return parsePyprojectLexical(data)
	}
	var out []plugin.ResolvedDependency
	listOK := true
	add := func(spec string) {
		listOK = listOK && !setuptoolsJoins(spec)
		if d, ok := declaredDependency(spec, "pyproject.toml"); ok {
			out = append(out, d)
		}
	}
	for _, spec := range pp.Project.Dependencies {
		add(spec)
	}
	for _, g := range slices.Sorted(maps.Keys(pp.Project.OptionalDependencies)) {
		for _, spec := range pp.Project.OptionalDependencies[g] {
			add(spec)
		}
	}
	files, ok := pyprojectDynamicFiles(pp)
	if !ok {
		return out, false
	}
	for _, f := range files {
		deps, fileOK := readRequirementFiles(filepath.Dir(path), f, "pyproject.toml")
		out = append(out, deps...)
		if !fileOK {
			return out, false
		}
	}
	return out, listOK
}

// pyprojectDynamicFiles returns, in a stable order, every requirement file named for
// dependencies or optional-dependencies by [tool.setuptools.dynamic] ({file = "a.txt"} or
// {file = ["a.txt", ...]}, per field and per optional group) and by
// [tool.hatch.metadata.hooks.requirements_txt] (files = [...] and an optional-dependencies
// table of file lists). ok is false for any other shape of those entries.
func pyprojectDynamicFiles(pp pyprojectDeps) (files []string, ok bool) {
	fileKey := func(v any) bool {
		m, isMap := v.(map[string]any)
		if !isMap || len(m) != 1 {
			return false
		}
		names, isList := stringList(m["file"])
		files = append(files, names...)
		return isList
	}
	dyn := pp.Tool.Setuptools.Dynamic
	if v, present := dyn["dependencies"]; present && !fileKey(v) {
		return nil, false
	}
	if v, present := dyn["optional-dependencies"]; present {
		groups, isMap := v.(map[string]any)
		if !isMap {
			return nil, false
		}
		for _, g := range slices.Sorted(maps.Keys(groups)) {
			if !fileKey(groups[g]) {
				return nil, false
			}
		}
	}
	if v, present := pp.Tool.Hatch.Metadata.Hooks["requirements_txt"]; present {
		hook, isMap := v.(map[string]any)
		if !isMap {
			return nil, false
		}
		if fv, has := hook["files"]; has {
			names, isList := stringList(fv)
			if !isList {
				return nil, false
			}
			files = append(files, names...)
		}
		if ov, has := hook["optional-dependencies"]; has {
			groups, isMap := ov.(map[string]any)
			if !isMap {
				return nil, false
			}
			for _, g := range slices.Sorted(maps.Keys(groups)) {
				names, isList := stringList(groups[g])
				if !isList {
					return nil, false
				}
				files = append(files, names...)
			}
		}
	}
	return files, true
}

// stringList accepts a TOML string or array of strings.
func stringList(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, isStr := e.(string)
			if !isStr {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// parsePyprojectLexical reads the "dependencies = [ ... ]" array under a "[project]" table
// line by line, resolving only exact "==" pins. It is the fallback for a file the TOML decoder
// rejects.
func parsePyprojectLexical(data []byte) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	inProject := false
	inDeps := false

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(line, "[") {
			inProject = line == "[project]"
			inDeps = false
			continue
		}
		if !inProject {
			continue
		}
		if strings.HasPrefix(line, "dependencies") && strings.Contains(line, "[") {
			inDeps = true
			line = line[strings.IndexByte(line, '[')+1:]
		}
		if !inDeps {
			continue
		}
		for _, entry := range strings.Split(line, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "]" || entry == "" {
				continue
			}
			closed := strings.Contains(entry, "]")
			entry = strings.Trim(entry, "[]")
			entry = strings.TrimSpace(strings.Trim(strings.TrimSpace(entry), `"'`))
			if entry != "" {
				name, version, resolved, _ := parseRequirementSpec(entry) // advisory path ignores extras
				if name != "" {
					out = append(out, pyResolved(name, version, resolved, "pyproject.toml"))
				}
			}
			if closed {
				inDeps = false
			}
		}
	}
	return out, true
}

// --- shared helpers ----------------------------------------------------------

// pyResolved builds a ResolvedDependency for a PyPI package. An empty/unresolved version
// is UNRESOLVED (Resolved=false), never guessed.
func pyResolved(name, version string, resolved bool, source string) plugin.ResolvedDependency {
	version = strings.TrimSpace(version)
	if name == "" || version == "" || !resolved {
		return plugin.ResolvedDependency{Coordinate: name, Resolved: false, Source: source}
	}
	return plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: source}
}

// normalizePyCoordinate applies PEP 503 name normalization: lowercase, and collapse runs
// of '-', '_', '.' to a single '-'. So "Flask", "flask", and "deep_diff"/"deep-diff"
// match the way PyPI treats them.
func normalizePyCoordinate(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	var b strings.Builder
	prevDash := false
	for _, r := range c {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return strings.Trim(b.String(), "-")
}

// coverageCovers is the no-manifest-entry coverage check (manifestSetCovers) over the
// manifests' declared names. It reads each manifest with the coverage readers
// (parseManifestCoverage), not the version-resolution vetoes above: a surface version
// resolution declines to read (a -r include) is one the coverage
// check accounts for itself, through manifestDecls and the install-surface walk, so a version
// left undecided must not withhold Exhaustive on its own.
func coverageCovers(root, coordinate string, manifests []string, installs pipInstalls) bool {
	perFile := make(map[string][]plugin.ResolvedDependency, len(manifests))
	failed := false
	for _, m := range manifests {
		deps, ok := parseManifestCoverage(m)
		if !ok {
			failed = true
		}
		perFile[m] = deps
	}
	return manifestSetCovers(root, coordinate, manifests, perFile, failed, installs)
}

// parseManifestCoverage reads one manifest's declared entries for the coverage check and the
// install-surface classifier (ManifestCandidates). The bool is false when the file cannot be
// read or does not parse.
func parseManifestCoverage(path string) ([]plugin.ResolvedDependency, bool) {
	data, err := readRegular(path)
	if err != nil {
		return nil, false
	}
	switch filepath.Base(path) {
	case "poetry.lock":
		return parsePoetryLock(data)
	case "Pipfile.lock":
		return parsePipfileLock(data)
	case "pdm.lock":
		return parsePDMLockAdvisory(data)
	case "uv.lock":
		return parseUVLockAdvisory(data)
	case "pyproject.toml":
		deps, ok := parsePyproject(path, data)
		return append(deps, buildRequires(path, data)...), ok
	case "setup.cfg":
		deps, ok := parseSetupCfg(path, data)
		return append(deps, buildRequires(path, data)...), ok
	case "setup.py":
		deps, ok := parseSetupPy(data)
		return append(deps, buildRequires(path, data)...), ok
	case "hatch_build.py":
		return parseHatchBuild(data)
	case "hatch.toml":
		// No declaration of its own here: manifestDecls reads its environments.
		var h hatchConfig
		return nil, toml.Unmarshal(data, &h) == nil
	}
	return parseRequirementsCoverage(data)
}

// parseRequirementsCoverage reads a requirements file's declared entries for the coverage
// check. Includes, editables and options are skipped here; manifestDecls accounts for them.
func parseRequirementsCoverage(data []byte) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	for _, req := range joinContinuations(string(data)) {
		line := stripReqComment(req)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") { // -r include, -e editable, --option
			continue
		}
		if strings.Contains(line, "://") || strings.HasPrefix(line, "git+") {
			continue // URL / VCS requirement — no PyPI-pinned version
		}
		// Drop an environment marker ("; python_version < '3.8'") and any --hash tokens.
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "--hash"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		name, version, resolved, _ := parseRequirementSpec(line) // advisory path ignores extras
		if name == "" {
			continue
		}
		d := pyResolved(name, version, resolved, "requirements.txt")
		if !d.Resolved {
			d.Constraint = requirementConstraint(line)
		}
		out = append(out, d)
	}
	return out, true
}
