package pythonanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ResolveDependencyVersions reads the Python codebase's INSTALLED (pinned) dependency
// versions from its manifests — requirements.txt (pip freeze / hashed pins), poetry.lock,
// Pipfile.lock, pdm.lock, uv.lock, Pipfile, and pyproject.toml (PEP 621 [project] and
// [tool.poetry]) — and returns the resolved version for the
// advisory's requested coordinate (the PyPI project name). It is the cheap Assess-tier
// input to the disqualification predicate, the Python mirror of jsanalysis /
// javaanalysis ResolveDependencyVersions.
//
// SOUNDNESS (inv.5): this NEVER guesses a version. Python's packaging zoo often carries a
// RANGE ("flask>=2.0") rather than a pinned install, or several inconsistent manifests, or
// none. Only an EXACT pin (poetry.lock/Pipfile.lock version, a requirements.txt "=="
// pin, or a PEP 621 "==" pin) yields Resolved=true; a range, a prefix ("==1.4.*"), or an
// unreadable entry is an UNRESOLVED marker (Resolved=false) the predicate fails OPEN on,
// never fabricating a not-affected.
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

	manifests := walkManifests(req.BuildDir, isVersionManifest)
	root, err := filepath.EvalSymlinks(req.BuildDir)
	if err != nil {
		root = filepath.Clean(req.BuildDir)
	}

	var (
		all         []plugin.ResolvedDependency
		origins     []manifestOrigin
		parseFailed bool
	)
	for _, m := range manifests {
		deps, o, ok := parseManifest(root, m)
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

	res := plugin.DependencyVersionResult{Partiality: part, All: all}
	res.Match, res.Found = matchCoordinate(all, origins, normalizePyCoordinate(req.Coordinate))
	if parseFailed && res.Found {
		res.Match.Version = ""
		res.Match.Resolved = false
	}
	return res, nil
}

// manifestOrigin records where an entry of All was read: its manifest's directory, the
// lock it came from ("" when it is not a lock), and, for a declaration, the locks that
// resolve it when they sit in the same directory.
type manifestOrigin struct {
	dir      string
	lock     string
	lockedBy []string
}

// The locks that resolve each kind of declaration. Pipfile.lock locks only the Pipfile;
// poetry.lock locks [tool.poetry] and [project]; pdm.lock and uv.lock lock [project].
var (
	projectLocks = []string{"poetry.lock", "pdm.lock", "uv.lock"}
	poetryLocks  = []string{"poetry.lock"}
	pipfileLocks = []string{"Pipfile.lock"}
)

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
// One exception to the third case: an UNRESOLVED declaration does not veto when its own
// lock in the SAME directory pins the coordinate: a pyproject.toml [project] range by
// poetry.lock, pdm.lock or uv.lock; a [tool.poetry] range by poetry.lock; a Pipfile range
// by Pipfile.lock. That lock is the project's own resolution of the declared range, so
// both describe one environment. A range in any other manifest or directory, or beside a
// lock of another tool, is a separate install surface and still vetoes.
// Versions compare as exact strings: "2.3" and "2.3.0" read as distinct, which can only fail
// open.
func matchCoordinate(all []plugin.ResolvedDependency, origins []manifestOrigin, want string) (plugin.ResolvedDependency, bool) {
	if want == "" {
		return plugin.ResolvedDependency{}, false
	}
	lockPinned := make(map[[2]string]bool) // {dir, lock basename}
	for i, d := range all {
		if d.Resolved && origins[i].lock != "" && normalizePyCoordinate(d.Coordinate) == want {
			lockPinned[[2]string{origins[i].dir, origins[i].lock}] = true
		}
	}
	lockedHere := func(o manifestOrigin) bool {
		for _, l := range o.lockedBy {
			if lockPinned[[2]string{o.dir, l}] {
				return true
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
// project's own top-level manifest.
func manifestFiles(root string) []string {
	return walkManifests(root, isManifest)
}

// isVersionManifest is isManifest plus the declarations version resolution also reads: a
// Pipfile is an install surface even without its lock.
func isVersionManifest(name string) bool {
	return isManifest(name) || name == "Pipfile"
}

// walkManifests returns every file under root whose name satisfies match, skipping the
// same trees as manifestFiles.
func walkManifests(root string, match func(string) bool) []string {
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
		if match(d.Name()) {
			out = append(out, path)
		}
		return nil
	})
	return out
}

// isManifest reports whether name is a recognized Python dependency manifest. A
// requirements*.txt family (requirements.txt, requirements-dev.txt, ...) is accepted so
// split requirement files still resolve.
func isManifest(name string) bool {
	switch name {
	case "poetry.lock", "Pipfile.lock", "pyproject.toml", "pdm.lock", "uv.lock":
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
func parseManifest(root, path string) ([]plugin.ResolvedDependency, []manifestOrigin, bool) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	if base != "Pipfile" && base != "pyproject.toml" && isRequirementsName(base) {
		r := requirementsReader{root: root, seen: make(map[string]bool)}
		deps, ok := r.read(path)
		return deps, originsFor(deps, manifestOrigin{dir: dir}), ok
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false
	}
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
	case "Pipfile":
		deps, ok = parsePipfile(data)
		return deps, originsFor(deps, manifestOrigin{dir: dir, lockedBy: pipfileLocks}), ok
	case "pyproject.toml":
		project, okProject := parsePyproject(data)
		poetry, okPoetry := parsePoetryDependencies(data)
		origins := append(originsFor(project, manifestOrigin{dir: dir, lockedBy: projectLocks}),
			originsFor(poetry, manifestOrigin{dir: dir, lockedBy: poetryLocks})...)
		return append(project, poetry...), origins, okProject && okPoetry
	default:
		return nil, nil, false
	}
	return deps, originsFor(deps, manifestOrigin{dir: dir, lock: base}), ok
}

// --- requirements.txt --------------------------------------------------------

// parseRequirementsTxt parses requirements-file content with no file context: an include
// cannot be followed and a relative path cannot be placed, so either makes it report false.
func parseRequirementsTxt(data []byte) ([]plugin.ResolvedDependency, bool) {
	return parseRequirementLines(data, "", nil)
}

// requirementsReader reads a requirements file and, recursively, the files it includes.
type requirementsReader struct {
	root string          // build root, symlinks resolved; nothing outside it is read
	seen map[string]bool // files already read in this traversal, symlinks resolved
}

// read parses the requirements file at path and every local -r/-c file it includes. A
// file that is missing, unreadable or outside the build root reports false. A file
// already read in this traversal contributes nothing more, so an include cycle ends.
func (r *requirementsReader) read(path string) ([]plugin.ResolvedDependency, bool) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil || !withinRoot(r.root, real) {
		return nil, false
	}
	if r.seen[real] {
		return nil, true
	}
	r.seen[real] = true
	data, err := os.ReadFile(real)
	if err != nil {
		return nil, false
	}
	return parseRequirementLines(data, filepath.Dir(path), r)
}

func withinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// parseRequirementLines parses a pip requirements file located in dir. Only an EXACT "=="
// pin yields a resolved version; a range/compatible/prefix spec is UNRESOLVED, and so is a
// URL or VCS requirement that names its project ("pkg @ https://...",
// "git+https://...#egg=pkg", editable or not), since it installs a version nobody can read
// here.
//
// The file reports false, exactly as an unparseable one does, when it can install a
// distribution whose name or version cannot be read here: a URL or VCS requirement that
// names no project, a local path or file: install other than the project's own directory
// ("-e ./vendor/x", "./dist/x.whl"; "-e ." and "." are the project itself), or a -r/-c
// include that is a URL or cannot be read. The caller then leaves every Found match
// unresolved; the entries that were read are still returned. A local include is read
// through inc, relative to dir, whatever its name; constraint pins are read as entries.
// Other option lines are skipped. Continuation lines ("\") and hashed pins
// ("pkg==1.2.3 --hash=sha256:...") are handled; environment markers (";...") and inline
// comments ("#...") are stripped.
func parseRequirementLines(data []byte, dir string, inc *requirementsReader) ([]plugin.ResolvedDependency, bool) {
	var out []plugin.ResolvedDependency
	readable := true
	for _, req := range joinContinuations(string(data)) {
		line := stripReqComment(req)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if target, isInclude := includeTarget(line); isInclude {
			if inc == nil || target == "" || strings.Contains(target, "://") {
				readable = false
				continue
			}
			deps, ok := inc.read(filepath.Join(dir, target))
			out = append(out, deps...)
			readable = readable && ok
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
		out = append(out, pyResolved(name, version, resolved, "requirements.txt"))
	}
	return out, readable
}

// includeTarget reports whether line is a -r/--requirement or -c/--constraint include and
// returns the file it names ("-r base.txt", "-rbase.txt", "--requirement=base.txt").
func includeTarget(line string) (string, bool) {
	for _, flag := range []string{"--requirement", "--constraint"} {
		if rest, ok := strings.CutPrefix(line, flag); ok && (rest == "" || rest[0] == '=' || rest[0] == ' ' || rest[0] == '\t') {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "=")), true
		}
	}
	for _, flag := range []string{"-r", "-c"} {
		if rest, ok := strings.CutPrefix(line, flag); ok {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "=")), true
		}
	}
	return "", false
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
// (parseRequirementsTxt, parsePyproject) ignores it, while the selected-set path resolves it
// against the declared extras selection.
func parseRequirementSpec(spec string) (name, version string, resolved bool, extras []string) {
	// Name runs up to the first operator/extras/space.
	end := len(spec)
	for i, c := range spec {
		if c == '=' || c == '<' || c == '>' || c == '!' || c == '~' || c == '[' || c == ' ' || c == '\t' {
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

// joinContinuations splits a requirements file into logical requirement strings, joining
// backslash-continued physical lines.
func joinContinuations(data string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
			cur.WriteString(strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
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

// parsePyproject parses a PEP 621 pyproject.toml's "[project] dependencies" array
// lexically, resolving only exact "==" pins (pyproject usually carries ranges, so most
// entries are UNRESOLVED — the authoritative pins live in poetry.lock/Pipfile.lock). It
// reads the "dependencies = [ ... ]" array under a "[project]" table.
func parsePyproject(data []byte) ([]plugin.ResolvedDependency, bool) {
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
