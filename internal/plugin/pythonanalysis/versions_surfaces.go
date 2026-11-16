package pythonanalysis

import (
	"bufio"
	"bytes"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- install surfaces ------------------------------------------------------------
//
// Version resolution reads the manifests manifestFiles discovers. Every other file under the
// build dir that names or holds a Python install surface, found by the shared walk
// (buildtree.Candidates, which enters everything but node_modules and site-packages, .git
// included), vetoes the pin unless it is one of the few surfaces read here and found to
// declare nothing (declaresNothing). Classification is by name, case-insensitively, or by
// content, so a surface this lane has no reader for vetoes by default instead of being
// listed one name at a time.

// versionSurfaces returns the manifests version resolution parses, whether any other install
// surface under root goes unread, whether a script surface may install a package no manifest
// or lock read here names (scriptsurface.Veto.Withheld), every pip install -r the script
// surfaces run, every poetry install they run with the groups it selects (poetryInstalls), and
// the distributions the build may hold at a version nothing read here records, which a caller
// withholds as it would every pin: pip after an allowed self-upgrade (pipSelfUpgrade), a tool
// installed outside the manifests with every coordinate it may move (toolOrder), and in every
// build the distributions an interpreter or venv seeds (seededDistributions). No
// self-upgrade is allowed when root holds a pip config file (pipConfigInTree) or a script
// surface names one (pipConfigNamedRE); configNamed reports the second. A script surface that names a uv config
// (uvConfigNamedRE) withholds when an allowed uv sync runs, and one that names a poetry or pdm
// config (toolConfigNamedRE) when an allowed poetry install or pdm sync runs. A poetry or pdm
// config in the tree is read when it sets only that tool's settings (toolConfigClean). unrecognised is where a file the rule does not read as a surface runs an
// installer (scriptsurface.Veto.Unrecognised), or "".
func versionSurfaces(root string) (manifests []string, unread, scriptWithheld bool, installs pipInstalls, poetry poetryInstalls, tooling map[string]bool, unrecognised string, inactive []scriptsurface.Site, configNamed bool) {
	return scanSurfaces(root, nil)
}

// scriptRun is a pip install a script surface runs: one the rule withholds, from a surface it
// withholds on, or an allowed self-upgrade. args are pip's arguments after install, as written,
// files the build-tree -r files they name that the lane does not already read, and uv whether
// uv runs it.
type scriptRun struct {
	surface string
	args    []string
	files   []runFile
	uv      bool
}

// runFile is a -r file a run resolves: the build-tree path, and the name the installer is
// given, by which it reads the file.
type runFile struct {
	path, name string
}

// scanSurfaces is versionSurfaces, and when runs is not nil it also records there every pip
// install the script surfaces run that names what it installs (scriptRun).
func scanSurfaces(root string, runs *[]scriptRun) (manifests []string, unread, scriptWithheld bool, installs pipInstalls, poetry poetryInstalls, tooling map[string]bool, unrecognised string, inactive []scriptsurface.Site, configNamed bool) {
	manifests, walked := manifestFiles(root)
	unread = !walked
	discovered := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		discovered[m] = true
	}
	// A requirement file a pyproject.toml or setup.cfg names in a file directive is read by
	// that manifest's reader; when the manifest cannot read it, the manifest fails instead. A
	// module a pyproject.toml's backend reads a dynamic version from is read here when it
	// holds it as a string literal (versionModules).
	via := map[string]bool{}
	for _, m := range manifests {
		if base := filepath.Base(m); base != "pyproject.toml" && base != "setup.cfg" {
			continue
		}
		if decls, ok := manifestDecls(m); ok {
			for _, f := range decls.files {
				via[filepath.Clean(f)] = true
			}
		}
		if filepath.Base(m) == "pyproject.toml" {
			for _, f := range versionModules(m) {
				via[filepath.Clean(f)] = true
			}
		}
	}
	manifest := func(path string) bool {
		return discovered[path] || via[filepath.Clean(path)] || declaresNothing(path)
	}
	read := func(path string) bool {
		return !wideMarked(path) && (manifest(path) || toolConfigClean(path))
	}
	installs, poetry = pipInstalls{}, poetryInstalls{}
	if !pipConfigInTree(root) {
		tooling = map[string]bool{}
	}
	spec := newScriptSpec(installs, poetry, tooling)
	spec.Library = gitShellLibrary
	var (
		veto    *scriptsurface.Veto
		current string // the surface the walk is classifying
	)
	order := &toolOrder{root: root, manifests: manifests}
	laneAllowed := spec.Allowed
	spec.Allowed = func(words []string, b scriptsurface.Binder) bool {
		list, listed := veto.AndList()
		ok := laneAllowed(words, b)
		switch {
		case ok:
			order.allowed(words, list, listed)
		case aptInstallsNoPyPI(words):
			ok = true
		case listed && tooling != nil && !sampleHook(root, current):
			ok = order.tool(words, list, listed, current)
		}
		return ok
	}
	configNamed, mypyInstalls, uvConfigNamed, toolConfigNamed, uvSynced, toolSynced := false, false, false, false, false, false
	spec.Text = func(src string) {
		configNamed = configNamed || pipConfigNamedRE.MatchString(src)
		mypyInstalls = mypyInstalls || installTypesTextRE.MatchString(src) ||
			installTypesAbbrevRE.MatchString(src) && mypyNamedRE.MatchString(src)
		uvConfigNamed = uvConfigNamed || uvConfigNamedRE.MatchString(src)
		toolConfigNamed = toolConfigNamed || toolConfigNamedRE.MatchString(src)
	}
	allowed := spec.Allowed
	spec.Allowed = func(words []string, b scriptsurface.Binder) bool {
		ok := allowed(words, b)
		if head, _ := scriptsurface.CommandName(words[0]); ok {
			uvSynced = uvSynced || head == "uv"
			toolSynced = toolSynced || (head == "poetry" || head == "pdm") && words[1] != "config"
		}
		return ok
	}
	var rec *runRecorder
	if runs != nil {
		rec = &runRecorder{inner: spec.Allowed, tooling: tooling}
		spec.Allowed = rec.allowed
	}
	veto = scriptsurface.New(root, read, spec)
	classify := veto.Classify(pyInstallSurface)
	if rec != nil {
		classify = rec.classify(root, veto)
	}
	match := func(path string, head []byte) (string, bool) {
		current = path
		mypyInstalls = mypyInstalls || mypyConfigInstalls(head) || installTypesLineRE.Match(head)
		return classify(path, head)
	}
	for _, c := range buildtree.Candidates(root, match, veto.FullyRead) {
		if !c.FullyRead {
			unread = true
		}
	}
	scriptWithheld = veto.Withheld() || mypyInstalls
	if len(order.tools) > 0 && !scriptWithheld {
		if keep, ok := order.pins(installs); ok {
			for n := range order.withheld(keep) {
				tooling[n] = true
			}
		} else {
			scriptWithheld = true
		}
	}
	if rec != nil {
		again := newScriptSpec(pipInstalls{}, poetryInstalls{}, maps.Clone(tooling))
		again.Library = gitShellLibrary
		rec.rescan(root, manifest, again)
		*runs = append(rec.runs, order.runs(rec.withheld)...)
	}
	if configNamed && len(tooling) > 0 {
		scriptWithheld, tooling = true, nil
	}
	if uvConfigNamed && uvSynced || toolConfigNamed && toolSynced {
		scriptWithheld = true
	}
	// After the check above: seeding is not a self-upgrade, and must not trip it.
	if tooling == nil {
		tooling = map[string]bool{}
	}
	for _, n := range seededDistributions {
		tooling[n] = true
	}
	return manifests, unread || scriptWithheld, scriptWithheld, installs, poetry, tooling, veto.Unrecognised(), veto.Inactive(), configNamed
}

// gitShellLibrary reports whether a word sourced alone is git-sh-setup, the shell library git's
// own hooks and commands source (a sample hook's . git-sh-setup), which defines functions and
// installs nothing.
func gitShellLibrary(word string) bool { return word == "git-sh-setup" }

// aptPythonRE matches the Debian packages an apt install may name beside packages that are not
// Python's: the interpreter, its headers, venv and pip. pip is a distribution, and stays
// withheld in every build (seededDistributions), as do setuptools and wheel, which a distro's
// pip depends on or recommends.
var aptPythonRE = regexp.MustCompile(`^python(?:|2|2\.[0-9]+|3|3\.[0-9]+|-dev|2\.[0-9]+-dev|3-dev|3\.[0-9]+-dev|3-venv|3\.[0-9]+-venv|-pip|3-pip)$`)

// debianNameRE is a Debian package name.
var debianNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// aptInstallsNoPyPI reports whether words is an apt-get install or apt install whose every
// package installs no PyPI distribution but pip: each, less a =version or /release suffix and
// in any case, is a Debian name that does not start with py, or one aptPythonRE matches. Every
// other word is an option flag. Any other python or py package (python3-django), a path, or a
// word that is not a package name withholds, as does every other package manager.
func aptInstallsNoPyPI(words []string) bool {
	head, ok := scriptsurface.CommandName(words[0])
	if !ok || head != "apt-get" && head != "apt" {
		return false
	}
	i := 1
	for i < len(words) && strings.HasPrefix(words[i], "-") {
		i++
	}
	if i == len(words) || words[i] != "install" {
		return false
	}
	packages := 0
	for _, w := range words[i+1:] {
		if strings.HasPrefix(w, "-") {
			continue
		}
		name, _, _ := strings.Cut(w, "=")
		name, _, _ = strings.Cut(name, "/")
		name = strings.ToLower(name)
		if !debianNameRE.MatchString(name) || strings.HasPrefix(name, "py") && !aptPythonRE.MatchString(name) {
			return false
		}
		packages++
	}
	return packages > 0
}

// toolTargetRE is a distribution name, bare or with a version specifier, and nothing else: no
// extras, marker, URL or path.
var toolTargetRE = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:(?:===|==|~=|!=|<=|>=|<|>)[0-9][0-9A-Za-z.*+!_-]*(?:,(?:===|==|~=|!=|<=|>=|<|>)[0-9][0-9A-Za-z.*+!_-]*)*)?$`)

// toolOrder follows the pip installs the script surfaces run when one of them installs a tool
// outside the manifests:
//
//	pip install [flags] <name>[<specifier>] ...   flags only from selfUpgradeFlags, and no
//	                                              name a manifest read here names
//
// pip may be pipN, pipN.M or pythonN.M -m pip. A tool installs its own dependencies at
// versions nothing read here records, so it withholds the names it installs and every
// coordinate the manifests do not pin exactly (withheld). An exact pin keeps its version only
// when every allowed install the build runs is a pip install -r, and every tool install runs
// before every one of those in one && list (scriptsurface.Veto.AndList), all through one
// installer (pipInstaller): pip then reinstalls each pin the files it installs hold, whatever a
// tool put in place before it, in the one environment both installed into. A pin only those
// files hold keeps it (pins). Any other order, a poetry, uv, pdm or pipenv install, or a
// complete lock, which Exhaustive takes as the whole of what the build installs, withholds every
// version, as a tool install did before this was followed. So do a tool install and an allowed
// self-upgrade where a script surface names a pip config (versionSurfaces).
type toolOrder struct {
	root      string
	manifests []string
	named     map[string]bool // every coordinate a manifest read here names, once read
	toolNames map[string]bool // every coordinate a tool install names
	steps     int
	tools     []toolStep
	installs  []toolStep // the allowed pip install -r runs
	other     bool       // an allowed install of another kind
	toolRuns  []scriptRun
}

// toolStep is one install: the order it ran in, the && list it was part of, and its installer
// (pipInstaller).
type toolStep struct {
	at, list  int
	listed    bool
	installer string
}

// pipInstaller returns the program as written before install in a pip install, with --user
// when the install carries it: pip3, /opt/venv/bin/pip, python3.11 -m pip. Two installs share an
// environment only when it can show they do, so pip, pip3, python -m pip, and two paths to one
// base name are each their own installer, and --user on one install only is another. It is
// empty when words is no pip install it reads.
func pipInstaller(words []string) string {
	head, ok := scriptsurface.CommandName(words[0])
	var id string
	switch {
	case !ok:
		return ""
	case pipHeadRE.MatchString(head) && len(words) >= 2 && words[1] == "install":
		id = words[0]
	case pythonHeadRE.MatchString(head) && len(words) >= 4 && words[1] == "-m" && pipHeadRE.MatchString(words[2]) && words[3] == "install":
		id = words[0] + " -m " + words[2]
	default:
		return ""
	}
	for _, w := range words {
		if w == "--user" {
			return id + " --user"
		}
	}
	return id
}

// allowed notes a command the rule allows.
func (o *toolOrder) allowed(words []string, list int, listed bool) {
	if args, ok := pipInstallArgs(words); ok && !isUVPip(words) {
		if !pipSelfUpgrade(args) {
			o.steps++
			o.installs = append(o.installs, toolStep{o.steps, list, listed, pipInstaller(words)})
		}
		return
	}
	head, _ := scriptsurface.CommandName(words[0])
	switch head {
	case "uv", "poetry", "pdm", "pipenv":
		o.other = o.other || len(words) > 1 && (words[1] == "sync" || words[1] == "install")
	}
}

// tool reports whether words is a tool install, and notes it. surface is where it runs.
func (o *toolOrder) tool(words []string, list int, listed bool, surface string) bool {
	args, ok := pipInstallArgs(words)
	if !ok || isUVPip(words) {
		return false
	}
	var names []string
	for _, a := range args {
		if selfUpgradeFlags[a] {
			continue
		}
		m := toolTargetRE.FindStringSubmatch(a)
		if m == nil {
			return false
		}
		names = append(names, normalizePyCoordinate(m[1]))
	}
	if len(names) == 0 {
		return false
	}
	named := o.manifestNames()
	for _, n := range names {
		if named[n] {
			return false
		}
	}
	o.steps++
	o.tools = append(o.tools, toolStep{o.steps, list, listed, pipInstaller(words)})
	o.toolRuns = append(o.toolRuns, scriptRun{surface: surface, args: args})
	if o.toolNames == nil {
		o.toolNames = map[string]bool{}
	}
	for _, n := range names {
		o.toolNames[n] = true
	}
	return true
}

// manifestNames returns every coordinate a manifest read here, or the tree's pixi manifests,
// names.
func (o *toolOrder) manifestNames() map[string]bool {
	if o.named != nil {
		return o.named
	}
	o.named = map[string]bool{}
	pixi, _, _ := pixiManifestDeps(o.root)
	for _, d := range pixi {
		o.named[normalizePyCoordinate(d.Coordinate)] = true
	}
	for _, m := range o.manifests {
		deps, _, _ := parseManifest(m)
		for _, d := range deps {
			o.named[normalizePyCoordinate(d.Coordinate)] = true
		}
	}
	return o.named
}

// pins returns the coordinates whose exact pins keep their version: each one a file the
// allowed pip install -r runs install (installs) pins exactly. ok is false when the order
// keeps none (toolOrder).
func (o *toolOrder) pins(installs pipInstalls) (keep map[string]bool, ok bool) {
	if o.other || len(o.installs) == 0 {
		return nil, false
	}
	for _, m := range o.manifests {
		if completeLockfiles[filepath.Base(m)] {
			return nil, false
		}
	}
	list, installer := o.tools[0].list, o.tools[0].installer
	for _, s := range append(o.tools[:len(o.tools):len(o.tools)], o.installs...) {
		if !s.listed || s.list != list || s.installer == "" || s.installer != installer {
			return nil, false
		}
	}
	if o.tools[len(o.tools)-1].at > o.installs[0].at {
		return nil, false
	}
	keep = map[string]bool{}
	for f := range installs {
		deps, _, read := parseManifest(f)
		if !read {
			return nil, false
		}
		for _, d := range deps {
			if d.Resolved {
				keep[normalizePyCoordinate(d.Coordinate)] = true
			}
		}
	}
	return keep, true
}

// withheld returns every coordinate a manifest names, or a tool installs, but keep.
func (o *toolOrder) withheld(keep map[string]bool) map[string]bool {
	out := map[string]bool{}
	maps.Copy(out, o.toolNames)
	for n := range o.manifestNames() {
		if !keep[n] {
			out[n] = true
		}
	}
	return out
}

// runs returns the tool installs' runs on the surfaces the rule did not withhold on, whose
// runs a rescan records already.
func (o *toolOrder) runs(withheld []surfaceHead) []scriptRun {
	again := map[string]bool{}
	for _, w := range withheld {
		again[w.path] = true
	}
	var out []scriptRun
	for _, r := range o.toolRuns {
		if !again[r.surface] {
			out = append(out, r)
		}
	}
	return out
}

// wideMarked reports whether the file at path starts with a UTF-16 or UTF-32 byte-order mark.
// pip decodes such a file, but the readers here take its bytes as UTF-8, so what they find in
// it is not what it declares.
func wideMarked(path string) bool {
	data, err := readRegular(path)
	if err != nil {
		return false
	}
	return bytes.HasPrefix(data, []byte{0xFF, 0xFE}) || bytes.HasPrefix(data, []byte{0xFE, 0xFF}) ||
		bytes.HasPrefix(data, []byte{0, 0, 0xFE, 0xFF})
}

// pyInstallSurface reports whether the file at path, with its buildtree.Head (nil when binary,
// empty or not a regular file, and then judged through buildtree.NULHeadMatch), names or holds
// a Python install surface, and the rule that matched. Every file ManifestCandidates classifies
// (pyCandidate) is one too.
func pyInstallSurface(path string, head []byte) (string, bool) {
	if why, ok := pySurfaceName(path); ok {
		return why, true
	}
	if why, ok := pySurfaceContent(path, head); ok {
		return why, true
	}
	return pyCandidate(path, head)
}

// pyForeignLocks are lowercased *.lock and *.lockb names other ecosystems own; every other one
// is a Python install surface.
var pyForeignLocks = map[string]bool{
	"cargo.lock": true, "gemfile.lock": true, "composer.lock": true, "yarn.lock": true,
	"bun.lock": true, "bun.lockb": true, "deno.lock": true, "flake.lock": true, "podfile.lock": true,
	"mix.lock": true, "pubspec.lock": true, "conan.lock": true, "paket.lock": true,
	"packages.lock": true, "shard.lock": true, "renv.lock": true, "elm.lock": true, "esy.lock": true,
}

func pySurfaceName(path string) (string, bool) {
	if inner, ok := buildtree.TemplateInner(path); ok {
		if why, ok := pySurfaceName(inner); ok {
			return "templated " + why, true
		}
	}
	lower := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(lower)
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	if _, ok := toolConfigName(lower, dir); ok {
		return "tool config name", true
	}
	switch {
	case isManifest(lower):
		return "manifest name", true
	case strings.HasPrefix(lower, "pipfile"), lower == "pixi.toml", strings.HasPrefix(lower, "pylock.") && ext == ".toml",
		lower == "tox.ini", lower == "noxfile.py", lower == "uv.toml":
		return "install surface name", true
	case isCondaEnvName(lower), strings.HasPrefix(lower, "conda-lock") && (ext == ".yml" || ext == ".yaml"):
		return "conda name", true
	case ext == ".in" && lower != "manifest.in":
		return "requirements input name", true
	case (ext == ".txt" || ext == ".lock" || ext == ".pip") &&
		(strings.Contains(lower, "requirement") || strings.Contains(lower, "constraint") || strings.HasPrefix(dir, "requirements")):
		return "requirements file name", true
	case (ext == ".lock" || ext == ".lockb") && !pyForeignLocks[lower]:
		return "lockfile name", true
	}
	return "", false
}

// isCondaEnvName reports whether a lowercased file name is a conda environment file's.
func isCondaEnvName(lower string) bool {
	ext := filepath.Ext(lower)
	return (ext == ".yml" || ext == ".yaml") && !strings.HasPrefix(lower, "conda-lock") &&
		(strings.HasPrefix(lower, "environment") || strings.HasPrefix(lower, "conda"))
}

// pySurfaceDocExts are formats no Python installer reads its configuration from, so a TOML or
// YAML snippet quoted in one is documentation. A requirements file can have any name, so the
// requirement-line rule still applies to them.
var pySurfaceDocExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".adoc": true, ".html": true, ".htm": true,
	".ipynb": true, ".py": true, ".pyi": true,
}

// pySurfaceTOMLHeaders are tables only a Python project, lock or environment declares.
var pySurfaceTOMLHeaders = []string{
	"[project]", "[build-system]", "[dependency-groups]", "[pypi-dependencies]", "[packages]", "[dev-packages]",
	"[tool.poetry", "[tool.pdm", "[tool.uv", "[tool.hatch", "[tool.setuptools", "[tool.pixi",
}

// pySurfaceLockMarkers are strings a Python lock's [[package]] entries carry.
var pySurfaceLockMarkers = []string{"requires-python", "requires_python", "python-versions", "pythonhosted.org", "pypi.org"}

func pySurfaceContent(path string, head []byte) (string, bool) {
	if head == nil {
		return buildtree.NULHeadMatch(path, pySurfaceContent)
	}
	src := string(head)
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".py" {
		if (strings.Contains(src, "setup(") || strings.Contains(src, "setuptools")) && strings.Contains(src, "_require") {
			return "setup() call content", true
		}
		return "", false
	}
	if requirementLinesContent(src) {
		return "requirement lines", true
	}
	if pySurfaceDocExts[ext] {
		return "", false
	}
	var tomlTable, lockPackage, condaDeps, condaPip bool
	for _, raw := range strings.Split(src, "\n") {
		l := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(l)
		for _, h := range pySurfaceTOMLHeaders {
			if t == h || strings.HasPrefix(h, "[tool.") && strings.HasPrefix(t, h) && len(t) > len(h) && (t[len(h)] == ']' || t[len(h)] == '.') {
				tomlTable = true
			}
		}
		lockPackage = lockPackage || t == "[[package]]"
		condaDeps = condaDeps || strings.HasPrefix(l, "dependencies:")
		condaPip = condaPip || t == "- pip:" || strings.HasPrefix(l, "channels:")
	}
	switch {
	case tomlTable:
		return "Python TOML table", true
	case lockPackage && !strings.Contains(src, "crates.io-index") && !strings.Contains(src, "@generated by Cargo"):
		for _, m := range pySurfaceLockMarkers {
			if strings.Contains(src, m) {
				return "Python lock content", true
			}
		}
	case condaDeps && condaPip:
		return "conda environment content", true
	}
	return "", false
}

// requirementLineRE is a PEP 508 requirement: a project name, optional extras, then an optional
// version clause or direct reference and an optional marker.
var requirementLineRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\s*(\[[^\]]*\])?\s*(\(?\s*(===|==|~=|!=|<=|>=|<|>)\s*[^\s,;()]+(\s*,\s*(===|==|~=|!=|<=|>=|<|>)\s*[^\s,;()]+)*\s*\)?|@\s*\S+)?\s*(;.*)?$`)

// requirementLinesContent reports whether src reads as a pip requirements file: every
// non-comment logical line is a PEP 508 requirement or a pip option, and at least one carries
// a version clause, a direct reference or an option, so a list of bare words (a word list, a
// VERSION file) is not taken for one.
func requirementLinesContent(src string) bool {
	strong := false
	for _, raw := range joinContinuations(src) {
		line := strings.TrimSpace(stripReqCommentSafe(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if len(line) < 2 || !(line[1] == '-' || line[1] >= 'a' && line[1] <= 'z' || line[1] >= 'A' && line[1] <= 'Z') {
				return false
			}
			strong = true
			continue
		}
		if i := strings.Index(line, " --"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		m := requirementLineRE.FindStringSubmatch(line)
		if m == nil {
			return false
		}
		if m[2] != "" {
			strong = true
		}
	}
	return strong
}

// declaresNothing reports whether a surface version resolution does not parse was read here
// and found to declare no dependency: a Pipfile with no package category, a conda
// environment that installs only the interpreter and pip, tox.ini with no deps key, or a
// noxfile that never installs. Every other surface, and any of these that cannot be read,
// declares something.
func declaresNothing(path string) bool {
	data, err := readRegular(path)
	if err != nil {
		return false
	}
	lower := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasPrefix(lower, "pipfile") && !strings.HasSuffix(lower, ".lock"):
		return !pipfileDeclares(data)
	case isCondaEnvName(lower):
		return !condaDeclares(data)
	case lower == "tox.ini":
		return !toxDeclares(string(data))
	case lower == "noxfile.py":
		return !bytes.Contains(data, []byte(".install("))
	}
	return false
}

// toxDeclares reports whether a tox.ini sets deps in any section.
func toxDeclares(src string) bool {
	for _, line := range strings.Split(src, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "deps" {
			return true
		}
	}
	return false
}

// --- installed copies -------------------------------------------------------------

// installedCopies reads the distributions installed in every site-packages directory under
// root, which the shared walk does not enter: each *.dist-info or *.egg-info names one by its
// metadata's Name and Version. A symlink, whether the site-packages directory itself or an entry
// in it, is followed when it resolves inside root, whatever its target is named, and makes ok
// false when it leaves root or does not resolve. Each site-packages directory is read once at
// its real path, and so is each metadata file: a link can make one directory both a
// site-packages and a metadata entry, and each role reads it. A copy whose metadata cannot be
// read makes ok false.
func installedCopies(root string) (copies []plugin.ResolvedDependency, origins []manifestOrigin, ok bool) {
	ok = true
	realRoot, rootErr := filepath.EvalSymlinks(root)
	escapes := func(path string) bool { return rootErr != nil || !buildtree.Inside(realRoot, path) }
	// once reports whether path's real path is seen for the first time in the role whose set
	// is seen. A path that does not resolve makes ok false.
	dirSeen, metaSeen := map[string]bool{}, map[string]bool{}
	once := func(seen map[string]bool, path string) bool {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			ok = false
			return false
		}
		if seen[real] {
			return false
		}
		seen[real] = true
		return true
	}
	_ = buildtree.Walk(root, func(e buildtree.Entry, err error) error {
		if err != nil || e.D.Name() != "site-packages" || !e.Skipped && !e.Symlink {
			return nil
		}
		if e.Symlink && e.Escapes {
			ok = false
			return nil
		}
		if !once(dirSeen, e.Path) {
			return nil
		}
		ents, rerr := os.ReadDir(e.Path)
		if rerr != nil {
			ok = false
			return nil
		}
		for _, d := range ents {
			name := d.Name()
			p := filepath.Join(e.Path, name)
			isDir := d.IsDir()
			if d.Type()&fs.ModeSymlink != 0 {
				if escapes(p) {
					ok = false
					continue
				}
				fi, serr := os.Stat(p)
				if serr != nil {
					ok = false
					continue
				}
				isDir = fi.IsDir()
			}
			var meta string
			switch {
			case strings.HasSuffix(name, ".dist-info") && isDir:
				meta = filepath.Join(p, "METADATA")
			case strings.HasSuffix(name, ".egg-info") && isDir:
				meta = filepath.Join(p, "PKG-INFO")
			case strings.HasSuffix(name, ".egg-info"):
				meta = p
			default:
				continue
			}
			if !once(metaSeen, meta) {
				continue
			}
			dist, version, mok := readDistMetadata(meta)
			if !mok {
				ok = false
				continue
			}
			copies = append(copies, pyResolved(dist, version, true, "site-packages"))
			origins = append(origins, manifestOrigin{dir: e.Path})
		}
		return nil
	})
	return copies, origins, ok
}

// readDistMetadata returns the Name and Version headers of a core-metadata file. ok is false
// when it cannot be read or names no project.
func readDistMetadata(path string) (name, version string, ok bool) {
	data, err := readRegular(path)
	if err != nil {
		return "", "", false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			break
		}
		if v, found := strings.CutPrefix(line, "Name:"); found {
			name = strings.TrimSpace(v)
		} else if v, found := strings.CutPrefix(line, "Version:"); found {
			version = strings.TrimSpace(v)
		}
	}
	return name, version, name != ""
}
