package pythonanalysis

// The runtime load set: which locked distributions the application can load, so an advisory
// on a distribution it never loads can be refuted (arm B, package_not_loaded).
//
// A distribution is loaded when a first-party runtime root names it (a static or literal
// dynamic import, a string literal naming a module, an entry point of the project) or when
// a loaded distribution depends on it in the lockfile. A curated table of enumerating
// loaders covers what a loaded distribution pulls in by entry-point group, URL scheme or
// settings string. Test code is not a root.
//
// A refutation additionally requires the distribution to sit outside the runtime install:
// only in dev/optional groups, or outside the closure of every runtime install target, as
// the lockfile's own markers say. A lockfile that cannot tell runtime from dev refutes
// nothing, and neither does a repository whose production install keeps dev dependencies
// (prodinstall.go).
//
// Everything uncertain fails closed: no lockfile, an edgeless lockfile, an import that maps
// to no distribution, an unbounded dynamic load, or any read failure clears complete.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// loadSet is the computed runtime load set of one build.
type loadSet struct {
	locks    *lockModel
	complete bool
	gaps     []string

	curated    DistImportMap
	known      map[string]bool     // locked ∪ declared PEP 503 names: the mapping universe
	fpSegments map[string]bool     // every path segment of a first-party runtime module
	fpTops     map[string]bool     // first-party top-level import names
	loaded     map[string]bool     // locked distributions in the runtime load set
	rootDists  map[string][]string // distribution → first-party roots that load it directly
	scanned    int                 // first-party runtime sources, project files and configs read
	loaders    map[string]bool     // enumerating loaders found loaded
	scoped     []plugin.ScopedReason
	unscoped   []string // unbounded dynamic loads in runtime code, "module: leaf"

	scan         *installScan    // what the build, deploy and CI files install
	reqRuntime   map[string]bool // named by a non-dev requirements file, a project table or an install command
	installed    map[string]bool // installed by a command or committed to the repository: never refuted
	projectNames map[string]bool // the project's own distribution names: root subjects, never refuted
	markerless   []string        // install sources whose runtime/dev split is unknown: nothing refutes
}

// noMarkers records an install source that cannot tell runtime from dev, or whose lockfile
// cannot be identified: no lockfile marker then decides what is installed.
func (ls *loadSet) noMarkers(format string, args ...any) {
	if len(ls.markerless) < 20 {
		ls.markerless = append(ls.markerless, fmt.Sprintf(format, args...))
	}
}

func (ls *loadSet) gap(format string, args ...any) {
	ls.complete = false
	if len(ls.gaps) < 20 {
		ls.gaps = append(ls.gaps, fmt.Sprintf(format, args...))
	}
}

// computeLoadSet builds the load set for the program loaded from buildDir.
func computeLoadSet(buildDir string, prog *program) *loadSet {
	ls := &loadSet{
		complete:   true,
		known:      map[string]bool{},
		fpSegments: map[string]bool{},
		fpTops:     map[string]bool{},
		loaded:     map[string]bool{},
		rootDists:  map[string][]string{},
		loaders:    map[string]bool{},
		reqRuntime: map[string]bool{},
		installed:  map[string]bool{},

		projectNames: map[string]bool{},
	}
	ls.locks = loadLocks(buildDir, ls)
	for d := range ls.locks.versions {
		ls.known[d] = true
	}
	for d := range prog.dists.declared {
		ls.known[d] = true
	}
	ls.curated = prog.dists.curated
	for t := range prog.dists.firstParty {
		ls.fpTops[t] = true
	}
	if prog.readFailed {
		ls.gap("a Python source could not be read")
	}
	for _, f := range prog.files {
		if f.test {
			continue
		}
		for _, seg := range strings.Split(f.module, "/") {
			ls.fpSegments[seg] = true
		}
	}

	var sites []struct {
		file string
		site dynSite
	}
	for _, f := range prog.files {
		if f.test {
			continue
		}
		file := f.module + ".py"
		ls.scanned++
		for _, m := range f.imports {
			ls.rootModule(m, file, true)
		}
		for _, m := range f.dyn.roots {
			ls.rootModule(m, file, true)
		}
		for _, m := range f.stars {
			ls.rootModule(m, file, true)
			sites = append(sites, struct {
				file string
				site dynSite
			}{file, dynSite{kind: dynStar, module: m}})
		}
		for _, s := range f.strs {
			ls.rootString(s, file)
		}
		for _, leaf := range f.dyn.opaque {
			ls.unscoped = append(ls.unscoped, file+": "+leaf)
			ls.gap("unbounded dynamic load in %s (%s)", file, leaf)
		}
		for _, s := range f.dyn.sites {
			if s.kind == dynPrefix {
				// The prefix names the package the computed module lives in: load it.
				ls.rootModule(s.module, file, false)
			}
			sites = append(sites, struct {
				file string
				site dynSite
			}{file, s})
		}
	}
	ls.projectRoots(buildDir)
	ls.configRoots(buildDir)
	ls.close()

	for _, s := range sites {
		ls.scopeSite(s.file, s.site)
	}
	ls.scanInstalls(buildDir)
	ls.committedInstalls(buildDir)
	ls.runtimeManifestNames(buildDir)
	ls.expandLoaders()
	return ls
}

// --- name mapping --------------------------------------------------------------------

type mapKind int

const (
	mapNone mapKind = iota
	mapFirstParty
	mapStdlib
	mapDist
)

// mapMode selects how far mapModule guesses past exact evidence.
type mapMode int

const (
	mapStrict mapMode = iota // curated rows, PEP 503 equality, common renames
	mapImport                // + known distributions named T-*
	mapString                // + known distributions named T-* or *-T (settings strings name apps by import name)
)

// mapModule resolves a dotted module name to the distributions that may provide it.
// Candidates, strongest first: a curated import-name row or PEP 503 equality of any dotted
// prefix with a known distribution; then the common renames (python-T, py-T, pyT, T-python,
// T-py, T-binary); then, per mode, known distributions sharing T as a name prefix or suffix.
// Marking an extra candidate loaded is always sound, so every candidate of the first tier
// that has one is returned. A first-party name maps only when no distribution does.
func (ls *loadSet) mapModule(mod string, mode mapMode) ([]string, mapKind) {
	if strings.HasPrefix(mod, ".") || mod == "" {
		return nil, mapFirstParty
	}
	segs := strings.Split(mod, ".")
	top := segs[0]
	if stdlibModules[top] {
		var dists []string
		if d := normalizePyCoordinate(top); ls.known[d] {
			dists = append(dists, d)
		}
		for _, d := range stdlibShadows[top] {
			if ls.known[d] {
				dists = append(dists, d)
			}
		}
		return dists, mapStdlib
	}
	var dists []string
	for i := len(segs); i >= 1; i-- {
		prefix := strings.Join(segs[:i], ".")
		dists = append(dists, ls.curated.Reverse(prefix)...)
		if d := normalizePyCoordinate(prefix); ls.known[d] {
			dists = append(dists, d)
		}
	}
	if len(dists) > 0 {
		return sortedDedup(dists), mapDist
	}
	if ls.fpTops[top] || ls.fpSegments[top] {
		return nil, mapFirstParty
	}
	t := normalizePyCoordinate(top)
	for _, d := range []string{"python-" + t, "py-" + t, "py" + t, t + "-python", t + "-py", t + "-binary"} {
		if ls.known[d] {
			dists = append(dists, d)
		}
	}
	if len(dists) > 0 || mode == mapStrict {
		return sortedDedup(dists), mapDist
	}
	for d := range ls.known {
		if strings.HasPrefix(d, t+"-") || (mode == mapString && strings.HasSuffix(d, "-"+t)) {
			dists = append(dists, d)
		}
	}
	return sortedDedup(dists), mapDist
}

// rootModule records a module a first-party runtime file loads. An import (gapOnMiss) that
// maps to nothing clears complete: some installed distribution provides it and the lane
// cannot say which.
func (ls *loadSet) rootModule(mod, file string, gapOnMiss bool) {
	dists, kind := ls.mapModule(mod, mapImport)
	if kind == mapDist && len(dists) == 0 {
		if gapOnMiss {
			ls.gap("import %s in %s maps to no locked distribution", mod, file)
		}
		return
	}
	for _, d := range dists {
		ls.markRoot(d, file)
	}
}

// markRoot marks a distribution loaded directly from a first-party root. close() later
// brings its lockfile dependency closure in; a distribution the lockfile does not lock has no
// known closure, so the load set is incomplete.
func (ls *loadSet) markRoot(dist, root string) {
	if ls.locks.members[dist] {
		return // a workspace member is first-party code, read as such
	}
	if len(ls.locks.versions) > 0 && ls.locks.versions[dist] == nil {
		ls.gap("%s, loaded from %s, is not locked: its dependencies are unknown", dist, root)
	}
	if !containsString(ls.rootDists[dist], root) {
		ls.rootDists[dist] = append(ls.rootDists[dist], root)
	}
	ls.loaded[dist] = true
}

var (
	sqlURLRe   = regexp.MustCompile(`^([a-z][a-z0-9]*)(?:\+([a-z0-9_]+))?://`)
	dottedRe   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+`)
	configURLs = regexp.MustCompile(`[a-z][a-z0-9]*(?:\+[a-z0-9_]+)?://`)
)

// rootString records a string literal or config value that may name a module: a dotted
// path ("django.contrib.admin", "logging.handlers.RotatingFileHandler"), an entry-point
// spec ("pkg.mod:attr", "name = pkg.mod:attr"), or a database/broker URL whose scheme names
// a driver. A string that maps to nothing is ordinary text, never a gap.
func (ls *loadSet) rootString(s, root string) {
	s = strings.TrimSpace(s)
	if m := sqlURLRe.FindStringSubmatch(s); m != nil {
		for _, d := range urlSchemeDrivers(m[1], m[2]) {
			if ls.known[d] {
				ls.markRoot(d, root)
			}
		}
		return
	}
	if _, spec, ok := strings.Cut(s, "="); ok && strings.Contains(spec, ":") {
		s = strings.TrimSpace(spec)
	}
	s, _, _ = strings.Cut(s, ":")
	s = strings.TrimSpace(s)
	if !isDottedName(s) {
		return
	}
	dists, _ := ls.mapModule(s, mapString)
	for _, d := range dists {
		ls.markRoot(d, root)
	}
}

// moduleLikeLiterals returns the literal bodies of one file that could name a module, an
// entry point, or a database URL: short, single-line, no spaces outside an entry-point spec.
func moduleLikeLiterals(lits map[int]strLiteral) []string {
	var out []string
	for _, l := range lits {
		b := strings.TrimSpace(l.body)
		if b == "" || len(b) > 200 || strings.ContainsAny(b, "\n\t") {
			continue
		}
		if sqlURLRe.MatchString(b) {
			out = append(out, b)
			continue
		}
		if strings.Contains(b, " ") && !strings.Contains(b, "=") {
			continue
		}
		out = append(out, b)
	}
	return sortedDedup(out)
}

// --- static imports ------------------------------------------------------------------

// staticImports returns every module a file's import statements name (`import a.b` → a.b;
// `from a import b` → a and a.b, since b may be a submodule) and the sources of its star
// imports. Relative names keep their leading dots. A statement after a compound-statement
// colon (`try: import x`) or a semicolon is read too.
func staticImports(lines []logicalLine) (mods, stars []string) {
	for _, ll := range lines {
		for _, stmt := range strings.Split(ll.text, ";") {
			stmt = importStatementText(strings.TrimSpace(stmt))
			if stmt == "" {
				continue
			}
			kw, rest := firstWord(stmt)
			switch kw {
			case "import":
				for _, item := range splitImportList(rest) {
					if path, _ := splitAlias(item); isDottedName(path) {
						mods = append(mods, path)
					}
				}
			case "from":
				rest = strings.TrimSpace(rest)
				i := strings.Index(rest, " import ")
				if i < 0 {
					continue
				}
				from := strings.TrimSpace(rest[:i])
				if lead := strings.TrimLeft(from, "."); lead != from {
					if lead != "" && !isDottedName(lead) {
						continue
					}
				} else if !isDottedName(from) {
					continue
				}
				mods = append(mods, from)
				for _, item := range splitImportList(rest[i+len(" import "):]) {
					name, _ := splitAlias(item)
					if name == "*" {
						stars = append(stars, from)
						continue
					}
					if isDottedName(name) && !strings.Contains(name, ".") && !strings.HasPrefix(from, ".") {
						mods = append(mods, from+"."+name)
					}
				}
			}
		}
	}
	return sortedDedup(mods), sortedDedup(stars)
}

// importStatementText returns the import statement a logical-line segment holds: the
// segment itself when it starts with import/from, or the part after a compound header's
// colon (`try: import x`, `if TYPE_CHECKING: from a import b`); "" otherwise.
func importStatementText(stmt string) string {
	if kw, _ := firstWord(stmt); kw == "import" || kw == "from" {
		return stmt
	}
	for _, kw := range []string{": import ", ": from "} {
		if i := strings.Index(stmt, kw); i >= 0 {
			return strings.TrimSpace(stmt[i+1:])
		}
	}
	return ""
}

// --- project and config roots --------------------------------------------------------

type pyprojectEntryPoints struct {
	Project struct {
		Name         string                       `toml:"name"`
		Dependencies []string                     `toml:"dependencies"`
		Dynamic      []string                     `toml:"dynamic"`
		Scripts      map[string]string            `toml:"scripts"`
		GUIScripts   map[string]string            `toml:"gui-scripts"`
		EntryPoints  map[string]map[string]string `toml:"entry-points"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Scripts      map[string]any               `toml:"scripts"`
			Name         string                       `toml:"name"`
			Plugins      map[string]map[string]string `toml:"plugins"`
			Dependencies map[string]any               `toml:"dependencies"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// projectRoots reads every first-party pyproject.toml's scripts and entry points, and
// setup.cfg's [options.entry_points], as roots: the installed project loads them. It also
// records the project's own distribution names from pyproject, setup.cfg and setup.py.
func (ls *loadSet) projectRoots(buildDir string) {
	walkProjectFiles(buildDir, func(rel, abs string) {
		base := filepath.Base(rel)
		switch base {
		case "pyproject.toml":
			ls.scanned++
			data, err := os.ReadFile(abs)
			if err != nil {
				ls.gap("%s could not be read", rel)
				return
			}
			var pp pyprojectEntryPoints
			if _, err := toml.Decode(string(data), &pp); err != nil {
				ls.gap("%s could not be parsed", rel)
				return
			}
			ls.addProjectName(pp.Project.Name)
			ls.addProjectName(pp.Tool.Poetry.Name)
			delete(pp.Tool.Poetry.Dependencies, "python")
			if len(pp.Project.Dependencies) > 0 || len(pp.Tool.Poetry.Dependencies) > 0 || dynamicDeps(pp.Project.Dynamic) {
				ls.unlockedProject(rel)
			}
			var specs []string
			for _, v := range pp.Project.Scripts {
				specs = append(specs, v)
			}
			for _, v := range pp.Project.GUIScripts {
				specs = append(specs, v)
			}
			for _, g := range pp.Project.EntryPoints {
				for _, v := range g {
					specs = append(specs, v)
				}
			}
			for _, v := range pp.Tool.Poetry.Scripts {
				switch t := v.(type) {
				case string:
					specs = append(specs, t)
				case map[string]any:
					if ref, ok := t["reference"].(string); ok {
						specs = append(specs, ref)
					}
				}
			}
			for _, g := range pp.Tool.Poetry.Plugins {
				for _, v := range g {
					specs = append(specs, v)
				}
			}
			for _, s := range specs {
				ls.rootString(s, rel)
			}
			for _, dep := range pp.Project.Dependencies {
				if name, _, _, _ := parseRequirementSpec(strings.TrimSpace(dep)); name != "" {
					ls.reqRuntime[normalizePyCoordinate(name)] = true
				}
			}
			for name := range pp.Tool.Poetry.Dependencies {
				ls.reqRuntime[normalizePyCoordinate(name)] = true
			}
		case "setup.cfg":
			ls.scanned++
			data, err := os.ReadFile(abs)
			if err != nil {
				ls.gap("%s could not be read", rel)
				return
			}
			for _, v := range iniSectionValues(string(data), "options.entry_points") {
				ls.rootString(v, rel)
			}
			if strings.Contains(string(data), "install_requires") {
				ls.unlockedProject(rel)
			}
			section := ""
			for _, line := range strings.Split(string(data), "\n") {
				t := strings.TrimSpace(line)
				if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
					section = strings.TrimSpace(t[1 : len(t)-1])
				} else if k, v, ok := strings.Cut(t, "="); ok && section == "metadata" && strings.TrimSpace(k) == "name" {
					ls.addProjectName(v)
				}
			}
		case "setup.py":
			data, err := os.ReadFile(abs)
			if err != nil {
				ls.gap("%s could not be read", rel)
				return
			}
			for _, m := range setupPyName.FindAllStringSubmatch(string(data), -1) {
				ls.addProjectName(m[1])
			}
			if strings.Contains(string(data), "install_requires") {
				ls.unlockedProject(rel)
			}
		case "Pipfile":
			ls.unlockedProject(rel)
		}
	})
}

// unlockedProject records a project manifest that declares runtime dependencies: installing
// it resolves them afresh unless a lockfile locks that project, so with none the install is
// markerless. A lockfile locks only its own directory's project and its declared uv workspace
// members, never a nested project outside them.
func (ls *loadSet) unlockedProject(rel string) {
	// unlockedProject is also reached for dependencies a build backend computes (dynamic):
	// only a lockfile that locks the project describes what they resolve to.
	if ls.locks.coverDirs[path.Dir(rel)] {
		return
	}
	ls.noMarkers("%s declares dependencies no lockfile locks", rel)
}

// dynamicDeps reports a [project] dynamic list naming dependencies or optional-dependencies:
// the build backend computes them, so the manifest itself does not list them.
func dynamicDeps(fields []string) bool {
	for _, f := range fields {
		if f == "dependencies" || f == "optional-dependencies" {
			return true
		}
	}
	return false
}

var setupPyName = regexp.MustCompile(`\bname\s*=\s*['"]([A-Za-z0-9][A-Za-z0-9._-]*)['"]`)

func (ls *loadSet) addProjectName(name string) {
	if n := normalizePyCoordinate(name); n != "" {
		ls.projectNames[n] = true
	}
}

// iniSectionValues returns the values (right of '=') of every line in an INI section,
// continuation lines included.
func iniSectionValues(data, section string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(data, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			in = strings.TrimSpace(t[1:len(t)-1]) == section
			continue
		}
		if !in || t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if _, v, ok := strings.Cut(t, "="); ok && strings.Contains(v, ":") {
			out = append(out, t)
		}
	}
	return out
}

// configExts are the non-Python config formats whose values can name a module.
var configExts = map[string]bool{".ini": true, ".cfg": true, ".toml": true, ".yaml": true, ".yml": true, ".json": true, ".conf": true}

// toolingConfigs are dev-tooling configs: they name tools, never runtime modules.
var toolingConfigs = map[string]bool{
	"pytest.ini": true, "tox.ini": true, "mypy.ini": true, ".mypy.ini": true, "ruff.toml": true, ".ruff.toml": true,
	"setup.cfg": true, "pyproject.toml": true, ".flake8": true, ".coveragerc": true, "pyrightconfig.json": true,
	".pre-commit-config.yaml": true, ".pre-commit-hooks.yaml": true, "mkdocs.yml": true, "mkdocs.yaml": true,
	".readthedocs.yaml": true, ".readthedocs.yml": true, "codecov.yml": true, ".codecov.yml": true,
	"package.json": true, "package-lock.json": true, "tsconfig.json": true, "renovate.json": true,
	"uv.lock": true, "pdm.lock": true, "poetry.lock": true, "Pipfile.lock": true,
}

// configRoots reads first-party config files for dotted module paths and driver URLs
// (logging handler classes, Celery/Django settings in YAML or INI). Single-word values are
// not read: in prose-like configs they are words, not modules.
func (ls *loadSet) configRoots(buildDir string) {
	walkProjectFiles(buildDir, func(rel, abs string) {
		base := filepath.Base(rel)
		if !configExts[filepath.Ext(base)] || toolingConfigs[base] || strings.HasPrefix(base, ".") {
			return
		}
		info, err := os.Stat(abs)
		if err != nil || info.Size() > 256<<10 {
			return
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			ls.gap("%s could not be read", rel)
			return
		}
		ls.scanned++
		text := string(data)
		for _, m := range dottedRe.FindAllString(text, -1) {
			ls.rootString(m, rel)
		}
		for _, loc := range configURLs.FindAllStringIndex(text, -1) {
			ls.rootString(text[loc[0]:], rel)
		}
	})
}

// walkProjectFiles calls fn for every file under buildDir outside skipped trees and test
// directories, with its slash-separated relative path.
func walkProjectFiles(buildDir string, fn func(rel, abs string)) {
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree contributes nothing; keep walking.
		}
		if d.IsDir() {
			if path != buildDir && (skipDir(d.Name()) || d.Name() == "tests" || d.Name() == "test") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(buildDir, path)
		if rerr != nil {
			return nil //nolint:nilerr // outside the build dir: not a project file.
		}
		fn(filepath.ToSlash(rel), path)
		return nil
	})
}

// --- closure and loaders -------------------------------------------------------------

// close extends the load set over lockfile edges and applies the enumerating loaders, until
// nothing changes.
func (ls *loadSet) close() {
	for {
		queue := make([]string, 0, len(ls.loaded))
		for d := range ls.loaded {
			queue = append(queue, d)
		}
		sort.Strings(queue)
		for len(queue) > 0 {
			d := queue[0]
			queue = queue[1:]
			for c := range ls.locks.edges[d] {
				if !ls.loaded[c] && !ls.locks.members[c] {
					ls.loaded[c] = true
					queue = append(queue, c)
				}
			}
		}
		changed := false
		for _, l := range enumeratingLoaders {
			if !ls.loaded[l.dist] {
				continue
			}
			if !ls.loaders[l.dist] {
				ls.loaders[l.dist] = true
			}
			for _, m := range l.marks {
				if ls.known[m] && !ls.loaded[m] && ls.locks.versions[m] != nil {
					ls.loaded[m] = true
					changed = true
				}
			}
		}
		if !changed {
			return
		}
	}
}

// enumeratingLoaders load distributions by entry-point group, URL scheme or settings
// string rather than by import. When one is loaded, marks join the load set; an unbounded
// loader marks every distribution it could load (expandLoaders). Names are PEP 503.
var enumeratingLoaders = []struct {
	dist      string
	marks     []string
	unbounded bool
	what      string
}{
	{"pluggy", nil, true, "plugins by entry-point group"},
	{"pytest", nil, true, "pytest11 entry-point plugins"},
	{"stevedore", nil, true, "drivers and extensions by entry-point namespace"},
	{"setuptools", nil, true, "pkg_resources entry points"},
	{"importlib-metadata", nil, true, "entry points (backport)"},
	{"django", sqlDrivers, true, "INSTALLED_APPS, MIDDLEWARE and backends by settings string"},
	{"apache-airflow", nil, true, "providers by apache_airflow_provider entry points"},
	{"celery", []string{"redis", "amqp", "kombu"}, true, "app, broker transport and result backend by settings string"},
	{"kombu", []string{"redis", "amqp"}, true, "transports by broker URL scheme"},
	{"sqlalchemy", sqlDrivers, true, "dialects and DBAPI drivers by URL and sqlalchemy.dialects entry points"},
	{"flask", nil, true, "flask.commands entry points and extensions by import string"},
	{"jinja2", nil, false, "extensions by import string (read from literals)"},
	{"babel", nil, true, "babel.extractors entry points"},
	{"mlflow", nil, true, "tracking, artifact and model-registry plugins by entry points"},
	{"litellm", nil, true, "provider SDKs by optional import"},
	{"pandas", nil, true, "plotting backends by entry points and IO engines by optional import"},
	{"opentelemetry-instrumentation", nil, true, "instrumentors by opentelemetry_instrumentor entry points"},
	{"keyring", nil, true, "backends by keyring.backends entry points"},
	{"fsspec", nil, true, "filesystem implementations by protocol"},
	{"markdown", nil, true, "extensions by markdown.extensions entry points"},
	{"pygments", nil, true, "lexers and styles by entry points"},
	{"gunicorn", nil, true, "worker classes by settings string"},
	{"uvicorn", nil, true, "loops, protocols and the app by settings string"},
}

// sqlDrivers are the DBAPI drivers SQLAlchemy and Django load by URL or ENGINE string.
var sqlDrivers = []string{
	"psycopg2", "psycopg2-binary", "psycopg", "psycopg-binary", "psycopg-c", "asyncpg", "pg8000",
	"pymysql", "mysqlclient", "mysql-connector-python", "aiomysql", "asyncmy",
	"cx-oracle", "oracledb", "pyodbc", "pymssql", "aioodbc", "aiosqlite", "pysqlite3", "pysqlite3-binary",
}

// urlSchemeDrivers returns the distributions a database or broker URL loads, by dialect
// and explicit driver (`postgresql+asyncpg://`).
func urlSchemeDrivers(dialect, driver string) []string {
	byDriver := map[string][]string{
		"psycopg2": {"psycopg2", "psycopg2-binary"}, "psycopg": {"psycopg", "psycopg-binary", "psycopg-c"},
		"asyncpg": {"asyncpg"}, "pg8000": {"pg8000"}, "pymysql": {"pymysql"}, "mysqldb": {"mysqlclient"},
		"mysqlconnector": {"mysql-connector-python"}, "aiomysql": {"aiomysql"}, "asyncmy": {"asyncmy"},
		"cx_oracle": {"cx-oracle"}, "oracledb": {"oracledb"}, "pyodbc": {"pyodbc"}, "pymssql": {"pymssql"},
		"aioodbc": {"aioodbc"}, "aiosqlite": {"aiosqlite"}, "pysqlite": {"pysqlite3", "pysqlite3-binary"},
	}
	byDialect := map[string][]string{
		"postgresql": {"psycopg2", "psycopg2-binary"}, "postgres": {"psycopg2", "psycopg2-binary"},
		"mysql": {"mysqlclient"}, "mariadb": {"mysqlclient"}, "oracle": {"cx-oracle", "oracledb"},
		"mssql": {"pyodbc"}, "redis": {"redis"}, "rediss": {"redis"}, "amqp": {"amqp"}, "pyamqp": {"amqp"},
		"mongodb": {"pymongo"}, "sqs": {"boto3"},
	}
	if driver != "" {
		if d, ok := byDriver[driver]; ok {
			return d
		}
		return []string{normalizePyCoordinate(driver)}
	}
	return byDialect[dialect]
}

// expandLoaders applies every unbounded loader in the load set. An entry-point or settings
// scan finds only installed distributions, so each one marks the whole runtime install loaded
// (installDists: every locked distribution when the lockfile cannot tell runtime from dev or
// the production install keeps dev dependencies) and the closure is re-run over their edges.
// Loaded is never refuted, so no scoped limit is needed. With no lockfile nothing is marked:
// the load set is already incomplete and refutes nothing, and an unbounded scoped limit would
// only pre-empt every row's own undetermined reason.
func (ls *loadSet) expandLoaders() {
	triggered := sortedKeys(ls.loaders)
	unbounded := false
	for _, d := range triggered {
		for _, l := range enumeratingLoaders {
			unbounded = unbounded || (l.dist == d && l.unbounded)
		}
	}
	install := ls.installDists()
	if !unbounded || install == nil {
		return
	}
	for _, d := range install {
		if !ls.locks.members[d] {
			ls.loaded[d] = true
		}
	}
	// Re-closing can flag more loaders among the marked distributions; the Detail names only
	// the loaders first-party roots reached.
	ls.close()
	ls.loaders = map[string]bool{}
	for _, d := range triggered {
		ls.loaders[d] = true
	}
}

// installDists over-approximates the distributions an installed-metadata scan could find;
// nil with no lockfile.
func (ls *loadSet) installDists() []string {
	if len(ls.locks.versions) == 0 {
		return nil
	}
	var out []string
	for d := range ls.locks.versions {
		if !ls.locks.distinguishes || len(ls.markerless) > 0 || ls.locks.runtime[d] || ls.loaded[d] || ls.reqRuntime[d] || ls.keptByInstall(d) {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// scopeSite bounds one dynamic load in first-party file to the packages it could reach, or
// records it unbounded (complete cleared).
func (ls *loadSet) scopeSite(file string, s dynSite) {
	kind := map[dynSiteKind]string{dynPrefix: "import_module prefix ", dynGetattr: "getattr on ", dynStar: "star import from "}[s.kind]
	path := file + ": " + kind + s.module
	mode := mapImport
	if s.kind == dynGetattr {
		mode = mapStrict
	}
	dists, mk := ls.mapModule(s.module, mode)
	switch {
	case mk == mapStdlib && s.kind == dynGetattr && dynamicStdlibModules[strings.Split(s.module, ".")[0]]:
		ls.unscoped = append(ls.unscoped, path)
		ls.gap("unbounded dynamic load in %s", path)
		return
	case mk == mapStdlib && len(dists) == 0:
		return // a stdlib module cannot load a distribution by name
	case mk == mapFirstParty:
		// Every first-party runtime module is already a root, so a load into first-party
		// code hides no distribution load.
		ls.scoped = append(ls.scoped, plugin.ScopedReason{Reason: plugin.PartialReasonDynamicImportSpecifier, Path: path, Targets: []string{""}})
		return
	case len(dists) == 0 || len(ls.locks.versions) == 0:
		ls.unscoped = append(ls.unscoped, path)
		ls.gap("unbounded dynamic load in %s", path)
		return
	}
	for _, d := range dists {
		ls.scoped = append(ls.scoped, plugin.ScopedReason{
			Reason:  plugin.PartialReasonDynamicImportSpecifier,
			Package: pypiPURL(d),
			Path:    path,
			Targets: ls.closureTargets(d),
		})
	}
}

// closureTargets is dist and everything it depends on in the lockfile, as PURLs.
func (ls *loadSet) closureTargets(dist string) []string {
	seen := map[string]bool{dist: true}
	queue := []string{dist}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		for c := range ls.locks.edges[d] {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, pypiPURL(d))
	}
	sort.Strings(out)
	return out
}

// runtimeManifestNames marks every distribution a non-dev requirements file names as
// installed at runtime: a pip install from it bypasses the lockfile's groups. pip resolves the
// file's dependencies itself, so the lockfile's markers describe that install only when the
// file is a complete pinned export of locked copies; any other non-dev requirements file
// leaves the install markerless.
func (ls *loadSet) runtimeManifestNames(buildDir string) {
	for _, m := range manifestFiles(buildDir) {
		base := filepath.Base(m)
		if !strings.HasPrefix(base, "requirements") || !strings.HasSuffix(base, ".txt") {
			continue
		}
		rel, err := filepath.Rel(buildDir, m)
		if err != nil {
			rel = m
		}
		rel = filepath.ToSlash(rel)
		if devManifestPath(rel) {
			continue
		}
		data, err := os.ReadFile(m)
		if err != nil {
			ls.gap("%s could not be read", rel)
			continue
		}
		deps, _ := parseRequirementsTxt(data)
		for _, d := range deps {
			ls.reqRuntime[normalizePyCoordinate(d.Coordinate)] = true
		}
		if why := ls.unpinnedExport(data); why != "" {
			ls.noMarkers("%s: %s", rel, why)
		}
	}
}

// reqOptionsKept are requirements-file options that change where pip fetches from, never
// which distributions it installs.
var reqOptionsKept = []string{"--hash", "--index-url", "--extra-index-url", "-i", "--trusted-host", "--require-hashes", "--only-binary", "--no-binary", "--prefer-binary"}

// unpinnedExport returns why pip's install from a requirements file is not exactly a set of
// locked copies, or "" when every line pins a locked version and the lockfile closure of
// every pinned name is pinned too.
func (ls *loadSet) unpinnedExport(data []byte) string {
	pinned := map[string]bool{}
	for _, req := range joinContinuations(string(data)) {
		line := strings.TrimSpace(stripReqComment(req))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			opt, _, _ := strings.Cut(strings.Fields(line)[0], "=")
			if !containsString(reqOptionsKept, opt) {
				return "option " + opt + " is not resolved against the lockfile"
			}
			continue
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "--hash"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		name, version, resolved, _ := parseRequirementSpec(line)
		n := normalizePyCoordinate(name)
		switch {
		case n == "" || strings.ContainsAny(line, "/@") || strings.Contains(line, "://"):
			return line + " is not a pinned distribution"
		case !resolved:
			return name + " is not pinned to one version"
		case !ls.locks.versions[n][version]:
			return name + "==" + version + " is not a locked copy"
		}
		pinned[n] = true
	}
	for _, n := range sortedKeys(pinned) {
		for _, c := range sortedKeys(ls.locks.edges[n]) {
			if !pinned[c] && !ls.locks.members[c] {
				return n + " depends on " + c + ", which the file does not pin"
			}
		}
	}
	return ""
}

// devManifestTokens mark a requirements file dev tooling when one is a whole word of its path.
var devManifestTokens = map[string]bool{
	"dev": true, "develop": true, "development": true, "test": true, "tests": true, "testing": true,
	"lint": true, "linting": true, "doc": true, "docs": true, "typing": true, "mypy": true, "ci": true,
	"tool": true, "tools": true, "tooling": true, "format": true, "style": true, "check": true,
	"checks": true, "bench": true, "benchmark": true, "benchmarks": true,
}

// devManifestPath reports whether a requirements file's path marks it dev tooling. Whole words
// only: requirements-docker.txt is a production install, not docs.
func devManifestPath(rel string) bool {
	for _, w := range strings.FieldsFunc(strings.ToLower(rel), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if devManifestTokens[w] {
			return true
		}
	}
	return false
}

// --- refutation ----------------------------------------------------------------------

// pypiPackageRef splits an admitted pkg:pypi PURL pinned to a version into its PEP 503 name
// and version. ok is false for any other PURL or a missing version.
func pypiPackageRef(purl string) (name, version string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(purl), "pkg:pypi/")
	if !found {
		return "", "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	name, version, found = strings.Cut(rest, "@")
	name = normalizePyCoordinate(name)
	version = strings.TrimSpace(version)
	if !found || name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// refute returns the package_not_loaded refutation for dist at version, or nil when any
// condition fails: the load set is incomplete; a counted scoped limit targets dist; dist is
// loaded, not locked at version, or the project's own distribution (a root subject); the
// lockfile cannot tell runtime from dev; some install source is markerless (an unpinned
// requirements file, an unlocked project, or a lockfile that is not the only candidate for
// its directory); the production install keeps dev dependencies; or any locked copy of dist
// is in the runtime install, or something in the repository installs it.
//
// The grounds are install-closure membership alone: dist is outside the runtime install per
// the lockfile's own markers and nothing installs it some other way. A missing import never
// grounds a refutation; ls.loaded only blocks one.
//
// dist arrives PEP 503 normalized (pypiPackageRef), and every name it is compared against was
// normalized the same way when recorded, so the advisory's spelling (PyJWT, python_multipart)
// never decides the answer.
func (ls *loadSet) refute(dist, version string) *plugin.Refutation {
	if !ls.complete || ls.locks == nil {
		return nil
	}
	purl := pypiPURL(dist)
	for _, s := range ls.scoped {
		if s.Targets == nil || s.Package == purl || containsString(s.Targets, purl) {
			return nil
		}
	}
	if ls.loaded[dist] || ls.installed[dist] || ls.locks.members[dist] || ls.projectNames[dist] || !ls.locks.versions[dist][version] {
		return nil
	}
	// The gate matches Refutation.Package on name, never version, so every locked copy of
	// dist must be outside the runtime install, not only the admitted one.
	runtime := ls.reqRuntime[dist]
	for v := range ls.locks.versions[dist] {
		runtime = runtime || ls.locks.copyRuntime[dist][v]
	}
	if runtime {
		return nil
	}
	if !ls.locks.distinguishes || len(ls.markerless) > 0 || ls.keptByInstall(dist) {
		return nil
	}
	return &plugin.Refutation{
		Basis:   plugin.RefutationPackageNotLoaded,
		Package: purl,
		Detail:  ls.detail(dist, version),
	}
}

// detail is the one-line, checkable account of a refutation.
func (ls *loadSet) detail(dist, version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s is locked (%s)", dist, version, strings.Join(ls.locks.files, ", "))
	switch {
	case ls.locks.devLabel[dist] != "":
		b.WriteString(" outside the runtime install, only reachable from dev tooling: " + ls.locks.devLabel[dist])
	default:
		b.WriteString(" outside the runtime install, not reachable from any runtime install target")
	}
	direct := make([]string, 0, len(ls.rootDists))
	for d := range ls.rootDists {
		direct = append(direct, d)
	}
	sort.Strings(direct)
	fmt.Fprintf(&b, "; no import, string, entry point or loader in %d first-party runtime files and configs loads it (%d of %d locked distributions loaded, %d named directly",
		ls.scanned, len(ls.loaded), len(ls.locks.versions), len(direct))
	if len(direct) > 0 {
		shown := direct
		if len(shown) > 8 {
			shown = shown[:8]
		}
		b.WriteString(": " + strings.Join(shown, ", "))
		if len(direct) > len(shown) {
			fmt.Fprintf(&b, ", +%d more", len(direct)-len(shown))
		}
	}
	b.WriteString(")")
	if len(ls.loaders) > 0 {
		b.WriteString("; loaders expanded: " + strings.Join(sortedKeys(ls.loaders), ", "))
	}
	if sc := ls.scan; sc != nil && len(sc.files) > 0 {
		shown := sc.files
		if len(shown) > 4 {
			shown = shown[:4]
		}
		noun := "files"
		if len(sc.files) == 1 {
			noun = "file"
		}
		fmt.Fprintf(&b, "; install commands checked in %d %s (%s", len(sc.files), noun, strings.Join(shown, ", "))
		if len(sc.files) > len(shown) {
			fmt.Fprintf(&b, ", +%d more", len(sc.files)-len(shown))
		}
		b.WriteString(")")
	} else {
		b.WriteString("; no file in the repository runs an install command")
	}
	if sc := ls.scan; sc != nil && len(sc.images) > 0 {
		images := sortedKeys(sc.images)
		fmt.Fprintf(&b, "; packages preinstalled in base images are not read (%s)", strings.Join(images, ", "))
	}
	b.WriteString("; assumes dev/tooling groups are not installed at runtime")
	return b.String()
}

// --- stdlib --------------------------------------------------------------------------

// stdlibShadows are distributions that install a module under a stdlib top-level name.
var stdlibShadows = map[string][]string{
	"distutils": {"setuptools"},
}

// dynamicStdlibModules are stdlib modules whose attributes load modules by name: getattr on
// one with a computed name can reach any loader.
var dynamicStdlibModules = map[string]bool{"importlib": true, "builtins": true, "runpy": true, "imp": true, "pkgutil": true, "zipimport": true}

// stdlibModules is the union of top-level stdlib module names across CPython 3.x
// (sys.stdlib_module_names of 3.14, plus modules removed in 3.10–3.13).
var stdlibModules = func() map[string]bool {
	names := strings.Fields(`__future__ __main__ _abc _ast _asyncio _bisect _blake2 _bz2 _codecs _collections
	_collections_abc _compat_pickle _contextvars _csv _ctypes _curses _datetime _decimal _elementtree _functools
	_hashlib _heapq _imp _io _json _locale _lsprof _lzma _markupbase _md5 _multiprocessing _opcode _operator
	_osx_support _pickle _posixsubprocess _py_abc _pydecimal _pyio _queue _random _sha1 _sha2 _sha256 _sha3 _sha512
	_signal _socket _sqlite3 _sre _ssl _stat _string _strptime _struct _symtable _thread _threading_local _tkinter
	_tracemalloc _warnings _weakref _weakrefset _winapi _dummy_thread _bootlocale
	abc aifc annotationlib antigravity argparse array ast asynchat asyncio asyncore atexit audioop base64 bdb
	binascii binhex bisect builtins bz2 cProfile calendar cgi cgitb chunk cmath cmd code codecs codeop collections
	colorsys compileall compression concurrent configparser contextlib contextvars copy copyreg crypt csv ctypes
	curses dataclasses datetime dbm decimal difflib dis distutils doctest dummy_threading email encodings
	ensurepip enum errno faulthandler fcntl filecmp fileinput fnmatch formatter fractions ftplib functools gc
	genericpath getopt getpass gettext glob graphlib grp gzip hashlib heapq hmac html http idlelib imaplib imghdr
	imp importlib inspect io ipaddress itertools json keyword lib2to3 linecache locale logging lzma macpath
	mailbox mailcap marshal math mimetypes mmap modulefinder msilib msvcrt multiprocessing netrc nis nntplib nt
	ntpath nturl2path numbers opcode operator optparse os ossaudiodev parser pathlib pdb pickle pickletools pipes
	pkgutil platform plistlib poplib posix posixpath pprint profile pstats pty pwd py_compile pyclbr pydoc
	pydoc_data pyexpat queue quopri random re readline reprlib resource rlcompleter runpy sched secrets select
	selectors shelve shlex shutil signal site smtpd smtplib sndhdr socket socketserver spwd sqlite3 sre_compile
	sre_constants sre_parse ssl stat statistics string stringprep struct subprocess sunau symbol symtable sys
	sysconfig syslog tabnanny tarfile telnetlib tempfile termios textwrap this threading time timeit tkinter token
	tokenize tomllib trace traceback tracemalloc tty turtle turtledemo types typing unicodedata unittest urllib uu
	uuid venv warnings wave weakref webbrowser winreg winsound wsgiref xdrlib xml xmlrpc zipapp zipfile zipimport
	zlib zoneinfo`)
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}()
