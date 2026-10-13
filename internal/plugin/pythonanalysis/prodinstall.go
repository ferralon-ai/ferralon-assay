package pythonanalysis

// What the repository installs. A package_not_loaded refutation rests only on install-closure
// membership: the distribution is outside the runtime install per the lockfile's markers
// (class (i)), and nothing in the repository installs it some other way. It never rests on the
// absence of an import. Class (i) assumes the lockfile's dev/optional groups are not installed
// at runtime, so the scanner needs positive evidence that the production install is fully
// characterized, and fails closed whenever it lacks that evidence:
//
//   - Every file under the build dir is walked (buildtree.Walk: only a committed node_modules or
//     site-packages is skipped, and a symlink that leaves the build dir vetoes). A file is a
//     candidate install surface when it is a Dockerfile/Containerfile, a GitHub workflow or
//     action, GitLab CI, a shell script (by extension or shebang), a Makefile, Procfile or
//     Jenkinsfile, a known deploy or CI config, or ANY text file whose content carries an
//     installer token (pip, uv, uvx, pipx, poetry, pdm, pipenv, micropipenv, pex, shiv, flit,
//     rye, hatch, pixi, conda, mamba, easy_install, setup.py install) or a PIP_* setting.
//   - Every candidate must parse fully into the modelled install set: a line that carries an
//     installer token but that the parser does not account for vetoes.
//   - A production install that keeps a lockfile group blocks every distribution reached only
//     through that group; the kept set is what the install mode provably keeps.
//   - An install outside a lockfile installs its requirement's unlisted transitive closure, so
//     it blocks ALL refutations: a pip requirement without an exact pin to a locked version, a
//     pinned one whose locked closure is not pinned in the same install, extras, and every
//     isolated tool install (pipx, uvx, uv tool, uv run --with). Only pip, setuptools, wheel
//     and uv, whose closures are fixed, are exempt.
//   - An index or find-links value (option, requirement-file line, environment setting or
//     project config) that is not a remote https index: a directory, a file: URL, a relative
//     or loopback location, or a value the scanner cannot resolve is an install source the
//     lockfile does not describe. A remote https index only changes where locked
//     distributions are fetched from.
//   - A pip configuration file anywhere, a PIP_* setting that changes what pip installs, an
//     installer setting naming groups or extras, a requirement file that cannot be placed (in a
//     Dockerfile: through WORKDIR, COPY and ADD), a COPY --from or RUN --mount from an image the
//     repository does not build, a group selector the scanner does not model (pdm :all), a
//     project whose dependencies are dynamic and unlocked, a system package manager installing
//     a Python distribution, and every install family or option the scanner does not parse veto
//     every refutation.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// installScan is what the repository's files install.
type installScan struct {
	ls           *loadSet
	root         string
	files        []string          // candidate install surfaces read, relative paths
	keep         map[string]string // group key → where a production install keeps it
	lockInstalls int               // production lockfile installs (uv sync, poetry install, ...)
	pipInstalls  int
	noDeps       string // where a pip install --no-deps ran
	reqSeen      map[string]bool
	images       map[string]bool // FROM images not built in the repository
	handled      int             // install commands the parser accounted for
	vetoes       int
}

// scanCtx locates one command: the file it is in, a human location, whether it is a
// production install, and the state relative paths resolve against.
type scanCtx struct {
	file, where string
	prod        bool
	st          *textState
}

// textState is what a relative path in a command resolves against: repository directories,
// or, inside a Dockerfile, the container working directory and the image's copies.
type textState struct {
	bases   []string // repository directories, slash-separated
	unknown bool     // a cd the scanner could not follow
	docker  *dockerRunCtx
}

func newTextState(bases ...string) *textState {
	return &textState{bases: append([]string(nil), bases...)}
}

func (sc *installScan) veto(c scanCtx, format string, args ...any) {
	sc.vetoes++
	sc.ls.noMarkers("%s: %s", c.where, fmt.Sprintf(format, args...))
}

type pendingWorkflow struct {
	rel  string
	data []byte
}

// scanInstalls reads every candidate install surface under buildDir into ls.scan.
func (ls *loadSet) scanInstalls(buildDir string) {
	sc := &installScan{ls: ls, root: buildDir, keep: map[string]string{}, reqSeen: map[string]bool{}, images: map[string]bool{}}
	ls.scan = sc
	var workflows []pendingWorkflow
	read := func(c scanCtx, file string) {
		base := strings.ToLower(path.Base(c.file))
		if base == "pip.conf" || base == "pip.ini" {
			sc.veto(c, "pip configuration file: it can add requirements and options the scanner does not read")
			return
		}
		data, content, err := readInstallFile(file)
		switch {
		case err != nil:
			sc.veto(c, "could not be read")
			return
		case content == contentArchive:
			sc.veto(c, "archive: distributions or install commands it bundles are not read")
			return
		case content == contentExecutable:
			sc.veto(c, "executable: an interpreter or distributions it bundles are not read")
			return
		case content == contentBinary:
			// An image, a font or other data is neither text nor an archive, but one named as
			// an install surface, or carrying an installer token, is a surface not read.
			if installSurface(c.file, nil) != "" || condaRecipeName(base) || installTokens(data) {
				sc.veto(c, "binary content in an install surface: install commands it holds are not read")
			}
			return
		}
		sc.configIndexes(c, base, data)
		if condaEnvironment(base, data) {
			sc.veto(c, "conda environment file: conda installs its packages and its pip section, which the lockfile does not describe")
		} else if manager := environmentManifest(base, data); manager != "" {
			sc.veto(c, "%s: its environment manager installs the packages it lists, which the lockfile does not describe", manager)
		}
		if condaRecipeName(base) {
			if why := ls.condaRecipe(data); why != "" {
				sc.veto(c, "conda recipe: %s", why)
			}
		}
		kind := installSurface(c.file, data)
		if kind == "" {
			return
		}
		sc.files = append(sc.files, c.file)
		if kind != "docker" && dockerInstructionRe.Match(data) {
			sc.veto(c, "Dockerfile instructions in a file not read as a Dockerfile: which files its install commands read is unknown")
		}
		sc.envVetoes(c, data)
		if kind == "workflow" {
			workflows = append(workflows, pendingWorkflow{c.file, data})
			return
		}
		sc.scanFile(c.file, data, kind)
	}
	for _, cand := range ls.buildTree(buildDir) {
		rel := relSlash(buildDir, cand.Path)
		c := scanCtx{file: rel, where: rel, prod: true}
		switch cand.Why {
		case treeFile:
			read(c, cand.Path)
		case "symlink leaves the build dir":
			sc.veto(c, "symlink that leaves the repository or does not resolve: install commands behind it are unknown")
		case "symlink to a non-regular file":
			sc.veto(c, "symlink to a non-regular file: install commands behind it are unknown")
		case "symlinked directory the walk does not read":
			sc.veto(c, "symlinked directory whose target the walk does not read: install commands behind it are unknown")
		default: // "unreadable", or any reason buildtree adds: what it holds is not read
			if unlistedDir(cand.Path) {
				sc.veto(c, "could not be read: install commands under it are unknown")
			} else {
				sc.veto(c, "could not be read")
			}
		}
	}
	sc.scanWorkflows(workflows)
	sort.Strings(sc.files)
	if sc.noDeps != "" && sc.pipInstalls > 1 {
		ls.noMarkers("%s: pip install --no-deps alongside another pip install leaves the installed dependencies unknown", sc.noDeps)
	}
}

// treeFile is the reason buildTree gives every regular file under the build dir, or symlink
// to one inside it: both scans read every file, not only the ones a lane classifier names.
const treeFile = "file"

// buildTree is buildtree.Candidates over buildDir with every file accepted, walked once for both
// scans: each file in walk order, then every entry what it holds cannot be read through.
func (ls *loadSet) buildTree(buildDir string) []buildtree.Candidate {
	if ls.treeRoot != buildDir {
		ls.tree = buildtree.Candidates(buildDir,
			func(string, []byte) (string, bool) { return treeFile, true },
			func(string) bool { return false })
		ls.treeRoot = buildDir
	}
	return ls.tree
}

// unlistedDir reports whether an unreadable candidate is a directory the walk could not list
// (or a build dir that does not exist) rather than a file it could not open.
func unlistedDir(p string) bool {
	fi, err := os.Lstat(p)
	return err != nil || fi.IsDir()
}

func relSlash(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

// underSkipped reports whether target lies inside a node_modules or site-packages directory
// under root (or outside root).
func underSkipped(root, target string) bool {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(realRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if buildtree.Skipped(part) {
			return true
		}
	}
	return false
}

// familyGap is what may sit between an install family word and its subcommand: separators,
// and any global options with their values or variables (pip --no-cache-dir install, poetry
// -C . install, uv $UV_FLAGS sync).
const familyGap = `(?:[\s"',\\]+[-$][^\s"',]*(?:[\s"',\\]+[^\s"',\\-][^\s"',]*)?)*[\s"',\\]+`

// installCommandRe matches an installer token: an install family word (with any directory
// prefix) followed, past any global options, by a subcommand that installs, or an installer
// that always installs. In installCommandPattern, ~ stands for familyGap.
var installCommandRe = regexp.MustCompile(strings.ReplaceAll(installCommandPattern, "~", familyGap))

const installCommandPattern = `(?:^|[^\w.-])(?:[\w.-]*/)*(?:` +
	`pip[0-9.]*~(?:install|config)\b|pip-sync\b|` +
	`uv~(?:pip|sync|add|run|tool|export|lock)\b|uvx\b|` +
	`pipx~(?:install|run|inject|upgrade|reinstall|install-all|runpip|upgrade-all|reinstall-all)\b|` +
	`poetry~(?:install|sync|add|update|export|self|lock)\b|` +
	`pdm~(?:install|sync|add|update|export|self|lock|plugin|import)\b|` +
	`pipenv~(?:install|sync|update|upgrade|lock)\b|` +
	`micropipenv\b|pex\b|shiv\b|flit~install\b|` +
	`rye~(?:sync|add|install|tools?)\b|hatch~(?:env|run|shell|test|fmt)\b|` +
	`pixi~(?:install|add|run|global|shell|exec)\b|` +
	`(?:conda|mamba|micromamba)~(?:install|create|env|update|upgrade)\b|` +
	`easy_install\b|setup\.py~(?:install|develop)\b)`

// pipEnvRe matches a pip setting by environment variable; installerEnvRe matches an installer
// setting whose name selects groups or extras.
var (
	pipEnvRe       = regexp.MustCompile(`\bPIP_([A-Z][A-Z0-9_]*)`)
	installerEnvRe = regexp.MustCompile(`\b(?:UV|POETRY|PDM|PIPENV)_[A-Z0-9_]*(?:GROUP|DEV|EXTRA|WITH|ONLY|CATEGOR|OPTIONAL)[A-Z0-9_]*`)
	// indexEnvRe matches an installer setting naming an index or find-links location, with
	// the value that follows it (=, : or whitespace), if any.
	indexEnvRe = regexp.MustCompile(`\b((?:PIP|UV)_(?:FIND_LINKS|INDEX_URL|EXTRA_INDEX_URL|INDEX|DEFAULT_INDEX)|PIPENV_PYPI_MIRROR)\b(?:[ \t]*[=:][ \t]*|[ \t]+)?("[^"\n]*"|'[^'\n]*'|[^\s"'#]+)?`)
)

// installTokens reports whether data carries an installer command or an installer setting.
func installTokens(data []byte) bool {
	return installCommandRe.Match(data) || pipEnvRe.Match(data) || installerEnvRe.Match(data) || indexEnvRe.Match(data)
}

// pipEnvHarmless are PIP_* settings that change how pip fetches or reports, never which
// requirements it installs.
var pipEnvHarmless = setOf("NO_CACHE_DIR", "DISABLE_PIP_VERSION_CHECK", "DEFAULT_TIMEOUT", "TIMEOUT", "RETRIES",
	"TRUSTED_HOST", "ROOT_USER_ACTION", "NO_INPUT", "PROGRESS_BAR",
	"BREAK_SYSTEM_PACKAGES", "PREFER_BINARY", "NO_COLOR", "QUIET", "VERBOSE", "CERT", "CLIENT_CERT", "PROXY",
	"CACHE_DIR", "NO_WARN_SCRIPT_LOCATION", "REQUIRE_VIRTUALENV", "NO_PYTHON_VERSION_WARNING", "KEYRING_PROVIDER",
	"ONLY_BINARY", "NO_BINARY", "NO_BUILD_ISOLATION", "COMPILE", "NO_COMPILE")

func (sc *installScan) envVetoes(c scanCtx, data []byte) {
	seen := map[string]bool{}
	for _, m := range pipEnvRe.FindAllSubmatch(data, -1) {
		name := string(m[1])
		if pipEnvHarmless[name] || seen[name] || indexEnvNames[name] {
			continue
		}
		seen[name] = true
		sc.veto(c, "sets PIP_%s, which can change what pip installs", name)
	}
	for _, m := range installerEnvRe.FindAll(data, -1) {
		if name := string(m); !seen[name] {
			seen[name] = true
			sc.veto(c, "sets %s, an installer setting that selects groups or extras", name)
		}
	}
	for _, m := range indexEnvRe.FindAllSubmatch(data, -1) {
		name, v := string(m[1]), strings.Trim(string(m[2]), `"'`)
		vals := strings.Fields(v)
		if len(vals) == 0 {
			vals = []string{""}
		}
		for _, v := range vals {
			if !sc.indexValue(c, name, v) {
				break
			}
		}
	}
}

// indexEnvNames are the PIP_* settings envVetoes reads through indexEnvRe.
var indexEnvNames = setOf("FIND_LINKS", "INDEX_URL", "EXTRA_INDEX_URL", "INDEX", "DEFAULT_INDEX")

// indexOptions are the installer options whose value is an index or find-links location.
var indexOptions = setOf("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index", "--default-index",
	"--pypi-mirror")

// indexValue vetoes, and returns false, when v is not a remote https index. what names the
// option or setting. A uv `--index name=https://…` value is read past its name.
func (sc *installScan) indexValue(c scanCtx, what, v string) bool {
	if remoteIndex(v) {
		return true
	}
	sc.veto(c, "%s %q is not a remote https index: what it serves is an install source the lockfile does not describe", what, v)
	return false
}

// remoteIndex reports whether v is a remote https index location.
func remoteIndex(v string) bool {
	u := v
	if name, rest, ok := strings.Cut(v, "="); ok && !strings.ContainsAny(name, ":/") {
		u = rest
	}
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Host != "" && !loopbackHost(p.Hostname())
}

func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// configIndexes vetoes an index or find-links location in a project or installer config
// file that is not a remote https index: uv.toml, pyproject [tool.uv], [[tool.poetry.source]]
// and [[tool.pdm.source]], and a Pipfile [[source]].
func (sc *installScan) configIndexes(c scanCtx, base string, data []byte) {
	if base != "pyproject.toml" && base != "uv.toml" && base != "pipfile" {
		return
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		sc.veto(c, "could not be parsed for index settings")
		return
	}
	table := func(m map[string]any, keys ...string) map[string]any {
		for _, k := range keys {
			next, _ := m[k].(map[string]any)
			if next == nil {
				return nil
			}
			m = next
		}
		return m
	}
	// tables reads an array of tables, which the decoder returns as []map[string]any.
	tables := func(what string, v any) ([]map[string]any, bool) {
		switch v := v.(type) {
		case nil:
			return nil, true
		case []map[string]any:
			return v, true
		}
		sc.veto(c, "%s is not an array of tables the scanner reads", what)
		return nil, false
	}
	var uv map[string]any
	var sources []map[string]any
	switch base {
	case "uv.toml":
		uv = doc
	case "pipfile":
		src, ok := tables("source", doc["source"])
		if !ok {
			return
		}
		sources = src
	default:
		uv = table(doc, "tool", "uv")
		for _, tool := range []string{"poetry", "pdm"} {
			src, ok := tables("tool."+tool+".source", table(doc, "tool", tool)["source"])
			if !ok {
				return
			}
			sources = append(sources, src...)
		}
	}
	var check func(what string, v any) bool
	check = func(what string, v any) bool {
		switch v := v.(type) {
		case nil:
			return true
		case string:
			return sc.indexValue(c, what, v)
		case []any:
			for _, x := range v {
				if !check(what, x) {
					return false
				}
			}
			return true
		}
		sc.veto(c, "%s is not a location the scanner reads", what)
		return false
	}
	for _, k := range []string{"find-links", "index-url", "extra-index-url"} {
		if uv != nil && !check(k, uv[k]) {
			return
		}
	}
	if uv != nil {
		idx, ok := tables("index", uv["index"])
		if !ok {
			return
		}
		sources = append(sources, idx...)
	}
	for _, m := range sources {
		if !check("source url", m["url"]) {
			return
		}
	}
}

// installSurface classifies a file: "workflow", "action", "gitlab", "docker", "shell" (lines of
// commands), "yaml"/"toml"/"json" (must parse, then read as lines), "text" (lines of
// commands), or "" when it is not an install surface.
func installSurface(rel string, data []byte) string {
	base := strings.ToLower(path.Base(rel))
	ext := path.Ext(base)
	yml := ext == ".yml" || ext == ".yaml"
	switch {
	case yml && path.Dir(rel) == ".github/workflows":
		return "workflow"
	case strings.HasPrefix(rel, ".github/") && (base == "action.yml" || base == "action.yaml"):
		return "action"
	case base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml":
		return "gitlab"
	case strings.HasPrefix(base, "dockerfile"), strings.HasPrefix(base, "containerfile"), ext == ".dockerfile", ext == ".containerfile":
		return "docker"
	case base == "makefile", base == "gnumakefile", ext == ".mk", base == "procfile", strings.HasPrefix(base, "jenkinsfile"),
		ext == ".sh", ext == ".bash", ext == ".zsh", ext == ".ksh", shellShebang.Match(data):
		return "shell"
	case yml && (strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose") ||
		strings.HasPrefix(base, "cloudbuild") || strings.HasPrefix(base, "azure-pipelines") ||
		base == "render.yaml" || base == "render.yml" || base == "app.yaml" || base == "app.yml" ||
		base == "heroku.yml" || base == ".travis.yml" || base == "bitbucket-pipelines.yml" ||
		strings.HasPrefix(base, "buildspec") || rel == ".circleci/config.yml" || strings.HasPrefix(rel, ".buildkite/")):
		return "yaml"
	case base == "fly.toml", base == "railway.toml":
		return "toml"
	case base == "railway.json":
		return "json"
	}
	if dockerfileContent(data) {
		return "docker"
	}
	if !installTokens(data) {
		return ""
	}
	if hasDisallowedEnvOnly(data) {
		return "env"
	}
	switch {
	case yml:
		return "yaml"
	case ext == ".toml":
		return "toml"
	case ext == ".json":
		return "json"
	}
	return "text"
}

// condaEnvironment reports a conda environment file (environment.yml, binder/environment.yml):
// YAML whose top-level dependencies is a list, beside channels, with a pip section, or under
// an environment file name. conda env create, mamba and repo2docker install it without a
// command naming the packages.
func condaEnvironment(base string, data []byte) bool {
	var doc map[string]any
	if yaml.Unmarshal(data, &doc) != nil {
		return false
	}
	deps, ok := doc["dependencies"].([]any)
	if !ok {
		return false
	}
	if _, ok := doc["channels"]; ok || strings.HasPrefix(base, "environment") {
		return true
	}
	for _, d := range deps {
		if m, ok := d.(map[string]any); ok {
			if _, ok := m["pip"]; ok {
				return true
			}
		}
	}
	return false
}

// environmentManifest names the environment manifest or lock file data is, or "". Like a
// conda environment file, each is installed by its manager (pixi, conda-lock, conda, spack,
// devbox, Nix) without a command naming the packages it lists, conda or PyPI.
func environmentManifest(base string, data []byte) string {
	switch {
	case base == "pixi.toml" || pixiTOML(data):
		return "pixi manifest"
	case base == "pixi.lock" || yamlHas(data, "environments", "packages"):
		return "pixi lock file"
	case strings.Contains(base, "conda-lock") || yamlHas(data, "metadata", "package"):
		return "conda lock file"
	case condaExplicitRe.Match(data):
		return "conda explicit spec"
	case base == "spack.yaml" || base == "spack.lock" || yamlHas(data, "spack") || yamlHas(data, "concrete_specs"):
		return "spack environment"
	case base == "devbox.json" || base == "devbox.lock":
		return "devbox environment"
	case path.Ext(base) == ".nix" && nixPythonRe.Match(data):
		return "Nix expression with Python packages"
	}
	return ""
}

// condaRecipeName reports a conda-build (meta.yaml) or rattler-build (recipe.yaml) recipe.
func condaRecipeName(base string) bool {
	return base == "meta.yaml" || base == "recipe.yaml"
}

var (
	// jinjaRe is a Jinja expression, statement or comment; rattler-build's ${{ }} included.
	jinjaRe = regexp.MustCompile(`\{\{|\{%|\{#`)
	// condaSelectorRe is a conda-build line selector: a trailing # [win], # [py<38].
	condaSelectorRe = regexp.MustCompile(`(?m)#[ \t]*\[[^\]\n]*\][ \t]*\r?$`)
	condaReqNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)
)

// condaFixedRun are the run requirements whose closure is fixed: the interpreter, and the
// installers the install scan already exempts.
var condaFixedRun = setOf("python", "pip", "setuptools", "wheel", "uv")

// condaRecipe reads a conda recipe as a build manifest, like setup.py: it records the
// package's name as a project name and returns why the recipe withholds every refutation, or
// "". A recipe conda renders before reading (Jinja, a line selector), one that does not parse
// into package and requirements, and one with outputs is not read. A run requirement beyond
// the interpreter installs a closure conda resolves, which no lockfile describes.
func (ls *loadSet) condaRecipe(data []byte) string {
	switch {
	case jinjaRe.Match(data):
		return "Jinja template: conda renders it before reading what it installs"
	case condaSelectorRe.Match(data):
		return "line selector: conda renders it before reading what it installs"
	}
	var doc struct {
		Package struct {
			Name string `yaml:"name"`
		} `yaml:"package"`
		Requirements struct {
			Run []any `yaml:"run"`
		} `yaml:"requirements"`
		Outputs []any `yaml:"outputs"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "does not parse: what it installs is unknown"
	}
	if len(doc.Outputs) > 0 {
		return "outputs: the requirements of each output are not read"
	}
	ls.addProjectName(doc.Package.Name)
	for _, r := range doc.Requirements.Run {
		req, ok := r.(string)
		name := strings.ToLower(condaReqNameRe.FindString(strings.TrimSpace(req)))
		switch {
		case !ok || name == "":
			return "a run requirement that is not a plain spec: what it installs is unknown"
		case !condaFixedRun[name]:
			return fmt.Sprintf("run requirement %s: conda installs it and the closure it resolves, which the lockfile does not describe", name)
		}
	}
	return ""
}

// condaExplicitRe is the marker line of a conda explicit spec (conda list --explicit, a
// conda-lock render), which conda create --file installs.
var condaExplicitRe = regexp.MustCompile(`(?m)^@EXPLICIT[ \t]*\r?$`)

// nixPythonRe is a Nix expression's reference to Python (python3, python312Packages,
// buildPythonPackage) or to a Python environment builder (poetry2nix, uv2nix, mach-nix).
var nixPythonRe = regexp.MustCompile(`(?i)python|2nix|mach-nix`)

// pixiTOML reports TOML that pixi reads as a manifest: a [tool.pixi] table, or PyPI
// dependencies at the top level or in a feature.
func pixiTOML(data []byte) bool {
	if !bytes.Contains(data, []byte("pixi")) && !bytes.Contains(data, []byte("pypi-dependencies")) {
		return false
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return false
	}
	if tool, ok := doc["tool"].(map[string]any); ok && tool["pixi"] != nil {
		return true
	}
	if doc["pypi-dependencies"] != nil {
		return true
	}
	features, _ := doc["feature"].(map[string]any)
	for _, f := range features {
		if f, ok := f.(map[string]any); ok && f["pypi-dependencies"] != nil {
			return true
		}
	}
	return false
}

// yamlHas reports YAML (or JSON) whose top level has every one of keys.
func yamlHas(data []byte, keys ...string) bool {
	var doc map[string]any
	if yaml.Unmarshal(data, &doc) != nil {
		return false
	}
	for _, k := range keys {
		if doc[k] == nil {
			return false
		}
	}
	return true
}

// dockerfileContent reports a Dockerfile by its content, whatever its name (docker/web.prod,
// build/app.image): after comments, parser directives and ARG lines, its first instruction
// is FROM.
func dockerfileContent(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		word, _, _ := strings.Cut(t, " ")
		word, _, _ = strings.Cut(word, "\t")
		switch strings.ToUpper(word) {
		case "ARG":
			continue
		case "FROM":
			return true
		}
		return false
	}
	return false
}

// dockerInstructionRe matches a line that is a Dockerfile instruction placing or locating
// files. In a file not read as a Dockerfile, it means the commands beside it may run in an
// image whose files are not the ones at their repository paths.
var dockerInstructionRe = regexp.MustCompile(`(?m)^[ \t]*(?:FROM|COPY|ADD|WORKDIR|ONBUILD)[ \t]+\S|(?im)^[ \t]*from[ \t]+\S+(?:[ \t]+as[ \t]+\S+)?[ \t]*\r?$`)

// hasDisallowedEnvOnly reports a file that is a candidate only for its settings: its vetoes
// come from envVetoes, and it carries no installer token to parse.
func hasDisallowedEnvOnly(data []byte) bool {
	return !installCommandRe.Match(data)
}

var shellShebang = regexp.MustCompile(`^#!\s*(?:/usr)?(?:/local)?/bin/(?:env\s+)?(?:sh|bash|dash|zsh|ksh|ash)\b`)

func (sc *installScan) scanFile(rel string, data []byte, kind string) {
	c := scanCtx{file: rel, where: rel, prod: true, st: newTextState(path.Dir(rel), ".")}
	switch kind {
	case "env":
		return
	case "yaml":
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var v any
			err := dec.Decode(&v)
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				sc.veto(c, "could not be parsed")
				return
			}
			sc.scanVectors(c, v)
		}
	case "toml":
		var v map[string]any
		if _, err := toml.Decode(string(data), &v); err != nil {
			sc.veto(c, "could not be parsed")
			return
		}
		sc.scanVectors(c, v)
	case "json":
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			sc.veto(c, "could not be parsed")
			return
		}
		sc.scanVectors(c, v)
	case "action":
		sc.scanAction(rel, data)
		return
	case "gitlab":
		sc.scanGitLab(rel, data)
		return
	case "docker":
		sc.scanDockerfile(rel, string(data))
		return
	}
	// A parsed config is also read line by line: a command can sit in any scalar.
	c.st = newTextState(path.Dir(rel), ".")
	sc.scanText(c, string(data))
}

// scanVectors reads every all-string sequence in a parsed config as one command (a container
// `command: [sh, -c, ...]` or an exec-form vector split over lines); the raw lines are read
// too.
func (sc *installScan) scanVectors(c scanCtx, v any) {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range sortedMapKeys(t) {
			sc.scanVectors(c, t[k])
		}
	case []any:
		words := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				words = nil
				break
			}
			words = append(words, s)
		}
		if len(words) > 1 {
			lc := c
			lc.where = c.where + " vector"
			lc.st = newTextState(path.Dir(c.file), ".")
			sc.scanText(lc, strings.Join(words, " "))
		}
		for _, e := range t {
			sc.scanVectors(c, e)
		}
	}
}

// scanText reads text as shell command lines: backslash continuations joined, comment lines
// skipped, each line split on && || ; |. A line that carries an installer token the parser
// does not account for vetoes.
func (sc *installScan) scanText(c scanCtx, text string) {
	if c.st == nil {
		c.st = newTextState(path.Dir(c.file), ".")
	}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		start := i
		line := lines[i]
		for strings.HasSuffix(strings.TrimRight(line, " \t\r"), "\\") && i+1 < len(lines) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t\r"), "\\") + " " + lines[i+1]
			i++
		}
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		lc := c
		lc.where = fmt.Sprintf("%s:%d", c.where, start+1)
		sc.scanLine(lc, line)
	}
}

// scanLine reads one logical command line.
func (sc *installScan) scanLine(c scanCtx, line string) {
	handled, vetoes := sc.handled, sc.vetoes
	for _, seg := range splitShellCommands(line) {
		tok := shellTokens(seg)
		if len(tok) > 0 && (cmdWord(tok[0]) == "cd" || cmdWord(tok[0]) == "pushd" || cmdWord(tok[0]) == "popd") {
			c.st.cd(tok)
			continue
		}
		sc.command(c, tok)
	}
	if installCommandRe.MatchString(line) && sc.handled == handled && sc.vetoes == vetoes {
		sc.veto(c, "an install command the scanner does not parse")
	}
}

// cd follows a change of directory: a literal relative path moves every base (or the container
// working directory); anything else leaves the directory unknown.
func (st *textState) cd(tok []string) {
	sub := strings.HasPrefix(tok[0], "(")
	if cmdWord(tok[0]) != "cd" || len(tok) < 2 || sub || strings.ContainsAny(tok[1], "$`~") || tok[1] == "-" || shellEnd(tok[1]) {
		st.unknown = true
		if st.docker != nil {
			st.docker.cwdUnknown = true
		}
		return
	}
	d := path.Clean(tok[1])
	if st.docker != nil {
		if path.IsAbs(d) {
			st.docker.cwd = d
		} else {
			st.docker.cwd = path.Join(st.docker.cwd, d)
		}
		return
	}
	if path.IsAbs(d) {
		st.unknown = true
		return
	}
	for i := range st.bases {
		st.bases[i] = path.Join(st.bases[i], d)
	}
}

var shellSeparators = regexp.MustCompile(`&&|\|\||;|\|`)

func splitShellCommands(line string) []string { return shellSeparators.Split(line, -1) }

// arrayOpen is the bracket that opens an exec-form array; an extras bracket (black[d]) follows
// a name instead.
var arrayOpen = regexp.MustCompile(`(^|[\s=:])\[`)

// execFormComma is the comma between two quoted words of an exec-form array.
var execFormComma = regexp.MustCompile(`(["'])\s*,\s*(["'])`)

// shellTokens splits a command into words, dropping quotes and JSON-array punctuation so the
// exec form `CMD ["uv", "run", "app"]` reads like the shell form. A comma inside an argument
// (`--without dev,docs`) is kept.
func shellTokens(seg string) []string {
	seg = execFormComma.ReplaceAllString(seg, "$1 $2")
	seg = arrayOpen.ReplaceAllString(seg, "$1 ")
	seg = strings.NewReplacer(`"`, " ", `'`, " ").Replace(seg)
	var out []string
	for _, f := range strings.Fields(seg) {
		if !strings.Contains(f, "[") {
			f = strings.TrimRight(f, "]")
		}
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// shellEnd reports a token that ends a command's arguments: a redirection or a comment.
func shellEnd(tok string) bool {
	return strings.HasPrefix(tok, "#") || strings.HasPrefix(tok, ">") || strings.HasPrefix(tok, "<") ||
		strings.HasPrefix(tok, "&>") || redirectRe.MatchString(tok)
}

var (
	redirectRe = regexp.MustCompile(`^\d+>`)
	pipWordRe  = regexp.MustCompile(`^pip(\d+(\.\d+)*)?$`)
	pythonRe   = regexp.MustCompile(`^(python(\d+(\.\d+)*)?|py)$`)
)

// cmdWord is a token as a command name: Make prefixes, subshell parens and the directory
// stripped.
func cmdWord(tok string) string {
	w := path.Base(strings.TrimLeft(tok, "@-+("))
	return strings.TrimSuffix(w, ".exe")
}

// installVerbs follow a command that a variable names (`$PIP install`, `$(PM) add`).
var installVerbs = map[string]bool{"install": true, "add": true, "sync": true, "inject": true}

// command reads one shell command for install families. Each family is read once per command;
// a `run` subcommand's own command is read recursively.
func (sc *installScan) command(c scanCtx, tok []string) {
	for i := 0; i < len(tok); i++ {
		if shellEnd(tok[i]) {
			return
		}
		w := cmdWord(tok[i])
		rest := tok[i+1:]
		if strings.ContainsAny(tok[i], "$`") && len(rest) > 0 && installVerbs[rest[0]] {
			sc.veto(c, "a command named by a variable or substitution runs %s", rest[0])
			return
		}
		switch {
		case pipWordRe.MatchString(w):
			sc.handled++
			sc.pip(c, rest)
			return
		case pythonRe.MatchString(w) && len(rest) >= 2 && rest[0] == "-m":
			mod := rest[1]
			if pipWordRe.MatchString(mod) {
				sc.handled++
				sc.pip(c, rest[2:])
				return
			}
			if familyWords[mod] {
				sc.handled++
				sc.family(c, mod, rest[2:])
				return
			}
		case w == "pip-sync":
			sc.handled++
			sc.syncFiles(c, rest)
			return
		case familyWords[w]:
			sc.handled++
			sc.family(c, w, rest)
			return
		case vetoFamilies[w]:
			sc.handled++
			sc.vetoFamily(c, w, rest)
			return
		case systemInstallers[w]:
			sc.handled++
			sc.systemInstall(c, w, rest)
			return
		case w == "easy_install":
			sc.veto(c, "easy_install is not parsed")
			return
		case w == "setup.py" && len(rest) > 0 && (rest[0] == "install" || rest[0] == "develop"):
			sc.veto(c, "setup.py %s installs the project, whose dependencies are not read", rest[0])
			return
		}
	}
}

var familyWords = map[string]bool{
	"uv": true, "uvx": true, "pipx": true, "poetry": true, "pdm": true, "pipenv": true,
	"conda": true, "mamba": true, "micromamba": true,
}

// vetoFamilies are installers the scanner does not model; harmless lists the subcommands of
// each that install nothing.
var (
	vetoFamilies = setOf("micropipenv", "pex", "shiv", "flit", "rye", "hatch", "pixi")
	vetoHarmless = map[string]map[string]bool{
		"flit":  setOf("build", "publish", "init", "--version", "--help", "-h"),
		"rye":   setOf("show", "version", "build", "publish", "fmt", "lint", "init", "config", "self", "--version", "--help", "-h", "help"),
		"hatch": setOf("build", "publish", "version", "clean", "config", "status", "new", "project", "--version", "--help", "-h", "help"),
		"pixi":  setOf("info", "list", "tree", "init", "auth", "config", "clean", "search", "--version", "--help", "-h", "help", "completion"),
	}
)

func (sc *installScan) vetoFamily(c scanCtx, w string, rest []string) {
	if len(rest) > 0 && vetoHarmless[w][rest[0]] {
		return
	}
	if len(rest) == 0 || shellEnd(rest[0]) {
		if w == "flit" || w == "rye" || w == "hatch" || w == "pixi" {
			return
		}
	}
	sc.veto(c, "%s installs dependencies the scanner does not parse", strings.TrimSpace(w+" "+firstArg(rest)))
}

func firstArg(xs []string) string {
	if len(xs) == 0 || shellEnd(xs[0]) {
		return ""
	}
	return xs[0]
}

// systemInstallers are system package managers; a Python distribution they install
// (python3-<name>, py3-<name>) is outside the lockfile.
var systemInstallers = setOf("apt-get", "apt", "apk", "dnf", "yum", "microdnf", "zypper")

// systemPythonHarmless are suffixes of interpreter and build-tool packages, not distributions
// an application imports.
var systemPythonHarmless = []string{"-pip", "-venv", "-dev", "-distutils", "-setuptools", "-wheel", "-minimal", "-full",
	"-lib2to3", "-all", "-all-dev", "-tk", "-gdbm", "-doc", "-dbg", "-examples", "-stdlib-extensions"}

var systemPythonRe = regexp.MustCompile(`^(?:python3?(?:\.\d+)?|py3)-([A-Za-z0-9][A-Za-z0-9._+-]*?)(?:=.*)?$`)

func (sc *installScan) systemInstall(c scanCtx, w string, rest []string) {
	if len(rest) == 0 || (rest[0] != "install" && rest[0] != "add") {
		// Options before the verb (`apt-get -y install`) are read too.
		i := 0
		for i < len(rest) && strings.HasPrefix(rest[i], "-") {
			i++
		}
		if i >= len(rest) || (rest[i] != "install" && rest[i] != "add") {
			return
		}
		rest = rest[i:]
	}
	for _, a := range rest[1:] {
		if shellEnd(a) {
			return
		}
		m := systemPythonRe.FindStringSubmatch(a)
		if m == nil {
			continue
		}
		pkg, _, _ := strings.Cut(a, "=")
		harmless := false
		for _, s := range systemPythonHarmless {
			harmless = harmless || strings.HasSuffix(pkg, s)
		}
		if !harmless {
			sc.veto(c, "%s installs %s, a Python distribution outside the lockfile", w, a)
			return
		}
	}
}

// --- pip -----------------------------------------------------------------------------

var (
	pipGlobalFlags = setOf("-q", "--quiet", "-v", "--verbose", "--isolated", "--no-cache-dir", "--disable-pip-version-check",
		"--no-input", "--no-color", "--require-virtualenv", "--no-python-version-warning", "-V", "--version", "-h", "--help",
		"--user", "--break-system-packages")
	pipGlobalValues = setOf("--python", "--log", "--proxy", "--retries", "--timeout", "--exists-action", "--trusted-host",
		"--cert", "--client-cert", "--cache-dir", "--use-feature", "--use-deprecated", "--keyring-provider")
	pipOtherSubs = setOf("download", "wheel", "freeze", "list", "show", "uninstall", "cache", "check", "inspect",
		"index", "hash", "debug", "completion", "help", "compile", "tree", "lock")
	pipInstallFlags = setOf("-U", "--upgrade", "--user", "--system", "--no-cache-dir", "-q", "--quiet", "-v", "--verbose",
		"--pre", "--force-reinstall", "-I", "--ignore-installed", "--no-build-isolation", "--break-system-packages",
		"--require-hashes", "--no-input", "--compile", "--no-compile", "--no-warn-script-location", "--prefer-binary",
		"--no-index", "--isolated", "--dry-run", "--strict", "--exact", "--reinstall", "--refresh", "-y",
		"--disable-pip-version-check", "--no-warn-conflicts", "--compile-bytecode", "--no-progress", "--native-tls",
		"--offline", "--progress-bar", "--root-user-action", "--ignore-requires-python", "--no-clean")
	pipInstallValues = setOf("-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host", "-t", "--target",
		"--prefix", "--root", "--platform", "--python-version", "--implementation", "--abi", "--src", "--python", "-p",
		"-C", "--config-settings", "--cache-dir", "--log", "--exclude-newer", "--upgrade-strategy", "--only-binary",
		"--no-binary", "--progress-bar", "--root-user-action", "--timeout", "--retries", "--proxy", "--cert",
		"--link-mode", "--index-strategy", "--resolution", "--prerelease", "--python-platform", "--keyring-provider",
		"--report", "--index")
	reqFileOptions = setOf("-i", "--index-url", "--extra-index-url", "--trusted-host", "-f", "--find-links", "--hash",
		"--require-hashes", "--only-binary", "--no-binary", "--prefer-binary", "--pre", "--no-index")
)

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// bootstrapClosures are installers whose dependencies are fixed and small, so an unpinned
// `pip install -U pip setuptools wheel` is still exactly known.
var bootstrapClosures = map[string][]string{"pip": nil, "setuptools": nil, "wheel": {"packaging"}, "uv": nil}

func (sc *installScan) pip(c scanCtx, args []string) {
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt, _, eq := strings.Cut(args[i], "=")
		switch {
		case pipGlobalFlags[opt]:
			i++
		case pipGlobalValues[opt]:
			i++
			if !eq {
				i++
			}
		default:
			sc.veto(c, "pip option %s is not parsed", opt)
			return
		}
	}
	if i >= len(args) || shellEnd(args[i]) {
		return
	}
	switch sub := args[i]; {
	case sub == "install":
		sc.pipInstall(c, args[i+1:])
	case sub == "config":
		if i+1 < len(args) && (args[i+1] == "list" || args[i+1] == "get" || args[i+1] == "debug") {
			return
		}
		sc.veto(c, "pip config changes pip's configuration, which can add requirements")
	case pipOtherSubs[sub]:
	default:
		sc.veto(c, "pip %s is not a subcommand the scanner parses", sub)
	}
}

// pipSet is what one install command asks for: the distributions it installs and the exact
// pins its requirements and constraints give.
type pipSet struct {
	installs []string
	boot     []string
	pins     map[string]string
	noDeps   bool
}

// pipInstall reads `pip install` / `uv pip install` arguments.
func (sc *installScan) pipInstall(c scanCtx, args []string) {
	sc.pipInstalls++
	for _, a := range args {
		if shellEnd(a) {
			break
		}
		if strings.ContainsAny(a, "$`") {
			sc.veto(c, "pip install argument %s is a variable or substitution", a)
			return
		}
	}
	set := &pipSet{pins: map[string]string{}}
	targets := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if shellEnd(a) {
			break
		}
		if !strings.HasPrefix(a, "-") {
			targets++
			if !sc.spec(c, a, set, false) {
				return
			}
			continue
		}
		opt, val, eq := strings.Cut(a, "=")
		if !strings.HasPrefix(opt, "--") && len(opt) > 2 {
			if opt[1] != 'r' && opt[1] != 'c' {
				sc.veto(c, "pip install option %s is not parsed", opt)
				return
			}
			opt, val, eq = a[:2], a[2:], true
		}
		next := func() (string, bool) {
			if eq {
				return val, true
			}
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		switch {
		case opt == "-r" || opt == "--requirement" || opt == "-c" || opt == "--constraint":
			v, ok := next()
			if !ok || strings.ContainsAny(v, "$`") {
				sc.veto(c, "%s names no file the scanner can read", opt)
				return
			}
			constraint := opt == "-c" || opt == "--constraint"
			if !constraint {
				targets++
			}
			if !sc.reqFile(c, v, set, constraint) {
				return
			}
		case opt == "-e" || opt == "--editable":
			sc.veto(c, "pip install %s installs a project whose dependencies are not read", opt)
			return
		case opt == "--no-deps":
			set.noDeps = true
			if sc.noDeps == "" {
				sc.noDeps = c.where
			}
		case pipInstallFlags[opt] && !eq:
		case pipInstallValues[opt]:
			v, ok := next()
			if !ok {
				sc.veto(c, "pip install option %s has no value", opt)
				return
			}
			if indexOptions[opt] && !sc.indexValue(c, opt, v) {
				return
			}
		default:
			sc.veto(c, "pip install option %s is not parsed", opt)
			return
		}
	}
	if targets == 0 {
		sc.veto(c, "pip install with no requirement the scanner could read")
		return
	}
	sc.installSet(c, set)
}

// installSet marks what a pip install installs, or vetoes when it resolves outside the
// lockfile: every requirement must be pinned exactly to a locked version, and so must every
// distribution in its locked closure, or pip installs an unlisted transitive closure.
func (sc *installScan) installSet(c scanCtx, set *pipSet) {
	locks := sc.ls.locks
	pinned := func(n string) bool {
		v, ok := set.pins[n]
		return ok && locks.versions[n][v]
	}
	for _, n := range set.installs {
		if !pinned(n) {
			sc.veto(c, "%s is not pinned to a locked version: it resolves outside the lockfile, so its transitive closure is not listed", n)
			return
		}
	}
	if !set.noDeps {
		seen := map[string]bool{}
		queue := append([]string(nil), set.installs...)
		for len(queue) > 0 {
			d := queue[0]
			queue = queue[1:]
			if seen[d] {
				continue
			}
			seen[d] = true
			if !pinned(d) {
				sc.veto(c, "%s, in the locked closure of what this install names, is not pinned in it: pip resolves it outside the lockfile", d)
				return
			}
			for ch := range locks.edges[d] {
				queue = append(queue, ch)
			}
		}
	}
	for _, n := range set.boot {
		sc.ls.markInstalled(n)
		for _, d := range bootstrapClosures[n] {
			sc.ls.markInstalled(d)
		}
	}
	for _, n := range set.installs {
		sc.ls.markInstalled(n)
	}
}

var artifactSuffixes = []string{".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".egg"}

// spec reads one requirement into set: an install target, or with constraint only a pin.
// Returns false when it vetoed.
func (sc *installScan) spec(c scanCtx, a string, set *pipSet, constraint bool) bool {
	a = strings.Trim(a, "()")
	if a == "" {
		return true
	}
	if strings.ContainsAny(a, "$`") {
		sc.veto(c, "requirement %s is a variable or substitution", a)
		return false
	}
	if strings.ContainsAny(a, "*?") {
		sc.veto(c, "requirement %s is a glob", a)
		return false
	}
	lower := strings.ToLower(a)
	artifact := false
	for _, s := range artifactSuffixes {
		artifact = artifact || strings.HasSuffix(lower, s)
	}
	if artifact || strings.HasPrefix(a, ".") || strings.HasPrefix(a, "~") || strings.ContainsAny(a, "/\\@") || strings.Contains(a, "://") {
		if constraint {
			return true
		}
		sc.veto(c, "%s installs a project, path, artifact, URL or VCS reference whose dependencies are not read", a)
		return false
	}
	name, version, resolved, extras := parseRequirementSpec(a)
	n := normalizePyCoordinate(name)
	if n == "" {
		sc.veto(c, "requirement %s is not parsed", a)
		return false
	}
	if resolved {
		set.pins[n] = version
	}
	if constraint {
		return true
	}
	if len(extras) > 0 {
		sc.veto(c, "%s requests extras whose dependencies the scanner does not read", a)
		return false
	}
	if _, ok := bootstrapClosures[n]; ok {
		set.boot = append(set.boot, n)
		return true
	}
	set.installs = append(set.installs, n)
	return true
}

// reqFile reads a requirement or constraint file an install names into set. Returns false
// when it vetoed.
func (sc *installScan) reqFile(c scanCtx, p string, set *pipSet, constraint bool) bool {
	rel, ok := sc.locate(c, p)
	if !ok {
		return false
	}
	key := rel
	if constraint {
		key = "c:" + rel
	}
	if sc.reqSeen[key] && set == nil {
		return true
	}
	sc.reqSeen[key] = true
	data, err := readRegular(filepath.Join(sc.root, filepath.FromSlash(rel)))
	if err != nil {
		sc.veto(c, "requirement file %s could not be read", rel)
		return false
	}
	if !containsString(sc.files, rel) {
		sc.files = append(sc.files, rel)
	}
	// A nested -r or -c resolves against the file's own directory.
	rc := scanCtx{file: rel, where: rel, prod: c.prod, st: newTextState(path.Dir(rel))}
	for _, line := range joinContinuations(string(data)) {
		t := strings.TrimSpace(stripReqComment(line))
		if t == "" {
			continue
		}
		if strings.ContainsAny(t, "$`") {
			sc.veto(rc, "%s is a variable or substitution", t)
			return false
		}
		if strings.HasPrefix(t, "-") {
			f := strings.Fields(t)
			opt, val, eq := strings.Cut(f[0], "=")
			if !strings.HasPrefix(opt, "--") && len(opt) > 2 {
				opt, val, eq = opt[:2], opt[2:], true
			}
			if !eq && len(f) > 1 {
				val = f[1]
			}
			switch {
			case opt == "-r" || opt == "--requirement" || opt == "-c" || opt == "--constraint":
				if val == "" {
					sc.veto(rc, "%s names no file", opt)
					return false
				}
				if !sc.reqFile(rc, val, set, constraint || opt == "-c" || opt == "--constraint") {
					return false
				}
			case opt == "-e" || opt == "--editable":
				if constraint {
					continue
				}
				sc.veto(rc, "%s installs a project whose dependencies are not read", opt)
				return false
			case reqFileOptions[opt]:
				if indexOptions[opt] && !sc.indexValue(rc, opt, val) {
					return false
				}
			default:
				sc.veto(rc, "option %s is not parsed", opt)
				return false
			}
			continue
		}
		if i := strings.IndexByte(t, ';'); i >= 0 {
			t = t[:i]
		}
		if i := strings.Index(t, "--hash"); i >= 0 {
			t = t[:i]
		}
		if !sc.spec(rc, strings.Join(strings.Fields(t), ""), set, constraint) {
			return false
		}
	}
	return true
}

// locate places a requirement file a command names in the repository: inside a Dockerfile
// through the image's working directory and copies, elsewhere against the command's base
// directories. It vetoes when the file is a URL, outside the repository, missing, or could be
// either of two files that differ.
func (sc *installScan) locate(c scanCtx, p string) (string, bool) {
	if strings.Contains(p, "://") {
		sc.veto(c, "requirement file %s is a URL", p)
		return "", false
	}
	st := c.st
	if st == nil {
		st = newTextState(path.Dir(c.file), ".")
	}
	if st.docker != nil {
		srcs, why := st.docker.locate(p)
		if why != "" {
			sc.veto(c, "requirement file %s %s", p, why)
			return "", false
		}
		return sc.pickRepoFile(c, p, srcs, []string{path.Dir(st.docker.df.rel), "."})
	}
	if path.IsAbs(p) || filepath.IsAbs(p) || strings.HasPrefix(p, "~") {
		sc.veto(c, "requirement file %s is not a repository path", p)
		return "", false
	}
	if st.unknown {
		sc.veto(c, "requirement file %s is read after a change of directory the scanner cannot follow", p)
		return "", false
	}
	return sc.pickRepoFile(c, p, []string{p}, st.bases)
}

// pickRepoFile resolves each source path against each base and returns the one existing
// regular file inside the repository; several that differ veto.
func (sc *installScan) pickRepoFile(c scanCtx, p string, srcs, bases []string) (string, bool) {
	var found []string
	var contents [][]byte
	for _, src := range srcs {
		for _, b := range bases {
			cand := path.Clean(path.Join(b, strings.TrimPrefix(src, "/")))
			if cand == ".." || strings.HasPrefix(cand, "../") || containsString(found, cand) {
				continue
			}
			abs := filepath.Join(sc.root, filepath.FromSlash(cand))
			info, err := os.Stat(abs)
			if err != nil || info.IsDir() || underSkipped(sc.root, mustEval(abs)) {
				continue
			}
			data, err := readRegular(abs)
			if err != nil {
				sc.veto(c, "requirement file %s could not be read", cand)
				return "", false
			}
			found = append(found, cand)
			contents = append(contents, data)
		}
	}
	switch {
	case len(found) == 0:
		sc.veto(c, "requirement file %s is not in the repository", p)
		return "", false
	case len(found) > 1:
		for _, d := range contents[1:] {
			if !bytes.Equal(d, contents[0]) {
				sc.veto(c, "requirement file %s could be %s or %s, which differ", p, found[0], found[1])
				return "", false
			}
		}
	}
	return found[0], true
}

func mustEval(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// syncFiles reads `uv pip sync` / `pip-sync`: every positional is a requirement file.
func (sc *installScan) syncFiles(c scanCtx, args []string) {
	sc.pipInstalls++
	set := &pipSet{pins: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if shellEnd(a) {
			break
		}
		if strings.ContainsAny(a, "$`") {
			sc.veto(c, "sync argument %s is a variable or substitution", a)
			return
		}
		if !strings.HasPrefix(a, "-") {
			if !sc.reqFile(c, a, set, false) {
				return
			}
			continue
		}
		opt, val, eq := strings.Cut(a, "=")
		switch {
		case pipInstallFlags[opt] && !eq:
		case opt == "-c" || opt == "--constraint":
			if !eq {
				if i+1 >= len(args) {
					sc.veto(c, "%s names no file", opt)
					return
				}
				i++
				val = args[i]
			}
			if !sc.reqFile(c, val, set, true) {
				return
			}
		case pipInstallValues[opt]:
			if !eq {
				i++
				if i < len(args) {
					val = args[i]
				}
			}
			if indexOptions[opt] && !sc.indexValue(c, opt, val) {
				return
			}
		default:
			sc.veto(c, "sync option %s is not parsed", opt)
			return
		}
	}
	sc.installSet(c, set)
}

// --- options -------------------------------------------------------------------------

// optSpec lists a command's options: flags take no value, values take one.
type optSpec struct{ flags, values map[string]bool }

// opts is a command's arguments as parsed: every option's values ("" for a flag), the
// positionals, and with stopAtCommand the arguments from the first positional on.
type opts struct {
	vals map[string][]string
	pos  []string
	rest []string
}

// indexOpts checks every index or find-links value o carries; see indexValue.
func (sc *installScan) indexOpts(c scanCtx, o opts) bool {
	names := make([]string, 0, len(o.vals))
	for n := range o.vals {
		if indexOptions[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		for _, v := range o.vals[n] {
			if !sc.indexValue(c, n, v) {
				return false
			}
		}
	}
	return true
}

func (o opts) has(names ...string) bool {
	for _, n := range names {
		if _, ok := o.vals[n]; ok {
			return true
		}
	}
	return false
}

// list returns the comma-split, PEP 503 normalized values of the named options, and the raw
// values that are not names (":all").
func (o opts) list(names ...string) (out, odd []string) {
	for _, n := range names {
		for _, v := range o.vals[n] {
			for _, p := range strings.Split(v, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if !groupNameRe.MatchString(p) {
					odd = append(odd, p)
					continue
				}
				out = append(out, normalizePyCoordinate(p))
			}
		}
	}
	return out, odd
}

var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// parseOpts parses args against spec: --opt=value, --opt value, -Xvalue, -X value and flag
// clusters (-qv). It returns the first option it cannot parse, or a variable, as bad.
func parseOpts(args []string, spec optSpec, stopAtCommand bool) (o opts, bad string) {
	o.vals = map[string][]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if shellEnd(a) {
			break
		}
		if strings.ContainsAny(a, "$`") {
			return o, a
		}
		if a == "--" {
			if stopAtCommand {
				o.rest = args[i+1:]
				return o, ""
			}
			o.pos = append(o.pos, args[i+1:]...)
			return o, ""
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			if stopAtCommand {
				o.rest = args[i:]
				return o, ""
			}
			o.pos = append(o.pos, a)
			continue
		}
		if strings.HasPrefix(a, "--") {
			name, val, eq := strings.Cut(a, "=")
			switch {
			case spec.flags[name] && !eq:
				o.vals[name] = append(o.vals[name], "")
			case spec.values[name]:
				if !eq {
					if i+1 >= len(args) || shellEnd(args[i+1]) {
						return o, a
					}
					i++
					val = args[i]
				}
				if strings.ContainsAny(val, "$`") {
					return o, a + " " + val
				}
				o.vals[name] = append(o.vals[name], val)
			default:
				return o, name
			}
			continue
		}
		short := a[:2]
		switch {
		case spec.values[short]:
			val := strings.TrimPrefix(a[2:], "=")
			if len(a) == 2 {
				if i+1 >= len(args) || shellEnd(args[i+1]) {
					return o, a
				}
				i++
				val = args[i]
			}
			if strings.ContainsAny(val, "$`") {
				return o, a + " " + val
			}
			o.vals[short] = append(o.vals[short], val)
		case spec.flags[a]:
			o.vals[a] = append(o.vals[a], "")
		default:
			for _, ch := range a[1:] {
				f := "-" + string(ch)
				if !spec.flags[f] {
					return o, a
				}
				o.vals[f] = append(o.vals[f], "")
			}
		}
	}
	return o, ""
}

func mergeSpec(specs ...optSpec) optSpec {
	out := optSpec{flags: map[string]bool{}, values: map[string]bool{}}
	for _, s := range specs {
		for k := range s.flags {
			out.flags[k] = true
		}
		for k := range s.values {
			out.values[k] = true
		}
	}
	return out
}

// --- other families ------------------------------------------------------------------

var (
	uvGlobalValues = setOf("--directory", "--project", "--config-file", "--cache-dir", "--color", "--python", "-p",
		"--allow-insecure-host", "--python-preference")
	uvCommon = optSpec{
		flags: setOf("--frozen", "--locked", "--no-dev", "--dev", "--only-dev", "--all-groups", "--no-default-groups",
			"--all-extras", "--no-install-project", "--no-install-workspace", "--no-install-local", "--no-editable",
			"--all-packages", "--compile-bytecode", "--no-progress", "--offline", "--refresh", "--no-cache", "-n", "-q",
			"--quiet", "-v", "--verbose", "--native-tls", "--no-build-isolation", "--no-build", "--no-binary",
			"--no-sources", "--upgrade", "-U", "--reinstall", "--no-config", "--no-python-downloads", "--managed-python",
			"--no-managed-python", "--preview", "--no-index", "--active", "--frozen-lockfile"),
		values: setOf("--extra", "--no-extra", "--group", "--no-group", "--only-group", "--package", "--python", "-p",
			"--directory", "--project", "--config-file", "--cache-dir", "--index-url", "--extra-index-url", "--index",
			"--default-index", "--find-links", "-f", "--link-mode", "--index-strategy", "--keyring-provider", "--resolution",
			"--prerelease", "--exclude-newer", "--python-platform", "--no-install-package", "--refresh-package",
			"--upgrade-package", "-P", "--reinstall-package", "--no-binary-package", "--no-build-package",
			"--no-build-isolation-package", "--config-setting", "-C", "--color", "--allow-insecure-host",
			"--python-preference"),
	}
	uvSync   = mergeSpec(uvCommon, optSpec{flags: setOf("--inexact", "--exact", "--dry-run", "--check")})
	uvExport = mergeSpec(uvCommon, optSpec{
		flags:  setOf("--no-hashes", "--no-header", "--no-annotate", "--no-emit-project", "--no-emit-workspace", "--no-emit-local"),
		values: setOf("--format", "-o", "--output-file", "--no-emit-package", "--prune"),
	})
	uvRun = mergeSpec(uvCommon, optSpec{
		flags:  setOf("--isolated", "--no-sync", "-m", "--module", "-s", "--script", "--gui-script", "--no-project", "--no-env-file", "--exact"),
		values: setOf("--with", "--with-requirements", "--with-editable", "--env-file"),
	})
	poetryInstall = optSpec{
		flags: setOf("--only-root", "--no-root", "--sync", "--no-directory", "--dry-run", "--all-extras", "--all-groups",
			"--compile", "--no-interaction", "-n", "--no-ansi", "--ansi", "-q", "--quiet", "-v", "-vv", "-vvv", "--verbose",
			"--no-plugins", "--no-cache", "--no-dev", "--remove-untracked", "--without-hashes", "--without-urls",
			"--with-credentials", "--dev"),
		values: setOf("--without", "--with", "--only", "-E", "--extras", "-C", "--directory", "-P", "--project", "-f",
			"--format", "-o", "--output"),
	}
	pdmInstall = optSpec{
		flags: setOf("--prod", "--production", "-d", "--dev", "--no-default", "--dry-run", "--check", "--frozen-lockfile",
			"--no-editable", "--no-self", "--fail-fast", "-x", "--no-isolation", "-v", "-q", "--verbose", "--quiet",
			"--plugins", "--clean", "--only-keep", "--reinstall", "--without-hashes", "--self", "--editable-self",
			"--expandvars", "--no-markers"),
		values: setOf("-G", "--group", "-k", "--skip", "-p", "--project", "--venv", "--override", "-f", "--format", "-o", "--output"),
	}
	pipenvInstall = optSpec{
		flags: setOf("--dev", "-d", "--system", "--deploy", "--ignore-pipfile", "--clear", "--keep-outdated",
			"--selective-upgrade", "--site-packages", "--no-site-packages", "--verbose", "-v", "--quiet", "-q", "--pre"),
		values: setOf("--categories", "--pypi-mirror", "--python"),
	}
)

// familyHarmless are the subcommands of each family that install nothing.
var familyHarmless = map[string]map[string]bool{
	"uv": setOf("venv", "python", "cache", "self", "version", "help", "init", "build", "publish", "tree", "format",
		"generate-shell-completion", "auth", "--version", "--help", "-h"),
	"pipx": setOf("list", "uninstall", "uninstall-all", "ensurepath", "environment", "completions", "upgrade-all",
		"reinstall-all", "upgrade-shared", "--version", "--help", "-h"),
	"poetry": setOf("build", "check", "config", "env", "new", "init", "publish", "search", "show", "source", "version",
		"about", "list", "help", "debug", "cache", "shell", "completions", "--version", "--help", "-h", "-V"),
	"pdm": setOf("build", "config", "info", "init", "list", "outdated", "publish", "search", "show", "use", "venv",
		"cache", "completion", "fix", "help", "--version", "--help", "-h", "-V", "python", "py"),
	"pipenv": setOf("requirements", "graph", "check", "clean", "shell", "--venv", "--where", "--py", "scripts", "verify",
		"open", "uninstall", "--version", "--help", "-h", "--rm", "--envs", "--support"),
	"conda": setOf("activate", "deactivate", "info", "list", "clean", "config", "init", "search", "remove", "uninstall",
		"shell", "--version", "--help", "-h", "-V", "package", "export"),
}

// family reads one uv/uvx/pipx/poetry/pdm/pipenv/conda command.
func (sc *installScan) family(c scanCtx, w string, rest []string) {
	if w == "uvx" {
		sc.toolSpecs(c, "uvx", rest)
		return
	}
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i], "-") && !shellEnd(rest[i]) {
		opt, _, eq := strings.Cut(rest[i], "=")
		if familyHarmless[familyKey(w)][opt] {
			return
		}
		i++
		if w == "uv" && uvGlobalValues[opt] && !eq {
			i++
		}
	}
	if i >= len(rest) || shellEnd(rest[i]) {
		return
	}
	sub, args := rest[i], rest[i+1:]
	if familyHarmless[familyKey(w)][sub] {
		return
	}
	switch w {
	case "uv":
		sc.uv(c, sub, args)
	case "pipx":
		switch sub {
		case "install", "upgrade", "reinstall", "run", "inject":
			sc.toolSpecs(c, "pipx "+sub, args)
		default:
			sc.veto(c, "pipx %s is not parsed", sub)
		}
	case "poetry":
		switch sub {
		case "install", "sync", "export":
			sc.poetryKeep(c, "poetry "+sub, args)
		case "lock":
			if o, bad := parseOpts(args, optSpec{flags: setOf("--check", "--no-update", "-n", "--no-interaction", "-q", "--quiet")}, false); bad == "" && o.has("--check") {
				return
			}
			sc.veto(c, "poetry lock regenerates the lockfile the scanner reads")
		case "run":
			sc.command(c, args)
		default:
			sc.veto(c, "poetry %s is not parsed", sub)
		}
	case "pdm":
		switch sub {
		case "install", "sync", "export":
			sc.pdmKeep(c, "pdm "+sub, args)
		case "lock":
			if o, bad := parseOpts(args, optSpec{flags: setOf("--check", "-v", "-q")}, false); bad == "" && o.has("--check") {
				return
			}
			sc.veto(c, "pdm lock regenerates the lockfile the scanner reads")
		case "run":
			sc.command(c, args)
		default:
			sc.veto(c, "pdm %s is not parsed", sub)
		}
	case "pipenv":
		switch sub {
		case "install", "sync":
			sc.pipenvKeep(c, "pipenv "+sub, args)
		case "run":
			sc.command(c, args)
		default:
			sc.veto(c, "pipenv %s is not parsed", sub)
		}
	case "conda", "mamba", "micromamba":
		switch sub {
		case "run":
			sc.command(c, args)
		default:
			sc.veto(c, "%s %s is not parsed", w, sub)
		}
	}
}

func familyKey(w string) string {
	if w == "mamba" || w == "micromamba" {
		return "conda"
	}
	return w
}

func (sc *installScan) uv(c scanCtx, sub string, args []string) {
	switch sub {
	case "pip":
		if len(args) == 0 || shellEnd(args[0]) {
			return
		}
		switch args[0] {
		case "install":
			sc.pipInstall(c, args[1:])
		case "sync":
			sc.syncFiles(c, args[1:])
		case "compile", "freeze", "list", "show", "tree", "check", "uninstall":
		default:
			sc.veto(c, "uv pip %s is not parsed", args[0])
		}
	case "sync":
		o, bad := parseOpts(args, uvSync, false)
		if bad != "" || len(o.pos) > 0 {
			sc.veto(c, "uv sync option %s is not parsed", strings.TrimSpace(bad+" "+strings.Join(o.pos, " ")))
			return
		}
		if !sc.indexOpts(c, o) {
			return
		}
		sc.uvKeep(c, "uv sync", o)
	case "export":
		o, bad := parseOpts(args, uvExport, false)
		if bad != "" || len(o.pos) > 0 {
			sc.veto(c, "uv export option %s is not parsed", strings.TrimSpace(bad+" "+strings.Join(o.pos, " ")))
			return
		}
		if !sc.indexOpts(c, o) {
			return
		}
		sc.uvKeep(c, "uv export", o)
	case "run":
		o, bad := parseOpts(args, uvRun, true)
		if bad != "" {
			sc.veto(c, "uv run option %s is not parsed", bad)
			return
		}
		if o.has("--with", "--with-requirements", "--with-editable") {
			sc.veto(c, "uv run --with installs into an environment outside the lockfile")
			return
		}
		if !sc.indexOpts(c, o) {
			return
		}
		if !o.has("--no-sync") && !o.has("--no-project") && !o.has("--isolated") {
			sc.uvKeep(c, "uv run", o)
		}
		sc.command(c, o.rest)
	case "lock":
		if o, bad := parseOpts(args, mergeSpec(uvCommon, optSpec{flags: setOf("--check", "--check-exists", "--dry-run")}), false); bad == "" && o.has("--check", "--locked", "--check-exists") {
			return
		}
		sc.veto(c, "uv lock regenerates the lockfile the scanner reads")
	case "tool":
		if len(args) == 0 || shellEnd(args[0]) {
			return
		}
		switch args[0] {
		case "list", "dir", "update-shell", "uninstall", "--help", "-h":
		default:
			sc.toolSpecs(c, "uv tool "+args[0], args[1:])
		}
	default:
		sc.veto(c, "uv %s is not parsed", sub)
	}
}

// toolSpecs reads an isolated tool install (pipx, uvx, uv tool): the tool resolves outside
// the lockfile, so anything but a bootstrap installer vetoes.
func (sc *installScan) toolSpecs(c scanCtx, what string, args []string) {
	var specs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if shellEnd(a) {
			break
		}
		if strings.ContainsAny(a, "$`") {
			sc.veto(c, "%s argument %s is a variable or substitution", what, a)
			return
		}
		if !strings.HasPrefix(a, "-") {
			specs = append(specs, a)
			if what == "uvx" || what == "pipx run" || what == "uv tool run" {
				break
			}
			continue
		}
		opt, val, eq := strings.Cut(a, "=")
		switch opt {
		case "--from", "--with", "--spec", "--with-requirements", "--with-editable":
			if !eq && i+1 < len(args) {
				i++
				val = args[i]
			}
			if opt == "--with-requirements" || opt == "--with-editable" {
				sc.veto(c, "%s %s installs requirements into a tool environment outside the lockfile", what, opt)
				return
			}
			specs = append(specs, strings.Split(val, ",")...)
		case "--python", "-p", "--index-url", "-i", "--extra-index-url", "--suffix", "--pip-args", "--index", "--python-preference", "--directory":
			if !eq {
				i++
			}
		}
	}
	for _, s := range specs {
		name, _, _ := strings.Cut(s, "@")
		n, _, _, extras := parseRequirementSpec(name)
		if _, ok := bootstrapClosures[normalizePyCoordinate(n)]; ok && len(extras) == 0 {
			sc.ls.markInstalled(normalizePyCoordinate(n))
			continue
		}
		sc.veto(c, "%s installs %s into a tool environment: it resolves outside the lockfile, so its transitive closure is not listed", what, s)
		return
	}
}

// lockInstall records a production install from a lockfile; one with no lockfile of its
// format resolves afresh, which the lockfile's markers do not describe.
func (sc *installScan) lockInstall(c scanCtx, format, what string) {
	sc.lockInstalls++
	if len(sc.ls.locks.lockDirs[format]) == 0 {
		sc.veto(c, "%s runs with no %s lockfile: it resolves afresh", what, format)
	}
}

func (sc *installScan) keepKey(key string, c scanCtx) {
	if sc.keep[key] == "" {
		sc.keep[key] = c.where
	}
}

// uvKeep records the groups and extras a production `uv sync`/`export`/`run` keeps: the
// project's [tool.uv] default-groups (dev when unset), as --no-default-groups, --only-group,
// --only-dev, --group, --dev, --all-groups, --no-group and --no-dev change them, plus requested
// extras.
func (sc *installScan) uvKeep(c scanCtx, what string, o opts) {
	if odd := oddSelectors(o, "--group", "--only-group", "--extra"); odd != "" {
		sc.veto(c, "%s selects %s, a group or extra the scanner does not model", what, odd)
		return
	}
	if !c.prod {
		return
	}
	sc.lockInstall(c, "uv", what)
	locks := sc.ls.locks
	groups := sc.uvDefaultGroups()
	if o.has("--no-default-groups") {
		groups = map[string]bool{}
	}
	if only, _ := o.list("--only-group"); len(only) > 0 || o.has("--only-dev") {
		groups = setOf(only...)
		if o.has("--only-dev") {
			groups["dev"] = true
		}
	}
	add, _ := o.list("--group")
	for _, g := range add {
		groups[g] = true
	}
	if o.has("--dev") {
		groups["dev"] = true
	}
	if o.has("--all-groups") {
		for g := range locks.uvGroups {
			groups[g] = true
		}
	}
	drop, _ := o.list("--no-group")
	for _, g := range drop {
		delete(groups, g)
	}
	if o.has("--no-dev") {
		delete(groups, "dev")
	}
	for g := range groups {
		if g == "*" {
			sc.keepKey("uv:g:*", c)
		} else {
			sc.keepKey(uvGroupKey(g), c)
		}
	}
	extras, _ := o.list("--extra")
	for _, e := range extras {
		sc.keepKey(uvExtraKey(e), c)
	}
	if o.has("--all-extras") {
		noExtra, _ := o.list("--no-extra")
		drop := setOf(noExtra...)
		for e := range locks.uvExtras {
			if !drop[e] {
				sc.keepKey(uvExtraKey(e), c)
			}
		}
	}
}

// oddSelectors returns the first value of the named keep options that is not a plain group
// name (":all", a glob), or "".
func oddSelectors(o opts, names ...string) string {
	if _, odd := o.list(names...); len(odd) > 0 {
		return odd[0]
	}
	return ""
}

// uvDefaultGroups reads [tool.uv] default-groups beside each uv.lock: unset is dev, "all" is
// every group the lock records, and an unreadable pyproject is "*", which no flag removes.
func (sc *installScan) uvDefaultGroups() map[string]bool {
	out := map[string]bool{}
	for _, dir := range sc.ls.locks.lockDirs["uv"] {
		data, err := readRegular(filepath.Join(sc.root, filepath.FromSlash(dir), "pyproject.toml"))
		if os.IsNotExist(err) {
			out["dev"] = true
			continue
		}
		var pp struct {
			Tool struct {
				UV struct {
					DefaultGroups any `toml:"default-groups"`
				} `toml:"uv"`
			} `toml:"tool"`
		}
		if err != nil {
			out["*"] = true
			continue
		}
		if _, err := toml.Decode(string(data), &pp); err != nil {
			out["*"] = true
			continue
		}
		switch v := pp.Tool.UV.DefaultGroups.(type) {
		case nil:
			out["dev"] = true
		case string:
			if v != "all" {
				out["*"] = true
				continue
			}
			for g := range sc.ls.locks.uvGroups {
				out[g] = true
			}
		case []any:
			for _, g := range v {
				s, ok := g.(string)
				if !ok {
					out["*"] = true
					continue
				}
				out[normalizePyCoordinate(s)] = true
			}
		default:
			out["*"] = true
		}
	}
	return out
}

// poetryKeep records the groups a production `poetry install`/`sync`/`export` keeps: every
// non-optional group (a group the lock records and the pyproject does not declare optional),
// as --only, --only-root, --with, --all-groups, --without and --no-dev change them. Extras
// change nothing: poetry.lock records extras' dependencies in the main group, which is
// runtime.
func (sc *installScan) poetryKeep(c scanCtx, what string, args []string) {
	o, bad := parseOpts(args, poetryInstall, false)
	if bad != "" || len(o.pos) > 0 {
		sc.veto(c, "%s option %s is not parsed", what, strings.TrimSpace(bad+" "+strings.Join(o.pos, " ")))
		return
	}
	if odd := oddSelectors(o, "--with", "--only"); odd != "" {
		sc.veto(c, "%s selects %s, a group the scanner does not model", what, odd)
		return
	}
	if !c.prod {
		return
	}
	sc.lockInstall(c, "poetry", what)
	base, optional, ok := sc.poetryGroups()
	if !ok {
		sc.keepKey("poetry:*", c)
		return
	}
	groups := base
	if only, _ := o.list("--only"); len(only) > 0 {
		groups = setOf(only...)
	}
	if o.has("--only-root") {
		groups = map[string]bool{}
	}
	with, _ := o.list("--with")
	for _, g := range with {
		groups[g] = true
	}
	if o.has("--dev") {
		groups["dev"] = true
	}
	if o.has("--all-groups") {
		for g := range optional {
			groups[g] = true
		}
	}
	without, _ := o.list("--without")
	for _, g := range without {
		delete(groups, g)
	}
	if o.has("--no-dev") {
		delete(groups, "dev")
	}
	delete(groups, "main")
	for g := range groups {
		sc.keepKey("poetry:"+g, c)
	}
}

// poetryGroups returns the non-optional and optional poetry groups beside each poetry.lock;
// ok is false when a pyproject there cannot be read.
func (sc *installScan) poetryGroups() (base, optional map[string]bool, ok bool) {
	base, optional = map[string]bool{}, map[string]bool{}
	declared := map[string]bool{}
	for _, dir := range sc.ls.locks.lockDirs["poetry"] {
		data, err := readRegular(filepath.Join(sc.root, filepath.FromSlash(dir), "pyproject.toml"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, nil, false
		}
		var pp struct {
			Tool struct {
				Poetry struct {
					Group           map[string]struct{ Optional bool } `toml:"group"`
					DevDependencies map[string]any                     `toml:"dev-dependencies"`
				} `toml:"poetry"`
			} `toml:"tool"`
		}
		if _, err := toml.Decode(string(data), &pp); err != nil {
			return nil, nil, false
		}
		if len(pp.Tool.Poetry.DevDependencies) > 0 {
			base["dev"] = true
		}
		for g, cfg := range pp.Tool.Poetry.Group {
			n := normalizePyCoordinate(g)
			declared[n] = true
			if cfg.Optional {
				optional[n] = true
			} else {
				base[n] = true
			}
		}
	}
	for g := range sc.ls.locks.poetryGroups {
		if !declared[g] {
			base[g] = true
		}
	}
	return base, optional, true
}

// pdmKeep records the groups a production `pdm install`/`sync`/`export` keeps: every group
// unless --prod, then the default group plus each -G group. -G :all and any other selector
// that is not a group name veto.
func (sc *installScan) pdmKeep(c scanCtx, what string, args []string) {
	o, bad := parseOpts(args, pdmInstall, false)
	if bad != "" || len(o.pos) > 0 {
		sc.veto(c, "%s option %s is not parsed", what, strings.TrimSpace(bad+" "+strings.Join(o.pos, " ")))
		return
	}
	if odd := oddSelectors(o, "-G", "--group"); odd != "" {
		sc.veto(c, "%s selects %s, a group selector the scanner does not model", what, odd)
		return
	}
	if !c.prod {
		return
	}
	sc.lockInstall(c, "pdm", what)
	if !o.has("--prod", "--production") || o.has("-d", "--dev") {
		sc.keepKey("pdm:*", c)
		return
	}
	groups, _ := o.list("-G", "--group")
	for _, g := range groups {
		sc.keepKey("pdm:"+g, c)
	}
}

// pipenvKeep records a production `pipenv install`/`sync`: --dev or --categories keeps every
// category. Packages on the command line change the lockfile and veto.
func (sc *installScan) pipenvKeep(c scanCtx, what string, args []string) {
	o, bad := parseOpts(args, pipenvInstall, false)
	if bad != "" {
		sc.veto(c, "%s option %s is not parsed", what, bad)
		return
	}
	if len(o.pos) > 0 {
		sc.veto(c, "%s with packages changes dependencies the committed lockfile records", what)
		return
	}
	if !sc.indexOpts(c, o) {
		return
	}
	if !c.prod {
		return
	}
	sc.lockInstall(c, "pipenv", what)
	if o.has("--dev", "-d", "--categories") {
		sc.keepKey("pipfile:*", c)
	}
}

// keptByInstall reports whether a production install keeps dist: one of its group keys, or
// that key's wildcard, is kept. A distribution outside the runtime install that no group
// reaches is kept whenever any production lockfile install runs.
func (ls *loadSet) keptByInstall(dist string) bool {
	sc := ls.scan
	if sc == nil {
		return false
	}
	keys := ls.locks.groups[dist]
	if len(keys) == 0 {
		return !ls.locks.runtime[dist] && sc.lockInstalls > 0
	}
	if sc.keep["*"] != "" {
		return true
	}
	for k := range keys {
		if sc.keep[k] != "" {
			return true
		}
		for i := 0; i < len(k); i++ {
			if k[i] == ':' && sc.keep[k[:i+1]+"*"] != "" {
				return true
			}
		}
	}
	return false
}

// markInstalled marks dist and its lockfile closure installed at runtime.
func (ls *loadSet) markInstalled(dist string) {
	seen := map[string]bool{}
	queue := []string{dist}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d] {
			continue
		}
		seen[d] = true
		ls.reqRuntime[d] = true
		ls.installed[d] = true
		for c := range ls.locks.edges[d] {
			queue = append(queue, c)
		}
	}
}

// --- CI configuration ----------------------------------------------------------------

// deployName marks a workflow, job, stage or file name as a deploy.
var deployName = regexp.MustCompile(`(?i)deploy|release|publish|docker|\bcd\b|\bprod(uction)?\b|staging`)

// deployCommand marks a run step as a deploy.
var deployCommand = regexp.MustCompile(`(?i)\bdeploy|update-function-code|\bkubectl\b|\bhelm\b|\btwine\b|docker\s+push|\bgcloud\b|\baz\s+(webapp|functionapp|containerapp)|\bheroku\b|\bflyctl\b|\bfly\s+deploy|\brailway\s+up|\bserverless\b|\bsls\b|\bsam\s+deploy|\bzappa\b|\bterraform\s+apply|\bpulumi\s+up|\brsync\b|\bscp\b|\baws\s+s3\s+(cp|sync)`)

// testEnvironments are the `environment:` names that mark a test job, not a deploy step:
// exact, case-insensitive. Staging, preview and expression values count as deploys.
var testEnvironments = regexp.MustCompile(`(?i)^(test|testing|ci|dev|development)$`)

type workflowDefaults struct {
	Run struct {
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

type workflowFile struct {
	Name     string                 `yaml:"name"`
	On       yaml.Node              `yaml:"on"`
	Defaults workflowDefaults       `yaml:"defaults"`
	Jobs     map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Name        string           `yaml:"name"`
	Environment yaml.Node        `yaml:"environment"`
	Uses        string           `yaml:"uses"`
	Needs       yaml.Node        `yaml:"needs"`
	Defaults    workflowDefaults `yaml:"defaults"`
	Steps       []struct {
		Uses             string `yaml:"uses"`
		Run              string `yaml:"run"`
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"steps"`
}

type parsedWorkflow struct {
	rel  string
	wf   workflowFile
	prod map[string]bool // job → production
	all  bool            // every job is production
}

// scanWorkflows reads every GitHub workflow. A job is a production install when it is a
// deploy job, when a production job needs it (it builds what the deploy ships), or when its
// whole workflow is production: named for a deploy, reusable (on: workflow_call), called by a
// production job, or the workflow_run trigger of a production workflow. A job that calls a
// reusable workflow outside the repository vetoes.
func (sc *installScan) scanWorkflows(files []pendingWorkflow) {
	var all []*parsedWorkflow
	byFile := map[string]*parsedWorkflow{}
	byName := map[string][]*parsedWorkflow{}
	for _, f := range files {
		var wf workflowFile
		if err := yaml.Unmarshal(f.data, &wf); err != nil {
			sc.veto(scanCtx{file: f.rel, where: f.rel}, "could not be parsed")
			continue
		}
		p := &parsedWorkflow{rel: f.rel, wf: wf, prod: map[string]bool{}}
		p.all = deployName.MatchString(path.Base(f.rel)) || deployName.MatchString(wf.Name) || nodeHasKey(wf.On, "workflow_call")
		all = append(all, p)
		byFile[f.rel] = p
		if wf.Name != "" {
			byName[wf.Name] = append(byName[wf.Name], p)
		}
	}
	for changed := true; changed; {
		changed = false
		for _, p := range all {
			for id, job := range p.wf.Jobs {
				if !p.prod[id] && (p.all || deployJob(id, job)) {
					p.prod[id] = true
					changed = true
				}
			}
			for id, job := range p.wf.Jobs {
				if !p.prod[id] {
					continue
				}
				for _, need := range nodeStrings(job.Needs) {
					if _, ok := p.wf.Jobs[need]; ok && !p.prod[need] {
						p.prod[need] = true
						changed = true
					}
				}
				if callee, ok := byFile[strings.TrimPrefix(path.Clean(strings.SplitN(job.Uses, "@", 2)[0]), "./")]; ok && !callee.all {
					callee.all = true
					changed = true
				}
			}
			if len(p.prod) > 0 {
				for _, name := range workflowRunSources(p.wf.On) {
					for _, src := range byName[name] {
						if !src.all {
							src.all = true
							changed = true
						}
					}
				}
			}
		}
	}
	for _, p := range all {
		for _, id := range sortedMapKeys(p.wf.Jobs) {
			job := p.wf.Jobs[id]
			if job.Uses != "" && !strings.HasPrefix(job.Uses, "./") {
				sc.veto(scanCtx{file: p.rel, where: p.rel + " job " + id}, "calls %s, a reusable workflow outside the repository", job.Uses)
			}
			wd := job.Defaults.Run.WorkingDirectory
			if wd == "" {
				wd = p.wf.Defaults.Run.WorkingDirectory
			}
			for i, st := range job.Steps {
				if st.Run == "" {
					continue
				}
				dir := wd
				if st.WorkingDirectory != "" {
					dir = st.WorkingDirectory
				}
				ts := newTextState(".")
				if dir != "" {
					ts = workingDirState(dir)
				}
				sc.scanText(scanCtx{file: p.rel, where: fmt.Sprintf("%s job %s step %d", p.rel, id, i+1), prod: p.prod[id], st: ts}, st.Run)
			}
		}
	}
}

// workingDirState is the base for a step's working-directory: a literal relative path, or
// unknown.
func workingDirState(dir string) *textState {
	if strings.Contains(dir, "${{") || strings.ContainsAny(dir, "$`~") || path.IsAbs(dir) {
		return &textState{bases: []string{"."}, unknown: true}
	}
	return newTextState(path.Clean(dir))
}

// nodeHasKey reports whether an `on:` node names the event key: as a scalar, a list item or
// a mapping key.
func nodeHasKey(n yaml.Node, key string) bool {
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value == key
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Value == key {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return true
			}
		}
	}
	return false
}

// nodeStrings returns a scalar or a sequence of scalars.
func nodeStrings(n yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	}
	return nil
}

// workflowRunSources returns the workflow names an `on: workflow_run` trigger follows.
func workflowRunSources(on yaml.Node) []string {
	if on.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(on.Content); i += 2 {
		if on.Content[i].Value != "workflow_run" {
			continue
		}
		wr := on.Content[i+1]
		for j := 0; j+1 < len(wr.Content); j += 2 {
			if wr.Content[j].Value == "workflows" {
				return nodeStrings(*wr.Content[j+1])
			}
		}
	}
	return nil
}

// deployJob reports whether a job is a deploy step: it targets a non-test environment, builds
// and pushes an image, uses a deploy/publish action, is named for a deploy, or runs a deploy
// command.
func deployJob(id string, job workflowJob) bool {
	if env := workflowEnvironmentName(job.Environment); env != "" && !testEnvironments.MatchString(env) {
		return true
	}
	if deployName.MatchString(id) || deployName.MatchString(job.Name) {
		return true
	}
	for _, st := range job.Steps {
		action, _, _ := strings.Cut(strings.ToLower(st.Uses), "@")
		if strings.HasPrefix(action, "docker/build-push-action") || strings.Contains(action, "deploy") || strings.Contains(action, "publish") {
			return true
		}
		if deployCommand.MatchString(st.Run) {
			return true
		}
	}
	return false
}

// workflowEnvironmentName returns a job's environment name: the scalar, or the mapping's
// `name`. An expression stays as written, so it never matches a test name.
func workflowEnvironmentName(n yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		return strings.TrimSpace(n.Value)
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "name" {
				if v := strings.TrimSpace(n.Content[i+1].Value); v != "" {
					return v
				}
				return "<unnamed>"
			}
		}
		return "<unnamed>"
	}
	return ""
}

// scanAction reads a composite action's run steps as production installs: its callers are
// not known.
func (sc *installScan) scanAction(rel string, data []byte) {
	var a struct {
		Runs struct {
			Steps []struct {
				Run              string `yaml:"run"`
				WorkingDirectory string `yaml:"working-directory"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &a); err != nil {
		sc.veto(scanCtx{file: rel, where: rel}, "could not be parsed")
		return
	}
	for i, st := range a.Runs.Steps {
		ts := &textState{bases: []string{"."}, unknown: true} // the caller's working directory
		if st.WorkingDirectory != "" {
			ts = workingDirState(st.WorkingDirectory)
		}
		sc.scanText(scanCtx{file: rel, where: fmt.Sprintf("%s step %d", rel, i+1), prod: true, st: ts}, st.Run)
	}
}

// gitlabGlobals are .gitlab-ci.yml top-level keys that are not jobs.
var gitlabGlobals = setOf("stages", "variables", "workflow", "image", "services", "cache")

// scanGitLab reads .gitlab-ci.yml. When any job deploys (named or staged for a deploy, a
// non-test environment, or a deploy command), every job is a production install, since any
// may build what it ships; hidden template jobs and the global scripts always are. An include
// pulls configuration the scanner does not read: veto.
func (sc *installScan) scanGitLab(rel string, data []byte) {
	c := scanCtx{file: rel, where: rel, prod: true}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		sc.veto(c, "could not be parsed")
		return
	}
	if _, ok := doc["include"]; ok {
		sc.veto(c, "include: pulls CI configuration the scanner does not read")
		return
	}
	type gjob struct {
		key  string
		job  map[string]any
		prod bool
	}
	var jobs []gjob
	anyDeploy := false
	for _, key := range sortedMapKeys(doc) {
		if gitlabGlobals[key] {
			continue
		}
		v := doc[key]
		if key == "before_script" || key == "after_script" {
			sc.gitlabScripts(scanCtx{file: rel, where: rel + " " + key, prod: true}, v)
			continue
		}
		job, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if key == "default" {
			sc.gitlabScripts(scanCtx{file: rel, where: rel + " default", prod: true}, job["before_script"], job["after_script"])
			continue
		}
		if t, ok := job["trigger"]; ok {
			if m, ok := t.(map[string]any); ok && m["include"] != nil {
				sc.veto(c, "job %s triggers a child pipeline the scanner does not read", key)
				return
			}
		}
		stage, _ := job["stage"].(string)
		deploy := deployName.MatchString(key) || deployName.MatchString(stage)
		switch env := job["environment"].(type) {
		case string:
			deploy = deploy || (env != "" && !testEnvironments.MatchString(env))
		case map[string]any:
			name, _ := env["name"].(string)
			deploy = deploy || !testEnvironments.MatchString(name)
		}
		for _, s := range flattenStrings(job["script"]) {
			deploy = deploy || deployCommand.MatchString(s)
		}
		anyDeploy = anyDeploy || (deploy && !strings.HasPrefix(key, "."))
		jobs = append(jobs, gjob{key, job, deploy || strings.HasPrefix(key, ".")})
	}
	for _, j := range jobs {
		sc.gitlabScripts(scanCtx{file: rel, where: rel + " job " + j.key, prod: j.prod || anyDeploy}, j.job["before_script"], j.job["script"], j.job["after_script"])
	}
}

func (sc *installScan) gitlabScripts(c scanCtx, vs ...any) {
	for _, v := range vs {
		for _, s := range flattenStrings(v) {
			c.st = newTextState(".")
			sc.scanText(c, s)
		}
	}
}

// flattenStrings returns every string in a YAML scalar or (nested) sequence.
func flattenStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, flattenStrings(e)...)
		}
		return out
	}
	return nil
}

// --- committed install targets -------------------------------------------------------

// vendorDirs hold installed or vendored packages: a package or module directly under one is
// installed code. python/ is the AWS Lambda layer layout.
var vendorDirs = setOf("lib", "vendor", "_vendor", "vendored", "third_party", "site-packages", "dist-packages", "python")

// committedInstalls marks installed every distribution the repository itself carries, on the
// same walk as the install scan: a *.dist-info or *.egg-info anywhere, a committed wheel or
// egg, every top-level entry of a committed site-packages, and a package or module vendored
// under lib/, vendor/, python/ and the like.
func (ls *loadSet) committedInstalls(buildDir string) {
	for _, cand := range ls.buildTree(buildDir) {
		rel := relSlash(buildDir, cand.Path)
		switch cand.Why {
		case treeFile:
		case "symlink leaves the build dir":
			ls.noMarkers("%s: symlink that leaves the repository or does not resolve: installed copies behind it are unknown", rel)
		case "symlink to a non-regular file":
			ls.noMarkers("%s: symlink to a non-regular file: installed copies behind it are unknown", rel)
		case "symlinked directory the walk does not read":
			ls.noMarkers("%s: symlinked directory whose target the walk does not read: installed copies behind it are unknown", rel)
		default:
			if fi, err := os.Lstat(cand.Path); err != nil || fi.IsDir() {
				ls.noMarkers("%s: could not be read: installed copies under it are unknown", rel)
			} else if fi.Mode()&os.ModeSymlink != 0 {
				ls.noMarkers("%s: unreadable: installed copies behind it are unknown", rel)
			}
			// A regular file the walk could not open places nothing by name; the install scan
			// vetoes it.
		}
	}
	_ = buildtree.Walk(buildDir, func(e buildtree.Entry, err error) error {
		if err != nil {
			if e.D != nil && e.D.IsDir() && e.Path != buildDir {
				return filepath.SkipDir
			}
			return nil
		}
		if e.Path == buildDir || e.Symlink && e.Escapes {
			return nil
		}
		rel := relSlash(buildDir, e.Path)
		// A symlink inside the repository is read at its target too, but its own name still
		// places what it links: a dist-info, a wheel, or a package under a vendor directory.
		name, isDir := e.D.Name(), e.D.IsDir()
		if e.Symlink {
			fi, err := os.Stat(e.Path)
			if err != nil {
				return nil
			}
			if isDir = fi.IsDir(); !isDir && !fi.Mode().IsRegular() {
				return nil
			}
		}
		if e.Skipped {
			if name == "site-packages" {
				ls.committedSitePackages(e.Path, rel)
			}
			return nil
		}
		if strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info") {
			ls.committedDist(e.Path, name, isDir)
			if e.D.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !isDir && (strings.HasSuffix(name, ".whl") || strings.HasSuffix(name, ".egg")) {
			n, _, _ := strings.Cut(name, "-")
			ls.markInstalled(normalizePyCoordinate(n))
			return nil
		}
		if vendorDirs[filepath.Base(filepath.Dir(e.Path))] {
			ls.committedModule(e.Path, name, isDir)
		}
		return nil
	})
}

// committedSitePackages marks every top-level entry of a committed site-packages installed.
func (ls *loadSet) committedSitePackages(dir, rel string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		ls.noMarkers("%s: could not be read: installed copies under it are unknown", rel)
		return
	}
	for _, d := range entries {
		name := d.Name()
		p := filepath.Join(dir, name)
		if strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info") {
			ls.committedDist(p, name, d.IsDir())
			continue
		}
		if d.IsDir() {
			if dists, _ := ls.mapModule(name, mapStrict); len(dists) > 0 {
				for _, dist := range dists {
					ls.markInstalled(dist)
				}
			}
			continue
		}
		ls.committedModule(p, name, false)
	}
}

// committedModule marks the distributions a vendored package directory or module maps to.
func (ls *loadSet) committedModule(p, name string, dir bool) {
	mod := ""
	if dir {
		if _, err := os.Stat(filepath.Join(p, "__init__.py")); err == nil {
			mod = name
		}
	} else if strings.HasSuffix(name, ".py") && name != "__init__.py" {
		mod = strings.TrimSuffix(name, ".py")
	}
	if mod != "" {
		dists, _ := ls.mapModule(mod, mapStrict)
		for _, dist := range dists {
			ls.markInstalled(dist)
		}
	}
}

// committedDist marks the distribution an installed-metadata entry names: its METADATA or
// PKG-INFO Name, else the entry name up to the first '-'.
func (ls *loadSet) committedDist(p, name string, dir bool) {
	n := strings.TrimSuffix(strings.TrimSuffix(name, ".dist-info"), ".egg-info")
	n, _, _ = strings.Cut(n, "-")
	files := []string{p}
	if dir {
		files = []string{filepath.Join(p, "METADATA"), filepath.Join(p, "PKG-INFO")}
	}
	for _, f := range files {
		data, err := readRegular(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "Name:"); ok {
				ls.markInstalled(normalizePyCoordinate(v))
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}
	}
	ls.markInstalled(normalizePyCoordinate(n))
}
