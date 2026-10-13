package pythonanalysis

// Install commands in the repository's build, deploy and CI files. A class (i) refutation
// assumes the lockfile's dev/optional groups are not installed at runtime and that nothing
// installs a distribution outside the lockfile's own selection. The scanner checks both and
// fails closed:
//
//   - A production install that keeps a lockfile group blocks every distribution reached only
//     through that group. The kept set is what the install mode provably keeps: `uv sync
//     --no-dev` still keeps [tool.uv] default-groups other than dev, and `poetry install
//     --without dev` still keeps every other non-optional group.
//   - An install command that names a distribution blocks it and its lockfile closure, in any
//     file and any job. Requirement and constraint files an install reads (-r, -c) are read
//     the same way.
//   - Anything the scanner cannot positively parse vetoes every refutation: a variable or
//     substitution in a command or its arguments; installing the project, a path, a wheel or
//     sdist, a URL or a VCS reference; -e; a requirement file it cannot read, from a URL, or
//     outside the repository; a name the lockfile does not lock; an unknown option or pip
//     subcommand; `--no-deps` alongside another pip install; a lockfile install with no
//     lockfile of its format; a scanned file that does not parse or a directory the walk cannot
//     read; and every install family it
//     does not parse (conda, mamba, uv/poetry/pdm add, pipenv install <pkgs>, easy_install,
//     setup.py install).
//
// Scope: Dockerfile*, Containerfile*, *.dockerfile, Makefile/*.mk, Procfile, Jenkinsfile and
// shell scripts outside test directories; every GitHub workflow and composite action; GitLab
// CI; docker-compose/compose files; cloudbuild, render, fly, railway, heroku and app.yaml
// configs; Azure Pipelines, Travis, Bitbucket, CircleCI and Buildkite configs. Group keeps
// count only in production contexts: everything except GitHub and GitLab jobs that are not
// deploy jobs.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// installScan is what the build, deploy and CI files install.
type installScan struct {
	ls           *loadSet
	root         string
	files        []string          // install surfaces read, relative paths
	keep         map[string]string // group key → where a production install keeps it
	lockInstalls int               // production lockfile installs (uv sync, poetry install, ...)
	pipInstalls  int
	noDeps       string // where a pip install --no-deps ran
	reqSeen      map[string]bool
}

// scanCtx locates one command: the file it is in, a human location, and whether it is a
// production install.
type scanCtx struct {
	file, where string
	prod        bool
}

func (sc *installScan) veto(c scanCtx, format string, args ...any) {
	sc.ls.noMarkers("%s: %s", c.where, fmt.Sprintf(format, args...))
}

// scanInstalls reads every install surface under buildDir into ls.scan.
func (ls *loadSet) scanInstalls(buildDir string) {
	sc := &installScan{ls: ls, root: buildDir, keep: map[string]string{}, reqSeen: map[string]bool{}}
	ls.scan = sc
	unreadable := func(rel string) {
		sc.veto(scanCtx{where: rel}, "could not be read: install commands under it are unknown")
	}
	walkProjectTree(buildDir, func(rel, abs string) {
		if kind := installSurface(rel); kind != "" {
			sc.scanFile(rel, abs, kind)
		}
	}, unreadable)
	// walkProjectFiles skips hidden trees; CI configuration lives in some.
	for _, dir := range []string{".github", ".circleci", ".buildkite"} {
		top := filepath.Join(buildDir, dir)
		_ = filepath.WalkDir(top, func(p string, d os.DirEntry, err error) error {
			rel, rerr := filepath.Rel(buildDir, p)
			if rerr != nil {
				return nil //nolint:nilerr // outside the build dir.
			}
			rel = filepath.ToSlash(rel)
			if err != nil {
				if !(p == top && errors.Is(err, fs.ErrNotExist)) {
					unreadable(rel)
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if kind := hiddenInstallSurface(rel); kind != "" {
				sc.scanFile(rel, p, kind)
			}
			return nil
		})
	}
	sort.Strings(sc.files)
	if sc.noDeps != "" && sc.pipInstalls > 1 {
		ls.noMarkers("%s: pip install --no-deps alongside another pip install leaves the installed dependencies unknown", sc.noDeps)
	}
}

// installSurface classifies a file walkProjectFiles visits: "shell" (lines of commands),
// "yaml"/"toml"/"json" (must parse, then read as lines), "gitlab", or "".
func installSurface(rel string) string {
	base := strings.ToLower(path.Base(rel))
	ext := path.Ext(base)
	yml := ext == ".yml" || ext == ".yaml"
	switch {
	case strings.HasPrefix(base, "dockerfile"), strings.HasPrefix(base, "containerfile"), ext == ".dockerfile",
		base == "makefile", base == "gnumakefile", ext == ".mk", base == "procfile", strings.HasPrefix(base, "jenkinsfile"),
		ext == ".sh", ext == ".bash":
		return "shell"
	case base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml":
		return "gitlab"
	case yml && (strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose") ||
		strings.HasPrefix(base, "cloudbuild") || strings.HasPrefix(base, "azure-pipelines") ||
		base == "render.yaml" || base == "render.yml" || base == "app.yaml" || base == "app.yml" ||
		base == "heroku.yml" || base == ".travis.yml" || base == "bitbucket-pipelines.yml"):
		return "yaml"
	case base == "fly.toml", base == "railway.toml":
		return "toml"
	case base == "railway.json":
		return "json"
	}
	return ""
}

// hiddenInstallSurface classifies a file under .github, .circleci or .buildkite.
func hiddenInstallSurface(rel string) string {
	base := strings.ToLower(path.Base(rel))
	ext := path.Ext(base)
	yml := ext == ".yml" || ext == ".yaml"
	switch {
	case yml && path.Dir(rel) == ".github/workflows":
		return "workflow"
	case strings.HasPrefix(rel, ".github/") && (base == "action.yml" || base == "action.yaml"):
		return "action"
	case yml && (rel == ".circleci/config.yml" || strings.HasPrefix(rel, ".buildkite/")):
		return "yaml"
	case ext == ".sh", ext == ".bash":
		return "shell"
	}
	return ""
}

func (sc *installScan) scanFile(rel, abs, kind string) {
	c := scanCtx{file: rel, where: rel, prod: true}
	data, err := os.ReadFile(abs)
	if err != nil {
		sc.veto(c, "could not be read")
		return
	}
	sc.files = append(sc.files, rel)
	switch kind {
	case "yaml":
		var v any
		if err := yaml.Unmarshal(data, &v); err != nil {
			sc.veto(c, "could not be parsed")
			return
		}
	case "toml":
		var v map[string]any
		if _, err := toml.Decode(string(data), &v); err != nil {
			sc.veto(c, "could not be parsed")
			return
		}
	case "json":
		if !json.Valid(data) {
			sc.veto(c, "could not be parsed")
			return
		}
	case "workflow":
		sc.scanWorkflow(rel, data)
		return
	case "action":
		sc.scanAction(rel, data)
		return
	case "gitlab":
		sc.scanGitLab(rel, data)
		return
	}
	sc.scanText(c, string(data))
}

// scanText reads text as shell command lines: backslash continuations joined, comment lines
// skipped, each line split on && || ; |.
func (sc *installScan) scanText(c scanCtx, text string) {
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
		for _, seg := range splitShellCommands(line) {
			sc.command(lc, shellTokens(seg))
		}
	}
}

var shellSeparators = regexp.MustCompile(`&&|\|\||;|\|`)

func splitShellCommands(line string) []string { return shellSeparators.Split(line, -1) }

// execFormComma is the comma between two quoted words of an exec-form array.
var execFormComma = regexp.MustCompile(`(["'])\s*,\s*(["'])`)

// shellTokens splits a command into words, dropping quotes and JSON-array punctuation so the
// exec form `CMD ["uv", "run", "app"]` reads like the shell form. A comma inside an argument
// (`--without dev,docs`) is kept.
func shellTokens(seg string) []string {
	seg = execFormComma.ReplaceAllString(seg, "$1 $2")
	seg = strings.NewReplacer(`"`, " ", `'`, " ", "[", " [").Replace(seg)
	var out []string
	for _, f := range strings.Fields(seg) {
		if f == "[" || f == "]" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func hasFlag(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}

// flagValues returns the values of every --flag value or --flag=value pair.
func flagValues(args []string, flags ...string) []string {
	var out []string
	for i, a := range args {
		for _, flag := range flags {
			if a == flag && i+1 < len(args) {
				out = append(out, args[i+1])
			} else if v, ok := strings.CutPrefix(a, flag+"="); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

// listValues is flagValues with comma-separated lists split and names PEP 503 normalized.
func listValues(args []string, flags ...string) []string {
	var out []string
	for _, v := range flagValues(args, flags...) {
		for _, p := range strings.Split(v, ",") {
			if n := normalizePyCoordinate(p); n != "" {
				out = append(out, n)
			}
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
			sc.pip(c, rest)
			return
		case pythonRe.MatchString(w) && len(rest) >= 2 && rest[0] == "-m":
			mod := rest[1]
			if pipWordRe.MatchString(mod) {
				sc.pip(c, rest[2:])
				return
			}
			if familyWords[mod] {
				sc.family(c, mod, rest[2:])
				return
			}
		case w == "pip-sync":
			sc.syncFiles(c, rest)
			return
		case familyWords[w]:
			sc.family(c, w, rest)
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

// --- pip -----------------------------------------------------------------------------

var (
	pipGlobalFlags = setOf("-q", "--quiet", "-v", "--verbose", "--isolated", "--no-cache-dir", "--disable-pip-version-check",
		"--no-input", "--no-color", "--require-virtualenv", "--no-python-version-warning", "-V", "--version", "-h", "--help",
		"--user", "--break-system-packages")
	pipGlobalValues = setOf("--python", "--log", "--proxy", "--retries", "--timeout", "--exists-action", "--trusted-host",
		"--cert", "--client-cert", "--cache-dir", "--use-feature", "--use-deprecated", "--keyring-provider")
	pipOtherSubs = setOf("download", "wheel", "freeze", "list", "show", "uninstall", "config", "cache", "check", "inspect",
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
	case pipOtherSubs[sub]:
	default:
		sc.veto(c, "pip %s is not a subcommand the scanner parses", sub)
	}
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
	targets := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if shellEnd(a) {
			break
		}
		if !strings.HasPrefix(a, "-") {
			targets++
			if !sc.spec(c, a, true) {
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
			targets++
			if !sc.reqFile(c, v) {
				return
			}
		case opt == "-e" || opt == "--editable":
			sc.veto(c, "pip install %s installs a project whose dependencies are not read", opt)
			return
		case opt == "--no-deps":
			if sc.noDeps == "" {
				sc.noDeps = c.where
			}
		case pipInstallFlags[opt] && !eq:
		case pipInstallValues[opt]:
			if _, ok := next(); !ok {
				sc.veto(c, "pip install option %s has no value", opt)
				return
			}
		default:
			sc.veto(c, "pip install option %s is not parsed", opt)
			return
		}
	}
	if targets == 0 {
		sc.veto(c, "pip install with no requirement the scanner could read")
	}
}

var artifactSuffixes = []string{".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".egg"}

// spec reads one requirement an install names. strict (pip into the application's
// environment): a locked or bootstrap name is blocked with its lockfile closure; any other
// name has an unknown closure and the scan vetoes. Not strict (an isolated tool
// environment: pipx, uv tool, uvx): a locked name is blocked with its closure, an unlocked one
// adds nothing. Returns false when it vetoed.
func (sc *installScan) spec(c scanCtx, a string, strict bool) bool {
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
		sc.veto(c, "%s installs a project, path, artifact, URL or VCS reference whose dependencies are not read", a)
		return false
	}
	name, _, _, _ := parseRequirementSpec(a)
	n := normalizePyCoordinate(name)
	if n == "" {
		sc.veto(c, "requirement %s is not parsed", a)
		return false
	}
	locks := sc.ls.locks
	if cl, ok := bootstrapClosures[n]; ok {
		sc.ls.markInstalled(n)
		for _, d := range cl {
			sc.ls.markInstalled(d)
		}
		return true
	}
	if !strict {
		if locks.versions[n] != nil {
			sc.ls.markInstalled(n)
		}
		return true
	}
	if locks.versions[n] == nil {
		sc.veto(c, "%s is not locked: its dependencies are unknown", a)
		return false
	}
	sc.ls.markInstalled(n)
	return true
}

// reqFile reads a requirement or constraint file an install names: every line must be a name
// a locked name or a source option. Returns false when it vetoed.
func (sc *installScan) reqFile(c scanCtx, p string) bool {
	if strings.Contains(p, "://") {
		sc.veto(c, "requirement file %s is a URL", p)
		return false
	}
	if path.IsAbs(p) || filepath.IsAbs(p) || strings.HasPrefix(p, "~") {
		sc.veto(c, "requirement file %s is not a repository path", p)
		return false
	}
	var rel string
	for _, cand := range []string{path.Join(path.Dir(c.file), p), path.Clean(p)} {
		if cand == ".." || strings.HasPrefix(cand, "../") {
			continue
		}
		if info, err := os.Stat(filepath.Join(sc.root, filepath.FromSlash(cand))); err == nil && !info.IsDir() {
			rel = cand
			break
		}
	}
	if rel == "" {
		sc.veto(c, "requirement file %s is not in the repository", p)
		return false
	}
	if sc.reqSeen[rel] {
		return true
	}
	sc.reqSeen[rel] = true
	data, err := os.ReadFile(filepath.Join(sc.root, filepath.FromSlash(rel)))
	if err != nil {
		sc.veto(c, "requirement file %s could not be read", rel)
		return false
	}
	sc.files = append(sc.files, rel)
	rc := scanCtx{file: rel, where: rel, prod: c.prod}
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
				if val == "" || !sc.reqFile(rc, val) {
					if val == "" {
						sc.veto(rc, "%s names no file", opt)
					}
					return false
				}
			case opt == "-e" || opt == "--editable":
				sc.veto(rc, "%s installs a project whose dependencies are not read", opt)
				return false
			case reqFileOptions[opt]:
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
		if !sc.spec(rc, strings.Join(strings.Fields(t), ""), true) {
			return false
		}
	}
	return true
}

// syncFiles reads `uv pip sync` / `pip-sync`: every positional is a requirement file.
func (sc *installScan) syncFiles(c scanCtx, args []string) {
	sc.pipInstalls++
	for i := 0; i < len(args); i++ {
		a := args[i]
		if shellEnd(a) {
			return
		}
		if strings.ContainsAny(a, "$`") {
			sc.veto(c, "sync argument %s is a variable or substitution", a)
			return
		}
		if !strings.HasPrefix(a, "-") {
			if !sc.reqFile(c, a) {
				return
			}
			continue
		}
		opt, _, eq := strings.Cut(a, "=")
		switch {
		case pipInstallFlags[opt] && !eq:
		case opt == "-c" || opt == "--constraint":
			if !eq && i+1 < len(args) {
				i++
				if !sc.reqFile(c, args[i]) {
					return
				}
			}
		case pipInstallValues[opt]:
			if !eq {
				i++
			}
		default:
			sc.veto(c, "sync option %s is not parsed", opt)
			return
		}
	}
}

// --- other families ------------------------------------------------------------------

var uvGlobalValues = setOf("--directory", "--project", "--config-file", "--cache-dir", "--color", "--python", "-p",
	"--allow-insecure-host", "--python-preference")

// family reads one uv/uvx/pipx/poetry/pdm/pipenv/conda command.
func (sc *installScan) family(c scanCtx, w string, rest []string) {
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i], "-") {
		opt, _, eq := strings.Cut(rest[i], "=")
		i++
		if w == "uv" && uvGlobalValues[opt] && !eq {
			i++
		}
	}
	if w == "uvx" {
		sc.toolSpecs(c, rest, true)
		return
	}
	if i >= len(rest) || shellEnd(rest[i]) {
		return
	}
	sub, args := rest[i], rest[i+1:]
	switch w {
	case "uv":
		switch sub {
		case "pip":
			if len(args) == 0 {
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
		case "sync", "export":
			sc.uvKeep(c, "uv "+sub, args)
		case "run":
			for _, v := range flagValues(args, "--with") {
				for _, s := range strings.Split(v, ",") {
					if !sc.spec(c, s, true) {
						return
					}
				}
			}
			for _, v := range flagValues(args, "--with-requirements") {
				if !sc.reqFile(c, v) {
					return
				}
			}
			if hasFlag(args, "--with-editable") {
				sc.veto(c, "uv run --with-editable installs a project whose dependencies are not read")
				return
			}
			if !hasFlag(args, "--no-sync") {
				sc.uvKeep(c, "uv run", args)
			}
			sc.command(c, args)
		case "add":
			sc.veto(c, "uv add changes dependencies the committed lockfile records")
		case "tool":
			if len(args) > 0 && (args[0] == "install" || args[0] == "run" || args[0] == "upgrade") {
				sc.toolSpecs(c, args[1:], args[0] == "run")
			}
		}
	case "pipx":
		switch sub {
		case "install", "upgrade", "reinstall":
			sc.toolSpecs(c, args, false)
		case "run":
			sc.toolSpecs(c, args, true)
		case "inject":
			if pos := positionals(args); len(pos) > 1 {
				sc.toolSpecs(c, pos[1:], false)
			}
		case "install-all":
			sc.veto(c, "pipx install-all reads a spec file the scanner does not parse")
		}
	case "poetry":
		switch sub {
		case "install", "sync", "export":
			sc.poetryKeep(c, "poetry "+sub, args)
		case "add", "update":
			sc.veto(c, "poetry %s changes dependencies the committed lockfile records", sub)
		case "run":
			sc.command(c, args)
		}
	case "pdm":
		switch sub {
		case "install", "sync", "export":
			if c.prod {
				sc.lockInstall(c, "pdm", "pdm "+sub)
				if !hasFlag(args, "--prod", "--production", "-P") || hasFlag(args, "-d", "--dev") {
					sc.keepKey("pdm:*", c)
				} else {
					for _, g := range listValues(args, "-G", "--group") {
						if g == "all" {
							g = "*"
						}
						sc.keepKey("pdm:"+g, c)
					}
				}
			}
		case "add", "update":
			sc.veto(c, "pdm %s changes dependencies the committed lockfile records", sub)
		case "run":
			sc.command(c, args)
		}
	case "pipenv":
		switch sub {
		case "install", "sync":
			if sub == "install" && len(positionals(args)) > 0 {
				sc.veto(c, "pipenv install with packages changes dependencies the committed lockfile records")
				return
			}
			if c.prod {
				sc.lockInstall(c, "pipenv", "pipenv "+sub)
				if hasFlag(args, "--dev", "-d", "--categories") {
					sc.keepKey("pipfile:*", c)
				}
			}
		case "update", "upgrade":
			sc.veto(c, "pipenv %s changes dependencies the committed lockfile records", sub)
		case "run":
			sc.command(c, args)
		}
	case "conda", "mamba", "micromamba":
		switch sub {
		case "install", "create", "update", "upgrade", "env":
			sc.veto(c, "%s %s is not parsed", w, sub)
		case "run":
			sc.command(c, args)
		}
	}
}

// positionals are the arguments that are not options. Option values are not told apart, so a
// caller only uses this where that over-reads safely.
func positionals(args []string) []string {
	var out []string
	for _, a := range args {
		if shellEnd(a) {
			break
		}
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

var toolValues = setOf("--python", "-p", "--index-url", "-i", "--extra-index-url", "--suffix", "--pip-args", "--index",
	"--python-preference", "--directory")

// toolSpecs reads the specs an isolated tool install names: --from/--with/--spec values and
// positionals (only the first when it is the command to run).
func (sc *installScan) toolSpecs(c scanCtx, args []string, firstOnly bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if shellEnd(a) {
			return
		}
		if strings.ContainsAny(a, "$`") {
			sc.veto(c, "tool install argument %s is a variable or substitution", a)
			return
		}
		if !strings.HasPrefix(a, "-") {
			name, _, _ := strings.Cut(a, "@")
			if !sc.spec(c, name, false) {
				return
			}
			if firstOnly {
				return
			}
			continue
		}
		opt, val, eq := strings.Cut(a, "=")
		switch {
		case opt == "--from" || opt == "--with" || opt == "--spec":
			if !eq && i+1 < len(args) {
				i++
				val = args[i]
			}
			for _, s := range strings.Split(val, ",") {
				if !sc.spec(c, s, false) {
					return
				}
			}
		case opt == "--with-requirements":
			if !eq && i+1 < len(args) {
				i++
				val = args[i]
			}
			if !sc.reqFile(c, val) {
				return
			}
		case opt == "--with-editable":
			sc.veto(c, "--with-editable installs a project whose dependencies are not read")
			return
		case toolValues[opt] && !eq:
			i++
		}
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
func (sc *installScan) uvKeep(c scanCtx, what string, args []string) {
	if !c.prod {
		return
	}
	sc.lockInstall(c, "uv", what)
	locks := sc.ls.locks
	groups := sc.uvDefaultGroups()
	if hasFlag(args, "--no-default-groups") {
		groups = map[string]bool{}
	}
	if only := listValues(args, "--only-group"); len(only) > 0 || hasFlag(args, "--only-dev") {
		groups = setOf(only...)
		if hasFlag(args, "--only-dev") {
			groups["dev"] = true
		}
	}
	for _, g := range listValues(args, "--group") {
		groups[g] = true
	}
	if hasFlag(args, "--dev") {
		groups["dev"] = true
	}
	if hasFlag(args, "--all-groups") {
		for g := range locks.uvGroups {
			groups[g] = true
		}
	}
	for _, g := range listValues(args, "--no-group") {
		delete(groups, g)
	}
	if hasFlag(args, "--no-dev") {
		delete(groups, "dev")
	}
	for g := range groups {
		if g == "*" {
			sc.keepKey("uv:g:*", c)
		} else {
			sc.keepKey(uvGroupKey(g), c)
		}
	}
	for _, e := range listValues(args, "--extra") {
		sc.keepKey(uvExtraKey(e), c)
	}
	if hasFlag(args, "--all-extras") {
		drop := setOf(listValues(args, "--no-extra")...)
		for e := range locks.uvExtras {
			if !drop[e] {
				sc.keepKey(uvExtraKey(e), c)
			}
		}
	}
}

// uvDefaultGroups reads [tool.uv] default-groups beside each uv.lock: unset is dev, "all" is
// every group the lock records, and an unreadable pyproject is "*", which no flag removes.
func (sc *installScan) uvDefaultGroups() map[string]bool {
	out := map[string]bool{}
	for _, dir := range sc.ls.locks.lockDirs["uv"] {
		data, err := os.ReadFile(filepath.Join(sc.root, filepath.FromSlash(dir), "pyproject.toml"))
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
// as --only, --only-root, --with, --all-groups, --without and --no-dev change them.
func (sc *installScan) poetryKeep(c scanCtx, what string, args []string) {
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
	if only := listValues(args, "--only"); len(only) > 0 {
		groups = setOf(only...)
	}
	if hasFlag(args, "--only-root") {
		groups = map[string]bool{}
	}
	for _, g := range listValues(args, "--with") {
		groups[g] = true
	}
	if hasFlag(args, "--all-groups") {
		for g := range optional {
			groups[g] = true
		}
	}
	for _, g := range listValues(args, "--without") {
		delete(groups, g)
	}
	if hasFlag(args, "--no-dev") {
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
		data, err := os.ReadFile(filepath.Join(sc.root, filepath.FromSlash(dir), "pyproject.toml"))
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

type workflowFile struct {
	Name string                 `yaml:"name"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Name        string    `yaml:"name"`
	Environment yaml.Node `yaml:"environment"`
	Steps       []struct {
		Uses string `yaml:"uses"`
		Run  string `yaml:"run"`
	} `yaml:"steps"`
}

// scanWorkflow reads every job's run steps; a deploy job's are production installs.
func (sc *installScan) scanWorkflow(rel string, data []byte) {
	var wf workflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		sc.veto(scanCtx{file: rel, where: rel}, "could not be parsed")
		return
	}
	whole := deployName.MatchString(path.Base(rel)) || deployName.MatchString(wf.Name)
	for _, id := range sortedMapKeys(wf.Jobs) {
		job := wf.Jobs[id]
		prod := whole || deployJob(id, job)
		for i, st := range job.Steps {
			if st.Run != "" {
				sc.scanText(scanCtx{file: rel, where: fmt.Sprintf("%s job %s step %d", rel, id, i+1), prod: prod}, st.Run)
			}
		}
	}
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
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &a); err != nil {
		sc.veto(scanCtx{file: rel, where: rel}, "could not be parsed")
		return
	}
	for i, st := range a.Runs.Steps {
		sc.scanText(scanCtx{file: rel, where: fmt.Sprintf("%s step %d", rel, i+1), prod: true}, st.Run)
	}
}

// gitlabGlobals are .gitlab-ci.yml top-level keys that are not jobs.
var gitlabGlobals = setOf("stages", "variables", "workflow", "image", "services", "cache")

// scanGitLab reads .gitlab-ci.yml. A deploy job (named or staged for a deploy, a non-test
// environment, or a deploy command), a hidden template job and the global scripts are
// production installs. An include pulls configuration the scanner does not read: veto.
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
		prod := strings.HasPrefix(key, ".") || deployName.MatchString(key) || deployName.MatchString(stage)
		switch env := job["environment"].(type) {
		case string:
			prod = prod || (env != "" && !testEnvironments.MatchString(env))
		case map[string]any:
			name, _ := env["name"].(string)
			prod = prod || !testEnvironments.MatchString(name)
		}
		for _, s := range flattenStrings(job["script"]) {
			prod = prod || deployCommand.MatchString(s)
		}
		sc.gitlabScripts(scanCtx{file: rel, where: rel + " job " + key, prod: prod}, job["before_script"], job["script"], job["after_script"])
	}
}

func (sc *installScan) gitlabScripts(c scanCtx, vs ...any) {
	for _, v := range vs {
		for _, s := range flattenStrings(v) {
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

// committedSkip are directories whose installed metadata is not part of the deployed tree:
// VCS and virtualenv internals, caches, and test fixtures.
var committedSkip = setOf(".git", "node_modules", ".venv", "venv", ".tox", ".nox", "__pycache__", ".mypy_cache",
	".pytest_cache", ".ruff_cache", "test", "tests", "testing", "testdata", "fixtures")

// vendorDirs hold installed or vendored packages: a package or module directly under one is
// installed code.
var vendorDirs = setOf("lib", "vendor", "_vendor", "vendored", "third_party", "site-packages", "dist-packages")

// committedInstalls marks installed every distribution the repository itself carries: a
// *.dist-info or *.egg-info anywhere outside skipped trees (site-packages, build output and
// hidden trees included), and a package or module vendored under lib/, vendor/, site-packages/
// and the like.
func (ls *loadSet) committedInstalls(buildDir string) {
	_ = filepath.WalkDir(buildDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if rel, rerr := filepath.Rel(buildDir, p); rerr == nil {
				ls.noMarkers("%s: could not be read: installed copies under it are unknown", filepath.ToSlash(rel))
			}
			return nil
		}
		if p == buildDir {
			return nil
		}
		name := d.Name()
		if d.IsDir() && committedSkip[name] {
			return filepath.SkipDir
		}
		if strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info") {
			ls.committedDist(p, name, d.IsDir())
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !vendorDirs[filepath.Base(filepath.Dir(p))] {
			return nil
		}
		mod := ""
		if d.IsDir() {
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
		return nil
	})
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
		data, err := os.ReadFile(f)
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
