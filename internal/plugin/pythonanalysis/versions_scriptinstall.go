package pythonanalysis

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// --- script installs: Python forms --------------------------------------------------
//
// A build can install a Python package with a command in a Dockerfile, a shell script, a
// Makefile, a CI or platform file or a package.json script, at a version no manifest read here
// records. Version resolution therefore withholds every pin (Resolved=false for the whole
// build, since a named install also pulls its own dependencies) when a script surface runs a
// Python installer in any form other than the few that install exactly what a manifest or lock
// read here says:
//
//	pip install -r <file>          <file> a literal path, from the command's directory, to a
//	                               requirements file read here; pip may be pipN, pipN.M or
//	                               pythonN.M -m pip, and -r may repeat
//	uv sync --locked | --frozen    --locked refuses a lock pyproject.toml has moved past;
//	                               --frozen installs the lock as written
//	poetry install                 refuses a lock pyproject.toml has moved past
//	pdm sync                       installs the lock as written
//	pipenv install --deploy        refuses a Pipfile.lock the Pipfile has moved past
//	pipenv sync                    installs Pipfile.lock as written
//	poetry|pdm|pipenv run <argv>   run without syncing; <argv> passes the same gate, and pdm
//	                               and pipenv run only where no script table can name <argv>
//
// with only --no-cache-dir, --user and -q added, and with the manifest each binds to (the
// nearest pyproject.toml or Pipfile at or above the command's directory) and the lock it
// installs (the nearest at or above that) read here. Anything
// else that names an installer withholds: a package argument, another flag, pipx, uvx, uv run
// (it syncs), a bare uv sync or pdm install (both re-lock), conda, mamba, easy_install. A
// PIP_* or UV_* variable set in any script surface withholds, since every pip or uv the build
// runs reads it. How a surface is read, and what binds a command to a file, is lane-neutral
// and below.

// laneEnvRE matches a PIP_* or UV_* name that is not a $, ${ or attribute reference, so is
// being set.
var laneEnvRE = regexp.MustCompile(`(?:^|[^$A-Za-z0-9_{.])(?:PIP|UV)_[A-Z0-9_]+`)

// laneToken reports whether word is a Python installer: uv, uvx, poetry, pdm, easy_install,
// mamba, micromamba, and any word starting pip or conda.
func laneToken(word string) bool {
	switch word {
	case "uv", "uvx", "poetry", "pdm", "easy_install", "mamba", "micromamba":
		return true
	}
	return strings.HasPrefix(word, "pip") || strings.HasPrefix(word, "conda")
}

var (
	pipHeadRE    = regexp.MustCompile(`^pip(?:\d+(?:\.\d+)?)?$`)
	pythonHeadRE = regexp.MustCompile(`^python(?:\d+(?:\.\d+)?)?$`)
)

// laneFlags are the flags every allowed form may carry.
var laneFlags = map[string]bool{"--no-cache-dir": true, "--user": true, "-q": true}

// laneRunWrapper returns the command a run wrapper runs, and whether words is one.
func laneRunWrapper(words []string) ([]string, bool) {
	if len(words) < 2 || words[1] != "run" {
		return nil, false
	}
	switch head, _ := scriptCommandName(words[0]); head {
	case "poetry", "pdm", "pipenv":
		return words[2:], true
	}
	return nil, false
}

// laneRunBinds reports whether a run wrapper's argv is the command it runs rather than a
// script a manifest names: pdm run and pipenv run look a name up in [tool.pdm.scripts] and a
// Pipfile's [scripts] first, and those values are not read here.
func laneRunBinds(words []string, b scriptBinder) bool {
	var name, table string
	switch head, _ := scriptCommandName(words[0]); head {
	case "pdm":
		name, table = "pyproject.toml", "[tool.pdm.scripts"
	case "pipenv":
		name, table = "Pipfile", "[scripts]"
	default:
		return true
	}
	for _, m := range b.nearest(name) {
		data, err := readRegular(m)
		if err != nil || strings.Contains(string(data), table) {
			return false
		}
	}
	return true
}

// laneAllowed reports whether a command holding an installer token, already free of
// expansions and redirects, is one of the allowed forms and binds to files read here.
func laneAllowed(words []string, b scriptBinder) bool {
	head, ok := scriptCommandName(words[0])
	if !ok {
		return false
	}
	switch {
	case pipHeadRE.MatchString(head):
		return pipRequirementsInstall(words[1:], b)
	case pythonHeadRE.MatchString(head) && len(words) >= 3 && words[1] == "-m" && pipHeadRE.MatchString(words[2]):
		return pipRequirementsInstall(words[3:], b)
	case len(words) < 2:
		return false
	case head == "uv" && words[1] == "sync":
		return scriptFlagsOnly(words[2:], laneFlags, "--locked", "--frozen") && b.nearest("pyproject.toml", "uv.lock") != nil
	case head == "poetry" && words[1] == "install":
		return scriptFlagsOnly(words[2:], laneFlags) && b.nearest("pyproject.toml", "poetry.lock") != nil
	case head == "pdm" && words[1] == "sync":
		return scriptFlagsOnly(words[2:], laneFlags) && b.nearest("pyproject.toml", "pdm.lock") != nil
	case head == "pipenv" && words[1] == "install":
		return scriptFlagsOnly(words[2:], laneFlags, "--deploy") && b.nearest("Pipfile", "Pipfile.lock") != nil
	case head == "pipenv" && words[1] == "sync":
		return scriptFlagsOnly(words[2:], laneFlags) && b.nearest("Pipfile", "Pipfile.lock") != nil
	}
	return false
}

// pipRequirementsInstall reports whether pip's arguments are install, the shared flags, and
// one or more -r naming a requirements file read here.
func pipRequirementsInstall(args []string, b scriptBinder) bool {
	if len(args) == 0 || args[0] != "install" {
		return false
	}
	reqs := 0
	for i := 1; i < len(args); i++ {
		var p string
		switch a := args[i]; {
		case laneFlags[a]:
			continue
		case (a == "-r" || a == "--requirement") && i+1 < len(args):
			p = args[i+1]
			i++
		case strings.HasPrefix(a, "--requirement="):
			p = strings.TrimPrefix(a, "--requirement=")
		default:
			return false
		}
		if name := filepath.Base(p); isManifest(name) && !isRequirementsName(name) || !b.file(p) {
			return false // a lock or build definition is not a requirements file
		}
		reqs++
	}
	return reqs > 0
}

// --- script installs: surfaces and binding ---------------------------------------------
//
// A script surface is a file whose lines a build runs as commands, recognised by name or by
// a shell shebang (scriptSurfaceOf). Each logical line, backslash continuations joined, is
// unwrapped by the surface's kind (a Dockerfile instruction, a Makefile recipe prefix, a YAML,
// TOML or Procfile key) and split into simple commands on unquoted &&, ||, ;, | and &. A
// package.json is read as JSON and every value under "scripts" is a command, whatever its key,
// so lifecycle scripts npm runs without being asked (preinstall, install, postinstall,
// prepare, prepublish, and pre<name> and post<name> of any script) pass the same gate as the
// rest; other decodable JSON surfaces gate every string value outside scriptDataKeys.
//
// A command that names an installer token anywhere in its words withholds unless it is an
// allowed form (laneAllowed), carries no $ or backtick and no redirect, and binds to a file
// read here. A line that names a token and does not tokenise withholds.
//
// Binding follows the directory a command runs in. On the host it starts at the surface's
// directory (shell scripts, Makefiles, Procfiles, package.json, tox.ini, noxfile.py) or the
// build root (CI and platform files, plus every literal in-tree working-directory the file
// names); a compose file's commands run in a container and bind nowhere. cd and pushd to a
// literal in-tree directory move it, and any other cd, pushd or popd loses it. A command binds
// a manifest as npm, pip, uv, poetry, pdm and pipenv find it: the nearest at or above the
// directory, which must lie inside the build root and be read here, and a lock-bound install
// binds the nearest of its locks at or above that manifest the same way. In a Dockerfile the
// directory is the stage's literal WORKDIR, and a container path binds only to a file COPY'd
// into it from the build context (the Dockerfile's directory, or the build root) earlier in
// the stage, with nothing since that could have changed it: a COPY --from, ADD, heredoc or
// unresolvable COPY over it, or any RUN command that is not itself an allowed form.
//
// Across the whole build, a command that is not an installer and names a bound file's base
// name among its arguments (sed -i, curl -o, mv, a redirect) could rewrite that file before
// the install reads it, so it withholds too (scriptVeto.rebound).

// Surface kinds, by how a line is unwrapped before it is read as a command.
const (
	scriptShell      = "shell"
	scriptDockerfile = "dockerfile"
	scriptMakefile   = "makefile"
	scriptData       = "data" // YAML, TOML, INI, JSON and Procfile lines: "key: command"
)

// Where a host surface's commands start.
const (
	scriptBaseDir  = "dir"
	scriptBaseRoot = "root"
	scriptBaseNone = "none"
)

type scriptSurface struct{ kind, base string }

// scriptDataNames are the lowercased names of CI, platform and tool files that carry commands
// as values, and where those commands start.
var scriptDataNames = map[string]string{
	".gitlab-ci.yml": scriptBaseRoot, "bitbucket-pipelines.yml": scriptBaseRoot, ".travis.yml": scriptBaseRoot,
	".drone.yml": scriptBaseRoot, "appveyor.yml": scriptBaseRoot, ".appveyor.yml": scriptBaseRoot,
	".woodpecker.yml": scriptBaseRoot, ".gitpod.yml": scriptBaseRoot, "render.yaml": scriptBaseRoot,
	"netlify.toml": scriptBaseRoot, "nixpacks.toml": scriptBaseRoot, "vercel.json": scriptBaseRoot,
	"app.json": scriptBaseRoot, "devcontainer.json": scriptBaseRoot, ".devcontainer.json": scriptBaseRoot,
	"package.json": scriptBaseDir, "tox.ini": scriptBaseDir, "noxfile.py": scriptBaseDir,
}

// scriptSurfaceOf reports whether the file at path, with its buildtree.Head, is one whose
// lines a build runs as commands.
func scriptSurfaceOf(path string, head []byte) (scriptSurface, bool) {
	lower := strings.ToLower(filepath.Base(path))
	slash := "/" + strings.ToLower(filepath.ToSlash(path))
	ext := filepath.Ext(lower)
	yaml := ext == ".yml" || ext == ".yaml"
	switch {
	case lower == "dockerfile", lower == "containerfile", strings.HasPrefix(lower, "dockerfile."),
		strings.HasPrefix(lower, "containerfile."), ext == ".dockerfile", ext == ".containerfile":
		return scriptSurface{scriptDockerfile, scriptBaseNone}, true
	case lower == "makefile", lower == "gnumakefile", ext == ".mk", ext == ".mak", lower == "justfile", lower == ".justfile":
		return scriptSurface{scriptMakefile, scriptBaseDir}, true
	case ext == ".sh", ext == ".bash", ext == ".zsh", ext == ".ksh", ext == ".ash", ext == ".dash", scriptShebang(head):
		return scriptSurface{scriptShell, scriptBaseDir}, true
	case lower == "procfile", strings.HasPrefix(lower, "procfile."):
		return scriptSurface{scriptData, scriptBaseDir}, true
	case yaml && (strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose.")):
		return scriptSurface{scriptData, scriptBaseNone}, true
	case yaml && (strings.Contains(slash, "/.github/workflows/") || strings.Contains(slash, "/.circleci/") ||
		strings.Contains(slash, "/.woodpecker/") || strings.HasPrefix(lower, "azure-pipelines") ||
		strings.HasPrefix(lower, "buildspec") || strings.HasPrefix(lower, "cloudbuild.") ||
		strings.HasPrefix(lower, "taskfile.")),
		strings.Contains(slash, "/.github/actions/") && (lower == "action.yml" || lower == "action.yaml"),
		strings.HasPrefix(lower, "jenkinsfile"):
		return scriptSurface{scriptData, scriptBaseRoot}, true
	}
	if base, ok := scriptDataNames[lower]; ok {
		return scriptSurface{scriptData, base}, true
	}
	return scriptSurface{}, false
}

// scriptShebang reports whether head starts with a #! line naming a POSIX-family shell.
func scriptShebang(head []byte) bool {
	first, _, _ := strings.Cut(string(head), "\n")
	rest, ok := strings.CutPrefix(first, "#!")
	if !ok {
		return false
	}
	f := strings.Fields(rest)
	if len(f) > 0 && filepath.Base(f[0]) == "env" {
		f = f[1:]
		for len(f) > 0 && strings.HasPrefix(f[0], "-") {
			f = f[1:]
		}
	}
	if len(f) == 0 {
		return false
	}
	switch filepath.Base(f[0]) {
	case "sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "busybox":
		return true
	}
	return false
}

// scriptVeto applies the rule to the script surfaces buildtree.Candidates visits. read is the
// walk's own fullyRead: whether version resolution reads the file at a path.
type scriptVeto struct {
	root      string
	read      func(path string) bool
	vetoed    map[string]bool
	bound     map[string]bool // lowercased base names of files allowed commands bind to
	mentioned map[string]bool // lowercased base names other commands take as arguments
}

func newScriptVeto(root string, read func(string) bool) *scriptVeto {
	return &scriptVeto{root: filepath.Clean(root), read: read, vetoed: map[string]bool{},
		bound: map[string]bool{}, mentioned: map[string]bool{}}
}

// classify wraps a buildtree.Candidates classifier: a script surface the rule withholds on is
// a candidate fullyRead reports unread, and every other file is classified by match.
func (v *scriptVeto) classify(match func(path string, head []byte) (string, bool)) func(string, []byte) (string, bool) {
	return func(path string, head []byte) (string, bool) {
		if why, ok := v.surface(path, head); ok {
			v.vetoed[path] = true
			return why, true
		}
		return match(path, head)
	}
}

// fullyRead is the walk's fullyRead with every withheld script surface unread.
func (v *scriptVeto) fullyRead(path string) bool {
	return !v.vetoed[path] && v.read(path)
}

// rebound reports whether a command anywhere in the build names, as an argument, a file an
// allowed command binds to, so may rewrite it first. Call it after the walk.
func (v *scriptVeto) rebound() bool {
	for name := range v.bound {
		if v.mentioned[name] {
			return true
		}
	}
	return false
}

func (v *scriptVeto) bind(name string) { v.bound[strings.ToLower(filepath.Base(name))] = true }

// mention records the base names of a command's arguments, a redirect's or an option's
// target included.
func (v *scriptVeto) mention(args []string) {
	for _, a := range args {
		a = strings.TrimLeft(a, "0123456789<>&")
		if i := strings.LastIndexByte(a, '='); i >= 0 {
			a = a[i+1:]
		}
		if b := strings.ToLower(path.Base(filepath.ToSlash(a))); b != "" && b != "." && b != "/" {
			v.mentioned[b] = true
		}
	}
}

func (v *scriptVeto) inRoot(p string) bool {
	rel, err := filepath.Rel(v.root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// surface reports whether the file at path is a script surface the rule withholds on, and why.
func (v *scriptVeto) surface(path string, head []byte) (string, bool) {
	s, ok := scriptSurfaceOf(path, head)
	if !ok || head == nil {
		return "", false
	}
	src := string(head)
	if len(head) == buildtree.HeadSize {
		data, err := readRegular(path)
		if err != nil {
			return "script surface unreadable", true
		}
		src = string(data)
	}
	if laneEnvRE.MatchString(src) {
		return "script surface sets an installer variable", true
	}
	var why string
	switch {
	case s.kind == scriptDockerfile:
		why = v.dockerfile(path, src)
	case strings.EqualFold(filepath.Ext(path), ".json"):
		if units, ok := scriptJSONUnits(path, src); ok {
			why = v.host(s, scriptShell, path, units)
			break
		}
		why = v.host(s, scriptData, path, []scriptUnit{{text: src}})
	default:
		why = v.host(s, s.kind, path, []scriptUnit{{text: src}})
	}
	return why, why != ""
}

// scriptUnit is a run of shell text sharing a starting directory, or one exec-form command.
// bad marks a command value that is neither.
type scriptUnit struct {
	text string
	exec []string
	bad  bool
}

// scriptJSONUnits reads a decodable JSON surface's commands: a package.json's "scripts"
// values, or every string value of any other outside scriptDataKeys, an array of strings
// being one exec-form command.
func scriptJSONUnits(path, src string) ([]scriptUnit, bool) {
	var units []scriptUnit
	if strings.EqualFold(filepath.Base(path), "package.json") {
		var p struct {
			Scripts map[string]json.RawMessage `json:"scripts"`
		}
		if json.Unmarshal([]byte(src), &p) != nil {
			return nil, false
		}
		for _, k := range scriptSortedKeys(p.Scripts) {
			var s string
			if json.Unmarshal(p.Scripts[k], &s) != nil {
				units = append(units, scriptUnit{text: string(p.Scripts[k]), bad: true})
				continue
			}
			units = append(units, scriptUnit{text: s})
		}
		return units, true
	}
	var doc any
	if json.Unmarshal([]byte(src), &doc) != nil {
		return nil, false
	}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			units = append(units, scriptUnit{text: t})
		case []any:
			words := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					words = append(words, s)
				}
			}
			if len(words) == len(t) && len(t) > 0 {
				units = append(units, scriptUnit{exec: words})
				return
			}
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, k := range scriptSortedKeys(t) {
				if !scriptDataKeys[strings.ToLower(k)] {
					walk(t[k])
				}
			}
		}
	}
	walk(doc)
	return units, true
}

func scriptSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scriptCdRE finds a directory change in a line that does not tokenise.
var scriptCdRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])(?:cd|pushd|popd)(?:$|[^A-Za-z0-9_.-])`)

// host applies the rule to a host surface's units, each line split as kind.
func (v *scriptVeto) host(s scriptSurface, kind, path string, units []scriptUnit) string {
	var base []string
	unknown := s.base == scriptBaseNone
	switch s.base {
	case scriptBaseDir:
		base = []string{filepath.Dir(path)}
	case scriptBaseRoot:
		base = []string{v.root}
		dirs, ok := v.workingDirs(units)
		base, unknown = append(base, dirs...), !ok
	}
	for _, u := range units {
		carry := &scriptHostCursor{v: v, dirs: append([]string(nil), base...), unknown: unknown}
		if u.bad {
			if scriptHasToken(u.text) {
				return "install command that is not a string"
			}
			continue
		}
		if u.exec != nil {
			if why := v.command(scriptSegment{words: u.exec, expands: scriptExpands(u.exec)}, carry, 0); why != "" {
				return why
			}
			continue
		}
		lines, joined := scriptLines(u.text)
		if !joined && scriptHasToken(lines[len(lines)-1]) {
			return "install command in an unjoined continuation"
		}
		for _, line := range lines {
			cur := &scriptHostCursor{v: v, dirs: append([]string(nil), carry.dirs...), unknown: carry.unknown}
			segs, ok := scriptCommandSegments(kind, line)
			if !ok {
				if scriptHasToken(line) {
					return "install command that does not tokenise"
				}
				v.mention(strings.Fields(line))
				cur.unknown = cur.unknown || scriptCdRE.MatchString(line)
			}
			for _, seg := range segs {
				if why := v.command(seg, cur, 0); why != "" {
					return why
				}
			}
			// Shell text (a script, a package.json script value) keeps its directory from line
			// to line; a recipe line or a CI step may start back where the surface started.
			if kind == scriptShell {
				carry = cur
			} else {
				carry.merge(cur)
			}
		}
	}
	return ""
}

// scriptWorkingDirKeys are keys that set where a CI or platform file's commands run.
var scriptWorkingDirKeys = map[string]bool{
	"working-directory": true, "working_directory": true, "workdir": true, "rootdir": true,
	"root_dir": true, "base": true,
}

// workingDirs returns each literal in-tree directory a CI or platform file's commands may be
// told to run in, relative to the build root; ok is false when one is anything else.
func (v *scriptVeto) workingDirs(units []scriptUnit) ([]string, bool) {
	var dirs []string
	for _, u := range units {
		for _, line := range strings.Split(u.text, "\n") {
			s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
			m := scriptKeyRE.FindStringSubmatch(s)
			if m == nil || !scriptWorkingDirKeys[strings.ToLower(strings.Trim(m[1], `"'`))] {
				continue
			}
			val := strings.TrimSpace(s[len(m[0]):])
			if strings.HasPrefix(val, `"`) || strings.HasPrefix(val, "'") {
				q, ok := scriptQuotedValue(val)
				if !ok {
					return nil, false
				}
				val = q
			} else if i := strings.Index(val, " #"); i >= 0 {
				val = strings.TrimSpace(val[:i])
			}
			d := filepath.Join(v.root, val)
			if val == "" || filepath.IsAbs(val) || strings.ContainsAny(val, "$`{~*") || !v.inRoot(d) || !scriptIsDir(d) {
				return nil, false
			}
			dirs = append(dirs, d)
		}
	}
	return dirs, true
}

// maxRunDepth bounds how many run wrappers one command may nest.
const maxRunDepth = 4

// command applies the rule to one simple command run from cur, and returns why it withholds,
// or "" when it does not.
func (v *scriptVeto) command(seg scriptSegment, cur scriptCursor, depth int) string {
	words := seg.words
	if len(words) == 0 {
		return ""
	}
	switch words[0] {
	case "cd", "pushd", "popd":
		if seg.expands {
			cur.cd(nil)
		} else {
			cur.cd(words)
		}
		return ""
	}
	if !scriptSegmentHasToken(words) {
		v.mention(words[1:])
		cur.other()
		return ""
	}
	if seg.expands || scriptRedirects(words) {
		return "install command with an expansion or redirect: " + strings.Join(words, " ")
	}
	if argv, ok := laneRunWrapper(words); ok {
		if len(argv) == 0 || depth >= maxRunDepth || !laneRunBinds(words, cur) {
			return "install command: " + strings.Join(words, " ")
		}
		return v.command(scriptSegment{words: argv}, cur, depth+1)
	}
	if !laneAllowed(words, cur) {
		return "install command: " + strings.Join(words, " ")
	}
	return ""
}

func scriptRedirects(words []string) bool {
	for _, w := range words {
		if strings.ContainsAny(w, "<>") {
			return true
		}
	}
	return false
}

func scriptExpands(words []string) bool {
	for _, w := range words {
		if strings.ContainsAny(w, "$`") {
			return true
		}
	}
	return false
}

// scriptCommandName returns the program a command word runs: the word itself, or the base
// name of an absolute path. A relative path runs whatever file sits there, so names nothing.
func scriptCommandName(word string) (string, bool) {
	if !strings.Contains(word, "/") {
		return word, true
	}
	if path.IsAbs(word) {
		return path.Base(word), true
	}
	return "", false
}

// scriptFlagsOnly reports whether args are all flags from allowed or need, with at least one
// of need when need is given.
func scriptFlagsOnly(args []string, allowed map[string]bool, need ...string) bool {
	met := len(need) == 0
	for _, a := range args {
		isNeed := false
		for _, n := range need {
			isNeed = isNeed || a == n
		}
		if !allowed[a] && !isNeed {
			return false
		}
		met = met || isNeed
	}
	return met
}

// scriptWordRE splits text into the words installer tokens are matched against.
var scriptWordRE = regexp.MustCompile(`[A-Za-z0-9_.+-]+`)

func scriptHasToken(text string) bool {
	for _, w := range scriptWordRE.FindAllString(text, -1) {
		if laneToken(w) {
			return true
		}
	}
	return false
}

// scriptSegmentHasToken reports whether any word of a command, not only the program it runs,
// names an installer, so sudo, env, xargs and the like do not hide one.
func scriptSegmentHasToken(words []string) bool {
	for _, w := range words {
		if scriptHasToken(w) {
			return true
		}
	}
	return false
}

// --- binding ------------------------------------------------------------------------

// scriptBinder resolves the files a command reads from the directory it runs in.
type scriptBinder interface {
	// file reports whether p, from the command's directory, is a file read here and unchanged.
	file(p string) bool
	// nearest returns the nearest name at or above the command's directory, one per directory
	// the command may run in, each read here and unchanged; with locks given, the nearest of
	// them at or above each must be read here and unchanged too. nil when any is not.
	nearest(name string, locks ...string) []string
}

// scriptCursor is a binder that also follows directory changes and other commands.
type scriptCursor interface {
	scriptBinder
	cd(words []string) // nil when the target is not literal
	other()            // a command that runs no installer and may change files
}

// scriptHostCursor is the set of host directories a command may run in.
type scriptHostCursor struct {
	v       *scriptVeto
	dirs    []string
	unknown bool
}

func (c *scriptHostCursor) cd(words []string) {
	if c.unknown {
		return
	}
	if len(words) != 2 || words[0] == "popd" || words[1] == "-" || strings.HasPrefix(words[1], "~") || filepath.IsAbs(words[1]) {
		c.unknown = true
		return
	}
	for i, d := range c.dirs {
		n := filepath.Join(d, words[1])
		if !c.v.inRoot(n) || !scriptIsDir(n) {
			c.unknown = true
			return
		}
		c.dirs[i] = n
	}
}

func (c *scriptHostCursor) other() {}

func (c *scriptHostCursor) merge(o *scriptHostCursor) {
	c.unknown = c.unknown || o.unknown
	for _, d := range o.dirs {
		seen := false
		for _, e := range c.dirs {
			seen = seen || e == d
		}
		if !seen {
			c.dirs = append(c.dirs, d)
		}
	}
}

func (c *scriptHostCursor) file(p string) bool {
	if c.unknown || len(c.dirs) == 0 || p == "" || filepath.IsAbs(p) || strings.ContainsAny(p, "*?[~") {
		return false
	}
	for _, d := range c.dirs {
		full := filepath.Join(d, p)
		if !c.v.inRoot(full) || !c.v.read(full) {
			return false
		}
	}
	c.v.bind(p)
	return true
}

func (c *scriptHostCursor) nearest(name string, locks ...string) []string {
	if c.unknown || len(c.dirs) == 0 {
		return nil
	}
	var found []string
	for _, d := range c.dirs {
		hit := ""
		for dir := d; c.v.inRoot(dir); dir = filepath.Dir(dir) {
			f := filepath.Join(dir, name)
			regular, there, known := scriptStat(f)
			if !known || there && !regular {
				return nil // npm or pip would stop here, at a file this cannot read
			}
			if regular {
				hit = f
				break
			}
			if dir == c.v.root {
				break
			}
		}
		if hit == "" || !c.v.read(hit) || len(locks) > 0 && !c.lockAbove(filepath.Dir(hit), locks) {
			return nil
		}
		found = append(found, hit)
	}
	c.v.bind(name)
	for _, l := range locks {
		c.v.bind(l)
	}
	return found
}

// lockAbove reports whether the nearest of locks at or above dir, inside root, is read here.
func (c *scriptHostCursor) lockAbove(dir string, locks []string) bool {
	for ; c.v.inRoot(dir); dir = filepath.Dir(dir) {
		for _, l := range locks {
			f := filepath.Join(dir, l)
			switch regular, there, known := scriptStat(f); {
			case !known || there && !regular:
				return false
			case regular:
				return c.v.read(f)
			}
		}
		if dir == c.v.root {
			break
		}
	}
	return false
}

// scriptStat reports whether path, followed through symlinks, is a regular file and whether
// it is there at all. known is false when it is there but could not be examined, which never
// stands for its absence.
func scriptStat(p string) (regular, there, known bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return false, false, absent(err)
	}
	return fi.Mode().IsRegular(), true, true
}

// scriptGlob lists what a COPY source pattern matches. ok is false when the pattern has a
// meta character before its last element or its directory is there but could not be listed:
// filepath.Glob drops such errors, and a match it did not list may be copied anyway.
func scriptGlob(pattern string) (matches []string, ok bool) {
	dir, base := filepath.Split(pattern)
	if strings.ContainsAny(dir, "*?[\\") {
		return nil, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, absent(err)
	}
	for _, e := range entries {
		m, err := filepath.Match(base, e.Name())
		if err != nil {
			return nil, false
		}
		if m {
			matches = append(matches, filepath.Join(dir, e.Name()))
		}
	}
	return matches, true
}

func scriptIsDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// --- Dockerfiles --------------------------------------------------------------------

// scriptDockerEvent is one change to a stage's filesystem, by container path: a COPY from the
// build context (hosts, the host files or directories copied), or a taint at dst, under dst
// when dir, or everywhere when all.
type scriptDockerEvent struct {
	dst   string
	hosts []string
	dir   bool
	taint bool
	all   bool
}

type scriptDockerStage struct {
	events  []scriptDockerEvent
	wd      string
	wdKnown bool
}

const (
	scriptAbsent = iota
	scriptBound
	scriptTainted
)

// lookup returns the host files a container path holds, newest change first.
func (st *scriptDockerStage) lookup(f string) ([]string, int) {
	for i := len(st.events) - 1; i >= 0; i-- {
		e := st.events[i]
		if e.all {
			return nil, scriptTainted
		}
		under := e.dir && (e.dst == "/" || strings.HasPrefix(f, e.dst+"/"))
		if f != e.dst && !under {
			continue
		}
		if e.taint {
			return nil, scriptTainted
		}
		if !e.dir {
			return e.hosts, scriptBound
		}
		rel := filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(f, e.dst), "/"))
		var hs []string
		for _, h := range e.hosts {
			hf := filepath.Join(h, rel)
			switch regular, there, known := scriptStat(hf); {
			case !known || there && !regular && !scriptIsDir(hf):
				return nil, scriptTainted
			case regular:
				hs = append(hs, hf)
			}
		}
		if len(hs) > 0 {
			return hs, scriptBound
		}
	}
	return nil, scriptAbsent
}

func (st *scriptDockerStage) taintAll() { st.events = append(st.events, scriptDockerEvent{all: true}) }

// resolve returns a container path for p, from the WORKDIR when relative.
func (st *scriptDockerStage) resolve(p string) (string, bool) {
	switch {
	case p == "" || strings.ContainsAny(p, "$`"):
		return "", false
	case path.IsAbs(p):
		return path.Clean(p), true
	case st.wdKnown:
		return path.Join(st.wd, p), true
	}
	return "", false
}

// copyInstr records a COPY or ADD. Only a plain COPY of existing build-context paths maps
// files; anything else taints its destination, or everything when that is unknown.
func (st *scriptDockerStage) copyInstr(v *scriptVeto, ctxs []string, rest string, add bool) {
	var args []string
	if strings.HasPrefix(rest, "[") {
		if json.Unmarshal([]byte(rest), &args) != nil {
			st.taintAll()
			return
		}
	} else {
		args = strings.Fields(rest)
	}
	plain := !add
	var operands []string
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			switch name, _, _ := strings.Cut(a, "="); name {
			case "--chown", "--chmod", "--link":
			default:
				plain = false // --from, --parents, --exclude and the rest
			}
			continue
		}
		operands = append(operands, a)
	}
	if len(operands) < 2 {
		st.taintAll()
		return
	}
	dest, srcs := operands[len(operands)-1], operands[:len(operands)-1]
	destC, ok := st.resolve(dest)
	if !ok {
		st.taintAll()
		return
	}
	if !plain || scriptExpands(srcs) {
		st.events = append(st.events, scriptDockerEvent{dst: destC, dir: true, taint: true})
		return
	}
	// A file copied to a directory lands inside it: a dest written as one, or the WORKDIR,
	// which exists once set.
	destDir := strings.HasSuffix(dest, "/") || path.Base("/"+dest) == "." || len(srcs) > 1 || st.wdKnown && destC == st.wd
	var mapped []scriptDockerEvent
	add1 := func(e scriptDockerEvent) {
		for i := range mapped {
			if mapped[i].dst == e.dst && mapped[i].dir == e.dir {
				mapped[i].hosts = append(mapped[i].hosts, e.hosts...)
				return
			}
		}
		mapped = append(mapped, e)
	}
	// A source this cannot place (outside root, unexaminable, matching nothing) may have put
	// anything under the destination.
	unplaced := false
	for _, src := range srcs {
		rel := filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+src), "/"))
		glob := strings.ContainsAny(src, "*?[")
		placed := false
		for _, ctx := range ctxs {
			pattern := filepath.Join(ctx, rel)
			matches := []string{pattern}
			if glob {
				var ok bool
				if matches, ok = scriptGlob(pattern); !ok {
					unplaced = true
					continue
				}
			}
			for _, m := range matches {
				regular, there, known := scriptStat(m)
				switch {
				case !v.inRoot(m) || !known:
					unplaced = true
				case scriptIsDir(m):
					add1(scriptDockerEvent{dst: destC, hosts: []string{m}, dir: true})
					placed = true
				case regular:
					dst := destC
					if destDir || glob {
						dst = path.Join(destC, filepath.Base(m))
					}
					add1(scriptDockerEvent{dst: dst, hosts: []string{m}})
					placed = true
				case there:
					unplaced = true
				}
			}
		}
		unplaced = unplaced || !placed
	}
	if len(mapped) == 0 || unplaced {
		st.events = append(st.events, scriptDockerEvent{dst: destC, dir: true, taint: true})
		return
	}
	st.events = append(st.events, mapped...)
}

// scriptDockerCursor is the container directory a RUN, CMD or ENTRYPOINT command runs in.
type scriptDockerCursor struct {
	v     *scriptVeto
	st    *scriptDockerStage
	dir   string
	known bool
}

func (c *scriptDockerCursor) cd(words []string) {
	if !c.known {
		return
	}
	if len(words) != 2 || words[0] == "popd" || words[1] == "-" || strings.HasPrefix(words[1], "~") {
		c.known = false
		return
	}
	if path.IsAbs(words[1]) {
		c.dir = path.Clean(words[1])
	} else {
		c.dir = path.Join(c.dir, words[1])
	}
}

// other taints the whole stage: a command that is not an allowed install may write anywhere.
func (c *scriptDockerCursor) other() { c.st.taintAll() }

func (c *scriptDockerCursor) file(p string) bool {
	if !path.IsAbs(p) && !c.known || strings.ContainsAny(p, "*?[~") {
		return false
	}
	f := path.Clean(p)
	if !path.IsAbs(p) {
		f = path.Join(c.dir, p)
	}
	hosts, state := c.st.lookup(f)
	if state != scriptBound {
		return false
	}
	for _, h := range hosts {
		if !c.v.read(h) {
			return false
		}
	}
	c.v.bind(p)
	return true
}

func (c *scriptDockerCursor) nearest(name string, locks ...string) []string {
	if !c.known {
		return nil
	}
	for d := c.dir; ; d = path.Dir(d) {
		hosts, state := c.st.lookup(path.Join(d, name))
		switch state {
		case scriptTainted:
			return nil
		case scriptBound:
			for _, h := range hosts {
				if !c.v.read(h) {
					return nil
				}
			}
			if len(locks) > 0 && !c.lockAbove(d, locks) {
				return nil
			}
			c.v.bind(name)
			for _, l := range locks {
				c.v.bind(l)
			}
			return hosts
		}
		if d == "/" {
			return nil
		}
	}
}

// lockAbove reports whether the nearest of locks at or above the container directory dir was
// copied from the build context, read here, and is unchanged since.
func (c *scriptDockerCursor) lockAbove(dir string, locks []string) bool {
	for ; ; dir = path.Dir(dir) {
		for _, l := range locks {
			hosts, state := c.st.lookup(path.Join(dir, l))
			switch state {
			case scriptTainted:
				return false
			case scriptBound:
				for _, h := range hosts {
					if !c.v.read(h) {
						return false
					}
				}
				return true
			}
		}
		if dir == "/" {
			return false
		}
	}
}

var (
	scriptHeredocRE   = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)`)
	scriptDockerPlain = map[string]bool{
		"ENV": true, "ARG": true, "LABEL": true, "EXPOSE": true, "USER": true, "VOLUME": true,
		"STOPSIGNAL": true, "MAINTAINER": true, "SHELL": true,
	}
)

// dockerfile applies the rule to a Dockerfile, stage by stage. CMD and ENTRYPOINT run after
// every RUN, so they are checked against the stage as it ends.
func (v *scriptVeto) dockerfile(file, src string) string {
	ctxs := []string{filepath.Dir(file)}
	if ctxs[0] != v.root {
		ctxs = append(ctxs, v.root)
	}
	lines, joined := scriptLines(src)
	if !joined && scriptHasToken(lines[len(lines)-1]) {
		return "install command in an unjoined continuation"
	}
	names := map[string]bool{}
	st := &scriptDockerStage{}
	var deferred []scriptSegment
	flush := func() string {
		for _, seg := range deferred {
			cur := &scriptDockerCursor{v: v, st: st, dir: st.wd, known: st.wdKnown}
			if why := v.command(seg, cur, 0); why != "" {
				return why
			}
		}
		deferred = nil
		return ""
	}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' {
			continue
		}
		word, rest, _ := strings.Cut(line, " ")
		instr, rest := strings.ToUpper(word), strings.TrimSpace(rest)
		if hd := scriptHeredocRE.FindAllStringSubmatch(rest, -1); hd != nil && (instr == "RUN" || instr == "COPY" || instr == "ADD") {
			body := line
			for _, m := range hd {
				for i++; i < len(lines) && strings.TrimSpace(lines[i]) != m[1]; i++ {
					body += "\n" + lines[i]
				}
			}
			if scriptHasToken(body) {
				return "install command in a heredoc"
			}
			v.mention(strings.Fields(body))
			st.taintAll()
			continue
		}
		hasTok := scriptHasToken(rest)
		switch {
		case instr == "FROM":
			if why := flush(); why != "" {
				return why
			}
			st = &scriptDockerStage{}
			f := strings.Fields(rest)
			for len(f) > 0 && strings.HasPrefix(f[0], "--") {
				f = f[1:]
			}
			if len(f) > 0 && names[strings.ToLower(f[0])] {
				st.taintAll() // a stage built on an earlier one holds whatever that one wrote
			}
			if len(f) >= 3 && strings.EqualFold(f[1], "as") {
				names[strings.ToLower(f[2])] = true
			}
		case instr == "WORKDIR":
			p := strings.Trim(rest, `"`)
			if c, ok := st.resolve(p); ok {
				st.wd, st.wdKnown = c, true
			} else {
				st.wdKnown = false
			}
		case instr == "COPY" || instr == "ADD":
			st.copyInstr(v, ctxs, rest, instr == "ADD")
		case instr == "RUN" || instr == "CMD" || instr == "ENTRYPOINT":
			for instr == "RUN" && strings.HasPrefix(rest, "--") {
				_, rest, _ = strings.Cut(rest, " ")
				rest = strings.TrimSpace(rest)
			}
			var segs []scriptSegment
			ok := true
			if strings.HasPrefix(rest, "[") {
				segs, ok = scriptExecForm(rest)
			} else {
				segs, ok = scriptShellSegments(rest)
			}
			if !ok {
				if hasTok {
					return "install command that does not tokenise"
				}
				v.mention(strings.Fields(rest))
				if instr == "RUN" {
					st.taintAll()
				}
				continue
			}
			if instr != "RUN" {
				deferred = append(deferred, segs...)
				continue
			}
			cur := &scriptDockerCursor{v: v, st: st, dir: st.wd, known: st.wdKnown}
			for _, seg := range segs {
				if why := v.command(seg, cur, 0); why != "" {
					return why
				}
			}
		case scriptDockerPlain[instr]:
		default: // ONBUILD, HEALTHCHECK and anything unknown run elsewhere or not at all
			if hasTok {
				return "install command in " + instr
			}
		}
	}
	return flush()
}

// --- lines and words ----------------------------------------------------------------

// scriptLines splits src into logical lines, joining a line that ends in an odd run of
// backslashes to the next. joined is false when the last line still continues.
func scriptLines(src string) (lines []string, joined bool) {
	var cur strings.Builder
	for _, l := range strings.Split(src, "\n") {
		l = strings.TrimSuffix(l, "\r")
		if n := len(l) - len(strings.TrimRight(l, `\`)); n%2 == 1 {
			cur.WriteString(l[:len(l)-1])
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(l)
		lines = append(lines, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		return append(lines, cur.String()), false
	}
	return lines, true
}

// scriptSegment is one simple command: its words, unquoted, and whether its text holds a $ or
// a backtick anywhere.
type scriptSegment struct {
	words   []string
	expands bool
}

// scriptDataKeys are keys whose values a build never runs as a command.
var scriptDataKeys = map[string]bool{
	"name": true, "id": true, "cache": true, "description": true, "title": true, "if": true,
	"package-ecosystem": true, "package-manager": true, "packagemanager": true,
	"cache-dependency-path": true, "working-directory": true, "working_directory": true,
	"image": true, "shell": true, "version": true, "license": true, "author": true,
	"homepage": true, "repository": true, "url": true, "main": true, "module": true,
	"types": true, "key": true, "restore-keys": true, "path": true, "paths": true,
}

// scriptKeyRE matches a leading YAML, TOML, INI or Procfile key and its separator.
var scriptKeyRE = regexp.MustCompile(`^("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.\-/]+)\s*(?::|=)(?:\s+|$)`)

// scriptCommandSegments unwraps a logical line by its surface kind and splits the command it
// holds. ok is false when the line does not tokenise.
func scriptCommandSegments(kind, line string) ([]scriptSegment, bool) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "#") || kind == scriptData && strings.HasPrefix(s, "//") {
		return nil, true
	}
	switch kind {
	case scriptMakefile:
		s = strings.TrimSpace(strings.TrimLeft(s, "@-+"))
	case scriptData:
		s = strings.TrimSpace(strings.TrimPrefix(s, "- "))
		if m := scriptKeyRE.FindStringSubmatch(s); m != nil {
			if scriptDataKeys[strings.ToLower(strings.Trim(m[1], `"'`))] {
				return nil, true
			}
			s = strings.TrimSpace(s[len(m[0]):])
		}
		switch {
		case s == "", strings.HasPrefix(s, "|"), strings.HasPrefix(s, ">"):
			return nil, true
		case strings.HasPrefix(s, "{"):
			return nil, false
		case strings.HasPrefix(s, "["):
			return scriptExecForm(strings.TrimSuffix(s, ","))
		case strings.HasPrefix(s, `"`), strings.HasPrefix(s, "'"):
			val, ok := scriptQuotedValue(s)
			if !ok {
				return nil, false
			}
			s = val
		}
	}
	return scriptShellSegments(s)
}

// scriptExecForm reads a JSON array of strings (a Dockerfile exec form, a devcontainer
// command) as one command.
func scriptExecForm(s string) ([]scriptSegment, bool) {
	var words []string
	if json.Unmarshal([]byte(s), &words) != nil {
		return nil, false
	}
	return []scriptSegment{{words: words, expands: scriptExpands(words)}}, true
}

// scriptQuotedValue decodes a leading double-quoted (JSON) or single-quoted (YAML) value,
// which may be followed only by a comma, a closing bracket or a comment.
func scriptQuotedValue(s string) (string, bool) {
	var val, rest string
	if s[0] == '"' {
		end := -1
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 || json.Unmarshal([]byte(s[:end+1]), &val) != nil {
			return "", false
		}
		rest = s[end+1:]
	} else {
		var b strings.Builder
		i := 1
		for ; i < len(s); i++ {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				break
			}
			b.WriteByte(s[i])
		}
		if i >= len(s) {
			return "", false
		}
		val, rest = b.String(), s[i+1:]
	}
	rest = strings.TrimSpace(rest)
	if rest != "" && !strings.HasPrefix(rest, "#") && strings.Trim(rest, ",}] ") != "" {
		return "", false
	}
	return val, true
}

// scriptShellSegments splits shell text into simple commands on unquoted &&, ||, ;, | and &,
// and each into words with quotes removed. An unquoted # starting a word ends the text. ok is
// false for an unterminated quote, a trailing backslash, or an unquoted parenthesis or brace
// (a subshell, group or function body this does not follow).
func scriptShellSegments(s string) ([]scriptSegment, bool) {
	var (
		segs   []scriptSegment
		cur    scriptSegment
		word   strings.Builder
		inWord bool
	)
	endWord := func() {
		if inWord {
			cur.words = append(cur.words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endSeg := func() {
		endWord()
		if len(cur.words) > 0 {
			segs = append(segs, cur)
		}
		cur = scriptSegment{}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '$' || c == '`':
			cur.expands = true
			word.WriteByte(c)
			inWord = true
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, false
			}
			word.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				switch s[j] {
				case '\\':
					if j+1 < len(s) {
						j++
					}
				case '$', '`':
					cur.expands = true
				}
				word.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, false
			}
			i = j
			inWord = true
		case c == '\\':
			if i+1 >= len(s) {
				return nil, false
			}
			i++
			word.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t':
			endWord()
		case c == '#' && !inWord:
			endSeg()
			return segs, true
		case c == '(' || c == ')' || (c == '{' || c == '}') && !inWord:
			return nil, false
		case c == ';' || c == '&' || c == '|':
			endSeg()
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endSeg()
	return segs, true
}
