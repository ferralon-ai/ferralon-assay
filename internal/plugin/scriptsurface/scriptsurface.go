// Package scriptsurface finds the commands a build runs from its script surfaces, and withholds
// a lane's resolved versions when one of them could install a version no file the lane reads
// records.
//
// A script surface is a file whose lines a build runs as commands, recognised by name or by a
// shell shebang (surfaceOf). Each logical line, backslash continuations joined, is unwrapped by
// the surface's kind (a Dockerfile instruction, a Makefile recipe prefix, a YAML, TOML or
// Procfile key) and split into simple commands on unquoted &&, ||, ;, | and &. A package.json
// is read as JSON and every value under "scripts" is a command, whatever its key, so lifecycle
// scripts npm runs without being asked (preinstall, install, postinstall, prepare, prepublish,
// and pre<name> and post<name> of any script) pass the same gate as the rest; other decodable
// JSON surfaces gate every string value outside dataKeys.
//
// The package decides no installer itself. A lane passes a Spec: the words that name its
// installers, the variables they read, and the few command forms it allows, each binding the
// manifest and lock it installs. A command that names a token anywhere in its words withholds
// unless it carries no $ or backtick and no redirect and the lane's Allowed accepts it; a run
// wrapper the lane does not name, a surface that sets one of the lane's variables, and a line
// that names a token and does not tokenise withhold too. A Spec missing any decision withholds
// on every surface it recognises.
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
// the install reads it, so it withholds too (Veto.Rebound).
package scriptsurface

import (
	"encoding/json"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// Spec is what a lane decides. Every field but RunWrapper and RunBinds is required.
type Spec struct {
	// Token reports whether a word names one of the lane's installers or package runners.
	Token func(word string) bool
	// Env matches one of the lane's installer variables being set.
	Env *regexp.Regexp
	// Allowed reports whether a command naming a token, already free of expansions and
	// redirects, is one of the lane's allowed forms and binds, through b, to the manifest and
	// lock it installs. Every other command naming a token withholds.
	Allowed func(words []string, b Binder) bool
	// RunWrapper returns the command a run wrapper runs (poetry run <argv>), and whether words
	// is one. nil means the lane has none.
	RunWrapper func(words []string) (argv []string, ok bool)
	// RunBinds reports whether a run wrapper's argv is the command it runs, not a name it looks
	// up somewhere this does not read. nil withholds every run wrapper.
	RunBinds func(words []string, b Binder) bool
	// ReadRegular reads a whole regular file, and Absent reports whether a filesystem error
	// means a path is not there: the lane's own, so every file this reads is read the lane's way.
	ReadRegular func(path string) ([]byte, error)
	Absent      func(err error) bool
}

func (s Spec) complete() bool {
	return s.Token != nil && s.Env != nil && s.Allowed != nil && s.ReadRegular != nil && s.Absent != nil
}

// Surface kinds, by how a line is unwrapped before it is read as a command.
const (
	kindShell      = "shell"
	kindDockerfile = "dockerfile"
	kindMakefile   = "makefile"
	kindData       = "data" // YAML, TOML, INI, JSON and Procfile lines: "key: command"
)

// Where a host surface's commands start.
const (
	baseDir  = "dir"
	baseRoot = "root"
	baseNone = "none"
)

type surfaceType struct{ kind, base string }

// dataNames are the lowercased names of CI, platform and tool files that carry commands
// as values, and where those commands start.
var dataNames = map[string]string{
	".gitlab-ci.yml": baseRoot, "bitbucket-pipelines.yml": baseRoot, ".travis.yml": baseRoot,
	".drone.yml": baseRoot, "appveyor.yml": baseRoot, ".appveyor.yml": baseRoot,
	".woodpecker.yml": baseRoot, ".gitpod.yml": baseRoot, "render.yaml": baseRoot,
	"netlify.toml": baseRoot, "nixpacks.toml": baseRoot, "vercel.json": baseRoot,
	"app.json": baseRoot, "devcontainer.json": baseRoot, ".devcontainer.json": baseRoot,
	"package.json": baseDir, "tox.ini": baseDir, "noxfile.py": baseDir,
}

// surfaceOf reports whether the file at path, with its buildtree.Head, is one whose
// lines a build runs as commands.
func surfaceOf(path string, head []byte) (surfaceType, bool) {
	lower := strings.ToLower(filepath.Base(path))
	slash := "/" + strings.ToLower(filepath.ToSlash(path))
	ext := filepath.Ext(lower)
	yaml := ext == ".yml" || ext == ".yaml"
	switch {
	case lower == "dockerfile", lower == "containerfile", strings.HasPrefix(lower, "dockerfile."),
		strings.HasPrefix(lower, "containerfile."), ext == ".dockerfile", ext == ".containerfile":
		return surfaceType{kindDockerfile, baseNone}, true
	case lower == "makefile", lower == "gnumakefile", ext == ".mk", ext == ".mak", lower == "justfile", lower == ".justfile":
		return surfaceType{kindMakefile, baseDir}, true
	case ext == ".sh", ext == ".bash", ext == ".zsh", ext == ".ksh", ext == ".ash", ext == ".dash", shellShebang(head):
		return surfaceType{kindShell, baseDir}, true
	case lower == "procfile", strings.HasPrefix(lower, "procfile."):
		return surfaceType{kindData, baseDir}, true
	case yaml && (strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose.")):
		return surfaceType{kindData, baseNone}, true
	case yaml && (strings.Contains(slash, "/.github/workflows/") || strings.Contains(slash, "/.circleci/") ||
		strings.Contains(slash, "/.woodpecker/") || strings.HasPrefix(lower, "azure-pipelines") ||
		strings.HasPrefix(lower, "buildspec") || strings.HasPrefix(lower, "cloudbuild.") ||
		strings.HasPrefix(lower, "taskfile.")),
		strings.Contains(slash, "/.github/actions/") && (lower == "action.yml" || lower == "action.yaml"),
		strings.HasPrefix(lower, "jenkinsfile"):
		return surfaceType{kindData, baseRoot}, true
	}
	if base, ok := dataNames[lower]; ok {
		return surfaceType{kindData, base}, true
	}
	return surfaceType{}, false
}

// shellShebang reports whether head starts with a #! line naming a POSIX-family shell.
func shellShebang(head []byte) bool {
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

// Veto applies the rule to the script surfaces buildtree.Candidates visits.
type Veto struct {
	root      string
	read      func(path string) bool
	spec      Spec
	vetoed    map[string]bool
	bound     map[string]bool // lowercased base names of files allowed commands bind to
	mentioned map[string]bool // lowercased base names other commands take as arguments
}

// New returns a Veto for the build rooted at root. read is the lane walk's own fullyRead:
// whether version resolution reads the file at a path. spec decides the lane's installers.
func New(root string, read func(string) bool, spec Spec) *Veto {
	return &Veto{root: filepath.Clean(root), read: read, spec: spec, vetoed: map[string]bool{},
		bound: map[string]bool{}, mentioned: map[string]bool{}}
}

// Classify wraps a buildtree.Candidates classifier: a script surface the rule withholds on is
// a candidate FullyRead reports unread, and every other file is classified by match.
func (v *Veto) Classify(match func(path string, head []byte) (string, bool)) func(string, []byte) (string, bool) {
	return func(path string, head []byte) (string, bool) {
		if why, ok := v.surface(path, head); ok {
			v.vetoed[path] = true
			return why, true
		}
		return match(path, head)
	}
}

// FullyRead is the walk's fullyRead with every withheld script surface unread.
func (v *Veto) FullyRead(path string) bool {
	return !v.vetoed[path] && v.read(path)
}

// Rebound reports whether a command anywhere in the build names, as an argument, a file an
// allowed command binds to, so may rewrite it first. Call it after the walk.
func (v *Veto) Rebound() bool {
	for name := range v.bound {
		if v.mentioned[name] {
			return true
		}
	}
	return false
}

func (v *Veto) bind(name string) { v.bound[strings.ToLower(filepath.Base(name))] = true }

// mention records the base names of a command's arguments, a redirect's or an option's
// target included.
func (v *Veto) mention(args []string) {
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

func (v *Veto) inRoot(p string) bool {
	rel, err := filepath.Rel(v.root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// surface reports whether the file at path is a script surface the rule withholds on, and why.
func (v *Veto) surface(path string, head []byte) (string, bool) {
	s, ok := surfaceOf(path, head)
	if !ok || head == nil {
		return "", false
	}
	if !v.spec.complete() {
		return "script surface under an incomplete lane spec", true
	}
	src := string(head)
	if len(head) == buildtree.HeadSize {
		data, err := v.spec.ReadRegular(path)
		if err != nil {
			return "script surface unreadable", true
		}
		src = string(data)
	}
	if v.spec.Env.MatchString(src) {
		return "script surface sets an installer variable", true
	}
	var why string
	switch {
	case s.kind == kindDockerfile:
		why = v.dockerfile(path, src)
	case strings.EqualFold(filepath.Ext(path), ".json"):
		if units, ok := jsonUnits(path, src); ok {
			why = v.host(s, kindShell, path, units)
			break
		}
		why = v.host(s, kindData, path, []unit{{text: src}})
	default:
		why = v.host(s, s.kind, path, []unit{{text: src}})
	}
	return why, why != ""
}

// unit is a run of shell text sharing a starting directory, or one exec-form command.
// bad marks a command value that is neither.
type unit struct {
	text string
	exec []string
	bad  bool
}

// jsonUnits reads a decodable JSON surface's commands: a package.json's "scripts"
// values, or every string value of any other outside dataKeys, an array of strings
// being one exec-form command.
func jsonUnits(path, src string) ([]unit, bool) {
	var units []unit
	if strings.EqualFold(filepath.Base(path), "package.json") {
		var p struct {
			Scripts map[string]json.RawMessage `json:"scripts"`
		}
		if json.Unmarshal([]byte(src), &p) != nil {
			return nil, false
		}
		for _, k := range sortedKeys(p.Scripts) {
			var s string
			if json.Unmarshal(p.Scripts[k], &s) != nil {
				units = append(units, unit{text: string(p.Scripts[k]), bad: true})
				continue
			}
			units = append(units, unit{text: s})
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
			units = append(units, unit{text: t})
		case []any:
			words := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					words = append(words, s)
				}
			}
			if len(words) == len(t) && len(t) > 0 {
				units = append(units, unit{exec: words})
				return
			}
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, k := range sortedKeys(t) {
				if !dataKeys[strings.ToLower(k)] {
					walk(t[k])
				}
			}
		}
	}
	walk(doc)
	return units, true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cdRE finds a directory change in a line that does not tokenise.
var cdRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])(?:cd|pushd|popd)(?:$|[^A-Za-z0-9_.-])`)

// host applies the rule to a host surface's units, each line split as kind.
func (v *Veto) host(s surfaceType, kind, path string, units []unit) string {
	var base []string
	unknown := s.base == baseNone
	switch s.base {
	case baseDir:
		base = []string{filepath.Dir(path)}
	case baseRoot:
		base = []string{v.root}
		dirs, ok := v.workingDirs(units)
		base, unknown = append(base, dirs...), !ok
	}
	for _, u := range units {
		carry := &hostCursor{v: v, dirs: append([]string(nil), base...), unknown: unknown}
		if u.bad {
			if v.hasToken(u.text) {
				return "install command that is not a string"
			}
			continue
		}
		if u.exec != nil {
			if why := v.command(segment{words: u.exec, expands: hasExpansion(u.exec)}, carry, 0); why != "" {
				return why
			}
			continue
		}
		lines, joined := logicalLines(u.text)
		if !joined && v.hasToken(lines[len(lines)-1]) {
			return "install command in an unjoined continuation"
		}
		for _, line := range lines {
			cur := &hostCursor{v: v, dirs: append([]string(nil), carry.dirs...), unknown: carry.unknown}
			if kind == kindData && v.hasToken(valuedKey(line)) {
				return "install key: " + strings.TrimSpace(line)
			}
			segs, ok := commandSegments(kind, line)
			if !ok {
				if v.hasToken(line) {
					return "install command that does not tokenise"
				}
				if expandedInstallLine(line) {
					return "install verb after an expansion that does not tokenise"
				}
				v.mention(strings.Fields(line))
				cur.unknown = cur.unknown || cdRE.MatchString(line)
			}
			for _, seg := range segs {
				if why := v.command(seg, cur, 0); why != "" {
					return why
				}
			}
			// Shell text (a script, a package.json script value) keeps its directory from line
			// to line; a recipe line or a CI step may start back where the surface started.
			if kind == kindShell {
				carry = cur
			} else {
				carry.merge(cur)
			}
		}
	}
	return ""
}

// workingDirKeys are keys that set where a CI or platform file's commands run.
var workingDirKeys = map[string]bool{
	"working-directory": true, "working_directory": true, "workdir": true, "rootdir": true,
	"root_dir": true, "base": true,
}

// workingDirs returns each literal in-tree directory a CI or platform file's commands may be
// told to run in, relative to the build root; ok is false when one is anything else.
func (v *Veto) workingDirs(units []unit) ([]string, bool) {
	var dirs []string
	for _, u := range units {
		for _, line := range strings.Split(u.text, "\n") {
			s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
			m := keyRE.FindStringSubmatch(s)
			if m == nil || !workingDirKeys[strings.ToLower(strings.Trim(m[1], `"'`))] {
				continue
			}
			val := strings.TrimSpace(s[len(m[0]):])
			if strings.HasPrefix(val, `"`) || strings.HasPrefix(val, "'") {
				q, ok := quotedValue(val)
				if !ok {
					return nil, false
				}
				val = q
			} else if i := strings.Index(val, " #"); i >= 0 {
				val = strings.TrimSpace(val[:i])
			}
			d := filepath.Join(v.root, val)
			if val == "" || filepath.IsAbs(val) || strings.ContainsAny(val, "$`{~*") || !v.inRoot(d) || !isDir(d) {
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
func (v *Veto) command(seg segment, cur cursor, depth int) string {
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
	if expandedInstall(words) {
		return "install verb after an expansion: " + strings.Join(words, " ")
	}
	if !v.segmentHasToken(words) {
		v.mention(words[1:])
		cur.other()
		return ""
	}
	if seg.expands || hasRedirect(words) {
		return "install command with an expansion or redirect: " + strings.Join(words, " ")
	}
	if v.spec.RunWrapper != nil {
		if argv, ok := v.spec.RunWrapper(words); ok {
			if len(argv) == 0 || depth >= maxRunDepth || v.spec.RunBinds == nil || !v.spec.RunBinds(words, cur) {
				return "install command: " + strings.Join(words, " ")
			}
			return v.command(segment{words: argv}, cur, depth+1)
		}
	}
	if !v.spec.Allowed(words, cur) {
		return "install command: " + strings.Join(words, " ")
	}
	return ""
}

// installVerbs are the subcommands with which a package manager installs or re-locks.
var installVerbs = map[string]bool{
	"install": true, "i": true, "add": true, "sync": true, "ci": true, "update": true,
	"upgrade": true, "up": true, "dlx": true,
}

// expandedInstall reports whether a word that expands is followed by an install verb: a
// package manager named by a variable set outside the tree ($PM add x), which names no token.
// make's own variable is left out: the target it runs is a recipe read here.
func expandedInstall(words []string) bool {
	for i := 0; i+1 < len(words); i++ {
		if strings.ContainsAny(words[i], "$`") && installVerbs[words[i+1]] && !makeVarRE.MatchString(words[i]) {
			return true
		}
	}
	return false
}

var (
	makeVarRE = regexp.MustCompile(`^\$+(?:\(MAKE\)|\{MAKE\}|MAKE)$`)
	// expandedInstallRE finds the same in a line that does not tokenise, such as a make
	// recipe calling $(PIP); its group is the expansion.
	expandedInstallRE = regexp.MustCompile(`(?:^|[\s;&|(])(\$+(?:\([^()\s]*\)|\{[^{}\s]*\}|[A-Za-z_][A-Za-z0-9_]*)|` +
		"`[^`]*`" + `)\S*\s+(?:install|i|add|sync|ci|update|upgrade|up|dlx)\b`)
)

// expandedInstallLine is expandedInstall for a line that does not tokenise.
func expandedInstallLine(line string) bool {
	for _, m := range expandedInstallRE.FindAllStringSubmatch(line, -1) {
		if !makeVarRE.MatchString(m[1]) {
			return true
		}
	}
	return false
}

func hasRedirect(words []string) bool {
	for _, w := range words {
		if strings.ContainsAny(w, "<>") {
			return true
		}
	}
	return false
}

func hasExpansion(words []string) bool {
	for _, w := range words {
		if strings.ContainsAny(w, "$`") {
			return true
		}
	}
	return false
}

// CommandName returns the program a command word runs: the word itself, or the base
// name of an absolute path. A relative path runs whatever file sits there, so names nothing.
func CommandName(word string) (string, bool) {
	if !strings.Contains(word, "/") {
		return word, true
	}
	if path.IsAbs(word) {
		return path.Base(word), true
	}
	return "", false
}

// FlagsOnly reports whether args are all flags from allowed or need, with at least one
// of need when need is given.
func FlagsOnly(args []string, allowed map[string]bool, need ...string) bool {
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

// wordRE splits text into the words installer tokens are matched against.
var wordRE = regexp.MustCompile(`[A-Za-z0-9_.+-]+`)

// hasToken reports whether a word of text, or a part of one split at - or _, names a token,
// so a hyphenated tool or action name (npm-install, setup-uv) names its installer too.
func (v *Veto) hasToken(text string) bool {
	for _, w := range wordRE.FindAllString(text, -1) {
		if v.spec.Token(w) {
			return true
		}
		parts := strings.FieldsFunc(w, func(r rune) bool { return r == '-' || r == '_' })
		if len(parts) < 2 {
			continue
		}
		for _, p := range parts {
			if v.spec.Token(p) {
				return true
			}
		}
	}
	return false
}

// segmentHasToken reports whether any word of a command, not only the program it runs,
// names an installer, so sudo, env, xargs and the like do not hide one.
func (v *Veto) segmentHasToken(words []string) bool {
	for _, w := range words {
		if v.hasToken(w) {
			return true
		}
	}
	return false
}
