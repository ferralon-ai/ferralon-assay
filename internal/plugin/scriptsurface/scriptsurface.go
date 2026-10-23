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
// that names a token and does not tokenise withhold too. A variable the lane's EnvKeeps names
// only selects among the packages a lock read here records, so setting it does not. A Spec
// missing any required decision withholds on every surface it recognises.
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
// A file run with . or source runs its commands in place, so it withholds unless it is a
// literal in-tree script surface the walk checks on its own, or only sets PATH: a
// version-manager init script named exactly as pathOnlyScripts lists it, or a literal
// <dir>/bin/activate whose <dir> names the same one place as the virtual environment the
// command before it, directory changes aside, created. That command must be in the same
// cursor: the same shell text on the host, the same shell unit of a GitHub workflow (a step's
// run:) or GitLab pipeline (a job's before_script then script), the same line of any other
// host surface, the same RUN in a Dockerfile. A creation that may not run (after &&, ||, | or
// &, or inside an if, case or loop) creates nothing here, nor does one whose bin/activate is
// already a file the build holds.
//
// A sample hook git writes into a hooks directory (pre-commit.sample in .git/hooks, a nested
// repository's .git/hooks or a submodule's .git/modules/<name>/hooks) is git's template
// content, and git never runs a hook under that name, so it withholds nothing while nothing
// in the build may reach one. Any of these triggers makes every sample hook a surface again:
// a surface's text naming .sample, hooks, dotglob or a .git directory, a glob over
// dot-names, a directory change or prefix whose argument expands, the text of an in-tree
// JavaScript, TypeScript, Python or Ruby file naming .sample or a .git directory, or a
// symlink into a .git directory. The gate reads only those: script surfaces, and the raw
// text of those source files. The build is trusted, so a form written to evade them is out
// of scope. A sample hook is not a script the walk reads, so sourcing one withholds.
//
// Across the whole build, a command that is not an installer and names a bound file's base
// name among its arguments (sed -i, curl -o, mv, a redirect) could rewrite that file before
// the install reads it, so it withholds too (Veto.Rebound).
package scriptsurface

import (
	"encoding/json"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// Spec is what a lane decides. Every field but EnvKeeps, RunWrapper, RunBinds and Concurrent
// is required.
type Spec struct {
	// Token reports whether a word names one of the lane's installers or package runners.
	Token func(word string) bool
	// Env matches one of the lane's installer variables being set.
	Env *regexp.Regexp
	// EnvKeeps reports whether an installer variable Env matched, by its name, only selects
	// which of the packages a lock read here records get installed, so setting it installs
	// nothing outside that lock. nil means none does.
	EnvKeeps func(name string) bool
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
	// Concurrent returns the commands a concurrent runner starts (concurrently "<cmd>" ...),
	// each shell text checked as sh -c would run it, and whether words is one. A runner with no
	// commands withholds, as does one this cannot read. nil means the lane has none.
	Concurrent func(words []string) (cmds []string, ok bool)
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
	kindData       = "data"   // YAML, TOML, INI, JSON and Procfile lines: "key: command"
	kindOpaque     = "opaque" // PowerShell and batch: not parsed, so a line naming a token withholds
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
	".gitlab-ci.yml": baseRoot, ".gitlab-ci.yaml": baseRoot, "bitbucket-pipelines.yml": baseRoot, ".travis.yml": baseRoot,
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
	case lower == "makefile", lower == "gnumakefile", ext == ".mk", ext == ".mak", ext == ".make", lower == "justfile", lower == ".justfile":
		return surfaceType{kindMakefile, baseDir}, true
	case ext == ".ps1", ext == ".bat", ext == ".cmd":
		return surfaceType{kindOpaque, baseDir}, true
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
	samples   []sampleRun     // the sample hooks surface passed over, each classified apart
	triggered bool            // a surface's text may reach a sample hook (trigger)
}

// sampleRun is what the rule found in one sample hook, classified as any other surface but
// apart from the rest of the build: why it withholds, and what its commands bind and mention.
type sampleRun struct {
	why              string
	bound, mentioned map[string]bool
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

// Withheld reports whether the rule withheld on any surface the walk classified, a command
// may rewrite a file an allowed command binds to, or a sample hook is live: the build may
// install a package no manifest or lock read here names. Call it after the walk.
func (v *Veto) Withheld() bool { return len(v.vetoed) > 0 || v.Rebound() || v.samplesLive() }

// samplesLive reports whether, once something in the build may reach a sample hook, the
// sample hooks read as surfaces withhold: one of them withholds on its own, or a command in
// one names a file a command anywhere binds to.
func (v *Veto) samplesLive() bool {
	if len(v.samples) == 0 || !v.triggered && !v.treeReaches() {
		return false
	}
	bound, mentioned := maps.Clone(v.bound), maps.Clone(v.mentioned)
	for _, s := range v.samples {
		if s.why != "" {
			return true
		}
		maps.Copy(bound, s.bound)
		maps.Copy(mentioned, s.mentioned)
	}
	for name := range bound {
		if mentioned[name] {
			return true
		}
	}
	return false
}

// The text triggers. Each is a natural way a command reaches a sample hook: naming one, its
// hooks directory or a .git directory; a glob over dot-names, which can match .git; or a
// directory change or prefix this cannot read, which can land in a hooks directory.
var (
	mentionRE = regexp.MustCompile(`\.sample|hooks|dotglob|\.git(?:$|[^A-Za-z0-9_])`)
	// sourceRE is the mention trigger for a build script in a language no surface parses. It
	// leaves out hooks, which every React tree's src/hooks would match.
	sourceRE  = regexp.MustCompile(`\.sample|\.git(?:$|[^A-Za-z0-9_])`)
	dotGlobRE = regexp.MustCompile(`(?:^|[\s/"'=;&|()<>` + "`" + `])\.[^\s/"'=;&|()<>` + "`" + `]*[*?\[{]`)
	dynDirRE  = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])(?:cd|pushd|-C|--prefix|--cwd)(?:\s+-{1,2}[A-Za-z]*)*(?:\s+|=)[^\s;&|)]*[$` + "`" + `]`)
)

// trigger notes whether a surface's raw text may reach a sample hook.
func (v *Veto) trigger(text string) {
	v.triggered = v.triggered || mentionRE.MatchString(text) || dotGlobRE.MatchString(text) || dynDirRE.MatchString(text)
}

// sourceExts are the build-script languages no surface parses, whose files a lifecycle
// script commonly runs (node scripts/setup.js, python3 tools/setup.py).
var sourceExts = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true,
	".cts": true, ".py": true, ".rb": true}

// treeReaches reports whether the build outside the script surfaces may reach a sample hook:
// an in-tree source file in sourceExts whose text sourceRE matches, or a symlink pointing
// into a .git directory, so a path that names neither may reach a hooks directory. A source
// file or link that cannot be read counts.
func (v *Veto) treeReaches() bool {
	found := false
	_ = buildtree.Walk(v.root, func(e buildtree.Entry, err error) error {
		if err != nil {
			return nil
		}
		if sourceExts[strings.ToLower(filepath.Ext(e.Path))] && !e.D.IsDir() {
			if e.Escapes {
				found = true
				return filepath.SkipAll
			}
			if data, err := v.spec.ReadRegular(e.Path); err != nil || sourceRE.Match(data) {
				found = true
				return filepath.SkipAll
			}
		}
		if !e.Symlink {
			return nil
		}
		target, err := os.Readlink(e.Path)
		if err != nil {
			found = true
			return filepath.SkipAll
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(e.Path), target)
		}
		for _, seg := range strings.Split(filepath.Clean(target), string(filepath.Separator)) {
			if seg == ".git" {
				found = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found
}

// sampleHook reports whether p is a sample hook: a name ending in .sample directly in a hooks
// directory that is a repository's .git/hooks (the build root's or a nested one's) or a
// submodule's .git/modules/<name>/hooks. Those are the only directories git itself fills
// with samples, and git runs a hook only under its exact name, so never one ending in
// .sample. Any other .sample file (.githooks/, tools/hooks/, a directory under hooks) stays a
// surface, as do an empty name and any other suffix.
func (v *Veto) sampleHook(p string) bool {
	rel, err := filepath.Rel(v.root, p)
	if err != nil {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	n := len(parts)
	if n < 3 || parts[n-2] != "hooks" {
		return false
	}
	if stem, ok := strings.CutSuffix(parts[n-1], ".sample"); !ok || stem == "" {
		return false
	}
	if parts[n-3] == ".git" {
		return true
	}
	for i := 0; i+1 < n-3; i++ {
		if parts[i] == ".git" && parts[i+1] == "modules" {
			return true
		}
	}
	return false
}

// setsEnv reports whether src sets an installer variable the lane's EnvKeeps does not keep.
func (v *Veto) setsEnv(src string) bool {
	for _, m := range v.spec.Env.FindAllString(src, -1) {
		name := strings.TrimLeftFunc(m, func(r rune) bool { return r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		if v.spec.EnvKeeps == nil || !v.spec.EnvKeeps(name) {
			return true
		}
	}
	return false
}

func (v *Veto) bind(name string) { v.bound[strings.ToLower(filepath.Base(name))] = true }

// mention records the base names of a command's arguments, a redirect's or an option's
// target included.
func (v *Veto) mention(args []string) {
	for _, w := range args {
		w = trimShell(w)
		if i := strings.LastIndexByte(w, '='); i >= 0 {
			w = trimShell(w[i+1:])
		}
		for _, a := range braces(filepath.ToSlash(w), 0) {
			if b := strings.ToLower(path.Base(a)); b != "" && b != "." && b != "/" {
				v.mentioned[b] = true
			}
		}
	}
}

// trimShell strips a leading redirect and shell punctuation from both ends of w: an opening
// or closing bracket only when w does not close or open it, or parentheses wrapping the word.
func trimShell(w string) string {
	for {
		t := strings.TrimLeft(w, "0123456789<>&")
		t = strings.Trim(t, ";&|`\"'")
		t = strings.TrimPrefix(t, "$(")
		for _, p := range []string{"()", "{}"} {
			o, c := p[:1], p[1:]
			if strings.HasPrefix(t, o) && strings.Count(t, o) > strings.Count(t, c) {
				t = t[1:]
			}
			if strings.HasSuffix(t, c) && strings.Count(t, c) > strings.Count(t, o) {
				t = t[:len(t)-1]
			}
			if o == "(" && len(t) >= 2 && strings.HasPrefix(t, o) && strings.HasSuffix(t, c) && !strings.ContainsAny(t[1:len(t)-1], p) {
				t = t[1 : len(t)-1]
			}
		}
		if t == w {
			return w
		}
		w = t
	}
}

// maxBraces bounds the words one brace expression expands to; past it the expression is a glob.
const maxBraces = 64

// braces returns the words w's brace lists expand to, outermost first; a brace range, or a
// list nested too deep or expanding past maxBraces, becomes *. Braces with no top-level comma stay as they are.
func braces(w string, depth int) []string {
	for i := 0; i < len(w); i++ {
		if w[i] != '{' || (i > 0 && w[i-1] == '$') {
			continue
		}
		level, commas, end := 0, []int{}, -1
		for j := i; j < len(w) && end < 0; j++ {
			switch w[j] {
			case '{':
				level++
			case '}':
				level--
				if level == 0 {
					end = j
				}
			case ',':
				if level == 1 {
					commas = append(commas, j)
				}
			}
		}
		if end < 0 {
			return []string{w}
		}
		if strings.Contains(w[i:end], "..") {
			return braces(w[:i]+"*"+w[end+1:], depth+1)
		}
		if len(commas) == 0 {
			continue
		}
		var out []string
		start := i + 1
		for _, c := range append(commas, end) {
			out = append(out, w[:i]+w[start:c]+w[end+1:])
			start = c + 1
		}
		if depth > 8 {
			return []string{w[:i] + "*" + w[end+1:]}
		}
		var all []string
		for _, o := range out {
			all = append(all, braces(o, depth+1)...)
			if len(all) > maxBraces {
				return []string{w[:i] + "*" + w[end+1:]}
			}
		}
		return all
	}
	return []string{w}
}

// walkedSurface reports whether p is an in-tree script surface outside every directory the
// walk skips, and not a sample hook.
func (v *Veto) walkedSurface(p string) bool {
	rel, err := filepath.Rel(v.root, p)
	if err != nil || !v.inRoot(p) || v.sampleHook(p) {
		return false
	}
	for _, part := range strings.Split(filepath.Dir(rel), string(filepath.Separator)) {
		if part != "." && buildtree.Skipped(part) {
			return false
		}
	}
	head, err := buildtree.Head(p)
	if err != nil {
		return false
	}
	_, ok := surfaceOf(p, head)
	return ok
}

func (v *Veto) inRoot(p string) bool {
	rel, err := filepath.Rel(v.root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// surface reports whether the file at path is a script surface the rule withholds on, and why.
// A sample hook is classified apart and withholds nothing here (samplesLive).
func (v *Veto) surface(path string, head []byte) (string, bool) {
	s, ok := surfaceOf(path, head)
	if !ok || head == nil {
		return "", false
	}
	if !v.sampleHook(path) {
		return v.classify(s, path, head, true)
	}
	bound, mentioned := v.bound, v.mentioned
	v.bound, v.mentioned = map[string]bool{}, map[string]bool{}
	why, _ := v.classify(s, path, head, false)
	v.samples = append(v.samples, sampleRun{why: why, bound: v.bound, mentioned: v.mentioned})
	v.bound, v.mentioned = bound, mentioned
	return "", false
}

// classify applies the rule to a script surface of type s, and with scan notes whether its
// text may reach a sample hook.
func (v *Veto) classify(s surfaceType, path string, head []byte, scan bool) (string, bool) {
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
	if v.setsEnv(src) {
		return "script surface sets an installer variable", true
	}
	var why string
	units := []unit{{text: src}}
	switch {
	case s.kind == kindDockerfile:
		why = v.dockerfile(path, src)
	case s.kind == kindOpaque:
		why = v.opaque(src)
	case strings.EqualFold(filepath.Ext(path), ".json"):
		// A decodable JSON surface's text is its commands, so a dependency named like a
		// trigger (eslint-plugin-react-hooks) is not one.
		if u, ok := jsonUnits(path, src); ok {
			units = u
			why = v.host(s, kindShell, path, units)
			break
		}
		why = v.host(s, kindData, path, units)
	case gitlabCI[strings.ToLower(filepath.Base(path))]:
		included, w := v.gitlabIncludes(path, src, map[string]bool{path: true}, 0)
		if w != "" {
			return w, true
		}
		units = append(units, included...)
		why = v.host(s, s.kind, path, units)
	default:
		why = v.host(s, s.kind, path, units)
	}
	for _, u := range units {
		if scan {
			v.trigger(u.text)
			v.trigger(strings.Join(u.exec, " "))
		}
	}
	return why, why != ""
}

// opaque applies the rule to a surface this does not parse: any line naming a token, or an
// install verb after an expansion, withholds.
func (v *Veto) opaque(src string) string {
	for _, line := range strings.Split(src, "\n") {
		if v.hasToken(line) {
			return "install command in a surface this does not parse"
		}
		if expandedInstallLine(line) {
			return "install verb after an expansion in a surface this does not parse"
		}
		v.mention(strings.Fields(line))
	}
	return ""
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
	ext := strings.ToLower(filepath.Ext(path))
	yaml := kind == kindData && (ext == ".yml" || ext == ".yaml")
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
	included := yaml && gitlabIncluded(path, units)
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
		lines, starts, joined := logicalLinesAt(u.text)
		if !joined && v.hasToken(lines[len(lines)-1]) {
			return "install command in an unjoined continuation"
		}
		read := make([]yamlLine, len(lines))
		for i, l := range lines {
			read[i] = yamlLine{text: l, start: i}
		}
		var shells map[int]shellUnit
		if yaml {
			read = foldYAML(lines)
			shells = v.shellUnits(path, u.text, included)
		}
		inUnit := map[int]*hostCursor{}
		for _, rl := range read {
			line, lineKind := rl.text, kind
			if rl.shell {
				lineKind = kindShell
			}
			// Lookups run from every directory the lines so far may have left; only the venv
			// rule carries its mark and the unit's one directory from line to line.
			cur := &hostCursor{v: v, dirs: append([]string(nil), carry.dirs...), unknown: carry.unknown, mark: carry.mark, wd: carry.wd}
			su, inShell := shells[starts[rl.start]]
			if prev := inUnit[su.id]; inShell && prev != nil {
				cur.mark, cur.wd = prev.mark, prev.wd
			} else if inShell {
				cur.mark, cur.wd = venvMark{}, su.dir
			}
			if lineKind == kindData && v.hasToken(valuedKey(line)) {
				return "install key: " + strings.TrimSpace(line)
			}
			segs, ok, dangles := commandSegments(lineKind, line)
			if cur.mark.dangle && len(segs) > 0 {
				segs[0].guarded = true
			}
			if len(segs) > 0 || !ok {
				// A blank or comment line leaves a trailing && or || waiting for its command.
				cur.mark.dangle = dangles
			}
			if !ok {
				// A line this cannot split may hold a subshell, group or function body: the venv
				// rule cannot say what ran, or where.
				cur.mark.made, cur.wd = "", ""
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
				if inShell {
					inUnit[su.id] = cur
				}
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
	mark := cur.venv()
	if mark.chain && !seg.and {
		// The && list a cd was part of has ended: what runs now may run where the cd did not.
		mark.made, mark.lost, mark.chain = "", true, false
	}
	made := mark.made
	mark.made = venvMade(seg, cur)
	if mark.open >= 0 {
		// Below 0 a fi, done or esac closed a body the rule did not see open, such as a line
		// of a heredoc: it no longer knows which body a command is in, so it stays below 0.
		mark.open += blockDepth[words[0]]
	}
	switch words[0] {
	case "cd", "pushd", "popd":
		mark.made = made // the venv's key was taken where it was made
		if seg.expands {
			cur.cd(nil)
		} else {
			cur.cd(words)
		}
		switch {
		case seg.background || seg.end == "|" || seg.end == "||":
			// A cd before & or | runs in a subshell, and what follows a cd before || runs only
			// if it failed: the shell is not where the cd went.
			mark.made, mark.lost, mark.chain = "", true, false
		case seg.and && mark.open == 0:
			// The cd may not have run, but what follows it in its && list runs only if it did.
			mark.chain = true
		case seg.guarded || mark.open != 0:
			// The cd may not have run, so neither the venv a command before it made nor the
			// directory it moved to is known.
			mark.made, mark.lost = "", true
		}
		return ""
	case ".", "source":
		// The sourced file's commands run here; they are checked only when it is a surface
		// the walk reads itself, or when it only sets PATH.
		if (seg.expands || len(words) < 2 || !cur.sourced(words[1])) && !pathOnly(seg, cur, made) {
			return "sources a file not read as a script: " + strings.Join(words, " ")
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
	if v.spec.Concurrent != nil {
		if cmds, ok := v.spec.Concurrent(words); ok {
			return v.concurrent(words, cmds, cur, depth)
		}
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

// concurrent applies the rule to the commands a concurrent runner starts, each in a shell of
// its own from where the runner runs: shell text that does not split into whole commands
// withholds, as does a runner with none or nested too deep.
func (v *Veto) concurrent(words, cmds []string, cur cursor, depth int) string {
	why := "install command: " + strings.Join(words, " ")
	// Each nested command is a strictly shorter string, so the depth bound here is defence in
	// depth; a run wrapper's script body is not, and needs it.
	if len(cmds) == 0 || depth >= maxRunDepth {
		return why
	}
	for _, c := range cmds {
		segs, ok, dangles := shellSegments(c)
		if !ok || dangles || len(segs) == 0 {
			return why
		}
		sh := cur.fork()
		for _, seg := range segs {
			if w := v.command(seg, sh, depth+1); w != "" {
				return w
			}
		}
	}
	return ""
}

// pathOnlyScripts are the version-manager init scripts, as written after . or source, that
// only set PATH and functions when sourced and install nothing.
var pathOnlyScripts = map[string]bool{
	"$NVM_DIR/nvm.sh": true, "$HOME/.nvm/nvm.sh": true, "~/.nvm/nvm.sh": true,
	"$HOME/.cargo/env": true, "~/.cargo/env": true,
}

// pathOnly reports whether a . or source of a file the walk does not read only sets PATH: one
// of pathOnlyScripts, its $ expanding, or a literal <dir>/bin/activate of the virtual
// environment that made, the previous command but for directory changes, created at the same
// place.
func pathOnly(seg segment, cur cursor, made string) bool {
	if len(seg.words) != 2 {
		return false
	}
	op := seg.words[1]
	if pathOnlyScripts[op] {
		return seg.expands == strings.Contains(op, "$")
	}
	dir, ok := strings.CutSuffix(op, "/bin/activate")
	if seg.expands || !ok {
		return false
	}
	key, ok := cur.at(dir)
	return ok && made != "" && key == made
}

// blockDepth is how far each word opening or closing an if, case or loop moves a command into
// or out of a body that may not run.
var blockDepth = map[string]int{
	"if": 1, "case": 1, "for": 1, "while": 1, "until": 1, "select": 1,
	"fi": -1, "esac": -1, "done": -1,
}

var pythonRE = regexp.MustCompile(`^python(?:\d+(?:\.\d+)?)?$`)

// venvMade returns the key of the virtual environment a command creates: python -m venv <dir>,
// virtualenv <dir>, or uv venv [<dir>] (.venv when there is none), with flags before or after
// <dir> and -p, --python or --prompt taking the next word. "" when it is none of these, when
// its directory is not one place, when it may not run (after &&, ||, | or &, or inside an if,
// case or loop) or not finish first (before a lone &), or when <dir>/bin/activate is already a file the build holds, which a creation
// that did not run would leave in place.
func venvMade(seg segment, cur cursor) string {
	words := seg.words
	head, ok := CommandName(words[0])
	var args []string
	switch {
	case seg.expands || !ok || seg.guarded || seg.background || cur.venv().open != 0:
		return ""
	case pythonRE.MatchString(head) && len(words) >= 3 && words[1] == "-m" && words[2] == "venv":
		args = words[3:]
	case head == "virtualenv":
		args = words[1:]
	case head == "uv" && len(words) >= 2 && words[1] == "venv":
		args = words[2:]
	default:
		return ""
	}
	var dirs []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-p" || a == "--python" || a == "--prompt":
			i++
		case strings.HasPrefix(a, "--directory") || strings.HasPrefix(a, "--project"):
			return ""
		case !strings.HasPrefix(a, "-"):
			dirs = append(dirs, a)
		}
	}
	switch {
	case len(dirs) == 0 && head == "uv":
		dirs = []string{".venv"}
	case len(dirs) != 1:
		return ""
	}
	key, ok := cur.at(dirs[0])
	if !ok || cur.present(filepath.Join(dirs[0], "bin", "activate")) {
		return ""
	}
	return key
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
// so a hyphenated tool or action name (npm-install, setup-uv) names its installer too. A
// variable the lane's EnvKeeps keeps (npm_config_production) names none.
func (v *Veto) hasToken(text string) bool {
	for _, w := range wordRE.FindAllString(text, -1) {
		if v.spec.EnvKeeps != nil && v.spec.EnvKeeps(w) {
			continue
		}
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
