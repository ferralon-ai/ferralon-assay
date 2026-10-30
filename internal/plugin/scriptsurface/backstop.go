package scriptsurface

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// The backstop reads the files surfaceOf does not recognise for a lane installer in a command
// position, and withholds on one as the rule withholds on a surface it cannot read: the file is
// vetoed, so FullyRead reports it unread, and the lane's versions and Exhaustive fall with it.
// Every command in a command position a word of which names a lane token, as its program, an
// argument, a path, or text a shell, eval or interpreter runs, goes to v.command from a
// directory it does not know, as the same line in install.sh would: a form a lane allows
// without binding a manifest, such as a pip self-upgrade, passes, a command that only reports
// passes (readOnly), and everything else withholds.
//
// A command position is one of these:
//
//   - every line of a file with a Dockerfile-style FROM line, in any case, which the
//     Dockerfile rule reads as it reads a Dockerfile (dockerfileAt), binding what its COPY and
//     ADD bring in;
//   - in any other text file, the value of a key that holds commands (cmdKey: run, script,
//     command, commands, cmd, entry, shell, before_install, post-install-commands, *_script,
//     and content in a Bitrise config, ...) as a scalar, a block scalar, a list or an array,
//     and every top-level value of a TOML task table ([tool.poe.tasks], [tool.pdm.scripts],
//     [tool.hatch.envs.<env>.scripts], [tasks]); in a decodable JSON file the same keys
//     whatever the layout; a key that sets an installer variable in an environment map
//     withholds too;
//   - a tab-indented make recipe line after a rule line;
//   - every line of a Husky hook or a Buildkite agent hook (shellDirs);
//   - in source code a build runs as its own script (buildScript), a string literal given to a
//     name that runs commands (subprocess.run, c.run, execSync, exec.Command, sh, a zx $), an
//     argv of literals given to one (["pip", "install", ...], [sys.executable, "-m", "pip",
//     ...]) or to an installer's own API (pip.main), and a nox session's install helpers.
//
// It does not read what no build runs as a command: binary and empty files, inertName files,
// lockfiles, prose and rendered text (proseExts, proseNames), a Read the Docs config, a file
// past its buildtree.Head once it is over backstopMax, inside a .git directory everything but
// the active hooks, and any source file that is not a build script. The Dockerfile rule's
// binding is the only binding it does; nothing else it reads feeds a lane's claims.

// backstopMax is the size past which the backstop reads only a file's buildtree.Head. A build
// script is far smaller; what is larger is generated output or data.
const backstopMax = 1 << 20

// proseNames are base names, compared case-insensitively, of the prose files a repository
// carries beside the ones inertName knows. Only the bare name is prose: install.py, install.js
// and install.yml are scripts and configs a build runs.
var proseNames = map[string]bool{
	"readme": true, "changes": true, "history": true, "news": true, "install": true,
	"contributing": true,
}

// proseExts are the extensions of prose, rendered documents, translations, patches and
// generated text. A notebook is read whole as prose: its code cells run in a kernel, not in
// the build.
var proseExts = map[string]bool{
	".txt": true, ".mdx": true, ".html": true, ".htm": true, ".ipynb": true, ".po": true,
	".pot": true, ".tex": true, ".patch": true, ".diff": true, ".map": true, ".snap": true,
	".svg": true, ".csv": true, ".tsv": true,
}

// sourceExts are the extensions of source code: the backstop reads only the string literals of
// a build script, never its lines as commands. hashComment marks a language whose comments
// start with #.
var sourceExts = map[string]bool{
	".py": true, ".pyi": true, ".rb": true, ".rake": true, ".pl": true, ".pm": true, ".php": true,
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".mts": true, ".cts": true,
	".tsx": true, ".go": true, ".java": true, ".kt": true, ".kts": true, ".scala": true, ".sbt": true,
	".groovy": true, ".gradle": true, ".rs": true, ".c": true, ".h": true, ".cc": true,
	".cpp": true, ".hpp": true, ".cs": true, ".swift": true, ".lua": true, ".dart": true,
	".vue": true, ".svelte": true,
}

var hashComment = map[string]bool{".py": true, ".pyi": true, ".rb": true, ".rake": true, ".pl": true, ".pm": true}

// sourceShebangs are the interpreters a "#!" line can name that run source code.
var sourceShebangs = regexp.MustCompile(`^(?:python[0-9.]*|pypy[0-9.]*|node|nodejs|deno|bun|ts-node|tsx|ruby|perl|php|groovy|lua|zx)$`)

// buildScriptStems are the base names, before the extension, of source files build runners
// and maintainers run as the build's own scripts: invoke, fabric, doit, paver, setuptools,
// gulp, grunt, jake, mage, cargo (build.rs), gradle and sbt (build.*, settings.*), rake.
var buildScriptStems = map[string]bool{
	"tasks": true, "fabfile": true, "dodo": true, "pavement": true, "setup": true, "build": true,
	"settings": true, "make": true, "gulpfile": true, "gruntfile": true, "jakefile": true,
	"magefile": true, "rakefile": true, "bootstrap": true, "install": true, "deploy": true,
	"release": true, "ci": true,
}

// toolDirs are directory names, compared case-insensitively, that hold a build's own scripts.
var toolDirs = map[string]bool{
	"scripts": true, "script": true, "tools": true, "tool": true, "tooling": true, "ci": true,
	".ci": true, "bin": true, "build": true, "dev": true, "hack": true, ".github": true,
	".buildkite": true, ".gitea": true, ".forgejo": true, ".circleci": true, "tasks": true,
	"magefiles": true, "buildsrc": true, ".devcontainer": true, "docker": true, "deploy": true,
	"release": true,
}

// backstopSkips reports whether the file at path, with its buildtree.Head, is one no build runs
// as a command, so the backstop does not read it.
func (v *Veto) backstopSkips(path string, head []byte) bool {
	if head == nil || inertName(path, head) {
		return true
	}
	if v.inGitDir(path) {
		return !v.gitHooksFile(path) || v.sampleHook(path)
	}
	if bytes.HasPrefix(head, []byte("#!")) {
		return false
	}
	lower := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(lower)
	switch {
	case lower == "cmakelists.txt":
		return false
	case proseExts[ext], proseNames[lower]:
		return true
	case ext == ".lock", lower == "go.sum":
		return true
	case lower == ".readthedocs.yml", lower == ".readthedocs.yaml":
		// Read the Docs runs these on its own builders, never in the build.
		return true
	case lower == ".pre-commit-hooks.yaml":
		// The hooks a repository publishes for others: pre-commit runs them only in a
		// repository whose .pre-commit-config.yaml names this one.
		return true
	case lower == "action.yml", lower == "action.yaml":
		// An action a repository publishes for others runs in their workflows, and in its
		// own only when one of them uses an action from the tree.
		return !v.localActions()
	}
	return false
}

// localActionRE matches a workflow step that uses an action from its own repository.
var localActionRE = regexp.MustCompile(`(?m)^[\s-]*uses:\s*['"]?\.{1,2}/`)

// localActions reports whether a GitHub, Gitea or Forgejo workflow in the build uses an action
// from the tree, or one of them cannot be read.
func (v *Veto) localActions() bool {
	if v.actions != nil {
		return *v.actions
	}
	used := false
	for _, dir := range []string{".github", ".gitea", ".forgejo"} {
		entries, err := os.ReadDir(filepath.Join(v.root, dir, "workflows"))
		if err != nil && !v.spec.Absent(err) {
			used = true
		}
		for _, e := range entries {
			if used {
				break
			}
			if e.IsDir() {
				continue
			}
			data, err := v.spec.ReadRegular(filepath.Join(v.root, dir, "workflows", e.Name()))
			used = err != nil || localActionRE.Match(data)
		}
	}
	v.actions = &used
	return used
}

// sourceKind reports whether the file at path is source code, and whether its comments start
// with #.
func sourceKind(path string, head []byte) (source, hash bool) {
	if rest, ok := bytes.CutPrefix(head, []byte("#!")); ok {
		first, _, _ := bytes.Cut(rest, []byte("\n"))
		f := strings.Fields(string(first))
		if len(f) > 0 && filepath.Base(f[0]) == "env" {
			f = f[1:]
			for len(f) > 0 && strings.HasPrefix(f[0], "-") {
				f = f[1:]
			}
		}
		if len(f) > 0 && sourceShebangs.MatchString(filepath.Base(f[0])) {
			b := filepath.Base(f[0])
			return true, strings.HasPrefix(b, "python") || strings.HasPrefix(b, "pypy") || b == "ruby" || b == "perl"
		}
		return false, true
	}
	lower := strings.ToLower(filepath.Base(path))
	if lower == "rakefile" {
		return true, true
	}
	ext := filepath.Ext(lower)
	if sourceExts[ext] {
		return true, hashComment[ext]
	}
	return false, true
}

// buildScript reports whether a source file is one a build runs as its own script: it starts
// with "#!", its stem is a buildScriptStems name, it is a tool's config a build loads as code
// (vite.config.ts, webpack.config.js), or a directory above it, inside the build, is a toolDirs
// name.
func (v *Veto) buildScript(path string, head []byte) bool {
	lower := strings.ToLower(filepath.Base(path))
	rel, err := filepath.Rel(v.root, filepath.Dir(path))
	if err != nil {
		rel = "."
	}
	dirs := strings.Split(strings.ToLower(filepath.ToSlash(rel)), "/")
	if testFile(lower, dirs) {
		return false
	}
	if bytes.HasPrefix(head, []byte("#!")) {
		return true
	}
	if i := strings.IndexByte(lower, '.'); i > 0 && buildScriptStems[lower[:i]] || buildScriptStems[lower] {
		return true
	}
	if strings.Contains(lower, ".config.") {
		return true
	}
	for _, d := range dirs {
		if toolDirs[d] {
			return true
		}
	}
	return false
}

// testDirs are directory names that hold tests and their fixtures.
var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "testing": true, "fixtures": true,
	"__fixtures__": true, "testdata": true, "e2e": true,
}

// testFile reports whether a source file, by its lowercased base name and the directories
// above it inside the build, is a test or a fixture: a test suite runs it, the build does not,
// and its strings are the inputs it checks.
func testFile(lower string, dirs []string) bool {
	stem := lower
	if i := strings.IndexByte(lower, '.'); i > 0 {
		stem = lower[:i]
	}
	if strings.HasPrefix(stem, "test_") || strings.HasSuffix(stem, "_test") || stem == "conftest" ||
		strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec.") {
		return true
	}
	for _, d := range dirs {
		if testDirs[d] {
			return true
		}
	}
	return false
}

// backstop applies the backstop to a file surfaceOf does not recognise, and returns why it
// withholds.
func (v *Veto) backstop(path string, head []byte) (string, bool) {
	if !v.spec.complete() || v.backstopSkips(path, head) {
		return "", false
	}
	source, hash := sourceKind(path, head)
	if source && !v.buildScript(path, head) {
		return "", false
	}
	src := string(head)
	if len(head) == buildtree.HeadSize {
		if fi, err := os.Stat(path); err == nil && fi.Size() > backstopMax {
			if i := strings.LastIndexByte(src, '\n'); i >= 0 {
				src = src[:i]
			}
		} else {
			data, err := v.spec.ReadRegular(path)
			if err != nil {
				return v.unrecognised(path, 0, "file unreadable"), true
			}
			src = string(data)
		}
	}
	var line int
	var why string
	switch {
	case source:
		line, why = v.backstopLiterals(src, hash, !hash)
	case shellDir(v.root, path):
		line, why = v.valueText(src, true)
		line++
	default:
		if dockerLike(src) {
			line, why = v.backstopDocker(path, src)
		}
		if why == "" && json.Valid([]byte(src)) {
			line, why = v.backstopJSON(src)
		}
		if why == "" {
			line, why = v.backstopLines(src, strings.HasPrefix(strings.ToLower(filepath.Base(path)), "bitrise."))
		}
	}
	if why != "" {
		return v.unrecognised(path, line, why), true
	}
	return "", false
}

// shellDirs are the directories, as slash-separated paths from the build root, whose files a
// hook manager or CI agent runs as shell scripts that need no #! line: Husky hooks and
// Buildkite agent hooks.
var shellDirs = []string{".husky/", ".buildkite/hooks/"}

// shellDir reports whether the file at path is in one of shellDirs, so the backstop reads each
// of its lines as shell text.
func shellDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, d := range shellDirs {
		if strings.HasPrefix(rel, d) {
			return true
		}
	}
	return false
}

var (
	// fromRE finds a Dockerfile-style FROM line.
	fromRE = regexp.MustCompile(`(?m)^[ \t]*FROM[ \t]+\S`)
	// fromAnyRE finds a FROM line in any case shaped as one: an image after its flags, an
	// optional stage name, and nothing after but a comment.
	fromAnyRE = regexp.MustCompile(`(?im)^[ \t]*from[ \t]+(?:--\S+[ \t]+)*\S+(?:[ \t]+as[ \t]+\S+)?[ \t]*(?:#.*)?\r?$`)
)

// dockerLike reports whether a file that is not source code holds a Dockerfile-style FROM
// line, so the Dockerfile rule reads it.
func dockerLike(src string) bool { return fromRE.MatchString(src) || fromAnyRE.MatchString(src) }

// backstopDocker applies the Dockerfile rule to a file with a FROM line that surfaceOf does
// not recognise, as classify applies it to a Dockerfile, and returns the 1-based line it
// withholds on and why. The rule follows heredocs, instructions in any case, and what its
// COPY and ADD instructions bind, so a bound install passes here as it does in a Dockerfile.
func (v *Veto) backstopDocker(path, src string) (int, string) {
	if v.spec.Text != nil {
		v.spec.Text(src)
	}
	if v.setsEnv(src) {
		for i, l := range strings.Split(src, "\n") {
			if v.setsEnv(l) {
				return i + 1, "sets an installer variable"
			}
		}
		return 0, "sets an installer variable"
	}
	v.trigger(src)
	why, line := v.dockerfileAt(path, src, false)
	return line, why
}

// unrecognised records the first file and line the backstop withholds on, and phrases why.
func (v *Veto) unrecognised(path string, line int, why string) string {
	rel, err := filepath.Rel(v.root, path)
	if err != nil {
		rel = path
	}
	at := filepath.ToSlash(rel)
	if line > 0 {
		at += ":" + strconv.Itoa(line)
	}
	if v.unrecognisedAt == "" {
		v.unrecognisedAt = at
	}
	return "installer in a file not read as a script surface (" + at + "): " + why
}

// Unrecognised returns where the backstop first withheld, as a slash-separated path relative to
// the build root and a 1-based line ("Earthfile:12"), or "" when it did not. Call it after the
// walk.
func (v *Veto) Unrecognised() string { return v.unrecognisedAt }

var (
	// ruleRE matches a make rule line: targets, a colon, and no assignment.
	ruleRE = regexp.MustCompile(`^[^\s:#=][^:=]*:(?:[^=]|$)`)
	// tableRE matches a TOML table header; its group is the table's name.
	tableRE = regexp.MustCompile(`^\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(?:#.*)?$`)
	// taskTableRE matches the name of a TOML table every value of which is a command: poe
	// and taskipy tasks, pdm, hatch and rye scripts, pixi tasks.
	taskTableRE = regexp.MustCompile(`(?:^|\.)(?:tasks|scripts)$`)
	// cmdKeyRE matches the keys, lowercased, whose values are commands, beside cmdKeys: a
	// hook before or after a phase (before_install, hatch's post-install-commands), a phase's
	// commands (install_script), tox's commands_pre, and any key ending in _script or -script
	// (Cirrus CI's test_script).
	cmdKeyRE = regexp.MustCompile(`^(?:(?:pre|post|before|after)[_-]?(?:install|build|script|test|deploy|run|checkout)(?:[_-]?(?:commands?|cmds?|scripts?|steps?))?|` +
		`(?:install|build|test|deploy|setup)[_-]?(?:script|scripts|command|commands|cmd|cmds|step|steps)|commands[_-](?:pre|post)|.+[_-]scripts?)$`)
)

// cmdKeys are the keys, lowercased, whose values a CI system, task runner or hook manager runs
// as commands.
var cmdKeys = map[string]bool{
	"run": true, "cmd": true, "cmds": true, "command": true, "commands": true, "script": true,
	"scripts": true, "shell": true, "entry": true, "install": true, "exec": true,
}

func cmdKey(key string) bool { return cmdKeys[key] || cmdKeyRE.MatchString(key) }

// lineComment reports whether a trimmed line of a file that is not source code is a comment.
func lineComment(t string) bool {
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, ";")
}

func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }

// backstopLines reads a file that is not source code for its command positions, and returns
// the first 1-based line that runs an installer, or sets an installer variable, and why.
func (v *Veto) backstopLines(src string, bitrise bool) (int, string) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	table, rule := "", false
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if strings.HasPrefix(raw, "\t") && rule {
			text, end := joined(lines, i)
			if why := v.shellText(text, true); why != "" {
				return i + 1, why
			}
			i = end
			continue
		}
		if !strings.HasPrefix(raw, "\t") {
			rule = ruleRE.MatchString(raw)
		}
		if lineComment(t) {
			continue
		}
		if m := tableRE.FindStringSubmatch(t); m != nil {
			table = strings.ToLower(strings.ReplaceAll(m[1], `"`, ""))
			continue
		}
		if strings.HasPrefix(t, "- ") && v.setsEnv(t) && envParent(lines, i, table) {
			return i + 1, "sets an installer variable"
		}
		ind, item := indentOf(raw), t
		if rest, ok := strings.CutPrefix(item, "- "); ok {
			item, ind = strings.TrimSpace(rest), ind+2
		}
		m := keyRE.FindStringSubmatch(item)
		if m == nil {
			continue
		}
		name := strings.Trim(m[1], `"'`)
		if v.setsEnv(name) && envParent(lines, i, table) {
			return i + 1, "sets an installer variable"
		}
		inTable := taskTableRE.MatchString(table) && !strings.HasPrefix(table, "project.") && indentOf(raw) == 0
		if !cmdKey(strings.ToLower(name)) && !inTable && !(bitrise && strings.EqualFold(name, "content")) {
			continue
		}
		val := strings.TrimSpace(item[len(m[0]):])
		start, text, shell := i, val, true
		switch {
		case val == "" || blockHeaderRE.MatchString(val):
			j := i + 1
			for ; j < len(lines); j++ {
				r := lines[j]
				rt := strings.TrimSpace(r)
				if rt == "" || indentOf(r) > ind || val == "" && indentOf(r) == ind && strings.HasPrefix(rt, "- ") {
					continue
				}
				break
			}
			start, text, shell = i+1, strings.Join(lines[i+1:j], "\n"), val != ""
		case strings.HasPrefix(val, "["):
			j := closing(lines, i, val)
			text, shell = strings.Join(append([]string{val}, lines[i+1:j+1]...), "\n"), false
		case strings.HasPrefix(val, `"""`) || strings.HasPrefix(val, "'''"):
			q := val[:3]
			j := i
			if !strings.Contains(val[3:], q) {
				for j = i + 1; j < len(lines) && !strings.Contains(lines[j], q); j++ {
				}
				j = min(j, len(lines)-1)
			}
			text = strings.Trim(strings.Join(append([]string{val}, lines[i+1:j+1]...), "\n"), `"'`)
		case strings.HasPrefix(val, `"`), strings.HasPrefix(val, "'"), strings.HasPrefix(val, "{"):
			shell = false
		}
		if line, why := v.valueText(text, shell); why != "" {
			return start + line + 1, why
		}
	}
	return 0, ""
}

// backstopJSON reads a decodable JSON file for the command positions backstopLines reads in
// text, whatever its layout, so one written on a single line is read too: every string under a
// cmdKey key or a tasks map is shell text, every array of strings there an argv whose items may
// be shell text, and a key that sets an installer variable in an environment map withholds. It
// returns the 1-based line of the value that withholds, and why.
func (v *Veto) backstopJSON(src string) (int, string) {
	var doc any
	d := json.NewDecoder(strings.NewReader(src))
	d.UseNumber()
	if d.Decode(&doc) != nil {
		return 0, ""
	}
	why, val := v.jsonValue(doc, false, false)
	if why == "" {
		return 0, ""
	}
	at := strings.Index(src, val)
	if at < 0 {
		if b, err := json.Marshal(val); err == nil {
			at = strings.Index(src, string(b))
		}
	}
	return strings.Count(src[:max(at, 0)], "\n") + 1, why
}

// jsonValue gates one decoded JSON value: cmd marks a value under a command key, env an
// environment map. It returns why it withholds and the text that does.
func (v *Veto) jsonValue(x any, cmd, env bool) (string, string) {
	switch t := x.(type) {
	case map[string]any:
		for _, k := range sortedKeys(t) {
			lk := strings.ToLower(k)
			if env && v.setsEnv(k) {
				return "sets an installer variable", k
			}
			c := cmdKey(lk) || lk == "tasks"
			if cmd && !c && dataKeys[lk] {
				continue
			}
			if why, at := v.jsonValue(t[k], cmd || c, envKey(k)); why != "" {
				return why, at
			}
		}
	case []any:
		var words []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				words = append(words, s)
			} else if why, at := v.jsonValue(e, cmd, false); why != "" {
				return why, at
			}
		}
		if cmd && len(words) > 0 {
			segs := []segment{{words: words, expands: hasExpansion(words)}}
			if why := v.segments(append(segs, listCommands(segs)...)); why != "" {
				return why, words[0]
			}
		}
	case string:
		if cmd {
			if why := v.shellText(t, false); why != "" {
				return why, t
			}
		}
	}
	return "", ""
}

// envKeys are the keys, lowercased with - and _ dropped, whose values are environment
// variables a CI system, task runner or hook manager sets for its commands.
var envKeys = map[string]bool{
	"env": true, "environment": true, "variables": true, "vars": true, "defaultenv": true,
	"envvars": true, "environmentvariables": true, "globalenv": true,
}

func envKey(key string) bool {
	return envKeys[strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(strings.Trim(key, `"'`)))]
}

// envParent reports whether lines[i] is an entry of an environment map: the nearest line above
// it with less indent is an envKeys key, or, at the top of a TOML table, the table is named
// for one (an [env] table, [tool.hatch.envs.default.env-vars]).
func envParent(lines []string, i int, table string) bool {
	ind := indentOf(lines[i])
	for j := i - 1; j >= 0 && ind > 0; j-- {
		t := strings.TrimSpace(lines[j])
		if t == "" || lineComment(t) || indentOf(lines[j]) >= ind {
			continue
		}
		m := keyRE.FindStringSubmatch(strings.TrimPrefix(t, "- "))
		return m != nil && envKey(m[1])
	}
	if ind > 0 || table == "" {
		return false
	}
	parts := strings.Split(table, ".")
	return envKey(parts[len(parts)-1])
}

// joined returns the logical line starting at lines[i], backslash continuations joined, and
// the index of its last physical line.
func joined(lines []string, i int) (string, int) {
	var b strings.Builder
	for j := i; j < len(lines); j++ {
		l := lines[j]
		if n := len(l) - len(strings.TrimRight(l, `\`)); n%2 == 1 {
			b.WriteString(l[:len(l)-1])
			b.WriteByte(' ')
			continue
		}
		b.WriteString(l)
		return b.String(), j
	}
	return b.String(), len(lines) - 1
}

// closing returns the index of the line that closes the bracket val, the value on lines[i],
// opens: brackets outside quotes are counted, and an array left open runs to the end.
func closing(lines []string, i int, val string) int {
	depth := 0
	count := func(s string) {
		var q byte
		for k := 0; k < len(s); k++ {
			switch c := s[k]; {
			case q != 0:
				if c == '\\' {
					k++
				} else if c == q {
					q = 0
				}
			case c == '"' || c == '\'':
				q = c
			case c == '#' && depth > 0:
				return
			case c == '[':
				depth++
			case c == ']':
				depth--
			}
		}
	}
	count(val)
	j := i
	for depth > 0 && j+1 < len(lines) {
		j++
		count(lines[j])
	}
	return j
}

// shellText gates shell text: a line that sets an installer variable withholds, and so does
// each simple command that runs an installer. recipe strips a make recipe prefix.
func (v *Veto) shellText(text string, recipe bool) string {
	if v.setsEnv(text) {
		return "sets an installer variable"
	}
	for _, seg := range backstopSegments(text) {
		if why := v.installAt(seg, recipe); why != "" {
			return why
		}
	}
	return ""
}

// valueText gates a command key's value, and returns the 0-based line within text and why it
// withholds. shell reads each line as shell text (a scalar, a block scalar); otherwise each
// line is a data line (a list item, an array element, a quoted scalar, an inline table).
func (v *Veto) valueText(text string, shell bool) (int, string) {
	lines, starts, _ := logicalLinesAt(text)
	for k, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if shell {
			if why := v.shellText(t, false); why != "" {
				return starts[k], why
			}
			continue
		}
		if v.setsEnv(t) {
			return starts[k], "sets an installer variable"
		}
		segs, ok, _ := commandSegments(kindData, t)
		if !ok {
			// An inline table or a fragment of an array: each string in it is a command.
			segs = nil
			for _, lit := range literals(t, false, false) {
				segs = append(segs, backstopSegments(lit.text)...)
			}
		}
		if why := v.segments(append(segs, listCommands(segs)...)); why != "" {
			return starts[k], why
		}
	}
	return 0, ""
}

func (v *Veto) segments(segs []segment) string {
	for _, seg := range segs {
		if why := v.installAt(seg, false); why != "" {
			return why
		}
	}
	return ""
}

// backstopSegments splits shell text into its simple commands, or, when it does not split
// (a brace group, an unclosed quote), returns its words as one command, so a name in it still
// reaches the rule.
func backstopSegments(text string) []segment {
	if segs, ok, _ := shellSegments(text); ok {
		return segs
	}
	return []segment{{words: strings.Fields(text), expands: strings.ContainsAny(text, "$`")}}
}

// listCommands returns the commands a list value holds when its items are shell text, not one
// argv: a hatch script's ["pip install x", "pytest"].
func listCommands(segs []segment) []segment {
	var out []segment
	for _, seg := range segs {
		for _, w := range seg.words {
			if !strings.ContainsAny(w, " \t") {
				continue
			}
			out = append(out, backstopSegments(w)...)
		}
	}
	return out
}

// installAt returns why the command seg withholds, or "". Any command a word of which names a
// lane token, as program, argument, path or the text a shell, eval or interpreter runs, or
// that runs an install verb after an expansion, goes to v.command from a directory it does not
// know, as the same line in install.sh would, unless it only reports (readOnly). recipe strips
// a make recipe prefix (@, - or +) from the program.
func (v *Veto) installAt(seg segment, recipe bool) string {
	words := seg.words
	if len(words) > 0 && recipe {
		if w := strings.TrimLeft(words[0], "@-+"); w != words[0] && w != "" {
			words = append([]string{w}, words[1:]...)
			seg.words = words
		}
	}
	if !v.segmentHasToken(words) && !expandedInstall(words) || v.readOnly(seg) {
		return ""
	}
	return v.command(seg, &hostCursor{v: v, unknown: true}, 0)
}

// readOnlyVerbs are installer subcommands that read or report, run no package script and
// change no installed package. pack and publish are not among them: npm runs a package's
// prepare script for both.
var readOnlyVerbs = map[string]bool{
	"list": true, "ls": true, "view": true, "info": true, "show": true, "freeze": true,
	"search": true, "outdated": true, "why": true, "help": true, "audit": true,
}

// readOnly reports whether seg only reports: it expands nothing and redirects nothing, its
// program past environment assignments and launchers (and past a Python interpreter's -m, or
// a leading -m, an argv after sys.executable) is a lane token, and that installer's first
// operand, past its flags (and past pip or tool for uv pip and uv tool), is a readOnlyVerbs
// verb, or every argument is --version, -v, -V or --help. Any other command naming a token,
// as an argument, in the text a shell or interpreter runs, or after a launcher's value, is not
// read-only.
func (v *Veto) readOnly(seg segment) bool {
	words := seg.words
	if seg.expands || hasRedirect(words) {
		return false
	}
	i := programAt(words)
	if i >= len(words) {
		return false
	}
	name, ok := CommandName(words[i])
	if !ok {
		return false
	}
	if pythonRE.MatchString(name) || name == "py" || name == "-m" {
		if name != "-m" {
			for i++; i < len(words) && strings.HasPrefix(words[i], "-") && words[i] != "-m"; i++ {
			}
		}
		if i+1 >= len(words) || words[i] != "-m" {
			return false
		}
		i++
		name = words[i]
	}
	if !v.spec.Token(name) {
		return false
	}
	rest := words[i+1:]
	if len(rest) == 0 {
		return false
	}
	verb := operand(rest, 0)
	if verb >= 0 && (rest[verb] == "pip" || rest[verb] == "tool") {
		verb = operand(rest, verb+1)
	}
	if verb >= 0 && readOnlyVerbs[rest[verb]] && !(rest[verb] == "audit" && slices.Contains(rest, "fix")) {
		return true
	}
	for _, a := range rest {
		if a != "--version" && a != "-v" && a != "-V" && a != "--help" {
			return false
		}
	}
	return true
}

// operand returns the index of the first word of words at or after from that is not a flag,
// or -1.
func operand(words []string, from int) int {
	for k := from; k < len(words); k++ {
		if !strings.HasPrefix(words[k], "-") {
			return k
		}
	}
	return -1
}

// programAt returns the index of the program words run, past leading environment
// assignments and launchers and their flags.
func programAt(words []string) int {
	i := 0
	for i < len(words) && assignRE.MatchString(words[i]) {
		i++
	}
	for i < len(words) {
		name, ok := CommandName(words[i])
		if !ok || !launchers[name] {
			break
		}
		i++
		for i < len(words) && (strings.HasPrefix(words[i], "-") || assignRE.MatchString(words[i])) {
			i++
		}
	}
	return i
}

// assignRE matches a leading NAME=value environment assignment.
var assignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// launchers run the command that follows them, after their own flags.
var launchers = map[string]bool{
	"sudo": true, "doas": true, "env": true, "exec": true, "time": true, "nohup": true,
	"command": true, "nice": true, "xargs": true, "stdbuf": true, "chronic": true,
	"ionice": true, "timeout": true, "then": true, "do": true, "else": true, "!": true,
}

// literal is one string literal of a file: its text and the byte offsets of its quotes.
type literal struct {
	text     string
	off, end int
}

// maxTemplate bounds how far a backtick literal may run across lines.
const maxTemplate = 8 << 10

// literals returns the string literals of src, outside comments: # comments when hash, //
// and /* */ comments when slash. A ' or " literal ends at its line; a triple-quoted one is a
// docstring and is passed over.
func literals(src string, hash, slash bool) []literal {
	var out []literal
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case hash && c == '#', slash && c == '/' && i+1 < len(src) && src[i+1] == '/':
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(src)
			}
		case slash && c == '/' && i+1 < len(src) && src[i+1] == '*':
			if j := strings.Index(src[i+2:], "*/"); j >= 0 {
				i += j + 3
			} else {
				i = len(src)
			}
		case (c == '"' || c == '\'') && strings.HasPrefix(src[i:], strings.Repeat(string(c), 3)):
			if j := strings.Index(src[i+3:], strings.Repeat(string(c), 3)); j >= 0 {
				i += j + 5
			} else {
				i = len(src)
			}
		case c == '"' || c == '\'' || c == '`':
			var b strings.Builder
			j := i + 1
			for ; j < len(src) && src[j] != c; j++ {
				if src[j] == '\n' && (c != '`' || j-i > maxTemplate) {
					break
				}
				if src[j] == '\\' && j+1 < len(src) {
					j++
				}
				b.WriteByte(src[j])
			}
			if j < len(src) && src[j] == c {
				out = append(out, literal{text: b.String(), off: i, end: j + 1})
			}
			i = j
		}
	}
	return out
}

// execNames are names, lowercased, that run the command given to them.
var execNames = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "x": true, "$": true, "sudo": true, "system": true,
	"call": true, "check_call": true, "check_output": true, "getoutput": true,
	"getstatusoutput": true, "execa": true, "local": true,
}

// execParts are parts, lowercased, of a name that runs the command given to it.
var execParts = []string{"run", "exec", "spawn", "shell", "popen", "cmd", "command", "system"}

// argvNames are the keys, lowercased, that hold a command a later call runs.
var argvNames = map[string]bool{
	"cmd": true, "cmds": true, "command": true, "commands": true, "args": true, "argv": true,
	"cmdline": true, "script": true,
}

// argvParts are parts, lowercased, of a variable name that holds a command a later call runs.
var argvParts = []string{"cmd", "command", "argv", "args"}

// argvVar reports whether an assignment or key, by its name and separator, holds a command: a
// variable assigned with = whose name has an argvParts part (pip_install_command, pytestCmd),
// or a key whose name is an argvNames name. A key is held to its exact name because an
// object's keys describe more than they run (a sandbox config's startCommand).
func argvVar(name, sep string) bool {
	lower := strings.ToLower(name)
	if sep == ":" {
		return argvNames[lower]
	}
	for _, p := range argvParts {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func execName(name string) bool {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(strings.TrimLeft(name, "_"))
	if execNames[name] {
		return true
	}
	for _, p := range execParts {
		if strings.Contains(name, p) {
			return true
		}
	}
	return false
}

var (
	// callerRE matches what runs the literal after it, at the end of the text before it: a
	// call whose first argument it is, alone, first in a list, or second after one expression
	// (run("..."), run(["...", check_call([sys.executable, "..."), or a paren-less call or tag
	// (sh "...", $`...`); its group is the name. A string prefix (f, r, b, u) is part of the
	// literal.
	callerRE = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$.]*)(?:\s*\(\s*\[?\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*,\s*)?|\s+|)(?:[rRbBfFuU]{1,2})?$`)
	// assignRunRE matches an assignment or key that holds a command for a later call
	// (pytest_cmd = [...], command: "..."); its groups are the name and the separator (argvVar).
	assignRunRE = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)["']?\s*([=:])\s*\[?\s*(?:[rRbBfFuU]{1,2})?$`)
	// argvSepRE matches what may separate the words of an argv written as literals, once
	// comments are dropped.
	argvSepRE = regexp.MustCompile(`^[\s,\[(]*$`)
	// sepCommentRE matches a comment between two literals.
	sepCommentRE = regexp.MustCompile(`(?m)(?://|#)[^\n]*$|/\*[\s\S]*?\*/`)
)

// backstopLiterals reads a build script's string literals, and returns the first 1-based line
// where one, or an argv of them, given to a name that runs commands runs an installer, and why.
// hash and slash choose the comments passed over.
func (v *Veto) backstopLiterals(src string, hash, slash bool) (int, string) {
	lits := literals(src, hash, slash)
	lineOf := func(off int) int { return strings.Count(src[:off], "\n") + 1 }
	for i := 0; i < len(lits); i++ {
		l := lits[i]
		before := src[max(0, l.off-120):l.off]
		m := callerRE.FindStringSubmatch(before)
		var api string
		if m != nil {
			if noxInstall(m[1]) {
				return lineOf(l.off), "installs through a nox session: " + m[1]
			}
			api = v.apiToken(m[1])
		}
		if (m == nil || !execName(m[1])) && api == "" {
			if a := assignRunRE.FindStringSubmatch(before); a == nil || !argvVar(a[1], a[2]) {
				continue
			}
		}
		// A run of single-word literals is an argv: subprocess.run(["pip", "install", "x"]),
		// spawn("npm", ["install"]).
		j := i
		for j+1 < len(lits) && singleWord(lits[j].text) && singleWord(lits[j+1].text) &&
			argvSepRE.MatchString(sepCommentRE.ReplaceAllString(src[lits[j].end:lits[j+1].off], "")) {
			j++
		}
		var segs []segment
		if j > i {
			words := make([]string, 0, j-i+2)
			if api != "" {
				words = append(words, api)
			}
			for k := i; k <= j; k++ {
				words = append(words, lits[k].text)
			}
			segs = []segment{{words: words, expands: hasExpansion(words)}}
		} else if api != "" {
			segs = []segment{{words: []string{api, l.text}, expands: strings.ContainsAny(l.text, "$`")}}
		} else {
			segs = backstopSegments(l.text)
		}
		if why := v.segments(segs); why != "" {
			return lineOf(l.off), why
		}
		i = j
	}
	return 0, ""
}

// noxInstall reports whether name is a nox session's install helper (session.install,
// session.run_install), which a helper module a noxfile imports may call.
func noxInstall(name string) bool {
	recv, method, ok := strings.Cut(strings.ToLower(name), ".")
	for ok && strings.Contains(method, ".") {
		recv, method, _ = strings.Cut(method, ".")
	}
	return ok && strings.HasSuffix(recv, "session") && (method == "install" || method == "run_install")
}

// apiToken returns the lane token a dotted call's receiver names, a package manager driven
// through its own API (pip.main, npm.commands.install), or "".
func (v *Veto) apiToken(name string) string {
	parts := strings.Split(name, ".")
	for _, p := range parts[:len(parts)-1] {
		if p = strings.Trim(p, "_"); v.spec.Token(p) {
			return p
		}
	}
	return ""
}

func singleWord(s string) bool { return s != "" && !strings.ContainsAny(s, " \t\n") }
