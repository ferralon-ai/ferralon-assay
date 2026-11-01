package scriptsurface

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
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
//   - every line of a file with a Dockerfile-style FROM line, in any case, and an instruction
//     that runs a command or sets its environment, which the Dockerfile rule reads as it reads
//     a Dockerfile (dockerfileAt), binding what its COPY and ADD bring in;
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
	case mcpConfig(path):
		// An MCP client, an editor or agent host, starts the servers these name, never the
		// build.
		return true
	case lower == "action.yml", lower == "action.yaml":
		// An action a repository publishes for others runs in their workflows, and in its
		// own only when one of them uses an action from the tree.
		return !v.localActions()
	}
	return false
}

// mcpConfig reports whether the file at path is an MCP client's server configuration: a
// .mcp.json (Claude Code, VS Code), .vscode/mcp.json, .cursor/mcp.json, or Claude Desktop's
// claude_desktop_config.json.
func mcpConfig(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.HasSuffix(p, "/.mcp.json"), strings.HasSuffix(p, "/claude_desktop_config.json"),
		strings.HasSuffix(p, "/.vscode/mcp.json"), strings.HasSuffix(p, "/.cursor/mcp.json"):
		return true
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
	if v.placedScript(path, head) {
		return true
	}
	lower := strings.ToLower(filepath.Base(path))
	if testFile(lower, v.dirsOf(path)) {
		return false
	}
	i := strings.IndexByte(lower, '.')
	return (i > 0 && buildScriptStems[lower[:i]] || buildScriptStems[lower]) && !v.packageModule(path)
}

// placedScript reports whether buildScript holds for the file at path by any rule but its
// stem: the one rule that asks packageModule, and so the walk (buildRead).
func (v *Veto) placedScript(path string, head []byte) bool {
	lower := strings.ToLower(filepath.Base(path))
	dirs := v.dirsOf(path)
	if testFile(lower, dirs) {
		return false
	}
	if bytes.HasPrefix(head, []byte("#!")) || strings.Contains(lower, ".config.") {
		return true
	}
	for _, d := range dirs {
		if toolDirs[d] {
			return true
		}
	}
	return false
}

// dirsOf returns the lowercased names of the directories above the file at path, inside the
// build.
func (v *Veto) dirsOf(path string) []string {
	rel, err := filepath.Rel(v.root, filepath.Dir(path))
	if err != nil {
		rel = "."
	}
	return strings.Split(strings.ToLower(filepath.ToSlash(rel)), "/")
}

// packageModule reports whether the file at path is a module of an importable Python package
// that nothing outside Python source mentions: a .py file beside an __init__.py, below the build
// root, which the application imports (mindsdb's integrations/utilities/install.py, poetry's
// console/commands/build.py). Its build-script stem then says nothing about the build running
// it. Any mention of it in a file the backstop reads (mentionSource), by its base name alone
// (build.py) or its package-qualified tail (pkg/build, pkg.build, from pkg import build), makes
// it a build script, and so does a mention in a module already counted that way, until none is
// left: a module counts unless the walk shows otherwise. What stays exempt is a module that only
// modules nobody mentions import.
func (v *Veto) packageModule(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".py") || filepath.Dir(path) == v.root {
		return false
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "__init__.py")); err != nil {
		return false
	}
	b := v.buildRead()
	return b.whole && b.modules[path] && !b.mentioned[path]
}

// buildFiles is what one walk of the build found: the files the build reads (for namedByBuild),
// the package modules with a build-script stem (packageModule) and which of them a text file
// mentions, and whether every entry the walk met was read.
type buildFiles struct {
	files     []buildFile
	modules   map[string]bool
	mentioned map[string]bool
	whole     bool
}

type buildFile struct {
	dir  string
	data []byte
}

// buildNames are the base names of the files the build reads beside the script surfaces: a
// project's own build configuration, wherever a sub-project keeps it.
var buildNames = map[string]bool{"pyproject.toml": true, "setup.py": true, "setup.cfg": true}

// launcherNames are the Python files that run a project's tasks by name; their mentions count
// as any config file's do.
var launcherNames = map[string]bool{"setup.py": true, "noxfile.py": true, "tasks.py": true, "fabfile.py": true}

// buildRead walks the build once. It keeps every script surface (walkedSurface) and every
// buildNames file, and lists every package module with a build-script stem and every text file
// that may mention one (mentionSource), then scans those for mentions (mentions). A directory or
// file that cannot be read, a symlinked directory, or a symlink that leaves the build leaves
// whole false, and then every module counts.
func (v *Veto) buildRead() *buildFiles {
	if v.build != nil {
		return v.build
	}
	b := &buildFiles{whole: true, modules: map[string]bool{}, mentioned: map[string]bool{}}
	var texts []string
	_ = buildtree.Walk(v.root, func(e buildtree.Entry, err error) error {
		if err != nil {
			b.whole = false
			return nil
		}
		if e.D.IsDir() || e.Skipped || v.inGitDir(e.Path) && !v.gitHooksFile(e.Path) || v.sampleHook(e.Path) {
			return nil
		}
		lower := strings.ToLower(e.D.Name())
		named := buildNames[lower]
		if e.Symlink {
			fi, err := os.Stat(e.Path)
			if e.Escapes || err != nil || fi.IsDir() {
				b.whole = false
			} else if _, ok := surfaceOf(e.Path, nil); ok || named {
				b.whole = false
			}
			return nil
		}
		if !e.D.Type().IsRegular() {
			return nil
		}
		head, err := buildtree.Head(e.Path)
		if err != nil {
			b.whole = false
			return nil
		}
		if v.stemModule(e.Path, lower) {
			b.modules[e.Path] = true
		}
		if count, ok := v.mentionSource(e.Path, lower, head); !ok {
			b.whole = false
		} else if count {
			texts = append(texts, e.Path)
		}
		if !named {
			if _, ok := surfaceOf(e.Path, head); !ok {
				return nil
			}
		}
		data, err := v.spec.ReadRegular(e.Path)
		if err != nil {
			b.whole = false
			return nil
		}
		b.files = append(b.files, buildFile{dir: filepath.Dir(e.Path), data: data})
		return nil
	})
	// Each module a pass finds mentioned is itself a build script, so its text is the next
	// pass's source, until a pass finds none new.
	read := map[string]bool{}
	for b.whole && len(b.modules) > 0 {
		b.mentions(v, texts)
		for _, t := range texts {
			read[t] = true
		}
		texts = nil
		for m := range b.mentioned {
			if !read[m] {
				texts = append(texts, m)
			}
		}
		if len(texts) == 0 {
			break
		}
	}
	v.build = b
	return b
}

// stemModule reports whether the regular file at path, with lowercased base name lower, is
// what packageModule asks about: a .py file below the build root, beside an __init__.py, whose
// stem is a buildScriptStems name.
func (v *Veto) stemModule(path, lower string) bool {
	i := strings.IndexByte(lower, '.')
	if !strings.HasSuffix(lower, ".py") || i <= 0 || !buildScriptStems[lower[:i]] || filepath.Dir(path) == v.root {
		return false
	}
	_, err := os.Lstat(filepath.Join(filepath.Dir(path), "__init__.py"))
	return err == nil
}

// mentionSource reports whether a text file may mention a package module to run it, before any
// module counts: every file the backstop reads (backstopSkips), Python source included only for
// a launcherNames file, a build script outside any package (buildScript; packageModule never
// asks about a file without an __init__.py beside it, so the walk does not recurse), or a module
// inside one that is a build script by its place or shebang (placedScript). A module with a
// build-script stem joins once a mention counts it (buildRead). ok is false when the check for
// that __init__.py fails other than by its absence.
func (v *Veto) mentionSource(path, lower string, head []byte) (count, ok bool) {
	if v.backstopSkips(path, head) {
		return false, true
	}
	if filepath.Ext(lower) != ".py" || launcherNames[lower] {
		return true, true
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "__init__.py")); err == nil {
		return v.placedScript(path, head), true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, false
	}
	return v.buildScript(path, head), true
}

// fromImportRE matches a from-import with its names, on one line or across a parenthesised
// group (from pkg import (\n    build,\n)).
var fromImportRE = regexp.MustCompile(`\bfrom[ \t]+([\w.]+)[ \t]+import[ \t]*(\([^)]*\)|[^\n]*)`)

// mentions marks every module in b.modules that one of texts mentions: by its base name alone
// (build.py, whatever path, separator, quoting or join comes before it, so cd pkg && python
// build.py counts), by its tail, the identifier pair <package>.<module>, <package>/<module> or
// <package>\<module>, or by a from-import of the module from its package, each compared whole
// (build_utils is not build). A module whose stem is not one identifier (build.local.py) cannot
// be matched that way, so it counts as mentioned.
func (b *buildFiles) mentions(v *Veto, texts []string) {
	pairs := map[string]map[string][]string{}
	leaves := map[string][]string{}
	for m := range b.modules {
		leaf := strings.TrimSuffix(filepath.Base(m), filepath.Ext(m))
		parent := filepath.Base(filepath.Dir(m))
		if strings.ContainsFunc(leaf, func(r rune) bool { return !identRune(r) }) {
			b.mentioned[m] = true
			continue
		}
		leaves[strings.ToLower(leaf)] = append(leaves[strings.ToLower(leaf)], m)
		if pairs[parent] == nil {
			pairs[parent] = map[string][]string{}
		}
		pairs[parent][leaf] = append(pairs[parent][leaf], m)
	}
	mark := func(parent, leaf []byte) {
		for _, m := range pairs[string(parent)][string(leaf)] {
			b.mentioned[m] = true
		}
	}
	for _, t := range texts {
		data, err := v.spec.ReadRegular(t)
		if err != nil {
			b.whole = false
			return
		}
		pyBasenames(data, func(stem []byte) {
			for _, m := range leaves[string(stem)] {
				b.mentioned[m] = true
			}
		})
		identPairs(data, mark)
		for _, g := range fromImportRE.FindAllSubmatch(data, -1) {
			mod := g[1][bytes.LastIndexByte(g[1], '.')+1:]
			if pairs[string(mod)] == nil {
				continue
			}
			for _, name := range identRE.FindAll(g[2], -1) {
				mark(mod, name)
			}
		}
	}
}

var identRE = regexp.MustCompile(`\w+`)

func identRune(r rune) bool {
	return r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

// pyBasenames calls visit with the lowercased stem of every <identifier>.py in data whose
// identifier starts after a non-identifier byte and whose extension ends before one.
func pyBasenames(data []byte, visit func(stem []byte)) {
	lower := bytes.ToLower(data)
	for off := 0; ; {
		i := bytes.Index(lower[off:], []byte(".py"))
		if i < 0 {
			return
		}
		at := off + i
		off = at + 3
		if off < len(lower) && identRune(rune(lower[off])) {
			continue
		}
		s := at
		for s > 0 && identRune(rune(lower[s-1])) {
			s--
		}
		if s < at {
			visit(lower[s:at])
		}
	}
}

// identPairs calls visit for every two identifiers in data joined by exactly one '.', '/' or
// '\'.
func identPairs(data []byte, visit func(a, b []byte)) {
	var prev []byte
	prevEnd := -2
	for i := 0; i < len(data); {
		if !identRune(rune(data[i])) {
			i++
			continue
		}
		j := i
		for j < len(data) && identRune(rune(data[j])) {
			j++
		}
		if prev != nil && i == prevEnd+1 && (data[prevEnd] == '.' || data[prevEnd] == '/' || data[prevEnd] == '\\') {
			visit(prev, data[i:j])
		}
		prev, prevEnd, i = data[i:j], j, j
	}
}

// namedByBuild reports whether a file the build reads (buildRead) names the file at path by
// its path from the build root or from the naming file's directory, with or without a leading
// src/. When an entry of the build could not be read, every path counts as named.
func (v *Veto) namedByBuild(path string) bool {
	b := v.buildRead()
	if !b.whole {
		return true
	}
	for _, f := range b.files {
		for _, dir := range []string{v.root, f.dir} {
			rel, err := filepath.Rel(dir, path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			rel = filepath.ToSlash(rel)
			if bytes.Contains(f.data, []byte(rel)) || bytes.Contains(f.data, []byte(strings.TrimPrefix(rel, "src/"))) {
				return true
			}
		}
	}
	return false
}

// fixtureExts are the extensions of JSON data files: under a testDirs directory, outside a
// package of its own and named by no file the build reads, one is a test's input, not the
// build's (testFixture).
var fixtureExts = map[string]bool{".json": true, ".jsonc": true, ".json5": true}

// taskStems are the stems of JSON files a task runner reads as its tasks wherever they sit:
// Nx project.json, Deno deno.json(c), turbo.json.
var taskStems = map[string]bool{"project": true, "deno": true, "turbo": true}

// taskJSON reports whether the file at path is one a task runner reads as its tasks: a
// taskStems name with a fixtureExts extension. testFixture never skips one.
func taskJSON(path string) bool {
	lower := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(lower)
	return fixtureExts[ext] && taskStems[strings.TrimSuffix(lower, ext)]
}

// testDirs are directory names that hold tests and their fixtures.
var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "testing": true, "fixtures": true,
	"__fixtures__": true, "testdata": true, "e2e": true,
}

// testFixture reports whether the file at path, not source code, is a test's JSON input: a
// fixtureExts file, not a taskJSON one, under a testDirs directory, whose own directory holds
// no package.json or pyproject.toml (a workspace package the build installs), and which no file
// the build reads names (namedByBuild), as a CI file that uploads or includes it would.
func (v *Veto) testFixture(path string) bool {
	if taskJSON(path) {
		return false
	}
	if !fixtureExts[strings.ToLower(filepath.Ext(path))] || !slices.ContainsFunc(v.dirsOf(path), func(d string) bool { return testDirs[d] }) {
		return false
	}
	for _, m := range []string{"package.json", "pyproject.toml"} {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(path), m)); !errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}
	return !v.namedByBuild(path)
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
	if !source && v.testFixture(path) {
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
		if why == "" {
			if doc, ok := jsonDoc(src); ok {
				line, why = v.backstopJSON(doc)
			} else if taskJSON(path) || strings.EqualFold(filepath.Ext(path), ".json5") {
				line, why = v.backstopStrings(src)
			}
		}
		if why == "" {
			lower := strings.ToLower(filepath.Base(path))
			line, why = v.backstopLines(src, strings.HasPrefix(lower, "bitrise."), filepath.Ext(lower) != ".cue")
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
	// runsRE finds an instruction that runs a command or sets the environment one runs in.
	runsRE = regexp.MustCompile(`(?im)^[ \t]*(?:run|cmd|entrypoint|onbuild|shell|env|arg)(?:[ \t\\\[]|\r?$)`)
)

// dockerLike reports whether a file that is not source code holds a Dockerfile-style FROM
// line and an instruction that runs a command or sets its environment, so the Dockerfile rule
// reads it. A FROM line alone, as SQL has, installs nothing as a Dockerfile and leaves the
// file to the line rules.
func dockerLike(src string) bool {
	return (fromRE.MatchString(src) || fromAnyRE.MatchString(src)) && runsRE.MatchString(src)
}

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
// recipes reads a tab-indented line under a "target:" line as a make recipe; a CUE file has
// none, and its tab-indented fields sit under "name: {" lines shaped as rules.
func (v *Veto) backstopLines(src string, bitrise, recipes bool) (int, string) {
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
			rule = recipes && ruleRE.MatchString(raw)
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
		if !cmdKey(strings.ToLower(name)) && !inTable && !(bitrise && strings.EqualFold(name, "content")) && !taskSteps(table, name) {
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
		case strings.HasPrefix(val, `"`), strings.HasPrefix(val, "'"):
			text, shell = continued(lines, i, ind, val), false
		case strings.HasPrefix(val, "{"):
			shell = false
		default:
			text = continued(lines, i, ind, val)
		}
		if line, why := v.valueText(text, shell); why != "" {
			return start + line + 1, why
		}
	}
	return 0, ""
}

// continued returns the scalar val that starts on lines[i] with its continuation lines, those
// after it indented past ind, joined on with spaces as YAML folds a plain or quoted scalar. A
// comment line folded into a plain scalar stays a shell comment.
func continued(lines []string, i, ind int, val string) string {
	parts := []string{val}
	for j := i + 1; j < len(lines); j++ {
		t := strings.TrimSpace(lines[j])
		if t == "" {
			continue
		}
		if indentOf(lines[j]) <= ind {
			break
		}
		parts = append(parts, t)
	}
	return strings.Join(parts, " ")
}

// taskSteps reports whether key, in the TOML table named table, lists a task's steps: the
// sequence of a poe task or the composite of a pdm script given its own table
// ([tool.poe.tasks.setup]), each step a command or a task name.
func taskSteps(table, key string) bool {
	i := strings.LastIndexByte(table, '.')
	k := strings.ToLower(key)
	return i > 0 && taskTableRE.MatchString(table[:i]) && !strings.HasPrefix(table, "project.") && (k == "sequence" || k == "composite")
}

// jsonDoc returns src as JSON the decoder accepts: src itself, or, for an object or array whose
// comments or trailing commas the decoder rejects (deno.jsonc, a tsconfig-style file, either
// led by a comment), src with those blanked in place, so offsets and lines still match src.
func jsonDoc(src string) (string, bool) {
	if json.Valid([]byte(src)) {
		return src, true
	}
	doc := stripJSONC(src)
	if t := strings.TrimSpace(doc); !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		return "", false
	}
	return doc, json.Valid([]byte(doc))
}

// stripJSONC blanks, outside strings, every // and /* */ comment and every comma that only
// whitespace separates from a closing } or ], keeping newlines.
func stripJSONC(src string) string {
	b := []byte(src)
	blank := func(from, to int) {
		for k := from; k < to; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	str := false
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case str:
			if c == '\\' {
				i++
			} else if c == '"' {
				str = false
			}
		case c == '"':
			str = true
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			end := bytes.IndexByte(b[i:], '\n')
			if end < 0 {
				end = len(b) - i
			}
			blank(i, i+end)
			i += end - 1
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := len(b)
			if j := bytes.Index(b[i+2:], []byte("*/")); j >= 0 {
				end = i + 2 + j + 2
			}
			blank(i, end)
			i = end - 1
		}
	}
	str = false
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case str:
			if c == '\\' {
				i++
			} else if c == '"' {
				str = false
			}
		case c == '"':
			str = true
		case c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				b[i] = ' '
			}
		}
	}
	return string(b)
}

// backstopStrings reads a task runner's JSON or a JSON5 file that does not decode for
// any string that, read as shell text, runs an installer, so a parse failure withholds rather
// than hides one. It returns the 1-based line of that string, and why.
func (v *Veto) backstopStrings(src string) (int, string) {
	for _, lit := range literals(src, false, true) {
		if why := v.segments(backstopSegments(lit.text)); why != "" {
			return strings.Count(src[:lit.off], "\n") + 1, why
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
	return v.segmentsAt(backstopSegments(text), recipe)
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

func (v *Veto) segments(segs []segment) string { return v.segmentsAt(segs, false) }

// segmentsAt gates each command of segs; recipe strips a make recipe prefix. A command piped
// into an interpreter or shell, directly or through other commands, keeps its URL words: what
// it fetches runs. So does an interpreter or shell that runs a process substitution
// (python3 <(curl -sS https://bootstrap.pypa.io/get-pip.py) x), and a command that writes into
// one an interpreter or shell runs (outputSubst); each splits as one command.
func (v *Veto) segmentsAt(segs []segment, recipe bool) string {
	for k, seg := range segs {
		piped := feedsInput(segs, k) || runsInput(seg) && slices.ContainsFunc(seg.words, func(w string) bool { return strings.HasPrefix(w, "<(") }) || outputSubst(seg)
		if why := v.installAt(seg, recipe, piped); why != "" {
			return why
		}
	}
	return ""
}

// outputSubst reports whether seg writes into an output process substitution that runs an
// interpreter or shell (tee >(python3 -), > >(sh), tee >( python3 - )), which splits as one
// command.
func outputSubst(seg segment) bool {
	for i, w := range seg.words {
		rest, ok := strings.CutPrefix(w, ">(")
		if !ok {
			continue
		}
		words := append([]string{rest}, seg.words[i+1:]...)
		if rest == "" {
			words = words[1:]
		}
		if len(words) > 0 {
			words[0] = strings.TrimRight(words[0], ")")
		}
		if runsInput(segment{words: words}) {
			return true
		}
	}
	return false
}

// feedsInput reports whether segs[k] pipes into an interpreter or shell (runsInput), or into a
// command that writes into one (outputSubst), directly or through later commands of the same
// pipeline: a filter between them (tee, sed, grep) passes what was fetched on.
func feedsInput(segs []segment, k int) bool {
	for j := k; segs[j].end == "|" && j+1 < len(segs); j++ {
		if runsInput(segs[j+1]) || outputSubst(segs[j+1]) {
			return true
		}
	}
	return false
}

func runsInput(seg segment) bool {
	i := programAt(seg.words)
	if i >= len(seg.words) {
		return false
	}
	name, ok := CommandName(seg.words[i])
	return ok && (sourceShebangs.MatchString(name) || stdinShells[name])
}

var stdinShells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "mksh": true}

// backstopSegments splits shell text into its simple commands, or, when it does not split
// (a brace group, an unclosed quote, a process substitution), returns its words as one command
// per stage of a pipeline, cut at each | or |&, spaced or not (get-pip.py|python3 -) but never
// within ||, inside a process substitution too, so a name in it still reaches the rule and
// feedsInput still follows the pipe past a tee >(sha256sum) or into tee >(cat | python3 -).
func backstopSegments(text string) []segment {
	if segs, ok, _ := shellSegments(text); ok {
		return segs
	}
	expands := strings.ContainsAny(text, "$`")
	var segs []segment
	var words []string
	for _, w := range strings.Fields(text) {
		for w != "" {
			i := pipeAt(w)
			if i < 0 {
				words = append(words, w)
				break
			}
			if i > 0 {
				words = append(words, w[:i])
			}
			segs = append(segs, segment{words: words, expands: expands, end: "|"})
			words = nil
			w = strings.TrimPrefix(w[i+1:], "&")
		}
	}
	return append(segs, segment{words: words, expands: expands})
}

// pipeAt returns the index in w of the first | that no other | adjoins, or -1.
func pipeAt(w string) int {
	for i := 0; i < len(w); i++ {
		if w[i] != '|' {
			continue
		}
		j := i + 1
		for j < len(w) && w[j] == '|' {
			j++
		}
		if j == i+1 {
			return i
		}
		i = j
	}
	return -1
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
func (v *Veto) installAt(seg segment, recipe, piped bool) string {
	words := seg.words
	if len(words) > 0 && recipe {
		if w := strings.TrimLeft(words[0], "@-+"); w != words[0] && w != "" {
			words = append([]string{w}, words[1:]...)
			seg.words = words
		}
	}
	named := words
	if !piped {
		named = slices.DeleteFunc(slices.Clone(words), urlRE.MatchString)
	}
	if !v.segmentHasToken(named) && !expandedInstall(words) || v.readOnly(seg) {
		return ""
	}
	return v.command(seg, &hostCursor{v: v, unknown: true}, 0)
}

// urlRE matches a word that is only a URL. A URL is an argument, never what a command runs,
// and its host and path name things (grafana-build-pipeline) that read as installer tokens.
var urlRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://\S*$`)

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
	verb := verbAt(rest, 0)
	if verb >= 0 && (rest[verb] == "pip" || rest[verb] == "tool") {
		verb = verbAt(rest, verb+1)
	}
	if verb >= 0 && readOnlyVerbs[rest[verb]] && !(rest[verb] == "audit" && slices.ContainsFunc(rest, auditFix)) {
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

// verbAt returns the index of the first word of words at or after from that is not a flag,
// past only flags that take no value (bareFlags) or carry theirs (--cache-dir=x), or -1: a
// flag that may take the next word as its value hides which word is the verb.
func verbAt(words []string, from int) int {
	for k := from; k < len(words); k++ {
		w := words[k]
		if !strings.HasPrefix(w, "-") {
			return k
		}
		if !bareFlags[w] && !strings.Contains(w, "=") {
			return -1
		}
	}
	return -1
}

// bareFlags are installer flags that take no value.
var bareFlags = map[string]bool{
	"-q": true, "-qq": true, "--quiet": true, "-v": true, "-vv": true, "--verbose": true,
	"-s": true, "--silent": true, "--json": true, "--long": true, "--no-color": true,
	"--no-input": true, "--isolated": true, "--disable-pip-version-check": true,
	"--offline": true, "--frozen": true, "--locked": true, "--no-cache": true, "-g": true,
	"--global": true, "-y": true, "--yes": true, "--all": true,
}

// auditFix reports whether w asks an audit to fix what it finds: npm audit fix, pnpm audit
// --fix.
func auditFix(w string) bool { return w == "fix" || w == "--fix" || strings.HasPrefix(w, "--fix=") }

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
			if v.spec.Token("pip") && noxInstall(m[1]) {
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

// apiToken returns the lane token a dotted call's leading receiver names, a package manager
// driven through its own API (pip.main, npm.commands.install), or "". A token later in the
// chain is an attribute (self.poetry.pyproject.data.get), not the module called.
func (v *Veto) apiToken(name string) string {
	parts := strings.Split(name, ".")
	if p := strings.Trim(parts[0], "_"); len(parts) > 1 && v.spec.Token(p) {
		return p
	}
	return ""
}

func singleWord(s string) bool { return s != "" && !strings.ContainsAny(s, " \t\n") }
