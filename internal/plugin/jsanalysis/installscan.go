package jsanalysis

// installscan.go positively rules out out-of-manifest npm installs, which class (i) needs: a
// package the lockfile marks dev-only is not installed at runtime only if nothing on the build
// or deploy path installs it some other way. The scan is inverted: it does not look for known
// surfaces and trust the rest, it walks the whole build dir with internal/plugin/buildtree's
// rule (treewalk.go): every directory but a node_modules or site-packages is entered, a symlink
// is never followed, and a symlinked directory is read only through its target, when the walk
// itself enters that target inside the build dir. Every file that could run an install must
// parse fully, and every entry the walk cannot read is a failure, or every refutation is
// withheld. Skipping a directory for this walk
// is not ignoring it for the install set: a committed node_modules is in the install set
// through the committed-tree sweep (gitindex.go, loadset.go).
//
// A file is a candidate when its name or place makes it one, or when its text carries an
// install token (installToken):
//
//   - Dockerfile*/Containerfile*/*.dockerfile/*.containerfile, in any directory: RUN (heredocs
//     too), CMD, ENTRYPOINT, HEALTHCHECK and ONBUILD, with lockfile provenance tracked through
//     COPY/ADD, bind mounts, stages and .dockerignore, and scripts the image runs by path read
//     where they came from (installdocker.go);
//   - Makefile/GNUmakefile/*.mk, justfile, Procfile*, shell scripts (*.sh/.bash/.zsh, or an sh
//     shebang) in any directory, test directories included, buildpack bin/ hooks, Elastic
//     Beanstalk .platform hooks and .ebextensions, and git hooks that are not samples;
//   - every package.json's scripts, every .npmrc, and every GitHub workflow and local action;
//   - docker-compose command/entrypoint, .gitlab-ci.yml, cloudbuild*, Jenkinsfile*;
//   - render.yaml, fly.toml, railway.json/toml, nixpacks.toml, app.yaml, heroku.yml, app.json,
//     netlify.toml, vercel.json, amplify.yml, and the other CI dialects (CircleCI, Azure,
//     Bitbucket, Travis, CodeBuild, Drone, Buildkite, AppVeyor, Woodpecker, Taskfile), read by
//     command-bearing keys;
//   - any other file with an install token: a JSON, YAML or TOML file must carry every such
//     string under a command key, which is then parsed; any other file (JavaScript, Python,
//     an Earthfile, ...) cannot be parsed for its installs and withholds every refutation.
//     Documentation (Markdown, reStructuredText, AsciiDoc, plain text, HTML, README/CHANGELOG/
//     LICENSE/CONTRIBUTING), lockfiles and binary files are not candidates, and neither is git's
//     own data under .git beyond its hooks;
//   - the install lifecycle scripts (preinstall, install, postinstall, prepare) of every package
//     in the production install closure, and the files they run (lifecycle).
//
// Only a lockfile install whose lockfile is provably the lane-read one passes. Everything else
// that installs withholds every refutation: a package named on the command line (npm install
// x, npm i -g x, yarn add x, npx/pnpm dlx/yarn dlx/bunx of a package that is not a bin of the
// production install, and the rest of installcmd.go), a variable or substitution in the
// arguments, a lockfile install in a directory whose lane-read lockfile is not the one that
// installs, a workspace selector, a flag the parser does not model, config that changes what
// installs (.npmrc, npm_config_* in the environment), a known install family the parser does
// not model, an unreadable file or directory, a symlink that leaves the build dir or names a
// directory, and a candidate that does not parse. The same walk feeds the prod-keeps-dev check
// (prodinstall.go).

import (
	"bytes"
	"encoding/json"
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

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

type installScan struct {
	m         *installModel   // nil: only the prod-keeps-dev check runs
	installed map[string]bool // the production install closure, by install path
	real      string
	scanned   []string
	all       string   // non-empty: every refutation is withheld, and why
	keepDev   []string // prod-keeps-dev hits, "<file>: <command>"
	workflows []ghFile // read during the walk, judged for prod-keeps-dev after it

	roots      []string // build-relative lockfile roots (for the node_modules copy check)
	dockers    []scannedFile
	contexts   []string // explicit docker build contexts, build-relative
	ctxUnknown string   // a docker build context the scanner could not resolve
}

type scannedFile struct {
	rel  string
	data []byte
}

func (sc *installScan) vetoAll(file, why string) {
	if sc.all == "" {
		sc.all = file + ": " + why
	}
}

func (sc *installScan) hit(label, cmd string) {
	sc.keepDev = append(sc.keepDev, label+": "+cmd)
}

// keepDevText runs the prod-keeps-dev check over text.
func (sc *installScan) keepDevText(label, text string, docker bool) {
	if cmd := keepsDevInstall(text, docker); cmd != "" {
		sc.hit(label, cmd)
	}
}

// scanBuild walks buildReal once. m supplies the lane-read lockfiles and installed the
// production install closure; with m nil only the prod-keeps-dev check runs.
func scanBuild(buildReal string, m *installModel, installed map[string]bool) *installScan {
	sc := &installScan{m: m, installed: installed, real: buildReal}
	for _, r := range discoverProjectRoots(buildReal) {
		rel, _ := filepath.Rel(buildReal, r)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = ""
		}
		sc.roots = append(sc.roots, rel)
	}
	fail := func(rel, why string) {
		sc.vetoAll(rel, why)
		sc.hit(rel, why)
	}
	walkTree(buildReal, func(path, rel string, d fs.DirEntry) error {
		sc.file(path, rel, d.Name())
		return nil
	}, fail)
	sc.judgeWorkflows()
	for _, f := range sc.dockers {
		sc.dockerfile(f)
	}
	sc.lifecycle()
	sort.Strings(sc.keepDev)
	return sc
}

type surface int

const (
	surfNone surface = iota
	surfDocker
	surfMake
	surfProcfile
	surfShell
	surfPackageJSON
	surfWorkflow
	surfAction
	surfCompose
	surfGitLab
	surfCloudBuild
	surfJenkins
	surfPlatform // deploy config read by command keys, commands run in its directory
	surfCI       // CI config read by command keys, commands run at the repo root
	surfNpmrc
	surfKeyedUnknown // config read by command keys, commands run in a directory it does not say
	surfToken        // no known kind, but its text carries an install token
	surfGitData      // git's own data under .git: not a candidate
)

var platformFiles = map[string]bool{
	"render.yaml": true, "render.yml": true, "fly.toml": true, "railway.json": true, "railway.toml": true,
	"nixpacks.toml": true, "nixpacks.json": true, "app.yaml": true, "app.yml": true, "heroku.yml": true,
	"app.json": true, "netlify.toml": true, "vercel.json": true, "now.json": true, "amplify.yml": true,
	"amplify.yaml": true, ".platform.app.yaml": true, "Taskfile.yml": true, "Taskfile.yaml": true,
	"taskfile.yml": true, "taskfile.yaml": true,
}

var ciFiles = map[string]bool{
	"bitbucket-pipelines.yml": true, ".travis.yml": true, ".drone.yml": true, "appveyor.yml": true,
	".appveyor.yml": true, ".woodpecker.yml": true, ".woodpecker.yaml": true,
}

func yamlExt(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	return ext == ".yml" || ext == ".yaml"
}

// buildpackHooks are the scripts a buildpack (in-repo bin/) or the Heroku Python buildpack's
// bin/pre_compile and bin/post_compile hooks run during the build.
var buildpackHooks = map[string]bool{
	"compile": true, "pre_compile": true, "post_compile": true, "detect": true, "release": true,
	"supply": true, "finalize": true,
}

func surfaceOf(rel, name string, data []byte) surface {
	lower := strings.ToLower(name)
	dir := path.Dir(rel)
	if underGit(rel) {
		if path.Base(dir) == "hooks" && path.Base(path.Dir(dir)) == ".git" && !strings.HasSuffix(name, ".sample") {
			return surfShell
		}
		return surfGitData
	}
	switch {
	case strings.HasPrefix(name, "Dockerfile") || strings.HasPrefix(name, "Containerfile") ||
		strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile"):
		if strings.HasSuffix(lower, ".dockerignore") || strings.HasSuffix(lower, ".containerignore") {
			return surfNone
		}
		return surfDocker
	case name == "Makefile" || name == "makefile" || name == "GNUmakefile" || path.Ext(lower) == ".mk" ||
		lower == "justfile" || lower == ".justfile":
		return surfMake
	case strings.HasPrefix(name, "Procfile"):
		return surfProcfile
	case name == "package.json":
		return surfPackageJSON
	case name == ".npmrc":
		return surfNpmrc
	case dir == ".github/workflows" && yamlExt(name):
		return surfWorkflow
	case lower == "action.yml" || lower == "action.yaml":
		return surfAction
	case yamlExt(name) && (strings.HasPrefix(lower, "docker-compose") || strings.HasPrefix(lower, "compose.") ||
		lower == "compose.yml" || lower == "compose.yaml"):
		return surfCompose
	case name == ".gitlab-ci.yml" || strings.HasSuffix(name, ".gitlab-ci.yml"):
		return surfGitLab
	case strings.HasPrefix(lower, "cloudbuild") && (yamlExt(name) || path.Ext(lower) == ".json"):
		return surfCloudBuild
	case strings.HasPrefix(name, "Jenkinsfile"):
		return surfJenkins
	case platformFiles[name]:
		return surfPlatform
	case ciFiles[name] || (dir == ".circleci" && yamlExt(name)) || (dir == ".buildkite" && yamlExt(name)) ||
		(dir == ".woodpecker" && yamlExt(name)) || (strings.HasPrefix(lower, "azure-pipelines") && yamlExt(name)) ||
		(strings.HasPrefix(lower, "buildspec") && yamlExt(name)):
		return surfCI
	case path.Base(dir) == ".ebextensions" && path.Ext(lower) == ".config":
		return surfKeyedUnknown
	case path.Base(dir) == "bin" && buildpackHooks[name],
		strings.HasPrefix(rel, ".platform/hooks/") || strings.HasPrefix(rel, ".platform/confighooks/"):
		return surfShell
	}
	switch path.Ext(lower) {
	case ".sh", ".bash", ".zsh":
		return surfShell
	case "":
		if shellShebang(data) {
			return surfShell
		}
	}
	if docFile(lower) || isLockName(name) || binaryText(data) || !installToken.Match(data) {
		return surfNone
	}
	return surfToken
}

// underGit reports whether rel lies inside a .git directory.
func underGit(rel string) bool {
	for _, seg := range strings.Split(path.Dir(rel), "/") {
		if seg == ".git" {
			return true
		}
	}
	return false
}

// docFile reports whether a (lower-cased) file name is documentation, data or styling: text
// that is read or rendered, and that no shell, build tool or runtime executes as a command.
func docFile(lower string) bool {
	switch path.Ext(lower) {
	case ".md", ".markdown", ".mdx", ".rst", ".adoc", ".asciidoc", ".txt", ".html", ".htm",
		".csv", ".tsv", ".css", ".scss", ".sass", ".less", ".map", ".svg":
		return true
	}
	for _, p := range []string{"readme", "changelog", "license", "licence", "contributing", "history", "authors", "notice"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// binaryText reports whether data looks binary: a NUL byte in its first 8000 bytes, git's own
// test.
func binaryText(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// installToken matches text that may run an npm-ecosystem install: a package manager (or a
// clone of one) followed on the same line by an install subcommand, a package runner, a bare
// or quoted yarn at a command position, or a command of an install family the scanner does not
// parse. A match makes a file a candidate; it never clears one.
var installToken = regexp.MustCompile(`(?m)` +
	`\b(?:npm|pnpm|bun|cnpm|tnpm|deno|volta)\b[^\n;&|]{0,80}?\s(?:install|i|in|isntall|add|a|ci|clean-install|ic|install-clean|it|install-test|cit|install-ci-test|dlx|exec|x|update|up|upgrade|udpate|link|ln|create|init|global|dedupe|ddp|fetch|import|audit|cache)\b` +
	`|\byarn\b[^\n;&|]{0,80}?\s(?:install|add|dlx|global|workspaces?|up|upgrade|upgrade-interactive|create|link|import|dedupe|--frozen-lockfile|--immutable)\b` +
	`|(?:^|[;&|(]|\b(?:then|do|else)\s)\s*yarn\s*(?:$|[;&|)]|-)` +
	"|[\"'`]yarn[\"'`]" +
	`|\b(?:npx|pnpx|bunx|nlx|nci|nup|npminstall|nypm)\b\s+\S` +
	`|\b(?:lerna\s+(?:bootstrap|add|link|exec)|rush\s+(?:install|update|add)|yalc\s+(?:add|link|update)|jspm\s+(?:install|i|link))\b` +
	`|(?:^|[;&|(]\s*)(?:ni|na|bolt)(?:\s+[\w@.-]|\s*$)`)

// shellShebang reports whether data starts with a POSIX-shell shebang.
func shellShebang(data []byte) bool {
	first, _, _ := bytes.Cut(data, []byte("\n"))
	if !bytes.HasPrefix(first, []byte("#!")) {
		return false
	}
	f2 := strings.Fields(string(first[2:]))
	if len(f2) == 0 {
		return false
	}
	interp := path.Base(f2[0])
	if interp == "env" && len(f2) > 1 {
		interp = f2[1]
		if interp == "-S" && len(f2) > 2 {
			interp = f2[2]
		}
	}
	switch interp {
	case "sh", "bash", "zsh", "dash", "ash", "ksh":
		return true
	}
	return false
}

func (sc *installScan) file(p, rel, name string) {
	if underGit(rel) && surfaceOf(rel, name, nil) == surfGitData {
		return
	}
	data, err := readRegular(p)
	if err != nil {
		sc.vetoAll(rel, "unreadable")
		sc.hit(rel, "unreadable")
		return
	}
	kind := surfaceOf(rel, name, data)
	if kind == surfNone || kind == surfGitData {
		return
	}
	sc.scanned = append(sc.scanned, rel)
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	text := string(data)
	if kind != surfNpmrc {
		sc.npmConfigText(rel, text)
	}
	switch kind {
	case surfDocker:
		sc.dockers = append(sc.dockers, scannedFile{rel: rel, data: data})
	case surfMake:
		sc.keepDevText(rel, text, false)
		sc.shell(text, shellCtx{file: rel, dir: knownDirs(dir), resetPerLine: !strings.Contains(text, ".ONESHELL")})
	case surfProcfile:
		if name == "Procfile" {
			sc.keepDevText(rel, text, false)
		}
		sc.shell(text, shellCtx{file: rel, dir: knownDirs(dir), resetPerLine: true})
	case surfShell:
		sc.keepDevText(rel, text, false)
		sc.shell(text, shellCtx{file: rel, dir: knownDirs(dir, "")})
	case surfPackageJSON:
		sc.packageScripts(rel, dir, data)
	case surfNpmrc:
		sc.npmrc(rel, text)
	case surfWorkflow:
		sc.workflow(rel, name, data)
	case surfAction:
		sc.action(rel, data)
	case surfCompose:
		sc.compose(rel, dir, data)
	case surfGitLab:
		sc.gitlab(rel, data)
	case surfCloudBuild:
		sc.cloudbuild(rel, data)
	case surfJenkins:
		sc.jenkins(rel, dir, text)
	case surfPlatform:
		sc.keyed(rel, data, knownDirs(dir), dir)
	case surfCI:
		sc.keyed(rel, data, knownDirs(""), "")
	case surfKeyedUnknown:
		sc.keyed(rel, data, cwd{unknown: true}, dir)
	case surfToken:
		sc.tokenFile(rel, data)
	}
}

// tokenFile reads a file that is a candidate only for the install token in its text. JSON,
// YAML and TOML are walked: a token-bearing string under a command key is parsed as shell (in
// a directory the file does not say), and one anywhere else withholds every refutation, as
// does a file in any other format.
func (sc *installScan) tokenFile(rel string, data []byte) {
	switch strings.ToLower(path.Ext(rel)) {
	case ".json", ".yaml", ".yml", ".toml":
	default:
		sc.vetoAll(rel, "carries an install command the scanner does not parse")
		return
	}
	v, err := parseConfig(rel, data)
	if err != nil {
		sc.unparsed(rel, "config")
		return
	}
	var all []string
	sc.walkKeyed(rel, v, false, cwd{unknown: true}, &all)
	sc.keepDevText(rel, strings.Join(all, "\n"), false)
}

func (sc *installScan) unparsed(rel, what string) {
	sc.vetoAll(rel, "unparseable "+what)
	sc.hit(rel, "unparseable "+what)
}

// packageScripts scans every script of a package.json; npm runs them in the package dir.
func (sc *installScan) packageScripts(rel, dir string, data []byte) {
	var p struct {
		Scripts map[string]any `json:"scripts"`
	}
	if json.Unmarshal(data, &p) != nil {
		sc.unparsed(rel, "package.json")
		return
	}
	keys := make([]string, 0, len(p.Scripts))
	for k := range p.Scripts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s, ok := p.Scripts[k].(string)
		if !ok {
			sc.unparsed(rel, "package.json script "+k)
			continue
		}
		label := rel + " scripts." + k
		sc.keepDevText(label, s, false)
		sc.shell(s, shellCtx{file: label, dir: knownDirs(dir)})
	}
}

// npmrc reads an .npmrc. npm's ini parser takes a bare key as key=true. A key that changes
// what an install puts on disk either is modelled (the dev-group keys: forcing dev dependencies
// in is a prod-keeps-dev hit) or withholds every refutation; a line the parser cannot read
// withholds every refutation too. The file applies wherever npm reads it, so its directory is
// not consulted.
func (sc *installScan) npmrc(rel, text string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			sc.vetoAll(rel, line+": an ini section the scanner does not read")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			v = "true"
		}
		sc.npmConfig(rel, line, k, v, true)
	}
}

// npmConfigEnv finds npm_config_* settings in a candidate's text (an environment assignment
// in a Dockerfile, a script, a workflow or a deploy config).
var npmConfigEnv = regexp.MustCompile(`(?i)\bnpm_config_([a-z0-9_-]+)(?:[ \t]*[=:][ \t]*|[ \t]+)?["']?([^\s"';&|]*)`)

func (sc *installScan) npmConfigText(rel, text string) {
	for _, m := range npmConfigEnv.FindAllStringSubmatch(text, -1) {
		sc.npmConfig(rel, strings.TrimSpace(m[0]), m[1], m[2], false)
	}
}

// npmDevKeys select which dependency groups an install keeps; the rest of npmInstallKeys
// change where or how it installs, or from what. The value each maps to is the one setting
// that leaves the install as the lockfile describes it.
var (
	npmDevKeys     = map[string]bool{"production": true, "dev": true, "include": true, "also": true, "omit": true, "only": true}
	npmInstallKeys = map[string]string{
		"global": "false", "location": "project", "package-lock": "true", "install-strategy": "hoisted",
		"global-style": "false", "legacy-bundling": "false", "workspace": "", "workspaces": "false",
		"include-workspace-root": "false", "prefix": "", "userconfig": "", "globalconfig": "", "before": "",
		"install-links": "false", "shrinkwrap": "true",
	}
)

// npmConfig judges one npm config setting. fromRc: it came from an .npmrc, where a dev-forcing
// value is a prod-keeps-dev hit here (prodinstall.go models the same settings in the
// environment).
func (sc *installScan) npmConfig(rel, line, key, val string, fromRc bool) {
	k := strings.TrimSuffix(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "_", "-"), "[]")
	v := strings.ToLower(strings.Trim(strings.TrimSpace(val), `"'`))
	if safe, ok := npmInstallKeys[k]; ok {
		if v != safe || safe == "" {
			sc.vetoAll(rel, line+": npm config "+k+" changes what an install puts on disk")
		}
		return
	}
	if !npmDevKeys[k] {
		return
	}
	switch {
	case v == "" || dynamicTok(v):
		sc.vetoAll(rel, line+": npm config "+k+" set to a value the scanner cannot read")
	case k == "production" && (v == "true" || v == "false"),
		(k == "include" || k == "also") && (strings.Contains(v, "dev") || v == "optional" || v == "peer"),
		k == "omit" && strings.Contains(v, "dev"),
		k == "only" && strings.HasPrefix(v, "prod"):
		// Modelled: prodinstall.go reads these from the environment and the command line.
		if fromRc && ((k == "production" && v == "false") || ((k == "include" || k == "also") && strings.Contains(v, "dev"))) {
			sc.hit(rel, line)
		}
	default:
		sc.vetoAll(rel, line+": npm config "+k+"="+v+" is not modelled")
	}
}

// --- GitHub ---------------------------------------------------------------------------

type ghDefaults struct {
	Run struct {
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

type ghStep struct {
	Uses             string         `yaml:"uses"`
	Run              string         `yaml:"run"`
	WorkingDirectory string         `yaml:"working-directory"`
	With             map[string]any `yaml:"with"`
}

type ghWorkflow struct {
	Name     string           `yaml:"name"`
	On       yaml.Node        `yaml:"on"`
	Defaults ghDefaults       `yaml:"defaults"`
	Jobs     map[string]ghJob `yaml:"jobs"`
}

type ghJob struct {
	Environment yaml.Node  `yaml:"environment"`
	Needs       yaml.Node  `yaml:"needs"`
	Uses        string     `yaml:"uses"`
	Defaults    ghDefaults `yaml:"defaults"`
	Steps       []ghStep   `yaml:"steps"`
}

// ghFile is a workflow read during the walk.
type ghFile struct {
	rel, name string
	wf        ghWorkflow
}

// nodeWords returns a scalar's value, a sequence's scalar values, or a mapping's keys.
func nodeWords(n yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	case yaml.MappingNode:
		var out []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
		return out
	}
	return nil
}

// judgeWorkflows runs the prod-keeps-dev check over the workflows the walk read. When any
// workflow consumes another run's output (a workflow_run trigger, or download-artifact with a
// run-id), what any workflow builds may ship, so every job of every workflow is judged.
func (sc *installScan) judgeWorkflows() {
	crossRun := false
	for _, f := range sc.workflows {
		if slicesContains(nodeWords(f.wf.On), "workflow_run") {
			crossRun = true
		}
		for _, j := range f.wf.Jobs {
			for _, st := range j.Steps {
				if _, ok := st.With["run-id"]; ok && strings.HasPrefix(strings.ToLower(st.Uses), "actions/download-artifact") {
					crossRun = true
				}
			}
		}
	}
	for _, f := range sc.workflows {
		sc.keepDev = append(sc.keepDev, sc.workflowKeepsDev(f.rel, f.name, f.wf, crossRun)...)
	}
}

type ghAction struct {
	Runs struct {
		Steps      []ghStep `yaml:"steps"`
		Args       []string `yaml:"args"`
		Entrypoint string   `yaml:"entrypoint"`
	} `yaml:"runs"`
}

func ghDir(base cwd, wds ...string) cwd {
	for _, wd := range wds {
		if wd != "" {
			return base.cd(wd, false)
		}
	}
	return base
}

func (sc *installScan) ghSteps(label string, steps []ghStep, dir cwd) {
	npmAt := map[string]bool{} // the job's steps run in order on one machine
	for _, s := range steps {
		if s.Run != "" {
			sc.shell(s.Run, shellCtx{file: label, dir: ghDir(dir, s.WorkingDirectory), npmAt: npmAt})
		}
		if c, ok := s.With["context"]; ok {
			sc.addContext(fmt.Sprint(c), knownDirs(""))
		}
	}
}

func (sc *installScan) workflow(rel, name string, data []byte) {
	var wf ghWorkflow
	if yaml.Unmarshal(data, &wf) != nil {
		sc.vetoAll(rel, "unparseable workflow")
		sc.hit(rel, "unparseable workflow")
		return
	}
	for _, id := range sortedJobIDs(wf.Jobs) {
		job := wf.Jobs[id]
		sc.ghSteps(rel+" job "+id, job.Steps, ghDir(knownDirs(""), job.Defaults.Run.WorkingDirectory, wf.Defaults.Run.WorkingDirectory))
	}
	sc.workflows = append(sc.workflows, ghFile{rel: rel, name: name, wf: wf})
}

func (sc *installScan) action(rel string, data []byte) {
	var a ghAction
	if yaml.Unmarshal(data, &a) != nil {
		sc.unparsed(rel, "action")
		return
	}
	sc.ghSteps(rel, a.Runs.Steps, knownDirs(""))
	if a.Runs.Entrypoint != "" || len(a.Runs.Args) > 0 {
		sc.shell(strings.TrimSpace(a.Runs.Entrypoint+" "+strings.Join(a.Runs.Args, " ")), shellCtx{file: rel, dir: cwd{unknown: true}})
	}
}

// --- docker-compose --------------------------------------------------------------------

func (sc *installScan) compose(rel, dir string, data []byte) {
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		sc.unparsed(rel, "compose file")
		return
	}
	names := make([]string, 0, len(doc.Services))
	for n := range doc.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		svc := doc.Services[n]
		label := rel + " service " + n
		for _, k := range []string{"command", "entrypoint"} {
			if v, ok := svc[k]; ok && v != nil {
				text := commandText(v)
				sc.keepDevText(label, text, false)
				sc.shell(text, shellCtx{file: label, dir: cwd{unknown: true}})
			}
		}
		switch b := svc["build"].(type) {
		case string:
			sc.addContext(b, knownDirs(dir))
		case map[string]any:
			c, ok := b["context"]
			if !ok {
				c = "."
			}
			sc.addContext(fmt.Sprint(c), knownDirs(dir))
		}
	}
}

// commandText renders a command given as a string or a list of words.
func commandText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprint(v)
}

// addContext records a docker build context, relative to the directories it is named from.
func (sc *installScan) addContext(c string, from cwd) {
	if dynamicTok(c) || strings.Contains(c, "://") || strings.HasPrefix(c, "git@") || c == "-" {
		if sc.ctxUnknown == "" {
			sc.ctxUnknown = c
		}
		return
	}
	d := from.cd(c, false)
	if d.unknown {
		if sc.ctxUnknown == "" {
			sc.ctxUnknown = c
		}
		return
	}
	sc.contexts = append(sc.contexts, d.dirs...)
}

// dockerBuild records the context of a `docker build` style command.
func (sc *installScan) dockerBuild(args []string, dir cwd, ctx *shellCtx) {
	pos := positionals(args, func(f string) bool {
		switch f {
		case "-f", "--file", "-t", "--tag", "--build-arg", "--target", "--platform", "--label", "--secret",
			"--ssh", "--cache-from", "--cache-to", "-o", "--output", "--progress", "--network", "--add-host",
			"--iidfile", "--metadata-file", "--builder", "--build-context", "--shm-size", "--ulimit":
			return true
		}
		return false
	})
	switch {
	case len(pos) >= 1 && (pos[0] == "build" || pos[0] == "bud"):
		pos = pos[1:]
	case len(pos) >= 2 && (pos[0] == "buildx" || pos[0] == "image") && pos[1] == "build":
		pos = pos[2:]
	default:
		return
	}
	if len(pos) == 0 {
		return
	}
	if ctx.docker != nil {
		sc.addContext("$", dir)
		return
	}
	sc.addContext(pos[len(pos)-1], dir)
}

// gcloudSource records `gcloud builds submit [dir]` and `gcloud run deploy --source dir`.
func (sc *installScan) gcloudSource(args []string, dir cwd, ctx *shellCtx) {
	a := parseArgs(args, func(f string) bool {
		return f == "--source" || f == "--config" || f == "--tag" || f == "--region" || f == "--project"
	})
	pos := cleaned(a.pos)
	if len(pos) >= 2 && pos[0] == "builds" && pos[1] == "submit" {
		src := "."
		if len(pos) > 2 {
			src = pos[2]
		}
		sc.addContext(src, dir)
	}
	if v := a.values("--source"); len(v) > 0 {
		sc.addContext(v[0], dir)
	}
	_ = ctx
}

// --- GitLab ----------------------------------------------------------------------------

var gitlabReserved = map[string]bool{
	"default": true, "include": true, "stages": true, "variables": true, "workflow": true, "image": true,
	"services": true, "cache": true, "before_script": true, "after_script": true, "types": true,
}

type gitlabDoc struct {
	rel  string
	jobs map[string]*yaml.Node
	sc   *installScan
	bad  string
}

func (sc *installScan) gitlab(rel string, data []byte) {
	var root yaml.Node
	if yaml.Unmarshal(data, &root) != nil || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		sc.unparsed(rel, "GitLab CI file")
		return
	}
	top := root.Content[0]
	g := &gitlabDoc{rel: rel, jobs: map[string]*yaml.Node{}, sc: sc}
	var order []string
	for i := 0; i+1 < len(top.Content); i += 2 {
		k, v := top.Content[i].Value, top.Content[i+1]
		if k == "include" {
			sc.vetoAll(rel, "include: is not followed")
			sc.hit(rel, "include: is not followed")
			return
		}
		if !gitlabReserved[k] && v.Kind == yaml.MappingNode {
			g.jobs[k] = v
			order = append(order, k)
		}
	}
	defaults := map[string]*yaml.Node{}
	for _, k := range []string{"before_script", "after_script"} {
		if n := mapGet(top, k); n != nil {
			defaults[k] = n
		}
		if d := mapGet(top, "default"); d != nil {
			if n := mapGet(d, k); n != nil {
				defaults[k] = n
			}
		}
	}
	for _, k := range []string{"before_script", "after_script"} {
		if n := defaults[k]; n != nil {
			sc.shell(strings.Join(g.lines(n, 0), "\n"), shellCtx{file: rel + " " + k, dir: knownDirs("")})
		}
	}
	sort.Strings(order)
	for _, id := range order {
		job := g.jobs[id]
		if t := mapGet(job, "trigger"); t != nil && (t.Kind != yaml.MappingNode || mapGet(t, "include") != nil) {
			sc.vetoAll(rel, "job "+id+" triggers a child pipeline that is not followed")
			sc.hit(rel, "job "+id+" triggers a child pipeline that is not followed")
		}
		for _, k := range []string{"before_script", "script", "after_script"} {
			if n := mapGet(job, k); n != nil {
				sc.shell(strings.Join(g.lines(n, 0), "\n"), shellCtx{file: rel + " job " + id, dir: knownDirs("")})
			}
		}
	}
	// prod-keeps-dev: once any job deploys, every job, with its extends chain and default
	// scripts. Stages pass artifacts forward, so what any job installs may ship.
	mergedJobs := map[string]map[string]*yaml.Node{}
	anyDeploy := false
	for _, id := range order {
		if strings.HasPrefix(id, ".") {
			continue
		}
		if merged := g.merged(id, map[string]bool{}); merged != nil {
			mergedJobs[id] = merged
			anyDeploy = anyDeploy || gitlabDeploy(id, merged)
		}
	}
	for _, id := range order {
		merged := mergedJobs[id]
		if merged == nil || !anyDeploy {
			continue
		}
		var text []string
		for _, k := range []string{"before_script", "script", "after_script"} {
			n := merged[k]
			if n == nil && k != "script" {
				n = defaults[k]
			}
			if n != nil {
				text = append(text, g.lines(n, 0)...)
			}
		}
		sc.keepDevText(rel+" job "+id, strings.Join(text, "\n"), false)
	}
	if g.bad != "" {
		sc.vetoAll(rel, g.bad)
		sc.hit(rel, g.bad)
	}
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// lines flattens a script value: a string, a (nested) list, or a !reference to another job's key.
func (g *gitlabDoc) lines(n *yaml.Node, depth int) []string {
	if depth > 10 {
		g.fail("!reference nesting too deep")
		return nil
	}
	switch {
	case n.Tag == "!reference":
		var path []string
		for _, c := range n.Content {
			path = append(path, c.Value)
		}
		if len(path) < 2 || g.jobs[path[0]] == nil {
			g.fail("unresolved !reference " + strings.Join(path, "."))
			return nil
		}
		cur := g.jobs[path[0]]
		for _, k := range path[1:] {
			cur = mapGet(cur, k)
			if cur == nil {
				g.fail("unresolved !reference " + strings.Join(path, "."))
				return nil
			}
		}
		return g.lines(cur, depth+1)
	case n.Kind == yaml.ScalarNode:
		return []string{n.Value}
	case n.Kind == yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, g.lines(c, depth+1)...)
		}
		return out
	}
	g.fail("script is neither a string nor a list")
	return nil
}

func (g *gitlabDoc) fail(why string) {
	if g.bad == "" {
		g.bad = why
	}
}

// merged resolves a job's extends chain into one key map (the child's keys win).
func (g *gitlabDoc) merged(id string, seen map[string]bool) map[string]*yaml.Node {
	job := g.jobs[id]
	if job == nil || seen[id] {
		g.fail("unresolved extends " + id)
		return nil
	}
	seen[id] = true
	out := map[string]*yaml.Node{}
	if ext := mapGet(job, "extends"); ext != nil {
		var parents []string
		switch ext.Kind {
		case yaml.ScalarNode:
			parents = []string{ext.Value}
		case yaml.SequenceNode:
			for _, c := range ext.Content {
				parents = append(parents, c.Value)
			}
		}
		for _, p := range parents {
			pm := g.merged(p, seen)
			if pm == nil {
				return nil
			}
			for k, v := range pm {
				out[k] = v
			}
		}
	}
	for i := 0; i+1 < len(job.Content); i += 2 {
		out[job.Content[i].Value] = job.Content[i+1]
	}
	delete(seen, id)
	return out
}

func gitlabDeploy(id string, job map[string]*yaml.Node) bool {
	if env := job["environment"]; env != nil {
		if name := environmentName(*env); name != nil && !nonDeployEnvironments[strings.ToLower(*name)] {
			return true
		}
	}
	if st := job["stage"]; st != nil && deployWord.MatchString(st.Value) {
		return true
	}
	return deployWord.MatchString(id)
}

// --- Cloud Build -----------------------------------------------------------------------

var builderTools = map[string]bool{"npm": true, "yarn": true, "pnpm": true, "docker": true, "gcloud": true, "git": true, "kubectl": true, "gsutil": true}

func (sc *installScan) cloudbuild(rel string, data []byte) {
	var doc struct {
		Steps []struct {
			Name       string   `yaml:"name"`
			Entrypoint string   `yaml:"entrypoint"`
			Args       []string `yaml:"args"`
			Script     string   `yaml:"script"`
			Dir        string   `yaml:"dir"`
		} `yaml:"steps"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		sc.unparsed(rel, "Cloud Build config")
		return
	}
	var all []string
	for i, s := range doc.Steps {
		text := s.Script
		if text == "" {
			cmd := s.Entrypoint
			if cmd == "" {
				img := s.Name
				if j := strings.LastIndexByte(img, '/'); j >= 0 {
					img = img[j+1:]
				}
				img, _, _ = strings.Cut(img, ":")
				img, _, _ = strings.Cut(img, "@")
				if builderTools[img] {
					cmd = img
				}
			}
			text = strings.TrimSpace(cmd + " " + strings.Join(s.Args, " "))
		}
		all = append(all, text)
		dir := knownDirs("")
		if s.Dir != "" {
			dir = dir.cd(s.Dir, false)
		}
		sc.shell(text, shellCtx{file: fmt.Sprintf("%s step %d", rel, i), dir: dir})
	}
	sc.keepDevText(rel, strings.Join(all, "\n"), false)
}

// --- Jenkins ---------------------------------------------------------------------------

// jenkins scans every string literal in a Jenkinsfile as shell text: sh/bat steps are string
// literals, and a literal that is not a command parses as nothing.
func (sc *installScan) jenkins(rel, dir, text string) {
	var lits []string
	for i := 0; i < len(text); i++ {
		switch {
		case strings.HasPrefix(text[i:], "//"):
			if j := strings.IndexByte(text[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(text)
			}
		case strings.HasPrefix(text[i:], "/*"):
			if j := strings.Index(text[i+2:], "*/"); j >= 0 {
				i += j + 3
			} else {
				i = len(text)
			}
		case strings.HasPrefix(text[i:], `"""`) || strings.HasPrefix(text[i:], `'''`):
			q := text[i : i+3]
			end := strings.Index(text[i+3:], q)
			if end < 0 {
				sc.unparsed(rel, "Jenkinsfile (unterminated string)")
				return
			}
			lits = append(lits, text[i+3:i+3+end])
			i += end + 5
		case text[i] == '"' || text[i] == '\'':
			q := text[i]
			j := i + 1
			for j < len(text) && text[j] != q && text[j] != '\n' {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			if j < len(text) {
				lits = append(lits, text[i+1:j])
			}
			i = j
		}
	}
	d := knownDirs(dir)
	if strings.Contains(text, "dir(") || strings.Contains(text, "ws(") {
		d = cwd{unknown: true}
	}
	joined := strings.Join(lits, "\n")
	sc.keepDevText(rel, joined, false)
	for _, l := range lits {
		sc.shell(l, shellCtx{file: rel, dir: d})
	}
}

// --- keyed configs (platform and other CI dialects) ------------------------------------

var commandKeys = map[string]bool{
	"run": true, "script": true, "scripts": true, "before_script": true, "after_script": true,
	"before_install": true, "install": true, "after_install": true, "before_deploy": true, "deploy": true,
	"after_deploy": true, "after_success": true, "after_failure": true, "before_cache": true, "command": true,
	"commands": true, "cmd": true, "cmds": true, "entrypoint": true, "args": true, "bash": true, "sh": true,
	"release": true, "build": true, "start": true, "web": true, "worker": true, "postdeploy": true,
	"pr-predestroy": true, "processes": true, "phases": true, "steps": true,
}

var dirKeys = map[string]bool{
	"working-directory": true, "working_directory": true, "working_dir": true, "workdir": true, "dir": true,
	"rootdir": true, "rootdirectory": true, "root_dir": true, "base": true,
}

func isCommandKey(k string) bool {
	k = strings.ToLower(k)
	return commandKeys[k] || strings.HasSuffix(k, "command") || strings.HasSuffix(k, "commands") ||
		strings.HasSuffix(k, "_script") || strings.HasSuffix(k, "cmd") || strings.HasSuffix(k, "cmds")
}

// argvHeads are the keys whose list value is an argv that a sibling args list continues.
var argvHeads = map[string]bool{"command": true, "entrypoint": true, "cmd": true}

// stringList returns v as a non-empty list of strings.
func stringList(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok || len(l) == 0 {
		return nil, false
	}
	out := make([]string, len(l))
	for i, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// shellQuote quotes s as one shell word.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`|&;<>()*?[]{}~#!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// parseConfig parses a JSON, TOML or YAML file by its extension (YAML by default).
func parseConfig(rel string, data []byte) (any, error) {
	var v any
	var err error
	switch strings.ToLower(path.Ext(rel)) {
	case ".toml":
		err = toml.Unmarshal(data, &v)
	case ".json":
		err = json.Unmarshal(data, &v)
	default:
		err = yaml.Unmarshal(data, &v)
	}
	return v, err
}

// keyed scans a YAML/JSON/TOML config by its command-bearing keys. Commands run in base,
// moved by any directory key beside them. Docker contexts named by dockerContext keys, and a
// fly.toml's own directory, join the build contexts. A string carrying an install token
// anywhere but under a command key withholds every refutation.
func (sc *installScan) keyed(rel string, data []byte, base cwd, dir string) {
	v, err := parseConfig(rel, data)
	if err != nil {
		sc.unparsed(rel, "config")
		return
	}
	if path.Base(rel) == "fly.toml" {
		sc.contexts = append(sc.contexts, dir)
	}
	var all []string
	sc.walkKeyed(rel, v, false, base, &all)
	sc.keepDevText(rel, strings.Join(all, "\n"), false)
}

// bareTools are package-manager names a config may hold as a plain value (lerna's npmClient,
// a packageManager-style setting): a string that is only one of them names a tool, it does
// not run one.
var bareTools = map[string]bool{"npm": true, "yarn": true, "pnpm": true, "bun": true}

func (sc *installScan) walkKeyed(rel string, v any, inCmd bool, dir cwd, all *[]string) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := t[k].(string); ok && dirKeys[strings.ToLower(k)] {
				dir = dir.cd(s, false)
			}
			if s, ok := t[k].(string); ok && (strings.EqualFold(k, "dockerContext") || strings.EqualFold(k, "docker_context")) {
				sc.addContext(s, dir)
			}
		}
		// An argv list (a container's command or entrypoint, then its args) is one command:
		// shelling each element alone would read "sh" of "sh -c ..." as a shell on stdin. A
		// string head with an args list (Cloud Build's entrypoint: npm, args: [ci]) is the
		// command its args continue.
		var argv []string
		head := ""
		done := map[string]bool{}
		args, hasArgs := []string(nil), false
		for _, k := range keys {
			if l, ok := stringList(t[k]); ok && strings.EqualFold(k, "args") {
				args, hasArgs, done[k] = l, true, true
			}
		}
		for _, k := range keys {
			if !argvHeads[strings.ToLower(k)] || argv != nil || head != "" {
				continue
			}
			if l, ok := stringList(t[k]); ok {
				argv, done[k] = l, true
			} else if s, ok := t[k].(string); ok && hasArgs {
				head, done[k] = s, true
			}
		}
		argv = append(argv, args...)
		if len(argv) > 0 || head != "" {
			q := make([]string, 0, len(argv)+1)
			if head != "" {
				q = append(q, head)
			}
			for _, a := range argv {
				q = append(q, shellQuote(a))
			}
			cmd := strings.Join(q, " ")
			*all = append(*all, cmd)
			sc.shell(cmd, shellCtx{file: rel, dir: dir})
			// A list of command lines reads the same way as an argv; an element with spaces that
			// is not a -c operand is also shelled on its own.
			for i, a := range argv {
				if strings.ContainsAny(a, " \t\n") && (i == 0 || argv[i-1] != "-c") {
					sc.shell(a, shellCtx{file: rel, dir: dir})
				}
			}
		}
		for _, k := range keys {
			if !done[k] {
				sc.walkKeyed(rel, t[k], inCmd || isCommandKey(k), dir, all)
			}
		}
	case []map[string]any:
		for _, e := range t {
			sc.walkKeyed(rel, e, inCmd, dir, all)
		}
	case []any:
		for _, e := range t {
			sc.walkKeyed(rel, e, inCmd, dir, all)
		}
	case string:
		switch {
		case inCmd:
			*all = append(*all, t)
			sc.shell(t, shellCtx{file: rel, dir: dir})
		case !bareTools[strings.TrimSpace(t)] && installToken.MatchString(t):
			line := strings.Join(strings.Fields(t), " ")
			if len(line) > 160 {
				line = line[:160] + "..."
			}
			sc.vetoAll(rel, line+": an install command outside any key the scanner reads as a command")
		}
	}
}

// --- install lifecycle -------------------------------------------------------------------

// lifecycleKeys are the scripts npm runs when it installs a package (prepare for git and
// directory dependencies).
var lifecycleKeys = []string{"preinstall", "install", "postinstall", "prepare"}

// lifecycle scans the install lifecycle of every package in the production install closure. A
// package whose lockfile entry says it has an install script must have its package.json on
// disk; its lifecycle scripts are parsed as shell in the package directory; and, since a
// script may run any file the package ships, every file of a package with a lifecycle script
// (its own package.json, lockfiles, documentation, binaries and nested node_modules aside) is
// a candidate whose install token withholds every refutation. Packages outside the
// production closure are not read: their scripts run only where dev dependencies install,
// which the prod-keeps-dev check already withholds.
func (sc *installScan) lifecycle() {
	if sc.m == nil {
		return
	}
	paths := make([]string, 0, len(sc.installed))
	for p := range sc.installed {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		in := sc.m.inst[p]
		if in == nil {
			continue
		}
		abs := filepath.Join(sc.real, filepath.FromSlash(p))
		data, err := readRegular(filepath.Join(abs, "package.json"))
		switch {
		case os.IsNotExist(err):
			if in.installScript {
				sc.vetoAll(p, "has an install script the scanner cannot read: the package is not on disk")
			}
			continue
		case err != nil:
			sc.vetoAll(p+"/package.json", "unreadable")
			continue
		}
		var pj struct {
			Scripts map[string]any `json:"scripts"`
		}
		if json.Unmarshal(data, &pj) != nil {
			sc.vetoAll(p+"/package.json", "unparseable package.json of an installed package")
			continue
		}
		has := false
		for _, k := range lifecycleKeys {
			v, ok := pj.Scripts[k]
			if !ok {
				continue
			}
			has = true
			text, ok := v.(string)
			if !ok {
				sc.vetoAll(p+"/package.json", "scripts."+k+" is not a string")
				continue
			}
			sc.shell(text, shellCtx{file: p + "/package.json scripts." + k, dir: knownDirs(p)})
		}
		if has || in.installScript {
			sc.packageFiles(p, abs)
		}
	}
}

// packageFiles withholds every refutation when a file of the installed package at p carries
// an install token.
func (sc *installScan) packageFiles(p, abs string) {
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || !buildtree.Inside(sc.real, abs) {
		sc.vetoAll(p, "installed package with an install script does not resolve inside the build dir")
		return
	}
	walkTree(real, func(path, rel string, d fs.DirEntry) error {
		label := joinRel(p, rel)
		if rel == "package.json" || isLockName(d.Name()) || docFile(strings.ToLower(d.Name())) {
			return nil
		}
		data, err := readRegular(path)
		if err != nil {
			sc.vetoAll(label, "unreadable file of an installed package with an install script")
			return filepath.SkipAll
		}
		if !binaryText(data) && installToken.Match(data) {
			sc.vetoAll(label, "an installed package with an install script ships an install command the scanner does not parse")
			return filepath.SkipAll
		}
		return nil
	}, func(rel, why string) {
		sc.vetoAll(joinRel(p, rel), why+" in an installed package with an install script")
	})
}

// --- result ----------------------------------------------------------------------------

// note is the refutation-detail clause naming what the scan read.
func (sc *installScan) note() string {
	if sc == nil {
		return ""
	}
	shown := sc.scanned
	if len(shown) > 8 {
		shown = shown[:8]
	}
	s := fmt.Sprintf("; no out-of-manifest install in %d scanned files", len(sc.scanned))
	if len(shown) > 0 {
		s += ": " + strings.Join(shown, ", ")
		if len(sc.scanned) > len(shown) {
			s += fmt.Sprintf(", +%d more", len(sc.scanned)-len(shown))
		}
	}
	return s
}
