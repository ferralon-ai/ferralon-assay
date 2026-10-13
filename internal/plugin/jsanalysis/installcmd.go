package jsanalysis

// installcmd.go parses shell text for npm-ecosystem installs on behalf of installscan.go. Only
// two commands pass: a lockfile install with no arguments, every flag modelled, in a directory
// whose lane-read lockfile is the one that installs, and a package runner (npx, npm exec,
// bunx) of a bin that such an install already put at the top of node_modules from the
// production install, earlier in the same image stage or script. Everything else that installs
// withholds every refutation: a package named on the command line or through a runner, global
// install or initializer, a link, a workspace selector, an unmodelled flag, a variable, and a
// known install family the parser does not model. A known family is a veto, never a skip.

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

// cwd is the set of directories a command may run in: build-relative, or container paths
// inside a Dockerfile. unknown means the scanner cannot say.
type cwd struct {
	dirs    []string
	unknown bool
}

func knownDirs(dirs ...string) cwd {
	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return cwd{dirs: out}
}

// cd returns the directories after changing into arg. container allows absolute paths
// (inside an image they are known); elsewhere an absolute path leaves the build dir.
func (c cwd) cd(arg string, container bool) cwd {
	arg = cleanTok(arg)
	if arg == "" || arg == "-" || dynamicTok(arg) || strings.HasPrefix(arg, "~") || hasGlob(arg) {
		return cwd{unknown: true}
	}
	if strings.HasPrefix(arg, "/") {
		if !container {
			return cwd{unknown: true}
		}
		return knownDirs(path.Clean(arg))
	}
	if c.unknown {
		return cwd{unknown: true}
	}
	out := make([]string, 0, len(c.dirs))
	for _, d := range c.dirs {
		var j string
		if container {
			if d == "" {
				return cwd{unknown: true}
			}
			j = path.Join(d, arg)
		} else {
			j = joinRel(d, arg)
			if j == "." {
				j = ""
			}
			if j == ".." || strings.HasPrefix(j, "../") {
				return cwd{unknown: true}
			}
		}
		out = append(out, j)
	}
	return knownDirs(out...)
}

// shellCtx says where a block of shell text runs.
type shellCtx struct {
	file         string
	dir          cwd
	resetPerLine bool       // Makefile recipes: every line is its own shell
	docker       *dockerRun // inside a Dockerfile: lockfile provenance comes from the image state
	// npmAt records the build-relative directories where a passing npm lockfile install ran
	// earlier in this script (or GitHub job), for the runner exception. Unused in a Dockerfile,
	// whose stages record their own.
	npmAt map[string]bool
	depth int // script-by-path nesting inside a Dockerfile
}

var (
	redirectTok  = regexp.MustCompile(`^\d*(?:>>?|<|>&|&>)`)
	heredocStart = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)
	validNpmName = regexp.MustCompile(`^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$`)
	installTools = map[string]bool{"npm": true, "npx": true, "pnpx": true, "yarn": true, "pnpm": true, "bun": true, "bunx": true}
	installSubs  = map[string]bool{"install": true, "i": true, "in": true, "add": true, "a": true, "ci": true, "dlx": true, "exec": true, "x": true, "update": true, "up": true, "upgrade": true, "create": true, "init": true, "link": true, "global": true}
	// unparsedTools are install families the parser does not model, by command, with the
	// subcommands that install (nil: every invocation).
	unparsedTools = map[string]map[string]bool{
		"ni": nil, "nci": nil, "nlx": nil, "nup": nil, "na": nil, "nun": nil, "bolt": nil, "cnpm": nil,
		"tnpm": nil, "npminstall": nil, "nypm": nil,
		"lerna": {"bootstrap": true, "add": true, "link": true, "exec": true, "import": true},
		"rush":  {"install": true, "update": true, "add": true, "upgrade-interactive": true, "remove": true},
		"yalc":  {"add": true, "link": true, "update": true, "retreat": true},
		"jspm":  {"install": true, "i": true, "link": true, "update": true},
	}
	shellTools = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true}
	// nodeCLIs maps a package manager's CLI script, run with node, to the manager.
	nodeCLIs = regexp.MustCompile(`^(?:(npm)-cli\.js|(yarn)(?:-[\w.-]+)?\.c?js|(pnpm)(?:-[\w.-]+)?\.c?js)$`)
)

// shell scans a block of shell text. A passing npm lockfile install counts for the runner
// exception on the rest of its own line, and, through ctx.npmAt, in the texts scanned after
// this one with the same map (the later steps of a GitHub job); never on a later line of the
// same text, whose order of execution a function definition can change.
func (sc *installScan) shell(text string, ctx shellCtx) {
	shared := ctx.npmAt
	if shared == nil {
		shared = map[string]bool{}
	}
	done := map[string]bool{}
	text = strings.ReplaceAll(text, "\\\r\n", " ")
	text = strings.ReplaceAll(text, "\\\n", " ")
	dir := ctx.dir
	for _, line := range strings.Split(text, "\n") {
		if ctx.resetPerLine {
			dir = ctx.dir
		}
		ctx.npmAt = map[string]bool{}
		for d := range shared {
			ctx.npmAt[d] = true
		}
		for _, seg := range segmentSplit.Split(line, -1) {
			dir = sc.segment(seg, dir, &ctx)
		}
		// A command substitution runs its own commands. The line was scanned as written (a
		// substitution in an install's arguments vetoes there); its bodies are scanned again as
		// commands of their own. A second pass only adds vetoes.
		if sub := substitutionStart.ReplaceAllString(line, " ; "); sub != line {
			subDir := dir
			for _, seg := range segmentSplit.Split(sub, -1) {
				subDir = sc.segment(seg, subDir, &ctx)
			}
		}
		for d := range ctx.npmAt {
			done[d] = true
		}
	}
	for d := range done {
		shared[d] = true
	}
}

var substitutionStart = regexp.MustCompile("\\$\\(|`|[<>]\\(")

// segment scans one simple command and returns the working directory after it.
func (sc *installScan) segment(seg string, dir cwd, ctx *shellCtx) cwd {
	raw := strings.Fields(seg)
	var toks []string
	for i := 0; i < len(raw); i++ {
		t := raw[i]
		if strings.HasPrefix(t, "#") {
			break
		}
		if t == "&" {
			continue
		}
		if redirectTok.MatchString(t) {
			if strings.TrimLeft(t, "0123456789<>&") == "" {
				i++ // the target is the next token
			}
			continue
		}
		toks = append(toks, t)
	}
	if len(toks) == 0 {
		return dir
	}
	line := strings.Join(toks, " ")
	if len(line) > 160 {
		line = line[:160] + "..."
	}
	for i, t := range toks {
		if cleanTok(t) == "xargs" {
			for _, u := range toks[i+1:] {
				if installTools[path.Base(cleanTok(u))] {
					sc.vetoAll(ctx.file, line+": xargs feeds an install its arguments")
					return dir
				}
			}
		}
	}
	rest, _, _ := stripCommandPrefix(toks)
	if len(rest) == 0 {
		return dir
	}
	head := rest[0]
	if dynamicTok(head) {
		for _, a := range rest[1:] {
			if installSubs[cleanTok(a)] {
				sc.vetoAll(ctx.file, line+": a variable names the command running an install subcommand")
				break
			}
		}
		return dir
	}
	tool := path.Base(cleanTok(head))
	args := rest[1:]
	if shellTools[tool] && !strings.Contains(seg, "<") {
		script := false
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				script = true
				break
			}
		}
		if !script {
			sc.vetoAll(ctx.file, line+": runs shell text from standard input the scanner cannot read")
			return dir
		}
	}
	switch tool {
	case "cd", "pushd":
		if len(args) == 0 {
			return cwd{unknown: true}
		}
		return dir.cd(args[0], ctx.docker != nil)
	case "popd":
		return cwd{unknown: true}
	case "npm":
		sc.npm(args, dir, ctx, line)
	case "npx", "pnpx", "bunx":
		sc.runner(tool, args, dir, ctx, line)
	case "yarn":
		sc.yarn(args, dir, ctx, line, false)
	case "pnpm":
		sc.pnpm(args, dir, ctx, line)
	case "bun":
		sc.bun(args, dir, ctx, line)
	case "deno":
		sc.deno(args, ctx, line)
	case "volta":
		if p := positionals(args, nil); len(p) > 0 && (p[0] == "install" || p[0] == "fetch") {
			sc.vetoAll(ctx.file, line+": volta installs tools by name, outside the lockfile")
		}
	case "node", "nodejs":
		return sc.nodeCLI(args, dir, ctx, line)
	case "ncu", "npm-check-updates":
		sc.ncu(args, ctx, line)
	case "docker", "podman", "nerdctl", "buildah":
		sc.dockerBuild(args, dir, ctx)
	case "gcloud":
		sc.gcloudSource(args, dir, ctx)
	default:
		if subs, ok := unparsedTools[tool]; ok {
			p := positionals(args, nil)
			if subs == nil || len(p) > 0 && subs[p[0]] {
				sc.vetoAll(ctx.file, line+": "+tool+" install commands are not parsed")
			}
		}
		if ctx.docker != nil {
			ctx.docker.lockMove(tool, args)
			ctx.docker.script(tool, head, args, dir, ctx, line)
		}
	}
	return dir
}

// nodeCLI handles `node <cli.js> ...` for a package manager's CLI script, and vetoes a
// variable script followed by an install subcommand.
func (sc *installScan) nodeCLI(args []string, dir cwd, ctx *shellCtx, line string) cwd {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if dynamicTok(a) {
			for _, b := range args[i+1:] {
				if installSubs[cleanTok(b)] {
					sc.vetoAll(ctx.file, line+": a variable names the script running an install subcommand")
					break
				}
			}
			return dir
		}
		m := nodeCLIs.FindStringSubmatch(path.Base(cleanTok(a)))
		switch {
		case m == nil:
		case m[1] != "":
			sc.npm(args[i+1:], dir, ctx, line)
		case m[2] != "":
			sc.yarn(args[i+1:], dir, ctx, line, false)
		case m[3] != "":
			sc.pnpm(args[i+1:], dir, ctx, line)
		}
		return dir
	}
	return dir
}

// cleanTok drops shell quoting and the punctuation of JSON or Groovy lists around a token.
func cleanTok(t string) string {
	t = strings.Trim(t, `"'`)
	t = strings.TrimRight(t, ",;)]}")
	t = strings.TrimLeft(t, "([{")
	return strings.Trim(t, `"'`)
}

func dynamicTok(t string) bool { return strings.ContainsAny(t, "$`") }

func hasGlob(t string) bool { return strings.ContainsAny(t, "*?[") }

// argSpec parses a tool's arguments: value flags consume the next token, "--" ends flags.
type argSpec struct {
	pos   []string
	flags map[string][]string // flag -> values ("" for a boolean)
}

func (a argSpec) has(names ...string) bool {
	for _, n := range names {
		if _, ok := a.flags[n]; ok {
			return true
		}
	}
	return false
}

func (a argSpec) values(names ...string) []string {
	var out []string
	for _, n := range names {
		for _, v := range a.flags[n] {
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func parseArgs(args []string, valueFlag func(flag string) bool) argSpec {
	out := argSpec{flags: map[string][]string{}}
	for i := 0; i < len(args); i++ {
		raw := args[i]
		t := cleanTok(raw)
		switch {
		case t == "--":
			for _, r := range args[i+1:] {
				out.pos = append(out.pos, r)
			}
			return out
		case strings.HasPrefix(t, "-") && len(t) > 1:
			if k, v, ok := strings.Cut(t, "="); ok {
				out.flags[k] = append(out.flags[k], v)
				continue
			}
			if valueFlag != nil && valueFlag(t) && i+1 < len(args) {
				i++
				v := args[i]
				if !dynamicTok(v) {
					v = cleanTok(v)
				}
				out.flags[t] = append(out.flags[t], v)
				continue
			}
			out.flags[t] = append(out.flags[t], "")
		default:
			out.pos = append(out.pos, raw)
		}
	}
	return out
}

func positionals(args []string, valueFlag func(string) bool) []string {
	var out []string
	for _, p := range parseArgs(args, valueFlag).pos {
		out = append(out, cleanTok(p))
	}
	return out
}

// withDir applies a --prefix/--cwd/-C style flag to the working directory.
func withDir(dir cwd, a argSpec, ctx *shellCtx, names ...string) cwd {
	for _, n := range names {
		for _, v := range a.flags[n] {
			if v == "" || dynamicTok(v) {
				return cwd{unknown: true}
			}
			dir = dir.cd(v, ctx.docker != nil)
		}
	}
	return dir
}

var npmValueFlags = map[string]bool{
	"--prefix": true, "-C": true, "--cache": true, "--registry": true, "--tag": true, "--omit": true,
	"--include": true, "--also": true, "--only": true, "--loglevel": true, "-w": true, "--workspace": true,
	"--userconfig": true, "--globalconfig": true, "--install-strategy": true, "--before": true,
	"--fetch-timeout": true, "--fetch-retries": true, "--save-prefix": true, "--node-options": true,
	"--script-shell": true, "--init-module": true, "--lockfile-version": true, "--location": true,
	"--cpu": true, "--os": true, "--libc": true, "--logs-dir": true, "--color": true,
	"--fetch-retry-mintimeout": true, "--fetch-retry-maxtimeout": true, "--maxsockets": true,
}

// npmInstallFlags are the flags an argument-less npm install or ci may carry and still install
// what the lockfile describes (with the dependency groups prodinstall.go models). Any other
// flag withholds every refutation.
var npmInstallFlags = map[string]bool{
	"--ignore-scripts": true, "--no-audit": true, "--audit": true, "--no-fund": true, "--fund": true,
	"--prefer-offline": true, "--offline": true, "--prefer-online": true, "--loglevel": true, "--silent": true,
	"-s": true, "--quiet": true, "-q": true, "--verbose": true, "-d": true, "-dd": true, "-ddd": true,
	"--progress": true, "--no-progress": true, "--update-notifier": true, "--no-update-notifier": true,
	"--cache": true, "--registry": true, "--foreground-scripts": true, "--no-save": true, "--save": true,
	"--legacy-peer-deps": true, "--strict-peer-deps": true, "--production": true, "--omit": true,
	"--include": true, "--also": true, "--only": true, "--prefix": true, "-C": true, "--no-optional": true,
	"--unsafe-perm": true, "--package-lock-only": true, "--dry-run": true, "--color": true, "--no-color": true,
	"--fetch-timeout": true, "--fetch-retries": true, "--fetch-retry-mintimeout": true,
	"--fetch-retry-maxtimeout": true, "--maxsockets": true, "--node-options": true, "--script-shell": true,
	"--no-bin-links": true, "--bin-links": true, "--engine-strict": true, "--lockfile-version": true,
	"--timing": true, "--logs-dir": true, "--package-lock": true, "--location": true,
}

// npmSelectors pick workspaces; the scanner does not model which packages they install.
var npmSelectors = []string{"-w", "--workspace", "--workspaces", "-ws", "--include-workspace-root"}

// npm parses one npm invocation.
func (sc *installScan) npm(args []string, dir cwd, ctx *shellCtx, line string) {
	sub := ""
	for _, t := range positionals(args, func(f string) bool { return npmValueFlags[f] }) {
		sub = t
		break
	}
	execFlags := func(f string) bool {
		return npmValueFlags[f] || f == "-p" || f == "--package" || f == "-c" || f == "--call"
	}
	a := parseArgs(args, func(f string) bool {
		if sub == "exec" || sub == "x" {
			return execFlags(f)
		}
		return npmValueFlags[f]
	})
	pos := a.pos
	if len(pos) > 0 {
		pos = pos[1:]
	}
	dir = withDir(dir, a, ctx, "--prefix", "-C")
	global := a.has("-g", "--global") || slicesContains(a.values("--location"), "global") ||
		slicesContains(a.values("--global"), "true")
	installing := true
	switch sub {
	case "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add",
		"it", "install-test", "cit", "install-ci-test", "ci", "clean-install", "ic", "install-clean",
		"isntall-clean", "update", "up", "upgrade", "udpate", "exec", "x", "link", "ln", "dedupe", "ddp",
		"audit", "init", "create", "innit", "explore":
	default:
		installing = false
	}
	if installing && a.has(npmSelectors...) {
		sc.vetoAll(ctx.file, line+": a workspace selector installs packages the scanner does not model")
		return
	}
	switch sub {
	case "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add",
		"it", "install-test", "cit", "install-ci-test":
		if len(pos) > 0 {
			sc.names(ctx, line, pos)
			return
		}
		if global {
			sc.vetoAll(ctx.file, line+": a global install with no package installs the working directory")
			return
		}
		if a.has("--no-package-lock") || slicesContains(a.values("--package-lock"), "false") {
			sc.vetoAll(ctx.file, line+": installs without the lockfile")
			return
		}
		if sc.npmFlags(a, ctx, line) {
			sc.argless("npm", dir, ctx, line, false)
		}
	case "ci", "clean-install", "ic", "install-clean", "isntall-clean":
		if sc.npmFlags(a, ctx, line) {
			sc.argless("npm", dir, ctx, line, true)
		}
	case "update", "up", "upgrade", "udpate":
		sc.namesOrVeto(ctx, line, pos, "updates every dependency past the lockfile")
	case "exec", "x":
		if a.has("-c", "--call") {
			sc.vetoAll(ctx.file, line+": npm exec --call runs an unparsed command")
			return
		}
		sc.runnerPackages("npm exec", dir, ctx, line, argSpec{pos: pos, flags: a.flags})
	case "init", "create", "innit":
		if len(pos) > 0 {
			sc.initializer(ctx, line, pos[0])
		}
	case "link", "ln":
		sc.vetoAll(ctx.file, line+": npm link installs a package from outside the lockfile")
	case "explore":
		sc.vetoAll(ctx.file, line+": npm explore runs an unparsed command")
	case "audit":
		if slicesContains(cleaned(pos), "fix") {
			sc.vetoAll(ctx.file, line+": npm audit fix installs versions outside the lockfile")
		}
	case "dedupe", "ddp":
		sc.vetoAll(ctx.file, line+": npm dedupe rewrites the install outside the lockfile")
	}
}

// npmFlags vetoes an argument-less npm install or ci carrying a flag outside
// npmInstallFlags, or one of those set to a value that changes what installs.
func (sc *installScan) npmFlags(a argSpec, ctx *shellCtx, line string) bool {
	keys := make([]string, 0, len(a.flags))
	for f := range a.flags {
		keys = append(keys, f)
	}
	sort.Strings(keys)
	for _, f := range keys {
		if !npmInstallFlags[f] {
			sc.vetoAll(ctx.file, line+": npm flag "+f+" is not modelled")
			return false
		}
		for _, v := range a.flags[f] {
			if dynamicTok(v) {
				sc.vetoAll(ctx.file, line+": npm flag "+f+" set from a variable")
				return false
			}
		}
	}
	for _, v := range a.values("--location") {
		if v != "project" {
			sc.vetoAll(ctx.file, line+": npm --location="+v+" installs outside the project")
			return false
		}
	}
	return true
}

// runner parses npx, pnpx and bunx: the package is every --package value, else the first
// positional.
func (sc *installScan) runner(tool string, args []string, dir cwd, ctx *shellCtx, line string) {
	a := parseArgs(args, func(f string) bool {
		return f == "-p" || f == "--package" || f == "-c" || f == "--call" || f == "--registry" || f == "--cache"
	})
	if a.has("-c", "--call") {
		sc.vetoAll(ctx.file, line+": "+tool+" --call runs an unparsed command")
		return
	}
	sc.runnerPackages(tool, dir, ctx, line, a)
}

// runnerPackages judges a package runner. A runner installs what it runs unless it finds it
// installed, so it withholds every refutation unless it is npx, npm exec or bunx naming, by a
// bare package name, a bin the lockfile install of the production closure already put at the
// top of node_modules in every directory it may run in (localBin). pnpx, pnpm dlx and yarn dlx
// always fetch.
func (sc *installScan) runnerPackages(tool string, dir cwd, ctx *shellCtx, line string, a argSpec) {
	if pk := a.values("-p", "--package"); len(pk) > 0 {
		sc.names(ctx, line, pk)
		return
	}
	if len(a.flags["-p"])+len(a.flags["--package"]) > 0 {
		sc.vetoAll(ctx.file, line+": a --package flag with no value")
		return
	}
	if len(a.pos) == 0 {
		return
	}
	switch tool {
	case "npx", "npm exec", "bunx", "bun x":
		if sc.localBin(a.pos[0], dir, ctx) {
			return
		}
	}
	sc.names(ctx, line, a.pos[:1])
}

// localBin reports whether spec, a bare package name, is a bin of a production-closure package
// installed directly under node_modules at an npm lockfile root, in every directory the
// command may run in, by a passing lockfile install that ran there earlier in the same script,
// GitHub job or image stage.
func (sc *installScan) localBin(spec string, dir cwd, ctx *shellCtx) bool {
	if sc.m == nil || dynamicTok(spec) || dir.unknown || len(dir.dirs) == 0 {
		return false
	}
	spec = cleanTok(spec)
	if !validNpmName.MatchString(spec) {
		return false
	}
	for _, d := range dir.dirs {
		root := d
		if ctx.docker != nil {
			r, ok := ctx.docker.cur.npmAt[d]
			if !ok {
				return false
			}
			root = r
		} else if !ctx.npmAt[d] {
			return false
		}
		if !sc.topBin(root, spec) {
			return false
		}
	}
	return true
}

// topBin reports whether root is an npm lockfile root whose production install puts a package
// directly under its node_modules that provides bin spec, or is named spec and has a bin.
func (sc *installScan) topBin(root, spec string) bool {
	if sc.m.lockOf[root] != "npm" {
		return false
	}
	nm := joinRel(root, "node_modules") + "/"
	ok := func(in *pkgInstance) bool {
		rest, found := strings.CutPrefix(in.path, nm)
		return found && rest == in.dirName && sc.installed[in.path] && len(in.bins) > 0
	}
	for _, in := range sc.m.byBin[spec] {
		if ok(in) {
			return true
		}
	}
	for _, in := range sc.m.byName[canonicalNpmName(spec)] {
		if ok(in) {
			return true
		}
	}
	return false
}

var yarnValueFlags = map[string]bool{
	"--cwd": true, "--modules-folder": true, "--cache-folder": true, "--registry": true,
	"--network-timeout": true, "--mutex": true, "--link-folder": true, "--global-folder": true,
	"--use-yarnrc": true, "--include": true, "--exclude": true, "-j": true, "--jobs": true, "--from": true,
}

// yarn parses one yarn invocation. inForeach turns lockfile installs into vetoes: they run in
// every workspace, not a directory the scanner knows.
func (sc *installScan) yarn(args []string, dir cwd, ctx *shellCtx, line string, inForeach bool) {
	sub := ""
	if p := positionals(args, func(f string) bool { return yarnValueFlags[f] }); len(p) > 0 {
		sub = p[0]
	}
	a := parseArgs(args, func(f string) bool {
		return yarnValueFlags[f] || (sub == "dlx" && (f == "-p" || f == "--package"))
	})
	dir = withDir(dir, a, ctx, "--cwd")
	if inForeach {
		dir = cwd{unknown: true}
	}
	pos := a.pos
	if len(pos) > 0 {
		pos = pos[1:]
	}
	switch sub {
	case "", "install":
		if a.has("--no-lockfile") {
			sc.vetoAll(ctx.file, line+": installs without the lockfile")
			return
		}
		sc.argless("yarn", dir, ctx, line, a.has("--frozen-lockfile", "--immutable"))
	case "add":
		sc.names(ctx, line, pos)
	case "global":
		if len(pos) > 0 {
			switch cleanTok(pos[0]) {
			case "add":
				sc.names(ctx, line, pos[1:])
			case "upgrade":
				sc.namesOrVeto(ctx, line, pos[1:], "upgrades every global package")
			}
		}
	case "dlx":
		sc.runnerPackages("yarn dlx", dir, ctx, line, argSpec{pos: pos, flags: a.flags})
	case "create":
		if len(pos) > 0 {
			sc.initializer(ctx, line, pos[0])
		}
	case "up", "upgrade":
		sc.namesOrVeto(ctx, line, pos, "upgrades every dependency past the lockfile")
	case "upgrade-interactive", "dedupe", "import":
		sc.vetoAll(ctx.file, line+": yarn "+sub+" rewrites the install outside the lockfile")
	case "link":
		sc.vetoAll(ctx.file, line+": yarn link installs a package from outside the lockfile")
	case "workspaces":
		if len(pos) == 0 {
			return
		}
		switch cleanTok(pos[0]) {
		case "focus":
			sc.vetoAll(ctx.file, line+": yarn workspaces focus installs a workspace selection the scanner does not model")
		case "foreach":
			sc.yarn(pos[1:], dir, ctx, line, true)
		}
	case "workspace":
		if len(pos) > 1 {
			sc.yarn(pos[1:], dir, ctx, line, true)
		}
	}
}

var pnpmValueFlags = map[string]bool{
	"-C": true, "--dir": true, "--filter": true, "-F": true, "--store-dir": true, "--virtual-store-dir": true,
	"--lockfile-dir": true, "--registry": true, "--reporter": true, "--modules-dir": true,
	"--network-concurrency": true, "--child-concurrency": true, "--workspace-dir": true,
	"-p": true, "--package": true, "-c": true, "--shell-mode": true,
}

func (sc *installScan) pnpm(args []string, dir cwd, ctx *shellCtx, line string) {
	a := parseArgs(args, func(f string) bool { return pnpmValueFlags[f] })
	dir = withDir(dir, a, ctx, "-C", "--dir")
	pos := a.pos
	sub := ""
	if len(pos) > 0 {
		sub = cleanTok(pos[0])
		pos = pos[1:]
	}
	switch sub {
	case "install", "i", "add", "dlx", "update", "up", "upgrade", "fetch", "dedupe", "import", "link", "ln", "create":
		if a.has("--filter", "-F", "-r", "--recursive", "-w", "--workspace-root", "--filter-prod") {
			sc.vetoAll(ctx.file, line+": a workspace selector installs packages the scanner does not model")
			return
		}
	}
	switch sub {
	case "install", "i":
		if len(pos) > 0 {
			sc.names(ctx, line, pos)
			return
		}
		if a.has("-g", "--global") {
			sc.vetoAll(ctx.file, line+": a global install with no package installs the working directory")
			return
		}
		if a.has("--no-lockfile", "--lockfile-dir", "--fix-lockfile") {
			sc.vetoAll(ctx.file, line+": installs without the lockfile the lane read")
			return
		}
		sc.argless("pnpm", dir, ctx, line, a.has("--frozen-lockfile"))
	case "add":
		sc.names(ctx, line, pos)
	case "dlx":
		if a.has("-c", "--shell-mode") {
			sc.vetoAll(ctx.file, line+": pnpm dlx --shell-mode runs an unparsed command")
			return
		}
		sc.runnerPackages("pnpm dlx", dir, ctx, line, argSpec{pos: pos, flags: a.flags})
	case "create":
		if len(pos) > 0 {
			sc.initializer(ctx, line, pos[0])
		}
	case "update", "up", "upgrade":
		sc.namesOrVeto(ctx, line, pos, "updates every dependency past the lockfile")
	case "dedupe", "import":
		sc.vetoAll(ctx.file, line+": pnpm "+sub+" rewrites the install outside the lockfile")
	case "fetch":
		sc.argless("pnpm", dir, ctx, line, true)
	case "link", "ln":
		sc.vetoAll(ctx.file, line+": pnpm link installs a package from outside the lockfile")
	}
}

// bun parses one bun invocation. The lane never reads bun's lockfile, so a lockfile install
// always vetoes (argless finds no bun root).
func (sc *installScan) bun(args []string, dir cwd, ctx *shellCtx, line string) {
	a := parseArgs(args, func(f string) bool { return f == "--cwd" || f == "-p" || f == "--package" || f == "--registry" })
	dir = withDir(dir, a, ctx, "--cwd")
	pos := a.pos
	sub := ""
	if len(pos) > 0 {
		sub = cleanTok(pos[0])
		pos = pos[1:]
	}
	switch sub {
	case "install", "i":
		if len(pos) > 0 {
			sc.names(ctx, line, pos)
			return
		}
		sc.argless("bun", dir, ctx, line, a.has("--frozen-lockfile"))
	case "add", "a":
		sc.names(ctx, line, pos)
	case "x":
		sc.runnerPackages("bun x", dir, ctx, line, argSpec{pos: pos, flags: a.flags})
	case "update":
		sc.namesOrVeto(ctx, line, pos, "updates every dependency past the lockfile")
	case "create", "c":
		if len(pos) > 0 {
			sc.initializer(ctx, line, pos[0])
		}
	case "link":
		sc.vetoAll(ctx.file, line+": bun link installs a package from outside the lockfile")
	}
}

// deno installs npm packages through npm: specifiers and, with no arguments, from package.json
// against its own lockfile, which the lane never reads.
func (sc *installScan) deno(args []string, ctx *shellCtx, line string) {
	pos := positionals(args, func(f string) bool { return f == "--config" || f == "-c" || f == "--lock" || f == "--import-map" })
	if len(pos) == 0 {
		return
	}
	sub, rest := pos[0], pos[1:]
	var npmSpecs []string
	for _, p := range rest {
		if s, ok := strings.CutPrefix(p, "npm:"); ok {
			npmSpecs = append(npmSpecs, s)
		}
	}
	switch sub {
	case "install", "i", "add", "cache":
		if len(rest) == 0 {
			sc.vetoAll(ctx.file, line+": deno installs package.json dependencies against its own lockfile")
			return
		}
		for _, p := range rest {
			if !strings.HasPrefix(p, "npm:") {
				sc.vetoAll(ctx.file, line+": deno "+sub+" of a non-npm specifier")
				return
			}
		}
	}
	if len(npmSpecs) > 0 {
		sc.names(ctx, line, npmSpecs)
	}
}

// ncu -u rewrites package.json past the lockfile; the next install resolves fresh versions.
func (sc *installScan) ncu(args []string, ctx *shellCtx, line string) {
	for _, t := range args {
		switch cleanTok(t) {
		case "-u", "--upgrade":
			sc.vetoAll(ctx.file, line+": npm-check-updates rewrites package.json past the lockfile")
			return
		}
	}
}

func (sc *installScan) namesOrVeto(ctx *shellCtx, line string, pos []string, why string) {
	if len(pos) == 0 {
		sc.vetoAll(ctx.file, line+": "+why)
		return
	}
	sc.names(ctx, line, pos)
}

// initializer maps `npm init <x>` / `yarn create <x>` to the package it runs.
func (sc *installScan) initializer(ctx *shellCtx, line, spec string) {
	raw := spec
	spec = cleanTok(spec)
	if dynamicTok(raw) || strings.HasPrefix(spec, "-") {
		if dynamicTok(raw) {
			sc.vetoAll(ctx.file, line+": a variable names the initializer")
		}
		return
	}
	name, ver := splitSpec(spec)
	switch {
	case strings.HasPrefix(name, "@") && !strings.Contains(name, "/"):
		name += "/create"
	case strings.HasPrefix(name, "@"):
		scope, base, _ := strings.Cut(name, "/")
		name = scope + "/create-" + base
	default:
		name = "create-" + name
	}
	if ver != "" {
		name += "@" + ver
	}
	sc.names(ctx, line, []string{name})
}

// names judges an install of packages named on the command line. It withholds every
// refutation: what a named install puts on disk is the named package's dependency closure as
// the registry resolves it today, which no lockfile the lane read describes, so blocking the
// named packages alone would leave their unlisted dependencies counted as not installed.
func (sc *installScan) names(ctx *shellCtx, line string, specs []string) {
	for _, raw := range specs {
		if _, ok := specNames(raw); !ok {
			sc.vetoAll(ctx.file, line+": "+cleanTok(raw)+" is not a registry package name")
			return
		}
	}
	if len(specs) > 0 {
		sc.vetoAll(ctx.file, line+": installs "+strings.Join(cleaned(specs), " ")+" by name, outside the lockfile")
	}
}

// splitSpec splits "name@range" (scoped names keep their leading @).
func splitSpec(s string) (name, version string) {
	at := strings.IndexByte(s, '@')
	if strings.HasPrefix(s, "@") {
		at = -1
		if i := strings.IndexByte(s[1:], '@'); i >= 0 {
			at = i + 1
		}
	}
	if at < 0 {
		return s, ""
	}
	return s[:at], s[at+1:]
}

var nonRegistryPrefixes = []string{
	".", "/", "~", "file:", "link:", "git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:",
	"http:", "https:", "workspace:", "jsr:", "catalog:", "portal:", "patch:", "exec:",
}

// specNames reduces an install argument to canonical registry names. An alias
// (x@npm:real@1) names both. ok is false for anything else: a variable, a path, a URL, a git
// or tarball spec, a glob, or an invalid name.
func specNames(raw string) ([]string, bool) {
	if dynamicTok(raw) {
		return nil, false
	}
	s := cleanTok(raw)
	if s == "" {
		return nil, false
	}
	if real, ok := strings.CutPrefix(s, "npm:"); ok {
		return specNames(real)
	}
	for _, p := range nonRegistryPrefixes {
		if strings.HasPrefix(s, p) {
			return nil, false
		}
	}
	lower := strings.ToLower(s)
	for _, suf := range []string{".tgz", ".tar.gz", ".tar", ".zip"} {
		if strings.HasSuffix(lower, suf) {
			return nil, false
		}
	}
	name, ver := splitSpec(s)
	if real, ok := strings.CutPrefix(ver, "npm:"); ok {
		more, ok := specNames(real)
		if !ok || !validNpmName.MatchString(name) {
			return nil, false
		}
		return append([]string{canonicalNpmName(name)}, more...), true
	}
	if strings.ContainsAny(ver, ":/") || hasGlob(name) || !validNpmName.MatchString(name) {
		return nil, false
	}
	return []string{canonicalNpmName(name)}, true
}

func cleaned(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = cleanTok(s)
	}
	return out
}

func slicesContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// jsonCommand turns a Dockerfile exec-form array into shell text, or returns s unchanged.
func jsonCommand(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "[") {
		return s
	}
	var arr []string
	if json.Unmarshal([]byte(t), &arr) != nil {
		return s
	}
	return strings.Join(arr, " ")
}

// argless checks a lockfile install: every directory it may run in must be a root whose
// selected lockfile is the lane-read lockfile of the same dialect.
func (sc *installScan) argless(dialect string, dir cwd, ctx *shellCtx, line string, frozen bool) {
	if sc.m == nil {
		return
	}
	if ctx.docker != nil {
		ctx.docker.argless(sc, dialect, dir, line, frozen)
		return
	}
	if dir.unknown || len(dir.dirs) == 0 {
		sc.vetoAll(ctx.file, line+": installs from a lockfile in a directory the scanner cannot determine")
		return
	}
	for _, d := range dir.dirs {
		if sc.checkRoot(ctx.file, line, dialect, d) && dialect == "npm" && ctx.npmAt != nil {
			ctx.npmAt[d] = true
		}
	}
}

// checkRoot vetoes unless d's selected lockfile is the dialect's lane-read lockfile, and
// reports whether it is.
func (sc *installScan) checkRoot(file, line, dialect, d string) bool {
	label := d
	if label == "" {
		label = "."
	}
	got, ok := sc.m.lockOf[d]
	switch {
	case !ok:
		sc.vetoAll(file, line+": installs in "+label+", which has no lockfile the lane selected (missing or ambiguous)")
	case got != dialect:
		sc.vetoAll(file, line+": installs with "+dialect+" in "+label+", whose selected lockfile is "+got)
	default:
		return true
	}
	return false
}
