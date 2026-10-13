package jsanalysis

// launch.go reads the runtime launch lines: scripts.start (and npm start/restart/stop), every
// Procfile process, and Dockerfile and Compose CMD/ENTRYPOINT. A package whose bin a launch
// line runs is loaded in production, whatever its lockfile marker says, so it roots the load
// set. The reader follows package scripts, wrappers (env, cross-env, tini, ...), sh -c and
// first-party shell scripts; anything it cannot parse in full (command substitution, eval, a
// variable naming the command, inline node code) marks the load set incomplete.

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// launch.go reads the commands a deployed process starts with: every first-party package.json's
// start script (with prestart and poststart), every line of a Procfile, the ENTRYPOINT and CMD
// of every Dockerfile stage, and the entrypoint and command of every compose service. A package
// whose bin such a command runs executes in production whatever its lockfile marker says, so
// every installed instance providing that bin is a runtime root. A launch command is followed
// through the scripts it runs (npm start, npm run, yarn, pnpm, bun, npm-run-all) and the
// first-party shell scripts it runs by relative path. A launch command the reader cannot fully
// parse (a command substitution, a variable naming the command, shell control flow, inline
// node code, a script by container path) withholds every refutation.

// launchRoot is an installed instance a launch command runs.
type launchRoot struct {
	in    *pkgInstance
	label string
}

// manifestScripts is one first-party package.json's scripts.
type manifestScripts struct {
	dir     string
	rel     string
	scripts map[string]string
}

type launchReader struct {
	m     *installModel
	ls    *loadSet
	out   *firstPartyRoots
	seen  map[string]bool // scripts already expanded, by manifest and name
	files map[string]bool // shell scripts already followed
}

const maxLaunchDepth = 8

// shWord is one shell word after quote removal. dynamic: it holds an expansion ($...) outside
// single quotes, so its value is not known.
type shWord struct {
	text    string
	dynamic bool
}

var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true, "for": true, "while": true,
	"until": true, "do": true, "done": true, "case": true, "esac": true, "function": true,
	"select": true, "{": true, "}": true, "[[": true, "]]": true, "coproc": true,
}

// splitShell splits shell text into simple commands, or says why it cannot. It models
// quoting, escapes, comments, line continuations, the list and pipe operators and
// redirections; a command substitution, process substitution, heredoc, subshell or brace
// group is not parsed.
func splitShell(text string) ([][]shWord, string) {
	var cmds [][]shWord
	var cur []shWord
	var b strings.Builder
	inWord, dynamic, skipNext := false, false, false
	endWord := func() {
		if !inWord {
			return
		}
		w := shWord{text: b.String(), dynamic: dynamic}
		b.Reset()
		inWord, dynamic = false, false
		if skipNext {
			skipNext = false
			return
		}
		cur = append(cur, w)
	}
	endCmd := func() {
		endWord()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
		}
		cur = nil
	}
	r := []rune(text)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '\\':
			if i+1 < len(r) && r[i+1] == '\n' {
				i++
				continue
			}
			if i+1 < len(r) {
				i++
				b.WriteRune(r[i])
				inWord = true
			}
		case c == '\'':
			j := i + 1
			for j < len(r) && r[j] != '\'' {
				j++
			}
			if j >= len(r) {
				return nil, "unterminated quote"
			}
			b.WriteString(string(r[i+1 : j]))
			inWord = true
			i = j
		case c == '"':
			j := i + 1
			for ; j < len(r) && r[j] != '"'; j++ {
				switch r[j] {
				case '\\':
					if j+1 < len(r) && strings.ContainsRune("$`\"\\\n", r[j+1]) {
						j++
					}
					b.WriteRune(r[j])
				case '`':
					return nil, "command substitution"
				case '$':
					if j+1 < len(r) && r[j+1] == '(' {
						return nil, "command substitution"
					}
					dynamic = true
					b.WriteRune(r[j])
				default:
					b.WriteRune(r[j])
				}
			}
			if j >= len(r) {
				return nil, "unterminated quote"
			}
			inWord = true
			i = j
		case c == '`':
			return nil, "command substitution"
		case c == '$':
			if i+1 < len(r) && r[i+1] == '(' {
				return nil, "command substitution"
			}
			dynamic = true
			inWord = true
			b.WriteRune(c)
		case c == '#' && !inWord:
			for i < len(r) && r[i] != '\n' {
				i++
			}
			endCmd()
		case c == '\n' || c == ';':
			if c == ';' && i+1 < len(r) && r[i+1] == ';' {
				return nil, "case clause"
			}
			endCmd()
		case c == '&' || c == '|':
			if c == '&' && i+1 < len(r) && r[i+1] == '>' {
				endWord()
				i++
				if i+1 < len(r) && r[i+1] == '>' {
					i++
				}
				skipNext = true
				continue
			}
			if i+1 < len(r) && r[i+1] == c {
				i++
			}
			endCmd()
		case c == '(' || c == ')':
			return nil, "subshell"
		case c == '<' || c == '>':
			if c == '<' && i+1 < len(r) && r[i+1] == '<' {
				return nil, "heredoc"
			}
			if i+1 < len(r) && r[i+1] == '(' {
				return nil, "process substitution"
			}
			// A word of digits before the operator is a file descriptor, not an argument.
			if inWord && !dynamic && strings.Trim(b.String(), "0123456789") == "" {
				b.Reset()
				inWord = false
			} else {
				endWord()
			}
			for i+1 < len(r) && strings.ContainsRune("<>&|", r[i+1]) {
				i++
			}
			// `>&2`: the target is the rest of this word; `> file`: the next word.
			if i+1 < len(r) && r[i+1] != ' ' && r[i+1] != '\t' {
				inWord = true
			}
			skipNext = true
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		default:
			b.WriteRune(c)
			inWord = true
		}
	}
	endCmd()
	return cmds, ""
}

var shellAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// launchWrappers run the rest of their arguments as a command. The value lists the flags that
// take a separate value; a count of leading operands (a user, a duration) follows the flags.
var launchWrappers = map[string]struct {
	valueFlags string
	operands   int
}{
	"exec": {}, "nohup": {}, "time": {}, "command": {}, "builtin": {}, "setsid": {},
	"env":       {valueFlags: " -u --unset -C --chdir "},
	"nice":      {valueFlags: " -n --adjustment "},
	"timeout":   {valueFlags: " -s --signal -k --kill-after ", operands: 1},
	"sudo":      {valueFlags: " -u -g -C -D -h -p "},
	"doas":      {valueFlags: " -u -C "},
	"tini":      {valueFlags: " -e -p "},
	"dumb-init": {valueFlags: " -r --rewrite "},
	"gosu":      {operands: 1},
	"su-exec":   {operands: 1},
	"cross-env": {},
	"env-cmd":   {valueFlags: " -f --file -e --environments -r --rc-file "},
	"dotenv":    {valueFlags: " -e -c -v "},
}

var (
	shellNames   = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true}
	systemPrefix = []string{"/usr/", "/bin/", "/sbin/", "/lib/"}
	// nodeValueFlags are node options whose value is the next word.
	nodeValueFlags = " -r --require --import --loader --experimental-loader --title --env-file --input-type --conditions -C --inspect-port --redirect-warnings --diagnostic-dir --report-directory --icu-data-dir --openssl-config --secure-heap --stack-trace-limit "
	// pmValueFlags are npm, yarn, pnpm and bun options whose value is the next word.
	pmValueFlags = " --prefix -w --workspace --cwd -C --dir --filter -F --userconfig --registry --cache --loglevel --script-shell --package -p --call -c "
)

func hasFlag(list, f string) bool { return strings.Contains(list, " "+f+" ") }

// shell evaluates shell text that runs at launch from build-relative dir.
func (lr *launchReader) shell(label, text, dir string, depth int) {
	if depth > maxLaunchDepth {
		lr.ls.gap("%s: launch commands nest too deep", label)
		return
	}
	cmds, why := splitShell(text)
	if why != "" {
		lr.ls.gap("%s: launch command not parsed (%s)", label, why)
		return
	}
	for _, c := range cmds {
		lr.command(label, c, dir, depth)
	}
}

// argv evaluates an exec-form command (a JSON or YAML list), whose words are never expanded.
func (lr *launchReader) argv(label string, words []string, dir string, depth int) {
	ws := make([]shWord, len(words))
	for i, w := range words {
		ws[i] = shWord{text: w}
	}
	lr.command(label, ws, dir, depth)
}

func (lr *launchReader) command(label string, w []shWord, dir string, depth int) {
	for len(w) > 0 && shellAssign.MatchString(w[0].text) {
		w = w[1:]
	}
	if len(w) == 0 {
		return
	}
	// Every word naming an installed bin roots it. That covers a bin run through any wrapper,
	// and over-approximates an argument that only shares a bin's name.
	for _, x := range w {
		if !x.dynamic {
			lr.bin(label, x.text, dir)
		}
	}
	head := w[0]
	if head.dynamic {
		lr.ls.gap("%s: a variable names the launch command", label)
		return
	}
	if shellKeywords[head.text] || head.text == "!" {
		lr.ls.gap("%s: launch command not parsed (shell control flow)", label)
		return
	}
	name := head.text
	if strings.Contains(name, "/") {
		if lr.nodeModulesRef(label, name, dir) {
			return
		}
		if path.IsAbs(name) {
			system := false
			for _, p := range systemPrefix {
				system = system || strings.HasPrefix(name, p)
			}
			if !system {
				lr.ls.gap("%s: launch command runs %s by container path", label, name)
				return
			}
			name = path.Base(name)
		} else {
			lr.scriptFile(label, name, dir, depth)
			return
		}
	}
	args := w[1:]
	if name == "cross-env-shell" {
		lr.ls.gap("%s: launch command not parsed (%s runs its arguments as shell text)", label, name)
		return
	}
	if wr, ok := launchWrappers[name]; ok {
		i := 0
		for i < len(args) && strings.HasPrefix(args[i].text, "-") {
			if args[i].text == "--" {
				i++
				break
			}
			if name == "env" && (args[i].text == "-S" || strings.HasPrefix(args[i].text, "--split-string")) {
				lr.ls.gap("%s: launch command not parsed (env splits a string into a command)", label)
				return
			}
			if hasFlag(wr.valueFlags, args[i].text) {
				i++
			}
			i++
		}
		for n := 0; n < wr.operands && i < len(args); n++ {
			i++
		}
		lr.command(label, args[min(i, len(args)):], dir, depth)
		return
	}
	switch name {
	case "eval", "source", ".":
		lr.ls.gap("%s: launch command runs %s", label, name)
	case "node", "nodejs":
		lr.node(label, args, dir, depth)
	case "npm":
		lr.npm(label, args, dir, depth)
	case "npx", "pnpx", "bunx":
		lr.runner(label, args, dir, depth)
	case "yarn", "pnpm", "bun":
		lr.pm(label, name, args, dir, depth)
	case "npm-run-all", "run-p", "run-s":
		for _, a := range args {
			switch {
			case a.dynamic:
				lr.ls.gap("%s: a variable names a script %s runs", label, name)
			case !strings.HasPrefix(a.text, "-"):
				lr.script(label, a.text, depth)
			}
		}
	case "concurrently":
		for _, a := range args {
			if s, ok := strings.CutPrefix(a.text, "npm:"); ok {
				lr.script(label, s, depth)
			}
		}
		lr.quotedArgs(label, args, dir, depth)
	default:
		if shellNames[name] {
			lr.sh(label, args, dir, depth)
		} else {
			lr.quotedArgs(label, args, dir, depth)
		}
	}
}

// quotedArgs evaluates every argument holding a space as a command of its own: a runner
// (concurrently, nodemon --exec, pm2) may run it.
func (lr *launchReader) quotedArgs(label string, args []shWord, dir string, depth int) {
	for _, a := range args {
		if strings.ContainsAny(a.text, " \t") && !a.dynamic {
			lr.shell(label, a.text, dir, depth+1)
		}
	}
}

// bin roots every installed instance that provides bin name.
func (lr *launchReader) bin(label, name, dir string) {
	for _, in := range lr.m.byBin[name] {
		lr.out.launched = append(lr.out.launched, launchRoot{in: in, label: label + " (runs " + name + ")"})
	}
}

// nodeModulesRef roots the package a path into node_modules names: node_modules/.bin/x runs
// bin x, node_modules/<pkg>/... runs a file of pkg.
func (lr *launchReader) nodeModulesRef(label, p, dir string) bool {
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return false
	}
	rest := p[i+len("node_modules/"):]
	if b, ok := strings.CutPrefix(rest, ".bin/"); ok {
		lr.bin(label, b, dir)
		return true
	}
	segs := strings.Split(rest, "/")
	pkg := segs[0]
	if strings.HasPrefix(pkg, "@") && len(segs) > 1 {
		pkg += "/" + segs[1]
	}
	if pkg != "" {
		lr.out.runtime = append(lr.out.runtime, rootRef{spec: pkg, from: dir, label: label + " (runs " + p + ")", fallback: true})
	}
	return true
}

// node reads `node [options] script`: inline code or a script from standard input is not
// parsed, and a script inside node_modules roots its package.
func (lr *launchReader) node(label string, args []shWord, dir string, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		f, _, hasValue := strings.Cut(a.text, "=")
		switch {
		case f == "-e" || f == "--eval" || f == "-p" || f == "--print" || a.text == "-":
			lr.ls.gap("%s: node runs inline code", label)
			return
		case strings.HasPrefix(a.text, "-"):
			if hasFlag(nodeValueFlags, f) && !hasValue {
				i++
				if i < len(args) && args[i].dynamic && (f == "-r" || f == "--require" || f == "--import" || strings.Contains(f, "loader")) {
					lr.ls.gap("%s: a variable names a preloaded module", label)
					return
				}
			} else if hasValue && a.dynamic && (f == "--require" || f == "--import" || strings.Contains(f, "loader")) {
				lr.ls.gap("%s: a variable names a preloaded module", label)
				return
			}
		case a.dynamic:
			lr.ls.gap("%s: a variable names the script node runs", label)
			return
		default:
			lr.nodeModulesRef(label, a.text, dir)
			return
		}
	}
}

// pmPositionals drops a package manager's options (and their values) from args.
func pmPositionals(args []shWord) []shWord {
	var out []shWord
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a.text == "--" {
			return append(out, args[i+1:]...)
		}
		if strings.HasPrefix(a.text, "-") {
			if !strings.Contains(a.text, "=") && hasFlag(pmValueFlags, a.text) {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

func (lr *launchReader) npm(label string, args []shWord, dir string, depth int) {
	pos := pmPositionals(args)
	if len(pos) == 0 {
		return
	}
	if pos[0].dynamic {
		lr.ls.gap("%s: a variable names the npm command", label)
		return
	}
	switch pos[0].text {
	case "start":
		lr.script(label, "start", depth)
	case "restart":
		lr.script(label, "restart", depth)
		lr.script(label, "stop", depth)
		lr.script(label, "start", depth)
	case "stop":
		lr.script(label, "stop", depth)
	case "test", "t", "tst":
		lr.script(label, "test", depth)
	case "run", "run-script", "rum", "urn":
		if len(pos) > 1 {
			lr.scriptWord(label, pos[1], depth)
		}
	case "exec", "x":
		lr.runner(label, args[1:], dir, depth)
	}
}

// pm reads yarn, pnpm and bun: `run x` and a bare `x` run script x when a manifest has one,
// and otherwise bin or file x.
func (lr *launchReader) pm(label, tool string, args []shWord, dir string, depth int) {
	pos := pmPositionals(args)
	if len(pos) == 0 {
		return
	}
	if pos[0].dynamic {
		lr.ls.gap("%s: a variable names the %s command", label, tool)
		return
	}
	sub := pos[0].text
	switch {
	case sub == "exec" || sub == "dlx" || sub == "x":
		lr.runner(label, pos[1:], dir, depth)
		return
	case sub == "node":
		lr.node(label, pos[1:], dir, depth)
		return
	case sub == "run" || sub == "run-script":
		if len(pos) < 2 {
			return
		}
		pos = pos[1:]
		sub = pos[0].text
		if pos[0].dynamic {
			lr.ls.gap("%s: a variable names a script %s runs", label, tool)
			return
		}
	}
	if lr.hasScript(sub) {
		lr.script(label, sub, depth)
		return
	}
	if tool == "bun" || strings.Contains(sub, "/") {
		lr.nodeModulesRef(label, sub, dir)
	}
}

// runner reads npx-style commands: -p/--package names packages, -c runs shell text, and the
// first positional is a bin or package spec.
func (lr *launchReader) runner(label string, args []shWord, dir string, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		f, v, hasValue := strings.Cut(a.text, "=")
		if !strings.HasPrefix(a.text, "-") {
			if a.dynamic {
				lr.ls.gap("%s: a variable names the package a runner runs", label)
				return
			}
			lr.spec(label, a.text, dir)
			return
		}
		if f == "--" {
			continue
		}
		if f == "-p" || f == "--package" || f == "-c" || f == "--call" {
			if !hasValue {
				i++
				if i >= len(args) {
					return
				}
				v = args[i].text
				if args[i].dynamic {
					lr.ls.gap("%s: a variable names what a runner runs", label)
					return
				}
			}
			if f == "-c" || f == "--call" {
				lr.shell(label, v, dir, depth+1)
				return
			}
			lr.spec(label, v, dir)
		}
	}
}

// spec roots a package spec (name, name@version) and any bin it names.
func (lr *launchReader) spec(label, s, dir string) {
	name, _ := splitSpec(s)
	if name == "" {
		return
	}
	lr.bin(label, name, dir)
	if validNpmName.MatchString(name) {
		lr.out.runtime = append(lr.out.runtime, rootRef{spec: name, from: dir, label: label + " (runs " + name + ")", fallback: true})
	}
}

func (lr *launchReader) sh(label string, args []shWord, dir string, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a.text == "-c" || strings.HasPrefix(a.text, "-") && strings.Contains(a.text, "c") && !strings.HasPrefix(a.text, "--"):
			if i+1 >= len(args) || args[i+1].dynamic {
				lr.ls.gap("%s: launch command not parsed (shell text the reader cannot see)", label)
				return
			}
			lr.shell(label, args[i+1].text, dir, depth+1)
			return
		case strings.HasPrefix(a.text, "-"):
		case a.dynamic:
			lr.ls.gap("%s: a variable names the script a shell runs", label)
			return
		default:
			lr.scriptFile(label, a.text, dir, depth)
			return
		}
	}
	lr.ls.gap("%s: launch command runs shell text from standard input", label)
}

func (lr *launchReader) hasScript(name string) bool {
	for _, ms := range lr.out.scripts {
		if _, ok := ms.scripts[name]; ok {
			return true
		}
	}
	return false
}

func (lr *launchReader) scriptWord(label string, w shWord, depth int) {
	if w.dynamic {
		lr.ls.gap("%s: a variable names the script npm runs", label)
		return
	}
	lr.script(label, w.text, depth)
}

// script expands script name (a glob for npm-run-all) in every first-party manifest that
// defines it, with its pre and post scripts. Which manifest a container runs from is not
// known, so every one counts.
func (lr *launchReader) script(_, name string, depth int) {
	pattern := strings.ReplaceAll(name, ":", "/")
	for _, ms := range lr.out.scripts {
		keys := make([]string, 0, len(ms.scripts))
		for k := range ms.scripts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k != name {
				if ok, _ := path.Match(pattern, strings.ReplaceAll(k, ":", "/")); !ok || !strings.ContainsAny(name, "*?[") {
					continue
				}
			}
			key := ms.rel + "\x00" + k
			if lr.seen[key] {
				continue
			}
			lr.seen[key] = true
			for _, s := range []string{"pre" + k, k, "post" + k} {
				if cmd, ok := ms.scripts[s]; ok {
					lr.shell(ms.rel+" scripts."+s, cmd, ms.dir, depth+1)
				}
			}
		}
	}
}

// scriptFile follows a first-party file a launch command runs by relative path: a shell
// script (by extension or shebang, or no shebang at all) is read as launch commands, a
// JavaScript file is first-party code the scan already reads, and one that is not a readable
// regular file inside the build dir withholds.
func (lr *launchReader) scriptFile(label, p, dir string, depth int) {
	var data []byte
	var rel string
	for _, base := range []string{dir, ""} {
		r := path.Clean(joinRel(base, p))
		if !lr.m.inside(r) {
			continue
		}
		if d, err := lr.m.readFirstParty(r); err == nil {
			data, rel = d, r
			break
		}
	}
	if data == nil {
		lr.ls.gap("%s: launch command runs %s, which is not a readable file in the build dir", label, p)
		return
	}
	ext := strings.ToLower(path.Ext(rel))
	first, _, _ := strings.Cut(string(data), "\n")
	switch {
	case codeExts[ext], strings.HasPrefix(first, "#!") && strings.Contains(first, "node"):
		return
	case ext == ".sh" || ext == ".bash" || shellShebang(data) || !strings.HasPrefix(first, "#!"):
		if lr.files[rel] {
			return
		}
		lr.files[rel] = true
		lr.shell(rel, string(data), dirOf(rel), depth+1)
	}
}

// procfile reads every process line of a Procfile.
func (lr *launchReader) procfile(rel string, data []byte) {
	dir := dirOf(rel)
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		proc, cmd, ok := strings.Cut(t, ":")
		if !ok || !procName.MatchString(proc) {
			lr.ls.gap("%s: launch line not parsed (%q)", rel, t)
			continue
		}
		lr.shell(rel+" "+proc, cmd, dir, 0)
	}
}

var procName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// launchCmd is an ENTRYPOINT or CMD: exec form (argv) or shell form (text).
type launchCmd struct {
	set   bool
	exec  bool
	argv  []string
	shell string
}

func parseLaunchCmd(v string) launchCmd {
	t := strings.TrimSpace(v)
	if strings.HasPrefix(t, "[") {
		var argv []string
		if json.Unmarshal([]byte(t), &argv) == nil {
			return launchCmd{set: true, exec: true, argv: argv}
		}
	}
	return launchCmd{set: true, shell: t}
}

// run evaluates the process an image starts: an exec-form ENTRYPOINT takes CMD as arguments
// (a shell-form CMD as `/bin/sh -c`), a shell-form ENTRYPOINT ignores CMD.
func (lr *launchReader) run(label string, ep, cmd launchCmd, dir string) {
	switch {
	case ep.set && !ep.exec:
		lr.shell(label, ep.shell, dir, 0)
	case ep.set:
		argv := append([]string{}, ep.argv...)
		if cmd.set && cmd.exec {
			argv = append(argv, cmd.argv...)
		} else if cmd.set {
			argv = append(argv, "/bin/sh", "-c", cmd.shell)
		}
		lr.argv(label, argv, dir, 0)
	case cmd.set && cmd.exec:
		lr.argv(label, cmd.argv, dir, 0)
	case cmd.set:
		lr.shell(label, cmd.shell, dir, 0)
	}
}

// dockerfile reads each stage's ENTRYPOINT and CMD, inherited from an earlier stage it builds
// on. Setting ENTRYPOINT clears an inherited CMD, as Docker does.
func (lr *launchReader) dockerfile(rel string, data []byte) {
	dir := dirOf(rel)
	type stage struct{ ep, cmd launchCmd }
	named := map[string]stage{}
	var cur *stage
	var name string
	flush := func() {
		if cur != nil {
			label := rel
			if name != "" {
				label += " stage " + name
			}
			lr.run(label, cur.ep, cur.cmd, dir)
			if name != "" {
				named[strings.ToLower(name)] = *cur
			}
		}
	}
	for _, in := range parseDockerfile(string(data)) {
		switch in.op {
		case "FROM":
			flush()
			_, words := splitInstrArgs(in.args)
			s := stage{}
			name = ""
			if len(words) > 0 {
				if base, ok := named[strings.ToLower(words[0])]; ok {
					s = base
				}
			}
			if len(words) >= 3 && strings.EqualFold(words[1], "AS") {
				name = words[2]
			}
			cur = &s
		case "ENTRYPOINT":
			if cur != nil {
				cur.ep = parseLaunchCmd(in.args)
				cur.cmd = launchCmd{}
			}
		case "CMD":
			if cur != nil {
				cur.cmd = parseLaunchCmd(in.args)
			}
		}
	}
	flush()
}

// compose reads every service's entrypoint and command.
func (lr *launchReader) compose(rel string, data []byte) {
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		lr.ls.gap("%s: compose file not parsed", rel)
		return
	}
	names := make([]string, 0, len(doc.Services))
	for n := range doc.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		svc := doc.Services[n]
		var ep, cmd launchCmd
		for key, dst := range map[string]*launchCmd{"entrypoint": &ep, "command": &cmd} {
			switch v := svc[key].(type) {
			case nil:
			case string:
				*dst = launchCmd{set: true, shell: v}
			case []any:
				argv := make([]string, 0, len(v))
				for _, e := range v {
					s, ok := e.(string)
					if !ok {
						lr.ls.gap("%s service %s: %s not parsed", rel, n, key)
						return
					}
					argv = append(argv, s)
				}
				*dst = launchCmd{set: true, exec: true, argv: argv}
			default:
				lr.ls.gap("%s service %s: %s not parsed", rel, n, key)
				return
			}
		}
		lr.run(rel+" service "+n, ep, cmd, dirOf(rel))
	}
}

// read reads every launch surface the first-party scan listed.
func (lr *launchReader) read(opsFiles []string) {
	for _, ms := range lr.out.scripts {
		if _, ok := ms.scripts["start"]; ok {
			lr.script(ms.rel+" scripts.start", "start", 0)
		}
	}
	for _, rel := range opsFiles {
		name := path.Base(rel)
		kind := surfaceOf(rel, name, nil)
		if name != "Procfile" && kind != surfDocker && kind != surfCompose {
			continue
		}
		data, err := lr.m.readFirstParty(rel)
		if err != nil {
			continue // scanFirstParty already reported it
		}
		switch {
		case name == "Procfile":
			lr.procfile(rel, data)
		case kind == surfDocker:
			lr.dockerfile(rel, data)
		default:
			lr.compose(rel, data)
		}
	}
}
