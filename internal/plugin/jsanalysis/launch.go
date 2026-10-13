package jsanalysis

// launch.go reads the commands a deployed process starts with: every first-party package.json's
// start script (with prestart and poststart), every Procfile line, the ENTRYPOINT, CMD and
// HEALTHCHECK of every Dockerfile stage, every compose service, every container in a Kubernetes
// manifest, every Exec line of a systemd unit, and the start commands of the deploy platforms'
// config files (launchsurfaces.go). A package whose bin such a command runs executes in
// production whatever its lockfile marker says, so every installed instance providing that bin
// is a runtime root.
//
// The reader accepts a command only when it knows what runs. A command word is a known shell
// builtin or system tool, a wrapper it follows (env, exec, tini, corepack, ...), a package
// manager it follows into the scripts it runs, a shell or first-party script it reads, or an
// installed bin. A script a container runs is followed through the Docker build that put it
// there. Anything else withholds every refutation: an unknown command, a process manager, a
// script the image supplies, a base image's own launch command, a variable naming what runs,
// inline node code, or shell text the reader cannot parse.

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

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
	seen  map[string]bool // scripts already expanded, by manifest, name and image
	files map[string]bool // shell scripts already followed, by path, arguments and image

	img      *imageCtx // the container the command runs in; nil outside one
	pos      []shWord  // positional parameters of the shell text being read
	posKnown bool

	images   map[string]*dockerImage // every Dockerfile read, by build-relative path
	contexts []string                // docker build contexts the launch surfaces name
}

const maxLaunchDepth = 8

// unknownDir is the working directory of a command after a cd the reader cannot follow. A
// working directory is otherwise build-relative ("" is the build dir), or an absolute path
// inside a container.
const unknownDir = "\x00"

// shWord is one shell word after quote removal. dynamic: it holds an expansion ($...), so its
// value is not known. raw: the word's text is known exactly, and only a shell reading it as
// shell text would expand it (a Dockerfile exec-form word, a Kubernetes argument).
type shWord struct {
	text    string
	dynamic bool
	raw     bool
}

func literal(words ...string) []shWord {
	out := make([]shWord, len(words))
	for i, w := range words {
		out[i] = shWord{text: w}
	}
	return out
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

var (
	shellAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	posParam    = regexp.MustCompile(`^\$(?:([0-9])|\{([0-9]+)\})$`)
)

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
	shellNames = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true}
	// nodeLike run a JavaScript file the way node does.
	nodeLike = map[string]bool{"node": true, "nodejs": true, "ts-node": true, "tsx": true, "babel-node": true, "vite-node": true, "esno": true, "esr": true}
	// processWrappers run commands, scripts or config files the reader does not follow.
	processWrappers = map[string]bool{
		"forever": true, "pm2": true, "pm2-runtime": true, "pm2-docker": true, "pm2-dev": true,
		"nodemon": true, "supervisor": true, "node-supervisor": true, "node-dev": true,
		"ts-node-dev": true, "tsnd": true, "start-server-and-test": true, "server-test": true,
		"nx": true, "lerna": true, "onchange": true, "chokidar": true, "run-script-os": true,
		"cross-var": true, "dotenvx": true, "foreman": true, "nf": true, "honcho": true,
		"overmind": true, "supervisord": true, "s6-svscan": true, "runsvdir": true, "xargs": true,
		"find": true, "awk": true, "flock": true, "watch": true, "su": true, "parallel": true,
	}
	// systemCommands run no package code; the reader accepts them as they are.
	systemCommands = map[string]bool{
		"echo": true, "printf": true, "true": true, "false": true, ":": true, "pwd": true,
		"export": true, "unset": true, "set": true, "shift": true, "wait": true, "exit": true,
		"return": true, "ulimit": true, "umask": true, "sleep": true, "test": true, "[": true,
		"mkdir": true, "rm": true, "rmdir": true, "cp": true, "mv": true, "ln": true, "chmod": true,
		"chown": true, "chgrp": true, "touch": true, "cat": true, "ls": true, "head": true,
		"tail": true, "grep": true, "sed": true, "tr": true, "cut": true, "sort": true, "uniq": true,
		"wc": true, "tee": true, "date": true, "id": true, "whoami": true, "hostname": true,
		"uname": true, "basename": true, "dirname": true, "readlink": true, "realpath": true,
		"mktemp": true, "stat": true, "df": true, "du": true, "envsubst": true, "curl": true,
		"wget": true, "tar": true, "gzip": true, "gunzip": true, "unzip": true, "which": true,
		"type": true, "hash": true, "read": true, "local": true, "declare": true, "typeset": true,
		"readonly": true, "let": true, "printenv": true, "kill": true, "ps": true, "getent": true,
		"jq": true, "nc": true, "netcat": true, "update-ca-certificates": true, "logger": true,
	}
	// argOnlyBins are installed bins whose arguments name files and options, never commands.
	argOnlyBins = map[string]bool{
		"next": true, "nuxt": true, "nuxi": true, "vite": true, "react-scripts": true, "nest": true,
		"remix-serve": true, "serve": true, "http-server": true, "astro": true, "gatsby": true,
		"ng": true, "vue-cli-service": true, "tsc": true,
	}
	// nodeValueFlags are node options whose value is the next word.
	nodeValueFlags = " -r --require --import --loader --experimental-loader --title --env-file --input-type --conditions -C --inspect-port --redirect-warnings --diagnostic-dir --report-directory --icu-data-dir --openssl-config --secure-heap --stack-trace-limit --run "
	// pmValueFlags are npm, yarn, pnpm and bun options whose value is the next word.
	pmValueFlags = " --prefix -w --workspace --cwd -C --dir --filter -F --userconfig --registry --cache --loglevel --script-shell --package -p --call -c "
	// pmBuiltins are package manager subcommands that run no script or bin at launch.
	pmBuiltins = map[string]bool{
		"install": true, "i": true, "add": true, "remove": true, "rm": true, "uninstall": true,
		"un": true, "up": true, "upgrade": true, "update": true, "ci": true, "prune": true,
		"link": true, "unlink": true, "audit": true, "outdated": true, "info": true, "view": true,
		"why": true, "list": true, "ls": true, "cache": true, "config": true, "version": true,
		"versions": true, "help": true, "dedupe": true, "rebuild": true, "rb": true, "pack": true,
		"publish": true, "login": true, "logout": true, "whoami": true, "store": true, "fetch": true,
		"import": true, "licenses": true, "check": true, "autoclean": true, "bin": true,
		"owner": true, "tag": true, "plugin": true, "constraints": true, "explain": true,
		"--version": true, "-v": true,
	}
)

func hasFlag(list, f string) bool { return strings.Contains(list, " "+f+" ") }

func isContainerDir(dir string) bool { return strings.HasPrefix(dir, "/") }

// shell evaluates shell text that runs at launch in working directory dir.
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
		dir = lr.command(label, c, dir, depth)
	}
}

// withShell runs f with fresh positional parameters (a new shell process).
func (lr *launchReader) withShell(pos []shWord, f func()) {
	savedPos, savedKnown := lr.pos, lr.posKnown
	lr.pos, lr.posKnown = pos, true
	f()
	lr.pos, lr.posKnown = savedPos, savedKnown
}

// command evaluates one simple command and returns the working directory after it.
func (lr *launchReader) command(label string, w []shWord, dir string, depth int) string {
	if depth > maxLaunchDepth {
		lr.ls.gap("%s: launch commands nest too deep", label)
		return dir
	}
	w, ok := lr.expand(label, w)
	if !ok {
		return dir
	}
	for len(w) > 0 && shellAssign.MatchString(w[0].text) {
		w = w[1:]
	}
	if len(w) == 0 {
		return dir
	}
	lr.sweep(label, w, dir)
	head := w[0]
	if head.dynamic {
		lr.ls.gap("%s: a variable names the launch command", label)
		return dir
	}
	if shellKeywords[head.text] || head.text == "!" {
		lr.ls.gap("%s: launch command not parsed (shell control flow)", label)
		return dir
	}
	switch head.text {
	case "cd", "pushd":
		return lr.cd(w[1:], dir)
	case "popd":
		return unknownDir
	}
	lr.run(label, head.text, w[1:], dir, depth)
	return dir
}

// expand substitutes the positional parameters of the script being read.
func (lr *launchReader) expand(label string, w []shWord) ([]shWord, bool) {
	out := make([]shWord, 0, len(w))
	for _, x := range w {
		if !x.dynamic {
			out = append(out, x)
			continue
		}
		t := x.text
		m := posParam.FindStringSubmatch(t)
		all := t == "$@" || t == "${@}" || t == "$*" || t == "${*}"
		if !all && m == nil {
			out = append(out, x)
			continue
		}
		if !lr.posKnown {
			lr.ls.gap("%s: the arguments a script runs with are not known", label)
			return nil, false
		}
		if all {
			out = append(out, lr.pos...)
			continue
		}
		n, _ := strconv.Atoi(m[1] + m[2])
		switch {
		case n == 0:
			out = append(out, x) // the script's own name
		case n <= len(lr.pos):
			out = append(out, lr.pos[n-1])
		}
	}
	return out, true
}

// sweep roots every installed bin a literal word names and every package a node_modules path
// names. That covers a bin run through any wrapper, and over-approximates an argument that
// only shares a bin's name.
func (lr *launchReader) sweep(label string, w []shWord, dir string) {
	for _, x := range w {
		if x.dynamic {
			if strings.Contains(x.text, "node_modules/") {
				lr.ls.gap("%s: a variable names a path into node_modules", label)
			}
			continue
		}
		lr.bin(label, x.text)
		if strings.Contains(x.text, "node_modules/") {
			lr.nodeModulesRef(label, x.text, dir)
		}
	}
}

func (lr *launchReader) cd(args []shWord, dir string) string {
	for len(args) > 0 && (args[0].text == "-L" || args[0].text == "-P" || args[0].text == "--") {
		args = args[1:]
	}
	if len(args) == 0 || args[0].dynamic || args[0].text == "-" || dir == unknownDir {
		return unknownDir
	}
	t := args[0].text
	switch {
	case path.IsAbs(t):
		if lr.img == nil && !isContainerDir(dir) {
			return unknownDir
		}
		return path.Clean(t)
	case isContainerDir(dir):
		return path.Join(dir, t)
	}
	r := normRel(joinRel(dir, t))
	if !lr.m.inside(r) {
		return unknownDir
	}
	return r
}

// run evaluates command name with its arguments.
func (lr *launchReader) run(label, name string, args []shWord, dir string, depth int) {
	if strings.Contains(name, "/") {
		lr.runPath(label, name, args, dir, depth)
		return
	}
	if lr.builtin(label, name, args, dir, depth) {
		return
	}
	if lr.img != nil && lr.img.df != nil {
		found := false
		for _, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			srcs, _, unknown := lr.containerFile(d+"/"+name, false)
			if unknown {
				lr.ls.gap("%s: launch command runs %s, which the image's PATH may supply from a source the reader cannot see", label, name)
				return
			}
			for _, s := range srcs {
				lr.followTree(label, s, args, dir, depth, fileExec)
				found = true
			}
			if found {
				return
			}
		}
	}
	if len(lr.m.byBin[name]) > 0 {
		lr.toolArgs(label, name, args, dir, depth)
		return
	}
	if lr.img != nil && lr.img.kind == imgNode && name == "docker-entrypoint.sh" {
		lr.nodeEntrypoint(label, args, dir, depth)
		return
	}
	lr.ls.gap("%s: launch command runs %s, which the reader does not follow", label, name)
}

// isBuiltin reports whether the reader handles command name itself.
func isBuiltin(name string) bool {
	if _, ok := launchWrappers[name]; ok {
		return true
	}
	switch name {
	case "cross-env-shell", "corepack", "eval", ".", "source", "trap", "npm", "npx", "pnpx", "bunx",
		"yarn", "pnpm", "bun", "npm-run-all", "run-p", "run-s", "concurrently":
		return true
	}
	return processWrappers[name] || systemCommands[name] || nodeLike[name] || shellNames[name]
}

// builtin evaluates a command the reader handles itself and reports whether name is one.
func (lr *launchReader) builtin(label, name string, args []shWord, dir string, depth int) bool {
	if wr, ok := launchWrappers[name]; ok {
		if name == "command" && len(args) > 0 && (args[0].text == "-v" || args[0].text == "-V") {
			return true
		}
		i := 0
		for i < len(args) && strings.HasPrefix(args[i].text, "-") {
			if args[i].text == "--" {
				i++
				break
			}
			if name == "env" && (args[i].text == "-S" || strings.HasPrefix(args[i].text, "--split-string")) {
				lr.ls.gap("%s: launch command not parsed (env splits a string into a command)", label)
				return true
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
		return true
	}
	switch {
	case processWrappers[name]:
		lr.ls.gap("%s: launch command runs %s, which runs commands the reader does not follow", label, name)
	case systemCommands[name]:
		lr.positional(name, args)
	case nodeLike[name]:
		lr.node(label, args, dir, depth)
	case shellNames[name]:
		lr.sh(label, args, dir, depth)
	default:
		switch name {
		case "cross-env-shell":
			lr.ls.gap("%s: launch command not parsed (%s runs its arguments as shell text)", label, name)
		case "eval":
			lr.ls.gap("%s: launch command runs eval", label)
		case "corepack":
			lr.corepack(label, args, dir, depth)
		case ".", "source":
			switch {
			case len(args) == 0:
			case args[0].dynamic:
				lr.ls.gap("%s: a variable names the file a script sources", label)
			default:
				lr.file(label, args[0].text, args[1:], dir, depth, fileSource)
			}
		case "trap":
			if len(args) > 0 {
				if args[0].dynamic {
					lr.ls.gap("%s: a variable names the command a trap runs", label)
				} else {
					lr.shell(label, args[0].text, dir, depth+1)
				}
			}
		case "npm":
			lr.npm(label, args, dir, depth)
		case "npx", "pnpx", "bunx":
			lr.runner(label, args, dir, depth)
		case "yarn", "pnpm", "bun":
			lr.pm(label, name, args, dir, depth)
		case "npm-run-all", "run-p", "run-s":
			lr.runAll(label, name, args, depth)
		case "concurrently":
			lr.concurrently(label, args, dir, depth)
		default:
			return false
		}
	}
	return true
}

// positional applies shift and set -- to the positional parameters.
func (lr *launchReader) positional(name string, args []shWord) {
	switch name {
	case "shift":
		n := 1
		if len(args) > 0 {
			v, err := strconv.Atoi(args[0].text)
			if args[0].dynamic || err != nil {
				lr.posKnown = false
				return
			}
			n = v
		}
		lr.pos = lr.pos[min(n, len(lr.pos)):]
	case "set":
		for i := 0; i < len(args); i++ {
			a := args[i].text
			switch {
			case a == "--":
				lr.pos, lr.posKnown = append([]shWord(nil), args[i+1:]...), true
				return
			case a == "-o" || a == "+o":
				i++
			case args[i].dynamic:
				lr.posKnown = false
				return
			case !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+"):
				lr.pos, lr.posKnown = append([]shWord(nil), args[i:]...), true
				return
			}
		}
	}
}

// runPath evaluates a command named by a path.
func (lr *launchReader) runPath(label, p string, args []shWord, dir string, depth int) {
	if name, ok := lr.nodeModulesRef(label, p, dir); ok {
		if name != "" {
			lr.pkgRun(label, name, args, dir, depth)
		}
		return
	}
	lr.file(label, p, args, dir, depth, fileExec)
}

// pkgRun evaluates the arguments of installed package code run by path.
func (lr *launchReader) pkgRun(label, name string, args []shWord, dir string, depth int) {
	if !lr.builtin(label, name, args, dir, depth) {
		lr.toolArgs(label, name, args, dir, depth)
	}
}

type fileMode int

const (
	fileExec   fileMode = iota // run as a program: its shebang decides how it is read
	fileShell                  // run by a shell: read as shell text whatever its shebang
	fileSource                 // sourced: read as shell text in the current shell
)

// file follows a file a launch command runs by path: in a container through the build that put
// it there, elsewhere inside the build dir.
func (lr *launchReader) file(label, p string, args []shWord, dir string, depth int, mode fileMode) {
	switch {
	case path.IsAbs(p):
		lr.containerPath(label, path.Clean(p), args, dir, depth, mode)
	case isContainerDir(dir):
		lr.containerPath(label, path.Join(dir, p), args, dir, depth, mode)
	case dir == unknownDir:
		lr.ls.gap("%s: launch command runs %s from a directory the reader cannot determine", label, p)
	default:
		r := normRel(joinRel(dir, p))
		if !lr.m.inside(r) {
			lr.ls.gap("%s: launch command runs %s, which is outside the build dir", label, p)
			return
		}
		lr.followTree(label, r, args, dir, depth, mode)
	}
}

// containerPath follows a file a container runs by absolute path. A file the Docker build
// copies from the build dir is read; a system tool the reader knows runs as itself; the node
// image's docker-entrypoint.sh is modelled; anything else the image supplies withholds.
func (lr *launchReader) containerPath(label, cp string, args []shWord, dir string, depth int, mode fileMode) {
	if lr.img != nil && lr.img.df != nil {
		srcs, absent, unknown := lr.containerFile(cp, true)
		if unknown {
			lr.ls.gap("%s: launch command runs %s, which comes from a source the reader cannot see", label, cp)
			return
		}
		for _, s := range srcs {
			lr.followTree(label, s, args, dir, depth, mode)
		}
		if !absent {
			return
		}
	}
	base := path.Base(cp)
	switch {
	case mode == fileExec && systemBins[path.Dir(cp)] && isBuiltin(base):
		lr.run(label, base, args, dir, depth)
	case mode == fileExec && lr.img != nil && lr.img.kind == imgNode && cp == "/usr/local/bin/docker-entrypoint.sh":
		lr.nodeEntrypoint(label, args, dir, depth)
	case lr.img == nil:
		lr.ls.gap("%s: launch command runs %s, which is not in the build dir", label, cp)
	default:
		lr.ls.gap("%s: launch command runs %s, which the image supplies", label, cp)
	}
}

// followTree reads build-relative file rel that a launch command runs.
func (lr *launchReader) followTree(label, rel string, args []shWord, dir string, depth int, mode fileMode) {
	data, err := lr.m.readFirstParty(rel)
	if err != nil {
		lr.ls.gap("%s: launch command runs %s, which is %s", label, rel, unreadableWhy(err))
		return
	}
	ext := strings.ToLower(path.Ext(rel))
	first, _, _ := strings.Cut(string(data), "\n")
	shebang := strings.HasPrefix(first, "#!")
	switch {
	case mode == fileExec && (codeExts[ext] || shebang && strings.Contains(first, "node")):
		return // first-party JavaScript, which the scan reads as code
	case mode != fileExec || ext == ".sh" || ext == ".bash" || shellShebang(data) || !shebang:
		pos, known := args, true
		if mode == fileSource && len(args) == 0 {
			pos, known = lr.pos, lr.posKnown
		}
		key := fmt.Sprintf("%s\x00%v\x00%v\x00%v", rel, known, pos, lr.imgKey())
		if lr.files[key] {
			return
		}
		lr.files[key] = true
		savedPos, savedKnown := lr.pos, lr.posKnown
		lr.pos, lr.posKnown = pos, known
		lr.shell(rel, string(data), dir, depth+1)
		lr.pos, lr.posKnown = savedPos, savedKnown
	default:
		lr.ls.gap("%s: launch command runs %s, a script for an interpreter the reader does not follow", label, rel)
	}
}

func (lr *launchReader) imgKey() string {
	if lr.img == nil {
		return ""
	}
	if lr.img.df != nil {
		return lr.img.df.rel + "#" + strconv.Itoa(lr.img.idx)
	}
	return "image " + lr.img.ref
}

// toolArgs evaluates the arguments of an installed bin: one that only takes files and options
// needs nothing more; otherwise an argument holding a space may be a command it runs, a word
// naming a script or a shell file may be run, a command follows `--`, and a variable makes
// what it runs unknown.
func (lr *launchReader) toolArgs(label, name string, args []shWord, dir string, depth int) {
	if argOnlyBins[name] {
		return
	}
	for i, a := range args {
		ext := strings.ToLower(path.Ext(a.text))
		switch {
		case a.dynamic:
			lr.ls.gap("%s: %s runs with an argument a variable sets", label, name)
			return
		case a.text == "--":
			if i+1 < len(args) {
				lr.command(label, args[i+1:], dir, depth+1)
			}
			return
		case strings.ContainsAny(a.text, " \t"):
			lr.shell(label, a.text, dir, depth+1)
		case lr.hasScript(a.text):
			lr.script(label, a.text, depth)
		case ext == ".sh" || ext == ".bash":
			lr.file(label, a.text, nil, dir, depth, fileShell)
		}
	}
}

// bin roots every installed instance that provides bin name.
func (lr *launchReader) bin(label, name string) {
	for _, in := range lr.m.byBin[name] {
		lr.out.launched = append(lr.out.launched, launchRoot{in: in, label: label + " (runs " + name + ")"})
	}
}

// rootSpec roots the package a bare specifier names, resolved from dir when dir is in the
// build dir, and every installed instance of that name otherwise.
func (lr *launchReader) rootSpec(label, spec, dir string) {
	if !isContainerDir(dir) && dir != unknownDir {
		lr.out.runtime = append(lr.out.runtime, rootRef{spec: spec, from: dir, label: label, fallback: true})
		return
	}
	pkg, _ := splitBareSpecifier(spec)
	for _, in := range lr.m.byDir[pkg] {
		lr.out.launched = append(lr.out.launched, launchRoot{in: in, label: label})
	}
}

// nodeModulesRef roots the package a path into node_modules names: node_modules/.bin/x runs
// bin x, node_modules/<pkg>/... runs a file of pkg. ok reports a node_modules path; name is
// the bin or package that runs ("" when the path withholds).
func (lr *launchReader) nodeModulesRef(label, p, dir string) (name string, ok bool) {
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return "", false
	}
	rest := p[i+len("node_modules/"):]
	if b, ok := strings.CutPrefix(rest, ".bin/"); ok {
		if len(lr.m.byBin[b]) == 0 {
			lr.ls.gap("%s: launch command runs %s, which no installed package provides", label, p)
			return "", true
		}
		lr.bin(label, b)
		return b, true
	}
	segs := strings.Split(rest, "/")
	pkg := segs[0]
	if strings.HasPrefix(pkg, "@") && len(segs) > 1 {
		pkg += "/" + segs[1]
	}
	if pkg == "" || strings.HasPrefix(pkg, ".") {
		lr.ls.gap("%s: launch command runs %s, which names no package", label, p)
		return "", true
	}
	from := dir
	if path.IsAbs(p) {
		from = unknownDir // which install tree an absolute path names is not known
	}
	lr.rootSpec(label+" (runs "+p+")", pkg, from)
	return pkg, true
}

// node reads `node [options] script`: inline code or a script from standard input is not
// parsed, a preloaded module is a root, and a script inside node_modules runs that package.
func (lr *launchReader) node(label string, args []shWord, dir string, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		f, v, hasValue := strings.Cut(a.text, "=")
		switch {
		case f == "-e" || f == "--eval" || f == "-p" || f == "--print" || a.text == "-":
			lr.ls.gap("%s: node runs inline code", label)
			return
		case strings.HasPrefix(a.text, "-"):
			dyn := a.dynamic
			if hasFlag(nodeValueFlags, f) && !hasValue {
				i++
				if i >= len(args) {
					return
				}
				v, dyn, hasValue = args[i].text, args[i].dynamic, true
			}
			if !hasValue {
				continue
			}
			switch {
			case f == "--run":
				if dyn {
					lr.ls.gap("%s: a variable names the script node runs", label)
					return
				}
				lr.script(label, v, depth)
			case f == "-r" || f == "--require" || f == "--import" || strings.Contains(f, "loader"):
				switch {
				case dyn:
					lr.ls.gap("%s: a variable names a preloaded module", label)
					return
				case isBareSpecifier(v):
					lr.rootSpec(label+" (preload "+v+")", v, dir)
				}
			}
		case a.dynamic:
			lr.ls.gap("%s: a variable names the script node runs", label)
			return
		default:
			if name, ok := lr.nodeModulesRef(label, a.text, dir); ok && name != "" {
				lr.pkgRun(label, name, args[i+1:], dir, depth)
			}
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
		for i, a := range args {
			if a.text == pos[0].text {
				lr.runner(label, args[i+1:], dir, depth)
				break
			}
		}
	case "explore", "create", "init":
		lr.ls.gap("%s: npm %s runs a command the reader does not follow", label, pos[0].text)
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
	case sub == "workspace":
		if len(pos) > 2 {
			lr.pm(label, tool, pos[2:], dir, depth)
		}
		return
	case sub == "workspaces" && len(pos) > 1 && pos[1].text == "foreach":
		lr.pm(label, tool, pos[2:], dir, depth)
		return
	case sub == "workspaces" && len(pos) > 2 && pos[1].text == "run":
		lr.scriptWord(label, pos[2], depth)
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
	case pmBuiltins[sub] || tool == "bun" && (sub == "build" || sub == "test" || sub == "pm" || sub == "upgrade"):
		return
	}
	if lr.hasScript(sub) {
		lr.script(label, sub, depth)
		return
	}
	if codeExts[strings.ToLower(path.Ext(sub))] || strings.Contains(sub, "/") {
		if name, ok := lr.nodeModulesRef(label, sub, dir); ok && name != "" {
			lr.pkgRun(label, name, pos[1:], dir, depth)
		}
		return // otherwise a first-party file, which the scan reads as code
	}
	lr.run(label, sub, pos[1:], dir, depth)
}

// runner reads npx-style commands: -p/--package names packages, -c runs shell text, and the
// first positional is the package or bin that runs, with the rest as its arguments.
func (lr *launchReader) runner(label string, args []shWord, dir string, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		f, v, hasValue := strings.Cut(a.text, "=")
		if !strings.HasPrefix(a.text, "-") {
			if a.dynamic {
				lr.ls.gap("%s: a variable names the package a runner runs", label)
				return
			}
			if name := lr.spec(label, a.text, dir); name != "" {
				lr.run(label, name, args[i+1:], dir, depth)
			}
			return
		}
		if f == "--" {
			continue
		}
		switch {
		case f == "-p" || f == "--package" || f == "-c" || f == "--call":
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
		case !hasValue && hasFlag(pmValueFlags, f):
			i++
		}
	}
}

// spec roots a package spec (name, name@version) and any bin it names, and returns the
// command it runs: the spec's name, or for a scoped package its one bin.
func (lr *launchReader) spec(label, s, dir string) string {
	name, _ := splitSpec(s)
	if name == "" {
		return ""
	}
	lr.bin(label, name)
	if validNpmName.MatchString(name) {
		lr.out.runtime = append(lr.out.runtime, rootRef{spec: name, from: specDir(dir), label: label + " (runs " + name + ")", fallback: true})
	}
	if !strings.HasPrefix(name, "@") {
		return name
	}
	bins := map[string]bool{}
	for _, in := range lr.m.byName[canonicalNpmName(name)] {
		for _, b := range in.bins {
			bins[b] = true
		}
	}
	if len(bins) != 1 {
		lr.ls.gap("%s: launch command runs %s, whose bin the reader cannot determine", label, name)
		return ""
	}
	for b := range bins {
		return b
	}
	return ""
}

// specDir is the build-relative directory a root resolves from ("" when dir is not one).
func specDir(dir string) string {
	if isContainerDir(dir) || dir == unknownDir {
		return ""
	}
	return dir
}

// runAll reads npm-run-all, run-p and run-s: every positional names a script (or a glob).
func (lr *launchReader) runAll(label, name string, args []shWord, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a.dynamic:
			lr.ls.gap("%s: a variable names a script %s runs", label, name)
			return
		case a.text == "--":
			return
		case a.text == "--npm-path" || a.text == "--max-parallel":
			i++
		case strings.HasPrefix(a.text, "-"):
		default:
			if f := strings.Fields(a.text); len(f) > 0 {
				lr.script(label, f[0], depth)
			}
		}
	}
}

// concurrentlyValueFlags are concurrently options whose value is the next word.
const concurrentlyValueFlags = " -n --names -c --prefix-colors -p --prefix -l --prefix-length -t --timestamp-format --default-input-target -s --success --restart-tries --restart-after --kill-signal --name-separator -m --max-processes -P "

// concurrently reads every positional as a command, or as a script with an npm:, yarn:,
// pnpm:, bun: or node: prefix.
func (lr *launchReader) concurrently(label string, args []shWord, dir string, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a.dynamic:
			lr.ls.gap("%s: a variable names a command concurrently runs", label)
			return
		case strings.HasPrefix(a.text, "-"):
			if !strings.Contains(a.text, "=") && hasFlag(concurrentlyValueFlags, a.text) {
				i++
			}
		default:
			if pm, s, ok := strings.Cut(a.text, ":"); ok && (pm == "npm" || pm == "yarn" || pm == "pnpm" || pm == "bun" || pm == "node") {
				if f := strings.Fields(s); len(f) > 0 {
					lr.script(label, f[0], depth)
				}
				continue
			}
			lr.shell(label, a.text, dir, depth+1)
		}
	}
}

// corepack runs the package manager it names.
func (lr *launchReader) corepack(label string, args []shWord, dir string, depth int) {
	for i, a := range args {
		if a.dynamic {
			lr.ls.gap("%s: a variable names what corepack runs", label)
			return
		}
		if strings.HasPrefix(a.text, "-") {
			continue
		}
		tool, _, _ := strings.Cut(a.text, "@")
		rest := args[i+1:]
		switch tool {
		case "npm":
			lr.npm(label, rest, dir, depth)
		case "npx", "pnpx":
			lr.runner(label, rest, dir, depth)
		case "pnpm", "yarn":
			lr.pm(label, tool, rest, dir, depth)
		case "yarnpkg":
			lr.pm(label, "yarn", rest, dir, depth)
		case "enable", "disable", "prepare", "install", "use", "up", "pack", "hydrate", "cache":
		default:
			lr.ls.gap("%s: corepack runs %s, which the reader does not follow", label, a.text)
		}
		return
	}
}

func (lr *launchReader) sh(label string, args []shWord, dir string, depth int) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a.text == "-c" || strings.HasPrefix(a.text, "-") && strings.Contains(a.text, "c") && !strings.HasPrefix(a.text, "--"):
			if i+1 >= len(args) || args[i+1].dynamic && !args[i+1].raw {
				lr.ls.gap("%s: launch command not parsed (shell text the reader cannot see)", label)
				return
			}
			var pos []shWord
			if i+3 <= len(args) {
				pos = args[i+3:] // $0 is args[i+2]
			}
			lr.withShell(pos, func() { lr.shell(label, args[i+1].text, dir, depth+1) })
			return
		case a.text == "-o" || a.text == "+o":
			i++
		case strings.HasPrefix(a.text, "-") && strings.Contains(a.text, "s") && !strings.HasPrefix(a.text, "--"):
			lr.ls.gap("%s: launch command runs shell text from standard input", label)
			return
		case strings.HasPrefix(a.text, "-") || strings.HasPrefix(a.text, "+"):
		case a.dynamic:
			lr.ls.gap("%s: a variable names the script a shell runs", label)
			return
		default:
			lr.file(label, a.text, args[i+1:], dir, depth, fileShell)
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
		lr.ls.gap("%s: a variable names the script a package manager runs", label)
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
			key := ms.rel + "\x00" + k + "\x00" + lr.imgKey()
			if lr.seen[key] {
				continue
			}
			lr.seen[key] = true
			for _, s := range []string{"pre" + k, k, "post" + k} {
				if cmd, ok := ms.scripts[s]; ok {
					lr.withShell(nil, func() { lr.shell(ms.rel+" scripts."+s, cmd, ms.dir, depth+1) })
				}
			}
		}
	}
}
