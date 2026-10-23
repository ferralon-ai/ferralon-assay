package scriptsurface

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// shells are the POSIX-family shells a command may hand a file or shell text to.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true, "mksh": true}

// maxRunBytes bounds a file a shell runs or a . or source reads in place; a larger one withholds.
const maxRunBytes = 1 << 20

// Marks a command leaves in Veto.mentioned beside the base names it names, so that a sample
// hook's are kept apart with the rest of its classification. globKey prefixes the lowercased
// base of a glob the shell expands, which names every bound file it matches; dynKey marks a
// write to a path that expands, which may name any bound file.
const (
	globKey = "\x01g:"
	dynKey  = "\x01dyn"
)

// rebinds reports whether a command names, as an argument, a file an allowed command binds
// to: by exact base name, by a glob over base names, or by a write to a path that expands.
func rebinds(bound, mentioned map[string]bool) bool {
	if len(bound) == 0 {
		return false
	}
	if mentioned[dynKey] {
		return true
	}
	for name := range bound {
		if mentioned[name] {
			return true
		}
	}
	for k := range mentioned {
		pat, ok := strings.CutPrefix(k, globKey)
		if !ok {
			continue
		}
		for name := range bound {
			if m, err := path.Match(pat, name); m || err != nil && pat == name {
				return true
			}
		}
	}
	return false
}

// redirect is one redirection: its operator and target, the word after the operator when the
// operator stands alone.
type redirect struct{ fd, op, target string }

var redirRE = regexp.MustCompile(`^([0-9]*)(<<<|<<-|<<|<>|<&|>&|>>|>\||<|>)(.*)$`)

// redirects splits a command's words into the words it runs and its redirections. An exec-form
// command, or one built from another's words, has none.
func redirects(seg segment) (args []string, rs []redirect) {
	if seg.exec || len(seg.redir) != len(seg.words) {
		return seg.words, nil
	}
	for i := 0; i < len(seg.words); i++ {
		m := redirRE.FindStringSubmatch(seg.words[i])
		if !seg.redir[i] || m == nil {
			args = append(args, seg.words[i])
			continue
		}
		r := redirect{fd: m[1], op: m[2], target: m[3]}
		if r.target == "" && i+1 < len(seg.words) {
			i++
			r.target = seg.words[i]
		}
		rs = append(rs, r)
	}
	return args, rs
}

// runEnv are the variables that name a file a shell runs before its own commands.
var runEnv = map[string]bool{"BASH_ENV": true, "ENV": true}

// unwrap strips the assignments and wrappers before the program a command runs (env,
// command, exec, nohup, sudo, time, nice, timeout). ok is false when a wrapper takes an option
// this does not read, so what it runs is not known; inert is true when it runs nothing.
func unwrap(args []string) (rest []string, inert, ok bool) {
	for len(args) > 0 {
		if m := assignRE.FindStringSubmatch(args[0]); m != nil {
			if runEnv[m[1]] {
				return nil, false, false
			}
			args = args[1:]
			continue
		}
		name, _ := CommandName(args[0])
		i := 1
		switch name {
		case "nohup":
		case "env":
		envArgs:
			for ; i < len(args); i++ {
				a := args[i]
				switch {
				case a == "--":
					i++
					break envArgs
				case a == "-i" || a == "-" || a == "--ignore-environment" || a == "-v" || a == "--debug" || strings.HasPrefix(a, "--unset="):
				case a == "-u" || a == "--unset":
					i++
				case strings.HasPrefix(a, "-"):
					return nil, false, false
				case assignRE.MatchString(a):
					if m := assignRE.FindStringSubmatch(a); runEnv[m[1]] {
						return nil, false, false
					}
				default:
					break envArgs
				}
			}
		case "command":
			for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
				switch args[i] {
				case "-p", "--":
				case "-v", "-V":
					return nil, true, true
				default:
					return nil, false, false
				}
			}
		case "exec":
			for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
				switch args[i] {
				case "-c", "-l", "--":
				case "-a":
					i++
				default:
					return nil, false, false
				}
			}
		case "sudo":
			for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
				switch args[i] {
				case "-E", "-H", "-n", "-S", "-k", "-b", "-P", "--preserve-env", "--":
				case "-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-T", "-D":
					i++
				default:
					return nil, false, false
				}
			}
		case "time":
			for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
				if args[i] != "-p" {
					return nil, false, false
				}
			}
		case "nice":
			for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
				if args[i] == "-n" {
					i++
				}
			}
		case "timeout":
			for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
				switch args[i] {
				case "--preserve-status", "--foreground", "-v", "--verbose":
				case "-s", "-k", "--signal", "--kill-after":
					i++
				default:
					if !strings.HasPrefix(args[i], "--signal=") && !strings.HasPrefix(args[i], "--kill-after=") {
						return nil, false, false
					}
				}
			}
			i++ // the duration
		default:
			return args, false, true
		}
		if i > len(args) {
			i = len(args)
		}
		args = args[i:]
	}
	return nil, true, true
}

var assignRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\+?=`)

// runners are programs that run a command named in their arguments, or one built from what
// they read, which this does not follow; one naming a shell or eval withholds.
var runners = map[string]bool{
	"xargs": true, "parallel": true, "watch": true, "flock": true, "chroot": true, "setsid": true,
	"stdbuf": true, "ionice": true, "taskset": true, "runuser": true, "doas": true, "fakeroot": true,
	"su": true, "script": true, "unbuffer": true, "sg": true, "busybox": true, "find": true,
}

// runsShell reports whether a word names a shell, eval, or . or source.
func runsShell(w string) bool {
	name, _ := CommandName(w)
	return shells[name] || name == "eval" || name == "source" || name == "."
}

// runnerRunsShell reports whether a runner's argument runs a shell. A runner executes a
// program, so a word alone runs one only by naming a shell (find's . is a path); a word
// holding several (su -c, script -c) is a command line, which runs one wherever it names a
// shell, eval, or . or source.
func runnerRunsShell(w string) bool {
	if f := strings.Fields(w); len(f) > 1 {
		return slices.ContainsFunc(f, runsShell)
	}
	name, _ := CommandName(w)
	return shells[name]
}

// shellRun applies the rule to a command that hands a file or shell text to a shell, or runs
// shell text with eval: the file or text is classified as the shell would run it, from a
// shell of its own (from here for eval). handled is false for any other command. Whatever
// runs that this cannot read withholds: a pipe into a shell from anything but cat of one
// literal file, a heredoc whose body is not read as shell lines, a command substitution
// handed to a shell, a wrapper option this does not read before a shell.
func (v *Veto) shellRun(seg segment, cur cursor, depth int) (why string, handled bool) {
	all, rs := redirects(seg)
	args, inert, ok := unwrap(all)
	if !ok {
		if slices.ContainsFunc(all[1:], runsShell) {
			return "shell run behind a wrapper this cannot read: " + strings.Join(seg.words, " "), true
		}
		return "", false
	}
	if inert || len(args) == 0 {
		return "", false
	}
	name, _ := CommandName(args[0])
	if runners[name] && slices.ContainsFunc(args[1:], runnerRunsShell) {
		return "shell run from a command this does not follow: " + strings.Join(seg.words, " "), true
	}
	if name == "eval" {
		text := strings.Join(args[1:], " ")
		if f, ok := catSubst(text); ok {
			return v.runFile(f, cur, depth+1, true), true
		}
		if seg.expands {
			return "eval of text that expands: " + strings.Join(seg.words, " "), true
		}
		return v.runText(text, cur, depth+1), true
	}
	if !shells[name] {
		return "", false
	}
	why = "shell runs what this cannot read: " + strings.Join(seg.words, " ")
	if depth >= maxRunDepth {
		return why, true
	}
	cmd, stdin := false, false
	var operand string
	var files []string // --rcfile and --init-file
	i := 1
opts:
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-" || a == "--":
			i++
			break opts
		case strings.HasPrefix(a, "--"):
			switch a {
			case "--rcfile", "--init-file":
				if i+1 >= len(args) {
					return why, true
				}
				i++
				files = append(files, args[i])
			case "--norc", "--noprofile", "--posix", "--login", "--noediting", "--restricted", "--verbose":
			case "--version", "--help":
				return "", true
			default:
				return why, true
			}
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			for _, c := range a[1:] {
				switch c {
				case 'c':
					cmd = true
				case 's':
					stdin = true
				case 'o', 'O':
					i++
				}
			}
		default:
			break opts
		}
	}
	if i < len(args) {
		operand = args[i]
	}
	for _, f := range files {
		if w := v.runFile(f, cur.fork(), depth+1, false); w != "" {
			return w, true
		}
	}
	switch {
	case cmd:
		if i >= len(args) {
			return why, true
		}
		if strings.Contains(operand, "$(") || strings.Contains(operand, "`") {
			return "shell runs a command substitution: " + strings.Join(seg.words, " "), true
		}
		return v.runText(operand, cur.fork(), depth+1), true
	case operand != "" && !stdin:
		return v.runFile(operand, cur.fork(), depth+1, false), true
	}
	// The shell reads its commands from standard input.
	for _, r := range rs {
		if r.fd != "" && r.fd != "0" {
			continue
		}
		switch r.op {
		case "<":
			return v.runFile(r.target, cur.fork(), depth+1, false), true
		case "<<", "<<-":
			if !v.lineShell {
				return "shell reads a heredoc this does not read: " + strings.Join(seg.words, " "), true
			}
			return "", true // its body is the lines that follow, read as shell lines
		case "<<<":
			if strings.Contains(r.target, "$(") || strings.Contains(r.target, "`") {
				return "shell runs a command substitution: " + strings.Join(seg.words, " "), true
			}
			return v.runText(r.target, cur.fork(), depth+1), true
		case "<>", "<&":
			return why, true
		}
	}
	if seg.from != nil {
		f, ok := catFile(seg.from)
		if !ok {
			return "pipe into a shell: " + strings.Join(seg.words, " "), true
		}
		return v.runFile(f, cur.fork(), depth+1, false), true
	}
	return "", true
}

// catFile returns the one literal file a cat command prints, and whether words is one.
func catFile(words []string) (string, bool) {
	args, inert, ok := unwrap(words)
	if !ok || inert || len(args) != 2 {
		return "", false
	}
	if name, _ := CommandName(args[0]); name != "cat" || strings.HasPrefix(args[1], "-") || hasExpansion(args[1:]) {
		return "", false
	}
	return args[1], true
}

var catSubstRE = regexp.MustCompile(`^\$\(\s*cat\s+([^\s$` + "`" + `()<>;&|'"\\-][^\s$` + "`" + `()<>;&|'"\\]*)\s*\)$`)

// catSubst returns the file of eval text that is exactly $(cat <file>).
func catSubst(text string) (string, bool) {
	m := catSubstRE.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// runFile applies the rule to the file at p, from cur, run by a shell (a fork of the caller's
// cursor) or in place by . or source. It withholds unless p names, from every directory the
// command may run in, a file inside the build, reached through no symlink, not a sample hook,
// at most maxRunBytes, not already running, and setting no installer variable. A file sourced
// from one directory runs in the caller's shell and moves it; one sourced from several leaves
// the caller not knowing where it is when it changes directory.
func (v *Veto) runFile(p string, cur cursor, depth int, sourced bool) string {
	why := "runs a file not read as a script: " + p
	if depth > maxRunDepth {
		return why
	}
	hosts, ok := cur.script(p)
	if !ok || len(hosts) == 0 {
		return why
	}
	for _, h := range hosts {
		if slices.Contains(v.running, h) {
			return "runs a file that runs itself: " + p
		}
		fi, err := os.Stat(h)
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxRunBytes {
			return why
		}
		data, err := v.spec.ReadRegular(h)
		if err != nil || len(data) > maxRunBytes {
			return why
		}
		src := string(data)
		if v.scan {
			v.trigger(src)
		}
		if v.setsEnv(src) {
			return "runs a file that sets an installer variable: " + p
		}
		run := cur
		if !sourced || len(hosts) > 1 {
			run = cur.fork()
		}
		v.running = append(v.running, h)
		w := v.runText(src, run, depth)
		v.running = v.running[:len(v.running)-1]
		if w != "" {
			return w
		}
		if sourced && len(hosts) > 1 && cdRE.MatchString(src) {
			cur.cd(nil)
		}
	}
	return ""
}

// runText applies the rule to shell text run from cur, line by line as a shell script.
func (v *Veto) runText(src string, cur cursor, depth int) string {
	if depth > maxRunDepth {
		return "shell text nested too deep"
	}
	lines, joined := logicalLines(src)
	if !joined && v.hasToken(lines[len(lines)-1]) {
		return "install command in an unjoined continuation"
	}
	prev := v.lineShell
	v.lineShell = true
	defer func() { v.lineShell = prev }()
	mark := cur.venv()
	for _, line := range lines {
		segs, ok, dangles := commandSegments(kindShell, line)
		if mark.dangle && len(segs) > 0 {
			segs[0].guarded = true
		}
		if len(segs) > 0 || !ok {
			mark.dangle = dangles
		}
		if !ok {
			mark.made = ""
			if why := v.untokenised(line, cur); why != "" {
				return why
			}
			if cdRE.MatchString(line) {
				cur.cd(nil)
			}
			continue
		}
		for _, seg := range segs {
			if why := v.command(seg, cur, depth); why != "" {
				return why
			}
		}
	}
	return ""
}

// shellLineRE finds, in a line that does not tokenise, a word that hands text to a shell:
// a shell, eval or source anywhere, or . where a command starts.
var shellLineRE = regexp.MustCompile(`(?:^|[\s;&|(` + "`" + `])(?:[\w./-]*/)?(?:sh|bash|dash|zsh|ksh|ash|mksh|eval|source)(?:$|[\s;&|)` + "`" + `])|(?:^|[;&|(]|then|do|else)\s*\.\s+\S`)

// untokenised applies the rule to a line that does not tokenise: one naming a token, an
// install verb after an expansion, or a shell run withholds, and the rest is mentioned.
func (v *Veto) untokenised(line string, cur cursor) string {
	if v.hasToken(line) {
		return "install command that does not tokenise"
	}
	if expandedInstallLine(line) {
		return "install verb after an expansion that does not tokenise"
	}
	if shellLineRE.MatchString(strings.TrimSpace(line)) {
		return "shell run that does not tokenise: " + strings.TrimSpace(line)
	}
	v.mention(strings.Fields(line))
	v.globs(unquotedGlobWords(line), carriesRE.MatchString(line), cur)
	if dynLine(line) {
		v.mentioned[dynKey] = true
	}
	return ""
}

// dynLine reports whether a line that does not tokenise redirects to a path that expands, or
// hands a writer an operand that does: the line read as blank-separated words, quotes removed,
// split at ;, & and |.
func dynLine(line string) bool {
	for _, part := range strings.FieldsFunc(line, func(r rune) bool { return r == ';' || r == '&' || r == '|' }) {
		words := strings.Fields(part)
		for i, w := range words {
			words[i] = strings.Trim(w, `"'`)
		}
		var args []string
		for i := 0; i < len(words); i++ {
			w := words[i]
			j := strings.IndexByte(w, '>')
			if j < 0 || strings.Trim(w[:j], "0123456789") != "" {
				args = append(args, w)
				continue
			}
			t := strings.Trim(strings.TrimLeft(w[j:], ">|"), `"'`)
			if t == "" && i+1 < len(words) {
				i++
				t = words[i]
			}
			if dynTargets([]string{t}) {
				return true
			}
		}
		if args, _, ok := unwrap(args); ok {
			if ops, ok := writeOperands(args); ok && dynTargets(ops) {
				return true
			}
		}
	}
	return false
}

// runnerVars are the files a CI runner gives a step to write to, which no install reads.
var runnerVars = []string{"$GITHUB_OUTPUT", "$GITHUB_ENV", "$GITHUB_PATH", "$GITHUB_STEP_SUMMARY", "$GITHUB_STATE",
	"${GITHUB_OUTPUT}", "${GITHUB_ENV}", "${GITHUB_PATH}", "${GITHUB_STEP_SUMMARY}", "${GITHUB_STATE}"}

// runnerFile reports whether a write target is one of runnerVars, or under the runner's
// temporary directory.
func runnerFile(t string) bool {
	return slices.Contains(runnerVars, t) || strings.HasPrefix(t, "$RUNNER_TEMP/") || strings.HasPrefix(t, "${RUNNER_TEMP}/")
}

// dynTargets reports whether a write target expands to a path this cannot name: one holding a
// $ or backtick that is not a runner file.
func dynTargets(ts []string) bool {
	for _, t := range ts {
		if strings.ContainsAny(t, "$`") && !runnerFile(t) {
			return true
		}
	}
	return false
}

// writers are the programs that write to a file named among their operands.
var writers = map[string]bool{"sed": true, "perl": true, "mv": true, "cp": true, "tee": true, "install": true,
	"ln": true, "rsync": true, "truncate": true, "patch": true, "dd": true, "curl": true, "wget": true}

// writeOperands returns the operands through which a writer command writes a file, and
// whether words is one.
func writeOperands(words []string) ([]string, bool) {
	if len(words) == 0 {
		return nil, false
	}
	name, _ := CommandName(words[0])
	if !writers[name] {
		return nil, false
	}
	args := words[1:]
	switch name {
	case "sed", "perl":
		inPlace, script := false, name == "sed"
		var ops []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--in-place" || strings.HasPrefix(a, "--in-place=") || strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], "i") && !strings.ContainsAny(a[1:], "e"):
				inPlace = true
			case a == "-e" || a == "-f" || a == "--expression" || a == "--file" || name == "perl" && (a == "-E" || a == "-M"):
				i++
				script = false
			case strings.HasPrefix(a, "-"):
				if name == "perl" && strings.Contains(a, "e") {
					i++ // perl -pie '...' takes the code next
					inPlace = inPlace || strings.Contains(a, "i")
					script = false
				}
			case script:
				script = false
			default:
				ops = append(ops, a)
			}
		}
		if !inPlace {
			return nil, true
		}
		return ops, true
	case "curl", "wget":
		var ops []string
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-o" || a == "-O" && name == "wget" || a == "--output" || a == "--output-document":
				if i+1 < len(args) {
					ops = append(ops, args[i+1])
				}
				i++
			case strings.HasPrefix(a, "--output=") || strings.HasPrefix(a, "--output-document="):
				_, t, _ := strings.Cut(a, "=")
				ops = append(ops, t)
			}
		}
		return ops, true
	}
	var ops []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			ops = append(ops, a)
		}
	}
	return ops, true
}

// writes notes how a command that is not an install writes files this cannot name: a redirect
// to a path that expands, a writer given an operand that expands, xargs feeding a writer, and
// find -exec running one (each a write to any bound file, dynKey), or find matching names by
// a pattern (a glob over them).
func (v *Veto) writes(seg segment) string {
	args, rs := redirects(seg)
	for _, r := range rs {
		if strings.HasPrefix(r.op, "<") || strings.HasPrefix(r.target, "&") || r.target == "/dev/null" {
			continue
		}
		if dynTargets([]string{r.target}) {
			v.mentioned[dynKey] = true
		}
	}
	args, _, ok := unwrap(args)
	if !ok || len(args) == 0 {
		return ""
	}
	if ops, ok := writeOperands(args); ok && dynTargets(ops) {
		v.mentioned[dynKey] = true
	}
	name, _ := CommandName(args[0])
	switch name {
	case "xargs":
		for i := 1; i < len(args); i++ {
			if _, ok := writeOperands(args[i:]); ok {
				v.mentioned[dynKey] = true
			}
		}
	case "find":
		named := false
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "-name", "-iname", "-path", "-ipath", "-wholename":
				if i+1 < len(args) {
					v.mentioned[globKey+strings.ToLower(path.Base(args[i+1]))] = true
					named = true
				}
			case "-exec", "-execdir", "-ok", "-okdir":
				if _, ok := writeOperands(args[i+1:]); ok && !named {
					v.mentioned[dynKey] = true
				}
			case "-delete":
				if !named {
					v.mentioned[dynKey] = true
				}
			}
		}
	}
	return ""
}

// carriers are the programs that put the files they are given somewhere else.
var carriers = map[string]bool{"cp": true, "mv": true, "rsync": true, "install": true, "ln": true}

// carriesRE finds a carrier in a line that does not tokenise.
var carriesRE = regexp.MustCompile(`(?:^|[\s;&|(])(?:cp|mv|rsync|install|ln)\s`)

// carries reports whether a command, past its wrappers, is a carrier.
func carries(words []string) bool {
	args, _, ok := unwrap(words)
	if !ok {
		return true
	}
	if len(args) == 0 {
		return false
	}
	name, _ := CommandName(args[0])
	return carriers[name]
}

// globs records what each word the shell expands as a glob may name, in a command that carries
// what it matches when carry: its base as a glob over the base names of bound files.
func (v *Veto) globs(words []string, carry bool, cur cursor) {
	for _, w := range words {
		w = trimShell(w)
		if i := strings.LastIndexAny(w, "<>"); i >= 0 {
			w = w[i+1:]
		}
		if i := strings.LastIndexByte(w, '='); i >= 0 {
			w = trimShell(w[i+1:])
		}
		for _, a := range braces(filepath.ToSlash(w), 0) {
			b := path.Base(a)
			if !strings.ContainsAny(b, "*?[") || !cur.globReach(a, carry) {
				continue
			}
			if _, err := path.Match(b, ""); err != nil {
				continue // the shell leaves a malformed pattern as it is: [ alone is the test command
			}
			v.mentioned[globKey+strings.ToLower(b)] = true
		}
	}
}

// globbedWords returns the words of a command the shell expands as globs.
func globbedWords(seg segment) []string {
	var out []string
	for i, w := range seg.words {
		if i < len(seg.globbed) && seg.globbed[i] {
			out = append(out, w)
		}
	}
	return out
}

// unquotedGlobWords splits a line that does not tokenise on blanks, keeping the words that hold
// a glob character outside quotes; an unterminated quote keeps every word.
func unquotedGlobWords(line string) []string {
	var out []string
	var w strings.Builder
	glob := false
	q := byte(0)
	flush := func() {
		if glob {
			out = append(out, w.String())
		}
		w.Reset()
		glob = false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				w.WriteByte(c)
			}
		case c == '\'' || c == '"':
			q = c
		case c == ' ' || c == '\t':
			flush()
		default:
			w.WriteByte(c)
			glob = glob || c == '*' || c == '?' || c == '['
		}
	}
	if q != 0 {
		return strings.Fields(line)
	}
	flush()
	return out
}
