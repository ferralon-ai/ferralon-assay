package scriptsurface

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
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

var redirRE = regexp.MustCompile(`^([0-9]*)(<<<|<<-|<<|<>|<&|>&|>>|>\||&>>|&>|<|>)(.*)$`)

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

// leadRedirects moves the redirections written before a command's program after its words,
// as the shell reads >f cmd, so that words[0] is the program.
func leadRedirects(seg segment) segment {
	if seg.exec || len(seg.redir) != len(seg.words) || len(seg.globbed) != len(seg.words) {
		return seg
	}
	n := 0
	for n < len(seg.words) && seg.redir[n] {
		m := redirRE.FindStringSubmatch(seg.words[n])
		if m == nil {
			break
		}
		n++
		if m[3] == "" && n < len(seg.words) {
			n++
		}
	}
	if n == 0 || n == len(seg.words) {
		return seg
	}
	rot := func(a []string) []string { return append(slices.Clone(a[n:]), a[:n]...) }
	rotb := func(a []bool) []bool { return append(slices.Clone(a[n:]), a[:n]...) }
	seg.words, seg.globbed, seg.redir = rot(seg.words), rotb(seg.globbed), rotb(seg.redir)
	return seg
}

// keywordHead returns how many words before a command are reserved words that only lead into
// it (if, then, do, else, elif, while, until, !, time and its -p), so that the command after
// them is seen; 0 when there are none.
func keywordHead(words []string) int {
	n := 0
	for n < len(words) {
		switch words[n] {
		case "if", "then", "do", "else", "elif", "while", "until", "!":
			n++
		case "time":
			n++
			if n < len(words) && words[n] == "-p" {
				n++
			}
		default:
			return n
		}
	}
	return n
}

// sourceHead returns how many words before a . or source only prefix it (assignments,
// command, builtin), so that the file it reads is seen; 0 when there are none or no . follows.
func sourceHead(words []string) int {
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case assignRE.MatchString(w):
		case w == "command" || w == "builtin":
			for i+1 < len(words) && (words[i+1] == "-p" || words[i+1] == "--") && w == "command" {
				i++
			}
		case w == "." || w == "source":
			return i
		default:
			return 0
		}
	}
	return 0
}

// drop returns the segment without its first n words.
func (s segment) drop(n int) segment {
	s.words = s.words[n:]
	if len(s.globbed) >= n {
		s.globbed = s.globbed[n:]
	}
	if len(s.redir) >= n {
		s.redir = s.redir[n:]
	}
	return s
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
		case "busybox", "toybox":
			// A multi-call binary runs the applet its first operand names.
			if len(args) > 1 && strings.HasPrefix(args[1], "-") {
				return nil, false, false
			}
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
				case a == "-S" || a == "--split-string" || strings.HasPrefix(a, "-S") || strings.HasPrefix(a, "--split-string="):
					// -S splits its string into the words that follow, which this reads only
					// when nothing in it is quoted, escaped or expanded.
					str, rest := strings.TrimPrefix(strings.TrimPrefix(a, "--split-string="), "-S"), args[i+1:]
					if a == "-S" || a == "--split-string" {
						if len(rest) == 0 {
							return nil, false, false
						}
						str, rest = rest[0], rest[1:]
					}
					if strings.ContainsAny(str, "'\"\\$`") {
						return nil, false, false
					}
					args = append(append(append([]string{}, args[:i]...), strings.Fields(str)...), rest...)
					i--
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
			shell, login := false, false
			var dir *string // -D, --chdir: the directory the command runs in
		sudoArgs:
			for ; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
				a := args[i]
				switch {
				case a == "--":
					i++
					break sudoArgs
				case a == "--preserve-env":
				case a == "--shell":
					shell = true
				case a == "--login":
					shell, login = true, true
				case a == "--chdir":
					if i+1 >= len(args) {
						return nil, false, false
					}
					i++
					d := args[i]
					dir = &d
				case strings.HasPrefix(a, "--chdir="):
					d := strings.TrimPrefix(a, "--chdir=")
					dir = &d
				case strings.HasPrefix(a, "--"):
					return nil, false, false
				default:
				cluster:
					for j := 1; j < len(a); j++ {
						switch c := rune(a[j]); {
						case strings.ContainsRune("EHnSkbPA", c):
						case c == 's':
							shell = true
						case c == 'i':
							shell, login = true, true
						case c == 'D':
							d := a[j+1:]
							if d == "" {
								if i+1 >= len(args) {
									return nil, false, false
								}
								i++
								d = args[i]
							}
							dir = &d
							break cluster
						case strings.ContainsRune("ugChpUrtT", c):
							if j+1 == len(a) {
								i++
							}
							break cluster
						default:
							return nil, false, false
						}
					}
				}
			}
			if i > len(args) {
				i = len(args)
			}
			if shell || dir != nil {
				// -s and -i run the command through the target user's shell, -i from its home,
				// each word escaped as sudo escapes it; -D runs it from dir. Each is read as
				// sh -c of that text.
				rest := args[i:]
				if shell && len(rest) == 0 && dir == nil {
					return []string{"sh"}, false, true
				}
				if dir != nil && !shell && len(rest) == 0 {
					return nil, false, false
				}
				var b strings.Builder
				if login {
					b.WriteString(`cd "$HOME"; `)
				}
				switch {
				case dir != nil && strings.ContainsAny(*dir, "$`"):
					// An expansion the caller's shell made: a directory this does not know.
					b.WriteString(`cd "` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(*dir) + `"; `)
				case dir != nil:
					// sudo itself changes to dir, so it is one literal word.
					b.WriteString("cd '" + strings.ReplaceAll(*dir, "'", `'\''`) + "'; ")
				}
				if shell && len(rest) == 0 {
					b.WriteString("sh")
				}
				// An empty word escapes to nothing, so it drops out as sudo drops it.
				for _, w := range rest {
					b.WriteString(" " + sudoEscape(w))
				}
				return []string{"sh", "-c", b.String()}, false, true
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
	"su": true, "script": true, "unbuffer": true, "sg": true, "find": true, "chrt": true,
	"strace": true, "ltrace": true, "xvfb-run": true, "unshare": true, "nsenter": true,
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
		return slices.ContainsFunc(f, fieldRunsShell)
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
		if slices.ContainsFunc(all[1:], lineRunsShell) {
			return "shell run behind a wrapper this cannot read: " + strings.Join(seg.words, " "), true
		}
		return "", false
	}
	if inert || len(args) == 0 {
		return "", false
	}
	name, _ := CommandName(args[0])
	switch text, k := commandLine(name, args[1:]); k {
	case lineText:
		if strings.Contains(text, "$(") || strings.Contains(text, "`") {
			return "shell runs a command substitution: " + strings.Join(seg.words, " "), true
		}
		return v.runText(text, cur.fork(), depth+1), true
	case lineStdin, lineUnread:
		return "shell runs what this cannot read: " + strings.Join(seg.words, " "), true
	}
	if runners[name] {
		if slices.ContainsFunc(args[1:], runnerRunsShell) {
			return "shell run from a command this does not follow: " + strings.Join(seg.words, " "), true
		}
		if c, ok := runnerCommand(name, args[1:]); ok {
			if strings.Contains(c, "{}") || strings.ContainsAny(c, "$`") {
				return "runs files this cannot name: " + strings.Join(seg.words, " "), true
			}
			if strings.Contains(c, "/") {
				if why, ok := v.execFile(c, cur, depth); ok {
					return why, true
				}
			}
		}
	}
	if strings.Contains(args[0], "/") && !strings.ContainsAny(args[0], "$`") {
		if why, ok := v.execFile(args[0], cur, depth); ok {
			return why, true
		}
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
	// Nothing here gives the shell its input: it reads whatever the caller's is.
	return "shell reads standard input this does not read: " + strings.Join(seg.words, " "), true
}

// lineRunsShell reports whether a word runs a shell: it names one, eval, . or source, or holds
// a command line (env -S 'sh f') that does.
func lineRunsShell(w string) bool {
	return slices.ContainsFunc(strings.Fields(w), fieldRunsShell)
}

// fieldRunsShell reports whether a field of a command line, its quotes and separators aside,
// runs a shell.
func fieldRunsShell(f string) bool { return runsShell(f) || runsShell(trimShell(f)) }

// The kinds of command a command-line runner (su, runuser, sg, script) is given.
const (
	lineNone   = iota // not a command-line runner, or one that execs a program (runuser -u)
	lineText          // shell text, run from where it runs
	lineStdin         // a shell reading its standard input
	lineUnread        // an option or shell this does not read
)

// commandLine returns the shell text su, runuser, sg or script runs, and its kind. Text from
// a login (su -, -l) runs from the user's home.
func commandLine(name string, args []string) (string, int) {
	switch name {
	case "su", "runuser", "sg", "script":
	default:
		return "", lineNone
	}
	var text string
	have, login := false, false
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			pos = append(pos, args[i+1:]...)
			i = len(args)
		case a == "-" || a == "-l" || a == "--login":
			login = true
		case a == "-c" || a == "--command":
			if i+1 >= len(args) {
				return "", lineUnread
			}
			i++
			text, have = args[i], true
		case strings.HasPrefix(a, "--command="):
			text, have = strings.TrimPrefix(a, "--command="), true
		case a == "-u" && name == "runuser":
			return "", lineNone // runuser -u execs the command after it, no shell between
		case a == "-s" || a == "--shell":
			if i+1 >= len(args) {
				return "", lineUnread
			}
			i++
			if b, _ := CommandName(args[i]); !shells[b] {
				return "", lineUnread
			}
		case a == "-g" || a == "-G" || a == "--group" || a == "--supp-group" || a == "-w" || a == "--whitelist-environment":
			i++
		case a == "-m" || a == "-p" || a == "--preserve-environment" || a == "-f" || a == "-P" || a == "--pty":
		case name == "script" && len(a) > 1 && a[0] == '-' && a[1] != '-':
			// script's clusters: -qc 'cmd', -q, -a, -e, -f; -t, -T, -I, -O, -B, -m, -E take a value.
			for j := 1; j < len(a); j++ {
				switch c := a[j]; {
				case c == 'c':
					if t := a[j+1:]; t != "" {
						text = t
					} else if i+1 < len(args) {
						i++
						text = args[i]
					} else {
						return "", lineUnread
					}
					have, j = true, len(a)
				case strings.IndexByte("tTIOBmE", c) >= 0:
					if j+1 == len(a) {
						i++
					}
					j = len(a)
				case strings.IndexByte("qaefk", c) < 0:
					return "", lineUnread
				}
			}
		case strings.HasPrefix(a, "-"):
			return "", lineUnread
		default:
			pos = append(pos, a)
		}
	}
	if name == "sg" && !have && len(pos) > 1 {
		text, have = strings.Join(pos[1:], " "), true // sg group 'cmd' runs it with sh -c
	}
	switch {
	case have && login:
		return `cd "$HOME"; ` + text, lineText
	case have:
		return text, lineText
	case name == "script":
		return "", lineUnread // an interactive shell recording to a file
	}
	return "", lineStdin
}

// runnerCommand returns the command find -exec or xargs runs.
func runnerCommand(name string, args []string) (string, bool) {
	switch name {
	case "find":
		for i, a := range args {
			if (a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir") && i+1 < len(args) {
				return args[i+1], true
			}
		}
	case "xargs":
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--":
				if i+1 < len(args) {
					return args[i+1], true
				}
				return "", false
			case a == "-I" || a == "-n" || a == "-L" || a == "-P" || a == "-s" || a == "-d" || a == "-E" || a == "-a" ||
				a == "--max-args" || a == "--max-procs" || a == "--delimiter" || a == "--arg-file" || a == "--max-lines" || a == "--max-chars":
				i++
			case strings.HasPrefix(a, "-"):
			default:
				return a, true
			}
		}
	}
	return "", false
}

// execFile applies the rule to a program run by its path: a text file in the build with no
// #! line runs in a shell of its own (the shell runs what the kernel will not exec), and one
// whose #! line names a shell runs in that shell, each from the caller's directory, so it is
// classified as one; one with another #! line is a script surface read in its own right, and
// a binary or a file not executable runs nothing of the build's. handled is false when p
// names no file of the build.
func (v *Veto) execFile(p string, cur cursor, depth int) (why string, handled bool) {
	hosts, ok := cur.script(p)
	if !ok {
		if filepath.IsAbs(p) {
			return "", false
		}
		if fi, err := os.Stat(filepath.Join(v.root, p)); err == nil && fi.Mode().IsRegular() {
			return "runs a file this cannot locate: " + p, true
		}
		// Wherever the shell is, a file of the build a shell would run may be the one named.
		if v.mayExec(filepath.Base(p)) {
			return "runs a file this cannot locate, which a build file may be: " + p, true
		}
		return "", false
	}
	for _, h := range hosts {
		fi, err := os.Stat(h)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			continue
		}
		data, err := v.spec.ReadRegular(h)
		if err != nil {
			return "runs a file this cannot read: " + p, true
		}
		// A #! line that names a shell runs the file as one from here, as does no #! line.
		if bytes.HasPrefix(data, []byte("#!")) && !shellShebang(data) || binary(data) {
			continue
		}
		return v.runFile(p, cur.fork(), depth+1, false), true
	}
	return "", false
}

// shellExecs returns the lowercased base names of the files in the build a shell would run by
// path: executable text with no #! line or a #! line naming a shell, or a symlink or a file
// this cannot read, which may be one. It walks the tree once per Veto.
func (v *Veto) shellExecs() map[string]bool {
	if v.execs != nil {
		return v.execs
	}
	v.execs = map[string]bool{}
	_ = buildtree.Walk(v.root, func(e buildtree.Entry, err error) error {
		if err != nil || e.D == nil || e.D.IsDir() || v.inGitDir(e.Path) {
			return nil
		}
		name := strings.ToLower(e.D.Name())
		if e.Symlink {
			v.execs[name] = true
			return nil
		}
		fi, err := e.D.Info()
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			return nil
		}
		// Head is nil for an empty file or one holding a NUL, neither of which a shell runs.
		head, err := buildtree.Head(e.Path)
		if err != nil || head != nil && (!bytes.HasPrefix(head, []byte("#!")) || shellShebang(head)) && !binary(head) {
			v.execs[name] = true
		}
		return nil
	})
	return v.execs
}

// nameIn reports whether base, lowercased and possibly a glob, matches a name in names.
func nameIn(base string, names map[string]bool) bool {
	if !strings.ContainsAny(base, "*?[\\") {
		return names[base]
	}
	for name := range names {
		if ok, err := path.Match(base, name); ok || err != nil {
			return true
		}
	}
	return false
}

// mayExec reports whether base, a file name that may be a glob, names a file of the build a
// shell would run by path; a pattern this cannot match may name any.
func (v *Veto) mayExec(base string) bool {
	return nameIn(strings.ToLower(base), v.shellExecs())
}

// binary reports whether a file's head is an executable format the kernel runs itself, or
// holds a NUL byte.
func binary(data []byte) bool {
	head := data[:min(len(data), 512)]
	for _, m := range [][]byte{{0x7f, 'E', 'L', 'F'}, {0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}, {'M', 'Z'}} {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return bytes.IndexByte(head, 0) >= 0
}

// catFile returns the one literal file a cat command prints, and whether words is one.
func catFile(words []string) (string, bool) {
	args, inert, ok := unwrap(words[keywordHead(words):])
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
	moves := false
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
		before := run.where()
		v.running = append(v.running, h)
		w := v.runText(src, run, depth)
		v.running = v.running[:len(v.running)-1]
		if w != "" {
			return w
		}
		// Whatever moved the host's shell, its own cd or one in a file it read in place, the
		// caller's moved as well.
		moves = moves || run.where() != before
	}
	if sourced && len(hosts) > 1 && moves {
		cur.cd(nil)
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

// shellLineRE finds, in a line that does not tokenise, a word that hands text to a shell: a
// shell, eval or source anywhere. sourceLineRE finds a . where a command starts, which a case
// pattern's ) or a reserved word may lead into; it is matched with each ) that closes a $(
// blanked, since that one ends a substitution rather than a pattern.
var (
	shellLineRE  = regexp.MustCompile(`(?:^|[\s;&|(` + "`" + `])(?:[\w./-]*/)?(?:sh|bash|dash|zsh|ksh|ash|mksh|eval|source)(?:$|[\s;&|)` + "`" + `])`)
	sourceLineRE = regexp.MustCompile(`(?:^|[;&|()!{]|\b(?:then|do|else|elif|if|while|until|time|coproc))\s*\.\s+\S`)
)

// blankSubstClose returns line with each ) that closes a $( replaced by a blank: that one ends a
// substitution, so what follows it continues the word or command the $( is in. A $( where a
// command starts is a program this cannot name, which unnamedLine withholds on its own.
func blankSubstClose(line string) string {
	b := []byte(line)
	var open []bool // for each ( still open, whether its ) is blanked
	for i, c := range b {
		switch c {
		case '(':
			open = append(open, i > 0 && b[i-1] == '$')
		case ')':
			if n := len(open); n > 0 {
				if open[n-1] {
					b[i] = ' '
				}
				open = open[:n-1]
			}
		}
	}
	return string(b)
}

// redirectRE matches the operator of a redirect at the start of a word.
var redirectRE = regexp.MustCompile(`^(?:[0-9]+|&)?(?:<<<|<<-?|<>|<&|>&|>>|>\||<|>)`)

// keywordAtRE finds a reserved word a command may follow, as a word of its own.
var keywordAtRE = regexp.MustCompile(`(?:^|[\s;&|()!{` + "`" + `])(?:then|do|else|elif|if|while|until|time|coproc)\s`)

// unnamedLine is unnamedProgram for a line that does not tokenise. A command may start at the
// start of the line, after a leading key, after any ; & | ( ) ! { or backtick, quoted or not,
// a ) that closes a $( not at a command start aside, and after a reserved word; each such
// start is read as words up to the next ; & | or ), quotes kept together, and judged as a
// command. Where the quotes do not pair up, the words cannot be placed, so any expansion
// withholds.
func unnamedLine(line string) string {
	if unpairedQuotes(line) {
		if strings.ContainsAny(line, "$`") {
			return "an expansion where commands cannot be placed"
		}
		return ""
	}
	b := blankSubstClose(line)
	starts := []int{0}
	if m := keyRE.FindStringIndex(strings.TrimPrefix(b, "- ")); m != nil {
		starts = append(starts, m[1]+len(b)-len(strings.TrimPrefix(b, "- ")))
	}
	for i := 0; i < len(b); i++ {
		if strings.IndexByte(";&|()!{`", b[i]) >= 0 {
			starts = append(starts, i+1)
		}
	}
	for _, m := range keywordAtRE.FindAllStringIndex(b, -1) {
		starts = append(starts, m[1])
	}
	for _, st := range starts {
		if why := unnamedProgram(lineWords(line[st:])); why != "" {
			return why
		}
	}
	return ""
}

// substEnd returns the index just past the ) that closes the ( at open, or len(s).
func substEnd(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

// unpairedQuotes reports whether a quote in line opens and never closes.
func unpairedQuotes(line string) bool {
	var q byte
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case q == 0 && c == '\\':
			i++
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case q == '"' && c == '\\':
			i++
		case c == q:
			q = 0
		}
	}
	return q != 0
}

// lineWords splits text into the words of the command it starts with: blank-separated, a
// quoted run kept in its word with its quotes, up to the first unquoted ; & | or ), and with
// redirects and their targets dropped.
func lineWords(text string) []string {
	var words []string
	var w strings.Builder
	var q byte
	end := func() {
		if w.Len() > 0 {
			words = append(words, w.String())
			w.Reset()
		}
	}
scan:
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case q == 0 && (c == ' ' || c == '\t'):
			end()
		case q == 0 && strings.IndexByte(";&|)", c) >= 0 && !(c == '&' && strings.HasSuffix(w.String(), ">")):
			break scan
		case q == 0 && c == '\\' && i+1 < len(text):
			w.WriteByte(c)
			i++
			w.WriteByte(text[i])
		case q != '\'' && c == '$' && i+1 < len(text) && text[i+1] == '(':
			// A substitution is part of the word it is in, whatever it holds.
			n := substEnd(text, i+1)
			w.WriteString(text[i:n])
			i = n - 1
		case q == 0 && (c == '\'' || c == '"'):
			q = c
			w.WriteByte(c)
		case q != 0 && c == q:
			q = 0
			w.WriteByte(c)
		default:
			w.WriteByte(c)
		}
	}
	end()
	var out []string
	for i := 0; i < len(words); i++ {
		if m := redirectRE.FindString(words[i]); m != "" {
			if m == words[i] {
				i++ // the target is the next word
			}
			continue
		}
		out = append(out, strings.Trim(words[i], `"'`))
	}
	return out
}

// untokenised applies the rule to a line that does not tokenise: one naming a token, an
// install verb after an expansion, or a shell run withholds, and the rest is mentioned.
func (v *Veto) untokenised(line string, cur cursor) string {
	if v.hasToken(line) {
		return "install command that does not tokenise"
	}
	if expandedInstallLine(line) {
		return "install verb after an expansion that does not tokenise"
	}
	if t := strings.TrimSpace(line); shellLineRE.MatchString(t) || sourceLineRE.MatchString(blankSubstClose(t)) {
		return "shell run that does not tokenise: " + strings.TrimSpace(line)
	}
	if why := unnamedLine(strings.TrimSpace(line)); why != "" {
		return why + " in a line that does not tokenise: " + strings.TrimSpace(line)
	}
	for _, f := range strings.Fields(line) {
		f = trimShell(f)
		if strings.Contains(f, "/") && !filepath.IsAbs(f) && !strings.ContainsAny(f, "$`") && v.mayExec(path.Base(f)) {
			return "runs a file by its path in a line that does not tokenise: " + strings.TrimSpace(line)
		}
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
		inPlace, script := false, true // the script is the first operand unless -e or -f gives it
		var ops []string
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--in-place" || strings.HasPrefix(a, "--in-place="):
				inPlace = true
			case a == "--expression" || a == "--file" || name == "perl" && (a == "-E" || a == "-M"):
				i++
				script = false
			case strings.HasPrefix(a, "--"):
			case strings.HasPrefix(a, "-") && name == "sed":
				// A cluster ends at i (its suffix follows) or at e, f or l (their argument
				// follows, here or in the next word): -ie is in place with suffix e.
			cluster:
				for j := 1; j < len(a); j++ {
					switch a[j] {
					case 'i':
						inPlace = true
						break cluster
					case 'e', 'f':
						if j+1 == len(a) {
							i++
						}
						script = false
						break cluster
					case 'l':
						if j+1 == len(a) {
							i++
						}
						break cluster
					}
				}
			case strings.HasPrefix(a, "-"):
				// A perl cluster ends at a switch taking a value, and -i takes the rest as
				// its suffix (-pie is -p -i with suffix e); -e takes the code next.
				f := a[1:]
				if k := strings.IndexAny(f, "MIdDxlC0V"); k >= 0 {
					f = f[:k]
				}
				if k := strings.IndexByte(f, 'i'); k >= 0 {
					inPlace, f = true, f[:k]
				}
				if strings.ContainsAny(f, "eE") {
					i++
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
		// The output file follows its flag, in the same word in a cluster (-fsSLo"$F") or
		// as the next word; wget's -o writes a log, as -O writes the download.
		outs := "o"
		if name == "wget" {
			outs = "oO"
		}
		var ops []string
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "--output" || a == "--output-document" || a == "--output-file" || a == "--append-output":
				if i+1 < len(args) {
					ops = append(ops, args[i+1])
				}
				i++
			case strings.HasPrefix(a, "--output=") || strings.HasPrefix(a, "--output-document=") || strings.HasPrefix(a, "--output-file=") || strings.HasPrefix(a, "--append-output="):
				_, t, _ := strings.Cut(a, "=")
				ops = append(ops, t)
			case len(a) > 1 && a[0] == '-' && a[1] != '-':
				if j := strings.IndexAny(a[1:], outs); j >= 0 {
					if t := a[j+2:]; t != "" {
						ops = append(ops, t)
					} else if i+1 < len(args) {
						i++
						ops = append(ops, args[i])
					}
				}
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
		v.mention([]string{r.target})
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

// sudoEscape escapes a word as sudo -s and -i do, a backslash before each byte but a letter,
// digit, _, - or $, so that an expansion stays live in the shell it runs. Glob, brace and ~
// characters stay bare as well: the shell that gave the word expanded them already, and
// leaving them to expand again names at least what it did.
func sudoEscape(w string) string {
	var b strings.Builder
	for i := 0; i < len(w); i++ {
		c := w[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("_-$*?[]{}~", c) >= 0) {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}
