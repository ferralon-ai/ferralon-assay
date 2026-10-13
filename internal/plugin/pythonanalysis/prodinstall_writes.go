package pythonanalysis

// Commands that may change a file a later install reads. A requirement file is read at the
// path the repository (or the image's COPY) puts it, so every command that runs between its
// placement and the install that reads it must leave it as it is. Commands are read against
// an allow-list: a parsed install command, or a command known to change no file's content.
// Any other command may change any file; an output redirect or output option changes the file
// it names. In an image the window runs from the COPY that places the file, through every
// later RUN, to the command that reads it; in a shell script, a CI job's steps or one command
// line it runs from the start.

import (
	"path"
	"regexp"
	"strings"
)

// fileWrite is a command that may change files: path is the one file it writes, or "" when
// it may change any file.
type fileWrite struct {
	path   string
	copies int // in an image, how many of the stage's copies precede it
	where  string
	what   string
}

// writeWindow is the part of a stage's writes that follow a placement: those recorded once
// the stage held more than after copies.
type writeWindow struct {
	stage *dockerStage
	after int
}

var (
	// inertCommands change no file's content: they print, test, wait or set shell state,
	// create or remove directories, change metadata, users or groups, create an empty file
	// (touch), or remove one, which leaves nothing for an install to read.
	inertCommands = setOf("echo", "printf", "true", "false", ":", "test", "exit", "return", "set", "export", "unset",
		"umask", "shift", "local", "readonly", "declare", "pwd", "ls", "cat", "head", "tail", "wc", "grep", "which",
		"id", "whoami", "uname", "date", "sleep", "nproc", "mkdir", "rmdir", "rm", "chmod", "chown", "chgrp", "touch",
		"useradd", "adduser", "groupadd", "addgroup", "usermod", "virtualenv", "fi", "done", "esac", "}")
	// shellKeywords open a compound command; the command that follows them is read.
	shellKeywords = setOf("if", "then", "else", "elif", "do", "while", "until", "!", "{")
	// shellHeaders are compound-command headers that run nothing themselves.
	shellHeaders = setOf("for", "case", "select")
	// sudoValued are the sudo options that take a value.
	sudoValued = setOf("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U")
	// redirectOutRe is an output redirection, with the target when attached.
	redirectOutRe = regexp.MustCompile(`^(?:\d*|&)>>?\|?(.*)$`)
	// outputOptions name the file a parsed command writes.
	outputOptions = setOf("-o", "--output", "--output-file")
	assignmentRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	keywordLeadRe = regexp.MustCompile(`^\s*(?:(?:if|then|else|elif|do|while|until|!|\{)\s+)*`)
)

// writes records what one command segment may change. parsed reports that command read it as
// an install command.
func (sc *installScan) writes(c scanCtx, seg string, tok []string, parsed bool) {
	for _, t := range tok {
		if m := redirectOutRe.FindStringSubmatch(t); m != nil {
			t = m[1]
		}
		if _, v, ok := strings.Cut(t, "="); ok {
			t = v
		}
		if installerConfigNames[strings.ToLower(path.Base(strings.Trim(t, ":")))] {
			sc.veto(c, "names %s, an installer configuration file the scanner does not read", t)
			return
		}
	}
	for i := 0; i < len(tok); i++ {
		m := redirectOutRe.FindStringSubmatch(tok[i])
		if m == nil || strings.HasPrefix(tok[i], "<") {
			continue
		}
		target := m[1]
		if target == "" && i+1 < len(tok) {
			i++
			target = tok[i]
		}
		if strings.HasPrefix(target, "&") || strings.HasPrefix(target, "/dev/") {
			continue
		}
		sc.write(c, target, "a redirect to "+target)
	}
	if parsed {
		for i, t := range tok {
			opt, val, eq := strings.Cut(t, "=")
			if !outputOptions[opt] {
				continue
			}
			if !eq {
				if i+1 >= len(tok) {
					continue
				}
				val = tok[i+1]
			}
			sc.write(c, val, opt+" "+val)
		}
		return
	}
	if what := writerCommand(seg, tok); what != "" {
		sc.write(c, "", what)
	}
}

// writerCommand returns the command a segment runs when it is not known to leave every file's
// content as it is, or "".
func writerCommand(seg string, tok []string) string {
	rest := keywordLeadRe.ReplaceAllString(seg, "")
	if strings.HasPrefix(strings.TrimLeft(rest, "("), "[") {
		return "" // a test expression
	}
	for len(tok) > 0 {
		w := cmdWord(tok[0])
		switch {
		case strings.ContainsAny(tok[0], "$`"):
			return tok[0]
		case shellKeywords[w], assignmentRe.MatchString(tok[0]), w == "time", w == "nohup", w == "exec":
			tok = tok[1:]
			continue
		case w == "sudo":
			tok = tok[1:]
			for len(tok) > 0 && strings.HasPrefix(tok[0], "-") {
				if sudoValued[tok[0]] && len(tok) > 1 {
					tok = tok[1:]
				}
				tok = tok[1:]
			}
			continue
		case w == "env":
			tok = tok[1:]
			for len(tok) > 0 && (strings.HasPrefix(tok[0], "-") || assignmentRe.MatchString(tok[0])) {
				tok = tok[1:]
			}
			continue
		case w == "command":
			if len(tok) > 1 && (tok[1] == "-v" || tok[1] == "-V") {
				return ""
			}
			tok = tok[1:]
			continue
		}
		break
	}
	if len(tok) == 0 || shellEnd(tok[0]) {
		return ""
	}
	w := cmdWord(tok[0])
	switch {
	case inertCommands[w], shellHeaders[w]:
		return ""
	case (w == "source" || w == ".") && len(tok) > 1 && strings.HasSuffix(tok[1], "/bin/activate"):
		return ""
	case pythonRe.MatchString(w):
		if mod, _, bad := pythonModule(w, tok[1:]); bad == "" && mod == "venv" {
			return ""
		}
	}
	return w
}

// write records that the command at c may change target, a path as the command names it, or
// any file when target is "".
func (sc *installScan) write(c scanCtx, target, what string) {
	if c.st == nil {
		return
	}
	w := fileWrite{where: c.where, what: what}
	if r := c.st.docker; r != nil {
		if target != "" && !strings.ContainsAny(target, "$`~") {
			switch {
			case path.IsAbs(target):
				w.path = path.Clean(target)
			case !r.cwdUnknown:
				w.path = path.Join(r.cwd, target)
			}
		}
		if !r.build {
			r.local = append(r.local, w)
			return
		}
		w.copies = len(r.stage.copies)
		r.stage.writes = append(r.stage.writes, w)
		return
	}
	if c.st.writes == nil {
		return
	}
	if target == "" || strings.ContainsAny(target, "$`~") || path.IsAbs(target) || c.st.unknown {
		*c.st.writes = append(*c.st.writes, w)
		return
	}
	for _, b := range c.st.bases {
		w.path = path.Clean(path.Join(b, target))
		*c.st.writes = append(*c.st.writes, w)
	}
}

// changedBy returns the first write among ws that may change p, or nil.
func changedBy(ws []fileWrite, p string) *fileWrite {
	for i := range ws {
		if ws[i].path == "" || ws[i].path == p {
			return &ws[i]
		}
	}
	return nil
}

// windowWrites returns the writes recorded in each window.
func windowWrites(wins []writeWindow) []fileWrite {
	var out []fileWrite
	for _, w := range wins {
		for _, fw := range w.stage.writes {
			if fw.copies > w.after {
				out = append(out, fw)
			}
		}
	}
	return out
}
