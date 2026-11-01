package scriptsurface

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// logicalLinesAt splits src into logical lines, joining a line that ends in an odd run of
// backslashes to the next the way kind's reader does, and returns the source line, from 0,
// each starts on. joined is false when the last line still continues.
//
// A shell removes the backslash and newline, so the two sides join with nothing, outside
// single quotes, comments and heredoc bodies; make passes a recipe line (one that starts
// with a tab) to the shell that way, after taking one tab off the next line. Every other
// join is not one this can read exactly: inside single quotes the pair stays in the text,
// which an sh -c or eval may still remove; a comment's backslash ends nothing; a heredoc
// body is the input of whatever reads it; and a Makefile line outside a recipe and a data
// surface's lines pass through make, YAML or TOML before any shell. Those keep the two sides
// apart: by a space, or, after a comment and in a heredoc body, by not joining. hidden
// returns, for the caller to check, the text a reader may run that lines does not show: the
// word the two sides would make joined with nothing, where a join is not one of a shell's, or
// where it is a recipe's, as just takes all the blanks off the next line; and each line of a
// logical line that starts with # yet continues, which only a quote read wrongly lets happen.
func logicalLinesAt(src, kind string) (lines []string, starts []int, hidden []string, joined bool) {
	var cur strings.Builder
	var docs []heredoc
	sh := shellQuote{prev: '\n'}
	start, open, recipe, lead, left := 0, false, false, false, ""
	for i, l := range strings.Split(src, "\n") {
		l = strings.TrimSuffix(l, "\r")
		if w := boundaryWord(left, l); w != "" {
			hidden = append(hidden, w)
		}
		left = ""
		if len(docs) > 0 {
			if n := len(l) - len(strings.TrimRight(l, `\`)); n%2 == 1 {
				left = l[:len(l)-1]
			}
			if docs[0].ends(l) {
				docs = docs[1:]
			}
			lines, starts = append(lines, l), append(starts, i)
			continue
		}
		if !open {
			start, open = i, true
			recipe = kind == kindMakefile && strings.HasPrefix(l, "\t")
			lead = strings.HasPrefix(strings.TrimLeft(l, " \t"), "#")
			if kind != kindShell {
				sh = shellQuote{prev: '\n'}
			}
		} else if recipe {
			l = strings.TrimPrefix(l, "\t")
		}
		shell := kind == kindShell || recipe
		if !shell {
			// Read here only for where a comment starts, line by line.
			sh = shellQuote{prev: '\n'}
		}
		if n := len(l) - len(strings.TrimRight(l, `\`)); n%2 == 1 {
			body := l[:len(l)-1]
			comment := sh.feed(body)
			if lead && !comment {
				hidden = append(hidden, body)
			}
			switch {
			case comment:
				left = body
			case shell && (sh.q == 0 || sh.q == '"'):
				if recipe {
					left = body
				}
				cur.WriteString(body)
				continue
			default:
				cur.WriteString(body)
				cur.WriteByte(' ')
				left = body
				continue
			}
		} else {
			sh.feed(l)
			if lead && cur.Len() > 0 {
				hidden = append(hidden, l)
			}
		}
		sh.prev = '\n'
		cur.WriteString(l)
		lines, starts = append(lines, cur.String()), append(starts, start)
		cur.Reset()
		open = false
		if kind == kindShell {
			docs, sh.docs = sh.docs, nil
		}
	}
	if open {
		return append(lines, cur.String()), append(starts, start), hidden, false
	}
	return lines, starts, hidden, true
}

// shellQuote follows a shell's quoting through text fed to it a piece at a time. q is the
// quote open: 0, ', ", or $ for $'...'. prev is the last byte fed, outside a quote, for
// whether a # starts a word. docs are the heredocs opened, whose bodies start on the next line.
type shellQuote struct {
	q    byte
	prev byte
	docs []heredoc
}

// heredoc is a heredoc's terminator, and whether <<- lets leading tabs precede it.
type heredoc struct {
	word string
	dash bool
}

// ends reports whether l is the heredoc's terminator line.
func (d heredoc) ends(l string) bool {
	return l == d.word || d.dash && strings.TrimLeft(l, "\t") == d.word
}

var shellHeredocRE = regexp.MustCompile(`^<<(-?)[ \t]*(?:\\|'|")?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// feed reads t on from the state so far, reporting whether a comment starts in it, in which
// case the rest of t is not read.
func (s *shellQuote) feed(t string) (comment bool) {
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case s.q == '\'':
			if c == '\'' {
				s.q = 0
			}
		case s.q != 0:
			if c == '\\' {
				i++
			} else if c == '"' && s.q == '"' || c == '\'' && s.q == '$' {
				s.q = 0
			}
		case c == '\\':
			i++
		case c == '\'', c == '"':
			s.q = c
		case c == '$' && i+1 < len(t) && t[i+1] == '\'':
			s.q, i = '$', i+1
		case c == '#' && strings.IndexByte(" \t\n;&|()", s.prev) >= 0:
			return true
		case strings.HasPrefix(t[i:], "<<<"):
			i += 2
		case c == '<':
			if m := shellHeredocRE.FindStringSubmatch(t[i:]); m != nil {
				s.docs = append(s.docs, heredoc{word: m[2], dash: m[1] == "-"})
				i += len(m[0]) - 1
			}
		}
		s.prev = c
	}
	return false
}

var (
	wordTailRE = regexp.MustCompile(`[A-Za-z0-9_.+-]+$`)
	wordHeadRE = regexp.MustCompile(`^[A-Za-z0-9_.+-]+`)
)

// boundaryWord returns the word left's last word and right's first make with nothing
// between them, right's leading blanks dropped, or "" when either side has none.
func boundaryWord(left, right string) string {
	a, b := wordTailRE.FindString(left), wordHeadRE.FindString(strings.TrimLeft(right, " \t"))
	if a == "" || b == "" {
		return ""
	}
	return a + b
}

var (
	dockerDirectiveRE = regexp.MustCompile(`^#\s*([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$`)
	dockerDirectives  = map[string]bool{"escape": true, "syntax": true, "check": true}
	dockerContinues   = map[string]*regexp.Regexp{
		`\`: regexp.MustCompile(`([^\\])\\[ \t]*$|^\\[ \t]*$`),
		"`": regexp.MustCompile("([^`])`[ \t]*$|^`[ \t]*$"),
	}
)

// dockerLines splits a Dockerfile into instructions the way BuildKit's parser does. A line
// whose last character other than blanks is the escape character, not after another,
// continues onto the next with nothing between, quoted or not; comment and blank lines
// inside a continuation are dropped; and the body lines of a RUN, COPY or ADD heredoc, and
// its terminator, are kept as they are. A heredoc opens where open, given its instruction's
// first source line, from 0, and text, says so; docs holds, by index in lines, the heredocs
// each instruction opens. The escape character is \ unless an escape directive at the top
// sets a backtick. joined is false when the last instruction still continues. unsure is true,
// and lines end, at an instruction whose heredocs can't be read (dockerUnsure).
func dockerLines(src string, open func(start int, line string) bool) (lines []string, docs map[int][]heredoc, joined, unsure bool) {
	raw := strings.Split(strings.TrimPrefix(src, "\ufeff"), "\n")
	cont, directives := dockerContinues[`\`], true
	docs = map[int][]heredoc{}
	for i := 0; i < len(raw); i++ {
		l := strings.TrimLeftFunc(strings.TrimRight(raw[i], "\r"), unicode.IsSpace)
		if directives {
			m := dockerDirectiveRE.FindStringSubmatch(l)
			directives = m != nil && dockerDirectives[strings.ToLower(m[1])]
			if directives && strings.EqualFold(m[1], "escape") && dockerContinues[m[2]] != nil {
				cont = dockerContinues[m[2]]
			}
		}
		if l == "" || l[0] == '#' {
			continue
		}
		start := i
		var b strings.Builder
		more := cont.MatchString(l)
		b.WriteString(cont.ReplaceAllString(l, "$1"))
		for more && i+1 < len(raw) {
			i++
			l := strings.TrimRight(raw[i], "\r")
			if t := strings.TrimSpace(l); t == "" || t[0] == '#' {
				continue
			}
			more = cont.MatchString(l)
			b.WriteString(cont.ReplaceAllString(l, "$1"))
		}
		lines = append(lines, b.String())
		if dockerUnsure(b.String()) {
			return lines, docs, !more, true
		}
		hd := dockerHeredocs(b.String())
		if hd == nil || !open(start, b.String()) {
			hd = nil
		} else {
			docs[len(lines)-1] = hd
		}
		for _, d := range hd {
			for i++; i < len(raw); i++ {
				l := strings.TrimRight(raw[i], "\r")
				lines = append(lines, l)
				if d.ends(l) {
					break
				}
			}
		}
		if more {
			return lines, docs, false, false
		}
	}
	return lines, docs, true, false
}

var (
	dockerHeredocRE     = regexp.MustCompile(`^(\d*)<<(-?)([^<]*)$`)
	dockerHeredocInstrs = map[string]bool{"run": true, "copy": true, "add": true}
	dockerOpExpandRE    = regexp.MustCompile(`\$\{[^}]*[:+\-?#%/]`)
	dockerBlankRE       = regexp.MustCompile(`[\t\v\f\r ]+`)
)

// dockerUnsure reports a RUN, COPY or ADD instruction, ONBUILD or not, that holds both a <<
// and a ${name<op>word} expansion. BuildKit splits such an expansion's text into words at
// every blank, quoted or escaped or not, and a word holding one is no heredoc there, so the
// heredocs the line opens are not ones dockerHeredocs can read.
func dockerUnsure(line string) bool {
	if !strings.Contains(line, "<<") || !dockerOpExpandRE.MatchString(line) {
		return false
	}
	name, _ := dockerInstr(line)
	return dockerHeredocInstrs[name]
}

// dockerInstr returns the instruction a line gives, in lower case, or for ONBUILD the one it
// triggers, and that instruction's arguments after its --flag words, taken as BuildKit's
// splitCommand takes them: the name ends at an ASCII blank, and the flags at a word that does
// not start with -- or after a bare --.
func dockerInstr(line string) (name, args string) {
	name, args = dockerSplit(line)
	if strings.ToLower(name) == "onbuild" {
		name, args = dockerSplit(args)
	}
	return strings.ToLower(name), args
}

func dockerSplit(line string) (name, args string) {
	cmd := dockerBlankRE.Split(strings.TrimSpace(line), 2)
	if len(cmd) == 2 {
		args = strings.TrimSpace(dockerFlagsEnd(cmd[1]))
	}
	return cmd[0], args
}

// dockerFlagsEnd returns what is left of line after its leading --flag words, a port of
// BuildKit's extractBuilderFlags, which reads it a byte at a time.
func dockerFlagsEnd(line string) string {
	const (
		spaces = iota
		inWord
		inQuote
	)
	phase, quote := spaces, byte(0)
	var word strings.Builder
	for pos := 0; pos < len(line); pos++ {
		ch := line[pos]
		if phase == spaces {
			if unicode.IsSpace(rune(ch)) {
				continue
			}
			if ch != '-' || pos+1 == len(line) || line[pos+1] != '-' {
				return line[pos:]
			}
			phase = inWord
		}
		switch {
		case phase == inWord && unicode.IsSpace(rune(ch)):
			if word.String() == "--" {
				return line[pos:]
			}
			word.Reset()
			phase = spaces
			continue
		case phase == inWord && (ch == '\'' || ch == '"'):
			quote, phase = ch, inQuote
			continue
		case phase == inQuote && ch == quote:
			phase = inWord
			continue
		case ch == '\\':
			if pos+1 == len(line) {
				phase = inWord
				continue
			}
			pos++
			ch = line[pos]
		}
		word.WriteByte(ch)
	}
	return ""
}

// dockerHeredocs returns the heredocs a RUN, COPY or ADD instruction, ONBUILD or not, opens in
// shell form, read the way BuildKit does: each word of the line, split the way a shell does but
// with its quotes and backslashes kept, that is all of <<, <<- or n<< and a name opens one,
// and the name, unquoted, is its terminator. A line BuildKit can't split, for an unterminated
// quote, opens none.
func dockerHeredocs(line string) []heredoc {
	var form []string
	if name, args := dockerInstr(line); !dockerHeredocInstrs[name] || strings.HasPrefix(args, "[") && json.Unmarshal([]byte(args), &form) == nil {
		return nil
	}
	var docs []heredoc
	for _, w := range dockerWords(line) {
		if m := dockerHeredocRE.FindStringSubmatch(w); m != nil {
			if name := dockerWords(m[3]); len(name) == 1 && unquoteWord(name[0]) != "" {
				docs = append(docs, heredoc{word: unquoteWord(name[0]), dash: m[2] == "-"})
			}
		}
	}
	return docs
}

// dockerWords splits line into words at blanks outside quotes, keeping the quotes and the
// backslashes, or returns nil when a quote is left open.
func dockerWords(line string) []string {
	var words []string
	var cur strings.Builder
	var q byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		r, n := utf8.DecodeRuneInString(line[i:])
		switch {
		case q == 0 && unicode.IsSpace(r):
			i += n - 1
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
			continue
		case c == '\\' && q != '\'' && i+1 < len(line):
			cur.WriteByte(c)
			i++
			c = line[i]
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case c == q:
			q = 0
		}
		cur.WriteByte(c)
	}
	if q != 0 {
		return nil
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

// unquoteWord removes a word's quotes and backslashes as BuildKit does, which inside double
// quotes takes a backslash off only before ", $ or another backslash.
func unquoteWord(w string) string {
	var b strings.Builder
	var q byte
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case c == '\\' && i+1 < len(w) && (q == 0 || q == '"' && strings.IndexByte(`"$\\`, w[i+1]) >= 0):
			i++
			b.WriteByte(w[i])
		case c == '\\' && i+1 == len(w) && q == 0:
			// BuildKit drops a trailing escape.
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case c == q:
			q = 0
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// segment is one simple command: its words, unquoted, and whether its text holds a $ or
// a backtick anywhere. guarded marks one that follows &&, ||, | or &, which may not run, or not
// before what follows it; and marks one that follows &&, which runs only if the command before
// it did; background marks one a lone & ends, which may not have finished when what follows runs.
// end is the operator that ends it (&&, ||, |, & or ;), or "" at the end of the text.
type segment struct {
	words      []string
	expands    bool
	guarded    bool
	and        bool
	background bool
	end        string
}

// dataKeys are keys whose values a build never runs as a command.
var dataKeys = map[string]bool{
	"name": true, "id": true, "cache": true, "description": true, "title": true, "if": true,
	"package-ecosystem": true, "package-manager": true, "packagemanager": true,
	"cache-dependency-path": true, "working-directory": true, "working_directory": true,
	"image": true, "shell": true, "version": true, "license": true, "author": true,
	"homepage": true, "repository": true, "url": true, "main": true, "module": true,
	"types": true, "key": true, "restore-keys": true, "path": true, "paths": true,
}

// keyRE matches a leading YAML, TOML, INI or Procfile key and its separator.
var keyRE = regexp.MustCompile(`^("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_.\-/]+)\s*(?::|=)(?:\s+|$)`)

// valuedKey returns the key of a data line that gives it a value on the line (an action
// input, an option), or "" for a key that only opens a nested block, such as a CI job name,
// whose lines are read on their own.
func valuedKey(line string) string {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
	m := keyRE.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	val := strings.TrimSpace(s[len(m[0]):])
	for _, f := range strings.Fields(val) {
		if strings.HasPrefix(f, "#") {
			break
		}
		if !strings.HasPrefix(f, "&") && !strings.HasPrefix(f, "!") {
			return strings.Trim(m[1], `"'`)
		}
	}
	return ""
}

// commandSegments unwraps a logical line by its surface kind and splits the command it
// holds. ok is false when the line does not tokenise.
func commandSegments(kind, line string) (segs []segment, ok, dangles bool) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "#") || kind == kindData && strings.HasPrefix(s, "//") {
		return nil, true, false
	}
	switch kind {
	case kindMakefile:
		s = strings.TrimSpace(strings.TrimLeft(s, "@-+"))
	case kindData:
		s = strings.TrimSpace(strings.TrimPrefix(s, "- "))
		if m := keyRE.FindStringSubmatch(s); m != nil {
			if dataKeys[strings.ToLower(strings.Trim(m[1], `"'`))] {
				return nil, true, false
			}
			s = strings.TrimSpace(s[len(m[0]):])
		}
		switch {
		case s == "", blockHeaderRE.MatchString(s):
			return nil, true, false
		case strings.HasPrefix(s, "{"):
			return nil, false, false
		case strings.HasPrefix(s, "["):
			segs, ok = execForm(strings.TrimSuffix(s, ","))
			return segs, ok, false
		case strings.HasPrefix(s, `"`), strings.HasPrefix(s, "'"):
			val, ok := quotedValue(s)
			if !ok {
				return nil, false, false
			}
			s = val
		}
	}
	return shellSegments(s)
}

// execForm reads a JSON array of strings (a Dockerfile exec form, a devcontainer
// command) as one command.
func execForm(s string) ([]segment, bool) {
	var words []string
	if json.Unmarshal([]byte(s), &words) != nil {
		return nil, false
	}
	return []segment{{words: words, expands: hasExpansion(words)}}, true
}

// quotedValue decodes a leading double-quoted (JSON) or single-quoted (YAML) value,
// which may be followed only by a comma, a closing bracket or a comment.
func quotedValue(s string) (string, bool) {
	var val, rest string
	if s[0] == '"' {
		end := -1
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 || json.Unmarshal([]byte(s[:end+1]), &val) != nil {
			return "", false
		}
		rest = s[end+1:]
	} else {
		var b strings.Builder
		i := 1
		for ; i < len(s); i++ {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				break
			}
			b.WriteByte(s[i])
		}
		if i >= len(s) {
			return "", false
		}
		val, rest = b.String(), s[i+1:]
	}
	rest = strings.TrimSpace(rest)
	if rest != "" && !strings.HasPrefix(rest, "#") && strings.Trim(rest, ",}] ") != "" {
		return "", false
	}
	return val, true
}

// shellSegments splits shell text into simple commands on unquoted &&, ||, ;, | and &,
// and each into words with quotes removed. An unquoted # starting a word ends the text. ok is
// false for an unterminated quote, a trailing backslash, or an unquoted parenthesis or brace
// (a subshell, group or function body this does not follow). dangles is true when the text
// ends in &&, || or |, so that the next line continues the list.
func shellSegments(s string) (segs []segment, ok, dangles bool) {
	var (
		cur    segment
		word   strings.Builder
		inWord bool
	)
	endWord := func() {
		if inWord {
			cur.words = append(cur.words, word.String())
			word.Reset()
			inWord = false
		}
	}
	endSeg := func() {
		endWord()
		if len(cur.words) > 0 {
			segs = append(segs, cur)
		}
		cur = segment{}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '$' || c == '`':
			cur.expands = true
			word.WriteByte(c)
			inWord = true
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, false, false
			}
			word.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				switch s[j] {
				case '\\':
					if j+1 < len(s) {
						j++
					}
				case '$', '`':
					cur.expands = true
				}
				word.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, false, false
			}
			i = j
			inWord = true
		case c == '\\':
			if i+1 >= len(s) {
				return nil, false, false
			}
			i++
			word.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t':
			endWord()
		case c == '#' && !inWord:
			endSeg()
			return segs, true, dangling(s[:i])
		case c == '(' || c == ')' || (c == '{' || c == '}') && !inWord:
			return nil, false, false
		case c == ';' || c == '&' || c == '|':
			cur.background = c == '&' && (i == 0 || !strings.ContainsRune("&|>", rune(s[i-1]))) && (i+1 == len(s) || !strings.ContainsRune("&>", rune(s[i+1])))
			cur.end = string(c)
			if c != ';' && i+1 < len(s) && s[i+1] == c {
				cur.end += string(c)
			}
			endSeg()
			cur.guarded = c != ';'
			cur.and = c == '&' && i > 0 && s[i-1] == '&'
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endSeg()
	return segs, true, dangling(s)
}

// dangling reports whether shell text ends in &&, || or |, which continue onto the next line.
func dangling(s string) bool {
	s = strings.TrimRight(s, " \t")
	return strings.HasSuffix(s, "&&") || strings.HasSuffix(s, "|")
}

// yamlLine is a line of a YAML surface as read: shell marks the text of a folded scalar,
// already unwrapped, which is read as shell text, not as a "key: value" line; start is the
// line, of those read, that the scalar it is part of starts on.
type yamlLine struct {
	text  string
	shell bool
	start int
}

// blockHeaderRE matches a block scalar indicator: | or >, then an indentation or chomping
// indicator in either order, then at most a comment, which YAML sets off with whitespace.
var blockHeaderRE = regexp.MustCompile(`^([|>])([1-9]?[+-]?|[+-]?[1-9]?)(?:\s+#.*)?\s*$`)

// foldYAML joins what YAML folds before a command is read. A folded block (>, >-, >+) becomes
// its folded lines, each a command, under a key whose value a build may run; a plain or quoted
// scalar continued on more-indented lines becomes one line, its continuations joined with
// spaces and a blank line starting a new command. A literal block (|) keeps one command per
// line, and its lines are passed through unread here.
func foldYAML(lines []string) []yamlLine {
	var out []yamlLine
	for i := 0; i < len(lines); i++ {
		col, key, val, ok := yamlScalarStart(lines[i])
		out = append(out, yamlLine{text: lines[i], start: i})
		if !ok {
			continue
		}
		end := i + 1
		for end < len(lines) && (strings.TrimSpace(lines[end]) == "" || yamlIndent(lines[end]) > col) {
			end++
		}
		run := !dataKeys[strings.ToLower(key)]
		switch m := blockHeaderRE.FindStringSubmatch(val); {
		case m != nil && m[1] == "|":
			for _, l := range lines[i+1 : end] {
				out = append(out, yamlLine{text: l, start: i})
			}
			i = end - 1
		case m != nil:
			base := col + 1
			if d := strings.Trim(m[2], "+-"); d != "" {
				base = col + int(d[0]-'0')
			} else {
				for _, l := range lines[i+1 : end] {
					if strings.TrimSpace(l) != "" {
						base = yamlIndent(l)
						break
					}
				}
			}
			if run {
				for _, p := range foldedPieces(lines[i+1:end], base) {
					out = append(out, yamlLine{text: p, shell: true, start: i})
				}
			}
			i = end - 1
		default:
			// A comment ends a plain scalar; anything after it is read line by line.
			for j := i + 1; j < end; j++ {
				if strings.HasPrefix(strings.TrimSpace(lines[j]), "#") {
					end = j
					break
				}
			}
			for end > i+1 && strings.TrimSpace(lines[end-1]) == "" {
				end--
			}
			if end == i+1 {
				continue
			}
			groups := plainGroups(lines[i+1 : end])
			out[len(out)-1].text = strings.TrimRight(lines[i], " \t") + " " + groups[0]
			if run {
				for _, g := range groups[1:] {
					out = append(out, yamlLine{text: g, shell: true, start: i})
				}
			}
			i = end - 1
		}
	}
	return out
}

// yamlScalarStart reports whether a line opens a scalar value: "key: value", "- key: value" or
// "- value", with a value that is not empty, a comment, or only an anchor or tag before a
// nested block. col is the indentation its continuation lines must exceed: the key's column,
// or the dash's for a bare item.
func yamlScalarStart(line string) (col int, key, val string, ok bool) {
	col = yamlIndent(line)
	s := line[col:]
	if rest, item := strings.CutPrefix(s, "- "); item {
		trimmed := strings.TrimLeft(rest, " ")
		if m := keyRE.FindStringSubmatch(trimmed); m != nil {
			col += 2 + len(rest) - len(trimmed)
			key, val = strings.Trim(m[1], `"'`), trimmed[len(m[0]):]
		} else {
			val = trimmed
		}
	} else if m := keyRE.FindStringSubmatch(s); m != nil {
		key, val = strings.Trim(m[1], `"'`), s[len(m[0]):]
	} else {
		return 0, "", "", false
	}
	val = strings.TrimSpace(val)
	for _, f := range strings.Fields(val) {
		if strings.HasPrefix(f, "#") {
			break
		}
		if !strings.HasPrefix(f, "&") && !strings.HasPrefix(f, "!") {
			return col, key, val, true
		}
	}
	return 0, "", "", false
}

func yamlIndent(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// foldedPieces folds a folded block's lines: lines at the block's indentation join with
// spaces, and a blank line or a more-indented line, which YAML keeps on its own line, ends
// the command.
func foldedPieces(lines []string, base int) []string {
	var (
		pieces []string
		cur    []string
	)
	flush := func() {
		if len(cur) > 0 {
			pieces = append(pieces, strings.Join(cur, " "))
			cur = nil
		}
	}
	for _, l := range lines {
		switch t := strings.TrimSpace(l); {
		case t == "":
			flush()
		case yamlIndent(l) > base:
			flush()
			pieces = append(pieces, t)
		default:
			cur = append(cur, t)
		}
	}
	flush()
	return pieces
}

// plainGroups joins a plain scalar's continuation lines with spaces; a blank line, which YAML
// keeps as a line break, starts a new group.
func plainGroups(lines []string) []string {
	groups := []string{""}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case t == "":
			if groups[len(groups)-1] != "" {
				groups = append(groups, "")
			}
		case groups[len(groups)-1] == "":
			groups[len(groups)-1] = t
		default:
			groups[len(groups)-1] += " " + t
		}
	}
	return groups
}
