package scriptsurface

import (
	"encoding/json"
	"regexp"
	"strings"
)

// logicalLines splits src into logical lines, joining a line that ends in an odd run of
// backslashes to the next. joined is false when the last line still continues.
func logicalLines(src string) (lines []string, joined bool) {
	lines, _, joined = logicalLinesAt(src)
	return lines, joined
}

// logicalLinesAt is logicalLines, also returning the source line, from 0, each starts on.
func logicalLinesAt(src string) (lines []string, starts []int, joined bool) {
	var cur strings.Builder
	start := 0
	for i, l := range strings.Split(src, "\n") {
		l = strings.TrimSuffix(l, "\r")
		if cur.Len() == 0 {
			start = i
		}
		if n := len(l) - len(strings.TrimRight(l, `\`)); n%2 == 1 {
			cur.WriteString(l[:len(l)-1])
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(l)
		lines, starts = append(lines, cur.String()), append(starts, start)
		cur.Reset()
	}
	if cur.Len() > 0 {
		return append(lines, cur.String()), append(starts, start), false
	}
	return lines, starts, true
}

// segment is one simple command: its words, unquoted, and whether its text holds a $ or
// a backtick anywhere. guarded marks one that follows &&, ||, | or &, which may not run, or not
// before what follows it; and marks one that follows &&, which runs only if the command before
// it did; background marks one a lone & ends, which may not have finished when what follows runs.
// end is the operator that ends it (&&, ||, |, & or ;), or "" at the end of the text. globbed
// marks, word by word, a glob character outside quotes, which the shell expands, and redir an
// unquoted redirect operator starting the word; from is the words of the command piped into
// this one; exec marks an exec-form command, which no shell reads.
type segment struct {
	words      []string
	expands    bool
	guarded    bool
	and        bool
	background bool
	end        string
	globbed    []bool
	redir      []bool
	from       []string
	exec       bool
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
		case s == "", strings.HasPrefix(s, "|"), strings.HasPrefix(s, ">"):
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
	return []segment{{words: words, expands: hasExpansion(words), exec: true}}, true
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
		glob   bool
		redir  bool
	)
	endWord := func() {
		if inWord {
			cur.words = append(cur.words, word.String())
			cur.globbed = append(cur.globbed, glob)
			cur.redir = append(cur.redir, redir)
			word.Reset()
			inWord, glob, redir = false, false, false
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
		case c == '{' && !inWord && strings.HasPrefix(s[i:], "{}") && (i+2 == len(s) || strings.IndexByte(" \t;&|", s[i+2]) >= 0):
			// find's {} is a word, not a group.
			word.WriteString("{}")
			i++
			inWord = true
		case c == '(' || c == ')' || (c == '{' || c == '}') && !inWord:
			return nil, false, false
		case c == '<' || c == '>':
			// A redirect starts a word of its own, an fd number or &> aside, as the shell
			// reads x>f.
			if inWord && strings.Trim(word.String(), "0123456789<>&") != "" {
				endWord()
			}
			redir = redir || !inWord || strings.Trim(word.String(), "0123456789<>&") == ""
			word.WriteByte(c)
			inWord = true
		case c == '&' && inWord && strings.HasSuffix(word.String(), ">") || c == '&' && inWord && strings.HasSuffix(word.String(), "<"):
			// >&2 and 2>&1 duplicate a descriptor; they end nothing.
			word.WriteByte(c)
		case c == '&' && i+1 < len(s) && s[i+1] == '>' && (i == 0 || s[i-1] != '&'):
			// &> and &>> redirect both outputs; they end nothing.
			endWord()
			word.WriteByte(c)
			inWord = true
		case c == '|' && inWord && strings.HasSuffix(word.String(), ">") && redir:
			// >| writes past noclobber; it ends nothing.
			word.WriteByte(c)
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
			glob = glob || c == '*' || c == '?' || c == '['
		}
	}
	endSeg()
	for i := 1; i < len(segs); i++ {
		if segs[i-1].end == "|" {
			segs[i].from = segs[i-1].words
		}
	}
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
// indicator in either order, then at most a comment.
var blockHeaderRE = regexp.MustCompile(`^([|>])([1-9]?[+-]?|[+-]?[1-9]?)\s*(?:#.*)?$`)

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
