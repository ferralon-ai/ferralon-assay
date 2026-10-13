package scriptsurface

import (
	"encoding/json"
	"regexp"
	"strings"
)

// logicalLines splits src into logical lines, joining a line that ends in an odd run of
// backslashes to the next. joined is false when the last line still continues.
func logicalLines(src string) (lines []string, joined bool) {
	var cur strings.Builder
	for _, l := range strings.Split(src, "\n") {
		l = strings.TrimSuffix(l, "\r")
		if n := len(l) - len(strings.TrimRight(l, `\`)); n%2 == 1 {
			cur.WriteString(l[:len(l)-1])
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(l)
		lines = append(lines, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		return append(lines, cur.String()), false
	}
	return lines, true
}

// segment is one simple command: its words, unquoted, and whether its text holds a $ or
// a backtick anywhere.
type segment struct {
	words   []string
	expands bool
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

// commandSegments unwraps a logical line by its surface kind and splits the command it
// holds. ok is false when the line does not tokenise.
func commandSegments(kind, line string) ([]segment, bool) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "#") || kind == kindData && strings.HasPrefix(s, "//") {
		return nil, true
	}
	switch kind {
	case kindMakefile:
		s = strings.TrimSpace(strings.TrimLeft(s, "@-+"))
	case kindData:
		s = strings.TrimSpace(strings.TrimPrefix(s, "- "))
		if m := keyRE.FindStringSubmatch(s); m != nil {
			if dataKeys[strings.ToLower(strings.Trim(m[1], `"'`))] {
				return nil, true
			}
			s = strings.TrimSpace(s[len(m[0]):])
		}
		switch {
		case s == "", strings.HasPrefix(s, "|"), strings.HasPrefix(s, ">"):
			return nil, true
		case strings.HasPrefix(s, "{"):
			return nil, false
		case strings.HasPrefix(s, "["):
			return execForm(strings.TrimSuffix(s, ","))
		case strings.HasPrefix(s, `"`), strings.HasPrefix(s, "'"):
			val, ok := quotedValue(s)
			if !ok {
				return nil, false
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
// (a subshell, group or function body this does not follow).
func shellSegments(s string) ([]segment, bool) {
	var (
		segs   []segment
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
				return nil, false
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
				return nil, false
			}
			i = j
			inWord = true
		case c == '\\':
			if i+1 >= len(s) {
				return nil, false
			}
			i++
			word.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t':
			endWord()
		case c == '#' && !inWord:
			endSeg()
			return segs, true
		case c == '(' || c == ')' || (c == '{' || c == '}') && !inWord:
			return nil, false
		case c == ';' || c == '&' || c == '|':
			endSeg()
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endSeg()
	return segs, true
}
