package scriptsurface

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// The rule for expansions: a line a build runs that holds anything the shell (or make) expands
// withholds its surface. What a line expands to is not known here, so neither is the program it
// runs, the file it hands a shell, or the file it writes; no placement of the expansion is
// attempted. The one exemption is make's own $(MAKE) in a recipe of a Makefile that sets MAKE
// nowhere (makeRefs).

// expansion returns what the shell text s holds that expands, or "": a $ in any form (a
// parameter, a command or arithmetic substitution, make's $(...) and $$), or a backtick,
// anywhere; outside quotes, a ~ starting a word or following = or :, or a brace list ({a,b},
// {a..b}); and, with unplaced, an unquoted glob character, for a line whose words this cannot
// place, where a glob may be the program.
func expansion(s string, unplaced bool) string {
	if strings.ContainsAny(s, "$`") {
		return "a $ or backtick, which expands to what this does not read"
	}
	var q byte
	start := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case q == '"':
			if c == '\\' {
				i++
			} else if c == '"' {
				q = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			q = c
		case c == '~' && start:
			return "a ~ that expands to a directory this does not know"
		case c == '{' && braceList(s, i):
			return "a brace list, which expands to words this does not read"
		case unplaced && (c == '*' || c == '?' || c == '[' && bracketCloses(s, i)):
			return "a glob in a line whose words this cannot place"
		}
		start = q == 0 && strings.IndexByte(" \t;&|()<>=:", c) >= 0
	}
	return ""
}

// wordEnd reports whether an unquoted c ends a shell word.
func wordEnd(c byte) bool { return strings.IndexByte(" \t;&|()<>", c) >= 0 }

// braceList reports whether the unquoted { at s[open] starts a brace list: a } closing it in
// the same word, with an unquoted , or .. between them (one inside a nested pair makes that
// pair a list, so the word expands either way).
func braceList(s string, open int) bool {
	depth, list := 0, false
	var q byte
	for i := open + 1; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case q == '"':
			if c == '\\' {
				i++
			} else if c == '"' {
				q = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			q = c
		case wordEnd(c):
			return false
		case c == '{':
			depth++
		case c == '}' && depth == 0:
			return list
		case c == '}':
			depth--
		case c == ',' || c == '.' && i+1 < len(s) && s[i+1] == '.':
			list = true
		}
	}
	return false
}

// bracketCloses reports whether the unquoted [ at s[open] is closed by a ] in the same word, so
// that the shell reads a bracket expression.
func bracketCloses(s string, open int) bool {
	for i := open + 1; i < len(s) && !wordEnd(s[i]); i++ {
		if s[i] == ']' {
			return true
		}
	}
	return false
}

// globWord reports whether an unquoted word holds a glob: *, ? or a closed [ ].
func globWord(w string) bool {
	if strings.ContainsAny(w, "*?") {
		return true
	}
	i := strings.IndexByte(w, '[')
	return i >= 0 && strings.Contains(w[i+1:], "]")
}

// sectionRE matches a TOML or INI table header, which names a section and runs no program.
var sectionRE = regexp.MustCompile(`^\[\[?[A-Za-z0-9_.:\-{}, ]+\]\]?$`)

// runValue returns the text a logical line of kind runs, and whether it runs any: a data
// line's value past its sequence marks and key, decoded when quoted; a recipe past its @, -
// and + marks; the line itself otherwise. A comment, a data key whose value a build never
// runs, a table header and a YAML block-scalar header run nothing. flow marks a data value
// that is a YAML flow collection, whose items are read on their own.
func runValue(kind, line string) (text string, runs, flow bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") || kind == kindData && strings.HasPrefix(s, "//") {
		return "", false, false
	}
	switch kind {
	case kindMakefile:
		return strings.TrimSpace(strings.TrimLeft(s, "@-+ \t")), true, false
	case kindData:
		if sectionRE.MatchString(s) {
			return "", false, false
		}
		s = seqItem(s)
		if m := keyRE.FindStringSubmatch(s); m != nil {
			if dataKeys[strings.ToLower(strings.Trim(m[1], `"'`))] {
				return "", false, false
			}
			s = strings.TrimSpace(s[len(m[0]):])
		}
		switch {
		case s == "", blockHeaderRE.MatchString(s):
			return "", false, false
		case strings.HasPrefix(s, "[") || strings.HasPrefix(s, "{"):
			return s, true, true
		case strings.HasPrefix(s, `"`), strings.HasPrefix(s, "'"):
			if val, ok := quotedValue(s); ok {
				return val, true, false
			}
		}
	}
	return s, true, false
}

// flowItems returns the scalars of a YAML flow collection as text, keys and values alike,
// nested collections flattened; ok is false when it does not decode. seq is true when it is a
// sequence holding only scalars and sequences: GitLab runs each such item as a command.
func flowItems(s string) (items []string, seq, ok bool) {
	var doc any
	if yaml.Unmarshal([]byte(strings.TrimSuffix(strings.TrimSpace(s), ",")), &doc) != nil {
		return nil, false, false
	}
	seq = true
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			seq = false
			for k, e := range t {
				items = append(items, k)
				walk(e)
			}
		case map[any]any:
			seq = false
			for k, e := range t {
				items = append(items, fmt.Sprint(k))
				walk(e)
			}
		case nil:
		default:
			items = append(items, fmt.Sprint(t))
		}
	}
	walk(doc)
	return items, seq, true
}

// lineExpands applies the rule for expansions to a logical line of a surface, split as kind:
// what it holds that expands, or "". A flow collection's items are each read as shell text;
// one that does not decode is left to the reading of a line that does not tokenise.
func lineExpands(kind, line string) string {
	t, runs, flow := runValue(kind, line)
	if !runs {
		return ""
	}
	if !flow {
		return expansion(t, false)
	}
	items, _, ok := flowItems(t)
	if !ok {
		// An opening line of a collection that spans lines, whose items are lines of their own;
		// commandSegments does not tokenise it, and untokenisedAs applies the rule to it.
		return ""
	}
	for _, it := range items {
		if why := expansion(it, false); why != "" {
			return why
		}
	}
	return ""
}

// makeRefRE finds a word that is exactly $(MAKE) or ${MAKE}, with one $.
var makeRefRE = regexp.MustCompile(`(^|[\s;&|()])\$(?:\(MAKE\)|\{MAKE\})($|[\s;&|()])`)

// makeRefs returns a recipe line with each word that is make's own $(MAKE) or ${MAKE} read as
// make: make expands it to the make running the recipe.
func makeRefs(t string) string {
	for {
		n := makeRefRE.ReplaceAllString(t, "${1}make$2")
		if n == t {
			return t
		}
		t = n
	}
}

// makeAssignRE finds an assignment to MAKE in a make file, in any flavour or position (override,
// export, a target-specific value, a define, a MAKEFLAGS word).
var makeAssignRE = regexp.MustCompile(`(?m)(?:^|[^A-Za-z0-9_])MAKE\s*(?:[:!?+]*=)|(?:^|\s)define\s+MAKE(?:\s|$)`)

// shellAssignRE matches a make variable assignment whose value make runs as shell text.
var shellAssignRE = regexp.MustCompile(`^\s*(?:(?:override|export|private)\s+)*[^\s:#=!]+\s*!=`)

// includeRE matches a make include line and its operands.
var includeRE = regexp.MustCompile(`^\s*(?:-include|sinclude|include)\s+(.*)$`)

// maxMakeIncludes bounds how deep makeOK follows include lines.
const maxMakeIncludes = 8

// makeOK reports whether the Makefile at p leaves $(MAKE) as make itself: it is a make file
// (not a justfile), and neither it nor any file it includes, followed from its directory,
// assigns MAKE. An include this cannot read, a glob or an expansion among its operands, or
// includes nested too deep leave MAKE unknown.
func (v *Veto) makeOK(p string) bool {
	if lower := strings.ToLower(filepath.Base(p)); lower == "justfile" || lower == ".justfile" {
		return false
	}
	return v.makeFileOK(p, filepath.Dir(p), map[string]bool{}, 0)
}

func (v *Veto) makeFileOK(p, dir string, seen map[string]bool, depth int) bool {
	if depth > maxMakeIncludes || !v.inRoot(p) {
		return false
	}
	if seen[p] {
		return true
	}
	seen[p] = true
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	data, err := v.spec.ReadRegular(p)
	if err != nil {
		return false
	}
	lines, _ := logicalLines(string(data))
	src := strings.Join(lines, "\n")
	if makeAssignRE.MatchString(src) {
		return false
	}
	for _, l := range lines {
		m := includeRE.FindStringSubmatch(l)
		if m == nil || strings.HasPrefix(l, "\t") {
			continue
		}
		ops := m[1]
		if i := strings.IndexByte(ops, '#'); i >= 0 {
			ops = ops[:i]
		}
		for _, f := range strings.Fields(ops) {
			if strings.ContainsAny(f, "$`*?[{~") || filepath.IsAbs(f) {
				return false
			}
			if !v.makeFileOK(filepath.Join(dir, f), dir, seen, depth+1) {
				return false
			}
		}
	}
	return true
}

// globProgram reports why a command runs a program a glob may name, or "": past the
// assignments and wrappers ahead of it, its program word holds a glob; or a wrapper this cannot
// read, or a runner (find only past its -exec), is given a word with an unquoted glob, which
// may be the program it runs.
func globProgram(seg segment) string {
	if seg.exec {
		return ""
	}
	var all []string
	var globbed []bool
	for i := 0; i < len(seg.words); i++ {
		if i < len(seg.redir) && seg.redir[i] {
			if m := redirRE.FindStringSubmatch(seg.words[i]); m != nil {
				if m[3] == "" {
					i++
				}
				continue
			}
		}
		all = append(all, seg.words[i])
		globbed = append(globbed, i < len(seg.globbed) && seg.globbed[i] && globWord(seg.words[i]))
	}
	if len(all) == 0 {
		return ""
	}
	prog, inert, ok := unwrap(all)
	if !ok {
		if slices.Contains(globbed[1:], true) {
			return "a glob behind a wrapper this cannot read"
		}
		return ""
	}
	if inert || len(prog) == 0 {
		return ""
	}
	if globWord(prog[0]) {
		return "runs a program a glob names"
	}
	name, _ := CommandName(prog[0])
	if !runners[name] {
		return ""
	}
	// The runner's arguments are the last of the command's words, unless a wrapper rewrote them.
	args := prog[1:]
	var flags []bool
	if len(prog) <= len(all) && slices.Equal(all[len(all)-len(prog):], prog) {
		flags = globbed[len(globbed)-len(args):]
	} else {
		flags = make([]bool, len(args))
		for i, a := range args {
			flags[i] = globWord(a)
		}
	}
	if name == "find" {
		i := slices.IndexFunc(args, func(a string) bool { return a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" })
		if i < 0 {
			return ""
		}
		flags = flags[i:]
	}
	if slices.Contains(flags, true) {
		return "runs a command a glob may name through " + name
	}
	return ""
}

// textExpands applies the rule for expansions to shell text a shell runs: a file, or the text
// a command hands a shell, which reads what quotes kept from the shell that handed it.
func textExpands(src string) string {
	lines, _ := logicalLines(src)
	for _, l := range lines {
		if why := lineExpands(kindShell, l); why != "" {
			return why + ": " + strings.TrimSpace(l)
		}
	}
	return ""
}
