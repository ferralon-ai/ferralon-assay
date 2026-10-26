package jsanalysis

import (
	"errors"
	"strings"
)

// ynode is one node of the YAML subset pnpm writes: a scalar (val), a block mapping (kids, in
// keys order) or a block sequence of scalars (items). A flow collection stays raw text in val.
type ynode struct {
	val    string
	quoted bool // val was written as a quoted scalar, so it is a string whatever it spells
	kids   map[string]*ynode
	keys   []string
	items  []string
}

var errYAMLSubset = errors.New("jsanalysis: yaml outside the subset pnpm writes")

// mapping returns n's entries as a mapping: its block entries, or none for an empty flow map or
// an absent node. ok is false for a scalar, a quoted one included, a sequence or a non-empty flow
// map.
func (n *ynode) mapping() (map[string]*ynode, []string, bool) {
	switch {
	case n == nil:
		return nil, nil, true
	case len(n.items) > 0 || n.quoted:
		return nil, nil, false
	case n.val == "" || n.val == "{}":
		return n.kids, n.keys, true
	}
	return nil, nil, false
}

// scalars returns n as a string map: every entry must be a scalar.
func (n *ynode) scalars() (map[string]string, bool) {
	kids, keys, ok := n.mapping()
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		c := kids[k]
		if len(c.kids) > 0 || len(c.items) > 0 || strings.HasPrefix(c.val, "{") || strings.HasPrefix(c.val, "[") {
			return nil, false
		}
		out[k] = c.val
	}
	return out, true
}

// child returns the entry k of a mapping node, or nil.
func (n *ynode) child(k string) *ynode {
	if n == nil {
		return nil
	}
	return n.kids[k]
}

// splitYAMLDocs splits a stream at column-0 "---" markers, dropping empty documents.
func splitYAMLDocs(data string) []string {
	var docs []string
	var cur []string
	flush := func() {
		if strings.TrimSpace(strings.Join(cur, "\n")) != "" {
			docs = append(docs, strings.Join(cur, "\n"))
		}
		cur = nil
	}
	for _, line := range strings.Split(data, "\n") {
		if t := strings.TrimRight(line, " \t\r"); t == "---" || strings.HasPrefix(t, "--- ") {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return docs
}

// parseYAMLSubset parses one document of block mappings, block sequences of scalars, plain and
// quoted scalars and single-line flow collections. Anything else (block scalars, anchors,
// aliases, tags, multi-line flow, duplicate keys, a document end marker, tab indentation) is an
// error: the caller withholds rather than guess what the full grammar would make of it.
func parseYAMLSubset(doc string) (*ynode, error) {
	type frame struct {
		ind      int
		childInd int
		n        *ynode
	}
	root := &ynode{kids: map[string]*ynode{}}
	stack := []*frame{{ind: -1, childInd: -1, n: root}}
	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimRight(raw, " \r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if t == "..." || strings.HasPrefix(t, "%") {
			return nil, errYAMLSubset
		}
		ind := 0
		for ind < len(line) && line[ind] == ' ' {
			ind++
		}
		if line[ind] == '\t' {
			return nil, errYAMLSubset
		}
		if t == "-" || strings.HasPrefix(t, "- ") {
			for len(stack) > 1 && stack[len(stack)-1].ind > ind {
				stack = stack[:len(stack)-1]
			}
			top := stack[len(stack)-1]
			if top.ind < 0 || len(top.n.kids) > 0 || top.n.val != "" {
				return nil, errYAMLSubset
			}
			v, err := yamlValue(strings.TrimSpace(strings.TrimPrefix(t, "-")))
			if err != nil || v == "" || yamlHasKey(v) {
				return nil, errYAMLSubset
			}
			top.n.items = append(top.n.items, v)
			continue
		}
		for len(stack) > 1 && stack[len(stack)-1].ind >= ind {
			stack = stack[:len(stack)-1]
		}
		top := stack[len(stack)-1]
		if len(top.n.items) > 0 || top.n.val != "" {
			return nil, errYAMLSubset
		}
		if top.childInd < 0 {
			top.childInd = ind
		} else if top.childInd != ind {
			return nil, errYAMLSubset
		}
		key, rest, err := yamlKey(t)
		if err != nil {
			return nil, err
		}
		v, err := yamlValue(rest)
		if err != nil {
			return nil, err
		}
		if top.n.kids == nil {
			top.n.kids = map[string]*ynode{}
		}
		if _, dup := top.n.kids[key]; dup {
			return nil, errYAMLSubset
		}
		r := strings.TrimSpace(rest)
		c := &ynode{val: v, quoted: r != "" && (r[0] == '"' || r[0] == '\'')}
		top.n.kids[key] = c
		top.n.keys = append(top.n.keys, key)
		if v == "" {
			stack = append(stack, &frame{ind: ind, childInd: -1, n: c})
		}
	}
	return root, nil
}

// yamlKey splits a mapping line into its key and the raw text after the ':'.
func yamlKey(t string) (key, rest string, err error) {
	if t[0] == '"' || t[0] == '\'' {
		end := yamlQuoteEnd(t)
		if end < 0 {
			return "", "", errYAMLSubset
		}
		after := t[end+1:]
		if !strings.HasPrefix(after, ":") || len(after) > 1 && after[1] != ' ' {
			return "", "", errYAMLSubset
		}
		key, ok := yamlUnescape(t[0], t[1:end])
		if !ok {
			return "", "", errYAMLSubset
		}
		return key, after[1:], nil
	}
	if strings.ContainsAny(t[:1], "&*!|>{[?") {
		return "", "", errYAMLSubset
	}
	i := strings.Index(t, ": ")
	switch {
	case i >= 0:
		key, rest = t[:i], t[i+1:]
	case strings.HasSuffix(t, ":"):
		key = t[:len(t)-1]
	default:
		return "", "", errYAMLSubset
	}
	key = strings.TrimSpace(key)
	if key == "" || key == "<<" || strings.Contains(key, " #") {
		return "", "", errYAMLSubset
	}
	return key, rest, nil
}

// yamlValue reads a scalar or single-line flow value, dropping a trailing comment.
func yamlValue(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", nil
	}
	switch s[0] {
	case '"', '\'':
		end := yamlQuoteEnd(s)
		if end < 0 {
			return "", errYAMLSubset
		}
		if after := strings.TrimSpace(s[end+1:]); after != "" && !strings.HasPrefix(after, "#") {
			return "", errYAMLSubset
		}
		v, ok := yamlUnescape(s[0], s[1:end])
		if !ok {
			return "", errYAMLSubset
		}
		return v, nil
	case '|', '>', '&', '*', '!', '%', '@', '`':
		return "", errYAMLSubset
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	switch s[0] {
	case '{':
		if !strings.HasSuffix(s, "}") {
			return "", errYAMLSubset
		}
	case '[':
		if !strings.HasSuffix(s, "]") {
			return "", errYAMLSubset
		}
	}
	return s, nil
}

// yamlQuoteEnd returns the index of the quote closing the scalar s opens, or -1.
func yamlQuoteEnd(s string) int {
	q := s[0]
	for i := 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q && q == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		case s[i] == q:
			return i
		}
	}
	return -1
}

// yamlUnescape undoes the quoting of a quoted scalar's body. A double-quoted body holding any
// escape other than \" and \\ is outside the subset, so ok is false: the lane decodes no other,
// and a name or version kept verbatim would not be the one pnpm installs.
func yamlUnescape(q byte, s string) (_ string, ok bool) {
	if q == '\'' {
		return strings.ReplaceAll(s, "''", "'"), true
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		if i+1 == len(s) || s[i+1] != '"' && s[i+1] != '\\' {
			return "", false
		}
		i++
	}
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s), true
}

// yamlRawQuoted reports whether s holds quoting that a reader which only strips quotes would
// misread: a backslash in a scalar with a double quote, or a doubled single quote inside a
// single-quoted one. A YAML loader decodes both where such a reader keeps the text verbatim.
func yamlRawQuoted(s string) bool {
	s = strings.TrimSpace(s)
	if n := len(s); n >= 2 && s[0] == '\'' && s[n-1] == '\'' {
		s = s[1 : n-1]
	}
	return strings.Contains(s, "''") || strings.Contains(s, `"`) && strings.Contains(s, `\`)
}

// quoteGuard records whether a lexical lock reader met a scalar or a line structure it would
// misread (such quoting, an unclosed or trailing-text quote, a comment, a flow or explicit key,
// a stray column-0 line); the reader then withholds the lock.
type quoteGuard struct {
	raw bool
	// classic selects yarn classic's grammar for header descriptors.
	classic bool
}

// check flags s when yamlRawQuoted holds for it.
func (g *quoteGuard) check(s string) {
	if yamlRawQuoted(s) {
		g.raw = true
	}
}

// scalar returns the plain or quoted scalar s as a lexical reader takes it, and flags the lock
// unless s is inside the closed grammar the lexical readers model. Anything outside it is
// withheld, not deny-listed shape by shape:
//
//   - a quoted scalar closes on its line with only whitespace after it (no comment), and its
//     body holds only grammarChars;
//   - a plain scalar holds only grammarChars, opens with a plain-start byte (so never an alias,
//     anchor, tag, block-scalar or flow indicator), has no whitespace-led '#', no tab, no ": "
//     and no trailing ':'.
//
// An empty scalar is returned as "" and the caller decides whether the field is required.
func (g *quoteGuard) scalar(s string) string {
	s = strings.TrimSpace(s)
	g.check(s)
	if s == "" {
		return s
	}
	if q := s[0]; q == '"' || q == '\'' {
		end := yamlQuoteEnd(s)
		if end < 0 || strings.TrimSpace(s[end+1:]) != "" || !grammarBody(s[1:end]) {
			g.raw = true
			return s
		}
		return s[1:end]
	}
	if !plainScalarOK(s) {
		g.raw = true
	}
	return s
}

// required is scalar for a field the reader needs on its key's line: an empty or absent value
// (the value on the next line, or nothing) withholds.
func (g *quoteGuard) required(s string) string {
	if strings.TrimSpace(s) == "" {
		g.raw = true
		return ""
	}
	return g.scalar(s)
}

// grammarChars is every byte a name, version, specifier, resolution or key may hold in the
// locks pnpm and yarn write: npm-name characters, semver and range operators, a peer suffix
// "(peer@x)", protocol prefixes (link: file: workspace: npm: git+https:), a URL or a git
// "#commit" and the base64 of an integrity. A space is allowed inside a range ("^1 || ^2").
// Widen it only for a character a real lock needs.
const grammarChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
	"._~^+=<>|*/@:()#,%&?!$- "

// grammarBody reports whether every byte of a quoted body is in grammarChars.
func grammarBody(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(grammarChars, s[i]) < 0 {
			return false
		}
	}
	return true
}

// plainScalarOK reports whether an unquoted scalar is one YAML string a quote-stripping reader
// reads the same way a loader does.
func plainScalarOK(s string) bool {
	switch c := s[0]; {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
	case strings.IndexByte("._~^+=</($", c) >= 0:
	case c == '-' && len(s) > 1 && s[1] != ' ':
	default:
		return false
	}
	if !grammarBody(s) || strings.Contains(s, " #") || strings.Contains(s, ": ") || strings.HasSuffix(s, ":") {
		return false
	}
	return true
}

// classicScalar is scalar for a yarn classic value or key. Classic writes a string unquoted
// only when it starts with a letter and holds none of ':', whitespace, '\\', '"', ',', '[' or
// ']' (shouldWrapKey in yarn's src/lockfile/stringify.js), and its tokenizer reads such a
// string as one token. Any other unquoted value, a digit-led "7.0.0#1.0.0" included, is
// withheld, and so is '#' since the tokenizer treats it as a comment opener.
func (g *quoteGuard) classicScalar(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s[0] == '"' || s[0] == '\'' {
		return g.scalar(s)
	}
	g.check(s)
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') || !grammarBody(s) ||
		strings.ContainsAny(s, ": \t\\\",[]#") ||
		strings.HasPrefix(s, "true") || strings.HasPrefix(s, "false") {
		g.raw = true
	}
	return s
}

// classicRequired is classicScalar for a field that must carry a value on its line.
func (g *quoteGuard) classicRequired(s string) string {
	if strings.TrimSpace(s) == "" {
		g.raw = true
		return ""
	}
	return g.classicScalar(s)
}

// yamlKeyStart reports whether s opens with a character that starts a flow collection, an
// explicit key, an anchor, an alias, a tag or a block scalar instead of a plain or quoted key.
func yamlKeyStart(s string) bool {
	return s != "" && strings.IndexByte("{[?&*!|>", s[0]) >= 0
}

// line flags a lexical reader's non-comment line that opens with such a character: the reader
// cannot tell which key, if any, it names.
func (g *quoteGuard) line(trimmed string) {
	if yamlKeyStart(trimmed) {
		g.raw = true
	}
}

// pnpmTop flags a column-0 line of a pnpm lock that is not a plain "key:" the readers model:
// a quoted or flow key, a line without a colon, or a section (importers, packages, snapshots)
// that carries a value after its colon other than an empty flow map or a comment.
func (g *quoteGuard) pnpmTop(trimmed string) {
	if strings.HasPrefix(trimmed, "---") {
		return
	}
	key, val, ok := strings.Cut(trimmed, ":")
	if !ok || yamlKeyStart(trimmed) || strings.ContainsAny(key[:1], `"'`) {
		g.raw = true
		return
	}
	switch key {
	case "importers", "packages", "snapshots":
		if val = strings.TrimSpace(val); val != "" && val != "{}" && !strings.HasPrefix(val, "#") {
			g.raw = true
		}
	}
}

// yarnTop flags a column-0 line of a yarn lock that is not an entry header ending in ':'. A
// header with a trailing comment is one, because the reader would take its fields for the
// previous entry's. A header that opens with an indicator (an anchor, say) fails the
// descriptor grammar instead.
func (g *quoteGuard) yarnTop(trimmed string) {
	if !strings.HasSuffix(trimmed, ":") {
		g.raw = true
	}
}

// yamlHasKey reports whether a sequence item is itself a mapping entry.
func yamlHasKey(v string) bool {
	if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
		return true
	}
	return strings.Contains(v, ": ") || strings.HasSuffix(v, ":")
}

// str returns a scalar node's value, or "" for an absent node.
func (n *ynode) str() string {
	if n == nil {
		return ""
	}
	return n.val
}

// descriptors splits a yarn header into its descriptors. Classic quotes each descriptor
// separately and berry quotes the whole comma-joined list, so a comma inside a quote is
// kept in the fragment and split after the quotes are stripped.
func (g *quoteGuard) descriptors(header string) []string {
	var out []string
	for rest := strings.TrimSpace(header); rest != ""; {
		end := strings.IndexByte(rest, ',')
		if q := rest[0]; q == '"' || q == '\'' {
			if e := yamlQuoteEnd(rest); e >= 0 {
				end = strings.IndexByte(rest[e:], ',')
				if end >= 0 {
					end += e
				}
			}
		}
		frag, next := rest, ""
		if end >= 0 {
			frag, next = rest[:end], strings.TrimSpace(rest[end+1:])
		}
		rest = next
		scalar := g.scalar
		if g.classic {
			scalar = g.classicScalar
		}
		for _, d := range strings.Split(scalar(frag), ",") {
			if d = strings.TrimSpace(d); d != "" {
				out = append(out, d)
			}
		}
	}
	return out
}
