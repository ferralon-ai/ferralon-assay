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
		key = t[1:end]
		after := t[end+1:]
		if !strings.HasPrefix(after, ":") || len(after) > 1 && after[1] != ' ' {
			return "", "", errYAMLSubset
		}
		return yamlUnescape(t[0], key), after[1:], nil
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
		return yamlUnescape(s[0], s[1:end]), nil
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

// yamlUnescape undoes the quoting of a quoted scalar's body. A double-quoted escape other than
// \" and \\ is kept verbatim: no name or version the lane reads carries one.
func yamlUnescape(q byte, s string) string {
	if q == '\'' {
		return strings.ReplaceAll(s, "''", "'")
	}
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s)
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
