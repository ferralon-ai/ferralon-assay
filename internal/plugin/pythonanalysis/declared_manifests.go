package pythonanalysis

// Declared-specifier readers for setuptools/hatch build definitions: setup.cfg, setup.py, and
// hatch_build.py. None of these is ever executed. Each yields DECLARED dependencies: an exact
// "==" pin resolves as everywhere else, a range is carried in Constraint with Resolved=false,
// and nothing here ever derives a version from a range.

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- setup.cfg ---------------------------------------------------------------

// parseSetupCfg reads setup.cfg's "[options] install_requires" and every key of
// "[options.extras_require]". Values are setuptools list fields: a dangling list (one
// requirement per indented continuation line) or a single-line ';'-separated string. A
// "file:" directive points at another file and contributes nothing here. Entries that are not
// well-formed PEP 508 requirements are skipped.
func parseSetupCfg(data []byte) ([]plugin.ResolvedDependency, bool) {
	var (
		out     []plugin.ResolvedDependency
		section string
		inList  bool // inside a dependency-list value's continuation lines
	)
	add := func(spec string) {
		spec = strings.TrimSpace(stripCfgInlineComment(spec))
		if spec == "" || strings.HasPrefix(spec, "file:") {
			return
		}
		if d, ok := declaredDependency(spec, "setup.cfg"); ok {
			out = append(out, d)
		}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		if indented && inList {
			add(trimmed)
			continue
		}
		inList = false
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}
		if indented {
			continue // continuation of a value we do not read
		}
		k := strings.IndexAny(trimmed, "=:")
		if k < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:k]))
		val := strings.TrimSpace(trimmed[k+1:])
		isDeps := (section == "options" && key == "install_requires") || section == "options.extras_require"
		if !isDeps {
			continue
		}
		inList = true
		if val != "" && !strings.HasPrefix(val, "file:") {
			for _, part := range splitCfgSemicolons(val) {
				add(part)
			}
		}
	}
	return out, true
}

// splitCfgSemicolons splits a single-line setuptools list value on ';'. A segment that does
// not parse as a requirement is rejoined to the previous one, so "pkg; python_version<'3.8'"
// keeps its marker instead of producing a junk "python_version" entry.
func splitCfgSemicolons(val string) []string {
	var out []string
	for _, seg := range strings.Split(val, ";") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if _, ok := parsePEP508(seg); !ok && len(out) > 0 {
			out[len(out)-1] += "; " + seg
			continue
		}
		out = append(out, seg)
	}
	return out
}

// stripCfgInlineComment drops a " #"/" ;" inline comment. A requirement never contains a
// whitespace-preceded '#', and a marker's ';' is never whitespace-preceded in practice; a
// marker written "pkg ; marker" survives because splitCfgSemicolons rejoins it.
func stripCfgInlineComment(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
	}
	return s
}

// --- setup.py ----------------------------------------------------------------

// parseSetupPy reads every literal "install_requires = [ ... ]" list in setup.py (keyword
// argument or variable assignment). A list is accepted only when every element is a plain
// string literal; one computed element (a name, a call, an f-string, a comprehension) rejects
// the whole list, because a partial read would silently misstate what is declared. The file is
// never executed.
func parseSetupPy(data []byte) ([]plugin.ResolvedDependency, bool) {
	src := string(data)
	var out []plugin.ResolvedDependency
	const key = "install_requires"
	for i := 0; ; {
		k := strings.Index(src[i:], key)
		if k < 0 {
			break
		}
		start := i + k
		i = start + len(key)
		if start > 0 && isIdentChar(src[start-1]) || i < len(src) && isIdentChar(src[i]) {
			continue
		}
		j := skipPySpace(src, i)
		if j >= len(src) || src[j] != '=' || j+1 < len(src) && src[j+1] == '=' {
			continue
		}
		j = skipPySpace(src, j+1)
		if j >= len(src) || src[j] != '[' {
			continue
		}
		elems, next, ok := literalStringList(src, j+1)
		i = next
		if !ok {
			continue
		}
		for _, e := range elems {
			if d, ok := declaredDependency(e, "setup.py"); ok {
				out = append(out, d)
			}
		}
	}
	return out, true
}

// literalStringList reads list elements starting just after '[' and returns them when every
// element is a string literal (adjacent literals concatenate). next is the index after the
// closing ']' (or where scanning stopped); ok is false for any non-literal element.
func literalStringList(src string, i int) (elems []string, next int, ok bool) {
	for {
		i = skipPySpaceAndComments(src, i)
		if i >= len(src) {
			return nil, i, false
		}
		if src[i] == ']' {
			return elems, i + 1, true
		}
		var val strings.Builder
		for {
			s, nx, isF, lit := readPyString(src, i)
			if !lit || isF {
				return nil, i + 1, false
			}
			val.WriteString(s)
			i = skipPySpaceAndComments(src, nx)
			if i >= len(src) || !startsPyString(src, i) {
				break
			}
		}
		elems = append(elems, val.String())
		if i >= len(src) {
			return nil, i, false
		}
		switch src[i] {
		case ',':
			i++
		case ']':
			return elems, i + 1, true
		default:
			return nil, i, false
		}
	}
}

// --- hatch_build.py ----------------------------------------------------------

// parseHatchBuild reads string literals from a hatch build hook that parse as PEP 508
// requirements carrying a version specifier, a direct reference, or extras. A bare word is not
// taken as a requirement: in an arbitrary Python file it is far more likely to be a key, a
// path, or prose. The hook is never executed; these are declared dependencies only.
func parseHatchBuild(data []byte) ([]plugin.ResolvedDependency, bool) {
	src := string(data)
	var out []plugin.ResolvedDependency
	seen := map[string]bool{}
	for i := 0; i < len(src); {
		c := src[i]
		if c == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		if startsPyString(src, i) && (i == 0 || !isIdentChar(src[i-1])) {
			s, next, isF, ok := readPyString(src, i)
			if !ok {
				i++
				continue
			}
			i = next
			if isF {
				continue
			}
			r, valid := parsePEP508(s)
			if !valid || (r.Specifier == "" && r.URL == "" && len(r.Extras) == 0) {
				continue
			}
			d, ok := declaredDependency(s, "hatch_build.py")
			if !ok {
				continue
			}
			k := normalizePyCoordinate(d.Coordinate) + "\x00" + d.Version + "\x00" + d.Constraint
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, d)
			continue
		}
		i++
	}
	return out, true
}

// --- Python lexical helpers --------------------------------------------------

func isIdentChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func skipPySpace(src string, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r' || src[i] == '\\') {
		i++
	}
	return i
}

func skipPySpaceAndComments(src string, i int) int {
	for {
		i = skipPySpace(src, i)
		if i < len(src) && src[i] == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		return i
	}
}

// pyStringPrefix returns the length of a string-literal prefix (r, u, b, f, and two-letter
// combinations, any case) at i that is immediately followed by a quote, or -1 when no string
// literal starts at i.
func pyStringPrefix(src string, i int) int {
	for n := 0; n <= 2 && i+n < len(src); n++ {
		if c := src[i+n]; c == '"' || c == '\'' {
			for _, p := range strings.ToLower(src[i : i+n]) {
				if !strings.ContainsRune("rubf", p) {
					return -1
				}
			}
			return n
		}
	}
	return -1
}

func startsPyString(src string, i int) bool { return pyStringPrefix(src, i) >= 0 }

// readPyString reads one Python string literal starting at i (prefix included) and returns
// its value, the index after it, whether it is an f-string (its value is a template, not a
// literal), and ok=false when no well-formed literal starts at i.
func readPyString(src string, i int) (val string, next int, fstring bool, ok bool) {
	n := pyStringPrefix(src, i)
	if n < 0 {
		return "", i, false, false
	}
	prefix := strings.ToLower(src[i : i+n])
	raw := strings.ContainsRune(prefix, 'r')
	fstring = strings.ContainsRune(prefix, 'f')
	i += n
	q := src[i]
	delim := string(q)
	if strings.HasPrefix(src[i:], strings.Repeat(string(q), 3)) {
		delim = strings.Repeat(string(q), 3)
	}
	i += len(delim)
	var b strings.Builder
	for i < len(src) {
		if strings.HasPrefix(src[i:], delim) {
			return b.String(), i + len(delim), fstring, true
		}
		c := src[i]
		if c == '\n' && len(delim) == 1 {
			return "", i, fstring, false
		}
		if c == '\\' && i+1 < len(src) {
			if raw {
				b.WriteByte(c)
				b.WriteByte(src[i+1])
			} else {
				switch e := src[i+1]; e {
				case '\\', '\'', '"':
					b.WriteByte(e)
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '\n':
				default:
					b.WriteByte(c)
					b.WriteByte(e)
				}
			}
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return "", i, fstring, false
}
