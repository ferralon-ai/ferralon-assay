package pythonanalysis

// Strict PEP 508 requirement-string parsing for the declared-specifier readers (setup.cfg,
// setup.py, PEP 621 pyproject, hatch_build.py) and for carrying a declared range as
// plugin.ResolvedDependency.Constraint.
//
// parseRequirementSpec stays the lenient name/pin extractor every existing path uses. This
// parser is deliberately strict: it rejects anything that is not a well-formed requirement, so
// a reader scanning arbitrary string literals (hatch_build.py) cannot mint a dependency out of
// a log message or a docstring.

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// pep508Req is one parsed PEP 508 requirement string.
type pep508Req struct {
	Name      string   // project name as written
	Extras    []string // normalized extras names, declared order
	Specifier string   // version specifier with whitespace and enclosing parens removed; "" when none
	URL       string   // direct reference ("name @ url"); "" when none
	Marker    string   // environment marker text after ';'; "" when none
}

// parsePEP508 parses s as a PEP 508 requirement. ok is false for anything that is not a
// well-formed requirement: an invalid project name, an unterminated extras group, or a
// specifier clause whose operator or version is malformed.
func parsePEP508(s string) (pep508Req, bool) {
	var r pep508Req
	s = strings.TrimSpace(s)
	if s == "" || containsJinja(s) {
		return r, false
	}

	i := 0
	for i < len(s) && isNameChar(s[i]) {
		i++
	}
	r.Name = s[:i]
	if !validProjectName(r.Name) {
		return pep508Req{}, false
	}
	rest := strings.TrimLeft(s[i:], " \t")

	if strings.HasPrefix(rest, "[") {
		j := strings.IndexByte(rest, ']')
		if j < 0 {
			return pep508Req{}, false
		}
		for _, e := range strings.Split(rest[1:j], ",") {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if !validProjectName(e) {
				return pep508Req{}, false
			}
			r.Extras = append(r.Extras, normalizePyCoordinate(e))
		}
		rest = strings.TrimLeft(rest[j+1:], " \t")
	}

	if strings.HasPrefix(rest, "@") {
		// A direct reference runs to whitespace; a marker must be separated from the URL by
		// whitespace before ';' (PEP 508), so a ';' inside the URL is not a marker split.
		rest = strings.TrimLeft(rest[1:], " \t")
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		r.URL = rest[:end]
		if r.URL == "" {
			return pep508Req{}, false
		}
		rest = strings.TrimLeft(rest[end:], " \t")
		if rest == "" {
			return r, true
		}
		if !strings.HasPrefix(rest, ";") {
			return pep508Req{}, false
		}
		r.Marker = strings.TrimSpace(rest[1:])
		return r, r.Marker != ""
	}

	spec := rest
	if k := strings.IndexByte(rest, ';'); k >= 0 {
		spec = rest[:k]
		r.Marker = strings.TrimSpace(rest[k+1:])
		if r.Marker == "" {
			return pep508Req{}, false
		}
	}
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "(") {
		if !strings.HasSuffix(spec, ")") {
			return pep508Req{}, false
		}
		spec = strings.TrimSpace(spec[1 : len(spec)-1])
	}
	if spec == "" {
		return r, true
	}
	norm, ok := normalizeSpecifier(spec)
	if !ok {
		return pep508Req{}, false
	}
	r.Specifier = norm
	return r, true
}

// normalizeSpecifier validates a comma-separated PEP 440 specifier set and returns it with all
// whitespace removed (">= 2.0, < 3" → ">=2.0,<3"). ok is false when any clause has an unknown
// operator or a version that does not look like a PEP 440 version.
func normalizeSpecifier(spec string) (string, bool) {
	clauses := strings.Split(spec, ",")
	out := make([]string, 0, len(clauses))
	for _, c := range clauses {
		c = strings.Join(strings.Fields(c), "")
		if c == "" {
			return "", false
		}
		op := ""
		for _, candidate := range []string{"===", "~=", "==", "!=", "<=", ">=", "<", ">"} {
			if strings.HasPrefix(c, candidate) {
				op = candidate
				break
			}
		}
		if op == "" {
			return "", false
		}
		ver := c[len(op):]
		if op == "===" {
			if ver == "" {
				return "", false
			}
		} else if !validPEP440Version(ver) {
			return "", false
		}
		out = append(out, op+ver)
	}
	return strings.Join(out, ","), true
}

// validPEP440Version is a shape check, not a full PEP 440 grammar: an optional "v", a leading
// digit, then version characters (including a trailing ".*" wildcard).
func validPEP440Version(v string) bool {
	v = strings.TrimPrefix(v, "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '.', c == '*', c == '+', c == '!', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// validProjectName applies PEP 508's name rule: alphanumeric at both ends, '.', '_', '-'
// allowed inside.
func validProjectName(n string) bool {
	if n == "" {
		return false
	}
	isAlnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	if !isAlnum(n[0]) || !isAlnum(n[len(n)-1]) {
		return false
	}
	for i := 0; i < len(n); i++ {
		if !isNameChar(n[i]) {
			return false
		}
	}
	return true
}

// requirementConstraint returns the declared specifier of a requirement spec (marker already
// removed or not) when it is a range rather than an exact pin, or "" when there is none, the
// spec is a direct reference, or the spec does not parse.
func requirementConstraint(spec string) string {
	r, ok := parsePEP508(spec)
	if !ok || r.URL != "" {
		return ""
	}
	return r.Specifier
}

// declaredDependency builds the advisory-path record for one declared PEP 508 requirement read
// from a non-lock manifest. Exact-pin resolution comes from parseRequirementSpec (shared with
// every other Python path, so an exact "==" pin keeps resolving exactly as before); a range rides only in Constraint and never becomes Version. ok is false for a string
// that is not a well-formed requirement.
func declaredDependency(spec, source string) (plugin.ResolvedDependency, bool) {
	r, ok := parsePEP508(spec)
	if !ok {
		return plugin.ResolvedDependency{}, false
	}
	version, resolved := "", false
	if r.URL == "" {
		head := spec
		if k := strings.IndexByte(head, ';'); k >= 0 {
			head = head[:k]
		}
		_, version, resolved, _ = parseRequirementSpec(strings.TrimSpace(head))
	}
	d := pyResolved(r.Name, version, resolved, source)
	if !d.Resolved {
		d.Constraint = r.Specifier
	}
	return d, true
}
