package jsanalysis

import (
	"strconv"
	"strings"
)

// rangeSatisfied reports whether a lockfile's recorded version satisfies a package.json
// dependency spec under node-semver's rules, the test npm applies to keep a locked version
// rather than re-resolve it. It models only a release version (X.Y.Z, no prerelease or build
// metadata), and a spec of "||"-separated alternatives, each a space-separated conjunction of
// these forms or one hyphen range. P is a partial: X, X.Y or X.Y.Z, where x, X or * in a part
// (or a missing part) leaves it and every later part free.
//
//	"" or a spec of only spaces   any version
//	*, x, X                       any version
//	X.Y.Z, =X.Y.Z                 exactly that version
//	>X.Y.Z, >=, <, <=             the comparison
//	P, =P                         any version matching P's fixed parts (1.2 is >=1.2.0 <1.3.0)
//	>P, >=P, <P, <=P              node-semver's x-range desugaring (>1.2 is >=1.3.0,
//	                              <=1.2 is <1.3.0, >* and <* match nothing)
//	^P                            >=P below the next release of its left-most non-zero fixed
//	                              part (^1.2.3 <2.0.0, ^0.2.3 <0.3.0, ^0.0.3 <0.0.4, ^0.x <1.0.0,
//	                              ^0.0.x <0.1.0)
//	~P                            >=P below the next minor (~1.2.3 <1.3.0), or the next major
//	                              when only X is fixed (~1 <2.0.0)
//	P1 - P2                       >=P1, and <=P2 when it is full, else below P2's next release
//
// With release operands and a release version, node-semver's prerelease rules never apply.
// Anything else is not satisfied, the whole spec with it, even if another alternative would
// hold: an empty alternative ("1.2.3 ||"), a tag, URL, git, file:, link:, workspace: or npm:
// spec, a v or = prefix on a partial's operand, "~>", a space between an operator and its
// operand, whitespace other than ASCII, a prerelease or build suffix on either side, a number
// with a leading zero, and any number, given or derived (^9007199254740991.0.0's upper bound),
// beyond 2^53-1, which node-semver rejects.
func rangeSatisfied(version, spec string) bool {
	v, ok := releaseVersion(version)
	if !ok {
		return false
	}
	alternatives, ok := parseRange(spec)
	if !ok {
		return false
	}
	for _, conj := range alternatives {
		holds := true
		for _, c := range conj {
			holds = holds && c.holds(v)
		}
		if holds {
			return true
		}
	}
	return false
}

// comparator is one desugared bound: op is "=", ">", ">=", "<" or "<=". A bound below X.Y.Z-0
// is recorded as <X.Y.Z, the same set of release versions.
type comparator struct {
	op string
	w  [3]int
}

func (c comparator) holds(v [3]int) bool {
	switch d := compareRelease(v, c.w); c.op {
	case "=":
		return d == 0
	case ">":
		return d > 0
	case ">=":
		return d >= 0
	case "<":
		return d < 0
	case "<=":
		return d <= 0
	}
	return false
}

func isASCIISpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
}

// parseRange desugars spec into alternatives, each a conjunction of comparators (an empty one
// holds for every version). ok is false when any part of spec is outside the modelled forms.
func parseRange(spec string) (alternatives [][]comparator, ok bool) {
	if len(strings.FieldsFunc(spec, isASCIISpace)) == 0 {
		return [][]comparator{nil}, true
	}
	for _, alt := range strings.Split(spec, "||") {
		fields := strings.FieldsFunc(alt, isASCIISpace)
		if len(fields) == 0 {
			return nil, false
		}
		var conj []comparator
		if len(fields) == 3 && fields[1] == "-" {
			cs, ok := hyphenRange(fields[0], fields[2])
			if !ok {
				return nil, false
			}
			conj = cs
		} else {
			for _, f := range fields {
				cs, ok := parseComparator(f)
				if !ok {
					return nil, false
				}
				conj = append(conj, cs...)
			}
		}
		alternatives = append(alternatives, conj)
	}
	return alternatives, true
}

// parsePartial reads X, X.Y or X.Y.Z, each part a number or x, X or *. fixed is how many leading
// parts are numbers before the first free one; the parts from there on read as 0.
func parsePartial(s string) (p [3]int, fixed int, ok bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return p, 0, false
	}
	fixed = len(parts)
	for i, part := range parts {
		if part == "x" || part == "X" || part == "*" {
			fixed = min(fixed, i)
			continue
		}
		if part == "" || len(part) > 1 && part[0] == '0' || strings.Trim(part, "0123456789") != "" {
			return p, 0, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n > semverMax {
			return p, 0, false
		}
		if i < fixed {
			p[i] = n
		}
	}
	return p, fixed, true
}

// next returns p with part i incremented and the later parts zeroed; ok is false past 2^53-1.
func next(p [3]int, i int) ([3]int, bool) {
	if p[i] >= semverMax {
		return p, false
	}
	p[i]++
	for j := i + 1; j < 3; j++ {
		p[j] = 0
	}
	return p, true
}

// between returns >=lo <(lo with part i incremented).
func between(lo [3]int, i int) ([]comparator, bool) {
	hi, ok := next(lo, i)
	return []comparator{{">=", lo}, {"<", hi}}, ok
}

func parseComparator(f string) ([]comparator, bool) {
	var op string
	for _, o := range []string{"^", "~", ">=", "<=", ">", "<", "="} {
		if rest, ok := strings.CutPrefix(f, o); ok {
			op, f = o, rest
			break
		}
	}
	p, fixed, ok := parsePartial(f)
	if !ok {
		return nil, false
	}
	switch op {
	case "^":
		switch {
		case fixed == 0:
			return nil, true
		case fixed == 1:
			return between(p, 0)
		case p[0] != 0:
			return between(p, 0)
		case fixed == 2 || p[1] != 0:
			return between(p, 1)
		default:
			return between(p, 2)
		}
	case "~":
		switch fixed {
		case 0:
			return nil, true
		case 1:
			return between(p, 0)
		default:
			return between(p, 1)
		}
	}
	switch {
	case fixed == 3:
		if op == "" {
			op = "="
		}
		return []comparator{{op, p}}, true
	case fixed == 0:
		if op == ">" || op == "<" {
			return []comparator{{"<", [3]int{}}}, true
		}
		return nil, true
	case op == ">":
		hi, ok := next(p, fixed-1)
		return []comparator{{">=", hi}}, ok
	case op == "<=":
		hi, ok := next(p, fixed-1)
		return []comparator{{"<", hi}}, ok
	case op == ">=" || op == "<":
		return []comparator{{op, p}}, true
	default: // "" or "="
		return between(p, fixed-1)
	}
}

// hyphenRange desugars "from - to": >=from, and <=to when to is full, else below to's next
// release at its last fixed part. A free from or to leaves that side unbounded.
func hyphenRange(from, to string) ([]comparator, bool) {
	lo, loFixed, ok := parsePartial(from)
	if !ok {
		return nil, false
	}
	hi, hiFixed, ok := parsePartial(to)
	if !ok {
		return nil, false
	}
	var cs []comparator
	if loFixed > 0 {
		cs = append(cs, comparator{">=", lo})
	}
	switch hiFixed {
	case 0:
	case 3:
		cs = append(cs, comparator{"<=", hi})
	default:
		bound, ok := next(hi, hiFixed-1)
		if !ok {
			return nil, false
		}
		cs = append(cs, comparator{"<", bound})
	}
	return cs, true
}

// semverMax is node-semver's MAX_SAFE_INTEGER bound on a version component.
const semverMax = 1<<53 - 1

// releaseVersion parses a strict X.Y.Z release.
func releaseVersion(s string) ([3]int, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var v [3]int
	for i, p := range parts {
		if p == "" || len(p) > 1 && p[0] == '0' || strings.Trim(p, "0123456789") != "" {
			return [3]int{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > semverMax {
			return [3]int{}, false
		}
		v[i] = n
	}
	return v, true
}

func compareRelease(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}
