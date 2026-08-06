// internal/pipeline/maven_version.go
//
// Maven version comparison for the Java disqualification axis. The Go semver package
// (golang.org/x/mod/semver) cannot compare Maven versions: they are not v-prefixed, segment
// counts vary (1.2 vs 1.2.0), and qualifiers like "-RELEASE"/"-RC1"/".Final" order by Maven's
// own rules, not SemVer's. This is a faithful port of the subset of Apache Maven's
// org.apache.maven.artifact.versioning.ComparableVersion needed for a SOUND "resolved >= fixed"
// disqualification decision. It returns ok=false on ANY input outside the modelled grammar so
// the predicate fails OPEN (inv.5) — an exotic version never yields a confident, possibly-wrong
// ordering that could fabricate a not-affected.
package pipeline

import (
	"math/big"
	"strings"
)

// mavenVersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper under Maven ordering. ok is false (no proof) on any input the comparator
// cannot confidently order. Provably-outside means compareMaven(ver, upper) >= 0.
func mavenVersionOutsideRange(ver, upper string) (outside bool, ok bool) {
	cmp, cok := compareMaven(ver, upper)
	if !cok {
		return false, false
	}
	return cmp >= 0, true
}

// compareMaven compares two Maven version strings, returning -1/0/+1 and ok. ok is false when
// either input is empty or contains a character outside the modelled grammar
// ([0-9A-Za-z.+_-]), so callers fail open on anything exotic.
func compareMaven(a, b string) (int, bool) {
	if !mavenGrammarOK(a) || !mavenGrammarOK(b) {
		return 0, false
	}
	return compareItem(parseMaven(a), parseMaven(b)), true
}

func mavenGrammarOK(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c == '.' || c == '-' || c == '_' || c == '+':
		default:
			return false
		}
	}
	return true
}

// --- ComparableVersion port --------------------------------------------------
//
// Maven parses a version into a nested list of items. An item is one of: an integer, a string
// (qualifier), or a sub-list (introduced by a '-' that follows a digit, i.e. a transition into
// a "release/qualifier" level). Comparison normalizes by trimming trailing "null" items.

type itemKind int

const (
	kindInt itemKind = iota
	kindString
	kindList
)

type item struct {
	kind itemKind
	intV *big.Int
	strV string  // normalized qualifier (for kindString)
	list []*item // for kindList
}

// parseMaven implements Maven's ComparableVersion(String) tokenizer.
func parseMaven(version string) *item {
	version = strings.ToLower(version)
	root := &item{kind: kindList}
	stack := []*item{root}
	cur := root

	isDigit := false
	startIndex := 0

	for i := 0; i < len(version); i++ {
		c := version[i]
		switch {
		case c == '.':
			if i == startIndex {
				cur.list = append(cur.list, intItem("0"))
			} else {
				cur.list = append(cur.list, parseItem(isDigit, version[startIndex:i]))
			}
			startIndex = i + 1
		case c == '-' || c == '_' || c == '+':
			if i == startIndex {
				cur.list = append(cur.list, intItem("0"))
			} else {
				cur.list = append(cur.list, parseItem(isDigit, version[startIndex:i]))
			}
			startIndex = i + 1
			// A separator after a digit opens a new sub-list (transition to qualifier level).
			if isDigit {
				sub := &item{kind: kindList}
				cur.list = append(cur.list, sub)
				stack = append(stack, sub)
				cur = sub
			}
		case isDigitByte(c):
			if !isDigit && i > startIndex {
				cur.list = append(cur.list, &item{kind: kindString, strV: normalizeQualifier(version[startIndex:i])})
				startIndex = i
				// digit after a string opens a sub-list too
				sub := &item{kind: kindList}
				cur.list = append(cur.list, sub)
				stack = append(stack, sub)
				cur = sub
			}
			isDigit = true
		default:
			if isDigit && i > startIndex {
				cur.list = append(cur.list, parseItem(true, version[startIndex:i]))
				startIndex = i
				sub := &item{kind: kindList}
				cur.list = append(cur.list, sub)
				stack = append(stack, sub)
				cur = sub
			}
			isDigit = false
		}
	}
	if len(version) > startIndex {
		cur.list = append(cur.list, parseItem(isDigit, version[startIndex:]))
	}

	// Normalize each list on the stack from the deepest up.
	for len(stack) > 0 {
		l := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		normalizeList(l)
	}
	return root
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func parseItem(isDigit bool, buf string) *item {
	if isDigit {
		return intItem(buf)
	}
	return &item{kind: kindString, strV: normalizeQualifier(buf)}
}

func intItem(s string) *item {
	n := new(big.Int)
	n.SetString(s, 10)
	if n.Sign() == 0 {
		n = big.NewInt(0)
	}
	return &item{kind: kindInt, intV: n}
}

// qualifier aliases per Maven's well-known qualifier table.
var qualifierAliases = map[string]string{
	"ga": "", "final": "", "release": "",
	"cr": "rc",
}

func normalizeQualifier(q string) string {
	if alias, ok := qualifierAliases[q]; ok {
		return alias
	}
	return q
}

// normalizeList trims trailing "null" items: integer 0, the empty string qualifier, or an empty
// sub-list — matching Maven's ListItem.normalize().
func normalizeList(l *item) {
	for len(l.list) > 0 && l.list[len(l.list)-1].isNull() {
		l.list = l.list[:len(l.list)-1]
	}
}

func (it *item) isNull() bool {
	switch it.kind {
	case kindInt:
		return it.intV.Sign() == 0
	case kindString:
		return qualifierOrder(it.strV) == qualifierOrderRelease
	case kindList:
		return len(it.list) == 0
	}
	return false
}

// --- comparison --------------------------------------------------------------

func compareItem(a, b *item) int {
	switch a.kind {
	case kindInt:
		return compareIntItem(a, b)
	case kindString:
		return compareStringItem(a, b)
	case kindList:
		return compareListItem(a, b)
	}
	return 0
}

func compareIntItem(a, b *item) int {
	if b == nil {
		if a.intV.Sign() == 0 {
			return 0
		}
		return 1
	}
	switch b.kind {
	case kindInt:
		return a.intV.Cmp(b.intV)
	case kindString:
		return 1 // int > string qualifier
	case kindList:
		return 1 // int > list
	}
	return 0
}

func compareStringItem(a, b *item) int {
	if b == nil {
		// compare against empty (release) qualifier
		return compareQualifier(a.strV, "")
	}
	switch b.kind {
	case kindInt:
		return -1 // string < int
	case kindString:
		return compareQualifier(a.strV, b.strV)
	case kindList:
		return -1 // string < list
	}
	return 0
}

func compareListItem(a, b *item) int {
	if b == nil {
		if len(a.list) == 0 {
			return 0
		}
		// compare first item against null
		return compareItem(a.list[0], nil)
	}
	switch b.kind {
	case kindInt:
		return -1 // list < int
	case kindString:
		return 1 // list > string
	case kindList:
		n := len(a.list)
		if len(b.list) > n {
			n = len(b.list)
		}
		for i := 0; i < n; i++ {
			var ai, bi *item
			if i < len(a.list) {
				ai = a.list[i]
			}
			if i < len(b.list) {
				bi = b.list[i]
			}
			var c int
			switch {
			case ai == nil && bi == nil:
				c = 0
			case ai == nil:
				c = -compareItem(bi, nil)
			default:
				c = compareItem(ai, bi)
			}
			if c != 0 {
				return c
			}
		}
		return 0
	}
	return 0
}

// Qualifier ordering. Maven uses a well-known list; the empty qualifier ("", i.e. release)
// sorts after the pre-release qualifiers and before "sp". Unknown qualifiers sort after the
// known set, lexically.
const (
	qualifierOrderRelease = 5 // index of "" in the ordered list below
)

var knownQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// qualifierOrder returns the index of q in the known-qualifier ordering, or len(known) when
// unknown (sorts after all known, then lexically among unknowns).
func qualifierOrder(q string) int {
	q = expandShortAlias(q)
	for i, k := range knownQualifiers {
		if q == k {
			return i
		}
	}
	return len(knownQualifiers)
}

// expandShortAlias maps single-letter Maven qualifier aliases to their long forms.
func expandShortAlias(q string) string {
	switch q {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "m":
		return "milestone"
	default:
		return q
	}
}

func compareQualifier(a, b string) int {
	oa, ob := qualifierOrder(a), qualifierOrder(b)
	if oa != ob {
		if oa < ob {
			return -1
		}
		return 1
	}
	if oa == len(knownQualifiers) {
		// both unknown → lexical
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		}
	}
	return 0
}
