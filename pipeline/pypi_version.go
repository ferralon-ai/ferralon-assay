// internal/pipeline/pypi_version.go
//
// PEP 440 version comparison and specifier matching for the Python (PyPI)
// disqualification axis. PEP 440 is structurally different from every other scheme
// versionOutsideRange understands: it has an EPOCH ("1!1.0", a higher epoch always
// wins), a VARIABLE-LENGTH release ("1.0" == "1.0.0", trailing zeros insignificant),
// pre-releases that sort BELOW their final release ("1.0a1" < "1.0"), post-releases
// that sort ABOVE it ("1.0" < "1.0.post1"), dev-releases that sort BELOW everything
// for the same release (even below pre-releases), a "~=" compatible-release operator,
// and LOCAL versions ("+abc.1") whose segment ordering is the REVERSE of npm's
// (numeric > alphabetic here). Neither golang.org/x/mod/semver nor the npm/maven
// comparators can order these, so this is a focused, pure-Go port of the subset of
// packaging.version needed for a SOUND disqualification decision.
//
// It returns ok=false on ANY input outside the modelled grammar so the predicate fails
// OPEN (inv.5) — an exotic version or specifier never yields a confident,
// possibly-wrong ordering that could fabricate a not-affected. Same contract
// npm_version.go / maven_version.go document.
//
// Two entry points (mirroring npm_version.go):
//   - pypiVersionOutsideRange(ver, upper): the "affects < upper" disqualification bound
//     (plugin resolves the literal installed version, pipeline applies the bound).
//   - pypiVersionInRange(ver, spec): the full PEP 440 specifier set (a ","-joined AND of
//     >=, <=, >, <, ==, !=, ~=, ==prefix.*, ===) for advisories carrying a specifier.
package pipeline

import (
	"regexp"
	"strconv"
	"strings"
)

// pypiVersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper under PEP 440 ordering. ok is false (no proof) on any input the
// comparator cannot confidently order. Provably-outside means comparePEP440(ver, upper) >= 0.
func pypiVersionOutsideRange(ver, upper string) (outside bool, ok bool) {
	a, aok := parsePEP440(ver)
	b, bok := parsePEP440(upper)
	if !aok || !bok {
		return false, false
	}
	return comparePEP440(a, b) >= 0, true
}

// pypiVersionInRange reports whether ver satisfies the PEP 440 specifier spec — a
// ","-joined conjunction (AND) of clauses, each one of >=, <=, >, <, ==, !=, ~=,
// "==X.Y.*" prefix match, or "===" arbitrary equality. PEP 440 has no "||" union.
// ok is false when ver or any clause falls outside the modelled grammar, so the
// caller fails open. A version satisfies the spec iff it satisfies EVERY clause.
func pypiVersionInRange(ver, spec string) (inRange bool, ok bool) {
	v, vok := parsePEP440(ver)
	if !vok {
		return false, false
	}
	for _, clause := range strings.Split(spec, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		sat, cok := satisfiesPEP440(v, ver, clause)
		if !cok {
			return false, false
		}
		if !sat {
			return false, true
		}
	}
	return true, true
}

// --- PEP 440 version model ---------------------------------------------------

// pep440Version is a parsed PEP 440 version. Absent optional segments are recorded by
// their has* flags so the canonical sort-key sentinels (a dev release sorts below a
// pre-release; a post release sorts above the final; a local sorts above the same
// version without one) can be applied in comparePEP440.
type pep440Version struct {
	epoch   int
	release []int

	hasPre  bool
	preKind string // normalized: "a" | "b" | "rc"
	preNum  int

	hasPost bool
	postNum int

	hasDev bool
	devNum int

	local []localSegment // nil for no local version
}

// localSegment is one dot-separated component of a "+local" version. A segment made
// entirely of digits is numeric (compared numerically and sorting ABOVE any
// alphabetic segment — the REVERSE of npm's prerelease rule); otherwise it is a
// string segment compared lexically.
type localSegment struct {
	isNum bool
	num   int
	str   string
}

// pep440Re is the canonical PEP 440 grammar (packaging.version's VERSION_PATTERN),
// anchored and case-insensitive. Separators '.', '-', '_' are all accepted between
// segments; alias spellings (alpha/beta/c/pre/preview, rev/r) are normalized after the
// match. The optional leading 'v' and surrounding whitespace are tolerated.
var pep440Re = regexp.MustCompile(`(?i)^\s*v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?` +
	`\s*$`)

// parsePEP440 parses s into a pep440Version. ok is false on any input outside the
// PEP 440 grammar (so the caller fails open, never fabricating a not-affected).
func parsePEP440(s string) (pep440Version, bool) {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pep440Version{}, false
	}
	g := func(name string) string { return m[pep440Re.SubexpIndex(name)] }

	var v pep440Version
	if e := g("epoch"); e != "" {
		n, err := strconv.Atoi(e)
		if err != nil {
			return pep440Version{}, false
		}
		v.epoch = n
	}

	for _, part := range strings.Split(g("release"), ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return pep440Version{}, false
		}
		v.release = append(v.release, n)
	}
	if len(v.release) == 0 {
		return pep440Version{}, false
	}

	if pl := g("pre_l"); pl != "" {
		v.hasPre = true
		v.preKind = normalizePreKind(pl)
		v.preNum = atoiOrZero(g("pre_n"))
	}

	// Post: either the implicit "-N" form (post_n1) or the explicit "post/rev/r N" form.
	if pn1 := g("post_n1"); pn1 != "" {
		v.hasPost = true
		v.postNum = atoiOrZero(pn1)
	} else if g("post_l") != "" {
		v.hasPost = true
		v.postNum = atoiOrZero(g("post_n2"))
	}

	if g("dev_l") != "" {
		v.hasDev = true
		v.devNum = atoiOrZero(g("dev_n"))
	}

	if loc := g("local"); loc != "" {
		v.local = parseLocal(loc)
	}
	return v, true
}

// normalizePreKind maps PEP 440's pre-release alias spellings onto the three canonical
// kinds a<b<rc: alpha→a, beta→b, c/pre/preview→rc.
func normalizePreKind(s string) string {
	switch strings.ToLower(s) {
	case "a", "alpha":
		return "a"
	case "b", "beta":
		return "b"
	case "c", "rc", "pre", "preview":
		return "rc"
	}
	return strings.ToLower(s)
}

// parseLocal splits a "+local" body on any of '.', '-', '_' into ordered segments. A
// wholly-numeric segment is numeric (leading zeros stripped by Atoi); anything else is
// a lowercased string segment.
func parseLocal(s string) []localSegment {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
	out := make([]localSegment, 0, len(fields))
	for _, f := range fields {
		if n, err := strconv.Atoi(f); err == nil && isAllDigits(f) {
			out = append(out, localSegment{isNum: true, num: n})
		} else {
			out = append(out, localSegment{str: strings.ToLower(f)})
		}
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func atoiOrZero(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// --- ordering ----------------------------------------------------------------

// comparePEP440 compares two parsed versions, returning -1/0/+1 under PEP 440's
// canonical sort key (epoch, release, pre, post, dev, local). Each field applies the
// packaging.version sentinel rules: a dev-only release sorts below any pre-release; a
// missing pre sorts above any pre; a missing post sorts below any post; a missing dev
// sorts above any dev; a missing local sorts below any local.
func comparePEP440(a, b pep440Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := compareRelease(a.release, b.release); c != 0 {
		return c
	}
	if c := comparePre(a, b); c != 0 {
		return c
	}
	if c := comparePost(a, b); c != 0 {
		return c
	}
	if c := compareDev(a, b); c != 0 {
		return c
	}
	return compareLocal(a.local, b.local)
}

// compareRelease compares two release tuples with trailing zeros stripped (so
// "1.0" == "1.0.0") and the shorter zero-padded, component-wise.
func compareRelease(a, b []int) int {
	a = stripTrailingZeros(a)
	b = stripTrailingZeros(b)
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if c := cmpInt(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

func stripTrailingZeros(r []int) []int {
	end := len(r)
	for end > 1 && r[end-1] == 0 {
		end--
	}
	return r[:end]
}

// comparePre applies PEP 440's pre-release sentinel: a version whose ONLY suffix is a
// dev release (no pre, no post) sorts below any pre-release (NegativeInfinity); a
// version with no pre at all otherwise sorts above any pre-release (Infinity); two
// pre-releases compare by (kind, number).
func comparePre(a, b pep440Version) int {
	ra, ka, na := preSortKey(a)
	rb, kb, nb := preSortKey(b)
	if ra != rb {
		return cmpInt(ra, rb)
	}
	if ra != 0 { // both NegativeInfinity or both Infinity
		return 0
	}
	if c := strings.Compare(ka, kb); c != 0 {
		return c
	}
	return cmpInt(na, nb)
}

// preSortKey returns the rank sentinel (-1 = below all pre, 0 = a concrete pre, 1 =
// above all pre) plus the concrete pre (kind, number) when rank is 0.
func preSortKey(v pep440Version) (rank int, kind string, num int) {
	if !v.hasPre && !v.hasPost && v.hasDev {
		return -1, "", 0
	}
	if !v.hasPre {
		return 1, "", 0
	}
	return 0, v.preKind, v.preNum
}

// comparePost applies the post-release sentinel: a missing post sorts BELOW any post,
// so a post-release ("1.0.post1") sorts above its final release ("1.0").
func comparePost(a, b pep440Version) int {
	if a.hasPost != b.hasPost {
		if a.hasPost {
			return 1
		}
		return -1
	}
	if !a.hasPost {
		return 0
	}
	return cmpInt(a.postNum, b.postNum)
}

// compareDev applies the dev-release sentinel: a missing dev sorts ABOVE any dev, so a
// dev-release ("1.0.dev1") sorts below its release ("1.0") and below its pre-release.
func compareDev(a, b pep440Version) int {
	if a.hasDev != b.hasDev {
		if a.hasDev {
			return -1
		}
		return 1
	}
	if !a.hasDev {
		return 0
	}
	return cmpInt(a.devNum, b.devNum)
}

// compareLocal orders the "+local" segment lists: a version WITH a local segment sorts
// above the same version without one; segment-wise, a numeric segment sorts above an
// alphabetic one (the reverse of npm), numerics compare numerically, alphabetics
// lexically, and a longer list wins when all shared segments are equal.
func compareLocal(a, b []localSegment) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	case len(b) == 0:
		return 1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := compareLocalSegment(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func compareLocalSegment(a, b localSegment) int {
	if a.isNum != b.isNum {
		if a.isNum { // numeric sorts ABOVE alphabetic (reverse of npm's prerelease rule)
			return 1
		}
		return -1
	}
	if a.isNum {
		return cmpInt(a.num, b.num)
	}
	return strings.Compare(a.str, b.str)
}

// --- specifier matching ------------------------------------------------------

// satisfiesPEP440 reports whether v (with raw text ver, needed for the "===" arbitrary
// string operator) satisfies one PEP 440 clause. ok is false when the clause's operator
// or operand is unparseable, so the caller fails open.
func satisfiesPEP440(v pep440Version, ver, clause string) (sat bool, ok bool) {
	op, operand := splitOperator(clause)
	if op == "" {
		return false, false
	}
	switch op {
	case "===":
		return strings.TrimSpace(ver) == strings.TrimSpace(operand), true
	case "~=":
		return compatibleRelease(v, operand)
	case "==":
		return equalOrPrefix(v, operand, false)
	case "!=":
		return equalOrPrefix(v, operand, true)
	case ">=", "<=", ">", "<":
		b, bok := parsePEP440(operand)
		if !bok {
			return false, false
		}
		cmp := comparePEP440(v, b)
		switch op {
		case ">=":
			return cmp >= 0, true
		case "<=":
			return cmp <= 0, true
		case ">":
			return cmp > 0, true
		case "<":
			return cmp < 0, true
		}
	}
	return false, false
}

// splitOperator peels the leading comparison operator off a clause, longest-match
// first so "===", "==", ">=", "<=", "~=", "!=" bind before the single-char forms.
func splitOperator(clause string) (op, operand string) {
	for _, cand := range []string{"===", "==", ">=", "<=", "!=", "~=", ">", "<"} {
		if strings.HasPrefix(clause, cand) {
			return cand, strings.TrimSpace(clause[len(cand):])
		}
	}
	return "", ""
}

// equalOrPrefix handles "==" / "!=" including the "X.Y.*" prefix-match form. For a
// prefix operand it compares epoch and the release prefix component-wise; otherwise it
// requires full-version equality. negate inverts the result for "!=".
func equalOrPrefix(v pep440Version, operand string, negate bool) (sat bool, ok bool) {
	if strings.HasSuffix(operand, ".*") {
		prefix, pok := parsePEP440(strings.TrimSuffix(operand, ".*"))
		if !pok {
			return false, false
		}
		match := prefixMatch(v, prefix)
		if negate {
			match = !match
		}
		return match, true
	}
	b, bok := parsePEP440(operand)
	if !bok {
		return false, false
	}
	eq := comparePEP440(v, b) == 0
	if negate {
		eq = !eq
	}
	return eq, true
}

// prefixMatch reports whether v matches a "==X.Y.*" prefix: same epoch and the release
// components up to the prefix length equal (the tail of v is unconstrained).
func prefixMatch(v, prefix pep440Version) bool {
	if v.epoch != prefix.epoch {
		return false
	}
	for i, want := range prefix.release {
		got := 0
		if i < len(v.release) {
			got = v.release[i]
		}
		if got != want {
			return false
		}
	}
	return true
}

// compatibleRelease implements "~=": ~=X.Y.Z ≡ >=X.Y.Z, <X.(Y+1); ~=X.Y ≡ >=X.Y, <(X+1).
// It requires at least two release components in the operand (PEP 440 rule); fewer is
// unparseable → fail open.
func compatibleRelease(v pep440Version, operand string) (sat bool, ok bool) {
	floor, fok := parsePEP440(operand)
	if !fok || len(floor.release) < 2 {
		return false, false
	}
	if comparePEP440(v, floor) < 0 {
		return false, true
	}
	// Ceiling: drop the operand's last release component and bump the new last one.
	ceilRelease := make([]int, len(floor.release)-1)
	copy(ceilRelease, floor.release[:len(floor.release)-1])
	ceilRelease[len(ceilRelease)-1]++
	ceil := pep440Version{epoch: floor.epoch, release: ceilRelease}
	return comparePEP440(v, ceil) < 0, true
}
