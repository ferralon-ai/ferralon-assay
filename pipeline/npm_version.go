// internal/pipeline/npm_version.go
//
// npm (node-semver) version comparison and range matching for the JS/TS disqualification
// axis. The Go semver package (golang.org/x/mod/semver) cannot order npm versions: npm
// versions are NOT v-prefixed (1.2.3, not v1.2.3), so semver.IsValid rejects them
// outright, and npm range operators (^ ~ || x-ranges, hyphen ranges, comparators) follow
// node-semver's own rules. This is a focused, pure-Go port of the node-semver subset
// needed for a SOUND disqualification decision on the operators advisories actually use.
//
// It returns ok=false / no-match on ANY input outside the modelled grammar so the
// predicate fails OPEN (inv.5) — an exotic version or range never yields a confident,
// possibly-wrong ordering that could fabricate a not-affected. Build metadata ("+...") is
// ignored per semver; a prerelease ("-rc.1") orders below its release and is compared by
// node-semver's prerelease-identifier rules.
//
// Two entry points:
//   - npmVersionOutsideRange(ver, upper): the "affects < upper" disqualification bound
//     (Java symmetry — plugin resolves the literal version, pipeline applies the bound).
//   - npmVersionInRange(ver, rangeExpr): the full range matcher (^ ~ || x-ranges, hyphen,
//     comparators) for advisories that carry a node-semver range string.
package pipeline

import (
	"strconv"
	"strings"
)

// npmDisqualifyOutside decides "provably outside the affected set" for an npm-scheme advisory
// bound, dispatching on the SHAPE of the bound string:
//
//   - A PLAIN version "X.Y.Z[-pre]" (parseNPMVersion succeeds) keeps the single upper-exclusive
//     comparator (affects < bound) via npmVersionOutsideRange. This is the only shape any corpus
//     advisory uses today, so every existing npm verdict is unchanged; it is node-semver-aware and
//     fails OPEN on a boundary prerelease (a prerelease below the fix stays affected).
//   - A RANGE EXPRESSION (any node-semver operator — ^ ~ < > = x-range, hyphen, "||") is a single
//     CONTIGUOUS affected-set string (NOT multi-range representation, which would need a slice). It
//     is evaluated by the full node-semver matcher (npmVersionInRangeIncludePrerelease): ver is
//     provably outside the affected set iff it is confidently NOT in the range. This un-bypasses the
//     matcher and lets an advisory pin a lower AND upper bound (e.g. ">=1.2.0 <1.4.0") so a
//     below-floor version the single-upper-bound path would over-include as affected is precisely
//     disqualified.
//
// The range branch uses INCLUDE-PRERELEASE membership (node-semver's prerelease isolation is
// DISABLED here): an installed prerelease whose numeric core falls inside the affected window (e.g.
// "1.3.0-rc.1" in ">=1.2.0 <1.4.0") counts as IN the affected set, so it is NEVER disqualified as
// not-affected. Isolation is a dependency-RESOLUTION convenience (don't auto-install prereleases);
// applying it to a vulnerability-membership test would fail CLOSED — a false negative excluding a
// genuinely-vulnerable in-window prerelease (inv.5). A prerelease OUTSIDE the numeric window (e.g.
// "1.5.0-rc.1") still fails a comparator and is correctly outside/not-affected.
//
// Either way ok=false fails OPEN (inv.5): an unparseable version or range never yields a confident,
// possibly-wrong "not affected".
func npmDisqualifyOutside(ver, bound string) (outside bool, ok bool) {
	if _, isPlain := parseNPMVersion(bound); isPlain {
		return npmVersionOutsideRange(ver, bound)
	}
	inRange, ok := npmVersionInRangeIncludePrerelease(ver, bound)
	if !ok {
		return false, false
	}
	return !inRange, true
}

// npmVersionOutsideRange reports whether ver is provably outside the affected set
// affects<upper under npm ordering. ok is false (no proof) on any input the comparator
// cannot confidently order. Provably-outside means compareNPM(ver, upper) >= 0.
func npmVersionOutsideRange(ver, upper string) (outside bool, ok bool) {
	a, aok := parseNPMVersion(ver)
	b, bok := parseNPMVersion(upper)
	if !aok || !bok {
		return false, false
	}
	return compareNPMVersion(a, b) >= 0, true
}

// npmVersionInRange reports whether ver satisfies the node-semver range expression
// rangeExpr (e.g. ">=1.2.0 <2.0.0", "^1.2.3", "~1.2", "1.x", "1.2.3 - 1.4.0", or a
// "||"-joined union of those). ok is false when ver or any part of the range falls
// outside the modelled grammar, so the caller fails open. A range is a union ("||") of
// comparator-set conjunctions; ver satisfies the range iff it satisfies every comparator
// in at least one set.
func npmVersionInRange(ver, rangeExpr string) (inRange bool, ok bool) {
	return npmVersionInRangeOpt(ver, rangeExpr, false)
}

// npmVersionInRangeIncludePrerelease is npmVersionInRange with node-semver's prerelease-isolation
// rule DISABLED: a prerelease version satisfies the range whenever its numeric core satisfies every
// comparator, regardless of whether any comparator named a prerelease with the same
// [major,minor,patch] tuple. The disqualification predicate uses this so an in-window prerelease
// fails OPEN (counts as affected) rather than being wrongly excluded (inv.5); see
// npmDisqualifyOutside.
func npmVersionInRangeIncludePrerelease(ver, rangeExpr string) (inRange bool, ok bool) {
	return npmVersionInRangeOpt(ver, rangeExpr, true)
}

func npmVersionInRangeOpt(ver, rangeExpr string, includePrerelease bool) (inRange bool, ok bool) {
	v, vok := parseNPMVersion(ver)
	if !vok {
		return false, false
	}
	sets := strings.Split(rangeExpr, "||")
	matchedAny := false
	for _, set := range sets {
		comps, cok := parseComparatorSet(strings.TrimSpace(set))
		if !cok {
			return false, false
		}
		if comparatorsSatisfied(v, comps, includePrerelease) {
			matchedAny = true
		}
	}
	return matchedAny, true
}

// --- npm version model -------------------------------------------------------

// npmVersion is a parsed node-semver version: three numeric components plus ordered
// prerelease identifiers. Build metadata is parsed away (it never affects ordering).
type npmVersion struct {
	major, minor, patch int
	prerelease          []string // empty for a release version
}

// parseNPMVersion parses a strict npm version "X.Y.Z[-pre][+build]" with an optional
// leading 'v'/'='. ok is false on any malformed input (missing components, non-numeric
// core, empty prerelease identifier) so the caller fails open.
func parseNPMVersion(s string) (npmVersion, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "=")
	if s == "" {
		return npmVersion{}, false
	}
	// Strip build metadata.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core := s
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, pre = s[:i], s[i+1:]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return npmVersion{}, false
	}
	major, ok1 := atoiNonNeg(parts[0])
	minor, ok2 := atoiNonNeg(parts[1])
	patch, ok3 := atoiNonNeg(parts[2])
	if !ok1 || !ok2 || !ok3 {
		return npmVersion{}, false
	}
	v := npmVersion{major: major, minor: minor, patch: patch}
	if pre != "" {
		ids := strings.Split(pre, ".")
		for _, id := range ids {
			if id == "" {
				return npmVersion{}, false
			}
		}
		v.prerelease = ids
	}
	return v, true
}

// atoiNonNeg parses a non-negative decimal integer with no leading '+'/'-'.
func atoiNonNeg(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || strings.HasPrefix(s, "+") {
		return 0, false
	}
	return n, true
}

// compareNPMVersion compares two parsed versions, returning -1/0/+1 per node-semver
// ordering: numeric core compared component-wise; a version WITH a prerelease orders
// BELOW the same core without one; prerelease identifiers compared per semver §11
// (numeric < non-numeric when mixed; numeric compared numerically; alphanumeric
// lexically; a longer identifier list wins when all shared identifiers are equal).
func compareNPMVersion(a, b npmVersion) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	return comparePrerelease(a.prerelease, b.prerelease)
}

func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0: // a is a release, b is a prerelease → a > b
		return 1
	case len(b) == 0:
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := comparePrereleaseID(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func comparePrereleaseID(a, b string) int {
	an, aNum := atoiNonNeg(a)
	bn, bNum := atoiNonNeg(b)
	switch {
	case aNum && bNum:
		return cmpInt(an, bn)
	case aNum: // numeric identifiers have lower precedence than alphanumeric
		return -1
	case bNum:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// --- range model -------------------------------------------------------------

// comparator is one primitive constraint: an operator (<, <=, >, >=, =) and a version.
type comparator struct {
	op string
	v  npmVersion
}

// comparatorsSatisfied reports whether v satisfies every comparator in the set. Unless
// includePrerelease is set, a prerelease version only satisfies the set when some comparator's own
// version shares the same [major,minor,patch] tuple (node-semver's prerelease-isolation rule), so a
// prerelease never leaks into a range that did not explicitly mention that tuple's prereleases. When
// includePrerelease is true, isolation is skipped: a prerelease satisfies the set purely on the
// numeric comparator checks (the vulnerability-membership direction — see npmDisqualifyOutside).
func comparatorsSatisfied(v npmVersion, comps []comparator, includePrerelease bool) bool {
	for _, c := range comps {
		if !satisfiesComparator(v, c) {
			return false
		}
	}
	if len(v.prerelease) > 0 && !includePrerelease {
		return prereleaseAllowed(v, comps)
	}
	return true
}

// prereleaseAllowed implements node-semver's prerelease isolation: a prerelease version
// is only admitted into a comparator set when some comparator in the set itself names a
// prerelease sharing the same [major,minor,patch] tuple.
func prereleaseAllowed(v npmVersion, comps []comparator) bool {
	for _, c := range comps {
		if len(c.v.prerelease) > 0 && sameCore(v, c.v) {
			return true
		}
	}
	return false
}

func satisfiesComparator(v npmVersion, c comparator) bool {
	cmp := compareNPMVersion(v, c.v)
	switch c.op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=", "":
		return cmp == 0
	}
	return false
}

func sameCore(a, b npmVersion) bool {
	return a.major == b.major && a.minor == b.minor && a.patch == b.patch
}

// parseComparatorSet parses a whitespace-separated comparator-set (a conjunction), each
// element one of: a bare/operator-prefixed version, a caret/tilde range, an x-range, or a
// hyphen range ("a - b"). It expands the high-level operators into primitive
// comparators. ok is false on any element it cannot model.
func parseComparatorSet(set string) ([]comparator, bool) {
	if set == "" || set == "*" {
		// "*" matches any release version; model as ">=0.0.0".
		return []comparator{{op: ">=", v: npmVersion{}}}, true
	}
	fields := strings.Fields(set)
	// Hyphen range "a - b".
	if i := indexOf(fields, "-"); i >= 0 {
		if i != 1 || len(fields) != 3 {
			return nil, false
		}
		lo, lok := parseNPMVersion(fields[0])
		hi, hok := parseNPMVersion(fields[2])
		if !lok || !hok {
			return nil, false
		}
		return []comparator{{op: ">=", v: lo}, {op: "<=", v: hi}}, true
	}

	var out []comparator
	for _, f := range fields {
		cs, ok := parseComparator(f)
		if !ok {
			return nil, false
		}
		out = append(out, cs...)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// parseComparator parses one comparator field into one or more primitive comparators.
func parseComparator(f string) ([]comparator, bool) {
	switch {
	case strings.HasPrefix(f, "^"):
		return caretRange(f[1:])
	case strings.HasPrefix(f, "~"):
		return tildeRange(f[1:])
	case strings.HasPrefix(f, ">="):
		return opComparator(">=", f[2:])
	case strings.HasPrefix(f, "<="):
		return opComparator("<=", f[2:])
	case strings.HasPrefix(f, ">"):
		return opComparator(">", f[1:])
	case strings.HasPrefix(f, "<"):
		return opComparator("<", f[1:])
	case strings.HasPrefix(f, "="):
		return exactOrXRange(f[1:])
	default:
		return exactOrXRange(f)
	}
}

// opComparator builds a single operator comparator from a strict version operand.
func opComparator(op, raw string) ([]comparator, bool) {
	v, ok := parseNPMVersion(strings.TrimSpace(raw))
	if !ok {
		return nil, false
	}
	return []comparator{{op: op, v: v}}, true
}

// exactOrXRange handles a bare version operand that may be a strict version (=match) or
// an x-range / partial version ("1", "1.2", "1.x", "1.2.*") which expands to a
// [>=floor, <ceil) pair.
func exactOrXRange(raw string) ([]comparator, bool) {
	raw = strings.TrimSpace(raw)
	if v, ok := parseNPMVersion(raw); ok {
		return []comparator{{op: "=", v: v}}, true
	}
	return xRange(raw)
}

// xRange expands a partial version / x-range into a [>=floor, <ceil) comparator pair.
// "1" or "1.x" → >=1.0.0 <2.0.0; "1.2" or "1.2.x" → >=1.2.0 <1.3.0; "*"/"x" → >=0.0.0.
func xRange(raw string) ([]comparator, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" || raw == "x" || raw == "X" {
		return []comparator{{op: ">=", v: npmVersion{}}}, true
	}
	parts := strings.Split(raw, ".")
	if len(parts) > 3 {
		return nil, false
	}
	major, mok := atoiNonNeg(parts[0])
	if !mok {
		return nil, false
	}
	if len(parts) == 1 || isWildcard(parts[1]) {
		return []comparator{
			{op: ">=", v: npmVersion{major: major}},
			{op: "<", v: npmVersion{major: major + 1}},
		}, true
	}
	minor, nok := atoiNonNeg(parts[1])
	if !nok {
		return nil, false
	}
	if len(parts) == 2 || isWildcard(parts[2]) {
		return []comparator{
			{op: ">=", v: npmVersion{major: major, minor: minor}},
			{op: "<", v: npmVersion{major: major, minor: minor + 1}},
		}, true
	}
	return nil, false
}

func isWildcard(s string) bool {
	return s == "x" || s == "X" || s == "*"
}

// caretRange expands "^X.Y.Z" to [>=floor, <ceil) following node-semver's caret
// semantics, where the ceiling depends on how many components are specified:
//   - partial "^X"     (major only): bump major   — ^1 → <2.0.0,   ^0 → <1.0.0.
//   - partial "^X.Y"   (no patch):   if major==0 bump minor else major — ^1.2 → <2.0.0,
//     ^0.2 → <0.3.0, ^0.0 → <0.1.0.
//   - full "^X.Y.Z":   bump the left-most non-zero component — ^1.2.3 → <2.0.0,
//     ^0.2.3 → <0.3.0, ^0.0.3 → <0.0.4.
//
// ok is false on a malformed operand.
func caretRange(raw string) ([]comparator, bool) {
	v, partial, ok := parsePartialVersion(raw)
	if !ok {
		return nil, false
	}
	floor := v
	var ceil npmVersion
	switch {
	case partial == 1:
		// Only major specified; minor/patch are wildcards → bump major.
		ceil = npmVersion{major: v.major + 1}
	case partial == 2:
		// major.minor specified, patch is a wildcard.
		if v.major == 0 {
			ceil = npmVersion{minor: v.minor + 1}
		} else {
			ceil = npmVersion{major: v.major + 1}
		}
	default:
		// Full version: bump the left-most non-zero component.
		switch {
		case v.major != 0:
			ceil = npmVersion{major: v.major + 1}
		case v.minor != 0:
			ceil = npmVersion{minor: v.minor + 1}
		default:
			ceil = npmVersion{patch: v.patch + 1}
		}
	}
	return []comparator{{op: ">=", v: floor}, {op: "<", v: ceil}}, true
}

// tildeRange expands "~X.Y.Z" / "~X.Y" to [>=floor, <ceil): ~1.2.3 → <1.3.0; ~1.2 →
// <1.3.0; ~1 → <2.0.0. ok is false on a malformed operand.
func tildeRange(raw string) ([]comparator, bool) {
	v, partial, ok := parsePartialVersion(raw)
	if !ok {
		return nil, false
	}
	floor := v
	var ceil npmVersion
	if partial >= 2 {
		ceil = npmVersion{major: v.major, minor: v.minor + 1}
	} else {
		ceil = npmVersion{major: v.major + 1}
	}
	return []comparator{{op: ">=", v: floor}, {op: "<", v: ceil}}, true
}

// parsePartialVersion parses "X", "X.Y", or "X.Y.Z" (missing components default to 0),
// returning the version, the count of specified components, and ok. A wildcard component
// is treated as absent. Prerelease/build suffixes on the final component are honored only
// for a full 3-part version.
func parsePartialVersion(raw string) (npmVersion, int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return npmVersion{}, 0, false
	}
	if v, ok := parseNPMVersion(raw); ok {
		return v, 3, true
	}
	parts := strings.Split(raw, ".")
	if len(parts) > 3 {
		return npmVersion{}, 0, false
	}
	var nums [3]int
	count := 0
	for i, p := range parts {
		if isWildcard(p) {
			break
		}
		n, ok := atoiNonNeg(p)
		if !ok {
			return npmVersion{}, 0, false
		}
		nums[i] = n
		count++
	}
	if count == 0 {
		return npmVersion{}, 0, false
	}
	return npmVersion{major: nums[0], minor: nums[1], patch: nums[2]}, count, true
}

func indexOf(ss []string, target string) int {
	for i, s := range ss {
		if s == target {
			return i
		}
	}
	return -1
}
