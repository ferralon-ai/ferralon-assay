package jsanalysis

import (
	"strconv"
	"strings"
)

// rangeSatisfied reports whether a lockfile's recorded version satisfies a package.json
// dependency spec under node-semver's rules, the test npm applies to keep a locked version
// rather than re-resolve it. It models only a release version (X.Y.Z, no prerelease or build
// metadata) against one conjunction of these, each with a full X.Y.Z release operand:
//
//	X.Y.Z, =X.Y.Z       exactly that version
//	>X.Y.Z, >=, <, <=   the comparison
//	^X.Y.Z              >=X.Y.Z below the next release of its left-most non-zero part
//	                    (^1.2.3 <2.0.0, ^0.2.3 <0.3.0, ^0.0.3 <0.0.4)
//	~X.Y.Z              >=X.Y.Z <X.(Y+1).0
//
// With release operands and a release version, node-semver's prerelease rules never apply.
// Every other spec is not satisfied: a tag, URL, git, file:, link:, workspace: or npm: spec,
// "*" or empty, a partial or x-range (1, 1.2, 1.x), a hyphen range, "||", a v prefix, a space
// between an operator and its version, a prerelease or build suffix on either side, and a
// number with a leading zero or beyond 2^53-1 (which node-semver rejects).
func rangeSatisfied(version, spec string) bool {
	v, ok := releaseVersion(version)
	if !ok {
		return false
	}
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if !comparatorHolds(v, f) {
			return false
		}
	}
	return true
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

func comparatorHolds(v [3]int, f string) bool {
	var op string
	for _, o := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
		if rest, ok := strings.CutPrefix(f, o); ok {
			op, f = o, rest
			break
		}
	}
	w, ok := releaseVersion(f)
	if !ok {
		return false
	}
	c := compareRelease(v, w)
	switch op {
	case "", "=":
		return c == 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case "^":
		i := 0
		for i < 2 && w[i] == 0 {
			i++
		}
		return c >= 0 && v[i] == w[i] && samePrefix(v, w, i)
	case "~":
		return c >= 0 && v[0] == w[0] && v[1] == w[1]
	}
	return false
}

// samePrefix reports whether v and w agree on every part before i.
func samePrefix(v, w [3]int, i int) bool {
	for j := 0; j < i; j++ {
		if v[j] != w[j] {
			return false
		}
	}
	return true
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
