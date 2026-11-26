package pipeline

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// ancestorReleaseTag returns the highest release tag of the Go module mod in the history of HEAD
// in the repository containing dir: a canonical semver tag under the module directory's prefix, at
// a major version the module path allows, that is HEAD or one of its ancestors. version is the tag
// with the prefix removed. ok is false when there is none, or when git fails. A shallow history
// answers only with the tags it still reaches, so it can find fewer tags, never a tag HEAD does not
// descend from.
func ancestorReleaseTag(ctx context.Context, dir, mod string) (tag, version string, ok bool) {
	_, pathMajor, split := module.SplitPathVersion(mod)
	if dir == "" || mod == "" || !split {
		return "", "", false
	}
	prefix, err := fixCommitGit(ctx, dir, "rev-parse", "--show-prefix")
	if err != nil {
		return "", "", false
	}
	out, err := fixCommitGit(ctx, dir, "tag", "--merged", "HEAD")
	if err != nil {
		return "", "", false
	}
	for _, t := range strings.Fields(out) {
		v, ok := strings.CutPrefix(t, prefix)
		if !ok || !semver.IsValid(v) || semver.Canonical(v) != v || module.IsPseudoVersion(v) || module.CheckPathMajor(v, pathMajor) != nil {
			continue
		}
		if version == "" || semver.Compare(v, version) > 0 {
			tag, version = t, v
		}
	}
	return tag, version, version != ""
}

// ancestorReleaseClears reports whether an advisory against the scanned project's own Go module is
// cleared by a release in the scanned history. The project's version at HEAD is not established
// (versions is empty), but HEAD descends from the release that release() names, so HEAD holds every
// change that release holds. The advisory is cleared when that release is at or past the fixed
// version of every range: each range then closed before the release, and HEAD carries the fixes
// unless one was reverted after it, which is the assumption the clearance names.
//
// Like fixCommitClears it only clears, and only when everything else is settled: every range ends
// at a fixed version under the Go module comparator, and every other affected package the build
// carries is outside its own ranges. A range that is open, ends at a last_affected, or closes above
// the release leaves HEAD's place in it unknown. release is asked only when the ranges and the
// other packages allow a clearance.
func ancestorReleaseClears(rngs []affectedRange, rangeKnown bool, versions []string, others []presentRanges, release func() (string, bool)) bool {
	if !rangeKnown || len(rngs) == 0 || len(versions) > 0 {
		return false
	}
	for _, r := range rngs {
		if r.UpperExclusive == "" || (r.Scheme != "" && r.Scheme != "gomod") {
			return false
		}
	}
	for _, o := range others {
		if !everyVersionOutside(o.Versions, o.Complete, o.Ranges, o.RangeKnown) {
			return false
		}
	}
	v, ok := release()
	if !ok {
		return false
	}
	for _, r := range rngs {
		if outside, ok := versionOutsideUpper(v, r); !ok || !outside {
			return false
		}
	}
	return true
}

// ancestorReleaseAssumption is the line a ReasonAncestorReleaseOutsideRange clearance rests on.
func ancestorReleaseAssumption(tag string) string {
	return fmt.Sprintf("the advisory's fix was not reverted between the release tag %s and the scanned commit", tag)
}
