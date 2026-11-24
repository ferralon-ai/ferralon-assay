package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

var fullCommitID = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// fixCommitID reads the commit an advisory's fix.upstream_commit names: a full object id, bare or
// as the last element of a ".../commit/<id>" URL. An abbreviated id names no single commit, so it
// and every other spelling yield ok false.
func fixCommitID(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if i := strings.LastIndex(ref, "/commit/"); i >= 0 {
		ref = ref[i+len("/commit/"):]
	}
	ref = strings.ToLower(ref)
	return ref, fullCommitID.MatchString(ref)
}

// fixCommitGit runs git against the repository containing dir with every route to another
// repository closed: no transport is allowed and a promisor remote is never asked for a missing
// object, so the answer comes from the objects the checkout already holds. Replacement objects
// and the grafts file are ignored, since either can rewrite the parents the ancestry walk follows.
func fixCommitGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(gitRepositoryEnv, name)
	}), "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1",
		"GIT_GRAFT_FILE="+os.DevNull)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// historyAnswer is what the checkout's history says about whether it contains a commit.
type historyAnswer int

const (
	// historyUnanswered: the checkout cannot say, because its history is shallow or git failed.
	historyUnanswered historyAnswer = iota
	// historyContains: the commit is HEAD or one of its ancestors.
	historyContains
	// historyLacks: the history is complete and the commit is not in it.
	historyLacks
)

// headContainsCommit answers whether commit is HEAD or one of its ancestors in the repository
// containing dir. Only a complete history answers either way. A shallow repository has cut its
// ancestry off, so it leaves the question unanswered, as does any git failure. A complete history
// that does not hold the commit at all lacks it, since it holds every ancestor of HEAD.
func headContainsCommit(ctx context.Context, dir, commit string) historyAnswer {
	if dir == "" || !fullCommitID.MatchString(commit) {
		return historyUnanswered
	}
	if shallow, err := fixCommitGit(ctx, dir, "rev-parse", "--is-shallow-repository"); err != nil || shallow != "false" {
		return historyUnanswered
	}
	_, err := fixCommitGit(ctx, dir, "merge-base", "--is-ancestor", commit, "HEAD")
	var exit *exec.ExitError
	switch {
	case err == nil:
		return historyContains
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return historyLacks
	}
	// merge-base fails the same way for a commit the store does not hold and for a HEAD that names
	// no commit; only the first is an answer, and only when the store holds every commit HEAD's
	// history names. A store that has lost some (an alternate gone, a corrupt pack) may have lost
	// the fix with them; walking the history fails on the first missing commit.
	if _, err := fixCommitGit(ctx, dir, "cat-file", "-e", commit); errors.As(err, &exit) && exit.ExitCode() == 1 {
		if _, err := fixCommitGit(ctx, dir, "rev-list", "--quiet", "HEAD"); err == nil {
			return historyLacks
		}
	}
	return historyUnanswered
}

// goVersionTag returns the ref of the tag that publishes version of the Go module mod from the
// repository containing dir: the canonical semver tag under the module directory's prefix, at a
// major version the module path allows. ok is false for anything else, a pseudo-version included,
// since no tag is then certain to mark that version.
func goVersionTag(ctx context.Context, dir, mod, version string) (ref string, ok bool) {
	_, pathMajor, split := module.SplitPathVersion(mod)
	if mod == "" || !split {
		return "", false
	}
	// A +incompatible version is the plain tag of a module whose path carries no major suffix.
	v, incompatible := strings.CutSuffix("v"+strings.TrimPrefix(version, "v"), "+incompatible")
	if !semver.IsValid(v) || semver.Canonical(v) != v || module.IsPseudoVersion(v) {
		return "", false
	}
	if incompatible {
		if pathMajor != "" || semver.Compare(semver.Major(v), "v2") < 0 {
			return "", false
		}
	} else if module.CheckPathMajor(v, pathMajor) != nil {
		return "", false
	}
	prefix, err := fixCommitGit(ctx, dir, "rev-parse", "--show-prefix")
	if err != nil {
		return "", false
	}
	return "refs/tags/" + prefix + v, true
}

// rangeEnteredBeforeFix reports whether the scanned history is known not to have entered the
// affected range that starts at version lower after the fix commit. An advisory with several
// ranges names one fix, and a HEAD that contains it may still sit inside a range opened later.
//
// The range's first version is the module's tag for lower, and whatever made that release
// affected is in the tag's history. If HEAD's history holds it too, it is in the history of some
// merge base of the tag and HEAD. So the range is settled only when every merge base is the fix
// commit or one of its ancestors: all that HEAD shares with the affected release then predates
// the fix. A version with no certain tag, a tag the repository lacks, histories with no merge
// base and any git failure read as false. mod is the project's Go module path; a project of
// another ecosystem has no tag convention to rely on.
//
// It assumes a complete history, which headContainsCommit establishes first.
func rangeEnteredBeforeFix(ctx context.Context, dir, mod, commit, lower string) bool {
	ref, ok := goVersionTag(ctx, dir, mod, lower)
	if !ok {
		return false
	}
	out, err := fixCommitGit(ctx, dir, "merge-base", "--all", ref+"^{commit}", "HEAD")
	bases := strings.Fields(out)
	if err != nil || len(bases) == 0 {
		return false
	}
	for _, base := range bases {
		if _, err := fixCommitGit(ctx, dir, "merge-base", "--is-ancestor", base, commit); err != nil {
			return false
		}
	}
	return true
}

// fixCommitClears reports whether an advisory against the scanned project's own package is cleared
// by its fix commit being in the scanned history. It can only clear, and only when everything else
// the clearance needs is settled:
//
//   - the project has no established version of its own (versions is empty): a version the axis
//     could compare and did not clear stands against the commit;
//   - every range of the package ends at a fixed version, so the advisory states that a fix closes
//     each one. A range that is open, or ends at a last_affected, names no fix to find;
//   - every other affected package the build carries is outside its own ranges, as the version
//     axis requires: the project's fix says nothing about a dependency;
//   - when the package has several ranges, every range that starts above zero is one the history
//     did not enter after the fix (enteredBeforeFix, given the range's first version): the one
//     commit the advisory names closes one range and says nothing about a later one.
//
// inHistory is asked only when the ranges and the other packages allow a clearance, and
// enteredBeforeFix only after inHistory said yes. unanswered reports that everything else allowed
// the clearance and inHistory could not say, so the history the checkout lacks decides the advisory.
func fixCommitClears(rngs []affectedRange, rangeKnown bool, versions []string, others []presentRanges, inHistory func() historyAnswer, enteredBeforeFix func(lower string) bool) (cleared, unanswered bool) {
	if !rangeKnown || len(rngs) == 0 || len(versions) > 0 {
		return false, false
	}
	for _, r := range rngs {
		if r.UpperExclusive == "" {
			return false, false
		}
	}
	for _, o := range others {
		if !everyVersionOutside(o.Versions, o.Complete, o.Ranges, o.RangeKnown) {
			return false, false
		}
	}
	switch inHistory() {
	case historyUnanswered:
		return false, true
	case historyLacks:
		return false, false
	}
	if len(rngs) > 1 {
		for _, r := range rngs {
			if r.LowerInclusive != "" && r.LowerInclusive != "0" && !enteredBeforeFix(r.LowerInclusive) {
				return false, false
			}
		}
	}
	return true, false
}

// rootOwnsAdvisoryPackage reports whether the package the advisory was adjudicated on is the
// scanned project's own with nothing else able to supply it. A Go path the scan cannot tell apart
// from another module's (goOwnerAmbiguous) is not: that module may share this history, and the
// build may take the path from it at a version before the fix.
func rootOwnsAdvisoryPackage(store artifact.Store, caseID, buildDir string, ws GoWorkspace) bool {
	if buildDir == "" || !RootSubject(store, caseID) {
		return false
	}
	if extractCodebaseEcosystem(store, caseID) != "golang" {
		return true
	}
	mod := rootGoModule(store, caseID, buildDir)
	advModule, ok := extractAdvisoryModule(store, caseID)
	return ok && mod != "" && goPathOwner(buildDir, ws, mod, advModule) == goOwnedByRoot
}

// rootGoModule returns the scanned project's Go module path, "" when it is not a Go project.
func rootGoModule(store artifact.Store, caseID, buildDir string) string {
	if extractCodebaseEcosystem(store, caseID) != "golang" {
		return ""
	}
	return goModFileModule(filepath.Join(buildDir, "go.mod"))
}

// extractFixCommit reads the advisory's fix commit off the normalized-advisory artifact.
func extractFixCommit(store artifact.Store, caseID string) (string, bool) {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", false
	}
	var adv struct {
		FixCommit string `json:"fix_commit"`
	}
	if err := json.Unmarshal(arts[0].Payload, &adv); err != nil {
		return "", false
	}
	return fixCommitID(adv.FixCommit)
}
