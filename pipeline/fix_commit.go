package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

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
// object, so the answer comes from the objects the checkout already holds. Replacement objects are
// ignored, since one can rewrite the parents the ancestry walk follows.
func fixCommitGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(gitRepositoryEnv, name)
	}), "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL=", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1")
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// headContainsCommit reports whether commit is HEAD or one of its ancestors in the repository
// containing dir. It is true only on a positive answer from a complete history: a shallow
// repository, a commit the object store does not hold, and any git failure all read as false,
// which says the question went unanswered and never that the commit is missing from the history.
func headContainsCommit(ctx context.Context, dir, commit string) bool {
	if dir == "" || !fullCommitID.MatchString(commit) {
		return false
	}
	if shallow, err := fixCommitGit(ctx, dir, "rev-parse", "--is-shallow-repository"); err != nil || shallow != "false" {
		return false
	}
	if _, err := fixCommitGit(ctx, dir, "cat-file", "-e", commit+"^{commit}"); err != nil {
		return false
	}
	_, err := fixCommitGit(ctx, dir, "merge-base", "--is-ancestor", commit, "HEAD")
	return err == nil
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
//     axis requires: the project's fix says nothing about a dependency.
//
// inHistory is asked last and only when the rest holds.
func fixCommitClears(rngs []affectedRange, rangeKnown bool, versions []string, others []presentRanges, inHistory func() bool) bool {
	if !rangeKnown || len(rngs) == 0 || len(versions) > 0 {
		return false
	}
	for _, r := range rngs {
		if r.UpperExclusive == "" {
			return false
		}
	}
	for _, o := range others {
		if !everyVersionOutside(o.Versions, o.Complete, o.Ranges, o.RangeKnown) {
			return false
		}
	}
	return inHistory()
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
	mod := goModFileModule(filepath.Join(buildDir, "go.mod"))
	advModule, ok := extractAdvisoryModule(store, caseID)
	return ok && mod != "" && goPathOwner(buildDir, ws, mod, advModule) == goOwnedByRoot
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
