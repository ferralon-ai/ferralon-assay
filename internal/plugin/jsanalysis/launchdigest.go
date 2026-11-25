package jsanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
)

// LaunchDigest is a sha256 over the launch surface the lane reads in the first-party tree at
// root: every text firstPartyLaunchTexts returns, keyed by its origin, and every reason that walk
// vetoes on. A tree whose digest is unchanged gives the lane the same texts to infer entry points
// from. "" when root is "" or the lane has no project there: no first-party package.json and no
// lockfile it reads.
func LaunchDigest(root string) string {
	if root == "" {
		return ""
	}
	roots, read := discoverProjectRoots(root)
	return launchDigest(root, len(roots) > 0 || !read)
}

// launchDigest is LaunchDigest for a caller that has already looked for project roots: project
// reports whether it found one, or could not read the whole tree.
func launchDigest(root string, project bool) string {
	prog := &program{root: root}
	if !project && len(firstPartyManifests(prog, newLoadRecord())) == 0 {
		return ""
	}
	lr := newLoadRecord()
	texts := firstPartyLaunchTexts(prog, lr)
	h := sha256.New()
	for _, t := range texts {
		fmt.Fprintf(h, "text %d:%s %d:%s\n", len(t.origin), t.origin, len(t.text), t.text)
	}
	for _, why := range slices.Sorted(maps.Keys(lr.vetoes)) {
		fmt.Fprintf(h, "veto %d:%s\n", len(why), why)
	}
	return hex.EncodeToString(h.Sum(nil))
}
