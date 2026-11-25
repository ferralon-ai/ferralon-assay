package jsanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
)

// LaunchDigest is a sha256 over the launch surface the lane reads in the first-party tree at
// root: every text launchTexts returns, keyed by its origin, and every reason that walk vetoes
// on. A tree whose digest is unchanged gives the lane the same texts to infer entry points from.
// "" when root is "" or holds no first-party package.json, where the lane has no project.
func LaunchDigest(root string) string {
	if root == "" {
		return ""
	}
	prog := &program{root: root}
	if len(firstPartyManifests(prog, newLoadRecord())) == 0 {
		return ""
	}
	lr := newLoadRecord()
	texts := launchTexts(prog, lr)
	h := sha256.New()
	for _, t := range texts {
		fmt.Fprintf(h, "text %d:%s %d:%s\n", len(t.origin), t.origin, len(t.text), t.text)
	}
	for _, why := range slices.Sorted(maps.Keys(lr.vetoes)) {
		fmt.Fprintf(h, "veto %d:%s\n", len(why), why)
	}
	return hex.EncodeToString(h.Sum(nil))
}
