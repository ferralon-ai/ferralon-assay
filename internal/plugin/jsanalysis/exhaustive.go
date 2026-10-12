package jsanalysis

// Exhaustiveness of the advisory-path dependency set (plugin.DependencyVersionResult.Exhaustive).
//
// Exhaustive claims that an npm package absent from All is provably not installed by this
// build, which lets the pipeline's intake guard disqualify an advisory for a package the
// codebase does not have. package-lock.json / npm-shrinkwrap.json, yarn.lock and pnpm-lock.yaml
// each record the full resolved tree, so the claim is made against them, and only when:
//
//   - at least one lockfile exists and every lockfile parsed;
//   - every package.json sits in the directory subtree of some lockfile (no sibling project the
//     locks do not govern);
//   - every name a package.json declares in dependencies, devDependencies,
//     optionalDependencies or peerDependencies appears in some lockfile (the lock is not stale
//     or partial). Peers are included because a peer the lock does not install is still
//     expected present at runtime (the host provides it), so its absence here proves nothing;
//   - the coordinate is not the name of any package.json under the build dir: a lockfile does
//     not list the project (or a workspace package) as its own dependency, so its absence from
//     the lock proves nothing about a first-party advisory.
//
// The lockfile "dev"/"optional" flags are never consulted: every locked package counts as
// present whatever its flags say.
//
// The direct-name cross-check also bounds the lexical yarn/pnpm readers: a dialect they
// misread drops declared names and so fails open. Anything else fails open.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

var lockedDependencyFields = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// exhaustiveLockSet reports whether the parsed lockfiles enumerate every installable package
// for every package.json under root.
func exhaustiveLockSet(root, coordinate string, locks []string, all []plugin.ResolvedDependency, parseFailed bool) bool {
	if parseFailed || len(locks) == 0 {
		return false
	}
	lockDirs := make([]string, 0, len(locks))
	for _, l := range locks {
		lockDirs = append(lockDirs, filepath.Dir(l))
	}
	locked := make(map[string]bool, len(all))
	for _, d := range all {
		locked[normalizeNPMCoordinate(d.Coordinate)] = true
	}
	exhaustive := true
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			exhaustive = false
			return filepath.SkipAll
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		if !underAnyDir(filepath.Dir(path), lockDirs) || !declaredNamesLocked(path, coordinate, locked) {
			exhaustive = false
			return filepath.SkipAll
		}
		return nil
	})
	return exhaustive
}

// declaredNamesLocked reports whether every dependency a package.json declares (in the fields
// a lockfile records) appears in locked, and that the package.json does not itself define the
// coordinate. An unreadable or malformed package.json is not covered.
func declaredNamesLocked(path, coordinate string, locked map[string]bool) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil {
		return false
	}
	if raw, ok := manifest["name"]; ok {
		var name string
		if json.Unmarshal(raw, &name) != nil || normalizeNPMCoordinate(name) == normalizeNPMCoordinate(coordinate) {
			return false
		}
	}
	for _, field := range lockedDependencyFields {
		raw, ok := manifest[field]
		if !ok {
			continue
		}
		var deps map[string]string
		if json.Unmarshal(raw, &deps) != nil {
			return false
		}
		for name := range deps {
			if !locked[normalizeNPMCoordinate(name)] {
				return false
			}
		}
	}
	return true
}

// underAnyDir reports whether dir is one of roots or nested beneath one.
func underAnyDir(dir string, roots []string) bool {
	for _, r := range roots {
		rel, err := filepath.Rel(r, dir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
