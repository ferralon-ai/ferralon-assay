package javaanalysis

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// GradleLockEntry is one gradle.lockfile line, unmerged: the coordinate, the version exactly as
// written ("" when the line names none) and the configurations it is locked in.
type GradleLockEntry struct {
	Group, Artifact, Version string
	Configs                  []string
}

// GradleLockEntries returns every coordinate line of every lockfile readLockfiles reads, in file
// then line order, without merging: a coordinate locked at different versions in different
// configurations (or files) appears once per line. A line whose coordinate names a group and
// artifact but no version is kept with Version "". ok is false when no lockfile exists.
//
// readLockfiles keeps one version per group:artifact for the inventory's node set; a consumer that
// must know which version a particular configuration selected reads these instead.
func GradleLockEntries(root string) (entries []GradleLockEntry, ok bool) {
	var files []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if name := d.Name(); name == "gradle.lockfile" || strings.HasSuffix(name, ".lockfile") {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
				continue
			}
			coord, configs, ok := splitLockLine(line)
			if !ok {
				continue
			}
			parts := strings.Split(coord, ":")
			if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
				continue
			}
			e := GradleLockEntry{Group: parts[0], Artifact: parts[1], Configs: configs}
			if len(parts) > 2 {
				e.Version = parts[2]
			}
			entries = append(entries, e)
		}
	}
	return entries, len(files) > 0
}
