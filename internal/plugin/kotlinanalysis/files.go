package kotlinanalysis

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// files.go — package-local source/build-output walk helpers, the Kotlin analogue of
// javaanalysis's javaFiles/skipDir. Kotlin SOURCE (.kt/.kts) is not what the analyzer
// reads for reachability (that is bytecode — see buildoutput.go); these helpers exist for
// detection-adjacent uses and to prune the same non-application trees consistently.

// kotlinExtensions are the Kotlin source suffixes: implementation (.kt) and Gradle/Kotlin
// script (.kts).
var kotlinExtensions = []string{".kt", ".kts"}

// isKotlinSource reports whether a filename is a Kotlin source file (.kt or .kts).
func isKotlinSource(name string) bool {
	for _, ext := range kotlinExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// kotlinFiles returns every .kt/.kts file under root, pruning the same build-output / VCS /
// dependency trees javaanalysis prunes so generated or vendored files never skew a walk.
// The list is sorted for deterministic iteration.
func kotlinFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if isKotlinSource(d.Name()) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// skipDir reports whether a directory is excluded from a source walk. It mirrors
// javaanalysis.skipDir verbatim — build output, VCS, caches, node_modules, and any hidden
// dir — so the Kotlin and Java walks agree on what "application source" means.
func skipDir(name string) bool {
	switch name {
	case "target", "build", "out", "bin", ".git", ".gradle", "node_modules":
		return true
	}
	return strings.HasPrefix(name, ".")
}
