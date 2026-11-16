package plugin

import "strings"

// GoModuleFamily is a Go module path without its major-version suffix: "/vN" (N >= 2), or ".vN"
// for gopkg.in. Every major version of a module shares one family, and each is a package instance of
// its own in a build.
func GoModuleFamily(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 && isGoMajorSuffix(path[i+1:]) {
		return path[:i]
	}
	if strings.HasPrefix(path, "gopkg.in/") {
		if i := strings.LastIndexByte(path, '.'); i >= 0 && isGoMajorSuffix(path[i+1:]) {
			return path[:i]
		}
	}
	return path
}

// isGoMajorSuffix reports whether s is "vN" with N a number of at least 2 and no leading zero.
func isGoMajorSuffix(s string) bool {
	if len(s) < 2 || s[0] != 'v' || s[1] == '0' || s == "v1" {
		return false
	}
	for _, r := range s[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
