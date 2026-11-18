package goanalysis

import (
	"errors"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// modCacheVersion matches the version a module cache path carries ("pkg@v1.2.3/").
var modCacheVersion = regexp.MustCompile(`@v[^/]*/`)

// partialRunNote opens, at the start of a line, the notes the scan appended to a failure about why no
// partial run was made. Everything from the first such line on is note text: a note can itself be a
// govulncheck failure spanning lines.
var partialRunNote = regexp.MustCompile(`(?m)^no partial govulncheck run`)

// FailureText renders err for a report row that cuts it short: the cause first. A govulncheck failure
// reads "govulncheck failed (<build dir>): <cause>: <stderr>", where the build directory is an
// internal temp path and a failed package load's text opens with a header, so a bounded row ends
// before the first compile error. For a failed package load FailureText leads with its first package
// error, the path made relative to the build or to the module cache and the module version dropped,
// then counts the rest; any other failure leads with its cause. The notes the scan added about the
// partial run follow, whole. An error that is no govulncheck failure, and one that wraps one under
// text of its own, is returned as it reads.
func FailureText(err error) string {
	var failed *govulncheckError
	if !errors.As(err, &failed) || error(failed) != err {
		return err.Error()
	}
	stderr, note := failed.stderr, ""
	if loc := partialRunNote.FindStringIndex(stderr); loc != nil {
		stderr, note = stderr[:loc[0]], strings.TrimRight(strings.Join(strings.Fields(stderr[loc[0]:]), " "), ": ")
	}
	var text string
	if perrs := failurePackageErrors(failed); len(perrs) > 0 {
		first := perrs[0]
		first.Pos = shortenPos(first.Pos, failed.buildDir, moduleCacheRoot())
		text = first.Error()
		if more := len(perrs) - 1; more > 0 {
			text += fmt.Sprintf(" (and %d more)", more)
		}
	} else {
		text = fmt.Sprintf("govulncheck failed: %v", failed.cause)
		var lines []string
		for _, line := range strings.Split(stderr, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
		if len(lines) > 0 {
			text += ": " + strings.Join(lines, "; ")
		}
	}
	if note != "" {
		text += "; " + note
	}
	return text
}

// moduleCacheRoot is the module cache of the environment the scan runs in.
func moduleCacheRoot() string {
	if dir := os.Getenv("GOMODCACHE"); dir != "" {
		return dir
	}
	if gopath := filepath.SplitList(build.Default.GOPATH); len(gopath) > 0 {
		return filepath.Join(gopath[0], "pkg", "mod")
	}
	return ""
}

// shortenPos makes the position of a package error relative to the build directory, or to the module
// cache with the module version dropped, which go.mod already names. A path under neither is kept.
func shortenPos(pos, buildDir, modCache string) string {
	pos, buildDir, modCache = canonTemp(pos), canonTemp(buildDir), canonTemp(modCache)
	if buildDir != "" {
		if rest, ok := strings.CutPrefix(pos, strings.TrimSuffix(buildDir, "/")+"/"); ok {
			return rest
		}
	}
	if modCache != "" {
		if rest, ok := strings.CutPrefix(pos, strings.TrimSuffix(modCache, "/")+"/"); ok {
			return modCacheVersion.ReplaceAllString(rest, "/")
		}
	}
	return pos
}

// canonTemp reads /private/tmp and /private/var as /tmp and /var, one directory each on macOS, where
// a build directory and the paths the toolchain prints for it can name the same place either way.
func canonTemp(p string) string {
	for _, dir := range []string{"/private/tmp/", "/private/var/"} {
		if strings.HasPrefix(p, dir) {
			return strings.TrimPrefix(p, "/private")
		}
	}
	return p
}
