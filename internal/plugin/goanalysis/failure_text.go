package goanalysis

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// govulncheckLoadHeader matches the lines govulncheck heads a failed package load's errors with; they
// name no cause.
var govulncheckLoadHeader = regexp.MustCompile(`^(govulncheck: loading packages:?|There are errors with the provided package patterns:?)\s*$`)

// modCacheVersion matches the version a module cache path carries ("pkg@v1.2.3/").
var modCacheVersion = regexp.MustCompile(`@v[^/]*/`)

// FailureText renders err for a report row that cuts it short: the cause first. A govulncheck failure
// reads "govulncheck failed (<build dir>): <exit>: <stderr>", where the build directory is an
// internal temp path and the stderr opens with a header, so a bounded row ends before the first
// compile error. FailureText leads with that error, its path made relative to the build or to the
// module cache and its module version dropped, then counts the rest, then repeats the notes the scan
// added about the partial run. Any other error, and one that wraps a govulncheck failure under text of its own, is returned as it reads.
func FailureText(err error) string {
	var failed *govulncheckError
	if !errors.As(err, &failed) || error(failed) != err {
		return err.Error()
	}
	var causes, notes []string
	for _, line := range strings.Split(failed.stderr, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || govulncheckLoadHeader.MatchString(line):
		case strings.HasPrefix(line, "no partial govulncheck run"):
			notes = append(notes, line)
		default:
			causes = append(causes, line)
		}
	}
	text := fmt.Sprintf("govulncheck failed: %v", failed.cause)
	if len(causes) > 0 {
		text = shortenPath(causes[0], failed.buildDir)
		if more := len(causes) - 1; more > 0 {
			text += fmt.Sprintf(" (and %d more)", more)
		}
	}
	return strings.Join(append([]string{text}, notes...), "; ")
}

// shortenPath drops from line the build directory and the module cache prefix of the path it opens
// with, and the module version in it, which go.mod already names.
func shortenPath(line, buildDir string) string {
	line = strings.TrimPrefix(line, strings.TrimSuffix(buildDir, "/")+"/")
	if _, rest, ok := strings.Cut(line, "/pkg/mod/"); ok && strings.HasPrefix(line, "/") {
		line = rest
	}
	return modCacheVersion.ReplaceAllString(line, "/")
}
