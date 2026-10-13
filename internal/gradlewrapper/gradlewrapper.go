// Package gradlewrapper decides whether a Gradle build's wrapper fetches Gradle's own
// distribution, for the readers that must not trust a build that can run its own init scripts.
package gradlewrapper

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var (
	gradleStockDist = regexp.MustCompile(`^https://services\.gradle\.org/distributions/gradle-[0-9][0-9A-Za-z.-]*-(bin|all)\.zip$`)
	// gradleWrapperLine is the only shape a property line may take: a key gradle init writes, an
	// "=" right after it, and a value with no whitespace and no backslash other than \: or \=.
	gradleWrapperLine = regexp.MustCompile(`^(distributionBase|distributionPath|distributionUrl|distributionSha256Sum|zipStoreBase|zipStorePath|networkTimeout|validateDistributionUrl)=((?:[^\\\s]|\\[:=])*)$`)
	gradleStorePath   = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
)

// StockGradleWrapper reports whether the wrapper, when there is one, fetches a distribution from
// services.gradle.org into the Gradle user home; a custom distribution can carry init scripts that
// set the version. Properties that are present but not a regular file this reader can open are
// not stock; the open does not block, so a FIFO in their place fails rather than hangs.
func StockGradleWrapper(buildDir string) bool {
	path := filepath.Join(buildDir, "gradle", "wrapper", "gradle-wrapper.properties")
	data, missing, err := readRegular(path)
	if missing {
		return true
	}
	if err != nil {
		return false
	}
	props, ok := stockWrapperProperties(string(data))
	if !ok {
		return false
	}
	for _, base := range []string{"distributionBase", "zipStoreBase"} {
		if v, set := props[base]; set && v != "GRADLE_USER_HOME" {
			return false
		}
	}
	for _, p := range []string{"distributionPath", "zipStorePath"} {
		if v, set := props[p]; set && !storePathWithinHome(v) {
			return false
		}
	}
	url, set := props["distributionUrl"]
	return set && gradleStockDist.MatchString(url)
}

// stockWrapperProperties reads the wrapper properties default-deny. The wrapper loads them with
// java.util.Properties, where whitespace or ":" also separates a key, escapes apply in keys and
// values, a trailing backslash continues a line, a lone CR ends one, and the last of a repeated
// key wins. So every line that isn't blank or a "#"/"!" comment must be key=value exactly
// (gradleWrapperLine), no backslash may appear but \: or \= in a value, a CR may only end a CRLF,
// and no key may repeat. Anything else is not read as stock. Values come back unescaped.
func stockWrapperProperties(data string) (map[string]string, bool) {
	data = strings.ReplaceAll(data, "\r\n", "\n")
	if strings.Contains(data, "\r") {
		return nil, false
	}
	if strings.Contains(strings.NewReplacer(`\:`, "", `\=`, "").Replace(data), `\`) {
		return nil, false
	}
	props := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		m := gradleWrapperLine.FindStringSubmatch(line)
		if m == nil {
			return nil, false
		}
		if _, dup := props[m[1]]; dup {
			return nil, false
		}
		props[m[1]] = strings.NewReplacer(`\:`, ":", `\=`, "=").Replace(m[2])
	}
	return props, true
}

// storePathWithinHome reports whether a distributionPath or zipStorePath stays under the Gradle
// user home it is resolved against: relative, with no ".." segment that could reach the checkout.
func storePathWithinHome(p string) bool {
	if !gradleStorePath.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return false
		}
	}
	return true
}

var errNotRegular = errors.New("not a regular file")

// readRegular reads path only when it is a regular file: checked with Lstat before the open, so
// a symlink is refused, and again on the open descriptor, so what is read is what was checked.
// The open is non-blocking, so a FIFO swapped in after the Lstat fails the second check rather
// than hanging the open. missing is true only when the Lstat finds nothing at path; any other
// failure is an error, and the file counts as present.
func readRegular(path string) (data []byte, missing bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, os.IsNotExist(err), err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errNotRegular
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	if info, err = f.Stat(); err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errNotRegular
	}
	data, err = io.ReadAll(f)
	return data, false, err
}
