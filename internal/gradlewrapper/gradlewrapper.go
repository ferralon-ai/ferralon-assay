// Package gradlewrapper decides whether a Gradle build's wrapper fetches Gradle's own
// distribution, for the readers that must not trust a build that can run its own init scripts.
package gradlewrapper

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
// set the version.
func StockGradleWrapper(buildDir string) bool {
	path := filepath.Join(buildDir, "gradle", "wrapper", "gradle-wrapper.properties")
	data, err := os.ReadFile(path)
	if err != nil {
		return absent(path)
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

// absent reports whether nothing exists at path; an error other than not-exist counts as present.
func absent(path string) bool {
	_, err := os.Lstat(path)
	return os.IsNotExist(err)
}
