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
	gradleDistURL   = regexp.MustCompile(`(?m)^[ \t\f]*distributionUrl[ \t\f]*[=:][ \t\f]*(.*?)[ \t\f\r]*$`)
)

// StockGradleWrapper reports whether the wrapper, when there is one, fetches a distribution from
// services.gradle.org; a custom distribution can carry init scripts that set the version.
func StockGradleWrapper(buildDir string) bool {
	path := filepath.Join(buildDir, "gradle", "wrapper", "gradle-wrapper.properties")
	data, err := os.ReadFile(path)
	if err != nil {
		return absent(path)
	}
	urls := gradleDistURL.FindAllStringSubmatch(string(data), -1)
	if len(urls) != 1 {
		return false
	}
	return gradleStockDist.MatchString(strings.NewReplacer(`\:`, ":", `\=`, "=").Replace(urls[0][1]))
}

// absent reports whether nothing exists at path; an error other than not-exist counts as present.
func absent(path string) bool {
	_, err := os.Lstat(path)
	return os.IsNotExist(err)
}
