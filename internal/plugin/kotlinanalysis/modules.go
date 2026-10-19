package kotlinanalysis

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// modules.go — detect a multi-project build. Reachability traces one program: the build
// root's output, closure and entry points. A Gradle multi-project or Maven reactor build keeps
// each further module's code under its own directory (app/build/classes/..., web/target/
// classes), so tracing the root alone could clear a sink an untraced module calls. Such builds
// are not supported yet: they are detected and declared, and no sink is cleared.

// partialReasonMultipleProjects is declared when the build has more than one project with
// code. did_not_run by the classifier (an unlisted reason).
const partialReasonMultipleProjects = "multiple_projects_unsupported"

// projectScanDepth bounds how deep below the build root another project is looked for.
const projectScanDepth = 6

// projectSkipDirs are never project directories, nor contain them: build output, caches,
// sources and Gradle's build-logic project (build code, not runtime code).
var projectSkipDirs = map[string]bool{
	"build": true, "target": true, "out": true, "src": true, "node_modules": true, "buildSrc": true,
}

var buildFileNames = []string{"build.gradle", "build.gradle.kts", "pom.xml"}

var (
	// include("a", ":b:c") may span lines; the Groovy form `include 'a', 'b'` does not.
	settingsIncludeCall  = regexp.MustCompile(`(?s)\binclude\s*\(([^)]*)\)`)
	settingsIncludeLine  = regexp.MustCompile(`(?m)\binclude\s+([^(\n].*)$`)
	settingsIncludeBuild = regexp.MustCompile(`\bincludeBuild\b`)
	pomModule            = regexp.MustCompile(`<module>\s*[^<\s]`)
)

// otherProjects returns evidence of projects in buildDir besides the root: a Gradle settings
// include or includeBuild, a Maven <module>, or a directory below the root holding code (a src
// tree or build output) next to a build file, or build output on its own. Empty means a
// single-project build.
func otherProjects(buildDir string) []string {
	var evidence []string
	for _, name := range []string{"settings.gradle", "settings.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(buildDir, name))
		if err != nil {
			continue
		}
		text := stripBuildComments(string(data))
		if settingsIncludeBuild.MatchString(text) {
			evidence = append(evidence, name+": includeBuild")
		}
		if settingsIncludeCall.MatchString(text) || settingsIncludeLine.MatchString(text) {
			evidence = append(evidence, name+": include")
		}
	}
	if data, err := os.ReadFile(filepath.Join(buildDir, "pom.xml")); err == nil {
		if pomModule.MatchString(stripXMLComments(string(data))) {
			evidence = append(evidence, "pom.xml: <modules>")
		}
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > projectScanDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || strings.HasPrefix(name, ".") || projectSkipDirs[name] {
				continue
			}
			sub := filepath.Join(dir, name)
			if projectWithCode(sub) {
				rel, _ := filepath.Rel(buildDir, sub)
				evidence = append(evidence, rel)
			}
			walk(sub, depth+1)
		}
	}
	walk(buildDir, 1)
	return evidence
}

// projectWithCode reports whether dir has build output, or a build file next to a src tree.
func projectWithCode(dir string) bool {
	for _, rel := range append([]string{firstPartyJarDir}, firstPartyClassRoots...) {
		if isDir(filepath.Join(dir, rel)) {
			return true
		}
	}
	if !isDir(filepath.Join(dir, "src")) {
		return false
	}
	for _, n := range buildFileNames {
		if fileExists(filepath.Join(dir, n)) {
			return true
		}
	}
	return false
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// stripBuildComments removes // line comments and /* */ block comments, so a commented-out
// include is not read as one.
func stripBuildComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case strings.HasPrefix(s[i:], "//"):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
		case strings.HasPrefix(s[i:], "/*"):
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 3
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

var xmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

func stripXMLComments(s string) string { return xmlComment.ReplaceAllString(s, "") }
