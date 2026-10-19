package javaanalysis

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The reasons unwalkedBuild returns: a Gradle build buildFiles doesn't read, and a directory
// symlink out of the build dir, which could hold any build file.
const (
	reasonGradleProjectUnwalked = plugin.PartialReasonToolFailure + ":gradle_project_unwalked"
	reasonSymlinkOutOfBuildDir  = plugin.PartialReasonToolFailure + ":symlink_out_of_build_dir"
)

// unwalkedBuild returns the reason root's inventory is incomplete because buildFiles doesn't read
// part of the build, or "" when it reads all of it. buildFiles skips output, VCS and dot
// directories and doesn't follow symlinks, so the inventory is incomplete when:
//   - a skipped directory has a build or settings script directly in it;
//   - a directory a root settings script names (an include, a projectDir = file(...), an
//     includeBuild, an includeFlat) has a script and wasn't walked, as when it lies outside root;
//   - a root settings script names a directory by an absolute path;
//   - a settings script names projects in a form this reader can't read literally, and any
//     skipped subtree holds a script;
//   - a symlink resolves to a directory outside root.
//
// A skipped directory with no script in reach stays skipped, so a Maven target/ or a
// node_modules holding Android builds doesn't make every inventory incomplete.
func unwalkedBuild(root string) string {
	root = filepath.Clean(root)
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return reasonGradleProjectUnwalked
	}
	walked := map[string]bool{}
	var skipped []string
	reason := ""
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // a listing error is buildFiles's to report.
		}
		switch {
		case d.IsDir() && path != root && skipDir(d.Name()):
			if len(gradleScriptsIn(path))+len(gradleSettingsIn(path)) > 0 {
				reason = reasonGradleProjectUnwalked
				return filepath.SkipAll
			}
			skipped = append(skipped, path)
			return filepath.SkipDir
		case d.IsDir():
			walked[path] = true
		case d.Type()&fs.ModeSymlink != 0 && symlinkLeaves(realRoot, path):
			reason = reasonSymlinkOutOfBuildDir
			return filepath.SkipAll
		}
		return nil
	})
	if reason != "" {
		return reason
	}
	dirs, literal, absolute := gradleSettingsDirs(root)
	if absolute {
		return reasonGradleProjectUnwalked
	}
	for _, dir := range dirs {
		if !walked[dir] && len(gradleScriptsIn(dir))+len(gradleSettingsIn(dir)) > 0 {
			return reasonGradleProjectUnwalked
		}
	}
	if !literal {
		for _, dir := range skipped {
			if holdsGradleScript(dir) {
				return reasonGradleProjectUnwalked
			}
		}
	}
	return ""
}

// The settings allow-list. A settings script is read as literal only when every non-blank line,
// comments stripped, is one of these forms in its block; any other line, anywhere, sends the build to
// the broad fallback. A string literal holds no quote, backslash or $, so its end and its value are
// what the text says.
//
// stripGradleCommentsChecked doesn't know Groovy triple-quoted or slashy strings, or string
// templates, and can strip real code inside one. That fails closed only because whatever it leaves
// keeps a """, a / outside a literal, or a $, and no allowed form accepts any of those outside a
// literal; keep it that way.
const settingsLit = `(?:"[^"$\\\n]*"|'[^'$\\\n]*')`

// settingsFilterLit is a repository content-filter argument: a regex may carry backslashes, and only
// filters which artifacts a repository serves.
const settingsFilterLit = `(?:"[^"$\n]*"|'[^'$\n]*')`

var (
	settingsRootLine      = regexp.MustCompile(`^rootProject\.name\s*=\s*` + settingsLit + `$`)
	settingsIncludeLine   = regexp.MustCompile(`^(include|includeFlat)\s*(\(?)\s*(` + settingsLit + `(?:\s*,\s*` + settingsLit + `)*)?\s*(,?)\s*(\)?)$`)
	settingsIncludeMore   = regexp.MustCompile(`^(` + settingsLit + `(?:\s*,\s*` + settingsLit + `)*)?\s*(,?)\s*(\)?)$`)
	settingsIncludeBuild  = regexp.MustCompile(`^includeBuild\s*(?:\(\s*(` + settingsLit + `)\s*\)|(` + settingsLit + `))\s*(\{?)$`)
	settingsProjectDir    = regexp.MustCompile(`^project\s*\(\s*` + settingsLit + `\s*\)\s*\.\s*projectDir\s*=\s*file\s*\(\s*(` + settingsLit + `)\s*\)$`)
	settingsFeature       = regexp.MustCompile(`^enableFeaturePreview\s*\(\s*` + settingsLit + `\s*\)$`)
	settingsBlock         = regexp.MustCompile(`^([A-Za-z]+)\s*\{$`)
	settingsRepo          = regexp.MustCompile(`^(?:google|mavenCentral|gradlePluginPortal|mavenLocal)\s*\(\s*\)$|^maven\s*\(\s*` + settingsLit + `\s*\)$|^maven\s*\{\s*url\s*(?:=\s*)?(?:uri\s*\(\s*` + settingsLit + `\s*\)|` + settingsLit + `)\s*\}$`)
	settingsMavenLine     = regexp.MustCompile(`^(?:url|name)\s*(?:=\s*)?(?:uri\s*\(\s*` + settingsLit + `\s*\)|` + settingsLit + `)$`)
	settingsContentFilter = regexp.MustCompile(`^(?:include|exclude)(?:Group|GroupByRegex|GroupAndSubgroups|Module|ModuleByRegex|Version|VersionByRegex)\s*\(?\s*` + settingsFilterLit + `(?:\s*,\s*` + settingsFilterLit + `)*\s*\)?$`)
	settingsReposMode     = regexp.MustCompile(`^repositoriesMode\s*(?:\.\s*set\s*\(\s*RepositoriesMode\.[A-Z_]+\s*\)|=\s*RepositoriesMode\.[A-Z_]+)$`)
	settingsPluginLine    = regexp.MustCompile(`^(?:id\s*\(\s*(` + settingsLit + `)\s*\)|id\s+(` + settingsLit + `)|kotlin\s*\(\s*` + settingsLit + `\s*\))(?:\s+version\s+` + settingsLit + `)?(?:\s+apply\s+false)?$`)
	settingsIncludeName   = regexp.MustCompile(settingsLit)

	// The named-directory forms, matched anywhere in a script, literal or not.
	settingsAnyInclude = regexp.MustCompile(`\b(include|includeFlat)\b\s*\(?\s*(` + settingsLit + `(?:\s*,\s*` + settingsLit + `)*)`)
	settingsAnyPath    = regexp.MustCompile(`\b(?:includeBuild|file)\s*\(?\s*(` + settingsLit + `)`)
)

// settingsPlugins are the settings plugins a literal settings script may apply; each configures
// toolchains or build scans and adds no project.
var settingsPlugins = map[string]bool{
	"org.gradle.toolchains.foojay-resolver-convention": true,
	"org.gradle.toolchains.foojay-resolver":            true,
	"com.gradle.enterprise":                            true,
	"com.gradle.develocity":                            true,
	"com.gradle.common-custom-user-data-gradle-plugin": true,
}

// settingsBlocks maps each block a literal settings script may open, by the block it sits in, to
// the block it opens. A block not listed here is not literal.
var settingsBlocks = map[string]map[string]string{
	"":                               {"pluginManagement": "pluginManagement", "dependencyResolutionManagement": "dependencyResolutionManagement", "plugins": "settingsPlugins"},
	"pluginManagement":               {"repositories": "repositories", "plugins": "managedPlugins"},
	"dependencyResolutionManagement": {"repositories": "repositories"},
	"repositories":                   {"google": "repository", "mavenCentral": "repository", "gradlePluginPortal": "repository", "maven": "maven"},
	"repository":                     {"content": "content"},
	"maven":                          {"content": "content"},
}

// gradleSettingsDirs returns every directory root's settings scripts name: each project on an
// include path, each includeFlat sibling, each file(...) and each includeBuild, wherever in a script
// it appears. literal is false when a script can't be read, or holds any line outside the settings
// allow-list, since then any directory could be a project. absolute is true when a script names a
// path by an absolute path.
func gradleSettingsDirs(root string) (dirs []string, literal, absolute bool) {
	literal = true
	for _, path := range gradleSettingsIn(root) {
		data, err := readRegular(path)
		if err != nil {
			literal = false
			continue
		}
		src, ok := stripGradleCommentsChecked(string(data))
		if !ok {
			literal, src = false, string(data)
		}
		named, abs := settingsNamedDirs(root, src)
		dirs = append(dirs, named...)
		absolute = absolute || abs
		named, ok = settingsLiteralDirs(root, src)
		dirs = append(dirs, named...)
		literal = literal && ok
	}
	return dirs, literal, absolute
}

// settingsNamedDirs returns every directory src names through an include, includeFlat,
// includeBuild or file(...) with string-literal arguments, wherever it appears, and whether any of
// those paths is absolute.
func settingsNamedDirs(root, src string) (dirs []string, absolute bool) {
	for _, m := range settingsAnyInclude.FindAllStringSubmatch(src, -1) {
		named, _ := settingsIncludeDirs(root, m[2], m[1] == "includeFlat")
		dirs = append(dirs, named...)
	}
	for _, m := range settingsAnyPath.FindAllStringSubmatch(src, -1) {
		absolute = absolute || settingsAbsolute(settingsUnquote(m[1]))
		dirs = append(dirs, settingsLitDir(root, m[1]))
	}
	return dirs, absolute
}

// settingsIncludeDirs returns the directories an include or includeFlat argument list names, and
// false when a name is empty or holds a path.
func settingsIncludeDirs(root, list string, flat bool) (dirs []string, ok bool) {
	ok = true
	for _, a := range settingsIncludeName.FindAllString(list, -1) {
		name := strings.TrimPrefix(settingsUnquote(a), ":")
		if name == "" || strings.ContainsAny(name, "/") || strings.Contains(name, "..") {
			ok = false
			continue
		}
		if flat {
			dirs = append(dirs, filepath.Join(filepath.Dir(root), name))
			continue
		}
		dir := root
		for _, seg := range strings.Split(name, ":") {
			dir = filepath.Join(dir, seg)
			dirs = append(dirs, dir)
		}
	}
	return dirs, ok
}

// settingsLiteralDirs reads src line by line against the settings allow-list, returning the
// directories it names and whether every line is allowed.
func settingsLiteralDirs(root, src string) (dirs []string, ok bool) {
	var (
		stack []string // the blocks open around the current line
		cont  string   // "(" or "," while an include's arguments continue on the next line
		flat  bool     // the continuing include is an includeFlat
	)
	in := func() string {
		if len(stack) == 0 {
			return ""
		}
		return stack[len(stack)-1]
	}
	include := func(list string, isFlat bool) bool {
		named, ok := settingsIncludeDirs(root, list, isFlat)
		dirs = append(dirs, named...)
		return ok
	}
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		if line == "" {
			continue
		}
		if cont != "" {
			m := settingsIncludeMore.FindStringSubmatch(line)
			if m == nil || !include(m[1], flat) {
				return dirs, false
			}
			switch {
			case cont == "(" && m[3] == ")":
				cont = ""
			case cont == "," && m[3] == ")":
				return dirs, false
			case cont == "," && m[2] == "":
				cont = ""
			}
			continue
		}
		if line == "}" {
			if len(stack) == 0 {
				return dirs, false
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if m := settingsBlock.FindStringSubmatch(line); m != nil {
			next, allowed := settingsBlocks[in()][m[1]]
			if !allowed {
				return dirs, false
			}
			stack = append(stack, next)
			continue
		}
		switch in() {
		case "":
			if m := settingsIncludeLine.FindStringSubmatch(line); m != nil {
				if !include(m[3], m[1] == "includeFlat") {
					return dirs, false
				}
				switch {
				case m[2] == "(" && m[5] == "":
					cont, flat = "(", m[1] == "includeFlat"
				case m[2] == "" && m[5] == ")":
					return dirs, false
				case m[2] == "" && m[4] == ",":
					cont, flat = ",", m[1] == "includeFlat"
				case m[3] == "":
					return dirs, false
				}
				continue
			}
			if m := settingsProjectDir.FindStringSubmatch(line); m != nil {
				dirs = append(dirs, settingsLitDir(root, m[1]))
				continue
			}
			if settingsRootLine.MatchString(line) || settingsFeature.MatchString(line) {
				continue
			}
			fallthrough
		case "pluginManagement":
			if m := settingsIncludeBuild.FindStringSubmatch(line); m != nil {
				dirs = append(dirs, settingsLitDir(root, m[1]+m[2]))
				if m[3] == "{" {
					stack = append(stack, "includedBuild")
				}
				continue
			}
		case "dependencyResolutionManagement":
			if settingsReposMode.MatchString(line) {
				continue
			}
		case "repositories":
			if settingsRepo.MatchString(line) {
				continue
			}
		case "maven":
			if settingsMavenLine.MatchString(line) {
				continue
			}
		case "content":
			if settingsContentFilter.MatchString(line) {
				continue
			}
		case "includedBuild":
			if strings.HasPrefix(line, "name") && settingsMavenLine.MatchString(line) {
				continue
			}
		case "managedPlugins":
			if settingsPluginLine.MatchString(line) {
				continue
			}
		case "settingsPlugins":
			if m := settingsPluginLine.FindStringSubmatch(line); m != nil && settingsPlugins[settingsUnquote(m[1]+m[2])] {
				continue
			}
		}
		return dirs, false
	}
	return dirs, cont == "" && len(stack) == 0
}

// settingsUnquote strips the quotes from a settings string literal, or returns "" for no literal.
func settingsUnquote(lit string) string {
	if len(lit) < 2 {
		return ""
	}
	return lit[1 : len(lit)-1]
}

// settingsLitDir is the directory a quoted settings path names: relative to root, or as written
// when absolute.
func settingsLitDir(root, lit string) string {
	path := filepath.FromSlash(settingsUnquote(lit))
	if settingsAbsolute(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(root, path)
}

// settingsAbsolute reports whether a settings path is absolute on any platform Gradle runs on.
func settingsAbsolute(path string) bool {
	return filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) ||
		len(path) >= 2 && path[1] == ':' && ('A' <= path[0] && path[0] <= 'Z' || 'a' <= path[0] && path[0] <= 'z')
}

// holdsGradleScript reports whether a build or settings script sits anywhere under dir, or dir
// can't be walked in full.
func holdsGradleScript(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			found = true
			return filepath.SkipAll
		}
		switch d.Name() {
		case "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts":
			if !d.IsDir() {
				found = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found
}

// outside reports whether dir lies outside root.
func outside(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// symlinkLeaves reports whether the link at path resolves to a directory outside realRoot, or
// can't be resolved for a reason other than its target being absent.
func symlinkLeaves(realRoot, path string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return !missing(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return !missing(err)
	}
	return info.IsDir() && outside(realRoot, target)
}
