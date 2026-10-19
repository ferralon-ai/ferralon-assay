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
	dirs, literal := gradleSettingsDirs(root)
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

var (
	// settingsStringLit is a quoted string with no escape and no interpolation; a backslash or a $
	// leaves the string to the broad fallback, since its end or its value isn't read here.
	settingsStringLit = `(?:"[^"$\\\n]*"|'[^'\\\n]*')`
	// settingsIncludeLit is an include or includeFlat whose arguments start with string literals, in
	// parentheses or not; settingsCallEnds decides whether the literals are the whole call.
	settingsIncludeLit = regexp.MustCompile(`\b(include|includeFlat)(\s*\()?\s*(` + settingsStringLit + `(?:\s*,\s*` + settingsStringLit + `)*)(\s*\))?`)
	// settingsIncludeBuildLit is an includeBuild whose argument starts with a string literal.
	settingsIncludeBuildLit = regexp.MustCompile(`\bincludeBuild(\s*\()?\s*(` + settingsStringLit + `)(\s*\))?`)
	// settingsProjectDirLit is a projectDir set to file() of one string literal.
	settingsProjectDirLit = regexp.MustCompile(`\bprojectDir\s*=\s*file\s*\(\s*(` + settingsStringLit + `)\s*\)`)
	// settingsProjectForm is every keyword that can add a project or move one; each must be one of
	// the literal forms above, or the script is read as naming projects this reader can't see.
	settingsProjectForm = regexp.MustCompile(`\b(?:include|includeFlat|includeBuild|projectDir)\b|\bapply\s*\(?\s*from\b`)
	settingsLitArg      = regexp.MustCompile(settingsStringLit)
)

// gradleSettingsDirs returns every directory root's settings scripts name literally: each project
// on an include path, each includeFlat sibling, each projectDir = file(...) and each includeBuild.
// literal is false when a script can't be read, or names projects in any other form (a variable, an
// interpolated string, an apply from, a path include), since then any directory could be one.
func gradleSettingsDirs(root string) (dirs []string, literal bool) {
	literal = true
	for _, path := range gradleSettingsIn(root) {
		data, err := readRegular(path)
		if err != nil {
			return dirs, false
		}
		src, ok := stripGradleCommentsChecked(string(data))
		if !ok {
			return dirs, false
		}
		matched := 0
		for _, ix := range settingsIncludeLit.FindAllStringSubmatchIndex(src, -1) {
			matched++
			if !settingsCallEnds(src, ix, false) {
				literal = false
				continue
			}
			for _, a := range settingsLitArg.FindAllString(src[ix[6]:ix[7]], -1) {
				name := strings.TrimPrefix(a[1:len(a)-1], ":")
				if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
					literal = false
					continue
				}
				if src[ix[2]:ix[3]] == "includeFlat" {
					dirs = append(dirs, filepath.Join(filepath.Dir(root), name))
					continue
				}
				dir := root
				for _, seg := range strings.Split(name, ":") {
					dir = filepath.Join(dir, seg)
					dirs = append(dirs, dir)
				}
			}
		}
		for _, ix := range settingsIncludeBuildLit.FindAllStringSubmatchIndex(src, -1) {
			matched++
			if !settingsCallEnds(src, ix, true) {
				literal = false
				continue
			}
			dirs = append(dirs, settingsLitDir(root, src[ix[4]:ix[5]]))
		}
		for _, ix := range settingsProjectDirLit.FindAllStringSubmatchIndex(src, -1) {
			matched++
			if !settingsStatementEnds(src[ix[1]:], false) {
				literal = false
				continue
			}
			dirs = append(dirs, settingsLitDir(root, src[ix[2]:ix[3]]))
		}
		if len(settingsProjectForm.FindAllString(src, -1)) != matched {
			literal = false
		}
	}
	return dirs, literal
}

// settingsCallEnds reports whether the call matched at ix (its open-paren group third from last,
// its close-paren group last) is its literals alone: parentheses balanced, then the end of
// the statement. Anything else after the literals (another argument, a +, a method call) means the
// call names more than the literals say. block admits a configuration block after an includeBuild.
func settingsCallEnds(src string, ix []int, block bool) bool {
	n := len(ix)
	open, closed := ix[n-6] >= 0, ix[n-2] >= 0
	return open == closed && settingsStatementEnds(src[ix[1]:], block && closed)
}

// settingsStatementEnds reports whether rest starts at the end of a statement: a newline, a
// semicolon or the end of the script, or a block opening when block is set.
func settingsStatementEnds(rest string, block bool) bool {
	rest = strings.TrimLeft(rest, " \t\r")
	return rest == "" || rest[0] == '\n' || rest[0] == ';' || block && rest[0] == '{'
}

// settingsLitDir is the directory a quoted settings path names, relative to root.
func settingsLitDir(root, lit string) string {
	return filepath.Join(root, filepath.FromSlash(lit[1:len(lit)-1]))
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
