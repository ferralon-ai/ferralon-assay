package javaanalysis

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reasonMultipleProjectsUnsupported marks a build with more than one Maven module or Gradle
// project with code. The dependency-JAR analysis binds one module's view of the dependency
// graph; with several modules that view does not stand for the build, so the result is
// partial run-wide and no sink is ever reported Searched for it.
const reasonMultipleProjectsUnsupported = "multiple_projects_unsupported"

// multipleProjects reports whether buildDir holds more than one project. The recognizer is
// inverted: anything that can name a second project counts unless it is read in full and names
// none. Maven: a POM that lists <modules>, in any profile too, or more than one pom.xml. Gradle:
// a root settings script that includes more than one project, or one beside root code, or that
// includes a build, or that cannot be read; a settings script below the root; or more than one
// build script beside a src directory. The walk enters every directory but VCS metadata,
// installed-package trees and the local dependency caches, since a project in bin/ or a dot-dir
// is still a project; anything it cannot read (see walkProjectTree) counts too. why names the
// evidence, for the partiality path.
func multipleProjects(buildDir string) (multi bool, why string) {
	skip := map[string]bool{}
	for _, root := range append(mavenRepoRoots(buildDir), gradleCacheRoots(buildDir)...) {
		skip[filepath.Clean(root)] = true
	}
	tree := walkProjectTree(buildDir, skip)
	var poms, gradle, settings []string
	for _, path := range tree.files {
		switch filepath.Base(path) {
		case "pom.xml":
			poms = append(poms, path)
		case "settings.gradle", "settings.gradle.kts":
			settings = append(settings, path)
		case "build.gradle", "build.gradle.kts":
			if info, err := os.Stat(filepath.Join(filepath.Dir(path), "src")); err == nil && info.IsDir() {
				gradle = append(gradle, path)
			}
		}
	}

	for _, p := range poms {
		if pomListsModules(p) {
			return true, relSlash(buildDir, p) + " lists modules"
		}
	}
	if len(poms) > 1 {
		return true, relSlash(buildDir, poms[0]) + ", " + relSlash(buildDir, poms[1])
	}

	for _, p := range settings {
		if filepath.Dir(p) != filepath.Clean(buildDir) {
			return true, relSlash(buildDir, p) + " defines another build"
		}
		projects, ok := gradleSettingsProjects(p)
		if !ok {
			return true, relSlash(buildDir, p) + " cannot be read in full"
		}
		count := len(projects)
		if info, err := os.Stat(filepath.Join(buildDir, "src")); err == nil && info.IsDir() {
			count++ // the root project has code of its own
		}
		if count > 1 {
			return true, relSlash(buildDir, p) + " includes " + strings.Join(projects, ", ")
		}
	}
	if len(gradle) > 1 {
		sort.Strings(gradle)
		return true, relSlash(buildDir, gradle[0]) + ", " + relSlash(buildDir, gradle[1])
	}
	if len(tree.unread) > 0 {
		return true, relSlash(buildDir, tree.unread[0]) + " cannot be read in full"
	}
	return false, ""
}

// projectTree is what walkProjectTree read under a build directory.
type projectTree struct {
	files  []string // every file it read, as walked (symlinks to files inside the root included)
	unread []string // every path whose contents it cannot vouch for, in walk order
}

// walkProjectTree walks root in lexical order without following a symlink. It enters every
// directory except one projectWalkSkip names or one whose path is in skip. What it cannot vouch
// for having read goes in unread: the root or a directory that cannot be read, a symlink that
// does not resolve or resolves outside root, and a symlinked directory whose target the walk
// does not itself enter. An in-root symlinked directory whose target it does enter is read at
// that target's real path, so it costs nothing; a link back to an ancestor is that case, which
// is what keeps the walk cycle-safe without following links. A symlink at a skip path, or one a
// projectWalkSkip name labels, is passed over as the directory it stands for would be.
func walkProjectTree(root string, skip map[string]bool) projectTree {
	var tree projectTree
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		tree.unread = append(tree.unread, root)
		return tree
	}
	walked := map[string]bool{} // real paths of the directories the walk entered
	type link struct{ path, target string }
	var linked []link
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			tree.unread = append(tree.unread, path)
			if d != nil && d.IsDir() && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if path != root && skip[filepath.Clean(path)] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, inside := resolveInside(realRoot, path)
			switch {
			case !inside:
				tree.unread = append(tree.unread, path)
			case isDirPath(target):
				if !projectWalkSkip(d.Name()) {
					linked = append(linked, link{path, target})
				}
			default:
				tree.files = append(tree.files, path)
			}
			return nil
		}
		if d.IsDir() {
			if path != root && projectWalkSkip(d.Name()) {
				return filepath.SkipDir
			}
			// No component below root is a symlink here, so the real path is a lexical join.
			if rel, err := filepath.Rel(root, path); err == nil {
				walked[filepath.Join(realRoot, rel)] = true
			}
			return nil
		}
		tree.files = append(tree.files, path)
		return nil
	})
	for _, l := range linked {
		if !walked[l.target] {
			tree.unread = append(tree.unread, l.path)
		}
	}
	return tree
}

// resolveInside resolves every symlink in path and reports whether the result lies under
// realRoot (itself already resolved). A path that does not resolve is not inside.
func resolveInside(realRoot, path string) (string, bool) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(realRoot, target)
	return target, err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isDirPath(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// projectWalkSkip names the directories the project walk never enters: VCS metadata and
// installed-package trees, which hold no project of this build.
func projectWalkSkip(name string) bool {
	switch name {
	case ".git", "node_modules", "site-packages":
		return true
	}
	return false
}

// pomListsModules reports whether the POM lists any <module>, at the top level or in a
// profile. A profile's modules join the reactor whenever the profile is active.
func pomListsModules(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var x struct {
		Modules  []string `xml:"modules>module"`
		Profiles []struct {
			Modules []string `xml:"modules>module"`
		} `xml:"profiles>profile"`
	}
	if unmarshalPOM(data, &x) != nil {
		return false
	}
	if len(x.Modules) > 0 {
		return true
	}
	for _, pr := range x.Profiles {
		if len(pr.Modules) > 0 {
			return true
		}
	}
	return false
}

var (
	settingsRootName  = regexp.MustCompile(`^rootProject\.name\s*=\s*(?:"[^"$\\\n]*"|'[^'\\\n]*')`)
	settingsInclude   = regexp.MustCompile(`^include\b`)
	settingsStringArg = regexp.MustCompile(`^\s*(?:"([^"$\\\n]*)"|'([^'\\\n]*)')`)
)

// gradleSettingsProjects returns the project paths a settings script includes. The reader is
// an allow-list: ok is true only when every statement is rootProject.name = "<literal>" or
// include over string literals naming in-tree projects. Anything else (a projectDir
// assignment, a plugins, pluginManagement or dependencyResolutionManagement block,
// includeFlat, includeBuild, apply, a loop or variable, an unknown call) can add a project,
// move one out of the tree or change how the build resolves, so ok is false; so is a script
// that cannot be read or whose comments cannot be stripped reliably.
func gradleSettingsProjects(path string) ([]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	src, ok := stripGradleCommentsChecked(string(data))
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	var projects []string
	rest := src
	for {
		rest = strings.TrimLeft(rest, " \t\r\n;")
		if rest == "" {
			break
		}
		if m := settingsRootName.FindString(rest); m != "" {
			after, ok := statementEnd(rest[len(m):])
			if !ok {
				return nil, false
			}
			rest = after
			continue
		}
		m := settingsInclude.FindString(rest)
		if m == "" {
			return nil, false
		}
		args, after, ok := gradleStringArgs(rest[len(m):])
		if !ok {
			return nil, false
		}
		for _, a := range args {
			a = strings.TrimPrefix(a, ":")
			if a == "" || strings.ContainsAny(a, "/\\") || strings.Contains(a, "..") {
				return nil, false
			}
			if !seen[a] {
				seen[a] = true
				projects = append(projects, a)
			}
		}
		rest = after
	}
	sort.Strings(projects)
	return projects, true
}

// gradleStringArgs reads the argument list after an include keyword: one or more string
// literals separated by commas, optionally in parentheses, ending the statement. It returns
// the text after the statement. ok is false for anything else.
func gradleStringArgs(rest string) (args []string, after string, ok bool) {
	rest = strings.TrimLeft(rest, " \t")
	paren := strings.HasPrefix(rest, "(")
	if paren {
		rest = rest[1:]
	}
	for {
		m := settingsStringArg.FindStringSubmatch(rest)
		if m == nil {
			return nil, "", false
		}
		args = append(args, m[1]+m[2])
		rest = rest[len(m[0]):]
		trimmed := strings.TrimLeft(rest, " \t\r\n")
		if strings.HasPrefix(trimmed, ",") {
			rest = trimmed[1:]
			continue
		}
		if paren {
			if !strings.HasPrefix(trimmed, ")") {
				return nil, "", false
			}
			rest = trimmed[1:]
		}
		after, ok := statementEnd(rest)
		if !ok {
			return nil, "", false
		}
		return args, after, true
	}
}

// statementEnd reports whether a statement ends at the start of rest (after spaces and tabs):
// at the end of the text, a line break or a semicolon. A trailing method call or operator could
// change what the literals name.
func statementEnd(rest string) (string, bool) {
	end := strings.TrimLeft(rest, " \t")
	if end == "" || strings.HasPrefix(end, "\n") || strings.HasPrefix(end, "\r") || strings.HasPrefix(end, ";") {
		return end, true
	}
	return "", false
}

// stripGradleComments removes // line and /* */ block comments outside string literals.
func stripGradleComments(src string) string {
	out, _ := stripGradleCommentsChecked(src)
	return out
}

// stripGradleCommentsChecked is stripGradleComments that also reports whether the result can be
// trusted: false for an unterminated block comment, whose rest of the text is dropped.
func stripGradleCommentsChecked(src string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(src) && src[j] != c && src[j] != '\n' {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(src) {
				j = len(src) - 1
			}
			b.WriteString(src[i : j+1])
			i = j
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				b.WriteByte('\n')
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return b.String(), false
			}
			i += end + 3
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// withMultipleProjects adds the run-wide multiple_projects_unsupported reason to p, with an
// unbounded scoped copy that carries the evidence.
func withMultipleProjects(p plugin.Partiality, why string) plugin.Partiality {
	out := plugin.Partiality{Complete: false, Scoped: append([]plugin.ScopedReason{}, p.Scoped...)}
	out.Reasons = append(append([]string{}, p.Reasons...), reasonMultipleProjectsUnsupported)
	out.Scoped = append(out.Scoped, plugin.ScopedReason{Reason: reasonMultipleProjectsUnsupported, Path: why})
	return out
}

func relSlash(base, path string) string {
	if r, err := filepath.Rel(base, path); err == nil {
		return filepath.ToSlash(r)
	}
	return path
}
