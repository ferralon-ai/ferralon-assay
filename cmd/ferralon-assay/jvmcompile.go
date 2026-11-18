package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
)

// jvmCompileTimeout bounds one tool's compile, on top of the scan's own context, so a build that
// hangs costs a bounded share of the scan.
const jvmCompileTimeout = 10 * time.Minute

// compileTool runs a build tool's compile; a test stands in for it.
var compileTool = buildgraph.Compile

// compileJVM compiles dir's first-party main classes with the repository's own Maven or Gradle
// when the class output the JVM lanes read is absent or does not cover the sources, so they search
// the build's bytecode rather than withholding the run. A repository whose output is present and
// current is not built. The compile is the project's own build (wrapper first, tests not run) under
// the conditions the graph was resolved with; it is never fatal to the scan.
//
// A scan that runs without the build tool (-build-graph off, or a graph file) does not compile. The
// returned note is what the lanes append to their first_party_bytecode_absent reason when the
// output still does not stand for the sources: the command to run, and why the run did not
// produce it. It is empty when nothing was needed or the compile produced the output.
func compileJVM(ctx context.Context, dir string, req graphRequest, w io.Writer) string {
	why := jvmOutputGap(dir)
	if why == "" {
		return ""
	}
	tools := compileTools(dir, req.tool)
	if len(tools) == 0 {
		return ""
	}
	if req.mode != buildGraphAuto && req.mode != "" {
		return fmt.Sprintf("%s; this run does not run the build tool, so run `%s` first", why, buildgraph.CompileCommand(dir, tools[0], req.conditions))
	}
	start := time.Now()
	var notes []string
	for _, t := range tools {
		command, f := compileTool(ctx, buildgraph.CompileRequest{Dir: dir, Tool: t, Conditions: req.conditions, Timeout: jvmCompileTimeout})
		if f != nil {
			fmt.Fprintf(w, "%s: compile: `%s`: %s\n", brand.Name, command, f.Cause())
			notes = append(notes, fmt.Sprintf("`%s` failed (%s: %s)", command, f.Cause(), oneLine(f.Log)))
		} else {
			fmt.Fprintf(w, "%s: compiled the main classes with `%s`\n", brand.Name, command)
			notes = append(notes, fmt.Sprintf("`%s` ran and the output still does not cover the sources", command))
		}
		if jvmOutputGap(dir) == "" {
			logPhase(w, "compile", time.Since(start))
			return ""
		}
	}
	logPhase(w, "compile", time.Since(start))
	return why + "; " + strings.Join(notes, "; ")
}

// compileTools is the tool or tools to compile with: the one the scan states, else each whose root
// build files dir holds.
func compileTools(dir, stated string) []string {
	switch stated {
	case buildgraph.ToolMaven, buildgraph.ToolGradle:
		return []string{stated}
	}
	maven, gradle := buildgraph.DetectTools(dir)
	var tools []string
	if maven {
		tools = append(tools, buildgraph.ToolMaven)
	}
	if gradle {
		tools = append(tools, buildgraph.ToolGradle)
	}
	return tools
}

// oneLine joins a tool's multi-line cause for a single-line reason.
func oneLine(s string) string {
	var parts []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, " | ")
}

// jvmOutputGap says why the class output under dir does not cover its main sources, "" when it
// does. A project with main sources and no class file in any of its output directories is a gap; so
// is a Java source whose type has no class file or a class older than the source. A source that
// declares no type named for its file is not held to one, so a built repository is never rebuilt
// for what the build never produced.
func jvmOutputGap(dir string) string {
	for _, p := range jvmProjects(dir) {
		if why := p.gap(dir); why != "" {
			return why
		}
	}
	return ""
}

// jvmProject is a directory with main sources: src/main/java or src/main/kotlin under it.
type jvmProject struct {
	dir     string
	srcDirs []string
}

// outputs are the class directories a Maven or Gradle build of the project writes main classes to.
func (p jvmProject) outputs() []string {
	return []string{
		filepath.Join(p.dir, "target", "classes"),
		filepath.Join(p.dir, "build", "classes", "java", "main"),
		filepath.Join(p.dir, "build", "classes", "kotlin", "main"),
	}
}

// jvmProjects lists the projects under dir that hold main sources, in path order. Build output,
// VCS metadata and dot directories are not walked.
func jvmProjects(dir string) []jvmProject {
	byDir := map[string]*jvmProject{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree holds no project; keep walking.
		}
		if p != dir && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "target" || d.Name() == "build") {
			return filepath.SkipDir
		}
		if filepath.Base(filepath.Dir(p)) == "src" && isTestSourceSet(d.Name()) {
			return filepath.SkipDir
		}
		if d.Name() == "main" && filepath.Base(filepath.Dir(p)) == "src" {
			for _, lang := range []string{"java", "kotlin"} {
				src := filepath.Join(p, lang)
				if hasSource(src) {
					root := filepath.Dir(filepath.Dir(p))
					if byDir[root] == nil {
						byDir[root] = &jvmProject{dir: root}
					}
					byDir[root].srcDirs = append(byDir[root].srcDirs, src)
				}
			}
			return filepath.SkipDir
		}
		return nil
	})
	out := make([]jvmProject, 0, len(byDir))
	for _, p := range byDir {
		sort.Strings(p.srcDirs)
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// isTestSourceSet mirrors the source-set rule of isMainSource in internal/plugin/javaanalysis
// (bytecode.go): a src/<set> directory named it, or containing "test", is not production code, so
// a project under it is not one the lane's coverage check holds to a class output.
func isTestSourceSet(name string) bool {
	set := strings.ToLower(name)
	return set == "it" || strings.Contains(set, "test")
}

// hasSource reports whether dir holds a .java or .kt file.
func hasSource(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil //nolint:nilerr // an unreadable subtree holds no source; keep walking.
		}
		if !d.IsDir() && isJVMSource(d.Name()) {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func isJVMSource(name string) bool {
	return strings.HasSuffix(name, ".java") || strings.HasSuffix(name, ".kt")
}

// gap is why the project's class output does not cover its sources, "" when it does.
func (p jvmProject) gap(root string) string {
	outs := p.outputs()
	rel := func(path string) string {
		if r, err := filepath.Rel(root, path); err == nil {
			return filepath.ToSlash(r)
		}
		return path
	}
	has := false
	for _, o := range outs {
		if hasClass(o) {
			has = true
			break
		}
	}
	name := rel(p.dir)
	if name == "." {
		name = "the repository root"
	}
	if !has {
		return "no compiled main classes for " + name
	}
	for _, src := range p.srcDirs {
		if filepath.Base(src) != "java" {
			continue
		}
		if why := javaGap(src, outs); why != "" {
			return why
		}
	}
	return ""
}

// declaresType matches a type declaration; the name is the file's.
func declaresType(text, name string) bool {
	return regexp.MustCompile(`(?m)\b(?:class|interface|enum|record|@interface)\s+` + regexp.QuoteMeta(name) + `\b`).MatchString(text)
}

// javaGap checks each Java source under src against the class output directories outs.
func javaGap(src string, outs []string) string {
	gap := ""
	_ = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".java") {
			return nil //nolint:nilerr // an unreadable subtree holds no source; keep walking.
		}
		base := strings.TrimSuffix(d.Name(), ".java")
		if base == "package-info" || base == "module-info" {
			return nil
		}
		text, err := os.ReadFile(p)
		if err != nil || !declaresType(string(text), base) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return nil
		}
		class := strings.TrimSuffix(rel, ".java") + ".class"
		var found os.FileInfo
		for _, o := range outs {
			if fi, err := os.Stat(filepath.Join(o, class)); err == nil {
				found = fi
				break
			}
		}
		switch {
		case found == nil:
			gap = "no class file for " + filepath.ToSlash(rel)
		case found.ModTime().Before(info.ModTime()):
			gap = "class file for " + filepath.ToSlash(rel) + " is older than its source"
		}
		if gap != "" {
			return fs.SkipAll
		}
		return nil
	})
	return gap
}

// hasClass reports whether dir holds a .class file.
func hasClass(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil //nolint:nilerr // an unreadable subtree holds no class; keep walking.
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".class") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}
