package scriptsurface

import (
	"bytes"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Site is where the backstop found an installer in a file nothing in the build invokes: a
// slash-separated path relative to the build root, a 1-based line (0 when unknown), and why.
type Site struct {
	Path string
	Line int
	Why  string
}

// String renders the site as path:line, or the path alone when the line is unknown.
func (s Site) String() string {
	if s.Line > 0 {
		return s.Path + ":" + strconv.Itoa(s.Line)
	}
	return s.Path
}

// Inactive returns the backstop's hits in files it found nothing in the build invokes, sorted
// and without repeats. The lane's claims stand as if those files were absent, so a lane carries
// each as an annotation on what it resolves. Call it after the walk.
func (v *Veto) Inactive() []Site {
	out := slices.Clone(v.inactive)
	slices.SortFunc(out, func(a, b Site) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return strings.Compare(a.Why, b.Why)
	})
	return slices.Compact(out)
}

// Annotations returns each site as a lane's annotation on what it resolves: install commands
// found there, which the result assumes are not active. The detail carries the site and fixed
// text only, no words of the file's.
func Annotations(sites []Site) []plugin.Annotation {
	var out []plugin.Annotation
	for _, s := range sites {
		out = append(out, plugin.Annotation{
			Reason: plugin.AnnotationInstallSurfaceInactive,
			Path:   s.String(),
			Detail: "install commands found at " + s.String() + "; this analysis assumes they are not active",
		})
	}
	return out
}

// relPath returns path as a slash-separated path relative to the build root.
func (v *Veto) relPath(path string) string {
	rel, err := filepath.Rel(v.root, path)
	if err != nil {
		rel = path
	}
	return filepath.ToSlash(rel)
}

// invoked reports whether the build may run the file at path, in which the backstop found an
// installer, so the backstop withholds on it rather than annotating it:
//
//   - a hook manager or CI agent runs it: an active git hook, a shellDirs file, or a hook
//     manager's configuration (hookConfig);
//   - a workflow uses an action from the tree, and it is an action's metadata (action.yml);
//   - a runner loads it by its default name without anything naming it (runnerDefault);
//   - a file the build reads or the backstop reads, other than itself, names it (namedIn).
//
// Each is an over-approximation: a name in a file nothing runs still counts.
func (v *Veto) invoked(path string) bool {
	return v.inGitDir(path) || shellDir(v.root, path) || hookConfig(path) || actionMetadata(path) ||
		runnerDefault(path) || v.namedIn(path)
}

// hookConfig reports whether the file at path is a hook manager's configuration, which the
// manager runs as hooks and CI runs by the manager's command without naming the file:
// pre-commit's and prek's, lefthook's, or overcommit's.
func hookConfig(path string) bool {
	lower := strings.ToLower(filepath.Base(path))
	switch lower {
	case ".pre-commit-config.yaml", ".pre-commit-config.yml", "prek.toml", ".overcommit.yml":
		return true
	}
	ext := filepath.Ext(lower)
	switch strings.TrimSuffix(lower, ext) {
	case "lefthook", ".lefthook", "lefthook-local", ".lefthook-local":
		return ext == ".yml" || ext == ".yaml" || ext == ".toml" || ext == ".json" || ext == ".jsonc"
	}
	return false
}

// actionMetadata reports whether the file at path is an action's metadata file. The backstop
// reads one only when a workflow uses an action from the tree (backstopSkips), and a workflow
// names the action by its directory alone, so each counts as invoked.
func actionMetadata(path string) bool {
	lower := strings.ToLower(filepath.Base(path))
	return lower == "action.yml" || lower == "action.yaml"
}

// runnerDefaultNames are the lowercased base names of the files a task runner, build tool or
// installer loads by default when it runs, and runnerDefaultStems the stems of those it loads
// whatever their extension. What surfaceOf recognises (a Makefile, justfile, Taskfile,
// Earthfile, noxfile.py, package.json, tox.ini) never reaches the backstop, so is not here.
var (
	runnerDefaultNames = map[string]bool{
		"tasks.py": true, "fabfile.py": true, "dodo.py": true, "pavement.py": true, "setup.py": true,
		"conftest.py": true, "pyproject.toml": true, "pixi.toml": true, "magefile.go": true,
		"build.rs": true, "build.sbt": true, "cmakelists.txt": true, "bitrise.yml": true,
		"bitrise.yaml": true,
	}
	runnerDefaultStems = map[string]bool{"gulpfile": true, "gruntfile": true, "jakefile": true, "rakefile": true}
)

// runnerDefault reports whether the file at path is one a runner loads by its default name
// (runnerDefaultNames, runnerDefaultStems), a Gradle build or settings script, a mage target
// under magefiles/, a tool's *.config.* file, or a task runner's own tasks file (taskJSON).
func runnerDefault(path string) bool {
	lower := strings.ToLower(filepath.Base(path))
	stem := lower
	if i := strings.IndexByte(lower, '.'); i > 0 {
		stem = lower[:i]
	}
	switch {
	case runnerDefaultNames[lower], runnerDefaultStems[stem]:
		return true
	case strings.HasSuffix(lower, ".gradle"), strings.HasSuffix(lower, ".gradle.kts"):
		return true
	case strings.Contains(lower, ".config."):
		return true
	case strings.HasSuffix(lower, ".go") && strings.EqualFold(filepath.Base(filepath.Dir(path)), "magefiles"):
		return true
	}
	return taskJSON(path)
}

// namedIn reports whether a file the build reads (buildRead's files) or one the backstop reads
// (its texts), other than the file at path itself, names it at any path it is reached at
// (pathsOf, names). When an entry of the build could not be read (buildRead's read), or a file
// that may name it cannot be, every path counts as named.
func (v *Veto) namedIn(path string) bool {
	if named, ok := v.named[path]; ok {
		return named
	}
	named := v.namedInBuild(path)
	if v.named == nil {
		v.named = map[string]bool{}
	}
	v.named[path] = named
	return named
}

func (v *Veto) namedInBuild(path string) bool {
	b := v.buildRead()
	if !b.read {
		return true
	}
	paths, ok := b.pathsOf(v.root, path)
	if !ok {
		return true
	}
	match := names(paths)
	for _, f := range b.files {
		if !slices.Contains(paths, f.path) && match(f.data) {
			return true
		}
	}
	for _, t := range b.texts {
		if slices.Contains(paths, t) {
			continue
		}
		data, err := v.spec.ReadRegular(t)
		if err != nil {
			return true
		}
		if match(data) {
			return true
		}
	}
	return false
}

// pathsOf returns every path the file at path, under root, is reached at: path itself, the path
// the walk visits its target at when it is a symlink, and the paths of the symlinks to that
// target or to the directory that holds it. A symlink to a directory further up changes no name
// that names reads. ok is false when path does not resolve inside the build.
func (b *buildFiles) pathsOf(root, path string) ([]string, bool) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, false
	}
	target, ok := b.walkPath(root, real)
	if !ok {
		return nil, false
	}
	out := []string{path}
	if target != path {
		out = append(out, target)
	}
	out = append(out, b.aliases[target]...)
	for _, link := range b.aliases[filepath.Dir(target)] {
		out = append(out, filepath.Join(link, filepath.Base(target)))
	}
	slices.Sort(out)
	return slices.Compact(out), true
}

// names returns a matcher for text that may run the file at any of paths by name, as nameOf
// reads each.
func names(paths []string) func(data []byte) bool {
	var matchers []func(data []byte) bool
	for _, p := range paths {
		matchers = append(matchers, nameOf(p))
	}
	return func(data []byte) bool {
		return slices.ContainsFunc(matchers, func(match func([]byte) bool) bool { return match(data) })
	}
}

// nameOf returns a matcher for text that may run the file at path by name: its base name
// (install.py, whatever path, separator or quoting comes before it, so cd scripts && python
// install.py and $(SCRIPTS)/install.py count); for source code, its stem after a path separator
// and before a quote, whitespace or line end, as an import specifier or an extensionless run
// names it (require("./install"), node scripts/install --prod); and for a Python
// module, the module run with -m (python -m install, python -m scripts.install), its dotted
// path from its directory (scripts.install), an import of it beside it (import install), or a
// from-import of it from that directory or a relative one (from scripts import install, from
// . import install, from .install import main). Each is compared whole: post_install.py and
// install_deps are other names. A package's __main__.py is also named as the module of its
// directory run with -m (python -m tools.provision).
func nameOf(path string) func(data []byte) bool {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	forms := []*regexp.Regexp{regexp.MustCompile(`(?:^|[^\w.-])` + regexp.QuoteMeta(base) + `(?:$|[^\w.-])`)}
	if stem != "" && sourceExts[strings.ToLower(ext)] {
		forms = append(forms, regexp.MustCompile(`(?m)[/\\]`+regexp.QuoteMeta(stem)+"(?:[\"'`\\s]|$)"))
	}
	tokens := [][]byte{[]byte(stemOr(stem, base))}
	if strings.EqualFold(ext, ".py") && stem != "" {
		q := regexp.QuoteMeta(stem)
		dirName := filepath.Base(filepath.Dir(path))
		dir := regexp.QuoteMeta(dirName)
		if stem == "__main__" {
			tokens = append(tokens, []byte(dirName))
			forms = append(forms, regexp.MustCompile(`-m[ \t]+(?:[\w.]+\.)?`+dir+`(?:$|[^\w.])`))
		}
		forms = append(forms,
			regexp.MustCompile(`-m[ \t]+(?:[\w.]+\.)?`+q+`(?:$|[^\w.])`),
			regexp.MustCompile(`(?:^|[^\w])`+dir+`\.`+q+`(?:$|[^\w])`),
			regexp.MustCompile(`\bfrom[ \t]+(?:[\w.]*\b`+dir+`|\.+)[ \t]+import[ \t]*(?:\([^)]*|[^\n;]*)[\s,(]`+q+`(?:$|[^\w.])`),
			regexp.MustCompile(`\bfrom[ \t]+\.+(?:[\w.]+\.)?`+q+`[ \t]`),
			regexp.MustCompile(`\bimport[ \t]+`+q+`(?:$|[^\w.])`))
	}
	return func(data []byte) bool {
		if !slices.ContainsFunc(tokens, func(t []byte) bool { return bytes.Contains(data, t) }) {
			return false
		}
		return slices.ContainsFunc(forms, func(re *regexp.Regexp) bool { return re.Match(data) })
	}
}

// stemOr returns stem, or base when stem is empty (a dotfile), as text every form but a
// __main__.py's -m contains.
func stemOr(stem, base string) string {
	if stem == "" {
		return base
	}
	return stem
}
