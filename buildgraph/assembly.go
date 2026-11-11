package buildgraph

import (
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// assemblyGoals are the maven-assembly-plugin goals assemblyUnlisted can bound: single builds the
// descriptors it is given, help prints usage.
var assemblyGoals = setOf("single", "help")

// assemblyConfigOpaque are maven-assembly-plugin parameters that select a descriptor this cannot
// read from the checkout (one built into the plugin or a dependency, written inline, or found by
// scanning a directory), or that move where the descriptor's fileSets read from.
var assemblyConfigOpaque = []string{"archiveBaseDirectory", "descriptor", "descriptorId", "descriptorRefs", "descriptorSourceDirectory", "inlineDescriptors"}

// assemblyTopLevel are the descriptor elements assemblyUnlisted reads or that add nothing; any
// other element (moduleSets, repositories, componentDescriptors, containerDescriptorHandlers,
// includeSiteDirectory) withholds the bound.
var assemblyTopLevel = setOf("id", "formats", "includeBaseDirectory", "baseDirectory", "fileSets", "files", "dependencySets")

// assemblyDescriptor is what assemblyUnlisted reads from an assembly descriptor. A dependencySet
// draws only from the project's own artifact and its resolved dependencies, which the graph lists,
// so its contents are not read.
type assemblyDescriptor struct {
	FileSets []struct {
		Directory string `xml:"directory"`
	} `xml:"fileSets>fileSet"`
	Files []struct {
		Source  string   `xml:"source"`
		Sources []string `xml:"sources>source"`
	} `xml:"files>file"`
}

// assemblyUnlisted returns why a bound maven-assembly-plugin execution may package what the graph
// does not list, or "" when it cannot: every goal is in assemblyGoals, and every descriptor is a
// file in the checkout holding only dependencySets and fileSets or files that read from inside the
// checkout, outside any local repository. Those paths hold what the checkout carries, which
// CheckedInArchives inspects, or what the build's other executions wrote under it, each of which
// this graph lists, records as Unlisted, or marks Incomplete. Paths interpolate only the module's
// basedir, build directories and version; anything else left as ${...} withholds the bound.
func assemblyUnlisted(dir, base string, repos []string, p effectiveProject, pl effectivePlugin, ex effectiveExecution) string {
	for _, g := range ex.Goals.Goal {
		if g = strings.TrimSpace(g); !assemblyGoals[g] {
			return "goal " + g + " is not one whose output the graph bounds"
		}
	}
	for _, c := range []xmlChildren{ex.Configuration, pl.Configuration} {
		for _, name := range assemblyConfigOpaque {
			if c.has(name) {
				return "sets " + name + ", which reads outside the descriptors in the checkout"
			}
		}
	}
	// Maven merges plugin and execution configuration; the execution's descriptors list replaces
	// the plugin's.
	cfg := pl.Configuration
	if ex.Configuration.has("descriptors") {
		cfg = ex.Configuration
	}
	var d struct {
		Descriptors []string `xml:"descriptors>descriptor"`
	}
	if err := xml.Unmarshal([]byte("<c>"+cfg.Inner+"</c>"), &d); err != nil || len(d.Descriptors) == 0 {
		return "has no descriptor this can read"
	}
	vars := map[string]string{
		"basedir":                       base,
		"project.basedir":               base,
		"project.build.directory":       strings.TrimSpace(p.Build.Directory),
		"project.build.outputDirectory": strings.TrimSpace(p.Build.OutputDirectory),
		"project.version":               strings.TrimSpace(p.Version),
	}
	for _, desc := range d.Descriptors {
		file, ok := assemblyPath(desc, base, vars)
		if !ok || !within(dir, file) {
			return "descriptor " + strings.TrimSpace(desc) + " is not a file in the checkout"
		}
		if why := assemblyDescriptorUnlisted(dir, base, repos, file, vars); why != "" {
			return "descriptor " + strings.TrimSpace(desc) + " " + why
		}
	}
	return ""
}

// assemblyDescriptorUnlisted is assemblyUnlisted's check of the descriptor at file.
func assemblyDescriptorUnlisted(dir, base string, repos []string, file string, vars map[string]string) string {
	b, err := os.ReadFile(file)
	if err != nil {
		return "cannot be read"
	}
	var top xmlChildren
	var desc assemblyDescriptor
	if xml.Unmarshal(b, &top) != nil || xml.Unmarshal(b, &desc) != nil {
		return "cannot be parsed"
	}
	for _, e := range top.Any {
		if !assemblyTopLevel[e.XMLName.Local] {
			return "has " + e.XMLName.Local
		}
	}
	var paths []string
	for _, fs := range desc.FileSets {
		// A fileSet with no directory reads the module's basedir.
		paths = append(paths, fs.Directory)
	}
	for _, f := range desc.Files {
		paths = append(paths, f.Source)
		paths = append(paths, f.Sources...)
	}
	for i, raw := range paths {
		v, ok := assemblyPath(raw, base, vars)
		if !ok {
			return "reads " + strings.TrimSpace(raw) + ", which is not interpolated"
		}
		if !within(dir, v) {
			return "reads " + v + ", outside the checkout"
		}
		if slices.ContainsFunc(repos, func(r string) bool { return within(r, v) }) {
			return "reads " + v + " in the local repository"
		}
		if i < len(desc.FileSets) {
			if why := assemblyTreeUnlisted(dir, v, repos); why != "" {
				return "reads " + v + ", which " + why
			}
		}
	}
	return ""
}

// assemblyTreeUnlisted returns why the fileSet directory top may copy files from outside the
// checkout or from a local repository, or "" when it cannot: no local repository lies under it,
// and every symlink under it, followed as the assembly plugin follows them, resolves inside the
// checkout and outside any local repository.
func assemblyTreeUnlisted(dir, top string, repos []string) string {
	seen := map[string]bool{}
	var walk func(root string) string
	walk = func(root string) string {
		real, err := filepath.EvalSymlinks(root)
		if err != nil || seen[real] {
			return "" // not written yet, or already walked
		}
		seen[real] = true
		for _, r := range repos {
			if within(real, r) {
				return "holds the local repository " + r
			}
		}
		var why string
		_ = filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.Type()&fs.ModeSymlink == 0 {
				return nil
			}
			t, err := filepath.EvalSymlinks(p)
			switch {
			case err != nil || !within(dir, t):
				why = "links " + p + " outside the checkout"
			case slices.ContainsFunc(repos, func(r string) bool { return within(r, t) }):
				why = "links " + p + " into the local repository"
			default:
				if fi, err := os.Stat(t); err == nil && fi.IsDir() {
					why = walk(t)
				}
			}
			if why != "" {
				return filepath.SkipAll
			}
			return nil
		})
		return why
	}
	return walk(top)
}

// assemblyPath interpolates vars into the descriptor path raw in one pass and resolves it against
// base; ok is false when it names any other ${...}, or one whose value is empty. within then
// resolves "..", and symlinks through the path's nearest existing parent.
func assemblyPath(raw, base string, vars map[string]string) (string, bool) {
	ok := true
	v := assemblyVar.ReplaceAllStringFunc(strings.TrimSpace(raw), func(m string) string {
		val := vars[m[2:len(m)-1]]
		if val == "" {
			ok = false
		}
		return val
	})
	if !ok || strings.Contains(v, "${") {
		return "", false
	}
	if !filepath.IsAbs(v) {
		v = filepath.Join(base, filepath.FromSlash(v))
	}
	return filepath.Clean(v), true
}

var assemblyVar = regexp.MustCompile(`\$\{[^}]*\}`)
