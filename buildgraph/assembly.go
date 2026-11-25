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
// draws only from the project's own artifact and its resolved dependencies, which the graph lists;
// only whether it unpacks them is read, since unpacking extracts the archives nested in each.
type assemblyDescriptor struct {
	DependencySets []struct {
		Unpack string `xml:"unpack"`
	} `xml:"dependencySets>dependencySet"`
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
	vars := assemblyVars(base, p)
	for _, desc := range d.Descriptors {
		file, ok := assemblyPath(desc, base, vars)
		if !ok || !within(dir, file) {
			return "descriptor " + strings.TrimSpace(desc) + " is not a file in the checkout"
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "descriptor " + strings.TrimSpace(desc) + " cannot be read"
		}
		if why := assemblyDescriptorUnlisted(dir, base, repos, b, vars); why != "" {
			return "descriptor " + strings.TrimSpace(desc) + " " + why
		}
	}
	return ""
}

// assemblyVars are the properties a descriptor path may interpolate: the module's basedir, build
// directories and version.
func assemblyVars(base string, p effectiveProject) map[string]string {
	return map[string]string{
		"basedir":                       base,
		"project.basedir":               base,
		"project.build.directory":       strings.TrimSpace(p.Build.Directory),
		"project.build.outputDirectory": strings.TrimSpace(p.Build.OutputDirectory),
		"project.version":               strings.TrimSpace(p.Version),
	}
}

// assemblyDescriptorUnlisted is the check of one assembly descriptor b, read from a file in the
// checkout by assemblyUnlisted, or written inline or built into the plugin for fabric8Unlisted.
func assemblyDescriptorUnlisted(dir, base string, repos []string, b []byte, vars map[string]string) string {
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
	for _, ds := range desc.DependencySets {
		if u := strings.TrimSpace(ds.Unpack); u != "" && !strings.EqualFold(u, "false") {
			return "has a dependencySet that unpacks what it draws"
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

// fabric8Goals are the io.fabric8:docker-maven-plugin goals fabric8Unlisted can bound: build makes
// the images it checks, push and tag name them, start, stop and remove run and drop containers, and
// help prints usage. copy copies files out of a container onto the host, source attaches the build
// archive as an artifact, and save writes an image to an archive; they are left out.
var fabric8Goals = setOf("build", "push", "start", "stop", "remove", "tag", "help")

// fabric8BuildOpaque are the elements of a docker-maven-plugin image build that make the image from
// what this does not read: a Dockerfile, its directory or the context sent with it (whose ADD, COPY
// and RUN lines run unread), an image archive, and commands run in the image.
var fabric8BuildOpaque = []string{"dockerFile", "dockerFileDir", "contextDir", "dockerArchive", "runCmds"}

// fabric8DescriptorRefs are the docker-maven-plugin built-in assembly descriptors fabric8Unlisted
// bounds, as the plugin (0.46.0) ships them less namespaces and comments: the project's own
// artifact, and with it its runtime dependencies and the classpath file the build may write. Each
// is checked as a descriptor in the checkout is. The rest are left out: project reads the whole
// module directory, hawt-app what another plugin wrote.
var fabric8DescriptorRefs = map[string]string{
	"artifact": `<assembly><id>artifact</id><dependencySets><dependencySet><useProjectArtifact>true</useProjectArtifact>` +
		`<includes><include>${project.groupId}:${project.artifactId}</include></includes>` +
		`<outputFileNameMapping>${project.build.finalName}.${artifact.extension}</outputFileNameMapping></dependencySet></dependencySets></assembly>`,
	"artifact-with-dependencies": `<assembly><id>artifact-with-dependencies</id><includeBaseDirectory>false</includeBaseDirectory>` +
		`<dependencySets><dependencySet><useProjectArtifact>true</useProjectArtifact>` +
		`<includes><include>${project.groupId}:${project.artifactId}</include></includes>` +
		`<outputFileNameMapping>${project.build.finalName}.${artifact.extension}</outputFileNameMapping></dependencySet>` +
		`<dependencySet><useProjectArtifact>false</useProjectArtifact><scope>runtime</scope><fileMode>0644</fileMode></dependencySet></dependencySets>` +
		`<fileSets><fileSet><includes><include>classpath</include></includes><directory>${project.build.directory}/</directory>` +
		`<outputDirectory>.</outputDirectory><fileMode>0644</fileMode></fileSet></fileSets></assembly>`,
}

// fabric8Unlisted returns why a bound io.fabric8:docker-maven-plugin execution may put into an image
// what the graph does not list, or "" when it cannot: no image is configured from properties or
// outside the POM, none is built from a Dockerfile, an archive or commands run in it, and every
// image assembly is written inline or is one of fabric8DescriptorRefs, holding only what
// assemblyDescriptorUnlisted bounds. The image's base layer is outside the graph, as jib's is.
// mavenIncomplete checks the goals against fabric8Goals.
func fabric8Unlisted(dir, base string, repos []string, p effectiveProject, pl effectivePlugin, ex effectiveExecution) string {
	if p.Properties.has("docker.imagePropertyConfiguration") {
		return "sets docker.imagePropertyConfiguration, which configures images from properties"
	}
	vars := assemblyVars(base, p)
	images := 0
	for _, c := range []xmlChildren{ex.Configuration, pl.Configuration} {
		if c.has("imagePropertyConfiguration") {
			return "sets imagePropertyConfiguration, which configures images from properties"
		}
		var cfg struct {
			Images []struct {
				Name     string       `xml:"name"`
				External *xmlChildren `xml:"external"`
				Build    xmlChildren  `xml:"build"`
			} `xml:"images>image"`
		}
		if xml.Unmarshal([]byte("<c>"+c.Inner+"</c>"), &cfg) != nil {
			return "has a configuration this cannot parse"
		}
		images += len(cfg.Images)
		for _, img := range cfg.Images {
			name := strings.TrimSpace(img.Name)
			if img.External != nil {
				return "image " + name + " sets external, which configures it outside the POM"
			}
			for _, e := range fabric8BuildOpaque {
				if img.Build.has(e) {
					return "image " + name + " sets " + e + ", which builds from what the graph does not read"
				}
			}
			var b struct {
				Assembly   []xmlChildren `xml:"assembly"`
				Assemblies []xmlChildren `xml:"assemblies>assembly"`
			}
			if xml.Unmarshal([]byte("<b>"+img.Build.Inner+"</b>"), &b) != nil {
				return "image " + name + " has a build this cannot parse"
			}
			for _, a := range append(b.Assembly, b.Assemblies...) {
				if why := fabric8AssemblyUnlisted(dir, base, repos, a, vars); why != "" {
					return "image " + name + " assembly " + why
				}
			}
		}
	}
	// With no image configured, the plugin builds the Dockerfile beside the module's POM.
	if _, err := os.Lstat(filepath.Join(base, "Dockerfile")); images == 0 && err == nil {
		return "configures no image, so it builds the module's Dockerfile"
	}
	return ""
}

// fabric8AssemblyUnlisted is fabric8Unlisted's check of one image assembly a.
func fabric8AssemblyUnlisted(dir, base string, repos []string, a xmlChildren, vars map[string]string) string {
	if a.has("descriptor") {
		return "sets descriptor, which this does not read"
	}
	var d struct {
		Ref    string       `xml:"descriptorRef"`
		Inline *xmlChildren `xml:"inline"`
	}
	if xml.Unmarshal([]byte("<a>"+a.Inner+"</a>"), &d) != nil {
		return "cannot be parsed"
	}
	if a.has("descriptorRef") {
		ref := strings.TrimSpace(d.Ref)
		desc, ok := fabric8DescriptorRefs[ref]
		if !ok {
			return "uses descriptorRef " + ref + ", which this does not bound"
		}
		if why := assemblyDescriptorUnlisted(dir, base, repos, []byte(desc), vars); why != "" {
			return "descriptorRef " + ref + " " + why
		}
	}
	if d.Inline != nil {
		if why := assemblyDescriptorUnlisted(dir, base, repos, []byte("<inline>"+d.Inline.Inner+"</inline>"), vars); why != "" {
			return "inline " + why
		}
	}
	return ""
}
