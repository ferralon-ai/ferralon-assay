package buildgraph

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// complete.go — whether the producer saw every way its build installs a dependency
// (Graph.Complete). It is earned, never assumed: each check passes only on what the producer
// observed and recognised, and anything it does not recognise withholds it. The claim covers
// what the build tool installs; a container image or a deploy step can add more, as with every
// lockfile lane.

// gradleTaskTypes are the task types whose actions install only what the build's configurations
// resolve: Gradle's own compile, packaging, test, report and publishing tasks, and those of the
// plugins beside them. A task of any other type withholds Complete.
var gradleTaskTypes = setOf(
	"org.gradle.api.DefaultTask",
	"org.gradle.api.tasks.Copy",
	"org.gradle.api.tasks.Sync",
	"org.gradle.api.tasks.Delete",
	"org.gradle.api.tasks.bundling.Jar",
	"org.gradle.api.tasks.bundling.War",
	"org.gradle.api.tasks.bundling.Zip",
	"org.gradle.api.tasks.bundling.Tar",
	"org.gradle.jvm.tasks.Jar",
	"org.gradle.plugins.ear.Ear",
	"org.gradle.api.tasks.compile.JavaCompile",
	"org.gradle.api.tasks.compile.GroovyCompile",
	"org.gradle.api.tasks.javadoc.Javadoc",
	"org.gradle.api.tasks.javadoc.Groovydoc",
	"org.gradle.api.tasks.testing.Test",
	"org.gradle.language.jvm.tasks.ProcessResources",
	"org.gradle.api.tasks.application.CreateStartScripts",
	"org.gradle.jvm.application.tasks.CreateStartScripts",
	"org.gradle.api.tasks.wrapper.Wrapper",
	"org.gradle.buildinit.tasks.InitBuild",
	"org.gradle.buildconfiguration.tasks.UpdateDaemonJvm",
	"org.gradle.configuration.Help",
	"org.gradle.api.tasks.diagnostics.ArtifactTransformsReportTask",
	"org.gradle.api.tasks.diagnostics.BuildEnvironmentReportTask",
	"org.gradle.api.tasks.diagnostics.DependencyInsightReportTask",
	"org.gradle.api.tasks.diagnostics.DependencyReportTask",
	"org.gradle.api.tasks.diagnostics.OutgoingVariantsReportTask",
	"org.gradle.api.tasks.diagnostics.ProjectReportTask",
	"org.gradle.api.tasks.diagnostics.PropertyReportTask",
	"org.gradle.api.tasks.diagnostics.ResolvableConfigurationsReportTask",
	"org.gradle.api.tasks.diagnostics.TaskReportTask",
	"org.gradle.api.reporting.components.ComponentReport",
	"org.gradle.api.reporting.dependents.DependentComponentsReport",
	"org.gradle.api.reporting.model.ModelReport",
	"org.gradle.jvm.toolchain.internal.task.ShowToolchainsTask",
	"org.gradle.kotlin.dsl.accessors.tasks.PrintAccessors",
	"org.gradle.testing.jacoco.tasks.JacocoReport",
	"org.gradle.testing.jacoco.tasks.JacocoCoverageVerification",
	"org.gradle.api.plugins.quality.Checkstyle",
	"org.gradle.api.plugins.quality.Pmd",
	"org.gradle.api.publish.maven.tasks.GenerateMavenPom",
	"org.gradle.api.publish.maven.tasks.PublishToMavenRepository",
	"org.gradle.api.publish.maven.tasks.PublishToMavenLocal",
	"org.gradle.api.publish.tasks.GenerateModuleMetadata",
	"org.gradle.plugins.signing.Sign",
	"org.jetbrains.kotlin.gradle.tasks.KotlinCompile",
	"org.jetbrains.kotlin.gradle.tasks.abi.KotlinLegacyAbiCheckTaskImpl",
	"org.jetbrains.kotlin.gradle.tasks.abi.KotlinLegacyAbiDumpTaskImpl",
	"org.jetbrains.kotlin.gradle.tasks.abi.KotlinLegacyAbiUpdateTask",
	"org.jetbrains.kotlin.gradle.tasks.publishing.CheckSigningTask",
	"org.jetbrains.kotlin.gradle.tasks.publishing.GeneratePgpKeys",
	"org.jetbrains.kotlin.gradle.tasks.publishing.UploadPgpKeyTask",
	"org.jetbrains.kotlin.gradle.plugin.diagnostics.CheckKotlinGradlePluginConfigurationErrors",
	"org.jetbrains.kotlin.gradle.tooling.BuildKotlinToolingMetadataTask$FromKotlinExtension",
	"org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetProcessor$createAdditionalClassesTaskForIdeRunner$IDEClassesTask",
	"org.springframework.boot.gradle.tasks.bundling.BootJar",
	"org.springframework.boot.gradle.tasks.bundling.BootWar",
	"org.springframework.boot.gradle.tasks.bundling.BootBuildImage",
	"org.springframework.boot.gradle.tasks.buildinfo.BuildInfo",
	"org.springframework.boot.gradle.plugin.ResolveMainClassName",
	"io.spring.gradle.dependencymanagement.internal.report.DependencyManagementReportTask",
	"com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar",
	"com.github.jengelman.gradle.plugins.shadow.tasks.KnowsTask",
	"com.google.cloud.tools.jib.gradle.BuildDockerTask",
	"com.google.cloud.tools.jib.gradle.BuildImageTask",
	"com.google.cloud.tools.jib.gradle.BuildTarTask",
	"com.google.cloud.tools.jib.gradle.skaffold.CheckJibVersionTask",
	"com.google.cloud.tools.jib.gradle.skaffold.FilesTaskV2",
	"com.google.cloud.tools.jib.gradle.skaffold.InitTask",
	"com.google.cloud.tools.jib.gradle.skaffold.SyncMapTask",
	"io.ktor.plugin.features.ConfigureJibExternalTask",
	"io.ktor.plugin.features.ConfigureJibLocalTask",
)

// gradleLeafTaskTypes run a program: the application, a container or a command. One no task
// depends on or is finalized by runs only when a command line names it, and nothing the build
// installs reads what it writes; one another task does depend on withholds Complete.
var gradleLeafTaskTypes = setOf(
	"org.gradle.api.tasks.JavaExec",
	"org.gradle.api.tasks.Exec",
	"org.springframework.boot.gradle.tasks.run.BootRun",
	"com.github.jengelman.gradle.plugins.shadow.internal.JavaJarExec",
	"io.ktor.plugin.features.RunDockerTask",
)

// gradleActionOrigins are the packages an action added to a task beside its type's own may come
// from: Gradle's and the plugins' above. One from a build script, a convention plugin or any
// other plugin withholds Complete.
var gradleActionOrigins = []string{
	"org.gradle.",
	"org.jetbrains.kotlin.gradle.",
	"org.springframework.boot.gradle.",
	"io.spring.gradle.dependencymanagement.",
	"com.github.jengelman.gradle.plugins.shadow.",
	"com.google.cloud.tools.jib.",
	"io.ktor.plugin.",
}

// gradleResolution is one resolution the root build made, as the init script's listener
// recorded it.
type gradleResolution struct {
	Path      string           `json:"path"`
	Script    bool             `json:"script"` // a project's build script classpath
	Failure   string           `json:"failure"`
	Artifacts []gradleResolved `json:"artifacts"`
}

// gradleResolved is one file a resolution resolved.
type gradleResolved struct {
	File    string `json:"file"`
	Project bool   `json:"project"` // a project's
	Module  bool   `json:"module"`  // a repository module's
}

// gradleIncomplete lists what keeps g from being Complete: a Gradle build file no project reads;
// a runtime classpath left uncollected; a task of a type off the list, an exec task another
// depends on (beside a run alias) or that a task finalizes, an action added from outside the
// listed packages, or an input file from outside the build that the graph does not hold; and a
// resolution (a detached configuration, say) that resolved a file the graph does not hold. A
// build script's own classpath is build logic, a POM file carries no code, a file that is not a
// repository module's and sits in a project's build directory, outside any user home or file
// repository, is what the build made from its own sources (a sibling's classes, say), and
// Gradle's transforms cache holds what it derived from an artifact some resolution resolved (the
// Kotlin compiler's classpath snapshots). A repository module's file is never the build's own,
// wherever the repository placed it.
func gradleIncomplete(out, dir string, projects []gradleProject, g *Graph) ([]string, error) {
	var reasons []string
	files := graphFiles(g)
	var buildDirs, foreign, homes []string
	for _, p := range projects {
		// A build directory at or above the root would hold the checkout and the caches with it.
		if rel, ok := realRel(dir, p.BuildDir); p.BuildDir != "" && ok && rel != "." {
			buildDirs = append(buildDirs, p.BuildDir)
		}
		if p.UserHome != "" {
			foreign = append(foreign, p.UserHome)
			homes = append(homes, filepath.Join(p.UserHome, "caches"))
		}
		foreign = append(foreign, p.ForeignRoots...)
		for _, r := range p.OpaqueRepos {
			reasons = append(reasons, "project "+p.Path+": Ivy repository "+r+" has no URL to place the files it resolves by")
		}
	}
	// A user home or file repository inside a build directory holds what Gradle fetched, not what
	// the build made.
	under := func(dirs []string, f string) bool {
		return slices.ContainsFunc(dirs, func(d string) bool { _, ok := relPath(d, f); return ok })
	}
	built := func(f string) bool { return under(buildDirs, f) && !under(foreign, f) }
	transformed := func(f string) bool {
		return slices.ContainsFunc(homes, func(c string) bool {
			rel, ok := relPath(c, f)
			if !ok {
				return false
			}
			segs := strings.Split(rel, "/")
			return len(segs) > 1 && gradleTransformsV7.MatchString(segs[0]) ||
				len(segs) > 2 && gradleVersionDir.MatchString(segs[0]) && segs[1] == "transforms"
		})
	}
	// A run alias (an action-less DefaultTask no task depends on, whose every dependency runs a
	// program) only runs programs, so a program it depends on is still a leaf.
	types := map[string]string{}
	dependents := map[string][]string{}
	for _, p := range projects {
		for _, t := range p.Tasks {
			types[t.Path] = t.Type
			for _, d := range t.Depends {
				dependents[d] = append(dependents[d], t.Path)
			}
		}
	}
	alias := map[string]bool{}
	for _, p := range projects {
		for _, t := range p.Tasks {
			alias[t.Path] = t.Failure == "" && t.Type == "org.gradle.api.DefaultTask" && len(t.Actions) == 0 && len(t.Depends) > 0 &&
				len(dependents[t.Path]) == 0 && !slices.ContainsFunc(t.Depends, func(d string) bool { return !gradleLeafTaskTypes[types[d]] })
		}
	}
	depended := func(path string) bool {
		return slices.ContainsFunc(dependents[path], func(d string) bool { return !alias[d] })
	}
	for _, p := range projects {
		for _, c := range p.Uncollected {
			reasons = append(reasons, "project "+p.Path+": configuration "+c+" was not collected")
		}
		for _, t := range p.Tasks {
			if t.Failure != "" {
				reasons = append(reasons, "task "+t.Path+" could not be observed: "+t.Failure)
				continue
			}
			switch {
			case gradleTaskTypes[t.Type]:
			case gradleLeafTaskTypes[t.Type]:
				if depended(t.Path) {
					reasons = append(reasons, "task "+t.Path+" runs a program ("+t.Type+") that another task depends on")
				}
				// A finalizer runs after the program whenever it runs, and can package what it wrote.
				if len(t.FinalizedBy) > 0 {
					reasons = append(reasons, "task "+t.Path+" runs a program ("+t.Type+") finalized by "+strings.Join(t.FinalizedBy, ", "))
				}
			default:
				reasons = append(reasons, "task "+t.Path+" has type "+t.Type+", which is not one whose installs the graph lists")
			}
			for _, a := range t.Actions {
				if !slices.ContainsFunc(gradleActionOrigins, func(p string) bool { return strings.HasPrefix(a, p) }) {
					reasons = append(reasons, "task "+t.Path+" has an action added by "+a)
				}
			}
			for _, f := range t.Outside {
				if !files[f] && !transformed(f) {
					reasons = append(reasons, "task "+t.Path+" reads "+f+", outside the build")
				}
			}
		}
	}
	resolved, ok, err := gradleResolutions(filepath.Join(out, "resolved"))
	if err != nil {
		return nil, err
	}
	if !ok {
		reasons = append(reasons, "the build recorded no resolution")
	}
	for _, r := range resolved {
		if r.Script || r.Path == "classpath" {
			continue
		}
		if r.Failure != "" {
			reasons = append(reasons, "resolution of "+r.Path+" failed: "+firstLine(r.Failure))
			continue
		}
		for _, a := range r.Artifacts {
			if !a.Project && !strings.HasSuffix(a.File, ".pom") && !files[a.File] && (a.Module || !built(a.File)) {
				reasons = append(reasons, "resolution of "+r.Path+" resolved "+a.File+", which no collected configuration lists")
			}
		}
	}
	orphans, err := gradleOrphanBuildFiles(dir, g.Subject.Outputs, projects, g.Subject.IncludedBuilds)
	if err != nil {
		return nil, err
	}
	reasons = append(reasons, orphans...)
	return sortedUnique(reasons), nil
}

// Gradle's transforms cache below <user home>/caches: transforms-<n> up to Gradle 7, and
// <gradle version>/transforms from Gradle 8.
var (
	gradleTransformsV7 = regexp.MustCompile(`^transforms-[0-9]+$`)
	gradleVersionDir   = regexp.MustCompile(`^[0-9]+\.[0-9]+[0-9A-Za-z.\-]*$`)
)

// gradleOutputs are the directories inside the checkout a Gradle build writes or caches into:
// each project's build directory and Kotlin cache, the root's project cache (.gradle), an
// included build's or buildSrc's build directory and project cache, and the Gradle user home.
func gradleOutputs(dir string, projects []gradleProject, included []string) []string {
	var out []string
	add := func(p string) {
		if rel, ok := realRel(dir, p); p != "" && ok && rel != "." {
			out = append(out, rel)
		}
	}
	add(filepath.Join(dir, ".gradle"))
	for _, p := range projects {
		add(p.BuildDir)
		add(p.UserHome)
		if p.Dir != "" {
			add(filepath.Join(p.Dir, ".kotlin"))
		}
	}
	for _, b := range append(slices.Clone(included), "buildSrc") {
		add(filepath.Join(dir, filepath.FromSlash(b), "build"))
		add(filepath.Join(dir, filepath.FromSlash(b), ".gradle"))
	}
	return sortedUnique(out)
}

// gradleResolutions reads the listener's records; false when it recorded none.
func gradleResolutions(dir string) ([]gradleResolution, bool, error) {
	fail := func(log string) error { return &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: log} }
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fail(err.Error())
	}
	var out []gradleResolution
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, false, fail(err.Error())
		}
		var r gradleResolution
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, false, fail("resolution record " + e.Name() + ": " + err.Error())
		}
		out = append(out, r)
	}
	return out, true, nil
}

// gradleOrphanBuildFiles lists the build and settings scripts under dir that no project of the
// build reads: a separate build, whose dependencies the graph never resolved. Included builds and
// buildSrc are build logic, bound as inputs.
func gradleOrphanBuildFiles(dir string, outputs []string, projects []gradleProject, included []string) ([]string, error) {
	read := map[string]bool{"settings.gradle": true, "settings.gradle.kts": true}
	for _, p := range projects {
		if rel, ok := relPath(p.RootDir, p.BuildFile); ok {
			read[rel] = true
		}
	}
	scripts, err := treeFiles(dir, outputs, func(rel, name string) bool {
		return name == "build.gradle" || name == "build.gradle.kts" || name == "settings.gradle" || name == "settings.gradle.kts"
	})
	if err != nil {
		return nil, err
	}
	trees := append(slices.Clone(included), "buildSrc")
	var out []string
	for _, s := range scripts {
		switch {
		case s.Escapes:
			out = append(out, s.Path+" links to a directory outside the checkout or into build output")
		case read[s.Path] || slices.ContainsFunc(trees, func(t string) bool { return strings.HasPrefix(s.Path, t+"/") }):
		default:
			out = append(out, s.Path+" is a Gradle build file no project of the build reads")
		}
	}
	return out, nil
}

// mavenPlugins are the plugins whose goals install only what dependency:tree lists, each with the
// goals that do, or nil for all of its goals. A bound execution of any other plugin or goal
// withholds Complete; so does a build extension, which can rebind the lifecycle.
var mavenPlugins = map[string]map[string]bool{
	"org.apache.maven.plugins:maven-clean-plugin":                nil,
	"org.apache.maven.plugins:maven-resources-plugin":            setOf("resources", "testResources", "copy-resources"),
	"org.apache.maven.plugins:maven-compiler-plugin":             nil,
	"org.apache.maven.plugins:maven-surefire-plugin":             nil,
	"org.apache.maven.plugins:maven-failsafe-plugin":             nil,
	"org.apache.maven.plugins:maven-jar-plugin":                  nil,
	"org.apache.maven.plugins:maven-war-plugin":                  nil,
	"org.apache.maven.plugins:maven-ear-plugin":                  nil,
	"org.apache.maven.plugins:maven-ejb-plugin":                  nil,
	"org.apache.maven.plugins:maven-shade-plugin":                nil,
	"org.apache.maven.plugins:maven-source-plugin":               nil,
	"org.apache.maven.plugins:maven-javadoc-plugin":              nil,
	"org.apache.maven.plugins:maven-install-plugin":              nil,
	"org.apache.maven.plugins:maven-deploy-plugin":               nil,
	"org.apache.maven.plugins:maven-site-plugin":                 nil,
	"org.apache.maven.plugins:maven-enforcer-plugin":             nil,
	"org.apache.maven.plugins:maven-checkstyle-plugin":           nil,
	"org.apache.maven.plugins:maven-project-info-reports-plugin": nil,
	"org.apache.maven.plugins:maven-jxr-plugin":                  nil,
	"org.apache.maven.plugins:maven-gpg-plugin":                  nil,
	"org.apache.maven.plugins:maven-help-plugin":                 nil,
	"org.apache.maven.plugins:maven-toolchains-plugin":           nil,
	"org.apache.maven.plugins:maven-plugin-plugin":               nil,
	// copy, unpack and get install an artifact the tree never lists; these act on the tree.
	"org.apache.maven.plugins:maven-dependency-plugin": setOf("tree", "list", "analyze", "analyze-only", "analyze-report",
		"analyze-dep-mgt", "analyze-duplicate", "analyze-exclusions", "resolve", "resolve-plugins", "sources", "go-offline",
		"build-classpath", "properties", "copy-dependencies", "unpack-dependencies", "display-ancestors", "collect",
		"list-repositories"),
	"org.codehaus.mojo:build-helper-maven-plugin": setOf("add-source", "add-test-source", "add-resource", "add-test-resource",
		"parse-version", "regex-property", "regex-properties", "timestamp-property", "uptodate-property", "uptodate-properties",
		"cpu-count", "local-ip", "reserve-network-port", "rootlocation", "maven-version", "released-version"),
	"org.codehaus.mojo:versions-maven-plugin":                   nil,
	"org.codehaus.mojo:license-maven-plugin":                    nil,
	"org.jacoco:jacoco-maven-plugin":                            nil,
	"org.springframework.boot:spring-boot-maven-plugin":         nil,
	"com.google.cloud.tools:jib-maven-plugin":                   nil,
	"org.openapitools:openapi-generator-maven-plugin":           nil,
	"org.apache.rat:apache-rat-plugin":                          nil,
	"org.hjug.refactorfirst.plugin:refactor-first-maven-plugin": nil,
	"io.spring.javaformat:spring-javaformat-maven-plugin":       nil,
	"pl.project13.maven:git-commit-id-plugin":                   nil,
	"io.github.git-commit-id:git-commit-id-maven-plugin":        nil,
	"com.gitlab.haynes:libsass-maven-plugin":                    nil,
}

// mavenSourceDirs are the configuration elements naming a directory a plugin copies into what the
// build installs; each must be inside the checkout.
var mavenSourceDirs = setOf("directory", "warSourceDirectory", "classesDirectory", "earSourceDirectory")

// mavenIncomplete lists what keeps a Maven graph from being Complete: a POM the reactor does not
// read; a build extension; a bound execution of a plugin or goal off mavenPlugins; dependency
// plugin configuration naming artifacts outside the tree; and a resource or source directory
// outside the checkout or in a local repository.
func mavenIncomplete(dir string, outputs []string, modules []Module, reactor []reactorProject, effective []effectiveProject) ([]string, error) {
	var reasons []string
	orphans, err := mavenOrphanPOMs(dir, outputs, reactor)
	if err != nil {
		return nil, err
	}
	reasons = append(reasons, orphans...)
	if _, err := os.Stat(filepath.Join(dir, ".mvn", "extensions.xml")); err == nil {
		reasons = append(reasons, ".mvn/extensions.xml loads build extensions")
	}
	repos := mavenRepos(modules)
	moduleDir := map[string]string{}
	for _, rp := range reactor {
		moduleDir[rp.key] = filepath.Join(dir, filepath.FromSlash(path.Dir(rp.file)))
	}
	for _, p := range effective {
		who := p.GroupID + ":" + p.ArtifactID
		base, ok := moduleDir[who]
		if !ok {
			return nil, &Failure{Kind: KindToolFailed, Detail: stepGraph, Log: "effective POM of " + who + " matches no module"}
		}
		inside := func(what, v string) {
			v = strings.TrimSpace(v)
			if v == "" {
				return
			}
			if strings.Contains(v, "${") {
				reasons = append(reasons, who+": "+what+" "+v+" is not interpolated")
				return
			}
			if !filepath.IsAbs(v) {
				v = filepath.Join(base, filepath.FromSlash(v))
			}
			if !within(dir, v) {
				reasons = append(reasons, who+": "+what+" "+v+" is outside the checkout")
				return
			}
			// A local repository inside the checkout holds what Maven fetched, not the checkout's.
			if slices.ContainsFunc(repos, func(r string) bool { return within(r, v) }) {
				reasons = append(reasons, who+": "+what+" "+v+" is in the local repository")
			}
		}
		for _, e := range p.Build.Extensions.Extension {
			reasons = append(reasons, who+": build extension "+e.GroupID+":"+e.ArtifactID)
		}
		for _, r := range append(slices.Clone(p.Build.Resources.Resource), p.Build.TestResources.Resource...) {
			inside("resource directory", r.Directory)
		}
		for _, pl := range p.Build.Plugins.Plugin {
			key := pl.key()
			goals, listed := mavenPlugins[key]
			if !listed {
				for _, ex := range pl.Executions.Execution {
					if ex.bound() {
						reasons = append(reasons, who+": "+key+" execution "+ex.ID+" is not a plugin whose installs the graph lists")
					}
				}
				continue
			}
			if pl.ArtifactID == "maven-dependency-plugin" {
				// Plugin-level or default-cli artifacts are what a command-line copy, unpack or get
				// installs: a POM configured for one is a build that runs it.
				if pl.Configuration.has("artifactItems") || pl.Configuration.has("artifact") {
					reasons = append(reasons, who+": "+key+" configures artifacts outside the tree")
				}
			}
			for _, d := range configValues(pl.Configuration.Inner, mavenSourceDirs) {
				inside(key+" directory", d)
			}
			for _, ex := range pl.Executions.Execution {
				if ex.ID == "default-cli" && pl.ArtifactID == "maven-dependency-plugin" && (ex.Configuration.has("artifactItems") || ex.Configuration.has("artifact")) {
					reasons = append(reasons, who+": "+key+" execution default-cli configures artifacts outside the tree")
				}
				if !ex.bound() {
					continue
				}
				for _, g := range ex.Goals.Goal {
					if g = strings.TrimSpace(g); goals != nil && !goals[g] {
						reasons = append(reasons, who+": "+key+":"+g+" (execution "+ex.ID+") installs what the graph does not list")
					}
				}
				for _, d := range configValues(ex.Configuration.Inner, mavenSourceDirs) {
					inside(key+" directory", d)
				}
			}
		}
	}
	return sortedUnique(reasons), nil
}

// key is the plugin's groupId:artifactId; an effective POM may leave out Maven's own group.
func (pl effectivePlugin) key() string {
	g := strings.TrimSpace(pl.GroupID)
	if g == "" {
		g = "org.apache.maven.plugins"
	}
	return g + ":" + strings.TrimSpace(pl.ArtifactID)
}

// bound reports whether the execution runs in the build: it names a goal and is not disabled by
// binding it to phase none.
func (ex effectiveExecution) bound() bool {
	return len(ex.Goals.Goal) > 0 && strings.TrimSpace(ex.Phase) != "none"
}

// configValues is the text of every element of a plugin configuration named in names, at any
// depth.
func configValues(inner string, names map[string]bool) []string {
	var out []string
	dec := xml.NewDecoder(strings.NewReader("<c>" + inner + "</c>"))
	var stack []string
	var text bytes.Buffer
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out
		}
		if err != nil {
			// An unparseable configuration names nothing this can check; the build would not
			// have run it either.
			return append(out, "${unparseable}")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if len(stack) > 0 && names[stack[len(stack)-1]] {
				out = append(out, text.String())
			}
			stack = stack[:len(stack)-1]
			text.Reset()
		}
	}
}

// rawPOM is what mavenOrphanPOMs reads from a POM as written.
type rawPOM struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Parent     *struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
}

func readRawPOM(file string) (rawPOM, error) {
	var p rawPOM
	b, err := os.ReadFile(file)
	if err != nil {
		return p, err
	}
	err = xml.Unmarshal(b, &p)
	return p, err
}

// mavenOrphanPOMs lists the POMs under dir that are neither a reactor module's nor a parent one
// reaches through its relativePath: a separate build, whose dependencies the graph never resolved.
func mavenOrphanPOMs(dir string, outputs []string, reactor []reactorProject) ([]string, error) {
	read := map[string]bool{}
	var queue []string
	for _, rp := range reactor {
		read[rp.file] = true
		queue = append(queue, rp.file)
	}
	for len(queue) > 0 {
		rel := queue[0]
		queue = queue[1:]
		p, err := readRawPOM(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil || p.Parent == nil {
			continue
		}
		rp := "../pom.xml"
		if p.Parent.RelativePath != nil {
			rp = strings.TrimSpace(*p.Parent.RelativePath)
		}
		if rp == "" {
			continue
		}
		target := path.Clean(path.Join(path.Dir(rel), filepath.ToSlash(rp)))
		if !strings.HasSuffix(target, ".xml") {
			target = path.Join(target, "pom.xml")
		}
		if read[target] || !cleanRel(target) && target != "pom.xml" {
			continue
		}
		parent, err := readRawPOM(filepath.Join(dir, filepath.FromSlash(target)))
		if err != nil {
			continue
		}
		group := parent.GroupID
		if group == "" && parent.Parent != nil {
			group = parent.Parent.GroupID
		}
		// Maven takes the file only when it is the parent named; otherwise it reads the parent
		// from a repository, and the file is no input of this build.
		if strings.TrimSpace(group) != strings.TrimSpace(p.Parent.GroupID) || strings.TrimSpace(parent.ArtifactID) != strings.TrimSpace(p.Parent.ArtifactID) {
			continue
		}
		read[target] = true
		queue = append(queue, target)
	}
	poms, err := treeFiles(dir, outputs, func(rel, name string) bool { return name == "pom.xml" })
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range poms {
		switch {
		case p.Escapes:
			out = append(out, p.Path+" links to a directory outside the checkout or into build output")
		case !read[p.Path]:
			out = append(out, p.Path+" is a POM the reactor does not read")
		}
	}
	return out, nil
}

// mavenOutputs are the directories inside the checkout a Maven build writes or caches into: each
// module's build directory (target unless the effective POM says otherwise) and the local
// repository, when the graph's artifacts show it is inside the checkout.
func mavenOutputs(dir string, reactor []reactorProject, effective []effectiveProject, modules []Module) []string {
	var out []string
	add := func(p string) {
		if rel, ok := realRel(dir, p); p != "" && ok && rel != "." {
			out = append(out, rel)
		}
	}
	buildDir := map[string]string{}
	for _, e := range effective {
		buildDir[strings.TrimSpace(e.GroupID)+":"+strings.TrimSpace(e.ArtifactID)] = strings.TrimSpace(e.Build.Directory)
	}
	for _, rp := range reactor {
		d := buildDir[rp.key]
		if d == "" {
			d = filepath.Join(dir, filepath.FromSlash(path.Dir(rp.file)), "target")
		}
		add(d)
	}
	for _, repo := range mavenRepos(modules) {
		add(repo)
	}
	return sortedUnique(out)
}

// LocalRepositories are the local repository directories a Maven graph's artifact files lie in,
// as the tool resolved them. Another tool's graph has none: its files are not laid out by a Maven
// local repository, and one in the checkout can be the project's own.
func LocalRepositories(g *Graph) []string {
	if g == nil || g.Tool.Name != ToolMaven {
		return nil
	}
	return mavenRepos(g.Modules)
}

// mavenRepos are the local repository directories the graph's artifacts lie in.
func mavenRepos(modules []Module) []string {
	var out []string
	for _, m := range modules {
		for _, n := range m.Nodes {
			if repo, ok := mavenRepoOf(n); ok {
				out = append(out, repo)
			}
		}
	}
	return sortedUnique(out)
}

// mavenRepoOf is the repository directory n's file lies in, laid out
// <group>/<artifact>/<version>/<file>; false for a file not so laid out, and for a system-scoped
// one, whose path the POM names.
func mavenRepoOf(n Node) (string, bool) {
	if n.File == nil || n.Scope == "system" || n.Group == "" || n.Artifact == "" || n.Version == "" {
		return "", false
	}
	d := filepath.Dir(filepath.Clean(n.File.Path))
	if filepath.Base(d) != n.Version {
		return "", false
	}
	d = filepath.Dir(d)
	if filepath.Base(d) != n.Artifact {
		return "", false
	}
	d = filepath.Dir(d)
	group := strings.Split(n.Group, ".")
	for i := len(group) - 1; i >= 0; i-- {
		if filepath.Base(d) != group[i] {
			return "", false
		}
		d = filepath.Dir(d)
	}
	return d, true
}

// treeEntry is a file treeFiles lists, or a directory link leaving the tree (Escapes).
type treeEntry struct {
	Path    string
	Escapes bool
}

// treeFiles lists the files under dir that match accepts, by slash path from dir once symlinks in
// dir are resolved. It skips the outputs (slash paths from dir; any that is not a clean relative
// path counts for nothing), .git, and a node_modules beside a package.json: nothing else, whatever
// its name. A build follows symlinks, so a link is listed by its own name whatever it points at.
// A directory link is not walked: its target is walked where it lies when that is inside dir and
// not skipped, and otherwise the link hides what it holds and is listed as Escapes, unless the
// link itself is an output.
func treeFiles(dir string, outputs []string, match func(rel, name string) bool) ([]treeEntry, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: "inputs", Log: err.Error()}
	}
	prune := map[string]bool{}
	for _, o := range outputs {
		if cleanRel(o) {
			prune[o] = true
		}
	}
	skipped := func(rel string) bool {
		if prune[rel] {
			return true
		}
		switch path.Base(rel) {
		case ".git":
			return true
		case "node_modules":
			_, err := os.Stat(filepath.Join(root, filepath.FromSlash(path.Dir(rel)), "package.json"))
			return err == nil
		}
		return false
	}
	// under reports whether rel is a skipped directory or inside one.
	under := func(rel string) bool {
		for p := rel; p != "." && p != "/"; p = path.Dir(p) {
			if skipped(p) {
				return true
			}
		}
		return false
	}
	var out []treeEntry
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipped(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if t, err := filepath.EvalSymlinks(p); err == nil {
				if fi, err := os.Stat(t); err == nil && fi.IsDir() {
					if !prune[rel] {
						if trel, inside := relPath(root, t); !inside || trel == "." || under(trel) {
							out = append(out, treeEntry{Path: rel, Escapes: true})
						}
					}
					return nil
				}
			}
		} else if !d.Type().IsRegular() {
			return nil
		}
		if match(rel, d.Name()) {
			out = append(out, treeEntry{Path: rel})
		}
		return nil
	})
	if err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: "inputs", Log: err.Error()}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// graphFiles is every artifact file g's nodes hold.
func graphFiles(g *Graph) map[string]bool {
	files := map[string]bool{}
	for _, m := range g.Modules {
		for _, n := range m.Nodes {
			if n.File != nil {
				files[n.File.Path] = true
			}
		}
	}
	return files
}

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func sortedUnique(xs []string) []string {
	sort.Strings(xs)
	return slices.Compact(xs)
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// wrapperJars are the archives a checkout carries to launch its build tool, not to install into
// what it builds.
var wrapperJars = setOf("gradle/wrapper/gradle-wrapper.jar", ".mvn/wrapper/maven-wrapper.jar")

// archiveExts are the files a build can package, unpack or load classes from as they stand.
var archiveExts = setOf(".jar", ".war", ".ear", ".zip", ".aar", ".jmod", ".rar", ".class")

// CheckedInArchives lists the archives and class files in dir, outside the directories g records
// as the build's outputs, that g holds as no node's file: what the build can package or load
// without resolving it, which g would then not list. A system-scoped dependency or a files()
// dependency is a node, and the build tool's wrapper JAR installs nothing. A local repository
// kept in the checkout (CI caches set one) is an output when g's artifacts lie in it: what the
// build takes from it, it resolved and g lists. A graph recording no outputs has every directory
// walked, build output too.
func CheckedInArchives(dir string, g *Graph) ([]string, error) {
	held := map[string]bool{}
	for f := range graphFiles(g) {
		if r, err := evalExisting(f); err == nil {
			held[r] = true
		}
	}
	archives, err := treeFiles(dir, g.Subject.Outputs, func(rel, name string) bool {
		return archiveExts[strings.ToLower(path.Ext(name))] && !wrapperJars[rel]
	})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range archives {
		r, err := evalExisting(filepath.Join(dir, filepath.FromSlash(a.Path)))
		if err != nil || !held[r] {
			out = append(out, a.Path)
		}
	}
	return out, nil
}
