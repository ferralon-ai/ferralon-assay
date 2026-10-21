package buildgraph

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The round trips below run a real Maven or Gradle over the testdata fixtures and check the
// producer's graph against the tool's own report. They need the network and a JDK, so they run
// only when ASSAY_BUILDGRAPH_MAVEN_BIN or ASSAY_BUILDGRAPH_GRADLE_BIN names the tool's bin
// directory; JAVA_HOME comes from the environment.

func realToolEnv(t *testing.T, binVar string) []string {
	t.Helper()
	bin := os.Getenv(binVar)
	if bin == "" {
		t.Skip(binVar + " unset")
	}
	path := bin + string(os.PathListSeparator) + os.Getenv("PATH")
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		path = filepath.Join(jh, "bin") + string(os.PathListSeparator) + path
	}
	return environ(os.Environ(), map[string]string{"PATH": path})
}

// copyFixture copies a testdata fixture so the tool's own writes stay out of the source tree.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	dst := filepath.Join(t.TempDir(), name)
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestMavenRoundTrip(t *testing.T) {
	env := realToolEnv(t, "ASSAY_BUILDGRAPH_MAVEN_BIN")
	for _, profiles := range [][]string{nil, {"extra"}} {
		t.Run(strings.Join(profiles, ","), func(t *testing.T) {
			dir := copyFixture(t, "maven-reactor")
			g, err := Resolve(context.Background(), Request{Dir: dir, Tool: ToolMaven, Conditions: Conditions{Profiles: profiles}, WorkDir: filepath.Join(t.TempDir(), "w"), Env: env})
			if err != nil {
				t.Fatalf("resolve: %v: %s", cause(err), err.(*Failure).Log)
			}
			if len(g.Modules) != 5 {
				t.Fatalf("modules %d", len(g.Modules))
			}
			if !g.Complete {
				t.Errorf("not Complete: %q", g.Incomplete)
			}
			// Whether the log named the POMs (3.8.8 and later) or reactor_paths asked for them,
			// each module sits in its own directory.
			for _, m := range g.Modules {
				want := strings.TrimPrefix(m.ID, "com.ferralon.benchmark:")
				if m.ID == "com.ferralon.benchmark:maven-reactor-divergence" {
					want = "."
				}
				if m.Path != want {
					t.Errorf("module %s at %q", m.ID, m.Path)
				}
			}
			evals := 0
			for _, cmd := range g.Commands {
				if cmd.Step == stepReactorPaths {
					evals++
				}
			}
			if evals != 0 && evals != 2*len(g.Modules)+1 {
				t.Errorf("%d reactor_paths evaluations for %d modules", evals, len(g.Modules))
			}
			t.Logf("maven %s: %d reactor_paths evaluations", g.Tool.Version, evals)
			c := module(t, g, "com.ferralon.benchmark:module-c")
			_, hasText := nodeIDs(c)["org.apache.commons:commons-text:jar:1.12.0"]
			if hasText != (len(profiles) == 1) {
				t.Errorf("commons-text present %v under profiles %v", hasText, profiles)
			}
			// Modules without a sibling dependency can be listed on the real reactor; the
			// generated reactor must have resolved every node to the very same file.
			for _, id := range []string{"module-a", "module-b", "module-d"} {
				m := module(t, g, "com.ferralon.benchmark:"+id)
				want := realMavenList(t, env, dir, id, profiles)
				got := map[string]string{}
				for _, n := range m.Nodes {
					if n.File != nil {
						got[n.ID] = n.File.Path
					}
				}
				if !equalMaps(got, want) {
					t.Errorf("%s: producer %v\nreal list %v", id, got, want)
				}
			}
		})
	}
}

// TestMavenComplete runs the real Maven over edits of maven-reactor that each install something
// dependency:tree does not list, and checks that the producer withholds Complete for it.
func TestMavenComplete(t *testing.T) {
	env := realToolEnv(t, "ASSAY_BUILDGRAPH_MAVEN_BIN")
	plugin := func(xml string) map[string]string {
		return map[string]string{"module-a/pom.xml": "<build><plugins>" + xml + "</plugins></build>"}
	}
	for _, tc := range []struct {
		name string
		edit map[string]string // file -> XML inserted before its closing </project>
		add  map[string]string // files written as is
		want string
	}{
		{
			name: "bound antrun execution",
			edit: plugin(`<plugin><artifactId>maven-antrun-plugin</artifactId><version>3.1.0</version><executions><execution><id>fetch</id><phase>package</phase><goals><goal>run</goal></goals></execution></executions></plugin>`),
			want: "maven-antrun-plugin execution fetch is not a plugin whose installs the graph lists",
		},
		{
			name: "dependency copy",
			edit: plugin(`<plugin><artifactId>maven-dependency-plugin</artifactId><version>3.8.1</version><executions><execution><id>agent</id><phase>package</phase><goals><goal>copy</goal></goals><configuration><artifactItems><artifactItem><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.16</version></artifactItem></artifactItems></configuration></execution></executions></plugin>`),
			want: "maven-dependency-plugin",
		},
		{
			name: "execution disabled by phase none",
			edit: plugin(`<plugin><artifactId>maven-antrun-plugin</artifactId><version>3.1.0</version><executions><execution><id>fetch</id><phase>none</phase><goals><goal>run</goal></goals></execution></executions></plugin>`),
		},
		{
			name: "POM the reactor does not read",
			add:  map[string]string{"tools/pom.xml": "<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>tools</artifactId><version>1</version></project>\n"},
			want: "tools/pom.xml is a POM the reactor does not read",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyFixture(t, "maven-reactor")
			for name, xml := range tc.edit {
				p := filepath.Join(dir, name)
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				i := bytes.LastIndex(b, []byte("</project>"))
				if i < 0 || bytes.Contains(b, []byte("<build>")) {
					t.Fatalf("%s: no </project>, or a <build> already", name)
				}
				if err := os.WriteFile(p, append(append(b[:i:i], xml...), b[i:]...), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			writeFiles(t, dir, tc.add)
			g, err := Resolve(context.Background(), Request{Dir: dir, Tool: ToolMaven, WorkDir: filepath.Join(t.TempDir(), "w"), Env: env})
			if err != nil {
				t.Fatalf("resolve: %v: %s", cause(err), err.(*Failure).Log)
			}
			t.Logf("maven %s: incomplete %q", g.Tool.Version, g.Incomplete)
			switch {
			case tc.want == "" && !g.Complete:
				t.Errorf("not Complete: %q", g.Incomplete)
			case tc.want != "" && (g.Complete || len(g.Incomplete) == 0 || slices.ContainsFunc(g.Incomplete, func(r string) bool { return !strings.Contains(r, tc.want) })):
				t.Errorf("incomplete %q, want only reasons with %q", g.Incomplete, tc.want)
			}
		})
	}
}

func realMavenList(t *testing.T, env []string, dir, module string, profiles []string) map[string]string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "list.txt")
	args := []string{"-B", "-q", "-pl", module}
	if len(profiles) > 0 {
		args = append(args, "-P", strings.Join(profiles, ","))
	}
	args = append(args, mavenDependency+":list", "-DoutputAbsoluteArtifactFilename=true", "-DoutputFile="+out)
	cmd := exec.Command(toolPath(t, "mvn", env), args...)
	cmd.Dir, cmd.Env = dir, env
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real list %s: %v\n%s", module, err, b)
	}
	m, err := parseList([]byte(readFile(t, out)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestGradleRoundTrip(t *testing.T) {
	env := realToolEnv(t, "ASSAY_BUILDGRAPH_GRADLE_BIN")
	dir := copyFixture(t, "gradle-multi")
	g, err := Resolve(context.Background(), Request{Dir: dir, Tool: ToolGradle, WorkDir: filepath.Join(t.TempDir(), "w"), Env: env})
	if err != nil {
		t.Fatalf("resolve: %v: %s", cause(err), err.(*Failure).Log)
	}
	for _, p := range []string{":app", ":kt", ":lib"} {
		m := module(t, g, p)
		// Each classpath as the real tool reports it, by g:a:v.
		runtime := realGradleDependencies(t, env, dir, p, gradleRuntime, g.Modules)
		compile := realGradleDependencies(t, env, dir, p, gradleCompile, g.Modules)
		test := realGradleDependencies(t, env, dir, p, gradleTest, g.Modules)
		ga := func(set map[string]string) map[string]bool {
			out := map[string]bool{}
			for k := range set {
				out[k[:strings.LastIndex(k, ":")]] = true
			}
			return out
		}
		onRuntime, onCompile := ga(runtime), ga(compile)
		want := map[string]map[string]string{"runtime": {}, "compile": {}, "provided": {}, "test": {}}
		for k := range runtime {
			if onCompile[k[:strings.LastIndex(k, ":")]] {
				want["compile"][k] = ""
			} else {
				want["runtime"][k] = ""
			}
		}
		for k := range compile {
			if !onRuntime[k[:strings.LastIndex(k, ":")]] {
				want["provided"][k] = ""
			}
		}
		for k := range test {
			if g := k[:strings.LastIndex(k, ":")]; !onRuntime[g] && !onCompile[g] {
				want["test"][k] = ""
			}
		}
		got := map[string]map[string]string{"runtime": {}, "compile": {}, "provided": {}, "test": {}, "other": {}}
		for _, n := range m.Nodes {
			if n.ID != m.Root {
				got[n.Scope][n.Group+":"+n.Artifact+":"+n.Version] = ""
			}
		}
		for scope := range want {
			if !equalMaps(got[scope], want[scope]) {
				t.Errorf("%s %s: producer %v\nreal dependencies %v", p, scope, keys(got[scope]), keys(want[scope]))
			}
		}
		if _, ok := got["other"]["org.slf4j:slf4j-api:2.0.16"]; ok != (p == ":app") {
			t.Errorf("%s: agent configuration at other scope = %v, producer %v", p, ok, keys(got["other"]))
		}
		if len(m.Unlisted) > 0 {
			t.Errorf("%s: unlisted %v", p, m.Unlisted)
		}
		t.Logf("%s: %d compile, %d runtime, %d provided, %d test, %d other", p, len(got["compile"]), len(got["runtime"]), len(got["provided"]), len(got["test"]), len(got["other"]))
	}
}

var (
	gradleDepLine  = regexp.MustCompile(`^[| ]*[+\\]--- (.+)$`)
	gradleSelected = regexp.MustCompile(`^([^:\s]+):([^:\s]+):(\S+?)(?: -> (\S+))?(?: \([*cn]\))?$`)
	// Gradle 9 quotes the project path: `project ':lib'`; Gradle 8 does not.
	gradleProjDep = regexp.MustCompile(`^project '?([^'\s]+)'?(?: \(\*\))?$`)
)

// realGradleDependencies reads `gradle <p>:dependencies --configuration <config>` into the g:a:v
// set it selects, with sibling projects by their coordinates.
func realGradleDependencies(t *testing.T, env []string, dir, project, config string, modules []Module) map[string]string {
	t.Helper()
	cmd := exec.Command(toolPath(t, "gradle", env), "-q", "--no-configuration-cache", "--project-cache-dir", filepath.Join(t.TempDir(), "pc"), project+":dependencies", "--configuration", config)
	cmd.Dir, cmd.Env = dir, env
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real dependencies %s: %v\n%s", project, err, b)
	}
	sibling := map[string]string{}
	for _, m := range modules {
		r := strings.Split(m.Root, ":")
		sibling[m.ID] = r[0] + ":" + r[1] + ":" + r[len(r)-1]
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		m := gradleDepLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if p := gradleProjDep.FindStringSubmatch(m[1]); p != nil {
			out[sibling[p[1]]] = ""
			continue
		}
		if strings.HasSuffix(m[1], "(c)") || strings.HasSuffix(m[1], "(n)") {
			continue
		}
		s := gradleSelected.FindStringSubmatch(m[1])
		if s == nil {
			t.Fatalf("unreadable dependency line %q", m[1])
		}
		v := s[3]
		if s[4] != "" {
			v = s[4]
		}
		out[s[1]+":"+s[2]+":"+v] = ""
	}
	return out
}

// toolPath finds the tool on the PATH the test hands it, not the test process's own.
func toolPath(t *testing.T, name string, env []string) string {
	t.Helper()
	p, err := lookPath(name, env)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return p
}

func nodeIDs(m Module) map[string]bool {
	out := map[string]bool{}
	for _, n := range m.Nodes {
		out[n.ID] = true
	}
	return out
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestGradleIncludedBuildsRoundTrip resolves a build that includes a plugin build, a library
// build, and a build only the library build includes, which the root build never lists.
func TestGradleIncludedBuildsRoundTrip(t *testing.T) {
	env := realToolEnv(t, "ASSAY_BUILDGRAPH_GRADLE_BIN")
	root := t.TempDir()
	dir := filepath.Join(root, "repo")
	writeFiles(t, root, map[string]string{
		"outside/settings.gradle":      "rootProject.name = 'outside'\n",
		"outside/src/main/java/O.java": "class O {}\n",
	})
	writeFiles(t, dir, map[string]string{
		"settings.gradle":                              "pluginManagement { includeBuild('build-logic') }\nrootProject.name = 'root'\nincludeBuild('libs/core')\nincludeBuild('../outside')\n",
		"build.gradle":                                 "plugins {\n    id 'java'\n    id 'acme.conv'\n}\n",
		"build-logic/settings.gradle":                  "rootProject.name = 'build-logic'\n",
		"build-logic/build.gradle":                     "plugins { id 'groovy-gradle-plugin' }\n",
		"build-logic/src/main/groovy/acme.conv.gradle": "// a convention plugin the root build applies, so Gradle compiles build-logic\n",
		"libs/core/settings.gradle":                    "rootProject.name = 'core'\nincludeBuild('../../nested')\n",
		"nested/settings.gradle":                       "rootProject.name = 'nested'\n",
		"nested/src/main/java/N.java":                  "class N {}\n",
		"buildSrc/src/main/groovy/acme/build/B.groovy": "package acme.build\nclass B {}\n",
	})
	g, err := Resolve(context.Background(), Request{Dir: dir, Tool: ToolGradle, WorkDir: filepath.Join(t.TempDir(), "w"), Env: env})
	if err != nil {
		t.Fatalf("resolve: %v: %s", cause(err), err.(*Failure).Log)
	}
	if want := []string{"build-logic", "buildSrc", "libs/core", "nested"}; !reflect.DeepEqual(g.Subject.IncludedBuilds, want) {
		t.Fatalf("included builds %v, want %v", g.Subject.IncludedBuilds, want)
	}
	// Real output beside build logic, including a buildSrc with no build script, is not an input.
	for _, out := range []string{"build-logic/build", "buildSrc/build"} {
		if fi, err := os.Stat(filepath.Join(dir, out)); err != nil || !fi.IsDir() {
			t.Fatalf("%s: Gradle produced no build output: %v", out, err)
		}
	}
	for _, in := range g.Subject.Inputs {
		if strings.HasPrefix(in.Path, "build-logic/build/") || strings.HasPrefix(in.Path, "buildSrc/build/") {
			t.Fatalf("build output recorded as an input: %s", in.Path)
		}
	}
	outside, err := filepath.EvalSymlinks(filepath.Join(root, "outside"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.ToSlash(outside)}; !reflect.DeepEqual(g.Subject.UnbindableIncludedBuilds, want) {
		t.Fatalf("unbindable included builds %v, want %v", g.Subject.UnbindableIncludedBuilds, want)
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file, dir, Conditions{}); cause(err) != "graph_rejected:subject_inputs" {
		t.Fatalf("Load of a file with an outside included build: %q", cause(err))
	}
	if _, err := Load(file, dir, Conditions{}, Fresh()); err != nil {
		t.Fatalf("Load fresh: %v", cause(err))
	}
	for _, edit := range []string{"nested/src/main/java/N.java", "buildSrc/src/main/groovy/acme/build/B.groovy"} {
		was, err := os.ReadFile(filepath.Join(dir, edit))
		if err != nil {
			t.Fatal(err)
		}
		writeFiles(t, dir, map[string]string{edit: "class Edited {}\n"})
		if _, err := Load(file, dir, Conditions{}, Fresh()); cause(err) != "graph_rejected:subject_inputs" {
			t.Fatalf("Load after editing %s: %q", edit, cause(err))
		}
		writeFiles(t, dir, map[string]string{edit: string(was)})
	}
}

// TestGradleComplete runs the real Gradle over edits of gradle-multi, each adding one way a build
// can install what its configurations do not list, and checks that the producer withholds
// Complete for it and only for it.
func TestGradleComplete(t *testing.T) {
	env := realToolEnv(t, "ASSAY_BUILDGRAPH_GRADLE_BIN")
	simple := "configurations.detachedConfiguration(dependencies.create('org.slf4j:slf4j-simple:2.0.16'))"
	for _, tc := range []struct {
		name       string
		append     map[string]string
		homeInside bool   // GRADLE_USER_HOME inside the checkout, as CI caches set it
		want       string // a substring of every reason expected; empty means Complete
		check      func(t *testing.T, g *Graph)
	}{
		{name: "fixture as is"},
		{name: "fixture with the user home inside the checkout", homeInside: true},
		{
			name:   "Exec another task must run after",
			append: map[string]string{"app/build.gradle": "def gen = tasks.register('gen', Exec) { commandLine 'true' }\ntasks.named('jar') { mustRunAfter gen }\n"},
			want:   "task :app:gen runs a program (org.gradle.api.tasks.Exec) that another task depends on",
		},
		{
			name:   "Exec another task should run after",
			append: map[string]string{"app/build.gradle": "def gen = tasks.register('gen', Exec) { commandLine 'true' }\ntasks.named('jar') { shouldRunAfter gen }\n"},
			want:   "task :app:gen runs a program (org.gradle.api.tasks.Exec) that another task depends on",
		},
		{
			name: "Zip of the build script classpath",
			append: map[string]string{
				"settings.gradle": "include 'bz'\n",
				"bz/build.gradle": "buildscript { repositories { mavenCentral() }; dependencies { classpath 'org.slf4j:slf4j-simple:2.0.16' } }\n" +
					"plugins.apply('base')\ntasks.register('z', Zip) { from buildscript.configurations.classpath; archiveFileName = 'z.zip'; destinationDirectory = layout.buildDirectory }\n",
			},
			want: "slf4j-simple-2.0.16.jar, outside the build",
		},
		{
			name: "Zip of the build script classpath with the user home inside the checkout",
			append: map[string]string{
				"settings.gradle": "include 'bz'\n",
				"bz/build.gradle": "buildscript { repositories { mavenCentral() }; dependencies { classpath 'org.slf4j:slf4j-simple:2.0.16' } }\n" +
					"plugins.apply('base')\ntasks.register('z', Zip) { from buildscript.configurations.classpath; archiveFileName = 'z.zip'; destinationDirectory = layout.buildDirectory }\n",
			},
			homeInside: true,
			want:       "slf4j-simple-2.0.16.jar, outside the build",
		},
		{
			name: "detached configuration with an unresolved project selector",
			append: map[string]string{"app/build.gradle": "configurations.detachedConfiguration(dependencies.create(project(path: ':lib', configuration: 'nope')), " +
				"dependencies.create('org.slf4j:slf4j-api:2.0.16')).incoming.artifactView { lenient(true) }.files.files\n"},
		},
		{
			name: "detached configuration with an unresolved project selector and a file that does not download",
			append: map[string]string{"app/build.gradle": "configurations.detachedConfiguration(dependencies.create(project(path: ':lib', configuration: 'nope')), " +
				"dependencies.create('org.slf4j:slf4j-api:2.0.16:nope')).incoming.artifactView { lenient(true) }.files.files\n"},
			want: "resolution of :app:detachedConfiguration1 failed",
		},
		{
			name:   "script action on an ad-hoc task",
			append: map[string]string{"app/build.gradle": "tasks.register('hello') { doLast { println 'hello' } }\n"},
			want:   "task :app:hello has an action added by",
		},
		{
			name:   "script action on jar",
			append: map[string]string{"app/build.gradle": "jar { doLast { println 'packed' } }\n"},
			want:   "task :app:jar has an action added by",
		},
		{
			name:   "script action on jar, Kotlin DSL",
			append: map[string]string{"kt/build.gradle.kts": "tasks.named(\"jar\") { doLast { println(\"packed\") } }\n"},
			want:   "task :kt:jar has an action added by",
		},
		{
			name:   "script-defined task type",
			append: map[string]string{"app/build.gradle": "class Fetch extends DefaultTask { @TaskAction void go() {} }\ntasks.register('fetch', Fetch)\n"},
			want:   "task :app:fetch has type Fetch",
		},
		{
			name:   "Exec another task depends on",
			append: map[string]string{"app/build.gradle": "def gen = tasks.register('gen', Exec) { commandLine 'true' }\ntasks.named('compileJava') { dependsOn gen }\n"},
			want:   "task :app:gen runs a program (org.gradle.api.tasks.Exec) that another task depends on",
		},
		{
			name:   "JavaExec leaf",
			append: map[string]string{"app/build.gradle": "tasks.register('runIt', JavaExec) { mainClass = 'Main'; classpath = sourceSets.main.runtimeClasspath }\n"},
		},
		{
			name: "JavaExec finalized by a packaging task",
			append: map[string]string{"app/build.gradle": "tasks.register('runIt', JavaExec) { mainClass = 'Main'; classpath = sourceSets.main.runtimeClasspath; finalizedBy 'pack' }\n" +
				"tasks.register('pack', Zip) { from layout.buildDirectory.dir('gen'); archiveFileName = 'p.zip'; destinationDirectory = layout.buildDirectory }\n"},
			want: "task :app:runIt runs a program (org.gradle.api.tasks.JavaExec) finalized by :app:pack",
		},
		{
			name: "Exec whose outputs a task reads",
			append: map[string]string{"app/build.gradle": "def gen = tasks.register('gen', Exec) { commandLine 'true'; outputs.dir(layout.buildDirectory.dir('gen')) }\n" +
				"tasks.register('pack', Zip) { from gen; archiveFileName = 'p.zip'; destinationDirectory = layout.buildDirectory }\n"},
			want: "task :app:gen runs a program (org.gradle.api.tasks.Exec) that another task depends on",
		},
		{
			name:   "Zip of a file outside the checkout",
			append: map[string]string{"app/build.gradle": "tasks.register('z', Zip) { from '/etc/hostname'; archiveFileName = 'z.zip'; destinationDirectory = layout.buildDirectory }\n"},
			want:   "task :app:z reads /etc/hostname, outside the build",
		},
		{
			name:   "detached configuration resolved at configuration",
			append: map[string]string{"app/build.gradle": simple + ".resolve()\n"},
			want:   "slf4j-simple-2.0.16.jar, which no collected configuration lists",
		},
		{
			name:   "detached configuration resolved lazily by a Copy",
			append: map[string]string{"app/build.gradle": "tasks.register('c', Copy) { from { " + simple + ".files }; into layout.buildDirectory.dir('c') }\n"},
			want:   "slf4j-simple-2.0.16.jar",
		},
		{
			name:   "detached configuration with a module that does not resolve",
			append: map[string]string{"app/build.gradle": "configurations.detachedConfiguration(dependencies.create('com.ferralon.missing:nope:1.0')).incoming.artifactView { lenient(true) }.files.files\n"},
			want:   "resolution of :app:detachedConfiguration1 failed",
		},
		{
			name: "distribution-only project with an agent configuration",
			append: map[string]string{
				"settings.gradle":   "include 'dist'\n",
				"dist/build.gradle": "plugins { id 'base' }\nconfigurations { agent { canBeConsumed = false; canBeResolved = true } }\ndependencies { agent 'org.slf4j:slf4j-api:2.0.16' }\n",
			},
			check: func(t *testing.T, g *Graph) {
				m := module(t, g, ":dist")
				for _, n := range m.Nodes {
					if n.Group+":"+n.Artifact+":"+n.Version == "org.slf4j:slf4j-api:2.0.16" {
						return
					}
				}
				t.Errorf(":dist: agent configuration not collected: %v", nodeIDs(m))
			},
		},
		{
			name: "dependency-management plugin importing a BOM",
			append: map[string]string{
				"settings.gradle": "include 'dm'\n",
				"dm/build.gradle": "plugins { id 'java'; id 'io.spring.dependency-management' version '1.1.6' }\n" +
					"dependencyManagement { imports { mavenBom 'org.springframework.boot:spring-boot-dependencies:3.3.5' } }\n" +
					"dependencies { implementation 'org.slf4j:slf4j-api' }\n",
			},
		},
		{
			name: "project build script classpath",
			append: map[string]string{
				"settings.gradle": "include 'bs'\n",
				"bs/build.gradle": "buildscript { repositories { mavenCentral() }; dependencies { classpath 'org.slf4j:slf4j-api:2.0.16' } }\n" +
					"apply plugin: 'java'\n",
			},
		},
		{
			name:   "build script no project reads",
			append: map[string]string{"tools/build.gradle": "plugins { id 'java' }\n"},
			want:   "tools/build.gradle is a Gradle build file no project of the build reads",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyFixture(t, "gradle-multi")
			for name, text := range tc.append {
				p := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("\n" + text)
				if cerr := f.Close(); err == nil {
					err = cerr
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			env := env
			if tc.homeInside {
				env = environ(env, map[string]string{"GRADLE_USER_HOME": filepath.Join(dir, ".gradle-home")})
			}
			g, err := Resolve(context.Background(), Request{Dir: dir, Tool: ToolGradle, WorkDir: filepath.Join(t.TempDir(), "w"), Env: env})
			if err != nil {
				t.Fatalf("resolve: %v: %s", cause(err), err.(*Failure).Log)
			}
			t.Logf("gradle %s: incomplete %q", g.Tool.Version, g.Incomplete)
			if tc.homeInside && !slices.Contains(g.Subject.Outputs, ".gradle-home") {
				t.Errorf("outputs %q, want the user home", g.Subject.Outputs)
			}
			switch {
			case tc.want == "" && !g.Complete:
				t.Errorf("not Complete: %q", g.Incomplete)
			case tc.want != "" && (g.Complete || len(g.Incomplete) == 0 || slices.ContainsFunc(g.Incomplete, func(r string) bool { return !strings.Contains(r, tc.want) })):
				t.Errorf("incomplete %q, want only reasons with %q", g.Incomplete, tc.want)
			}
			if g.Complete != (len(g.Incomplete) == 0) {
				t.Errorf("Complete %v beside incomplete %q", g.Complete, g.Incomplete)
			}
			if tc.check != nil {
				tc.check(t, g)
			}
		})
	}
}
