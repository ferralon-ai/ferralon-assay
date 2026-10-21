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
		got := map[string]map[string]string{"runtime": {}, "compile": {}, "provided": {}, "test": {}}
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
		t.Logf("%s: %d compile, %d runtime, %d provided, %d test", p, len(got["compile"]), len(got["runtime"]), len(got["provided"]), len(got["test"]))
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
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"settings.gradle":                      "pluginManagement { includeBuild('build-logic') }\nrootProject.name = 'root'\nincludeBuild('libs/core')\n",
		"build.gradle":                         "plugins { id 'java' }\n",
		"build-logic/settings.gradle":          "rootProject.name = 'build-logic'\n",
		"build-logic/src/main/groovy/A.groovy": "class A {}\n",
		"libs/core/settings.gradle":            "rootProject.name = 'core'\nincludeBuild('../../nested')\n",
		"nested/settings.gradle":               "rootProject.name = 'nested'\n",
		"nested/src/main/java/N.java":          "class N {}\n",
	})
	g, err := Resolve(context.Background(), Request{Dir: dir, Tool: ToolGradle, WorkDir: filepath.Join(t.TempDir(), "w"), Env: env})
	if err != nil {
		t.Fatalf("resolve: %v: %s", cause(err), err.(*Failure).Log)
	}
	if want := []string{"build-logic", "libs/core", "nested"}; !reflect.DeepEqual(g.Subject.IncludedBuilds, want) {
		t.Fatalf("included builds %v, want %v", g.Subject.IncludedBuilds, want)
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file, dir, Conditions{}); err != nil {
		t.Fatalf("Load: %v", cause(err))
	}
	writeFiles(t, dir, map[string]string{"nested/src/main/java/N.java": "class N { int x; }\n"})
	if _, err := Load(file, dir, Conditions{}); cause(err) != "graph_rejected:subject_inputs" {
		t.Fatalf("Load after a nested edit: %q", cause(err))
	}
}
