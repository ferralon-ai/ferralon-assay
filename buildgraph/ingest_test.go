package buildgraph

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	mavenC := Conditions{Profiles: []string{"extra"}, JDK: "21"}
	gradleC := Conditions{}
	firstFile := func(g *Graph) *Node {
		for i := range g.Modules {
			for j := range g.Modules[i].Nodes {
				if g.Modules[i].Nodes[j].File != nil {
					return &g.Modules[i].Nodes[j]
				}
			}
		}
		return nil
	}
	firstDep := func(g *Graph) (*Module, *Node) {
		for i := range g.Modules {
			m := &g.Modules[i]
			for j := range m.Nodes {
				if m.Nodes[j].ID != m.Root && m.Nodes[j].File != nil {
					return m, &m.Nodes[j]
				}
			}
		}
		return nil, nil
	}
	setInputs := func(g *Graph, in []Input) {
		g.Subject.Inputs = in
		g.Subject.InputsDigest = InputsDigest(in)
	}

	tests := []struct {
		name   string
		tool   string
		stated *Conditions
		raw    string
		edit   func(t *testing.T, g *Graph, r fakeRepo)
		want   string
		log    string
	}{
		{name: "maven graph loads", tool: "maven"},
		{name: "gradle graph loads", tool: "gradle"},
		{name: "not json", tool: "maven", raw: "{", want: "graph_rejected:decode"},
		{name: "Validate runs", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Schema = "other" }, want: "graph_rejected:schema"},
		{name: "graph from v0.5.x", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Schema = schemaV1 }, want: "graph_rejected:schema", log: "re-run resolve-graph"},
		{name: "other profiles", tool: "maven", stated: &Conditions{JDK: "21"}, want: "graph_rejected:conditions"},
		{name: "other jdk", tool: "gradle", stated: &Conditions{JDK: "17"}, want: "graph_rejected:conditions"},
		{name: "other properties", tool: "maven", stated: &Conditions{Profiles: []string{"extra"}, JDK: "21", Properties: map[string]string{"skipTests": "true"}}, want: "graph_rejected:conditions"},
		{name: "other env", tool: "maven", stated: &Conditions{Profiles: []string{"extra"}, JDK: "21", Env: map[string]string{"CI": "true"}}, want: "graph_rejected:conditions"},
		{name: "input edited since", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"module-a/pom.xml": "<project><x/></project>"})
		}, want: "graph_rejected:subject_inputs"},
		{name: "gradle input edited since", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"gradle/libs.versions.toml": "[versions]\n"})
		}, want: "graph_rejected:subject_inputs"},
		{name: "input deleted since", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			if err := os.Remove(filepath.Join(r.dir, "module-c", "pom.xml")); err != nil {
				t.Fatal(err)
			}
		}, want: "graph_rejected:subject_inputs"},
		{name: "unnamed pom in checkout", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"module-d/pom.xml": "<project/>"})
		}, want: "graph_rejected:subject_inputs"},
		{name: "unnamed mvn config", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{".mvn/jvm.config": "-Xmx1g\n"})
		}, want: "graph_rejected:subject_inputs"},
		{name: "unnamed lockfile", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"app/gradle.lockfile": ""})
		}, want: "graph_rejected:subject_inputs"},
		// The other tool's build is the plugin's to mark uncovered (OtherToolBuildFiles), not a reason
		// to refuse a graph that is sound for its own.
		{name: "gradle build beside a maven graph", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"svc/build.gradle": "dependencies {}\n"})
		}},
		{name: "maven build beside a gradle graph", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"svc/pom.xml": "<project/>"})
		}},
		{name: "input outside checkout", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			setInputs(g, append(g.Subject.Inputs, Input{Path: "../fake/version.txt", SHA256: "x"}))
		}, want: "graph_rejected:subject_inputs"},
		{name: "unclean input path", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			for _, in := range g.Subject.Inputs {
				if in.Path == "pom.xml" {
					setInputs(g, append(g.Subject.Inputs, Input{Path: "./pom.xml", SHA256: in.SHA256}))
					return
				}
			}
			t.Fatal("no root pom.xml input")
		}, want: "graph_rejected:subject_inputs"},
		{name: "input through symlink out", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			if err := os.Symlink(r.fake, filepath.Join(r.dir, "out")); err != nil {
				t.Fatal(err)
			}
			sum, err := sha256File(filepath.Join(r.fake, "version.txt"))
			if err != nil {
				t.Fatal(err)
			}
			setInputs(g, append(g.Subject.Inputs, Input{Path: "out/version.txt", SHA256: sum}))
		}, want: "graph_rejected:subject_inputs"},
		{name: "absolute input", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			setInputs(g, append(g.Subject.Inputs, Input{Path: filepath.Join(r.dir, "pom.xml"), SHA256: "x"}))
		}, want: "graph_rejected:subject_inputs"},
		{name: "unknown tool", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Tool.Name = "ant" }, want: "graph_rejected:subject_inputs"},
		{name: "module above checkout", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Modules[1].Path = "../fake" }, want: "graph_rejected:module_path"},
		{name: "absolute module", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Modules[len(g.Modules)-1].Path = r.dir }, want: "graph_rejected:module_path"},
		{name: "unclean module path", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Modules[1].Path = "./" + g.Modules[1].Path }, want: "graph_rejected:module_path"},
		{name: "module not a directory", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Modules[1].Path = "pom.xml" }, want: "graph_rejected:module_path"},
		{name: "module missing", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Modules[len(g.Modules)-1].Path = "gone" }, want: "graph_rejected:module_path"},
		{name: "module through symlink out", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			if err := os.Symlink(r.fake, filepath.Join(r.dir, "out")); err != nil {
				t.Fatal(err)
			}
			g.Modules[len(g.Modules)-1].Path = "out"
		}, want: "graph_rejected:module_path"},
		{name: "two versions of one key", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			m, n := firstDep(g)
			dup := *n
			dup.Version += ".1"
			dup.ID = NodeID(dup.Group, dup.Artifact, dup.Type, dup.Classifier, dup.Version)
			m.Nodes = append(m.Nodes, dup)
		}, want: "graph_rejected:duplicate_key"},
		{name: "unknown scope", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			_, n := firstDep(g)
			n.Scope = "import"
		}, want: "graph_rejected:scope"},
		{name: "empty scope", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			_, n := firstDep(g)
			n.Scope = ""
		}, want: "graph_rejected:scope"},
		{name: "jar without file", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			_, n := firstDep(g)
			n.File = nil
		}, want: "graph_rejected:node_file"},
		// Relative to the scan's working directory, the file exists and matches; a graph still
		// names files absolutely.
		{name: "relative file", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			n := firstFile(g)
			wd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			rel, err := filepath.Rel(wd, n.File.Path)
			if err != nil {
				t.Fatal(err)
			}
			n.File.Path = rel
		}, want: "graph_rejected:node_file"},
		{name: "file changed since", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			if err := os.WriteFile(firstFile(g).File.Path, []byte("tampered"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, want: "graph_rejected:node_file"},
		{name: "file gone", tool: "gradle", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			if err := os.Remove(firstFile(g).File.Path); err != nil {
				t.Fatal(err)
			}
		}, want: "graph_rejected:node_file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, c := newFakeMaven(t, "", "", nil), mavenC
			if tc.tool == "gradle" {
				r, c = newFakeGradle(t, "", nil), gradleC
			}
			g, err := r.resolve(t, tc.tool, c)
			if err != nil {
				t.Fatalf("resolve: %v", cause(err))
			}
			if tc.edit != nil {
				tc.edit(t, g, r)
			}
			b, err := json.Marshal(g)
			if err != nil {
				t.Fatal(err)
			}
			if tc.raw != "" {
				b = []byte(tc.raw)
			}
			file := filepath.Join(t.TempDir(), "graph.json")
			if err := os.WriteFile(file, b, 0o644); err != nil {
				t.Fatal(err)
			}
			stated := c
			if tc.stated != nil {
				stated = *tc.stated
			}
			loaded, err := Load(file, r.dir, stated)
			if got := cause(err); got != tc.want {
				t.Fatalf("Load = %q, want %q", got, tc.want)
			}
			var f *Failure
			if tc.log != "" && (!errors.As(err, &f) || !strings.Contains(f.Log, tc.log)) {
				t.Fatalf("Load log = %v, want it to contain %q", err, tc.log)
			}
			if tc.want == "" && len(loaded.Modules) != len(g.Modules) {
				t.Fatalf("loaded %d modules, resolved %d", len(loaded.Modules), len(g.Modules))
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.json"), t.TempDir(), Conditions{})
	if got := cause(err); got != "graph_rejected:decode" {
		t.Fatalf("Load = %q", got)
	}
}

// newFakeGradleIncluded is newFakeGradle over a checkout whose settings include build-logic, a
// convention-plugin build whose Kotlin sources no build-script rule names. answers adds to the
// fake's: included.txt and direct.txt list the directories the init script records, with @ROOT@
// the checkout and @OUT@ a build-logic outside it.
func newFakeGradleIncluded(t *testing.T, answers map[string]string, files map[string]string) fakeRepo {
	t.Helper()
	r := newFakeGradle(t, "", answers)
	outside := filepath.Join(filepath.Dir(r.dir), "outside")
	writeFiles(t, outside, map[string]string{"settings.gradle.kts": "", "src/Plugin.kt": "class Plugin"})
	r.env = append(r.env, "FAKE_OUTSIDE="+outside)
	writeFiles(t, r.dir, map[string]string{
		"build-logic/settings.gradle.kts":             "",
		"build-logic/src/main/kotlin/Conventions.kt":  "class Conventions",
		"build-logic/build/classes/Conventions.class": "out",
	})
	writeFiles(t, r.dir, files)
	return r
}

func included(paths string) map[string]string { return map[string]string{"included.txt": paths} }

func TestGradleIncludedBuilds(t *testing.T) {
	r := newFakeGradleIncluded(t, map[string]string{"included.txt": "@ROOT@/build-logic\n@ROOT@/build-logic\n@OUT@\n", "direct.txt": "@ROOT@/build-logic\n"}, nil)
	g, err := r.resolve(t, ToolGradle, Conditions{})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	outside, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(r.dir), "outside"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.Subject.IncludedBuilds, []string{"build-logic"}) || !reflect.DeepEqual(g.Subject.UnbindableIncludedBuilds, []string{filepath.ToSlash(outside)}) {
		t.Fatalf("included builds %v, unbindable %v", g.Subject.IncludedBuilds, g.Subject.UnbindableIncludedBuilds)
	}
	in := map[string]bool{}
	for _, i := range g.Subject.Inputs {
		in[i.Path] = true
	}
	if !in["build-logic/src/main/kotlin/Conventions.kt"] || !in["build-logic/settings.gradle.kts"] || in["build-logic/build/classes/Conventions.class"] {
		t.Fatalf("inputs %v", in)
	}

	for _, tc := range []struct {
		name    string
		answers map[string]string
		files   map[string]string
		link    [2]string // a symlink written into the checkout: name, target
		want    string
		log     string
	}{
		{name: "the root", answers: included("@ROOT@\n"), want: "tool_failed:graph"},
		{name: "an empty path", answers: included("\n"), want: "tool_failed:graph", log: "without an absolute path"},
		{name: "a relative path", answers: included("build-logic\n"), want: "tool_failed:graph"},
		{name: "a direct include the init script missed", answers: map[string]string{"included.txt": "@ROOT@/build-logic\n", "direct.txt": "@ROOT@/other\n"}, want: "tool_failed:graph"},
		{name: "an included build holding nothing", answers: included("@ROOT@/empty\n"), files: map[string]string{"empty/.gradle/cache": ""}, want: "tool_failed:inputs"},
		{name: "a symlink out of the checkout", answers: included("@ROOT@/build-logic\n"), link: [2]string{"build-logic/src/Out.kt", "@OUT@/src/Plugin.kt"}, want: "tool_failed:inputs", log: "points outside the checkout"},
		{name: "a symlinked directory", answers: included("@ROOT@/build-logic\n"), files: map[string]string{"shared/A.kt": ""}, link: [2]string{"build-logic/src/shared", "@ROOT@/shared"}, want: "tool_failed:inputs", log: "is not to a file"},
	} {
		r := newFakeGradleIncluded(t, tc.answers, tc.files)
		if tc.link[0] != "" {
			target := strings.NewReplacer("@ROOT@", r.dir, "@OUT@", filepath.Join(filepath.Dir(r.dir), "outside")).Replace(tc.link[1])
			if err := os.Symlink(target, filepath.Join(r.dir, tc.link[0])); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.resolve(t, ToolGradle, Conditions{}); cause(err) != tc.want || !strings.Contains(failureLog(err), tc.log) {
			t.Errorf("%s: %v (%s), want %s (%s)", tc.name, cause(err), failureLog(err), tc.want, tc.log)
		}
	}
}

// An included build recorded in another case than the checkout spells it binds its files under
// that spelling, or fails: it never contributes nothing.
func TestGradleIncludedBuildCase(t *testing.T) {
	r := newFakeGradleIncluded(t, included("@ROOT@/Build-Logic\n"), nil)
	g, err := r.resolve(t, ToolGradle, Conditions{})
	if err != nil {
		return // a case-sensitive file system: the path is not there
	}
	file := writeGraphFile(t, g)
	writeFiles(t, r.dir, map[string]string{"build-logic/src/main/kotlin/Conventions.kt": "class Conventions { val foo = 1 }"})
	if _, err := Load(file, r.dir, Conditions{}); cause(err) != "graph_rejected:subject_inputs" {
		t.Fatalf("Load = %q", cause(err))
	}
}

func writeGraphFile(t *testing.T, g *Graph) string {
	t.Helper()
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestLoadIncludedBuilds(t *testing.T) {
	edited := func(rel string) func(t *testing.T, g *Graph, r fakeRepo) {
		return func(t *testing.T, g *Graph, r fakeRepo) { writeFiles(t, r.dir, map[string]string{rel: "edited"}) }
	}
	tests := []struct {
		name    string
		answers map[string]string
		files   map[string]string
		link    [2]string
		fresh   bool
		edit    func(t *testing.T, g *Graph, r fakeRepo)
		want    string
		log     string
	}{
		{name: "loads"},
		{name: "included source edited since", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"build-logic/src/main/kotlin/Conventions.kt": "class Conventions { val foo = 1 }"})
		}, want: "graph_rejected:subject_inputs"},
		{name: "included source added", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"build-logic/src/main/kotlin/More.kt": "class More"})
		}, want: "graph_rejected:subject_inputs"},
		{name: "included build output ignored", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"build-logic/build/classes/More.class": "out"})
		}},
		{name: "sibling of an included build ignored", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			writeFiles(t, r.dir, map[string]string{"build-logic-docs/notes.kt": "notes"})
		}},
		{name: "included build path absolute", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			g.Subject.IncludedBuilds = []string{filepath.ToSlash(filepath.Join(r.dir, "build-logic"))}
		}, want: "graph_rejected:subject_inputs"},
		{name: "included build gone", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			g.Subject.IncludedBuilds = []string{"gone"}
		}, want: "graph_rejected:subject_inputs"},
		{name: "included build path unclean", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			g.Subject.IncludedBuilds = []string{"../elsewhere"}
		}, want: "graph_rejected:subject_inputs"},
		{name: "included build through a symlink out", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			if err := os.Symlink(t.TempDir(), filepath.Join(r.dir, "linked")); err != nil {
				t.Fatal(err)
			}
			g.Subject.IncludedBuilds = append(g.Subject.IncludedBuilds, "linked")
		}, want: "graph_rejected:subject_inputs"},
		{name: "included build through a symlink in", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			if err := os.Symlink("build-logic", filepath.Join(r.dir, "bl")); err != nil {
				t.Fatal(err)
			}
			g.Subject.IncludedBuilds = append(g.Subject.IncludedBuilds, "bl")
		}, want: "graph_rejected:subject_inputs", log: "included build outside the checkout: bl"},
		{name: "included build is a file", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			g.Subject.IncludedBuilds = append(g.Subject.IncludedBuilds, "settings.gradle")
		}, want: "graph_rejected:subject_inputs", log: "is not a directory"},
		{name: "included builds dropped", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			g.Subject.IncludedBuilds = nil
		}, want: "graph_rejected:subject_inputs"},
		{name: "maven graph with included builds", edit: func(t *testing.T, g *Graph, r fakeRepo) {
			g.Tool.Name = "maven"
		}, want: "graph_rejected:subject_inputs"},
		{name: "included build under a skipped name edited", answers: included("@ROOT@/node_modules/plug\n"),
			files: map[string]string{"node_modules/plug/settings.gradle.kts": "", "node_modules/plug/src/P.kt": "class P"},
			edit:  edited("node_modules/plug/src/P.kt"), want: "graph_rejected:subject_inputs"},
		{name: "source package named build edited", files: map[string]string{"build-logic/src/main/kotlin/com/acme/build/Conv.kt": "class Conv"},
			edit: edited("build-logic/src/main/kotlin/com/acme/build/Conv.kt"), want: "graph_rejected:subject_inputs"},
		{name: "buildSrc source package named build edited", files: map[string]string{"buildSrc/build.gradle.kts": "", "buildSrc/src/main/kotlin/acme/build/B.kt": "class B"},
			edit: edited("buildSrc/src/main/kotlin/acme/build/B.kt"), want: "graph_rejected:subject_inputs"},
		{name: "buildSrc output ignored", files: map[string]string{"buildSrc/build.gradle.kts": "", "buildSrc/src/B.kt": "class B"},
			edit: edited("buildSrc/build/classes/B.class")},
		{name: "script-less buildSrc output ignored", files: map[string]string{"buildSrc/src/main/groovy/B.groovy": "class B", "buildSrc/build/libs/buildSrc.jar": "jar"},
			edit: edited("buildSrc/build/libs/buildSrc.jar")},
		{name: "script file in a source tree hides no package named build",
			files: map[string]string{"build-logic/src/main/kotlin/acme/build.gradle.kts": "", "build-logic/src/main/kotlin/acme/build/Helper.kt": "class Helper"},
			edit:  edited("build-logic/src/main/kotlin/acme/build/Helper.kt"), want: "graph_rejected:subject_inputs"},
		{name: "IDE state in an included build edited", edit: edited("build-logic/.idea/workspace.xml"), want: "graph_rejected:subject_inputs"},
		{name: "resource directory named like IDE state edited", files: map[string]string{"build-logic/src/main/resources/.idea/x.properties": "a=1"},
			edit: edited("build-logic/src/main/resources/.idea/x.properties"), want: "graph_rejected:subject_inputs"},
		{name: "Finder metadata in an included build ignored", edit: edited("build-logic/src/.DS_Store")},
		{name: "symlinked source target edited", files: map[string]string{"shared/Shared.kt": "class Shared"},
			link: [2]string{"build-logic/src/Shared.kt", "../../shared/Shared.kt"},
			edit: edited("shared/Shared.kt"), want: "graph_rejected:subject_inputs"},
		{name: "included build outside the checkout", answers: included("@ROOT@/build-logic\n@OUT@\n"), want: "graph_rejected:subject_inputs"},
		{name: "included build outside the checkout, resolved in this run", answers: included("@ROOT@/build-logic\n@OUT@\n"), fresh: true},
		{name: "maven graph with an unbindable included build, resolved in this run", answers: included("@OUT@\n"), fresh: true,
			edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Tool.Name = "maven" }, want: "graph_rejected:subject_inputs", log: "included builds in a maven graph"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			answers := tc.answers
			if answers == nil {
				answers = included("@ROOT@/build-logic\n")
			}
			r := newFakeGradleIncluded(t, answers, tc.files)
			if tc.link[0] != "" {
				if err := os.Symlink(tc.link[1], filepath.Join(r.dir, tc.link[0])); err != nil {
					t.Fatal(err)
				}
			}
			g, err := r.resolve(t, ToolGradle, Conditions{})
			if err != nil {
				t.Fatalf("resolve: %v", cause(err))
			}
			if tc.edit != nil {
				tc.edit(t, g, r)
			}
			var opts []LoadOption
			if tc.fresh {
				opts = append(opts, Fresh())
			}
			if _, err := Load(writeGraphFile(t, g), r.dir, Conditions{}, opts...); cause(err) != tc.want || !strings.Contains(failureLog(err), tc.log) {
				t.Fatalf("Load = %q (%s), want %q (%s)", cause(err), failureLog(err), tc.want, tc.log)
			}
		})
	}
}
