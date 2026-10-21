package buildgraph

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	}{
		{name: "maven graph loads", tool: "maven"},
		{name: "gradle graph loads", tool: "gradle"},
		{name: "not json", tool: "maven", raw: "{", want: "graph_rejected:decode"},
		{name: "Validate runs", tool: "maven", edit: func(t *testing.T, g *Graph, r fakeRepo) { g.Schema = "other" }, want: "graph_rejected:schema"},
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
		// The other tool's build is the plugin's to mark uncovered (OtherToolInputs), not a reason
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
