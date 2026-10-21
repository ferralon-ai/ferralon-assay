package buildgraph

import (
	"reflect"
	"testing"
)

func validGraph() *Graph {
	g := &Graph{
		Schema:  Schema,
		Tool:    Tool{Name: "maven", Version: "3.9.9"},
		JVM:     JVM{Version: "21.0.1"},
		Subject: Subject{Inputs: []Input{{Path: "pom.xml", SHA256: "aa"}}},
		Modules: []Module{{
			ID: "g:root", Path: ".", Root: "g:root:jar:1",
			Nodes: []Node{
				{ID: "g:root:jar:1", Group: "g", Artifact: "root", Version: "1", Type: "jar"},
				{ID: "g:dep:jar:x:2", Group: "g", Artifact: "dep", Version: "2", Type: "jar", Classifier: "x"},
			},
			Edges: []Edge{{From: "g:root:jar:1", To: "g:dep:jar:x:2"}},
		}},
	}
	g.Subject.InputsDigest = InputsDigest(g.Subject.Inputs)
	return g
}

// addCopy adds of's testRuntimeClasspath copy holding g:dep at another version.
func addCopy(g *Graph, of, path, root string) *Module {
	g.Modules = append(g.Modules, Module{
		ID: of + "#testRuntimeClasspath", CopyOf: of, Path: path, Root: root,
		Nodes: []Node{
			{ID: "g:root:jar:1", Group: "g", Artifact: "root", Version: "1", Type: "jar"},
			{ID: "g:dep:jar:x:1", Group: "g", Artifact: "dep", Version: "1", Type: "jar", Classifier: "x"},
		},
	})
	return &g.Modules[len(g.Modules)-1]
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(g *Graph)
		want string
	}{
		{name: "valid", edit: func(*Graph) {}, want: ""},
		{name: "unknown schema", edit: func(g *Graph) { g.Schema = "assay.buildgraph/v3" }, want: "schema"},
		{name: "older schema", edit: func(g *Graph) { g.Schema = schemaV1 }, want: "schema"},
		{name: "no tool version", edit: func(g *Graph) { g.Tool.Version = " " }, want: "tool_version"},
		{name: "no tool name", edit: func(g *Graph) { g.Tool.Name = "" }, want: "tool_version"},
		{name: "no jvm", edit: func(g *Graph) { g.JVM.Version = "" }, want: "jvm"},
		{name: "inputs edited after digest", edit: func(g *Graph) { g.Subject.Inputs[0].SHA256 = "bb" }, want: "inputs_digest"},
		{name: "input added after digest", edit: func(g *Graph) { g.Subject.Inputs = append(g.Subject.Inputs, Input{Path: "a/pom.xml", SHA256: "cc"}) }, want: "inputs_digest"},
		{name: "no modules", edit: func(g *Graph) { g.Modules = nil }, want: "modules"},
		{name: "empty module id", edit: func(g *Graph) { g.Modules[0].ID = "" }, want: "module_id"},
		{name: "duplicate module", edit: func(g *Graph) { g.Modules = append(g.Modules, g.Modules[0]) }, want: "module_id"},
		{name: "node id disagrees with coordinate", edit: func(g *Graph) { g.Modules[0].Nodes[1].Version = "3" }, want: "node_id"},
		{name: "duplicate node", edit: func(g *Graph) { g.Modules[0].Nodes = append(g.Modules[0].Nodes, g.Modules[0].Nodes[1]) }, want: "duplicate_node"},
		{name: "root not a node", edit: func(g *Graph) { g.Modules[0].Root = "g:other:jar:1" }, want: "missing_node"},
		{name: "edge to a missing node", edit: func(g *Graph) { g.Modules[0].Edges[0].To = "g:gone:jar:1" }, want: "missing_node"},
		{name: "edge from a missing node", edit: func(g *Graph) { g.Modules[0].Edges[0].From = "g:gone:jar:1" }, want: "missing_node"},
		{name: "classpath copy", edit: func(g *Graph) { addCopy(g, "g:root", ".", "g:root:jar:1") }, want: ""},
		{name: "classpath copy of no project", edit: func(g *Graph) { addCopy(g, "g:other", ".", "g:root:jar:1") }, want: "classpath_copy"},
		{name: "classpath copy at another path", edit: func(g *Graph) { addCopy(g, "g:root", "sub", "g:root:jar:1") }, want: "classpath_copy"},
		{name: "classpath copy with another root", edit: func(g *Graph) { addCopy(g, "g:root", ".", "g:dep:jar:x:1") }, want: "classpath_copy"},
		{name: "classpath copy named for another project", edit: func(g *Graph) { addCopy(g, "g:root", ".", "g:root:jar:1").ID = "g:x#testRuntimeClasspath" }, want: "classpath_copy"},
		{name: "classpath copy of a copy", edit: func(g *Graph) {
			c := addCopy(g, "g:root", ".", "g:root:jar:1")
			addCopy(g, c.ID, ".", "g:root:jar:1")
		}, want: "classpath_copy"},
		// Gradle allows '#' in a project name: only copy_of marks a copy.
		{name: "project named with #", edit: func(g *Graph) {
			addCopy(g, "g:root", "v2", "g:root:jar:1").CopyOf = ""
		}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := validGraph()
			tc.edit(g)
			if got := g.Validate(); got != tc.want {
				t.Fatalf("Validate() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInputsDigestIgnoresOrder(t *testing.T) {
	a := []Input{{Path: "b", SHA256: "1"}, {Path: "a", SHA256: "2"}}
	b := []Input{{Path: "a", SHA256: "2"}, {Path: "b", SHA256: "1"}}
	if InputsDigest(a) != InputsDigest(b) {
		t.Fatal("digest depends on order")
	}
	if InputsDigest(a) == InputsDigest([]Input{{Path: "a", SHA256: "1"}, {Path: "b", SHA256: "2"}}) {
		t.Fatal("digest ignores which path holds which sha")
	}
}

func TestParseList(t *testing.T) {
	got, err := parseList([]byte(`
The following files have been resolved:
   none

The following files have been resolved:
   g:a:jar:1:compile:/m2/a.jar -- module a [auto]
   g:b:jar:tests:1:test:/m2/b-tests.jar -- module b (auto)
   g:c:pom:1:runtime:/m2/c.pom
`))
	want := map[string]string{"g:a:jar:1": "/m2/a.jar", "g:b:jar:tests:1": "/m2/b-tests.jar", "g:c:pom:1": "/m2/c.pom"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := parseList([]byte("   g:a:1:compile:/x\n")); err == nil {
		t.Fatal("a three-part coordinate parsed")
	}
	if _, err := parseList([]byte("   not a line\n")); err == nil {
		t.Fatal("an unreadable line parsed")
	}
}

func TestGradleArtifact(t *testing.T) {
	for _, tc := range []struct{ name, version, file, typ, classifier string }{
		{"lwjgl", "3.3.4", "lwjgl-3.3.4.jar", "jar", ""},
		{"lwjgl", "3.3.4", "lwjgl-3.3.4-natives-linux.jar", "jar", "natives-linux"},
		{"thing", "1.0", "thing-1.0.aar", "aar", ""},
		{"thing", "1.0", "renamed.jar", "jar", ""},
	} {
		if typ, classifier := gradleArtifact(tc.name, tc.version, tc.file); typ != tc.typ || classifier != tc.classifier {
			t.Errorf("%s: %s/%s", tc.file, typ, classifier)
		}
	}
}

func TestCheckJDK(t *testing.T) {
	for _, tc := range []struct{ want, have, cause string }{
		{"", "21.0.1", ""},
		{"21", "21.0.12.1", ""},
		{"1.8", "1.8.0_392", ""},
		{"8", "1.8.0_392", ""},
		{"17", "21.0.1", "jdk_mismatch:17/21.0.1"},
		{"temurin", "21.0.1", "jdk_mismatch:temurin/21.0.1"},
	} {
		got := ""
		if f := checkJDK(tc.want, tc.have); f != nil {
			got = f.Cause()
		}
		if got != tc.cause {
			t.Errorf("checkJDK(%q, %q) = %q, want %q", tc.want, tc.have, got, tc.cause)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct{ out, cause string }{
		{"Error: JAVA_HOME is not set and no 'java' command could be found in your PATH.", "toolchain_absent"},
		{"Could not transfer artifact a:b:pom:1 from/to corp (https://x): status code: 401, reason phrase: Unauthorized", "credentials:corp"},
		{"Could not transfer artifact a:b:pom:1 from/to corp (https://x): status code: 404, reason phrase: Not Found", "tool_failed:tree"},
		{"Could not transfer artifact corp:x:pom:1 from/to corp (http://127.0.0.1:18401/repo): authentication failed for http://127.0.0.1:18401/repo/corp/x/1/x-1.pom, status: 401 Unauthorized -> [Help 1]", "credentials:corp"},
		{"> Could not GET 'https://maven.corp.example/a/b.pom'. Received status code 403 from server: Forbidden", "credentials:https://maven.corp.example"},
		{"Could not resolve corp:x:1.\nCould not get resource 'https://maven.corp.example/x-1.pom'.\nCould not GET 'https://maven.corp.example/x-1.pom'.\nReceived status code 401 from server: Unauthorized", "credentials:https://maven.corp.example"},
		{"[ERROR] BUILD FAILURE", "tool_failed:tree"},
	} {
		if got := classify("tree", []byte(tc.out)).Cause(); got != tc.cause {
			t.Errorf("classify(%q) = %q, want %q", tc.out, got, tc.cause)
		}
	}
}
