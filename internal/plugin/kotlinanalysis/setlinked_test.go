package kotlinanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
)

// setlinked_test.go: on a linked run (the loaded classes are every class the build's runtime
// classpath defines, and a licensed launch runs on it) a dependency class below a type no
// classpath entry and no JDK package supplies cannot link, so it is no hidden receiver of a
// first-party call. org.d:d:1.0 holds org/d/D implementing org/opt/Plugin, which nothing
// defines; main calls com/example/Svc.run virtually.

const (
	linkedSvc    = "com/example/Svc"
	linkedAbsent = "org/opt/Plugin"
)

// linkedD emits org/d/D implementing linkedAbsent. With withRun, D.run()V calls the jackson
// sink, so the hidden receiver yields a path; without, D inherits run from the unopened type
// and the search is undetermined.
func linkedD(withRun bool) []byte {
	b := newKClassBuilder()
	b.addMethod("<init>", "()V", []byte{opReturn})
	if withRun {
		b.addMethod("run", "()V", append(callsReadValue(b), opReturn))
	}
	return b.buildWithInterfaces(holeD, "java/lang/Object", linkedAbsent)
}

// linkedBuild is a jackson build with org.d:d:1.0, a first-party Svc with an empty run, and a
// licensed main calling Svc.run.
func linkedBuild(t *testing.T, withRun bool) string {
	t.Helper()
	dir := gradleJacksonBuild(t, `    implementation("org.d:d:1.0")`)
	writeGradleCacheJar(t, dir, "org.d", "d", "1.0", map[string][]byte{holeD: linkedD(withRun)})
	svc := newKClassBuilder()
	svc.addMethod("<init>", "()V", []byte{opReturn})
	svc.addMethod("run", "()V", []byte{opReturn})
	writeClassFixture(t, dir, linkedSvc, svc.build(linkedSvc, "java/lang/Object"))
	writeMain(t, dir, func(b *kclassBuilder) []byte { return b.invokeVirtual(linkedSvc, "run", "()V") })
	return dir
}

// linkedGraph is the graph of every JAR cached in dir, complete, on a recorded JDK 21 with no
// toolchain of its own, writing to build and .gradle as a Gradle build does; edit, when set, changes it before it is written.
func linkedGraph(t *testing.T, dir string, edit func(*buildgraph.Graph)) javaanalysis.Option {
	t.Helper()
	m := cacheModule(dir)
	m.JDKToolchainsKnown = true
	g := buildgraph.Graph{
		Schema:     buildgraph.Schema,
		Tool:       buildgraph.Tool{Name: "gradle", Version: "test"},
		JVM:        buildgraph.JVM{Version: "21.0.4"},
		Conditions: buildgraph.Conditions{JDK: "21.0.4"},
		Subject:    buildgraph.Subject{Outputs: []string{".gradle", "build"}},
		Modules:    []buildgraph.Module{m},
		Complete:   true,
	}
	if edit != nil {
		edit(&g)
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return javaanalysis.WithBuildGraph(file)
}

// TestReachability_LinkedBoundsHiddenSubtype: the search an unopened supertype left
// undetermined is Searched once the run is linked.
func TestReachability_LinkedBoundsHiddenSubtype(t *testing.T) {
	dir := linkedBuild(t, false)

	unlinked := reachWith(t, dir, cacheGraph(t, dir), readValueSink) // no recorded JDK: not linked
	if contains(unlinked.Searched, readValueSink) || len(unlinked.Paths) != 0 {
		t.Fatalf("unlinked run: Searched %v, paths %+v; want the hidden receiver to withhold", unlinked.Searched, unlinked.Paths)
	}

	linked := reachWith(t, dir, linkedGraph(t, dir, nil), readValueSink)
	if !contains(linked.Searched, readValueSink) {
		t.Fatalf("linked run: sink not Searched (paths %+v, partiality %+v)", linked.Paths, linked.Partiality)
	}
}

// TestReachability_LinkagePreconditions: each row breaks one condition the run is linked
// under, and nothing else, so D stays a hidden receiver and its run still reaches the sink.
// The first row breaks none: D cannot link, and the sink is Searched.
func TestReachability_LinkagePreconditions(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		edit  func(*buildgraph.Graph)
		want  bool // a path through D.run
	}{
		{name: "linked", want: false},
		{
			name: "graph does not list every install",
			edit: func(g *buildgraph.Graph) { g.Complete = false },
			want: true,
		},
		{
			name: "runtime JDK 8",
			edit: func(g *buildgraph.Graph) { g.Conditions.JDK = "1.8.0_392" },
			want: true,
		},
		{
			name: "a dependency class that does not parse",
			setup: func(t *testing.T, dir string) {
				writeGradleCacheJar(t, dir, "org.d", "d", "1.0", map[string][]byte{
					holeD:          linkedD(true),
					"org/d/Broken": append(be4(0xCAFEBABE), 0, 0),
				})
			},
			want: true,
		},
		{
			name: "two JARs define one class",
			setup: func(t *testing.T, dir string) {
				util := func() []byte { return newKClassBuilder().build("org/d/Util", "java/lang/Object") }
				writeGradleCacheJar(t, dir, "org.d", "d", "1.0", map[string][]byte{holeD: linkedD(true), "org/d/Util": util()})
				writeGradleCacheJar(t, dir, "org.e", "e", "1.0", map[string][]byte{"org/d/Util": util()})
			},
			want: true,
		},
		{
			name: "a launch option the lanes do not model",
			setup: func(t *testing.T, dir string) {
				p := filepath.Join(dir, "build.gradle.kts")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, "\napplication {\n    applicationDefaultJvmArgs = listOf(\"-Djava.security.manager=org.d.D\")\n}\n"...)
				if err := os.WriteFile(p, data, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
		{
			name: "a first-party class that does not parse",
			setup: func(t *testing.T, dir string) {
				writeClassFixture(t, dir, "com/example/Broken", append(be4(0xCAFEBABE), 0, 0))
			},
			want: true,
		},
		{
			name: "a further project",
			setup: func(t *testing.T, dir string) {
				writeBuildFile(t, dir, "settings.gradle.kts", `include("lib")`+"\n")
			},
			want: true,
		},
		{
			name: "no named launch entry",
			setup: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "src", "main", "resources", "META-INF", "MANIFEST.MF")); err != nil {
					t.Fatal(err)
				}
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := linkedBuild(t, true)
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			res := reachWith(t, dir, linkedGraph(t, dir, tt.edit), readValueSink)
			if got := len(res.Paths) == 1; got != tt.want {
				t.Fatalf("path found = %v, want %v (paths %+v, Searched %v, partiality %+v)", got, tt.want, res.Paths, res.Searched, res.Partiality)
			}
			if got := contains(res.Searched, readValueSink); got == tt.want {
				t.Errorf("Searched = %v, want %v (partiality %+v)", got, !tt.want, res.Partiality)
			}
		})
	}
}
