package javaanalysis

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The search loads the JARs on every module's runtime classpath, one version per package, and
// names every package it cannot load instead of guessing.
func TestRuntimeSelection(t *testing.T) {
	dir := t.TempDir()
	jd := func(version, scope string) graphDep {
		return graphDep{group: "com.fasterxml.jackson.core", artifact: "jackson-databind", version: version, scope: scope,
			jar: filepath.Join(dir, "jackson-databind-"+version+".jar")}
	}
	const coord = "com.fasterxml.jackson.core:jackson-databind"
	jdJar := func(version string) RuntimeJar {
		p := filepath.Join(dir, "jackson-databind-"+version+".jar")
		return RuntimeJar{Coordinate: coord, Version: version, Path: p, SHA256: fileSHA256(p)}
	}
	servlet := graphDep{group: "javax.servlet", artifact: "servlet-api", version: "2.5", scope: "provided", jar: filepath.Join(dir, "servlet-api-2.5.jar")}
	for _, tc := range []struct {
		name     string
		modules  []buildgraph.Module
		wantLoad []RuntimeJar
		wantMiss []RuntimeMiss
	}{
		{
			name:     "test-only version left out, compile version loaded",
			modules:  []buildgraph.Module{testModule(t, ".", "app", jd("2.9.8", "test"), jd("2.9.9", "compile"))},
			wantLoad: []RuntimeJar{jdJar("2.9.9")},
		},
		{
			name:    "test-only package not loaded",
			modules: []buildgraph.Module{testModule(t, ".", "app", jd("2.9.8", "test"))},
		},
		{
			name:    "provided and runtime are on the running classpath",
			modules: []buildgraph.Module{testModule(t, ".", "app", servlet, jd("2.9.9", "runtime"))},
			wantLoad: []RuntimeJar{jdJar("2.9.9"), {Coordinate: "javax.servlet:servlet-api", Version: "2.5",
				Path: servlet.jar, SHA256: fileSHA256(servlet.jar)}},
		},
		{
			name:     "one version in two modules is loaded once",
			modules:  []buildgraph.Module{testModule(t, "a", "a", jd("2.9.9", "compile")), testModule(t, "b", "b", jd("2.9.9", "runtime"))},
			wantLoad: []RuntimeJar{jdJar("2.9.9")},
		},
		{
			name:     "two runtime versions across modules are a named miss",
			modules:  []buildgraph.Module{testModule(t, "a", "a", jd("2.9.8", "compile")), testModule(t, "b", "b", jd("2.9.9", "runtime"))},
			wantMiss: []RuntimeMiss{{Coordinate: coord, Ambiguous: true, Detail: coord + ": runtime versions 2.9.8, 2.9.9"}},
		},
		{
			name: "a classpath copy at another version is not loaded",
			modules: func() []buildgraph.Module {
				m := testModule(t, ".", "app", jd("2.9.9", "runtime"))
				return []buildgraph.Module{m, classpathCopy(t, m, "compileClasspath", jd("2.9.8", "provided"))}
			}(),
			wantLoad: []RuntimeJar{jdJar("2.9.9")},
		},
		{
			name: "a file that is not a JAR is a named miss",
			modules: []buildgraph.Module{testModule(t, ".", "app",
				graphDep{group: "com.dep", artifact: "ui", version: "1", jar: filepath.Join(dir, "ui-1.aar")})},
			wantMiss: []RuntimeMiss{{Coordinate: "com.dep:ui", Detail: "com.dep:ui:jar:1: ui-1.aar is not a JAR"}},
		},
		{
			name:    "a pom has nothing to load",
			modules: []buildgraph.Module{testModule(t, ".", "app", graphDep{group: "com.dep", artifact: "bom", version: "1"})},
		},
		{
			name: "a reactor sibling is first-party output",
			modules: []buildgraph.Module{
				testModule(t, "a", "a", graphDep{group: "com.example", artifact: "b", version: "1", jar: filepath.Join(dir, "b-1.jar")}),
				testModule(t, "b", "b"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			load, miss := RuntimeSelection(&buildgraph.Graph{Schema: buildgraph.Schema, Modules: tc.modules})
			if !reflect.DeepEqual(load, tc.wantLoad) {
				t.Errorf("load = %+v, want %+v", load, tc.wantLoad)
			}
			if !reflect.DeepEqual(miss, tc.wantMiss) {
				t.Errorf("miss = %+v, want %+v", miss, tc.wantMiss)
			}
		})
	}
}

// A dependency only the tests use is not loaded, so a main calling into it meets an
// unloaded class (a hazard), never a path through test-only code.
func TestBytecodeReach_TestScopedDependencyIsNotLoaded(t *testing.T) {
	a := newApp(t, "", false)
	a.deps[0].scope = "test"
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callFetch))

	res := a.reach(netkitSinkID)
	if len(res.Paths) != 0 || len(res.Searched) != 0 {
		t.Fatalf("test-scoped JAR was loaded: Paths %v Searched %v", res.Paths, res.Searched)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("missing reachability_undetermined: %+v", res.Partiality)
	}
}

// indy is an InvokeDynamic constant (bootstrap index 0) for name and desc.
func (b *cpb) indy(name, desc string) uint16 {
	return b.add("indy:"+name+desc, append(append([]byte{18}, be2(0)...), be2(b.nt(name, desc))...))
}

// A lambda hides its body behind invokedynamic: the only route from the ingress to the sink
// runs through a synthetic method no static edge reaches. The search must find a path or
// say it could not; an empty, clean answer would be a false negative.
func TestBytecodeReach_LambdaOnlyIngressPathIsNeverClean(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.source("src/main/java/com/acme/Web.java", servletSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.class("target/classes", "com/acme/Web", func(b *cpb) []xmethod {
		makeRunnable := append([]byte{0xBA}, append(be2(b.indy("run", "()Ljava/lang/Runnable;")), 0, 0, 0x57, 0xB1)...)
		return []xmethod{
			{"doGet", "(Ljava/lang/Object;Ljava/lang/Object;)V", accPublic, makeRunnable},
			{"lambda$doGet$0", "()V", 0x100A, callFetch(b)},
		}
	})

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Fatalf("lambda-only path listed the sink as Searched: %v", res.Searched)
	}
	if len(res.Paths) == 0 && !hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("lambda-only path came back clean: Paths %v, partiality %+v", res.Paths, res.Partiality)
	}
}

// The closure engine runs on the JDK the graph's run conditions state: on the platformMethods
// release, a loadable class's method no platform supertype declares is no root, and on any
// other release or none, or when a module's toolchain selects another or went unread, as in a
// graph written before toolchains were recorded, it stays one. The rows share one build dir, so a
// cached engine built for one JDK is never reused for another.
func TestBytecodeReach_ClosureRunsOnTheStatedJDK(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(func(b *cpb) []byte {
		idx := b.mref("java/lang/System", "getProperty", "(Ljava/lang/String;)Ljava/lang/String;")
		return append([]byte{0x01, 0xB8}, append(be2(idx), 0x57, 0xB1)...)
	}))
	a.classI("target/classes", "com/acme/Snap", "java/util/concurrent/CopyOnWriteArrayList", nil, 0x0021, func(b *cpb) []xmethod {
		return []xmethod{{"snapshot", "()Ljava/lang/Object;", accPublic, callFetch(b)}}
	})
	for _, tc := range []struct {
		jdk        string
		toolchains []string
		unread     bool
		wantPath   bool
	}{
		{jdk: "21.0.4", wantPath: false},
		{jdk: "17.0.12", wantPath: true},
		{jdk: "21.0.4", wantPath: false}, // the same build dir again: the closure cache is keyed on the JDK
		{jdk: "21.0.4", toolchains: []string{"17"}, wantPath: true},
		{jdk: "21.0.4", toolchains: []string{"21"}, wantPath: false},
		{jdk: "21.0.4", unread: true, wantPath: true},
		{jdk: "", wantPath: true},
	} {
		m := testModule(t, ".", "app", a.deps...)
		m.JDKToolchains = tc.toolchains
		m.JDKToolchainsKnown = !tc.unread
		a.graph = writeGraph(t, buildgraph.Graph{
			Schema:     buildgraph.Schema,
			Tool:       buildgraph.Tool{Name: "maven", Version: "test"},
			JVM:        buildgraph.JVM{Version: "21.0.4"},
			Conditions: buildgraph.Conditions{JDK: tc.jdk},
			Modules:    []buildgraph.Module{m},
		})
		res := a.reach(netkitSinkID)
		if got := len(res.Paths) > 0; got != tc.wantPath {
			t.Errorf("JDK %q, toolchains %q, unread %t: path found = %t, want %t: Paths %v, partiality %+v", tc.jdk, tc.toolchains, tc.unread, got, tc.wantPath, res.Paths, res.Partiality)
		}
	}
}
