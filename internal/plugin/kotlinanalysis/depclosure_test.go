package kotlinanalysis

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depclosure_test.go — S2 fixtures: Reachability over first-party build output PLUS the
// dependency closure the inventory resolves, with root licensing (only `main` clears a sink).
// Classes are emitted as JVMS §4 bytes and JARs are written into the build-local caches
// LocateDependencyJar searches, so everything runs through the real parser, inventory and
// engine.

const (
	opInvokeVirtual = 0xB6

	jacksonGroup    = "com.fasterxml.jackson.core"
	jacksonArtifact = "jackson-databind"
	jacksonVersion  = "2.9.8"
	jacksonPURL     = "pkg:maven/com.fasterxml.jackson.core/jackson-databind"
	objectMapper    = "com/fasterxml/jackson/databind/ObjectMapper"
	readValueDesc   = "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"
	readValueSink   = objectMapper + ".readValue" + readValueDesc
	mainStringsDesc = "([Ljava/lang/String;)V"
)

func (b *kclassBuilder) invokeVirtual(owner, name, desc string) []byte {
	idx := b.methodref(owner, name, desc)
	return append([]byte{opInvokeVirtual}, be2(idx)...)
}

// writeJar writes internalName->classBytes entries as a JAR at path.
func writeJar(t *testing.T, path string, classes map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, data := range classes {
		w, err := zw.Create(name + ".class")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeGradleCacheJar places a JAR in the build-local Gradle module cache.
func writeGradleCacheJar(t *testing.T, build, group, artifact, version string, classes map[string][]byte) {
	t.Helper()
	writeJar(t, filepath.Join(build, ".gradle", "caches", "modules-2", "files-2.1",
		group, artifact, version, "0123abcd", artifact+"-"+version+".jar"), classes)
}

// m2Path returns the build-local Maven repository path of an artifact file.
func m2Path(build, group, artifact, version, ext string) string {
	return filepath.Join(build, ".m2", "repository", strings.ReplaceAll(group, ".", "/"),
		artifact, version, artifact+"-"+version+"."+ext)
}

// jacksonJar emits a stand-in jackson-databind with ObjectMapper.readValue and an unrelated
// ObjectMapper.writeValueAsString.
func jacksonJar() map[string][]byte {
	b := newKClassBuilder()
	b.addMethod("readValue", readValueDesc, []byte{opReturn})
	b.addMethod("writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;", []byte{opReturn})
	return map[string][]byte{objectMapper: b.build(objectMapper, "java/lang/Object")}
}

// gradleJacksonBuild declares jackson-databind (and any extra lines) in build.gradle.kts and
// caches the jackson JAR.
func gradleJacksonBuild(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", `
dependencies {
    implementation("`+jacksonGroup+":"+jacksonArtifact+":"+jacksonVersion+`")
`+extra+`
}
`)
	writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
	return dir
}

// writeMain emits com/example/MainKt.main(String[]) whose body is code (return appended).
func writeMain(t *testing.T, dir string, emit func(b *kclassBuilder) []byte) {
	t.Helper()
	b := newKClassBuilder()
	code := append(emit(b), opReturn)
	b.addMethod("main", mainStringsDesc, code)
	writeClassFixture(t, dir, "com/example/MainKt", b.build("com/example/MainKt", "java/lang/Object"))
}

func reach(t *testing.T, dir string, sinks ...string) plugin.ReachabilityResult {
	t.Helper()
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: sinks})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	return res
}

// TestReachability_DependencyClosure is the S2 verdict table. Each row's comment names the
// over-approximation it pins: narrowing that rule flips the row.
func TestReachability_DependencyClosure(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T) string
		wantPath     bool
		wantSearched bool
		wantReasons  []string // must all be present
		denyReasons  []string // must all be absent
	}{
		{
			// The closure is loaded: without it the sink is not loaded and the row is
			// undetermined, never a candidate.
			name: "main calls jackson readValue: candidate",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, "")
				writeMain(t, dir, func(b *kclassBuilder) []byte {
					return b.invokeVirtual(objectMapper, "readValue", readValueDesc)
				})
				return dir
			},
			wantPath: true,
		},
		{
			// Depends on jackson but never calls readValue: the sink is loaded code, main
			// searched the whole closure hazard-free, so it is listed Searched.
			name: "depends on jackson, never calls it: searched",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, "")
				writeMain(t, dir, func(b *kclassBuilder) []byte {
					return b.invokeVirtual(objectMapper, "writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;")
				})
				return dir
			},
			wantSearched: true,
			denyReasons:  []string{plugin.PartialReasonNoIngress, plugin.PartialReasonReachabilityUndetermined},
		},
		{
			// Spring Boot: main hands control to SpringApplication.run, which drives the
			// framework through reflection. Undetermined with a reflection reason, never
			// Searched, even though the controller does not call the sink.
			name: "spring boot main: undetermined with reflection",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, `    implementation("org.springframework.boot:spring-boot:2.7.0")`)
				sb := newKClassBuilder()
				sbCode := append(sb.invokeVirtual("java/lang/reflect/Method", "invoke",
					"(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), opReturn)
				sb.addMethod("run", "(Ljava/lang/Class;[Ljava/lang/String;)Lorg/springframework/context/ConfigurableApplicationContext;", sbCode)
				writeGradleCacheJar(t, dir, "org.springframework.boot", "spring-boot", "2.7.0", map[string][]byte{
					"org/springframework/boot/SpringApplication": sb.build("org/springframework/boot/SpringApplication", "java/lang/Object"),
				})
				writeMain(t, dir, func(b *kclassBuilder) []byte {
					return b.invokeStatic("org/springframework/boot/SpringApplication", "run",
						"(Ljava/lang/Class;[Ljava/lang/String;)Lorg/springframework/context/ConfigurableApplicationContext;")
				})
				ctrl := newKClassBuilder()
				ctrl.addClassAnnotation(ctrl.anno(descRestController))
				ctrl.addMethodAnnotated("health", "()V", []byte{opReturn},
					ctrl.anno(descGetMapping, kannoElem{name: "value", value: "/health"}))
				writeClassFixture(t, dir, "com/example/api/HealthController",
					ctrl.build("com/example/api/HealthController", "java/lang/Object"))
				return dir
			},
			wantReasons: []string{plugin.PartialReasonReflection, plugin.PartialReasonReachabilityUndetermined},
		},
		{
			// Only main licenses: a framework root's clean empty search clears nothing.
			name: "framework root only, sink not reached: no_whole_program_root",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, "")
				ctrl := newKClassBuilder()
				ctrl.addClassAnnotation(ctrl.anno(descRestController))
				ctrl.addMethodAnnotated("health", "()V", []byte{opReturn},
					ctrl.anno(descGetMapping, kannoElem{name: "value", value: "/health"}))
				writeClassFixture(t, dir, "com/example/api/HealthController",
					ctrl.build("com/example/api/HealthController", "java/lang/Object"))
				return dir
			},
			wantReasons: []string{partialReasonNoWholeProgramRoot, plugin.PartialReasonReachabilityUndetermined},
			denyReasons: []string{plugin.PartialReasonNoIngress},
		},
		{
			// A framework root that does reach the sink is still a candidate.
			name: "framework root reaches sink: candidate without main",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, "")
				ctrl := newKClassBuilder()
				ctrl.addClassAnnotation(ctrl.anno(descRestController))
				code := append(ctrl.invokeVirtual(objectMapper, "readValue", readValueDesc), opReturn)
				ctrl.addMethodAnnotated("parse", "()V", code,
					ctrl.anno(descGetMapping, kannoElem{name: "value", value: "/parse"}))
				writeClassFixture(t, dir, "com/example/api/ParseController",
					ctrl.build("com/example/api/ParseController", "java/lang/Object"))
				return dir
			},
			wantPath: true,
		},
		{
			// A framework root that abstains blocks the clear even when main is clean.
			name: "main clean, framework root hazard: undetermined",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, "")
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				ctrl := newKClassBuilder()
				ctrl.addClassAnnotation(ctrl.anno(descRestController))
				code := append(ctrl.invokeStatic("java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;"), opReturn)
				ctrl.addMethodAnnotated("load", "()V", code,
					ctrl.anno(descGetMapping, kannoElem{name: "value", value: "/load"}))
				writeClassFixture(t, dir, "com/example/api/LoadController",
					ctrl.build("com/example/api/LoadController", "java/lang/Object"))
				return dir
			},
			wantReasons: []string{plugin.PartialReasonReflection, plugin.PartialReasonReachabilityUndetermined},
		},
		{
			// Roots come from first-party code only: a `main` inside a dependency JAR that
			// calls the sink is not this program's entry point.
			name: "dependency jar main is not a root: searched",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, `    implementation("org.tool:cli:1.0")`)
				cli := newKClassBuilder()
				code := append(cli.invokeVirtual(objectMapper, "readValue", readValueDesc), opReturn)
				cli.addMethod("main", mainStringsDesc, code)
				writeGradleCacheJar(t, dir, "org.tool", "cli", "1.0", map[string][]byte{
					"org/tool/Cli": cli.build("org/tool/Cli", "java/lang/Object"),
				})
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				return dir
			},
			wantSearched: true,
		},
		{
			// A call into a dependency the inventory never listed is unseen code.
			name: "call into undeclared dependency: undetermined",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, "")
				writeMain(t, dir, func(b *kclassBuilder) []byte {
					return b.invokeStatic("org/other/Helper", "run", "()V")
				})
				return dir
			},
			wantReasons: []string{plugin.PartialReasonReachabilityUndetermined},
		},
		{
			// The reflection reason must survive an earlier, different hazard on the same search.
			name: "unloaded call then reflection: reflection still reported",
			setup: func(t *testing.T) string {
				dir := gradleJacksonBuild(t, "")
				writeMain(t, dir, func(b *kclassBuilder) []byte {
					code := b.invokeStatic("org/other/Helper", "run", "()V")
					return append(code, b.invokeStatic("java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;")...)
				})
				return dir
			},
			wantReasons: []string{plugin.PartialReasonReflection, plugin.PartialReasonReachabilityUndetermined},
		},
		{
			// An abstract sink is never an engine target, so an empty search for it is not
			// evidence.
			name: "abstract sink: undetermined",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeBuildFile(t, dir, "build.gradle.kts", "dependencies {\n    implementation(\"org.x:iface:1.0\")\n}\n")
				ib := newKClassBuilder()
				ib.methods = append(ib.methods, kbuiltMethod{nameIdx: ib.utf8("parse"), descIdx: ib.utf8("()V")})
				writeGradleCacheJar(t, dir, "org.x", "iface", "1.0", map[string][]byte{
					"org/x/Parser": buildAbstractMethodClass(ib, "org/x/Parser"),
				})
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				return dir
			},
			wantReasons: []string{plugin.PartialReasonReachabilityUndetermined},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			sink := readValueSink
			if strings.HasPrefix(tt.name, "abstract sink") {
				sink = "org/x/Parser.parse()V"
			}
			res := reach(t, dir, sink)
			if got := len(res.Paths) == 1; got != tt.wantPath {
				t.Errorf("path found = %v, want %v (paths %+v, partiality %+v)", got, tt.wantPath, res.Paths, res.Partiality)
			}
			wantSearched := []string(nil)
			if tt.wantSearched {
				wantSearched = []string{sink}
			}
			if !reflect.DeepEqual(res.Searched, wantSearched) {
				t.Errorf("Searched = %v, want %v (partiality %+v)", res.Searched, wantSearched, res.Partiality)
			}
			for _, r := range tt.wantReasons {
				if !hasReason(res.Partiality, r) {
					t.Errorf("reasons %v missing %q", res.Partiality.Reasons, r)
				}
			}
			for _, r := range tt.denyReasons {
				if hasReason(res.Partiality, r) {
					t.Errorf("reasons %v must not carry %q", res.Partiality.Reasons, r)
				}
			}
			if tt.wantSearched && !res.Partiality.Complete {
				t.Errorf("searched row must be Complete, got %+v", res.Partiality)
			}
		})
	}
}

// buildAbstractMethodClass emits an abstract class whose single method (already registered on
// b without code) is ACC_ABSTRACT. The shared builder always emits a Code attribute, so the
// method table is written here.
func buildAbstractMethodClass(b *kclassBuilder, name string) []byte {
	const accAbstract = 0x0400
	thisIdx := b.class(name)
	superIdx := b.class("java/lang/Object")
	var out []byte
	out = append(out, be4(0xCAFEBABE)...)
	out = append(out, be2(0)...)
	out = append(out, be2(classMajorJava8)...)
	out = append(out, be2(uint16(len(b.entries)+1))...)
	for _, e := range b.entries {
		out = append(out, e...)
	}
	out = append(out, be2(accPublicSuper|accAbstract)...)
	out = append(out, be2(thisIdx)...)
	out = append(out, be2(superIdx)...)
	out = append(out, be2(0)...) // interfaces
	out = append(out, be2(0)...) // fields
	out = append(out, be2(uint16(len(b.methods)))...)
	for _, m := range b.methods {
		out = append(out, be2(accPublic|accAbstract)...)
		out = append(out, be2(m.nameIdx)...)
		out = append(out, be2(m.descIdx)...)
		out = append(out, be2(0)...) // no attributes
	}
	out = append(out, be2(0)...) // class attributes
	return out
}

// TestReachability_MissingJarScopedTargets: an inventory dependency whose JAR is not cached is a
// scoped blind spot. Its Targets are the JAR's package, its closure, first-party code ("") and
// first-party code's dependency closure (every inventory node), or nil when either closure is
// unknown. Each scoped reason is also declared run-wide.
//
// The fixture inventory: app depends on a, c and optionally nopom; a depends on b. b and c are
// fully cached; a's POM is cached, its JAR only when the row says so; nopom has neither.
func TestReachability_MissingJarScopedTargets(t *testing.T) {
	tests := []struct {
		name      string
		cacheA    bool // a's JAR is cached
		withNoPOM bool // the app also depends on nopom (no POM, no JAR)
		want      []plugin.ScopedReason
	}{
		{name: "jar present: no reason", cacheA: true},
		{
			name: "jar missing, closures known: own closure, first party and its closure",
			want: []plugin.ScopedReason{{
				Reason: partialReasonMissingJar, Package: "pkg:maven/org.a/a", Path: "org.a:a:1.0",
				Targets: []string{"", "pkg:maven/org.a/a", "pkg:maven/org.b/b", "pkg:maven/org.c/c"},
			}},
		},
		{
			name:   "jar and metadata missing: unbounded",
			cacheA: true, withNoPOM: true,
			want: []plugin.ScopedReason{{Reason: partialReasonMissingJar, Package: "pkg:maven/org.nopom/nopom", Path: "org.nopom:nopom:3.0"}},
		},
		{
			name:      "jar missing, first-party closure unknown: unbounded",
			withNoPOM: true,
			want: []plugin.ScopedReason{
				{Reason: partialReasonMissingJar, Package: "pkg:maven/org.a/a", Path: "org.a:a:1.0"},
				{Reason: partialReasonMissingJar, Package: "pkg:maven/org.nopom/nopom", Path: "org.nopom:nopom:3.0"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			deps := `<dependency><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></dependency>
<dependency><groupId>org.c</groupId><artifactId>c</artifactId><version>1.0</version></dependency>`
			if tt.withNoPOM {
				deps += `
<dependency><groupId>org.nopom</groupId><artifactId>nopom</artifactId><version>3.0</version></dependency>`
			}
			writeBuildFile(t, dir, "pom.xml", `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies>
`+deps+`
</dependencies></project>`)
			writePOM := func(group, artifact, version, body string) {
				p := m2Path(dir, group, artifact, version, "pom")
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			writePOM("org.a", "a", "1.0", `<project><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.b</groupId><artifactId>b</artifactId><version>2.0</version></dependency></dependencies></project>`)
			writePOM("org.b", "b", "2.0", `<project><groupId>org.b</groupId><artifactId>b</artifactId><version>2.0</version></project>`)
			writePOM("org.c", "c", "1.0", `<project><groupId>org.c</groupId><artifactId>c</artifactId><version>1.0</version></project>`)
			jar := func(group, artifact, version, class string) {
				b := newKClassBuilder()
				b.addMethod("sink", "()V", []byte{opReturn})
				writeJar(t, m2Path(dir, group, artifact, version, "jar"), map[string][]byte{class: b.build(class, "java/lang/Object")})
			}
			jar("org.b", "b", "2.0", "org/b/B")
			jar("org.c", "c", "1.0", "org/c/C")
			if tt.cacheA {
				jar("org.a", "a", "1.0", "org/a/A")
			}

			mb := newKClassBuilder()
			mb.addMethod("main", mainStringsDesc, []byte{opReturn})
			path := filepath.Join(dir, "target", "classes", "com", "example", "Main.class")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, mb.build("com/example/Main", "java/lang/Object"), 0o644); err != nil {
				t.Fatal(err)
			}

			res := reach(t, dir, "org/b/B.sink()V")
			if !reflect.DeepEqual(res.Partiality.Scoped, tt.want) {
				t.Fatalf("Scoped = %+v\nwant     %+v", res.Partiality.Scoped, tt.want)
			}
			if mirrored := hasReason(res.Partiality, partialReasonMissingJar); mirrored != (len(tt.want) > 0) {
				t.Errorf("run-wide %s declared = %v, want %v (every scoped reason is mirrored run-wide): %v",
					partialReasonMissingJar, mirrored, len(tt.want) > 0, res.Partiality.Reasons)
			}
			if len(tt.want) > 0 && res.Partiality.Complete {
				t.Error("a result carrying scoped reasons must not be Complete")
			}
			// b was loaded and main never calls it: the sink is searched either way. The scoped
			// reasons are the gate's to apply per advisory.
			if !reflect.DeepEqual(res.Searched, []string{"org/b/B.sink()V"}) {
				t.Errorf("Searched = %v, want the loaded sink", res.Searched)
			}
		})
	}
}

// TestProgramClosure: first-party code's dependency closure is every inventory node, and it is
// unknown (nil) as soon as any part of the graph is: a graph-level limit, a node whose out-edges
// were not read, a node that is not a Maven package, or an edge to a node the inventory lacks.
func TestProgramClosure(t *testing.T) {
	node := func(id, purl string, reasons ...string) plugin.DependencyNode {
		return plugin.DependencyNode{ID: id, PURL: purl, Partiality: plugin.Partiality{Complete: len(reasons) == 0, Reasons: reasons}}
	}
	a := node("a", "pkg:maven/org.a/a@1.0")
	b := node("b", "pkg:maven/org.b/b@2.0")
	c := node("c", "pkg:maven/org.c/c@1.0")
	ab := []plugin.DependencyEdge{{Parent: "a", Child: "b"}}
	tests := []struct {
		name string
		inv  plugin.DependencyInventory
		want []string
	}{
		{
			name: "complete graph: every node",
			inv:  plugin.DependencyInventory{Partiality: plugin.Partiality{Complete: true}, Nodes: []plugin.DependencyNode{a, b, c}, Edges: ab},
			want: []string{"pkg:maven/org.a/a", "pkg:maven/org.b/b", "pkg:maven/org.c/c"},
		},
		{
			name: "graph-level limit",
			inv: plugin.DependencyInventory{
				Partiality: plugin.Partiality{Reasons: []string{plugin.PartialReasonRelationshipUnexpressed + ":property_unresolved"}},
				Nodes:      []plugin.DependencyNode{a, b, c}, Edges: ab,
			},
		},
		{
			name: "a node whose out-edges were not read",
			inv: plugin.DependencyInventory{Partiality: plugin.Partiality{Complete: true}, Nodes: []plugin.DependencyNode{
				a, b, node("c", "pkg:maven/org.c/c@1.0", partialReasonMissingJar),
			}, Edges: ab},
		},
		{
			name: "a node that is not a Maven package",
			inv:  plugin.DependencyInventory{Partiality: plugin.Partiality{Complete: true}, Nodes: []plugin.DependencyNode{a, b, c, node("x", "pkg:generic/x@1")}, Edges: ab},
		},
		{
			name: "an edge to a node the inventory lacks",
			inv: plugin.DependencyInventory{Partiality: plugin.Partiality{Complete: true}, Nodes: []plugin.DependencyNode{a, b, c},
				Edges: append([]plugin.DependencyEdge{{Parent: "c", Child: "gone"}}, ab...)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newInventoryGraph(tt.inv).programClosure(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("programClosure = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestReachability_DuplicateClassIsScoped: when two dependency JARs define the same class, the
// engine keeps the first; the shadowed body is a scoped blind spot of the second JAR.
func TestReachability_DuplicateClassIsScoped(t *testing.T) {
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", `
dependencies {
    implementation("org.one:one:1.0")
    implementation("org.two:two:1.0")
}
`)
	dup := func() []byte {
		b := newKClassBuilder()
		b.addMethod("run", "()V", []byte{opReturn})
		return b.build("org/shared/Dup", "java/lang/Object")
	}
	writeGradleCacheJar(t, dir, "org.one", "one", "1.0", map[string][]byte{"org/shared/Dup": dup()})
	writeGradleCacheJar(t, dir, "org.two", "two", "1.0", map[string][]byte{"org/shared/Dup": dup()})
	writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })

	res := reach(t, dir, "org/shared/Dup.run()V")
	if len(res.Partiality.Scoped) != 1 {
		t.Fatalf("want one scoped reason, got %+v", res.Partiality.Scoped)
	}
	if !hasReason(res.Partiality, partialReasonDuplicateClass) {
		t.Errorf("a scoped blind spot must also be declared run-wide, got %v", res.Partiality.Reasons)
	}
	got := res.Partiality.Scoped[0]
	if got.Reason != partialReasonDuplicateClass || got.Package != "pkg:maven/org.two/two" {
		t.Errorf("scoped = %+v, want duplicate_class on org.two:two", got)
	}
	// Declared-direct Gradle nodes carry gradle_transitive: the closure is unknown.
	if got.Targets != nil {
		t.Errorf("Targets = %v, want nil (closure unknown without a lockfile)", got.Targets)
	}
}

// TestResolveDependencySymbols_OriginsAndMatched: every symbol resolved from the dependency JAR
// carries the dependency's PURL (no version) as its Origin, and each advisory symbol maps,
// verbatim, to the SCIPs it resolved to. An advisory symbol that resolved to nothing is absent
// from the map and declared.
func TestResolveDependencySymbols_OriginsAndMatched(t *testing.T) {
	dir := gradleJacksonBuild(t, "")
	const (
		hit  = "com.fasterxml.jackson.databind.ObjectMapper.readValue"
		miss = "com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping"
	)
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        dir,
		PURL:            jacksonPURL,
		AdvisorySymbols: []string{hit, " " + miss},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || res.Resolved[0].SCIP != readValueSink {
		t.Fatalf("Resolved = %+v, want only %s", res.Resolved, readValueSink)
	}
	if !reflect.DeepEqual(res.Origins, map[string]string{readValueSink: jacksonPURL}) {
		t.Errorf("Origins = %v", res.Origins)
	}
	if !reflect.DeepEqual(res.Matched, map[string][]string{hit: {readValueSink}}) {
		t.Errorf("Matched = %v", res.Matched)
	}
	if !hasReason(res.Partiality, partialReasonAdvisorySymbolUnresolved) {
		t.Errorf("an unresolved advisory symbol must be declared, got %+v", res.Partiality)
	}

	// The resolved sink is exactly what Reachability lists as Searched for an app that depends
	// on jackson but never calls readValue: the arm-A chain Matched → Origins → Searched.
	writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
	r := reach(t, dir, res.Resolved[0].SCIP)
	if !reflect.DeepEqual(r.Searched, []string{readValueSink}) {
		t.Errorf("Searched = %v, want [%s]", r.Searched, readValueSink)
	}
}
