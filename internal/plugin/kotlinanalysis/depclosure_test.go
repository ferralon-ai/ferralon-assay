package kotlinanalysis

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
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

// gradleLocking is the locking statement the Java lane's lock confirmation requires before it
// takes a lockfile's versions as the build's: without it Gradle never reads the lock.
const gradleLocking = "dependencyLocking { lockAllConfigurations() }\n"

// enforceLocking appends gradleLocking to dir's build.gradle.kts.
func enforceLocking(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, "build.gradle.kts")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(data, gradleLocking...), 0o644); err != nil {
		t.Fatal(err)
	}
}

// gradleJacksonBuild declares jackson-databind (and any extra implementation lines) in
// build.gradle.kts, enforces locking, locks every declared coordinate on runtimeClasspath with
// its POM cached, and caches the jackson JAR. The confirmed lock is what lets an empty search be
// Searched: without one the inventory declares gradle_transitive (no lockfile) or
// gradle_lockfile_unconfirmed and the op withholds Searched.
func gradleJacksonBuild(t *testing.T, extra string) string {
	t.Helper()
	dir := unlockedJacksonBuild(t, extra)
	enforceLocking(t, dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	coords := []string{jacksonGroup + ":" + jacksonArtifact + ":" + jacksonVersion}
	for _, m := range regexp.MustCompile(`implementation\("([^"]+)"\)`).FindAllStringSubmatch(extra, -1) {
		coords = append(coords, m[1])
	}
	var lock strings.Builder
	for _, c := range coords {
		gav := strings.Split(c, ":")
		lock.WriteString(c + "=runtimeClasspath\n")
		pom := filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1", gav[0], gav[1], gav[2], "feed", gav[1]+"-"+gav[2]+".pom")
		writeFileAt(t, filepath.Dir(pom), filepath.Base(pom),
			"<project><groupId>"+gav[0]+"</groupId><artifactId>"+gav[1]+"</artifactId><version>"+gav[2]+"</version></project>")
	}
	lock.WriteString("empty=\n")
	writeBuildFile(t, dir, "gradle.lockfile", lock.String())
	return dir
}

// unlockedJacksonBuild is gradleJacksonBuild without a lockfile: the inventory carries the
// declared-direct coordinates only and declares gradle_transitive.
func unlockedJacksonBuild(t *testing.T, extra string) string {
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
	nameLaunchEntry(t, dir, "com.example.MainKt")
}

// nameLaunchEntry ships a manifest naming main as the launch entry, the form that licenses an
// empty search.
func nameLaunchEntry(t *testing.T, dir, main string) {
	t.Helper()
	writeFileAt(t, filepath.Join(dir, "src", "main", "resources", "META-INF"), "MANIFEST.MF",
		"Manifest-Version: 1.0\nMain-Class: "+main+"\n")
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
			nameLaunchEntry(t, dir, "com.example.Main")

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
			// b was loaded and main never calls it. A missing JAR alone leaves the sink searched:
			// the scoped reasons are the gate's to apply per advisory. A missing POM leaves a
			// subtree the inventory cannot see (maven_uncached_subtree), and the op withholds
			// Searched under it.
			var want []string
			if !tt.withNoPOM {
				want = []string{"org/b/B.sink()V"}
			}
			if !reflect.DeepEqual(res.Searched, want) {
				t.Errorf("Searched = %v, want %v (%v)", res.Searched, want, res.Partiality.Reasons)
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
			// A scoped limit names a package the inventory could not fully read, so the graph is
			// not fully known even with no graph-level reason.
			name: "a scoped limit only",
			inv: plugin.DependencyInventory{
				Partiality: plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonToolFailure, Package: "pkg:maven/org.c/c"}}},
				Nodes:      []plugin.DependencyNode{a, b, c}, Edges: ab,
			},
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

// jacksonJarWriteCallsRead is a jackson-databind whose writeValueAsString calls readValue: the
// sink is reachable from a main that only writes.
func jacksonJarWriteCallsRead() map[string][]byte {
	b := newKClassBuilder()
	b.addMethod("readValue", readValueDesc, []byte{opReturn})
	code := append(b.invokeVirtual(objectMapper, "readValue", readValueDesc), opReturn)
	b.addMethod("writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;", code)
	return map[string][]byte{objectMapper: b.build(objectMapper, "java/lang/Object")}
}

// lockedJacksonBuild is a Gradle build declaring jackson-databind with the given lockfiles
// (path relative to the build -> content). Jackson 2.9.8's writeValueAsString is a leaf and
// 2.9.9's calls the sink; both JARs are cached, with their POMs in the user Gradle cache so the
// inventory graph is complete. main calls writeValueAsString.
func lockedJacksonBuild(t *testing.T, lockfiles map[string]string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", "dependencies {\n    implementation(\""+jacksonGroup+":"+jacksonArtifact+":2.9.8\")\n}\n"+gradleLocking)
	for rel, content := range lockfiles {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"2.9.8", "2.9.9"} {
		pom := filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1", jacksonGroup, jacksonArtifact, v, "feed", jacksonArtifact+"-"+v+".pom")
		if err := os.MkdirAll(filepath.Dir(pom), 0o755); err != nil {
			t.Fatal(err)
		}
		body := "<project><groupId>" + jacksonGroup + "</groupId><artifactId>" + jacksonArtifact + "</artifactId><version>" + v + "</version></project>"
		if err := os.WriteFile(pom, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, "2.9.8", jacksonJar())
	writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, "2.9.9", jacksonJarWriteCallsRead())
	writeMain(t, dir, func(b *kclassBuilder) []byte {
		return b.invokeVirtual(objectMapper, "writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;")
	})
	return dir
}

// TestReachability_GradleLockRuntimeVersion: with a lockfile, the closure loads the version
// runtimeClasspath locks, never one locked only for kapt, annotation processing or tests. A
// coordinate runtimeClasspath locks at more than one version, or at one that is not concrete,
// loads nothing: a named scoped miss (mirrored run-wide) and its package is never Searched.
func TestReachability_GradleLockRuntimeVersion(t *testing.T) {
	const ga = jacksonGroup + ":" + jacksonArtifact
	bounded := []string{"", jacksonPURL}
	tests := []struct {
		name       string
		lockfiles  map[string]string
		wantPath   bool
		wantScoped []plugin.ScopedReason
	}{
		{
			// The inventory keeps the first-seen 2.9.8 (kapt); the runtime runs 2.9.9, whose
			// writeValueAsString reaches the sink.
			name:      "kapt version and runtime version: runtime loads",
			lockfiles: map[string]string{"gradle.lockfile": ga + ":2.9.8=kapt\n" + ga + ":2.9.9=compileClasspath,runtimeClasspath\nempty=\n"},
			wantPath:  true,
		},
		{
			// Not on the runtime classpath: not loaded, so the call is an unloaded dependency.
			name:      "locked only for kapt and tests: not loaded",
			lockfiles: map[string]string{"gradle.lockfile": ga + ":2.9.8=kapt,testRuntimeClasspath\nempty=\n"},
		},
		{
			// A legacy gradle/dependency-locks directory leaves the lock unconfirmed, so the
			// inventory is incomplete and the closure, hence Targets, unbounded.
			name: "two runtime versions: named miss",
			lockfiles: map[string]string{
				"gradle.lockfile": ga + ":2.9.8=runtimeClasspath\nempty=\n",
				"gradle/dependency-locks/runtimeClasspath.lockfile": ga + ":2.9.9=runtimeClasspath\n",
			},
			wantScoped: []plugin.ScopedReason{{Reason: partialReasonRuntimeVersionAmbiguous, Package: jacksonPURL,
				Path: ga + ": runtime classpaths lock 2.9.8, 2.9.9"}},
		},
		{
			// Spring Boot's bootJar packages productionRuntimeClasspath.
			name:      "kapt version and productionRuntimeClasspath version: production runtime loads",
			lockfiles: map[string]string{"gradle.lockfile": ga + ":2.9.8=kapt\n" + ga + ":2.9.9=productionRuntimeClasspath\nempty=\n"},
			wantPath:  true,
		},
		{
			name:      "runtimeClasspath and productionRuntimeClasspath disagree: named miss",
			lockfiles: map[string]string{"gradle.lockfile": ga + ":2.9.8=runtimeClasspath\n" + ga + ":2.9.9=productionRuntimeClasspath\nempty=\n"},
			wantScoped: []plugin.ScopedReason{{Reason: partialReasonRuntimeVersionAmbiguous, Package: jacksonPURL,
				Path: ga + ": runtime classpaths lock 2.9.8, 2.9.9", Targets: bounded}},
		},
		{
			// No POM is cached for 2.+, so the inventory is incomplete (gradle_uncached) and the
			// closure, hence Targets, unbounded.
			name:      "runtime version not concrete: named miss",
			lockfiles: map[string]string{"gradle.lockfile": ga + ":2.9.8=kapt\n" + ga + ":2.+=runtimeClasspath\nempty=\n"},
			wantScoped: []plugin.ScopedReason{{Reason: partialReasonRuntimeVersionAmbiguous, Package: jacksonPURL,
				Path: ga + ": runtime classpaths lock 2.+"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := reach(t, lockedJacksonBuild(t, tt.lockfiles), readValueSink)
			if got := len(res.Paths) == 1; got != tt.wantPath {
				t.Errorf("path found = %v, want %v (partiality %+v)", got, tt.wantPath, res.Partiality)
			}
			if res.Searched != nil {
				t.Errorf("Searched = %v, want none", res.Searched)
			}
			if !reflect.DeepEqual(res.Partiality.Scoped, tt.wantScoped) {
				t.Errorf("Scoped = %+v\nwant     %+v", res.Partiality.Scoped, tt.wantScoped)
			}
			if mirrored := hasReason(res.Partiality, partialReasonRuntimeVersionAmbiguous); mirrored != (len(tt.wantScoped) > 0) {
				t.Errorf("run-wide %s declared = %v, want %v: %v", partialReasonRuntimeVersionAmbiguous, mirrored, len(tt.wantScoped) > 0, res.Partiality.Reasons)
			}
		})
	}
}

// TestResolveDependencySymbols_GradleLockRuntimeVersion: with a lockfile the sink resolves
// against the runtimeClasspath version, the bytes the closure loads, not the build file's or a
// kapt lock's. A PURL pinned to another version is declared: the bytes resolved are not the ones
// it names.
func TestResolveDependencySymbols_GradleLockRuntimeVersion(t *testing.T) {
	const (
		ga       = jacksonGroup + ":" + jacksonArtifact
		onlyNew  = "com.fasterxml.jackson.databind.ObjectMapper.onlyInRuntime"
		onlyDesc = "()V"
	)
	tests := []struct {
		name         string
		purl         string
		wantDeclared bool
	}{
		{name: "unpinned", purl: jacksonPURL},
		{name: "pinned to the kapt version", purl: jacksonPURL + "@2.9.8", wantDeclared: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := lockedJacksonBuild(t, map[string]string{"gradle.lockfile": ga + ":2.9.8=kapt\n" + ga + ":2.9.9=runtimeClasspath\nempty=\n"})
			b := newKClassBuilder()
			b.addMethod("readValue", readValueDesc, []byte{opReturn})
			b.addMethod("onlyInRuntime", onlyDesc, []byte{opReturn})
			writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, "2.9.9", map[string][]byte{objectMapper: b.build(objectMapper, "java/lang/Object")})
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
				BuildDir:        dir,
				PURL:            tt.purl,
				AdvisorySymbols: []string{onlyNew},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := res.Matched[onlyNew]; !ok {
				t.Errorf("%s did not resolve against the runtime 2.9.9 JAR: Matched=%v partiality=%+v", onlyNew, res.Matched, res.Partiality)
			}
			if got := hasReason(res.Partiality, partialReasonNoDependencyArtifact); got != tt.wantDeclared {
				t.Errorf("%s declared = %v, want %v: %v", partialReasonNoDependencyArtifact, got, tt.wantDeclared, res.Partiality.Reasons)
			}
		})
	}
}

// TestReachability_InventoryVersionSelectionLimit: an inventory graph-level reason under which a
// node's version may not be the one the build selects (here an imported BOM absent from the
// cache, so the versions it manages are unknown) is declared run-wide on the result.
func TestReachability_InventoryVersionSelectionLimit(t *testing.T) {
	const bomUncached = plugin.PartialReasonSourceUnpinned + ":bom_uncached"
	tests := []struct {
		name      string
		cacheBOM  bool
		wantLimit bool
	}{
		{name: "imported BOM cached", cacheBOM: true},
		{name: "imported BOM uncached", wantLimit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			dir := t.TempDir()
			writeBuildFile(t, dir, "pom.xml", `<project>
<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencyManagement><dependencies><dependency><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
<dependencies><dependency><groupId>`+jacksonGroup+`</groupId><artifactId>`+jacksonArtifact+`</artifactId><version>`+jacksonVersion+`</version></dependency></dependencies></project>`)
			writePOM := func(group, artifact, version, body string) {
				p := m2Path(dir, group, artifact, version, "pom")
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tt.cacheBOM {
				writePOM("org.bom", "bom", "1.0", `<project><groupId>org.bom</groupId><artifactId>bom</artifactId><version>1.0</version><packaging>pom</packaging></project>`)
			}
			writePOM(jacksonGroup, jacksonArtifact, jacksonVersion, `<project><groupId>`+jacksonGroup+`</groupId><artifactId>`+jacksonArtifact+`</artifactId><version>`+jacksonVersion+`</version></project>`)
			writeJar(t, m2Path(dir, jacksonGroup, jacksonArtifact, jacksonVersion, "jar"), jacksonJar())
			writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })

			res := reach(t, dir, readValueSink)
			if got := hasReason(res.Partiality, bomUncached); got != tt.wantLimit {
				t.Errorf("%s declared = %v, want %v: %+v", bomUncached, got, tt.wantLimit, res.Partiality)
			}
			if tt.wantLimit && res.Partiality.Complete {
				t.Error("result Complete despite an inventory version-selection limit")
			}
			// The loaded jackson may not be the version the BOM would select: no Searched.
			if got := res.Searched != nil; got == tt.wantLimit {
				t.Errorf("Searched = %v with limit %v", res.Searched, tt.wantLimit)
			}
		})
	}
}

// TestMissingJarReasonIsDistinct: the missing-JAR reason is not the inventory's uncached-POM
// reason, so a report never merges "one JAR absent" into "the graph is unresolved", and it
// stays a did-not-run disclosure.
func TestMissingJarReasonIsDistinct(t *testing.T) {
	if partialReasonMissingJar == plugin.PartialReasonRelationshipUnexpressed+":maven_uncached_subtree" {
		t.Errorf("%s is the inventory's maven_uncached_subtree reason", partialReasonMissingJar)
	}
	for _, r := range []string{partialReasonMissingJar, partialReasonRuntimeVersionAmbiguous} {
		if got := report.ClassifyPartialityReason(r); got != report.PartialityDidNotRun {
			t.Errorf("ClassifyPartialityReason(%s) = %v, want did_not_run", r, got)
		}
	}
}

// TestProgramClosureCoversInventory pins admitted ⊆ program for inventory mode: the dependency
// SBOM a Kotlin run admits advisories against is javaanalysis.ResolveInventory's node set, the
// same call the closure reads, so every package it names must be inside first-party code's
// closure whenever that closure is bounded. A Targets bound that excluded one of them could
// narrow a limit away from an admitted package.
func TestProgramClosureCoversInventory(t *testing.T) {
	const ga = jacksonGroup + ":" + jacksonArtifact
	dir := lockedJacksonBuild(t, map[string]string{"gradle.lockfile": ga + ":2.9.8=runtimeClasspath\nempty=\n"})
	inv, err := javaanalysis.ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	program := newInventoryGraph(inv).programClosure()
	if program == nil {
		t.Fatalf("closure unbounded on a complete lockfile inventory: %+v", inv.Partiality)
	}
	in := map[string]bool{}
	for _, p := range program {
		in[p] = true
	}
	for _, n := range inv.Nodes {
		group, artifact, _, ok := splitMavenNodePURL(n.PURL)
		if !ok || !in["pkg:maven/"+group+"/"+artifact] {
			t.Errorf("admitted node %s outside the program closure %v", n.PURL, program)
		}
	}
}

// TestLocateDependencyJar_CopiesAcrossCaches: the Gradle module cache and .m2 are one set of
// candidates. Copies of a version whose bytes differ, even one per cache, leave the build's
// bytes unknown and are a miss.
func TestLocateDependencyJar_CopiesAcrossCaches(t *testing.T) {
	jar := func(method string) map[string][]byte {
		b := newKClassBuilder()
		b.addMethod(method, "()V", []byte{opReturn})
		return map[string][]byte{objectMapper: b.build(objectMapper, "java/lang/Object")}
	}
	tests := []struct {
		name          string
		gradle, maven string // method the copy in each cache defines; "" = no copy
		wantOK        bool
	}{
		{name: "gradle cache only", gradle: "a", wantOK: true},
		{name: "m2 only", maven: "a", wantOK: true},
		{name: "same bytes in both", gradle: "a", maven: "a", wantOK: true},
		{name: "different bytes across caches", gradle: "a", maven: "b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			dir := t.TempDir()
			if tt.gradle != "" {
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jar(tt.gradle))
			}
			if tt.maven != "" {
				writeJar(t, m2Path(dir, jacksonGroup, jacksonArtifact, jacksonVersion, "jar"), jar(tt.maven))
			}
			if _, ok := LocateDependencyJar(dir, jacksonGroup+":"+jacksonArtifact, jacksonVersion); ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

// TestInventoryReasons: the graph reasons the op adopts from the inventory, including a
// resolver tool that failed partway, which leaves the node set short of what the build runs.
func TestInventoryReasons(t *testing.T) {
	for _, tt := range []struct {
		reason string
		want   bool
	}{
		{plugin.PartialReasonSourceUnpinned + ":no_lockfile", true},
		{plugin.PartialReasonEnvConditionUnresolved + ":maven_profile", true},
		{plugin.PartialReasonRelationshipUnexpressed + ":gradle_substitution", true},
		{plugin.PartialReasonToolFailure, true},
		{plugin.PartialReasonToolFailure + ":gradle", true},
		{"reflection", false},
	} {
		inv := plugin.DependencyInventory{Partiality: plugin.Partiality{Reasons: []string{tt.reason}}}
		if got := len(inventoryReasons(inv)) == 1; got != tt.want {
			t.Errorf("inventoryReasons(%q) adopted = %v, want %v", tt.reason, got, tt.want)
		}
	}
}

// TestReachability_InventoryGraphReasonsWithholdSearched: the op itself withholds Searched under
// every graph reason the inventory declares, so a library consumer that never applies the
// gate's inventory limits still cannot read an empty search as complete. Each row's main never
// calls the loaded sink.
func TestReachability_InventoryGraphReasonsWithholdSearched(t *testing.T) {
	mavenBuild := func(t *testing.T, childPOM bool) string {
		dir := t.TempDir()
		writeBuildFile(t, dir, "pom.xml", `<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>`)
		pom := func(g, a, v, body string) {
			p := m2Path(dir, g, a, v, "pom")
			writeFileAt(t, filepath.Dir(p), filepath.Base(p), body)
		}
		pom("org.a", "a", "1.0", `<project><groupId>org.a</groupId><artifactId>a</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.b</groupId><artifactId>b</artifactId><version>2.0</version></dependency></dependencies></project>`)
		if childPOM {
			pom("org.b", "b", "2.0", `<project><groupId>org.b</groupId><artifactId>b</artifactId><version>2.0</version></project>`)
		}
		for _, j := range []struct{ g, a, v, class string }{{"org.a", "a", "1.0", "org/a/A"}, {"org.b", "b", "2.0", "org/b/B"}} {
			b := newKClassBuilder()
			b.addMethod("sink", "()V", []byte{opReturn})
			writeJar(t, m2Path(dir, j.g, j.a, j.v, "jar"), map[string][]byte{j.class: b.build(j.class, "java/lang/Object")})
		}
		mb := newKClassBuilder()
		mb.addMethod("main", mainStringsDesc, []byte{opReturn})
		writeFileAt(t, filepath.Join(dir, "target", "classes", "com", "example"), "Main.class", string(mb.build("com/example/Main", "java/lang/Object")))
		nameLaunchEntry(t, dir, "com.example.Main")
		return dir
	}
	gradle := func(locked bool) func(t *testing.T) (string, string) {
		return func(t *testing.T) (string, string) {
			var dir string
			if locked {
				dir = gradleJacksonBuild(t, "")
			} else {
				t.Setenv("HOME", t.TempDir())
				dir = unlockedJacksonBuild(t, "")
			}
			writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
			return dir, readValueSink
		}
	}
	maven := func(childPOM bool) func(t *testing.T) (string, string) {
		return func(t *testing.T) (string, string) { return mavenBuild(t, childPOM), "org/a/A.sink()V" }
	}
	tests := []struct {
		name     string
		build    func(t *testing.T) (string, string)
		reason   string // the graph reason the row declares, "" for none
		searched bool
	}{
		{"gradle, locked: searched", gradle(true), "", true},
		{"gradle, no lockfile: gradle_transitive withholds Searched", gradle(false), "relationship_unexpressed:gradle_transitive", false},
		{"maven, child POM cached: searched", maven(true), "", true},
		{"maven, child POM uncached: maven_uncached_subtree withholds Searched", maven(false), "relationship_unexpressed:maven_uncached_subtree", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, sink := tt.build(t)
			res := reach(t, dir, sink)
			if got := len(res.Searched) > 0; got != tt.searched {
				t.Errorf("Searched = %v, want searched %v (%+v)", res.Searched, tt.searched, res.Partiality)
			}
			if tt.reason != "" && !hasReason(res.Partiality, tt.reason) {
				t.Errorf("reasons %v must carry %q", res.Partiality.Reasons, tt.reason)
			}
			if len(res.Paths) > 0 {
				t.Errorf("main never calls the sink, got paths %v", res.Paths)
			}
		})
	}
}
