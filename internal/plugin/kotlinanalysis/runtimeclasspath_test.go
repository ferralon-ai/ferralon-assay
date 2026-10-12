package kotlinanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// runtimeclasspath_test.go — the Gradle start-script classpath as the closure source, the
// bytes-the-build-uses rule, and the multi-project guard.

// writeStartScript writes a Gradle unix start script at build/<rel> whose classpath is jars
// (each $APP_HOME/lib/<jar>) and whose launch class is mainClass.
func writeStartScript(t *testing.T, dir, rel string, jars []string, mainClass string) {
	t.Helper()
	entries := make([]string, len(jars))
	for i, j := range jars {
		entries[i] = "$APP_HOME/lib/" + j
	}
	script := "#!/bin/sh\nAPP_HOME=$( cd -P \"${APP_HOME:-./}..\" > /dev/null && printf '%s\\n' \"$PWD\" ) || exit\n\n" +
		"CLASSPATH=" + strings.Join(entries, ":") + "\n\n" +
		"set -- \\\n        -classpath \"$CLASSPATH\" \\\n        " + mainClass + " \\\n        \"$@\"\n\nexec \"$JAVACMD\" \"$@\"\n"
	p := filepath.Join(dir, "build", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// writeFileAt writes dir/name, creating dir.
func writeFileAt(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBuildFile(t, dir, name, content)
}

// classCalling emits class name with method run()V whose body is code.
func classCalling(name, method, desc string, emit func(b *kclassBuilder) []byte) []byte {
	b := newKClassBuilder()
	var code []byte
	if emit != nil {
		code = emit(b)
	}
	b.addMethod(method, desc, append(code, opReturn))
	return b.build(name, "java/lang/Object")
}

func callsReadValue(b *kclassBuilder) []byte {
	return b.invokeVirtual(objectMapper, "readValue", readValueDesc)
}

// emptyGradleBuild is a Gradle project with no declared dependencies: without a start script
// nothing but first-party code is loaded.
func emptyGradleBuild(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", "plugins { application }\n")
	return dir
}

const jacksonJarName = jacksonArtifact + "-" + jacksonVersion + ".jar"

// TestReachability_RuntimeClasspath: each row names the rule it pins; loosening the rule flips
// the row.
func TestReachability_RuntimeClasspath(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T) string
		wantPath     bool
		wantSearched bool
		wantReasons  []string
		denyReasons  []string
		wantScoped   []plugin.ScopedReason
	}{
		{
			// Control for the next row: the inventory has no jackson, so the call is unseen.
			name: "no start script, undeclared jackson: undetermined",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeMain(t, dir, callsReadValue)
				return dir
			},
			wantReasons: []string{plugin.PartialReasonReachabilityUndetermined},
		},
		{
			// The script's classpath replaces the inventory: jackson is loaded from the cache
			// by file name though no build file declares it.
			name: "start script names a transitive jar: candidate",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeMain(t, dir, callsReadValue)
				writeStartScript(t, dir, "scripts/app", []string{jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantPath: true,
		},
		{
			// The launch class a script names is a root even though it lives in a dependency.
			name: "launch main in a dependency jar reaches the sink: candidate",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeGradleCacheJar(t, dir, "org.fw", "fw", "1.0", map[string][]byte{
					"org/fw/Launcher": classCalling("org/fw/Launcher", "main", mainStringsDesc, callsReadValue),
				})
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				writeStartScript(t, dir, "scripts/app", []string{"fw-1.0.jar", jacksonJarName}, "org.fw.Launcher")
				return dir
			},
			wantPath: true,
		},
		{
			// Only the named launch class is a root: another dependency main is not.
			name: "dependency main the script does not name: searched",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeGradleCacheJar(t, dir, "org.tool", "cli", "1.0", map[string][]byte{
					"org/tool/Cli": classCalling("org/tool/Cli", "main", mainStringsDesc, callsReadValue),
				})
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				writeStartScript(t, dir, "scripts/app", []string{"cli-1.0.jar", jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantSearched: true,
		},
		{
			// Every first-party main is a root, not just the first one found.
			name: "second first-party main reaches the sink: candidate",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				writeClassFixture(t, dir, "com/example/ToolKt", classCalling("com/example/ToolKt", "main", "()V", callsReadValue))
				writeStartScript(t, dir, "scripts/app", []string{jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantPath: true,
		},
		{
			// On one ordered classpath the JVM loads the first definition: the later JAR's copy
			// (which calls the sink) never runs, and is not a blind spot.
			name: "ordered duplicate: the later copy never runs",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeGradleCacheJar(t, dir, "org.one", "one", "1.0", map[string][]byte{
					"org/shared/Dup": classCalling("org/shared/Dup", "run", "()V", nil),
				})
				writeGradleCacheJar(t, dir, "org.two", "two", "1.0", map[string][]byte{
					"org/shared/Dup": classCalling("org/shared/Dup", "run", "()V", callsReadValue),
				})
				writeMain(t, dir, func(b *kclassBuilder) []byte { return b.invokeStatic("org/shared/Dup", "run", "()V") })
				writeStartScript(t, dir, "scripts/app", []string{"one-1.0.jar", "two-1.0.jar", jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantSearched: true,
			denyReasons:  []string{partialReasonDuplicateClass},
		},
		{
			// Two scripts with different classpaths: which copy runs depends on the launch, so
			// the shadowed copy is an unbounded blind spot, declared run-wide too.
			name: "differing classpaths: duplicate is scoped and declared",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeGradleCacheJar(t, dir, "org.one", "one", "1.0", map[string][]byte{
					"org/shared/Dup": classCalling("org/shared/Dup", "run", "()V", nil),
				})
				writeGradleCacheJar(t, dir, "org.two", "two", "1.0", map[string][]byte{
					"org/shared/Dup": classCalling("org/shared/Dup", "run", "()V", callsReadValue),
				})
				writeMain(t, dir, func(b *kclassBuilder) []byte { return b.invokeStatic("org/shared/Dup", "run", "()V") })
				writeStartScript(t, dir, "scripts/a", []string{"one-1.0.jar", "two-1.0.jar", jacksonJarName}, "com.example.MainKt")
				writeStartScript(t, dir, "scripts/b", []string{"two-1.0.jar", "one-1.0.jar", jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantSearched: true,
			wantReasons:  []string{partialReasonDuplicateClass},
			wantScoped: []plugin.ScopedReason{{
				Reason:  partialReasonDuplicateClass,
				Package: "pkg:maven/org.two/two",
				Path:    "classpath: two-1.0.jar shadowed by one-1.0.jar: org/shared/Dup",
			}},
		},
		{
			name: "classpath jar found nowhere: unbounded scoped reason, declared run-wide",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				writeStartScript(t, dir, "scripts/app", []string{"ghost-1.0.jar", jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantSearched: true,
			wantReasons:  []string{partialReasonMissingJar},
			wantScoped:   []plugin.ScopedReason{{Reason: partialReasonMissingJar, Path: "classpath: ghost-1.0.jar"}},
		},
		{
			// The cache holds two different jackson-databind-2.9.8.jar files and no installDist
			// copy says which one ran: neither is analysed.
			name: "cached copies disagree: the jar is not bound",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
				writeJar(t, filepath.Join(dir, ".gradle", "caches", "modules-2", "files-2.1",
					jacksonGroup, jacksonArtifact, jacksonVersion, "fedcba98", jacksonJarName), map[string][]byte{
					objectMapper: classCalling(objectMapper, "readValue", readValueDesc, func(b *kclassBuilder) []byte {
						return b.invokeStatic("org/other/Helper", "run", "()V")
					}),
				})
				writeMain(t, dir, callsReadValue)
				writeStartScript(t, dir, "scripts/app", []string{jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantReasons: []string{partialReasonMissingJar, plugin.PartialReasonReachabilityUndetermined},
			wantScoped: []plugin.ScopedReason{{
				Reason: partialReasonMissingJar, Package: jacksonPURL, Path: "classpath: " + jacksonJarName,
			}},
		},
		{
			// installDist's lib copy is the one the application runs; a disagreeing cache does
			// not matter then.
			name: "installDist lib copy is bound over the cache",
			setup: func(t *testing.T) string {
				dir := emptyGradleBuild(t)
				writeJar(t, filepath.Join(dir, "build", "install", "app", "lib", jacksonJarName), jacksonJar())
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
				writeStartScript(t, dir, "install/app/bin/app", []string{jacksonJarName}, "com.example.MainKt")
				return dir
			},
			wantSearched: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			res := reach(t, dir, readValueSink)
			if got := len(res.Paths) == 1; got != tt.wantPath {
				t.Errorf("path found = %v, want %v (paths %+v, partiality %+v)", got, tt.wantPath, res.Paths, res.Partiality)
			}
			var wantSearched []string
			if tt.wantSearched {
				wantSearched = []string{readValueSink}
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
			if !reflect.DeepEqual(res.Partiality.Scoped, tt.wantScoped) {
				t.Errorf("Scoped = %+v\nwant     %+v", res.Partiality.Scoped, tt.wantScoped)
			}
		})
	}
}

func TestParseStartScript(t *testing.T) {
	tests := []struct {
		name      string
		classpath string
		launch    string
		wantCP    []string
		wantMain  string
		wantOK    bool
	}{
		{"plain", "$APP_HOME/lib/app-1.0.jar:$APP_HOME/lib/b-2.jar", "io.ktor.server.netty.EngineMain", []string{"app-1.0.jar", "b-2.jar"}, "io/ktor/server/netty/EngineMain", true},
		{"wildcard entry", "$APP_HOME/lib/*", "a.Main", nil, "", false},
		{"entry outside lib", "$APP_HOME/lib/a.jar:/opt/x.jar", "a.Main", nil, "", false},
		{"nested lib path", "$APP_HOME/lib/sub/a.jar", "a.Main", nil, "", false},
		{"not a jar", "$APP_HOME/lib/classes", "a.Main", nil, "", false},
		{"empty classpath", "", "a.Main", nil, "", false},
		{"module launch has no main", "$APP_HOME/lib/a.jar", "--module", []string{"a.jar"}, "", true},
		{"nested launch class", "$APP_HOME/lib/a.jar", "com.x.App$Main", []string{"a.jar"}, "com/x/App$Main", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "app")
			script := "#!/bin/sh\nCLASSPATH=" + tt.classpath + "\nset -- \\\n        -classpath \"$CLASSPATH\" \\\n        " + tt.launch + " \\\n        \"$@\"\n"
			if err := os.WriteFile(p, []byte(script), 0o644); err != nil {
				t.Fatal(err)
			}
			cp, main, ok := parseStartScript(p)
			if ok != tt.wantOK || main != tt.wantMain || !reflect.DeepEqual(cp, tt.wantCP) {
				t.Errorf("got (%v, %q, %v), want (%v, %q, %v)", cp, main, ok, tt.wantCP, tt.wantMain, tt.wantOK)
			}
		})
	}
}

// TestLocateDependencyJar_CachedCopiesMustAgree: two copies of one version in different
// content-hash directories bind only when their bytes are identical.
func TestLocateDependencyJar_CachedCopiesMustAgree(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tests := []struct {
		name   string
		second map[string][]byte
		wantOK bool
	}{
		{"single copy", nil, true},
		{"identical copies", jacksonJar(), true},
		{"different copies", map[string][]byte{objectMapper: classCalling(objectMapper, "other", "()V", nil)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeGradleCacheJar(t, dir, jacksonGroup, jacksonArtifact, jacksonVersion, jacksonJar())
			if tt.second != nil {
				writeJar(t, filepath.Join(dir, ".gradle", "caches", "modules-2", "files-2.1",
					jacksonGroup, jacksonArtifact, jacksonVersion, "fedcba98", jacksonJarName), tt.second)
			}
			if _, ok := LocateDependencyJar(dir, jacksonGroup+":"+jacksonArtifact, jacksonVersion); ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

// TestResolveDependencySymbols_BindsToRuntimeClasspathVersion: the build file declares 2.0.0 but
// the start script runs 1.0.0 (conflict resolution). Advisory symbols resolve against 1.0.0's
// bytes only.
func TestResolveDependencySymbols_BindsToRuntimeClasspathVersion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", "dependencies {\n    implementation(\"com.example:vuln:2.0.0\")\n}\n")
	writeGradleCacheJar(t, dir, "com.example", "vuln", "1.0.0", map[string][]byte{"com/example/net/UrlFetcher": vulnClass()})
	writeGradleCacheJar(t, dir, "com.example", "vuln", "2.0.0", map[string][]byte{
		"com/example/net/UrlFetcher": classCalling("com/example/net/UrlFetcher", "open", "()V", nil),
	})
	writeStartScript(t, dir, "scripts/app", []string{"vuln-1.0.0.jar"}, "com.example.MainKt")

	tests := []struct {
		name           string
		purl           string
		advisory       string
		wantMatched    bool
		wantUnresolved bool
		wantMismatch   bool
	}{
		{"symbol only in the running version resolves", "pkg:maven/com.example/vuln", "com.example.net.UrlFetcher.fetch", true, false, false},
		{"symbol only in the declared version does not", "pkg:maven/com.example/vuln", "com.example.net.UrlFetcher.open", false, true, false},
		{"a pinned version other than the running one is declared", "pkg:maven/com.example/vuln@2.0.0", "com.example.net.UrlFetcher.fetch", true, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
				BuildDir: dir, PURL: tt.purl, AdvisorySymbols: []string{tt.advisory},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(res.Matched[tt.advisory]) > 0; got != tt.wantMatched {
				t.Errorf("matched = %v, want %v (%v)", got, tt.wantMatched, res.Matched)
			}
			if got := hasReason(res.Partiality, partialReasonAdvisorySymbolUnresolved); got != tt.wantUnresolved {
				t.Errorf("unresolved = %v, want %v (%+v)", got, tt.wantUnresolved, res.Partiality)
			}
			if got := hasReason(res.Partiality, partialReasonNoDependencyArtifact); got != tt.wantMismatch {
				t.Errorf("version mismatch declared = %v, want %v (%+v)", got, tt.wantMismatch, res.Partiality)
			}
		})
	}
}

// TestReachability_MultipleProjectsUnsupported: only the build root is traced, so any sign of
// a further project clears no sink and declares multiple_projects_unsupported, which the
// report classifies did_not_run.
func TestReachability_MultipleProjectsUnsupported(t *testing.T) {
	if got := report.ClassifyPartialityReason(partialReasonMultipleProjects); got != report.PartialityDidNotRun {
		t.Fatalf("%s classified %v, want did_not_run", partialReasonMultipleProjects, got)
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		multi bool
	}{
		{"single project", func(t *testing.T, dir string) {}, false},
		{"commented-out include", func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "rootProject.name = \"app\"\n// include(\"web\")\n/* include(\"cli\") */\n")
		}, false},
		{"subdirectory without code", func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "docs"), "README.md", "docs\n")
		}, false},
		{"settings include", func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "rootProject.name = \"app\"\ninclude(\n    \":web\",\n)\n")
		}, true},
		{"groovy settings include", func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle", "include 'web', 'cli'\n")
		}, true},
		{"includeBuild", func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "includeBuild(\"../lib\")\n")
		}, true},
		{"maven modules", func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "pom.xml", "<project><modules><module>web</module></modules></project>")
		}, true},
		{"second project with sources", func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "web"), "build.gradle.kts", "plugins { kotlin(\"jvm\") }\n")
			writeFileAt(t, filepath.Join(dir, "web", "src", "main", "kotlin"), "Web.kt", "fun main() {}\n")
		}, true},
		{"second project's class output", func(t *testing.T, dir string) {
			writeClassFixture(t, filepath.Join(dir, "web"), "com/example/web/WebKt",
				classCalling("com/example/web/WebKt", "main", mainStringsDesc, nil))
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := gradleJacksonBuild(t, "")
			writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
			tt.setup(t, dir)
			res := reach(t, dir, readValueSink)
			if got := hasReason(res.Partiality, partialReasonMultipleProjects); got != tt.multi {
				t.Errorf("%s declared = %v, want %v (%+v)", partialReasonMultipleProjects, got, tt.multi, res.Partiality)
			}
			if got := len(res.Searched) > 0; got == tt.multi {
				t.Errorf("Searched = %v with multi-project = %v", res.Searched, tt.multi)
			}
		})
	}
}
