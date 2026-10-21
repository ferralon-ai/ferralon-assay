package kotlinanalysis

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// splitpackage_test.go — the platform set through the real loaders: a package counts as the
// JDK's only while no classpath JAR or class directory defines a class in it, and an entry
// that cannot be listed leaves only java/ and arrays to the JDK.

const (
	errorproneGroup    = "com.google.errorprone"
	errorproneArtifact = "javac"
	errorproneVersion  = "9.4.0"
	javacOption        = "com/sun/tools/javac/main/Option"
	saxParserFactory   = "javax/xml/parsers/SAXParserFactory"
)

// writeRawJar writes a JAR whose entries are named exactly as given (writeJar appends .class).
func writeRawJar(t *testing.T, path string, entries map[string][]byte) {
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
	for name, data := range entries {
		w, err := zw.Create(name)
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

func plainClass(name string) []byte {
	b := newKClassBuilder()
	b.addMethod("run", "()V", []byte{opReturn})
	return b.build(name, "java/lang/Object")
}

// TestReachability_SplitPackages: main calls jackson's writeValueAsString and one class under
// a JDK package; readValue is the sink. Searched means that class was taken as the JDK's.
func TestReachability_SplitPackages(t *testing.T) {
	callsOption := func(b *kclassBuilder) []byte {
		return append(b.invokeStatic(javacOption, "values", "()[Lcom/sun/tools/javac/main/Option;"),
			b.invokeVirtual(objectMapper, "writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;")...)
	}
	callsParsers := func(b *kclassBuilder) []byte {
		return append(b.invokeStatic(saxParserFactory, "newDefaultInstance", "()Ljavax/xml/parsers/SAXParserFactory;"),
			b.invokeVirtual(objectMapper, "writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;")...)
	}
	// errorproneJarPath is the JAR's place in a cache outside the build tree the launch-option
	// scan reads. A build whose errorprone JAR goes there (withErrorprone with no jar) has the
	// graph name it there, whether or not a row writes it.
	var home string
	errorproneJarPath := func(string) string {
		return filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1",
			errorproneGroup, errorproneArtifact, errorproneVersion, "0123abcd", errorproneArtifact+"-"+errorproneVersion+".jar")
	}
	var outside []graphDep
	withErrorprone := func(t *testing.T, main func(*kclassBuilder) []byte, jar map[string][]byte) string {
		dir := gradleJacksonBuild(t, `    implementation("`+errorproneGroup+":"+errorproneArtifact+":"+errorproneVersion+`")`)
		if jar != nil {
			writeGradleCacheJar(t, dir, errorproneGroup, errorproneArtifact, errorproneVersion, jar)
		} else {
			outside = append(outside, graphDep{group: errorproneGroup, artifact: errorproneArtifact, version: errorproneVersion, jar: errorproneJarPath(dir)})
		}
		writeMain(t, dir, main)
		return dir
	}
	tests := []struct {
		name         string
		setup        func(t *testing.T) string
		wantSearched bool
		wantReasons  []string
	}{
		{"a dependency JAR defines Option only under META-INF/versions/11/: Option is unopened", func(t *testing.T) string {
			return withErrorprone(t, callsOption, map[string][]byte{"META-INF/versions/11/" + javacOption: plainClass(javacOption)})
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
		{"a dependency JAR defines a class beside Option: Option is unopened", func(t *testing.T) string {
			return withErrorprone(t, callsOption, map[string][]byte{"com/sun/tools/javac/main/Main": plainClass("com/sun/tools/javac/main/Main")})
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
		{"control: no classpath entry defines com/sun/tools/javac/main, so Option is the JDK's", func(t *testing.T) string {
			return withErrorprone(t, callsOption, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
		}, true, nil},
		{"a first-party JAR defines Option only under META-INF/versions/11/: Option is unopened", func(t *testing.T) string {
			dir := withErrorprone(t, callsOption, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
			writeJar(t, filepath.Join(dir, "build", "libs", "app.jar"), map[string][]byte{"META-INF/versions/11/" + javacOption: plainClass(javacOption)})
			return dir
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
		{"a fat JAR in build/libs nests BOOT-INF/lib/javac-shaded.jar: Option is unopened", func(t *testing.T) string {
			dir := withErrorprone(t, callsOption, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
			writeRawJar(t, filepath.Join(dir, "build", "libs", "app.jar"), map[string][]byte{
				"com/acme/Boot.class":           plainClass("com/acme/Boot"),
				"BOOT-INF/lib/javac-shaded.jar": []byte("PK nested"),
			})
			return dir
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
		{"a WAR-shaped JAR in build/libs nests WEB-INF/lib/javac-shaded.jar: Option is unopened", func(t *testing.T) string {
			dir := withErrorprone(t, callsOption, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
			writeRawJar(t, filepath.Join(dir, "build", "libs", "app.jar"), map[string][]byte{
				"com/acme/Boot.class":          plainClass("com/acme/Boot"),
				"WEB-INF/lib/javac-shaded.jar": []byte("PK nested"),
			})
			return dir
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
		{"a dependency JAR's manifest names Class-Path: javac-shaded.jar: Option is unopened", func(t *testing.T) string {
			dir := withErrorprone(t, callsOption, nil)
			writeRawJar(t, errorproneJarPath(dir), map[string][]byte{
				"com/google/errorprone/Other.class": plainClass("com/google/errorprone/Other"),
				"META-INF/MANIFEST.MF":              []byte("Manifest-Version: 1.0\r\nClass-Path: javac-shaded.jar\r\n\r\n"),
			})
			return dir
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
		{"control: a dependency JAR's manifest has an empty Class-Path, so Option is the JDK's", func(t *testing.T) string {
			dir := withErrorprone(t, callsOption, nil)
			writeRawJar(t, errorproneJarPath(dir), map[string][]byte{
				"com/google/errorprone/Other.class": plainClass("com/google/errorprone/Other"),
				"META-INF/MANIFEST.MF":              []byte("Manifest-Version: 1.0\r\nClass-Path: \r\n\r\n"),
			})
			return dir
		}, true, nil},
		{"control: a JAR in build/libs with no nested archive, so Option is the JDK's", func(t *testing.T) string {
			dir := withErrorprone(t, callsOption, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
			writeRawJar(t, filepath.Join(dir, "build", "libs", "app.jar"), map[string][]byte{
				"com/acme/Boot.class":  plainClass("com/acme/Boot"),
				"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\n\n"),
			})
			return dir
		}, true, nil},
		{"a first-party class root holds a nested JAR: Option is unopened", func(t *testing.T) string {
			dir := withErrorprone(t, callsOption, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
			writeRawJar(t, filepath.Join(dir, "build", "classes", "kotlin", "main", "lib", "javac-shaded.jar"),
				map[string][]byte{"com/sun/tools/javac/main/Main.class": plainClass("com/sun/tools/javac/main/Main")})
			return dir
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
		{"a corrupt dependency JAR may define javax/xml/parsers: not searched", func(t *testing.T) string {
			dir := withErrorprone(t, callsParsers, nil)
			p := errorproneJarPath(dir)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("PK\x03\x04 not a zip"), 0o644); err != nil {
				t.Fatal(err)
			}
			return dir
		}, false, []string{plugin.PartialReasonReachabilityUndetermined, plugin.PartialReasonToolFailure}},
		{"control: every dependency JAR lists, so javax/xml/parsers is the JDK's", func(t *testing.T) string {
			return withErrorprone(t, callsParsers, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
		}, true, nil},
		{"an uncached dependency JAR may define javax/xml/parsers: not searched", func(t *testing.T) string {
			return withErrorprone(t, callsParsers, nil)
		}, false, []string{plugin.PartialReasonReachabilityUndetermined}},
	}
	// moveClassRoot moves the first-party class root out to target and leaves a symlink to it.
	moveClassRoot := func(t *testing.T, dir, target string) {
		t.Helper()
		root := filepath.Join(dir, "build", "classes", "kotlin", "main")
		if err := os.Rename(root, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, root); err != nil {
			t.Fatal(err)
		}
	}
	controlBuild := func(t *testing.T) string {
		return withErrorprone(t, callsParsers, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
	}
	tests = append(tests, []struct {
		name         string
		setup        func(t *testing.T) string
		wantSearched bool
		wantReasons  []string
	}{
		{"a class root symlinked outside the build tree is never opened: its main calling the sink is not read", func(t *testing.T) string {
			dir := withErrorprone(t, func(b *kclassBuilder) []byte {
				return b.invokeVirtual(objectMapper, "readValue", readValueDesc)
			}, map[string][]byte{"com/google/errorprone/Other": plainClass("com/google/errorprone/Other")})
			moveClassRoot(t, dir, filepath.Join(t.TempDir(), "elsewhere"))
			return dir
		}, false, nil},
		{"control: a class root symlinked inside the build tree lists and loads normally", func(t *testing.T) string {
			dir := controlBuild(t)
			moveClassRoot(t, dir, filepath.Join(dir, "build", "real-classes"))
			return dir
		}, true, nil},
		{"a FIFO in build/libs is never opened: not searched", func(t *testing.T) string {
			dir := controlBuild(t)
			if err := os.MkdirAll(filepath.Join(dir, "build", "libs"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := mkfifo(filepath.Join(dir, "build", "libs", "app.jar")); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			return dir
		}, false, nil},
		{"a FIFO in build/libs is a load failure even when no JDK-named class is called: not searched", func(t *testing.T) string {
			dir := gradleJacksonBuild(t, "")
			writeMain(t, dir, func(b *kclassBuilder) []byte {
				return b.invokeVirtual(objectMapper, "writeValueAsString", "(Ljava/lang/Object;)Ljava/lang/String;")
			})
			if err := os.MkdirAll(filepath.Join(dir, "build", "libs"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := mkfifo(filepath.Join(dir, "build", "libs", "app.jar")); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			return dir
		}, false, []string{plugin.PartialReasonToolFailure}},
	}...)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, outside = t.TempDir(), nil
			dir := tt.setup(t)
			res := reachWith(t, dir, cacheGraph(t, dir, outside...), readValueSink)
			if len(res.Paths) != 0 {
				t.Fatalf("paths %+v", res.Paths)
			}
			want := []string(nil)
			if tt.wantSearched {
				want = []string{readValueSink}
			}
			if !reflect.DeepEqual(res.Searched, want) {
				t.Errorf("Searched = %v, want %v (partiality %+v)", res.Searched, want, res.Partiality)
			}
			for _, r := range tt.wantReasons {
				if !hasReason(res.Partiality, r) {
					t.Errorf("reasons %v missing %q", res.Partiality.Reasons, r)
				}
			}
		})
	}
}
