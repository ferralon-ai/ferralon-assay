package kotlinanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

// callbackClass emits class name (super, ifaces) whose handle()V calls jackson's readValue, the
// sink: a container may call it back with no call the search can see.
func callbackClass(name, super string, ifaces []string, anno string) []byte {
	b := newKClassBuilder()
	if anno != "" {
		b.addClassAnnotation(b.anno(anno))
	}
	b.addMethod("handle", "()V", append(callsReadValue(b), opReturn))
	return b.buildWithInterfaces(name, super, ifaces...)
}

func interfaceStub(name string) []byte {
	return newKClassBuilder().build(name, "java/lang/Object")
}

// withJacksonEntries rewrites the cached jackson JAR with extra raw entries beside its classes.
func withJacksonEntries(t *testing.T, dir string, extra map[string][]byte) {
	t.Helper()
	entries := map[string][]byte{}
	for n, data := range jacksonJar() {
		entries[n+".class"] = data
	}
	for n, data := range extra {
		entries[n] = data
	}
	writeRawJar(t, filepath.Join(dir, ".gradle", "caches", "modules-2", "files-2.1",
		jacksonGroup, jacksonArtifact, jacksonVersion, "0123abcd", jacksonJarName), entries)
}

func appendBuildScript(t *testing.T, dir, text string) {
	t.Helper()
	p := filepath.Join(dir, "build.gradle.kts")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	writeBuildFile(t, dir, "build.gradle.kts", string(data)+text)
}

func writeAppJar(t *testing.T, dir string, entries map[string][]byte) {
	t.Helper()
	writeRawJar(t, filepath.Join(dir, "build", "libs", "app.jar"), entries)
}

func manifest(lines string) []byte { return []byte("Manifest-Version: 1.0\n" + lines + "\n") }

// TestReachability_LaunchEntryLicence: main is empty and readValue is the sink, so each row's
// empty search is Searched only when the build names that main as its launch entry and has no
// other entry shape. Each withheld row's reason is the only thing withholding it.
func TestReachability_LaunchEntryLicence(t *testing.T) {
	tests := []struct {
		name     string
		named    bool // writeMain ships a manifest naming com.example.MainKt
		setup    func(t *testing.T, dir string)
		searched bool
		reason   string
	}{
		{"named main: searched", true, nil, true, ""},
		{"no named entry", false, nil, false, reasonLaunchEntryUnnamed},
		{"gradle literal mainClass.set names the main: searched", false, func(t *testing.T, dir string) {
			appendBuildScript(t, dir, "application { mainClass.set(\"com.example.MainKt\") }\n")
		}, true, ""},
		{"built manifest names a dependency launcher", true, func(t *testing.T, dir string) {
			writeAppJar(t, dir, map[string][]byte{"META-INF/MANIFEST.MF": manifest("Main-Class: io.ktor.server.netty.EngineMain")})
		}, false, reasonLaunchEntryUnmapped},
		{"Main-Verticle", true, func(t *testing.T, dir string) {
			writeAppJar(t, dir, map[string][]byte{"META-INF/MANIFEST.MF": manifest("Main-Verticle: com.example.MainVerticle")})
		}, false, reasonLaunchEntryUnmapped},
		{"Spring Boot launcher starting the first-party main: searched", false, func(t *testing.T, dir string) {
			writeAppJar(t, dir, map[string][]byte{"META-INF/MANIFEST.MF": manifest(
				"Main-Class: org.springframework.boot.loader.launch.JarLauncher\nStart-Class: com.example.MainKt")})
		}, true, ""},
		{"start script names a loaded dependency launcher", true, func(t *testing.T, dir string) {
			launcher := newKClassBuilder()
			launcher.addMethod("main", mainStringsDesc, []byte{opReturn})
			withJacksonEntries(t, dir, map[string][]byte{"io/ktor/server/netty/EngineMain.class": launcher.build("io/ktor/server/netty/EngineMain", "java/lang/Object")})
			writeStartScript(t, dir, "scripts/app", []string{jacksonJarName}, "io.ktor.server.netty.EngineMain")
		}, false, reasonLaunchEntryUnmapped},
		{"javax Filter beside an empty main, servlet API loaded", true, func(t *testing.T, dir string) {
			withJacksonEntries(t, dir, map[string][]byte{"javax/servlet/Filter.class": interfaceStub("javax/servlet/Filter")})
			writeClassFixture(t, dir, "com/example/AuditFilter", callbackClass("com/example/AuditFilter", "java/lang/Object", []string{"javax/servlet/Filter"}, ""))
		}, false, reasonContainerCallback},
		{"jakarta ServletContextListener", true, func(t *testing.T, dir string) {
			writeClassFixture(t, dir, "com/example/Boot", callbackClass("com/example/Boot", "java/lang/Object", []string{"jakarta/servlet/ServletContextListener"}, ""))
		}, false, reasonContainerCallback},
		{"Filter inherited through a first-party base", true, func(t *testing.T, dir string) {
			withJacksonEntries(t, dir, map[string][]byte{"javax/servlet/Filter.class": interfaceStub("javax/servlet/Filter")})
			writeClassFixture(t, dir, "com/example/BaseFilter", newKClassBuilder().buildWithInterfaces("com/example/BaseFilter", "java/lang/Object", "javax/servlet/Filter"))
			writeClassFixture(t, dir, "com/example/AuditFilter", callbackClass("com/example/AuditFilter", "com/example/BaseFilter", nil, ""))
		}, false, reasonContainerCallback},
		{"@WebServlet on a plain class", true, func(t *testing.T, dir string) {
			writeClassFixture(t, dir, "com/example/Hook", callbackClass("com/example/Hook", "java/lang/Object", nil, "Ljakarta/servlet/annotation/WebServlet;"))
		}, false, reasonContainerCallback},
		{"ancestor neither loaded nor in the JDK", true, func(t *testing.T, dir string) {
			writeClassFixture(t, dir, "com/example/Hook", callbackClass("com/example/Hook", "org/unknown/Base", nil, ""))
		}, false, reasonContainerCallback},
		{"JDK ancestor: searched", true, func(t *testing.T, dir string) {
			writeClassFixture(t, dir, "com/example/Worker", callbackClass("com/example/Worker", "java/lang/Thread", nil, ""))
		}, true, ""},
		{"HttpServlet subclass ends the walk: searched", true, func(t *testing.T, dir string) {
			withJacksonEntries(t, dir, map[string][]byte{"javax/servlet/http/HttpServlet.class": interfaceStub("javax/servlet/http/HttpServlet")})
			b := newKClassBuilder()
			b.addMethod("doGet", "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V", []byte{opReturn})
			writeClassFixture(t, dir, "com/example/Page", b.build("com/example/Page", "javax/servlet/http/HttpServlet"))
		}, true, ""},
		{"built .war", true, func(t *testing.T, dir string) {
			writeRawJar(t, filepath.Join(dir, "build", "libs", "app.war"), map[string][]byte{"META-INF/MANIFEST.MF": manifest("")})
		}, false, reasonWarPackaging},
		{"multi-release override in a class root", true, func(t *testing.T, dir string) {
			writeClassFixture(t, dir, "META-INF/versions/11/com/example/Extra", plainClass("com/example/Extra"))
		}, false, reasonMultiReleaseUnread},
		{"module-info under versions only: searched", true, func(t *testing.T, dir string) {
			writeClassFixture(t, dir, "META-INF/versions/9/module-info", []byte("not parsed"))
		}, true, ""},
		{"multi-release override in a first-party JAR", true, func(t *testing.T, dir string) {
			writeAppJar(t, dir, map[string][]byte{"META-INF/versions/11/com/example/Extra.class": plainClass("com/example/Extra")})
		}, false, reasonMultiReleaseUnread},
		{"multi-release override in a dependency JAR", true, func(t *testing.T, dir string) {
			withJacksonEntries(t, dir, map[string][]byte{"META-INF/versions/11/com/fasterxml/jackson/databind/ObjectMapper.class": plainClass(objectMapper)})
		}, false, reasonMultiReleaseUnread},
		{"manifest that is a FIFO beside a literal gradle main", false, func(t *testing.T, dir string) {
			appendBuildScript(t, dir, "application { mainClass.set(\"com.example.MainKt\") }\n")
			metaInf := filepath.Join(dir, "src", "main", "resources", "META-INF")
			if err := os.MkdirAll(metaInf, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := mkfifo(filepath.Join(metaInf, "MANIFEST.MF")); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
		}, false, reasonLaunchEntryUnmapped},
		{"build/libs that cannot be listed", true, func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "build"), "libs", "not a directory")
		}, false, reasonLaunchEntryUnmapped},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := gradleJacksonBuild(t, "")
			if tt.named {
				writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
			} else {
				b := newKClassBuilder()
				b.addMethod("main", mainStringsDesc, []byte{opReturn})
				writeClassFixture(t, dir, "com/example/MainKt", b.build("com/example/MainKt", "java/lang/Object"))
			}
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			res := reach(t, dir, readValueSink)
			if got := len(res.Searched) > 0; got != tt.searched {
				t.Errorf("Searched = %v, want searched %v (%+v)", res.Searched, tt.searched, res.Partiality)
			}
			if len(res.Paths) != 0 {
				t.Errorf("paths = %+v, want none", res.Paths)
			}
			if tt.reason != "" && !hasReason(res.Partiality, tt.reason) {
				t.Errorf("reasons %v must carry %q", res.Partiality.Reasons, tt.reason)
			}
		})
	}
}

// TestLaunchEntryReasons_GradleScript reads the build script alone: the inventory already
// withholds on most script forms, so the end-to-end rows cannot isolate these.
func TestLaunchEntryReasons_GradleScript(t *testing.T) {
	tests := []struct {
		name   string
		script string
		named  []string
		want   []string
	}{
		{"literal mainClass.set", `application { mainClass.set("com.example.MainKt") }`, []string{"com.example.MainKt"}, nil},
		{"literal mainClass =", `application { mainClass = "com.example.MainKt" }`, []string{"com.example.MainKt"}, nil},
		{"literal mainClassName", `mainClassName = 'com.example.MainKt'`, []string{"com.example.MainKt"}, nil},
		{"literal Main-Class attribute", `jar { manifest { attributes("Main-Class" to "com.example.MainKt") } }`, []string{"com.example.MainKt"}, nil},
		{"commented-out entry", "// mainClass.set(\"com.example.Old\")\n", nil, nil},
		{"mainClass from a variable", "val appMain = \"com.example.Other\"\napplication { mainClass.set(appMain) }", nil, []string{reasonLaunchEntryUnmapped}},
		{"interpolated mainClass", `application { mainClass.set("${group}.MainKt") }`, nil, []string{reasonLaunchEntryUnmapped}},
		{"war plugin", "plugins {\n    war\n}", nil, []string{reasonWarPackaging}},
		{"war plugin by id", `plugins { id("war") }`, nil, []string{reasonWarPackaging}},
		{"apply war plugin", `apply(plugin = "war")`, nil, []string{reasonWarPackaging}},
		{"bootWar task", `tasks.bootWar { enabled = true }`, nil, []string{reasonWarPackaging}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBuildFile(t, dir, "build.gradle.kts", tt.script+"\n")
			r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}}
			r.gradle(filepath.Join(dir, "build.gradle.kts"))
			for _, n := range tt.named {
				if !r.named[n] {
					t.Errorf("named %v, want %q", r.named, n)
				}
			}
			if len(r.named) != len(tt.named) {
				t.Errorf("named %v, want %v", r.named, tt.named)
			}
			if len(r.reasons) != len(tt.want) {
				t.Errorf("reasons %v, want %v", r.reasons, tt.want)
			}
			for _, w := range tt.want {
				if !r.reasons[w] {
					t.Errorf("reasons %v must carry %q", r.reasons, w)
				}
			}
		})
	}
}
