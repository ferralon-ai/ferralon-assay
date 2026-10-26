package kotlinanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	accStatic            = 0x0008
	springBootAppAnno    = "Lorg/springframework/boot/autoconfigure/SpringBootApplication;"
	bootPluginsBlock     = "plugins {\n    id(\"org.springframework.boot\") version \"3.3.5\"\n    id(\"io.spring.dependency-management\") version \"1.1.6\"\n    kotlin(\"jvm\") version \"2.0.21\"\n    kotlin(\"plugin.spring\") version \"2.0.21\"\n}\n"
	kotlinOnlyPluginsBlk = "plugins {\n    kotlin(\"jvm\") version \"2.0.21\"\n}\n"
)

// bootGradleBuild is gradleJacksonBuild with plugins prepended to its build script.
func bootGradleBuild(t *testing.T, plugins string) string {
	t.Helper()
	dir := gradleJacksonBuild(t, "")
	p := filepath.Join(dir, "build.gradle.kts")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	writeBuildFile(t, dir, "build.gradle.kts", plugins+string(data))
	return dir
}

// writeFacade emits the class a Kotlin file's top-level `fun main(args: Array<String>)`
// compiles to: <File>Kt with a public static final main(String[]).
func writeFacade(t *testing.T, dir, root, name string) {
	t.Helper()
	b := newKClassBuilder()
	b.addMethodAccess(accPublic|accStatic|0x0010, "main", mainStringsDesc, []byte{opReturn})
	writeClassAt(t, dir, root, name, b.build(name, "java/lang/Object"))
}

// writeBootAppClass emits the @SpringBootApplication class beside the facade: the annotation
// sits here, and the class declares no main.
func writeBootAppClass(t *testing.T, dir, name string) {
	t.Helper()
	b := newKClassBuilder()
	b.addClassAnnotation(b.anno(springBootAppAnno))
	b.addMethod("<init>", "()V", []byte{opReturn})
	writeClassFixture(t, dir, name, b.build(name, "java/lang/Object"))
}

func writeClassAt(t *testing.T, dir, root, name string, data []byte) {
	t.Helper()
	full := filepath.Join(dir, root, filepath.FromSlash(name)+".class")
	writeFileAt(t, filepath.Dir(full), filepath.Base(full), string(data))
}

var kotlinMainRoot = filepath.Join("build", "classes", "kotlin", "main")

// TestReachability_BootMain: the build names no main, so an empty search is Searched only when
// the build applies the Spring Boot Gradle plugin, the one main its MainClassFinder would pick is
// first-party, and nothing in the build can hand the plugin another. The app is the Kotlin shape:
// @SpringBootApplication on com/example/App, the main on the com/example/AppKt facade.
func TestReachability_BootMain(t *testing.T) {
	tests := []struct {
		name     string
		plugins  string
		setup    func(t *testing.T, dir string)
		searched bool
		reason   string
	}{
		// found
		{"Kotlin facade main, annotation on the app class: searched", bootPluginsBlock, nil, true, ""},
		{"Groovy-style id and core accessor plugins: searched",
			"plugins {\n    id 'org.springframework.boot' version '3.3.5'\n    `java-library`\n    application\n}\n", nil, true, ""},
		{"annotated class's companion @JvmStatic main preferred over the facade: searched", bootPluginsBlock, func(t *testing.T, dir string) {
			b := newKClassBuilder()
			b.addClassAnnotation(b.anno(springBootAppAnno))
			b.addMethodAccess(accPublic|accStatic|0x0010, "main", mainStringsDesc, []byte{opReturn})
			writeClassFixture(t, dir, "com/example/App", b.build("com/example/App", "java/lang/Object"))
			c := newKClassBuilder()
			c.addMethod("main", mainStringsDesc, []byte{opReturn})
			writeClassFixture(t, dir, "com/example/App$Companion", c.build("com/example/App$Companion", "java/lang/Object"))
		}, true, ""},
		{"resolvedMainClassName names the facade beside a second main: searched", bootPluginsBlock, func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "build"), "resolvedMainClassName", "com.example.AppKt")
			writeFacade(t, dir, kotlinMainRoot, "com/example/ToolKt")
		}, true, ""},
		{"settings applying only foojay: searched", bootPluginsBlock, func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "plugins {\n    id(\"org.gradle.toolchains.foojay-resolver-convention\") version \"0.8.0\"\n}\nrootProject.name = \"app\"\n")
		}, true, ""},
		{"settings declaring repositories only: searched", bootPluginsBlock, func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", `pluginManagement {
    repositories {
        gradlePluginPortal()
        maven { url = uri("https://repo.example.com/maven") }
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { mavenCentral() }
}
rootProject.name = "app"
`)
		}, true, ""},
		{"buildscript classpath of the Boot and Kotlin plugins: searched", "buildscript {\n    ext.kotlinVersion = '2.0.21'\n    repositories { mavenCentral() }\n    dependencies {\n        classpath 'org.springframework.boot:spring-boot-gradle-plugin:3.3.5'\n        classpath \"org.jetbrains.kotlin:kotlin-gradle-plugin:${kotlinVersion}\"\n    }\n}\napply plugin: 'org.springframework.boot'\napply plugin: 'org.jetbrains.kotlin.jvm'\n", nil, true, ""},

		// no Boot plugin
		{"Kotlin JVM plugin only", kotlinOnlyPluginsBlk, nil, false, reasonLaunchEntryUnnamed},
		{"Boot plugin declared apply false", "plugins {\n    id(\"org.springframework.boot\") version \"3.3.5\" apply false\n}\n", nil, false, reasonLaunchEntryUnnamed},

		// ambiguous
		{"two facade mains", bootPluginsBlock, func(t *testing.T, dir string) {
			writeFacade(t, dir, kotlinMainRoot, "com/example/ToolKt")
		}, false, reasonLaunchEntryUnnamed},
		{"the one main in java/main beside kotlin/main classes", bootPluginsBlock, func(t *testing.T, dir string) {
			writeFacade(t, dir, filepath.Join("build", "classes", "java", "main"), "com/example/ToolKt")
		}, false, reasonLaunchEntryUnnamed},
		{"a second, non-public static main", bootPluginsBlock, func(t *testing.T, dir string) {
			b := newKClassBuilder()
			b.addMethodAccess(accStatic, "main", mainStringsDesc, []byte{opReturn})
			writeClassFixture(t, dir, "com/example/Tool", b.build("com/example/Tool", "java/lang/Object"))
		}, false, reasonLaunchEntryUnnamed},

		// blocked: the build can hand the plugin a main the reader does not see
		{"convention plugin by id", bootPluginsBlock + "plugins { id(\"com.example.conventions\") }\n", nil, false, reasonLaunchEntryUnnamed},
		{"version-catalog alias", "plugins {\n    alias(libs.plugins.spring.boot)\n    id(\"org.springframework.boot\")\n}\n", nil, false, reasonLaunchEntryUnnamed},
		{"apply from a script", bootPluginsBlock + "apply(from = \"gradle/boot.gradle.kts\")\n", nil, false, reasonLaunchEntryUnnamed},
		{"apply of an unlisted plugin", bootPluginsBlock + "apply(plugin = \"com.example.conventions\")\n", nil, false, reasonLaunchEntryUnnamed},
		{"resolveMainClassName configured", bootPluginsBlock + "tasks.resolveMainClassName { configuredMainClassName.set(provider { pick() }) }\n", nil, false, reasonLaunchEntryUnnamed},
		{"source sets reconfigured", bootPluginsBlock + "sourceSets { main { kotlin.srcDir(\"gen\") } }\n", nil, false, reasonLaunchEntryUnnamed},
		{"settings hook configures every project", bootPluginsBlock, func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "gradle.allprojects { }\n")
		}, false, reasonLaunchEntryUnnamed},
		{"settings task-graph hook sets bootJar's main", bootPluginsBlock, func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "rootProject.name = \"app\"\ngradle.taskGraph.whenReady { allTasks.filterIsInstance<BootJar>().forEach { it.mainClass.set(\"io.ktor.server.netty.EngineMain\") } }\n")
		}, false, reasonLaunchEntryUnnamed},
		{"settings project evaluation listener", bootPluginsBlock, func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "gradle.addProjectEvaluationListener(Hook())\n")
		}, false, reasonLaunchEntryUnnamed},
		{"settings plugin resolution strategy", bootPluginsBlock, func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "pluginManagement {\n    resolutionStrategy { eachPlugin { useModule(\"com.example:boot-fork:1\") } }\n}\n")
		}, false, reasonLaunchEntryUnnamed},
		{"buildSrc helper called from the root script", bootPluginsBlock + "configureLaunch()\n", func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "buildSrc", "src", "main", "kotlin"), "Launch.kt",
				"fun org.gradle.api.Project.configureLaunch() { tasks.named(\"bootJar\") { } }\n")
		}, false, reasonLaunchEntryUnnamed},
		{"buildscript classpath of another plugin", bootPluginsBlock + "buildscript {\n    dependencies { classpath(\"com.example:launch-helpers:1.0\") }\n}\n", nil, false, reasonLaunchEntryUnnamed},
		{"non-default import", "import com.example.gradle.configureLaunch\n" + bootPluginsBlock, nil, false, reasonLaunchEntryUnnamed},
		{"resolvedMainClassName beside an unlisted plugin", bootPluginsBlock + "plugins { id(\"com.example.conventions\") }\n", func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "build"), "resolvedMainClassName", "com.example.AppKt")
		}, false, reasonLaunchEntryUnnamed},
		{"resolvedMainClassName without the Boot plugin", kotlinOnlyPluginsBlk, func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "build"), "resolvedMainClassName", "com.example.AppKt")
		}, false, reasonLaunchEntryUnnamed},
		{"settings plugin outside the list", bootPluginsBlock, func(t *testing.T, dir string) {
			writeBuildFile(t, dir, "settings.gradle.kts", "plugins { id(\"com.example.settings\") }\n")
		}, false, reasonLaunchEntryUnnamed},
		{"resolvedMainClassName that is empty", bootPluginsBlock, func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "build"), "resolvedMainClassName", "")
		}, false, reasonLaunchEntryUnmapped},

		// a named main takes precedence over the one the plugin finds
		{"literal springBoot mainClass beside two mains: searched", bootPluginsBlock + "springBoot { mainClass.set(\"com.example.AppKt\") }\n", func(t *testing.T, dir string) {
			writeFacade(t, dir, kotlinMainRoot, "com/example/ToolKt")
		}, true, ""},
		{"literal bootJar Start-Class: searched", bootPluginsBlock + "tasks.bootJar { manifest { attributes(\"Start-Class\" to \"com.example.AppKt\") } }\n", func(t *testing.T, dir string) {
			writeFacade(t, dir, kotlinMainRoot, "com/example/ToolKt")
		}, true, ""},
		{"named class that is not a main: no fallback to the plugin's", bootPluginsBlock + "springBoot { mainClass.set(\"com.example.App\") }\n", nil, false, reasonLaunchEntryUnmapped},
		{"resolvedMainClassName names a class with no main", bootPluginsBlock, func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, "build"), "resolvedMainClassName", "com.example.App")
		}, false, reasonLaunchEntryUnmapped},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := bootGradleBuild(t, tt.plugins)
			writeBootAppClass(t, dir, "com/example/App")
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			if _, err := os.Lstat(filepath.Join(dir, kotlinMainRoot, "com", "example", "AppKt.class")); err != nil {
				writeFacade(t, dir, kotlinMainRoot, "com/example/AppKt")
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

// TestLaunchEntryReasons_GradleBootUnread: a settings script that cannot be read blocks the
// plugin's main. Reader-level: the module scan reads settings scripts before this reader does.
func TestLaunchEntryReasons_GradleBootUnread(t *testing.T) {
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", bootPluginsBlock)
	if err := mkfifo(filepath.Join(dir, "settings.gradle.kts")); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}}
	r.gradleBoot(dir)
	if !r.bootPlugin || !r.bootBlocked {
		t.Errorf("bootPlugin, bootBlocked = %v, %v; want true, true", r.bootPlugin, r.bootBlocked)
	}
	if !r.reasons[reasonLaunchEntryUnmapped] {
		t.Errorf("reasons %v must carry %q", r.reasons, reasonLaunchEntryUnmapped)
	}
}

// TestLaunchEntryReasons_GradleBootSettings reads settings scripts alone: one that includes a
// build is already withheld as a multi-project build before the launch entry matters.
func TestLaunchEntryReasons_GradleBootSettings(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		blocked  bool
	}{
		{"name and repositories", "rootProject.name = 'app'\ndependencyResolutionManagement { repositories { mavenCentral() } }\n", false},
		{"includeBuild supplying plugins", "pluginManagement {\n    includeBuild(\"build-logic\")\n}\n", true},
		{"include", "include(\"app\")\n", true},
		{"interpolated repository URL", "pluginManagement { repositories { maven { url = uri(\"${repoUrl}\") } } }\n", true},
		{"settings hook", "gradle.beforeProject { }\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBuildFile(t, dir, "build.gradle.kts", bootPluginsBlock)
			writeBuildFile(t, dir, "settings.gradle.kts", tt.settings)
			r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}}
			r.gradleBoot(dir)
			if !r.bootPlugin || r.bootBlocked != tt.blocked {
				t.Errorf("bootPlugin, bootBlocked = %v, %v; want true, %v", r.bootPlugin, r.bootBlocked, tt.blocked)
			}
		})
	}
}

// TestLaunchEntryReasons_MavenBoot reads a Kotlin Maven build's POM through the Java lane's
// Boot plugin reader: the end-to-end path needs a Maven build graph the fixtures do not build.
func TestLaunchEntryReasons_MavenBoot(t *testing.T) {
	const bootPlugin = `<build><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build>`
	pom := func(parent, build string) string {
		return `<project><modelVersion>4.0.0</modelVersion>` + parent +
			`<groupId>com.example</groupId><artifactId>app</artifactId><version>1</version>` + build + `</project>`
	}
	tests := []struct {
		name        string
		pom         string
		setup       func(t *testing.T, dir string)
		plugin      bool
		blocked     bool
		cliProperty bool
	}{
		{"Boot plugin", pom("", bootPlugin), nil, true, false, false},
		{"no Boot plugin", pom("", ""), nil, false, false, false},
		{"parent not in the Maven cache", pom(`<parent><groupId>com.example</groupId><artifactId>uncached-parent</artifactId><version>1</version></parent>`, bootPlugin), nil, true, true, false},
		{"start-class set by a launch option", pom("", bootPlugin), func(t *testing.T, dir string) {
			writeFileAt(t, filepath.Join(dir, ".mvn"), "maven.config", "-Dstart-class=com.example.ToolKt\n")
		}, true, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			dir := t.TempDir()
			writeBuildFile(t, dir, "pom.xml", tt.pom)
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}}
			r.maven(filepath.Join(dir, "pom.xml"))
			if r.bootPlugin != tt.plugin || (tt.plugin && r.bootBlocked != tt.blocked) {
				t.Errorf("bootPlugin, bootBlocked = %v, %v; want %v, %v", r.bootPlugin, r.bootBlocked, tt.plugin, tt.blocked)
			}
			if got := r.reasons[reasonLaunchEntryCLIProp]; got != tt.cliProperty {
				t.Errorf("reasons %v: launch_entry_cli_property %v, want %v", r.reasons, got, tt.cliProperty)
			}
		})
	}
}

// TestScriptPlugins pins the plugin forms the Boot reader accepts; any other form is unread.
func TestScriptPlugins(t *testing.T) {
	tests := []struct {
		name   string
		script string
		ids    []string
		ok     bool
	}{
		{"kts ids and kotlin()", bootPluginsBlock, []string{"org.springframework.boot", "io.spring.dependency-management", "org.jetbrains.kotlin.jvm", "org.jetbrains.kotlin.plugin.spring"}, true},
		{"groovy apply plugin", "apply plugin: 'org.springframework.boot'\n", []string{"org.springframework.boot"}, true},
		{"consecutive apply plugin lines", "apply plugin: 'org.springframework.boot'\napply plugin: 'org.jetbrains.kotlin.jvm'\n", []string{"org.springframework.boot", "org.jetbrains.kotlin.jvm"}, true},
		{"commented-out plugin", "plugins {\n    // id(\"com.example.x\")\n    java\n}\n", []string{"java"}, true},
		{"interpolated version", "plugins { id(\"org.springframework.boot\") version \"$bootVersion\" }\n", nil, false},
		{"pluginManager.apply", "pluginManager.apply(\"com.example.x\")\n", nil, false},
		{"scope-function apply", "val x = Foo().apply { bar = 1 }\n", nil, false},
		{"unbalanced plugins block", "plugins {\n    java\n", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, ok := scriptPlugins(tt.script)
			if ok != tt.ok {
				t.Errorf("ok = %v, want %v (ids %v)", ok, tt.ok, ids)
			}
			if tt.ok && !equalStrings(ids, tt.ids) {
				t.Errorf("ids = %v, want %v", ids, tt.ids)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
