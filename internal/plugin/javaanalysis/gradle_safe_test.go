package javaanalysis

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A statement outside the SAFE set that can move a version off what the lock and the literal
// declarations say leaves every locked GA unconfirmed, even when the lock and the declarations
// agree: here the lock holds 1.0.0 while the build resolves 2.0.0.
func TestGradle_UnsafeStatementsUnconfirmLock(t *testing.T) {
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	const lock = "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\norg.pulls:it:1.0=compileClasspath,runtimeClasspath\n"
	const catalogRef = "[versions]\nn = \"2.0.0\"\n\n[libraries]\nnetkit = { module = \"com.evil:netkit\", version.ref = \"n\" }\n"
	const catalogLit = "[libraries]\nnetkit = { module = \"com.evil:netkit\", version = \"2.0.0\" }\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name     string
		files    map[string]string
		resolved bool
	}{
		{"no construct", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, true},
		{"catalog alias with version.ref", map[string]string{
			"build.gradle":              enforced + "dependencies {\n    implementation libs.netkit\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"catalog alias with version.ref, kts", map[string]string{
			"build.gradle.kts":          enforced + "dependencies {\n    implementation(libs.netkit)\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"catalog alias with a literal", map[string]string{
			"build.gradle":              enforced + "dependencies {\n    implementation libs.netkit\n}\n",
			"gradle/libs.versions.toml": catalogLit,
		}, false},
		{"catalog version in an interpolation", map[string]string{
			"build.gradle":              enforced + "dependencies {\n    implementation \"com.evil:netkit:${libs.versions.n.get()}\"\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"version { strictly }", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation('com.evil:netkit:1.0.0') { version { strictly '2.0.0' } }\n}\n",
		}, false},
		{"version { require }", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation('com.evil:netkit:1.0.0') { version { require '2.0.0' } }\n}\n",
		}, false},
		{"version { prefer }", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation('com.evil:netkit') { version { prefer '2.0.0' } }\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"eachDependency useVersion", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.eachDependency { if (it.requested.name == 'netkit') it.useVersion '2.0.0' }\n}\n" +
				"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"eachDependency useVersion on a transitive-only GA", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.eachDependency { if (it.requested.name == 'netkit') it.useVersion '2.0.0' }\n}\n" +
				"dependencies {\n    implementation 'org.pulls:it:1.0'\n}\n",
		}, false},
		{"eachDependency useVersion, kts", map[string]string{
			"build.gradle.kts": enforced + "configurations.all {\n    resolutionStrategy {\n        eachDependency { if (requested.name == \"netkit\") useVersion(\"2.0.0\") }\n    }\n}\n" +
				"dependencies {\n    implementation(\"com.evil:netkit:1.0.0\")\n}\n",
		}, false},
		{"force through a catalog alias", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.force libs.netkit\n}\n" +
				"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"gradle/libs.versions.toml": catalogRef,
		}, false},
		{"force on the declaration, kts", map[string]string{
			"build.gradle.kts": enforced + "dependencies {\n    implementation(\"com.evil:netkit:1.0.0\") { isForce = true }\n    implementation(\"org.pulls:it:1.0\")\n}\n",
		}, false},
		{"dependency substitution", map[string]string{
			"build.gradle": enforced + "configurations.all {\n    resolutionStrategy.dependencySubstitution {\n        substitute module('com.evil:netkit') using module('com.evil:netkit:2.0.0')\n    }\n}\n" +
				"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"enforced platform", map[string]string{
			"build.gradle": enforced + "dependencies {\n    implementation enforcedPlatform('com.evil:bom:2.0')\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
		}, false},
		{"a construct in the root script reaches the subproject", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        "subprojects {\n    configurations.all { resolutionStrategy.eachDependency { it.useVersion '2.0.0' } }\n}\n",
			"app/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"app/gradle.lockfile": lock,
		}, false},
		{"a construct in the root script reaches a GA only the subproject locks", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        "subprojects {\n    configurations.all { resolutionStrategy.eachDependency { if (it.requested.name == 'netkit') it.useVersion '2.0.0' } }\n}\n",
			"gradle.lockfile":     "org.pulls:it:1.0=compileClasspath,runtimeClasspath\n",
			"app/build.gradle":    enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"app/gradle.lockfile": "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\n",
		}, false},
		{"a construct in a project without a lock", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"build.gradle":     enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n",
			"app/build.gradle": "configurations.all { resolutionStrategy.force 'com.evil:netkit:2.0.0' }\n",
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			locked := false
			for rel, body := range tt.files {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
				locked = locked || filepath.Base(rel) == "gradle.lockfile"
			}
			if !locked {
				writeFile(t, filepath.Join(dir, "gradle.lockfile"), lock)
			}
			inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
			if got := findNode(t, inv, netkit) != nil; got != tt.resolved {
				t.Fatalf("netkit resolved at 1.0.0 = %v, want %v; nodes %+v", got, tt.resolved, inv.Nodes)
			}
			if tt.resolved {
				return
			}
			n := findNode(t, inv, mavenPURL("com.evil", "netkit", ""))
			if n == nil || !hasStr(n.Partiality.Reasons, reasonGradleLockUnconfirmed) {
				t.Errorf("want netkit present, unresolved, %s; got %+v", reasonGradleLockUnconfirmed, n)
			}
		})
	}
}

// gradleScriptSafe admits a script only when every statement is in the SAFE set.
func TestGradleScriptSafe(t *testing.T) {
	const lockAll = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	for _, tt := range []struct {
		name, src string
		safe      bool
	}{
		{"empty", "", true},
		{"every SAFE form, Groovy", "plugins {\n    id 'java'\n    id 'application'\n}\n" +
			"group = 'com.example'\nversion '1.0'\ndescription = \"demo\"\n" +
			"sourceCompatibility = 1.8\ntargetCompatibility = JavaVersion.VERSION_1_8\n" +
			"apply plugin: 'idea'\n" +
			"repositories {\n    mavenCentral()\n    google()\n    mavenLocal()\n    maven { url 'https://repo.example/m2' }\n    maven { url = uri('https://repo.example/m2') }\n}\n" +
			"dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n    api('org.a:b:2.0')\n    runtimeOnly group: 'org.c', name: 'd', version: '3.0'\n" +
			"    testImplementation project(':core')\n    compileOnly 'org.e:f:1.+'\n    implementation 'org.g:h:1.0:linux@zip'\n}\n" +
			lockAll +
			"java {\n    toolchain {\n        languageVersion = JavaLanguageVersion.of(17)\n    }\n    withSourcesJar()\n}\n" +
			"application {\n    mainClassName = 'a.Main'\n}\n" +
			"test {\n    useJUnitPlatform()\n}\n" +
			"allprojects {\n    repositories { mavenCentral() }\n}\n", true},
		{"every SAFE form, Kotlin", "plugins {\n    java\n    `java-library`\n    id(\"maven-publish\")\n}\n" +
			"group = \"com.example\"\nversion = \"1.0\"\n" +
			"java.sourceCompatibility = JavaVersion.VERSION_17\n" +
			"java.toolchain.languageVersion.set(JavaLanguageVersion.of(17))\n" +
			"apply(plugin = \"eclipse\")\n" +
			"repositories {\n    mavenCentral()\n    gradlePluginPortal()\n    maven(\"https://repo.example/m2\")\n}\n" +
			"dependencies {\n    implementation(\"com.evil:netkit:1.0.0\")\n    implementation(project(\":core\"))\n}\n" +
			lockAll +
			"application {\n    mainClass.set(\"a.Main\")\n}\n" +
			"tasks.named<Test>(\"test\") {\n    useJUnitPlatform()\n}\n" +
			"tasks.test { useJUnitPlatform() }\n", true},
		{"statements split by semicolons", "group = 'x'; version = '1'\n", true},
		{"a SAFE statement in a comment beside an unsafe one", "// group = 'x'\nconfigurations.all { }\n", false},
		{"a plugin from a repository", "plugins { id 'org.springframework.boot' version '3.2.0' }\n", false},
		{"a non-core plugin id", "plugins { id 'my.conv' }\n", false},
		{"a core plugin with a version", "plugins { id 'java' version '1.0' }\n", false},
		{"apply plugin with a non-core id", "apply plugin: 'org.springframework.boot'\n", false},
		{"apply from", "apply from: 'deps.gradle'\n", false},
		{"apply from, kts", "apply(from = \"deps.gradle.kts\")\n", false},
		{"buildscript", "buildscript { repositories { mavenCentral() } }\n", false},
		{"ext block", "ext { v = '1.0' }\n", false},
		{"configurations.all", "configurations.all { }\n", false},
		{"interpolated coordinate", "dependencies {\n    implementation \"com.evil:netkit:${v}\"\n}\n", false},
		{"interpolated property", "version = \"${v}\"\n", false},
		{"escaped string", "group = 'a\\'b'\n", false},
		{"catalog accessor", "dependencies {\n    implementation libs.netkit\n}\n", false},
		{"catalog accessor, kts", "dependencies {\n    implementation(libs.netkit)\n}\n", false},
		{"platform", "dependencies {\n    implementation platform('com.evil:bom:1.0')\n}\n", false},
		{"a declaration with a closure", "dependencies {\n    implementation('com.evil:netkit:1.0.0') { force = true }\n}\n", false},
		{"kts named arguments", "dependencies {\n    implementation(group = \"com.evil\", name = \"netkit\", version = \"1.0.0\")\n}\n", false},
		{"map notation in parentheses", "dependencies {\n    implementation(group: 'com.evil', name: 'netkit', version: '1.0.0')\n}\n", false},
		{"map notation over two lines", "dependencies {\n    implementation group: 'com.evil',\n        name: 'netkit', version: '1.0.0'\n}\n", false},
		{"an unknown configuration", "dependencies {\n    force 'com.evil:netkit:2.0.0'\n}\n", false},
		{"a string that is no coordinate", "dependencies {\n    implementation 'netkit'\n}\n", false},
		{"components rule", "dependencies {\n    components { }\n}\n", false},
		{"a locking block that sets a mode", "dependencyLocking {\n    lockAllConfigurations()\n    lockMode = LockMode.LENIENT\n}\n", false},
		{"a locking block with only a mode", "dependencyLocking { lockMode = LockMode.STRICT }\n", false},
		{"two locking calls", "dependencyLocking {\n    lockAllConfigurations()\n    lockAllConfigurations()\n}\n", false},
		{"a test block that holds more", "test {\n    useJUnitPlatform()\n    maxParallelForks = 2\n}\n", false},
		{"another task", "tasks.named('jar') { }\n", false},
		{"a call chained on a block", "dependencyLocking { lockAllConfigurations() }.with { }\n", false},
		{"a statement continued on the next line", "version = '1.0' +\n    '-x'\n", false},
		{"a call continued with a leading dot", "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n.each { }\n", false},
		{"a property from another name", "rootProject.name = 'x'\n", false},
		{"a triple-quoted string", "group = '''x'''\n", false},
		{"an unterminated string", "group = 'x\n", false},
		{"unbalanced braces", "dependencies {\n", false},
		{"an unterminated block comment", "group = 'x'\n/* ", false},
		{"a JavaVersion that isn't one", "sourceCompatibility = JavaVersion.current()\n", false},
		{"a compatibility from a variable", "sourceCompatibility = javaVersion\n", false},
		{"a declaration's argument on the next line", "dependencies {\n    implementation(\n        \"com.evil:netkit:1.0.0\"\n    )\n}\n", true},
		{"allprojects holding an unsafe statement", "allprojects {\n    configurations.all { }\n}\n", false},
		{"a maven repository with more than a url", "repositories {\n    maven {\n        url 'https://repo.example/m2'\n        credentials { }\n    }\n}\n", false},
		{"a java block holding a block other than toolchain", "java {\n    consistentResolution {\n        languageVersion = JavaLanguageVersion.of(17)\n    }\n}\n", false},
		{"a compatibility with more after it", "sourceCompatibility = JavaVersion.VERSION_17 + evil()\n", false},
		{"a quoted method name", "repositories {\n    \"mavenCentral\"()\n}\n", false},
		{"a backquoted id that doesn't close", "plugins {\n    `java\n}\n", false},
		{"a triple-quoted string over lines", "description = \"\"\"\nplugins { id 'java' }\n\"\"\"\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := gradleScriptSafe(tt.src); got != tt.safe {
				t.Errorf("gradleScriptSafe = %v, want %v", got, tt.safe)
			}
		})
	}
}

// A lock confirms only when every script Gradle would evaluate is SAFE (gradleBuildSafe) and the
// project locks every configuration. Each row but the controls is a build whose lock (netkit
// 1.0.0) and literal declarations agree while Gradle can resolve something else; each one locks
// in its own script, so only the allow-list (or, for P10, the missing locking statement) leaves
// netkit unconfirmed.
func TestGradle_SafeBuildGatesLock(t *testing.T) {
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	const lock = "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\norg.pulls:it:1.0=compileClasspath,runtimeClasspath\n"
	const pulls = "dependencies {\n    implementation 'org.pulls:it:1.0'\n}\n"
	const dyn = "dependencies {\n    implementation 'com.evil:netkit:1.+'\n}\n"
	const forces = "configurations.all { resolutionStrategy.force 'com.evil:netkit:2.0.0' }\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tt := range []struct {
		name     string
		files    map[string]string
		resolved bool
	}{
		{"control", map[string]string{"build.gradle": enforced + pulls}, true},
		{"control, kts", map[string]string{"build.gradle.kts": enforced + "dependencies {\n    implementation(\"org.pulls:it:1.0\")\n}\n"}, true},
		{"S0 control, a literal include", map[string]string{
			"settings.gradle":  "include 'app'\n",
			"app/build.gradle": enforced + pulls, "app/gradle.lockfile": lock,
		}, true},
		{"S0k control, a literal include, kts", map[string]string{
			"settings.gradle.kts":  "rootProject.name = \"x\"\ninclude(\"app\")\n",
			"app/build.gradle.kts": enforced + "dependencies {\n    implementation(\"org.pulls:it:1.0\")\n}\n", "app/gradle.lockfile": lock,
		}, true},
		{"a settings name that is a Gradle word", map[string]string{
			"settings.gradle": "rootProject.name = 'force'\n",
			"build.gradle":    enforced + pulls,
		}, true},
		{"E0 control, enforced, dynamic", map[string]string{"build.gradle": enforced + dyn}, true},
		{"P1 apply from a script that declares 2.0.0", map[string]string{
			"build.gradle": enforced + "apply from: 'deps.gradle'\n" + pulls,
			"deps.gradle":  "dependencies {\n    implementation 'com.evil:netkit:2.0.0'\n}\n",
		}, false},
		{"P1k apply(from =), kts", map[string]string{
			"build.gradle.kts": enforced + "apply(from = \"deps.gradle.kts\")\n",
			"deps.gradle.kts":  "dependencies {\n    implementation(\"com.evil:netkit:2.0.0\")\n}\n",
		}, false},
		{"P2 buildSrc convention plugin", map[string]string{
			"build.gradle":                            "plugins { id 'my.conv' }\n" + enforced + pulls,
			"buildSrc/build.gradle":                   "plugins { id 'groovy-gradle-plugin' }\n",
			"buildSrc/src/main/groovy/my.conv.gradle": forces,
		}, false},
		{"S2b buildSrc convention plugin, no buildSrc build script", map[string]string{
			"build.gradle": "plugins { id 'my.conv' }\n" + enforced + pulls,
			"buildSrc/src/main/groovy/my.conv.gradle": forces,
		}, false},
		{"buildSrc present, nothing names it", map[string]string{
			"build.gradle": enforced + pulls,
			"buildSrc/src/main/groovy/my.conv.gradle": forces,
		}, false},
		{"build-logic present", map[string]string{
			"build.gradle": enforced + pulls,
			"build-logic/src/main/groovy/my.conv.gradle": forces,
		}, false},
		{"P3 getResolutionStrategy getter and useTarget", map[string]string{
			"build.gradle": enforced + "configurations.all { getResolutionStrategy().getDependencySubstitution().all { if (it.requested.module == 'netkit') it.useTarget([it.requested.group, it.requested.module, '2.0.0'].join(':')) } }\n" + pulls,
		}, false},
		{"P3b setForcedModules", map[string]string{
			"build.gradle": enforced + "configurations.all { getResolutionStrategy().setForcedModules(['com.evil', 'netkit', '2.0.0'].join(':')) }\n" + pulls,
		}, false},
		{"P3c string-built invokeMethod", map[string]string{
			"build.gradle": enforced + "configurations.all { c -> c.getProperty('resolution' + 'Strategy').invokeMethod('each' + 'Dependency', { d -> d.invokeMethod('use' + 'Version', '2.0.0') }) }\n" + pulls,
		}, false},
		{"P5 component metadata rule", map[string]string{
			"build.gradle": enforced + "dependencies {\n  components {\n    withModule('org.pulls:it') {\n      allVariants { withDependencies { removeAll { it.name == 'netkit' }; add(['com.evil','netkit','2.0.0'].join(':')) } }\n    }\n  }\n}\n" + pulls,
		}, false},
		{"P9 spring dependency-management BOM", map[string]string{
			"build.gradle": "plugins { id 'io.spring.dependency-management' version '1.1.4' }\n" + enforced + "dependencyManagement { imports { mavenBom 'com.evil:bom:2.0' } }\n" + pulls,
		}, false},
		{"P10 no locking statement, the literal agrees", map[string]string{
			"build.gradle": "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n    implementation 'org.pulls:it:1.0'\n}\n",
		}, false},
		{"no locking anywhere", map[string]string{
			"settings.gradle":     "include 'app'\n",
			"build.gradle":        "group = 'com.example'\n",
			"app/build.gradle":    "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n    implementation 'org.pulls:it:1.0'\n}\n",
			"app/gradle.lockfile": lock,
		}, false},
		{"P11 enforced, apply from forces 2.0.0", map[string]string{
			"build.gradle": enforced + "apply from: 'deps.gradle'\n" + pulls,
			"deps.gradle":  forces,
		}, false},
		{"P12 init.d in an in-checkout Gradle home", map[string]string{
			"build.gradle":            enforced + pulls,
			".gradle/init.d/x.gradle": "allprojects { " + forces + " }\n",
		}, false},
		{"init.gradle in an in-checkout Gradle home", map[string]string{
			"build.gradle":        enforced + pulls,
			".gradle/init.gradle": "allprojects { " + forces + " }\n",
		}, false},
		{"init.gradle.kts in an in-checkout Gradle home", map[string]string{
			"build.gradle":            enforced + pulls,
			".gradle/init.gradle.kts": "allprojects { " + forces + " }\n",
		}, false},
		{"an in-checkout Gradle cache, no init script", map[string]string{
			"build.gradle":                   enforced + pulls,
			".gradle/caches/modules-2/x.bin": "",
		}, true},
		{"P13 capabilities resolution", map[string]string{
			"build.gradle": enforced + "configurations.all { getResolutionStrategy().capabilitiesResolution.all { selectHighestVersion() } }\n" + pulls,
		}, false},
		{"P14 module replacement", map[string]string{
			"build.gradle": enforced + "dependencies { modules { module('com.evil:netkit') { replacedBy('com.evil:netkit2') } } }\n" + pulls,
		}, false},
		{"E1 enforced, apply from sets LENIENT", map[string]string{
			"build.gradle": enforced + "apply from: 'lock.gradle'\n" + dyn,
			"lock.gradle":  "dependencyLocking { lockMode = LockMode.LENIENT }\n",
		}, false},
		{"E2 enforced, a buildSrc plugin sets LENIENT", map[string]string{
			"build.gradle": "plugins { id 'my.conv' }\n" + enforced + dyn,
			"buildSrc/src/main/groovy/my.conv.gradle": "dependencyLocking { lockMode = LockMode.LENIENT }\n",
		}, false},
		{"E3 enforced, unlocked by a string-built call", map[string]string{
			"build.gradle": enforced + "configurations.all { it.invokeMethod('deactivate' + 'DependencyLocking', null) }\n" + dyn,
		}, false},
		{"E4 enforced, unlocked through a kts getter", map[string]string{
			"build.gradle.kts": enforced + "configurations.all { getResolutionStrategy().deactivateDependencyLocking() }\ndependencies {\n    implementation(\"com.evil:netkit:1.+\")\n}\n",
		}, false},
		{"an unsafe statement in a sibling project", map[string]string{
			"settings.gradle": "include 'a', 'b'\n",
			"a/build.gradle":  enforced + pulls, "a/gradle.lockfile": lock,
			"b/build.gradle": "rootProject.allprojects { " + forces + " }\n",
		}, false},
		{"includeBuild in settings", map[string]string{
			"settings.gradle": "includeBuild 'logic'\n",
			"build.gradle":    enforced + pulls,
		}, false},
		{"pluginManagement in settings", map[string]string{
			"settings.gradle": "pluginManagement { includeBuild('logic') }\n",
			"build.gradle":    enforced + pulls,
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			locked := false
			for rel, body := range tt.files {
				writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
				locked = locked || filepath.Base(rel) == "gradle.lockfile"
			}
			if !locked {
				writeFile(t, filepath.Join(dir, "gradle.lockfile"), lock)
			}
			inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
			if got := findNode(t, inv, netkit) != nil; got != tt.resolved {
				why, safe := gradleBuildSafe(dir)
				t.Fatalf("netkit resolved at 1.0.0 = %v, want %v (build safe %v: %s)", got, tt.resolved, safe, why)
			}
			if tt.resolved {
				return
			}
			n := findNode(t, inv, mavenPURL("com.evil", "netkit", ""))
			if n == nil || !hasStr(n.Partiality.Reasons, reasonGradleLockUnconfirmed) {
				t.Errorf("want netkit present, unresolved, %s; got %+v", reasonGradleLockUnconfirmed, n)
			}
		})
	}

	// N1: a catalog the reader can't open is treated as empty, and an accessor into it is no
	// SAFE statement, so the lock stays unconfirmed.
	t.Run("a catalog alias with the catalog linked to a FIFO", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "build.gradle"), enforced+"dependencies {\n    implementation libs.netkit\n    implementation 'org.pulls:it:1.0'\n}\n")
		writeFile(t, filepath.Join(dir, "gradle.lockfile"), lock)
		mustFIFO(t, filepath.Join(dir, "f"))
		if err := os.MkdirAll(filepath.Join(dir, "gradle"), 0o755); err != nil {
			t.Fatal(err)
		}
		mustSymlink(t, filepath.Join("..", "f"), filepath.Join(dir, "gradle", "libs.versions.toml"))
		withinDeadline(t, 5*time.Second, func() {
			if findNode(t, toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir()))), netkit) != nil {
				t.Error("netkit bound at its locked version through an unreadable catalog")
			}
		})
	})
}

// gradleBuildSafe is the predicate other readers share, so each way a build leaves the SAFE set
// is checked on it directly, not only through a lock.
func TestGradleBuildSafe(t *testing.T) {
	const safe = "dependencyLocking {\n    lockAllConfigurations()\n}\ndependencies {\n    implementation 'org.pulls:it:1.0'\n}\n"
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		safe  bool
	}{
		{"SAFE root and subproject", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "settings.gradle"), "include 'app'\n")
			writeFile(t, filepath.Join(dir, "build.gradle"), safe)
			writeFile(t, filepath.Join(dir, "app", "build.gradle.kts"), "group = \"x\"\n")
		}, true},
		{"no scripts at all", func(t *testing.T, dir string) {}, true},
		{"settings off the settings allow-list", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "settings.gradle"), "includeBuild 'logic'\n")
			writeFile(t, filepath.Join(dir, "build.gradle"), safe)
		}, false},
		{"an unsafe subproject script", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "settings.gradle"), "include 'app'\n")
			writeFile(t, filepath.Join(dir, "build.gradle"), safe)
			writeFile(t, filepath.Join(dir, "app", "build.gradle"), "configurations.all { }\n")
		}, false},
		{"an unsafe script in a directory no settings script includes", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "build.gradle"), safe)
			writeFile(t, filepath.Join(dir, "other", "build.gradle"), "configurations.all { }\n")
		}, true},
		{"a build script that is a FIFO", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "build.gradle"))
		}, false},
		{"an empty buildSrc directory", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "build.gradle"), safe)
			if err := os.MkdirAll(filepath.Join(dir, "buildSrc"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"buildSrc as a dangling link", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "build.gradle"), safe)
			mustSymlink(t, "nowhere", filepath.Join(dir, "buildSrc"))
		}, false},
		{"an in-checkout Gradle home that can't be searched", func(t *testing.T, dir string) {
			if os.Geteuid() == 0 {
				t.Skip("root searches a mode-000 directory")
			}
			writeFile(t, filepath.Join(dir, "build.gradle"), safe)
			home := filepath.Join(dir, ".gradle")
			if err := os.MkdirAll(home, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(home, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(home, 0o755) })
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)
			withinDeadline(t, 5*time.Second, func() {
				if why, got := gradleBuildSafe(dir); got != tt.safe {
					t.Errorf("gradleBuildSafe = %v (%s), want %v", got, why, tt.safe)
				}
			})
		})
	}
}
