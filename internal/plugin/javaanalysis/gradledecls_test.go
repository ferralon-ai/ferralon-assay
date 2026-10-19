package javaanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnmodeledGradleDependencies(t *testing.T) {
	groovyModeled := `plugins { id 'java' }
repositories { mavenCentral() }
dependencies {
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.0'
    implementation "org.x:y:${v}", 'a:b:1'
    implementation group: 'com.google.errorprone', name: 'javac', version: '9.4.0', classifier: 'all', ext: 'jar'
    implementation(platform('org.springframework.boot:spring-boot-dependencies:3.2.0'))
    implementation libs.guava
    testImplementation(libs.bundles.junit) {
        exclude group: 'org.hamcrest'
    }
    api enforcedPlatform(libs.bom); runtimeOnly 'c:d:1'
    implementation('a:b:1') { transitive = false }
    constraints {
        implementation('a:b:2') { because 'cve' }
    }
    implementation 'a:b:1',
        'c:d:2'
    // implementation files('x.jar')
    /* implementation fileTree('libs') */
    implementation(
        'e:f:1'
    )
}
apply from: 'gradle/extra.gradle'
apply plugin: 'java'
def total = 4 / 2
`
	ktsModeled := `plugins { kotlin("jvm") version "1.9.0" apply false }
dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.0")
    implementation(group = "com.google.errorprone", name = "javac", version = "9.4.0")
    implementation(platform(libs.bom))
    implementation(kotlin("stdlib"))
    "implementation"("a:b:1")
    testImplementation(testFixtures("a:b:1"))
    implementation("a:b:1") { exclude(group = "x"); isTransitive = false }
    constraints { implementation("a:b:2") { version { strictly("2") } } }
    // implementation(files("x.jar"))
}
apply(from = "$rootDir/gradle/extra.gradle.kts")
val cfg = configurations.getByName("x").apply { isCanBeResolved = true }
val ratio = 4 / 2
val q = run { 4 } / 2
`
	extraGroovy := "dependencies { implementation 'g:h:1' }\n"
	extraKts := "dependencies { implementation(\"g:h:1\") }\n"
	groovyWith := func(line string) map[string]string {
		return map[string]string{"build.gradle": "dependencies {\n    implementation 'a:b:1'\n" + line + "\n}\n"}
	}
	ktsWith := func(line string) map[string]string {
		return map[string]string{"build.gradle.kts": "dependencies {\n    implementation(\"a:b:1\")\n" + line + "\n}\n"}
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string // a substring of some entry; "" means nil
	}{
		{"groovy files()", groovyWith("    implementation files('libs/javac-shaded.jar')"), "3: unmodeled declaration implementation files"},
		{"kts files()", ktsWith(`    implementation(files("libs/javac-shaded.jar"))`), "3: unmodeled declaration implementation files"},
		{"groovy runtimeOnly(files())", groovyWith("    runtimeOnly(files('libs/javac-shaded.jar'))"), "runtimeOnly files"},
		{"kts runtimeOnly(files())", ktsWith(`    runtimeOnly(files("libs/javac-shaded.jar"))`), "runtimeOnly files"},
		{"groovy fileTree()", groovyWith("    implementation fileTree(dir: 'libs', include: ['*.jar'])"), "implementation fileTree"},
		{"kts fileTree()", ktsWith(`    implementation(fileTree("libs"))`), "implementation fileTree"},
		{"groovy flatDir", map[string]string{"build.gradle": "repositories {\n  flatDir { dirs 'libs' }\n}\ndependencies { implementation name: 'javac-shaded' }\n"}, "2: flatDir"},
		{"kts flatDir in settings", map[string]string{"build.gradle.kts": extraKts, "settings.gradle.kts": "dependencyResolutionManagement {\n  repositories { flatDir { dirs(\"libs\") } }\n}\n"}, "settings.gradle.kts:2: flatDir"},
		{"groovy project(path:, configuration:)", groovyWith("    implementation project(path: ':lib', configuration: 'shadow')"), "implementation project"},
		{"kts project(path =, configuration =)", ktsWith(`    implementation(project(path = ":lib", configuration = "shadow"))`), "implementation project"},
		{"groovy testFixtures(project())", groovyWith("    testImplementation testFixtures(project(':lib'))"), "testImplementation testFixtures"},
		{"groovy map notation with a configuration key", groovyWith("    implementation group: 'a', name: 'b', configuration: 'shadow'"), "unmodeled declaration"},
		{"groovy variable argument", groovyWith("    implementation someJars"), "implementation someJars"},
		{"kts variable argument", ktsWith(`    implementation(someJars)`), "implementation someJars"},
		{"kts call chained on a declaration", ktsWith(`    implementation("a:b:1").also { add("implementation", files("x.jar")) }`), "unmodeled declaration"},
		{"groovy map value computed by a call", groovyWith("    implementation group: 'a', name: 'b', version: versionFor('b')"), "unmodeled declaration"},
		{"groovy gradleApi()", groovyWith("    implementation gradleApi()"), "implementation gradleApi"},
		{"groovy concatenated coordinate", groovyWith("    implementation 'a:b:' + v"), "unmodeled declaration"},
		{"groovy conditional declaration", groovyWith("    if (x) { implementation 'a:b:1' }"), "unmodeled declaration if"},
		{"kts local in the block", ktsWith(`    val jars = files("libs")`), "unmodeled declaration val"},
		{"groovy dependencies.add outside a block", map[string]string{"build.gradle": "dependencies.add('implementation', files('x.jar'))\n"}, "1: dependencies reference"},
		{"kts project.dependencies.add", map[string]string{"build.gradle.kts": "project.dependencies.add(\"implementation\", files(\"x.jar\"))\n"}, "1: dependencies reference"},
		{"kts includeBuild in settings", map[string]string{"build.gradle.kts": extraKts, "settings.gradle.kts": "includeBuild(\"../javac\")\n"}, "settings.gradle.kts:1: includeBuild"},
		{"groovy dependencySubstitution", map[string]string{"build.gradle": "configurations.all { resolutionStrategy.dependencySubstitution { substitute module('a:b') using project(':c') } }\n"}, "dependencySubstitution"},
		{"kts withDependencies", map[string]string{"build.gradle.kts": "configurations.implementation { withDependencies { add(project.dependencies.create(files(\"x\"))) } }\n"}, "withDependencies"},
		{"groovy defaultDependencies", map[string]string{"build.gradle": "configurations.custom.defaultDependencies { deps -> deps.add(x) }\n"}, "defaultDependencies"},
		{"groovy apply from a URL", map[string]string{"build.gradle": "apply from: 'https://example.com/deps.gradle'\n"}, "1: apply from"},
		{"groovy apply from a missing script", map[string]string{"build.gradle": "apply from: 'gradle/missing.gradle'\n"}, "1: apply from"},
		{"groovy apply from a templated path", map[string]string{"build.gradle": "apply from: \"${dir}/x.gradle\"\n", "x.gradle": extraGroovy}, "1: apply from"},
		{"kts apply from a skipped directory", map[string]string{"build.gradle.kts": "apply(from = \"build/x.gradle.kts\")\n", "build/x.gradle.kts": extraKts}, "1: apply from"},
		{"kts apply block", map[string]string{"build.gradle.kts": "apply { from(\"x.gradle.kts\") }\n", "x.gradle.kts": extraKts}, "1: apply block"},
		{"groovy unterminated string", map[string]string{"build.gradle": "dependencies { implementation 'a:b:1 }\n"}, "0: unlexable"},
		{"kts unbalanced braces", map[string]string{"build.gradle.kts": "dependencies { implementation(\"a:b:1\")\n"}, "0: unbalanced brackets"},
		{"a precompiled script plugin under buildSrc", map[string]string{"build.gradle.kts": extraKts, "buildSrc/src/main/kotlin/conv.gradle.kts": "dependencies { \"implementation\"(files(\"libs/x.jar\")) }\n"}, "buildSrc/src/main/kotlin/conv.gradle.kts:1: unmodeled declaration"},
		{"control: groovy modeled forms only", map[string]string{"build.gradle": groovyModeled, "gradle/extra.gradle": extraGroovy}, ""},
		{"control: kts modeled forms only", map[string]string{"build.gradle.kts": ktsModeled, "gradle/extra.gradle.kts": extraKts}, ""},
		{"control: a script under build/ or .gradle/ is not read", map[string]string{"build.gradle": extraGroovy, "build/tmp/x.gradle": "dependencies { implementation files('x') }\n", ".gradle/init.gradle": "dependencies { implementation files('x') }\n"}, ""},
		{"control: a script applies another by $rootDir from a subdirectory", map[string]string{"build.gradle": "apply from: 'gradle/a.gradle'\n", "gradle/a.gradle": "apply from: \"${rootDir}/gradle/b.gradle\"\n", "gradle/b.gradle": extraGroovy}, ""},
		{"control: no Gradle script", map[string]string{"pom.xml": "<project/>"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tc.files {
				p := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := UnmodeledGradleDependencies(dir)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("got %q, want nil", got)
				}
				return
			}
			for _, e := range got {
				if strings.Contains(e, tc.want) {
					return
				}
			}
			t.Fatalf("got %q, want an entry containing %q", got, tc.want)
		})
	}
}

func TestUnmodeledGradleDependencies_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "build.gradle")
	if err := os.WriteFile(p, []byte("dependencies { implementation 'a:b:1' }\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	got := UnmodeledGradleDependencies(dir)
	if len(got) != 1 || got[0] != "build.gradle:0: unreadable" {
		t.Fatalf("got %q, want [build.gradle:0: unreadable]", got)
	}
}
