package buildgraph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hasReason reports whether one of reasons contains want.
func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if strings.Contains(r, want) {
			return true
		}
	}
	return false
}

func TestGradleIncomplete(t *testing.T) {
	jar := "/cache/files/lib-1.0.jar"
	graph := &Graph{Modules: []Module{{Nodes: []Node{{ID: "r"}, {ID: "lib", File: &File{Path: jar}}}}}}
	task := func(path, typ string) gradleTask { return gradleTask{Path: path, Type: typ} }
	resolution := func(path string, files ...string) gradleResolution {
		r := gradleResolution{Path: path}
		for _, f := range files {
			r.Artifacts = append(r.Artifacts, struct {
				File    string `json:"file"`
				Project bool   `json:"project"`
			}{File: f})
		}
		return r
	}
	for _, tc := range []struct {
		name        string
		tasks       []gradleTask
		uncollected []string
		resolved    []gradleResolution
		noRecords   bool
		files       map[string]string
		want        string // a reason fragment; "" wants Complete
	}{
		{name: "listed tasks", tasks: []gradleTask{task(":jar", "org.gradle.api.tasks.bundling.Jar"), task(":bootJar", "org.springframework.boot.gradle.tasks.bundling.BootJar")}},
		{name: "unknown task type", tasks: []gradleTask{task(":fetch", "build_abc.FetchTask")}, want: "task :fetch has type build_abc.FetchTask"},
		{name: "exec task as a leaf", tasks: []gradleTask{task(":run", "org.gradle.api.tasks.JavaExec")}},
		{name: "exec task behind a run alias", tasks: []gradleTask{task(":runShadow", "com.github.jengelman.gradle.plugins.shadow.internal.JavaJarExec"), {Path: ":runFatJar", Type: "org.gradle.api.DefaultTask", Depends: []string{":runShadow"}}}},
		{name: "run alias with an action", tasks: []gradleTask{task(":run", "org.gradle.api.tasks.JavaExec"), {Path: ":go", Type: "org.gradle.api.DefaultTask", Depends: []string{":run"}, Actions: []string{"org.gradle.api.internal.AbstractTask$ClosureTaskAction"}}}, want: "task :run runs a program"},
		{name: "run alias depending on more than programs", tasks: []gradleTask{task(":run", "org.gradle.api.tasks.JavaExec"), task(":jar", "org.gradle.api.tasks.bundling.Jar"), {Path: ":go", Type: "org.gradle.api.DefaultTask", Depends: []string{":run", ":jar"}}}, want: "task :run runs a program"},
		{name: "run alias something depends on", tasks: []gradleTask{task(":run", "org.gradle.api.tasks.JavaExec"), {Path: ":go", Type: "org.gradle.api.DefaultTask", Depends: []string{":run"}}, {Path: ":assemble", Type: "org.gradle.api.DefaultTask", Depends: []string{":go"}}}, want: "task :run runs a program"},
		{name: "exec task finalized by a packaging task", tasks: []gradleTask{{Path: ":runit", Type: "org.gradle.api.tasks.JavaExec", Depends: []string{":jar"}, FinalizedBy: []string{":jar"}}, task(":jar", "org.gradle.api.tasks.bundling.Jar")}, want: "task :runit runs a program (org.gradle.api.tasks.JavaExec) finalized by :jar"},
		{name: "exec task depended on", tasks: []gradleTask{task(":gen", "org.gradle.api.tasks.Exec"), {Path: ":jar", Type: "org.gradle.api.tasks.bundling.Jar", Depends: []string{":gen"}}}, want: "task :gen runs a program"},
		{name: "action from a plugin on the list", tasks: []gradleTask{{Path: ":test", Type: "org.gradle.api.tasks.testing.Test", Actions: []string{"org.gradle.testing.jacoco.plugins.JacocoPluginExtension$JacocoOutputCleanupTestTaskAction"}}}},
		{name: "action from a build script", tasks: []gradleTask{{Path: ":jar", Type: "org.gradle.api.tasks.bundling.Jar", Actions: []string{"Build_gradle$$$result$1$1"}}}, want: "has an action added by Build_gradle"},
		{name: "outside input the graph holds", tasks: []gradleTask{{Path: ":jar", Type: "org.gradle.api.tasks.bundling.Jar", Outside: []string{jar}}}},
		{name: "outside input the graph lacks", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/etc/agent.jar"}}}, want: "reads /etc/agent.jar, outside the build"},
		{name: "task not observed", tasks: []gradleTask{{Path: ":jar", Failure: "boom"}}, want: "task :jar could not be observed"},
		{name: "uncollected configuration", uncollected: []string{"agent"}, want: "configuration agent was not collected"},
		{name: "detached resolution of a listed file", resolved: []gradleResolution{resolution(":detachedConfiguration1", jar, "/cache/lib-1.0.pom")}},
		{name: "detached resolution of an unlisted file", resolved: []gradleResolution{resolution(":detachedConfiguration2", "/cache/agent-1.0.jar")}, want: "resolved /cache/agent-1.0.jar"},
		{name: "build script classpath", resolved: []gradleResolution{resolution("classpath", "/cache/plugin.jar")}},
		{name: "project build script classpath", resolved: []gradleResolution{func() gradleResolution {
			r := resolution(":app:classpath", "/cache/plugin.jar")
			r.Script = true
			return r
		}()}},
		{name: "project configuration named classpath", resolved: []gradleResolution{resolution(":app:classpath", "/cache/agent-1.0.jar")}, want: "resolved /cache/agent-1.0.jar"},
		{name: "project artifact", resolved: []gradleResolution{{Path: ":app:runtimeClasspath", Artifacts: []struct {
			File    string `json:"file"`
			Project bool   `json:"project"`
		}{{File: "/repo/lib/build/libs/lib.jar", Project: true}}}}},
		{name: "detached resolution of a project's build output", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "/repo/app/build/classes/java/main")}},
		{name: "detached resolution beside a project's build output", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "/repo/app/libs/agent.jar")}, want: "resolved /repo/app/libs/agent.jar"},
		{name: "outside input from the transforms cache", tasks: []gradleTask{{Path: ":compileKotlin", Type: "org.jetbrains.kotlin.gradle.tasks.KotlinCompile", Outside: []string{"/home/u/.gradle/caches/8.14.6/transforms/1c35/transformed/guava_jar-snapshot.bin", "/home/u/.gradle/caches/transforms-3/9a/transformed/lib.jar"}}}},
		{name: "outside input from the module cache", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/.gradle/caches/modules-2/files-2.1/org.slf4j/slf4j-simple/2.0.16/x/slf4j-simple-2.0.16.jar"}}}, want: "slf4j-simple-2.0.16.jar, outside the build"},
		{name: "outside input under transforms outside the caches", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/transforms/agent.jar"}}}, want: "reads /home/u/transforms/agent.jar"},
		{name: "failed resolution", resolved: []gradleResolution{{Path: ":detachedConfiguration3", Failure: "Could not resolve\nmore"}}, want: "resolution of :detachedConfiguration3 failed: Could not resolve"},
		{name: "no resolution recorded", noRecords: true, want: "recorded no resolution"},
		{name: "build file no project reads", files: map[string]string{"tools/build.gradle": ""}, want: "tools/build.gradle is a Gradle build file"},
		{name: "settings file no project reads", files: map[string]string{"sample/settings.gradle.kts": ""}, want: "sample/settings.gradle.kts"},
		{name: "build files in buildSrc and an included build", files: map[string]string{"buildSrc/build.gradle.kts": "", "logic/build.gradle": "", "logic/settings.gradle": ""}},
		{name: "build file under build output", files: map[string]string{"build/tmp/build.gradle": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"settings.gradle": "", "build.gradle": "", "app/build.gradle": ""})
			writeFiles(t, dir, tc.files)
			out := t.TempDir()
			if !tc.noRecords {
				rec := filepath.Join(out, "resolved")
				if err := os.MkdirAll(rec, 0o755); err != nil {
					t.Fatal(err)
				}
				for i, r := range append([]gradleResolution{resolution(":runtimeClasspath", jar)}, tc.resolved...) {
					b, err := json.Marshal(r)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(rec, string(rune('a'+i))+".txt"), b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			projects := []gradleProject{
				{Path: ":", RootDir: dir, BuildFile: filepath.Join(dir, "build.gradle"), Tasks: tc.tasks, Uncollected: tc.uncollected},
				{Path: ":app", RootDir: dir, BuildFile: filepath.Join(dir, "app", "build.gradle"), BuildDir: "/repo/app/build", UserHome: "/home/u/.gradle"},
			}
			g := *graph
			g.Subject.IncludedBuilds = []string{"logic"}
			reasons, err := gradleIncomplete(out, dir, projects, &g)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" && len(reasons) > 0 {
				t.Fatalf("want complete, got %q", reasons)
			}
			if tc.want != "" && !hasReason(reasons, tc.want) {
				t.Fatalf("want a reason with %q, got %q", tc.want, reasons)
			}
		})
	}
}

func TestMavenIncomplete(t *testing.T) {
	const pom = `<project><groupId>com.example</groupId><artifactId>app</artifactId></project>`
	effective := func(build string) string {
		return `<project><groupId>com.example</groupId><artifactId>app</artifactId><build>` + build + `</build></project>`
	}
	plugin := func(coord, body string) string {
		g, a, _ := strings.Cut(coord, ":")
		return `<plugins><plugin><groupId>` + g + `</groupId><artifactId>` + a + `</artifactId>` + body + `</plugin></plugins>`
	}
	exec := func(id, phase string, goals ...string) string {
		s := `<executions><execution><id>` + id + `</id>`
		if phase != "" {
			s += `<phase>` + phase + `</phase>`
		}
		s += `<goals>`
		for _, g := range goals {
			s += `<goal>` + g + `</goal>`
		}
		return s + `</goals></execution></executions>`
	}
	for _, tc := range []struct {
		name    string
		build   string
		files   map[string]string
		reactor string // the module's POM; "" is the root's
		want    string
	}{
		{name: "core lifecycle", build: plugin("org.apache.maven.plugins:maven-compiler-plugin", exec("default-compile", "compile", "compile"))},
		{name: "plugin off the list", build: plugin("org.apache.maven.plugins:maven-antrun-plugin", exec("fetch", "generate-resources", "run")), want: "maven-antrun-plugin execution fetch"},
		{name: "plugin off the list at phase none", build: plugin("org.codehaus.mojo:exec-maven-plugin", exec("off", "none", "exec"))},
		{name: "plugin off the list with no goals", build: plugin("org.codehaus.mojo:exec-maven-plugin", "")},
		{name: "dependency copy", build: plugin("org.apache.maven.plugins:maven-dependency-plugin", exec("agent", "package", "copy")), want: "maven-dependency-plugin:copy"},
		{name: "dependency tree", build: plugin("org.apache.maven.plugins:maven-dependency-plugin", exec("t", "validate", "tree"))},
		{name: "dependency artifactItems at plugin level", build: plugin("org.apache.maven.plugins:maven-dependency-plugin", `<configuration><artifactItems><artifactItem/></artifactItems></configuration>`), want: "configures artifacts outside the tree"},
		{name: "dependency artifact on default-cli", build: plugin("org.apache.maven.plugins:maven-dependency-plugin", `<executions><execution><id>default-cli</id><configuration><artifact>g:a:1</artifact></configuration></execution></executions>`), want: "default-cli configures artifacts"},
		{name: "build-helper attach-artifact", build: plugin("org.codehaus.mojo:build-helper-maven-plugin", exec("attach", "package", "attach-artifact")), want: "build-helper-maven-plugin:attach-artifact"},
		{name: "build-helper add-source", build: plugin("org.codehaus.mojo:build-helper-maven-plugin", exec("gen", "generate-sources", "add-source"))},
		{name: "build extension", build: `<extensions><extension><groupId>kr.motd.maven</groupId><artifactId>os-maven-plugin</artifactId></extension></extensions>`, want: "build extension kr.motd.maven:os-maven-plugin"},
		{name: "extensions.xml", files: map[string]string{".mvn/extensions.xml": "<extensions/>"}, want: ".mvn/extensions.xml"},
		{name: "resource directory inside", build: `<resources><resource><directory>src/main/resources</directory></resource></resources>`},
		{name: "resource directory outside", build: `<resources><resource><directory>/opt/agent</directory></resource></resources>`, want: "resource directory /opt/agent is outside the checkout"},
		{name: "resource directory uninterpolated", build: `<testResources><testResource><directory>${agent.dir}</directory></testResource></testResources>`, want: "is not interpolated"},
		{name: "war source outside", build: plugin("org.apache.maven.plugins:maven-war-plugin", `<configuration><warSourceDirectory>../../web</warSourceDirectory></configuration>`), want: "is outside the checkout"},
		{name: "copy-resources directory outside", build: plugin("org.apache.maven.plugins:maven-resources-plugin", `<executions><execution><id>c</id><phase>process-resources</phase><goals><goal>copy-resources</goal></goals><configuration><resources><resource><directory>/srv/x</directory></resource></resources></configuration></execution></executions>`), want: "/srv/x is outside the checkout"},
		{name: "POM outside the reactor", files: map[string]string{"samples/pom.xml": pom}, want: "samples/pom.xml is a POM the reactor does not read"},
		{name: "parent through relativePath", files: map[string]string{"pom.xml": `<project><parent><groupId>com.example</groupId><artifactId>parent</artifactId><relativePath>build-parent</relativePath></parent><artifactId>app</artifactId></project>`, "build-parent/pom.xml": `<project><groupId>com.example</groupId><artifactId>parent</artifactId></project>`}},
		{name: "default relativePath naming another project", reactor: "app/pom.xml", files: map[string]string{"app/pom.xml": `<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId></parent><artifactId>app</artifactId></project>`}, want: "pom.xml is a POM the reactor does not read"},
		{name: "default relativePath naming the parent", reactor: "app/pom.xml", files: map[string]string{"app/pom.xml": `<project><parent><groupId>com.example</groupId><artifactId>app</artifactId></parent><artifactId>app</artifactId></project>`}},
		{name: "empty relativePath", reactor: "app/pom.xml", files: map[string]string{"app/pom.xml": `<project><parent><groupId>com.example</groupId><artifactId>app</artifactId><relativePath/></parent><artifactId>app</artifactId></project>`}, want: "pom.xml is a POM the reactor does not read"},
		{name: "POM under build output", files: map[string]string{"target/classes/META-INF/maven/pom.xml": pom}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"pom.xml": pom})
			writeFiles(t, dir, tc.files)
			eff, err := parseEffectivePOM([]byte(effective(tc.build)))
			if err != nil {
				t.Fatal(err)
			}
			file := tc.reactor
			if file == "" {
				file = "pom.xml"
			}
			reasons, err := mavenIncomplete(dir, []reactorProject{{key: "com.example:app", file: file}}, eff)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" && len(reasons) > 0 {
				t.Fatalf("want complete, got %q", reasons)
			}
			if tc.want != "" && !hasReason(reasons, tc.want) {
				t.Fatalf("want a reason with %q, got %q", tc.want, reasons)
			}
		})
	}
}

func TestCheckedInArchives(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"libs/agent.jar":                        "x",
		"lib/held.jar":                          "x",
		"web/app.WAR":                           "x",
		"gradle/wrapper/gradle-wrapper.jar":     "x",
		".mvn/wrapper/maven-wrapper.jar":        "x",
		".m2/repository/g/a/1/a-1.jar":          "x",
		"target/app.jar":                        "x",
		"build/libs/app.jar":                    "x",
		"src/main/resources/notes.txt":          "x",
		"sub/gradle/wrapper/gradle-wrapper.jar": "x",
	})
	g := &Graph{Modules: []Module{{Nodes: []Node{{ID: "h", File: &File{Path: filepath.Join(dir, "lib", "held.jar")}}}}}}
	got, err := CheckedInArchives(dir, g)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"libs/agent.jar", "sub/gradle/wrapper/gradle-wrapper.jar", "web/app.WAR"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("archives = %q, want %q", got, want)
	}
}
