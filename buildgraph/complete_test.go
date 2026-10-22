package buildgraph

import (
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
			r.Artifacts = append(r.Artifacts, gradleResolved{File: f})
		}
		return r
	}
	module := func(path, file string) gradleResolution {
		return gradleResolution{Path: path, Artifacts: []gradleResolved{{File: file, Module: true}}}
	}
	for _, tc := range []struct {
		name        string
		tasks       []gradleTask
		uncollected []string
		resolved    []gradleResolution
		noRecords   bool
		files       map[string]string
		buildDir    string   // :app's; $ROOT/app/build when empty
		userHome    string   // :app's; /home/u/.gradle when empty
		repoRoots   []string // :app's file repository roots
		opaque      []string // :app's Ivy repositories with no URL
		want        string   // a reason fragment; "" wants Complete. $ROOT in paths is the checkout.
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
		{name: "project artifact", resolved: []gradleResolution{{Path: ":app:runtimeClasspath", Artifacts: []gradleResolved{{File: "/repo/lib/build/libs/lib.jar", Project: true}}}}},
		{name: "detached resolution of a project's build output", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/app/build/classes/java/main")}},
		{name: "detached resolution beside a project's build output", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/app/libs/agent.jar")}, want: "app/libs/agent.jar, which no collected configuration lists"},
		{name: "build directory at the checkout root", buildDir: "$ROOT", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/libs/agent.jar")}, want: "libs/agent.jar, which no collected configuration lists"},
		{name: "build directory above the checkout", buildDir: "$ROOT/..", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/libs/agent.jar")}, want: "libs/agent.jar, which no collected configuration lists"},
		{name: "resolution under a user home inside a build directory", buildDir: "$ROOT/app/build", userHome: "$ROOT/app/build/gh", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/app/build/gh/caches/modules-2/files-2.1/com.example/agent/1.0/x/agent-1.0.jar")}, want: "agent-1.0.jar, which no collected configuration lists"},
		{name: "resolution under a build directory beside a user home inside it", buildDir: "$ROOT/app/build", userHome: "$ROOT/app/build/gh", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/app/build/classes/java/main")}},
		{name: "resolution under a file repository inside a build directory", repoRoots: []string{"$ROOT/app/build/m2"}, resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/app/build/m2/com/example/agent/1.0/agent-1.0.jar")}, want: "agent-1.0.jar, which no collected configuration lists"},
		{name: "resolution under a flat directory inside another project's build directory", repoRoots: []string{"$ROOT/build/flat"}, resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/build/flat/agent-1.0.jar")}, want: "agent-1.0.jar, which no collected configuration lists"},
		{name: "repository module under a build directory with no file repository recorded", resolved: []gradleResolution{module(":kt:detachedConfiguration1", "$ROOT/app/build/m2/com/example/agent/1.0/agent-1.0.jar")}, want: "agent-1.0.jar, which no collected configuration lists"},
		{name: "repository module the graph holds", resolved: []gradleResolution{module(":kt:detachedConfiguration1", jar)}},
		{name: "resolution under a build directory beside a file repository inside it", repoRoots: []string{"$ROOT/app/build/m2"}, resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "$ROOT/app/build/classes/java/main")}},
		{name: "Ivy repository with no URL", opaque: []string{"ivy"}, want: "project :app: Ivy repository ivy has no URL to place the files it resolves by"},
		{name: "build directory outside the checkout", buildDir: "/repo/app/build", resolved: []gradleResolution{resolution(":kt:detachedConfiguration1", "/repo/app/build/classes/java/main")}, want: "resolved /repo/app/build/classes/java/main"},
		{name: "outside input from the transforms cache", tasks: []gradleTask{{Path: ":compileKotlin", Type: "org.jetbrains.kotlin.gradle.tasks.KotlinCompile", Outside: []string{"/home/u/.gradle/caches/8.14.6/transforms/1c35/transformed/guava_jar-snapshot.bin", "/home/u/.gradle/caches/transforms-3/9a/transformed/lib.jar"}}}},
		{name: "outside input from the module cache", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/.gradle/caches/modules-2/files-2.1/org.slf4j/slf4j-simple/2.0.16/x/slf4j-simple-2.0.16.jar"}}}, want: "slf4j-simple-2.0.16.jar, outside the build"},
		{name: "outside input from a module named like the transforms cache", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/.gradle/caches/modules-2/files-2.1/com.acme/transforms-api/1.0/x/transforms-api-1.0.jar"}}}, want: "transforms-api-1.0.jar, outside the build"},
		{name: "outside input from a transforms directory below the version's", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/.gradle/caches/8.14.6/kotlin-dsl/transforms/agent.jar"}}}, want: "kotlin-dsl/transforms/agent.jar, outside the build"},
		{name: "input from a user home inside the checkout", userHome: "$ROOT/.gradle", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"$ROOT/.gradle/caches/modules-2/files-2.1/org.slf4j/slf4j-simple/2.0.16/x/slf4j-simple-2.0.16.jar"}}}, want: "slf4j-simple-2.0.16.jar, outside the build"},
		{name: "transforms cache in a user home inside the checkout", userHome: "$ROOT/.gradle", tasks: []gradleTask{{Path: ":compileKotlin", Type: "org.jetbrains.kotlin.gradle.tasks.KotlinCompile", Outside: []string{"$ROOT/.gradle/caches/8.14.6/transforms/1c35/transformed/guava_jar-snapshot.bin"}}}},
		{name: "input under a build directory inside a user home inside the checkout", buildDir: "$ROOT/.gradle/build", userHome: "$ROOT/.gradle", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"$ROOT/.gradle/build/agent.jar"}}}, want: "build/agent.jar, outside the build"},
		{name: "build file under a user home inside the checkout", userHome: "$ROOT/ci-cache/gradle", files: map[string]string{"ci-cache/gradle/caches/x/build.gradle": ""}},
		{name: "outside input under a transforms directory below another cache", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/.gradle/caches/journal-1/transforms/agent.jar"}}}, want: "journal-1/transforms/agent.jar, outside the build"},
		{name: "outside input from a cache named like transforms-<n>", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/.gradle/caches/transforms-backup/agent.jar"}}}, want: "transforms-backup/agent.jar, outside the build"},
		{name: "outside input under transforms outside the caches", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/home/u/transforms/agent.jar"}}}, want: "reads /home/u/transforms/agent.jar"},
		{name: "failed resolution", resolved: []gradleResolution{{Path: ":detachedConfiguration3", Failure: "Could not resolve\nmore"}}, want: "resolution of :detachedConfiguration3 failed: Could not resolve"},
		{name: "no resolution recorded", noRecords: true, want: "recorded no resolution"},
		{name: "build file no project reads", files: map[string]string{"tools/build.gradle": ""}, want: "tools/build.gradle is a Gradle build file"},
		{name: "settings file no project reads", files: map[string]string{"sample/settings.gradle.kts": ""}, want: "sample/settings.gradle.kts"},
		{name: "build files in buildSrc and an included build", files: map[string]string{"buildSrc/build.gradle.kts": "", "logic/build.gradle": "", "logic/settings.gradle": ""}},
		{name: "build file under build output", files: map[string]string{"build/tmp/build.gradle": "", "app/build/tmp/build.gradle": "", "logic/build/tmp/build.gradle": "", ".gradle/x/build.gradle": "", "app/.kotlin/build.gradle": ""}},
		{name: "build file under a directory named build that no project builds into", files: map[string]string{"tools/build/build.gradle": ""}, want: "tools/build/build.gradle is a Gradle build file"},
		{name: "build file under a nested .gradle", files: map[string]string{"app/.gradle/build.gradle": ""}, want: "app/.gradle/build.gradle is a Gradle build file"},
		{name: "build file beside node_modules without a package.json", files: map[string]string{"web/node_modules/x/build.gradle": ""}, want: "web/node_modules/x/build.gradle is a Gradle build file"},
		{name: "build file under node_modules beside a package.json", files: map[string]string{"web/package.json": "{}", "web/node_modules/x/build.gradle": ""}},
		{name: "build file in a directory named like buildSrc", files: map[string]string{"buildSrcOld/build.gradle": ""}, want: "buildSrcOld/build.gradle is a Gradle build file"},
		{name: "outside input under a build directory outside the checkout", tasks: []gradleTask{{Path: ":zip", Type: "org.gradle.api.tasks.bundling.Zip", Outside: []string{"/repo/app/build/libs/agent.jar"}}}, want: "reads /repo/app/build/libs/agent.jar"},
		{name: "resolution from the transforms cache", resolved: []gradleResolution{resolution(":detachedConfiguration4", "/home/u/.gradle/caches/transforms-3/9a/transformed/agent.jar")}, want: "resolved /home/u/.gradle/caches/transforms-3/9a/transformed/agent.jar"},
		{name: "resolution of a file named like a POM", resolved: []gradleResolution{resolution(":detachedConfiguration5", "/cache/agent-1.0.pom.jar")}, want: "resolved /cache/agent-1.0.pom.jar"},
		{name: "run alias not observed", tasks: []gradleTask{task(":run", "org.gradle.api.tasks.JavaExec"), {Path: ":go", Type: "org.gradle.api.DefaultTask", Depends: []string{":run"}, Failure: "boom"}}, want: "task :run runs a program"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"settings.gradle": "", "build.gradle": "", "app/build.gradle": ""})
			writeFiles(t, dir, tc.files)
			sub := func(s string) string { return strings.ReplaceAll(s, "$ROOT", dir) }
			tasks := make([]gradleTask, len(tc.tasks))
			for i, tk := range tc.tasks {
				tk.Outside = append([]string(nil), tk.Outside...)
				for j := range tk.Outside {
					tk.Outside[j] = sub(tk.Outside[j])
				}
				tasks[i] = tk
			}
			resolved := make([]gradleResolution, len(tc.resolved))
			for i, r := range tc.resolved {
				r.Artifacts = slices.Clone(r.Artifacts)
				for j := range r.Artifacts {
					r.Artifacts[j].File = sub(r.Artifacts[j].File)
				}
				resolved[i] = r
			}
			buildDir, userHome := cmp.Or(tc.buildDir, "$ROOT/app/build"), cmp.Or(tc.userHome, "/home/u/.gradle")
			out := t.TempDir()
			if !tc.noRecords {
				rec := filepath.Join(out, "resolved")
				if err := os.MkdirAll(rec, 0o755); err != nil {
					t.Fatal(err)
				}
				for i, r := range append([]gradleResolution{resolution(":runtimeClasspath", jar)}, resolved...) {
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
				{Path: ":", RootDir: dir, Dir: dir, BuildFile: filepath.Join(dir, "build.gradle"), BuildDir: filepath.Join(dir, "build"), Tasks: tasks, Uncollected: tc.uncollected},
				{Path: ":app", RootDir: dir, Dir: filepath.Join(dir, "app"), BuildFile: filepath.Join(dir, "app", "build.gradle"), BuildDir: filepath.Clean(sub(buildDir)), UserHome: sub(userHome), OpaqueRepos: tc.opaque},
			}
			for _, r := range tc.repoRoots {
				projects[1].ForeignRoots = append(projects[1].ForeignRoots, sub(r))
			}
			g := *graph
			g.Subject.IncludedBuilds = []string{"logic"}
			g.Subject.Outputs = gradleOutputs(dir, projects, g.Subject.IncludedBuilds)
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
		repo    bool   // the graph holds an artifact from a local repository at .m2/repository
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
		{name: "resource directory in the local repository", repo: true, build: `<resources><resource><directory>.m2/repository/com/oracle/ojdbc8/19.3</directory></resource></resources>`, want: "is in the local repository"},
		{name: "resource directory beside the local repository", repo: true, build: `<resources><resource><directory>src/main/resources</directory></resource></resources>`},
		{name: "war resources in the local repository", repo: true, build: plugin("org.apache.maven.plugins:maven-war-plugin", `<configuration><webResources><resource><directory>$ROOT/.m2/repository/com/oracle</directory></resource></webResources></configuration>`), want: "is in the local repository"},
		{name: "ear source outside", build: plugin("org.apache.maven.plugins:maven-ear-plugin", `<configuration><earSourceDirectory>/opt/ear-extras</earSourceDirectory></configuration>`), want: "/opt/ear-extras is outside the checkout"},
		{name: "POM outside the reactor", files: map[string]string{"samples/pom.xml": pom}, want: "samples/pom.xml is a POM the reactor does not read"},
		{name: "parent through relativePath", files: map[string]string{"pom.xml": `<project><parent><groupId>com.example</groupId><artifactId>parent</artifactId><relativePath>build-parent</relativePath></parent><artifactId>app</artifactId></project>`, "build-parent/pom.xml": `<project><groupId>com.example</groupId><artifactId>parent</artifactId></project>`}},
		{name: "default relativePath naming another project", reactor: "app/pom.xml", files: map[string]string{"app/pom.xml": `<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId></parent><artifactId>app</artifactId></project>`}, want: "pom.xml is a POM the reactor does not read"},
		{name: "default relativePath naming the parent", reactor: "app/pom.xml", files: map[string]string{"app/pom.xml": `<project><parent><groupId>com.example</groupId><artifactId>app</artifactId></parent><artifactId>app</artifactId></project>`}},
		{name: "empty relativePath", reactor: "app/pom.xml", files: map[string]string{"app/pom.xml": `<project><parent><groupId>com.example</groupId><artifactId>app</artifactId><relativePath/></parent><artifactId>app</artifactId></project>`}, want: "pom.xml is a POM the reactor does not read"},
		{name: "POM under build output", files: map[string]string{"target/classes/META-INF/maven/pom.xml": pom}},
		{name: "POM under a directory named target that no module builds into", files: map[string]string{"tools/target/pom.xml": pom}, want: "tools/target/pom.xml is a POM the reactor does not read"},
		{name: "POM under a build directory the effective POM names", build: `<directory>$ROOT/out</directory>`, files: map[string]string{"out/classes/META-INF/maven/pom.xml": pom}},
		{name: "POM under target beside a build directory the effective POM names", build: `<directory>$ROOT/out</directory>`, files: map[string]string{"target/classes/META-INF/maven/pom.xml": pom}, want: "target/classes/META-INF/maven/pom.xml is a POM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"pom.xml": pom})
			writeFiles(t, dir, tc.files)
			eff, err := parseEffectivePOM([]byte(effective(strings.ReplaceAll(tc.build, "$ROOT", dir))))
			if err != nil {
				t.Fatal(err)
			}
			file := tc.reactor
			if file == "" {
				file = "pom.xml"
			}
			reactor := []reactorProject{{key: "com.example:app", file: file}}
			var modules []Module
			if tc.repo {
				jar := filepath.Join(dir, ".m2", "repository", "com", "oracle", "ojdbc8", "19.3", "ojdbc8-19.3.jar")
				modules = []Module{{Nodes: []Node{{Group: "com.oracle", Artifact: "ojdbc8", Version: "19.3", File: &File{Path: jar}}}}}
				writeFiles(t, dir, map[string]string{".m2/repository/com/oracle/ojdbc8/19.3/ojdbc8-19.3.jar": ""})
			}
			reasons, err := mavenIncomplete(dir, mavenOutputs(dir, reactor, eff, modules), modules, reactor, eff)
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
		".m2/repository/g/b/2/b-2.jar":          "x",
		"target/app.jar":                        "x",
		"build/libs/app.jar":                    "x",
		"src/main/resources/notes.txt":          "x",
		"sub/gradle/wrapper/gradle-wrapper.jar": "x",
		"vendor/m2/a.jar":                       "x",
		"vendor/.m2/ojdbc8.jar":                 "x",
		"tools/build/vendor/ojdbc8.jar":         "x",
		"tools/target/agent.jar":                "x",
		"app/.gradle/agent.jar":                 "x",
		"web/node_modules/agent.jar":            "x",
		"ui/package.json":                       "{}",
		"ui/node_modules/dep/dep.jar":           "x",
		"vendor/sdk.zip":                        "x",
		"vendor/lib.aar":                        "x",
		"vendor/java.sql.jmod":                  "x",
		"vendor/conn.rar":                       "x",
		"vendor/classes/A.class":                "x",
		"libs/m2-tools.jar":                     "x",
		"store/agent.bin":                       "x",
	})
	outside := t.TempDir()
	writeFiles(t, outside, map[string]string{"agent.jar": "x"})
	links := map[string]string{
		"libs/linked.jar":    filepath.Join(dir, "store", "agent.bin"),
		"libs/held-link.jar": filepath.Join(dir, "lib", "held.jar"),
		"libs/gone.jar":      filepath.Join(dir, "missing.jar"),
		"vendor/opt":         outside,
		"vendor/inside":      filepath.Join(dir, "lib"),
		"vendor/built":       filepath.Join(dir, "target"),
		"vendor/self":        dir,
		"sub/build":          outside,
		"app/node_modules":   outside,
		"cache":              outside,
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	via := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(dir, via); err != nil {
		t.Fatal(err)
	}
	nodes := []Node{
		{ID: "h", File: &File{Path: filepath.Join(dir, "lib", "held.jar")}},
		{ID: "a", Group: "g", Artifact: "a", Version: "1", File: &File{Path: filepath.Join(dir, ".m2", "repository", "g", "a", "1", "a-1.jar")}},
		// None of these is laid out under its coordinates, or it is system-scoped, so none names
		// a repository; the last is laid out from the checkout root, which is never an output.
		{ID: "s", Group: "g", Artifact: "s", Version: "1", Scope: "system", File: &File{Path: filepath.Join(dir, "x0", "g", "s", "1", "s-1.jar")}},
		{ID: "v", Group: "g", Artifact: "v", Version: "9", File: &File{Path: filepath.Join(dir, "x1", "g", "v", "2", "v-2.jar")}},
		{ID: "r", Group: "g", Artifact: "r", Version: "1", File: &File{Path: filepath.Join(dir, "x2", "g", "z", "1", "r-1.jar")}},
		{ID: "q", Group: "g.h", Artifact: "q", Version: "1", File: &File{Path: filepath.Join(dir, "x3", "g", "x", "q", "1", "q-1.jar")}},
		{ID: "o", Group: "g", Artifact: "o", Version: "1", File: &File{Path: filepath.Join(dir, "g", "o", "1", "o-1.jar")}},
	}
	g := &Graph{Modules: []Module{{Nodes: nodes}}}
	g.Subject.Outputs = append(mavenOutputs(dir, []reactorProject{{key: "g:app", file: "pom.xml"}}, nil, g.Modules), "build", "cache")
	if want := ".m2/repository,build,cache,target"; strings.Join(sortedUnique(g.Subject.Outputs), ",") != want {
		t.Fatalf("outputs = %q, want %s", g.Subject.Outputs, want)
	}
	want := []string{
		"app/.gradle/agent.jar", "app/node_modules", "libs/agent.jar", "libs/gone.jar", "libs/linked.jar", "libs/m2-tools.jar",
		"sub/build", "sub/gradle/wrapper/gradle-wrapper.jar", "tools/build/vendor/ojdbc8.jar", "tools/target/agent.jar",
		"vendor/.m2/ojdbc8.jar", "vendor/built", "vendor/classes/A.class", "vendor/conn.rar", "vendor/java.sql.jmod",
		"vendor/lib.aar", "vendor/m2/a.jar", "vendor/opt", "vendor/sdk.zip", "vendor/self", "web/app.WAR", "web/node_modules/agent.jar",
	}
	for _, root := range []string{dir, via} {
		got, err := CheckedInArchives(root, g)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: archives = %q, want %q", root, got, want)
		}
	}
	// A graph recording no outputs, or outputs that are not paths in the checkout, has build
	// output walked.
	for _, outputs := range [][]string{nil, {"", ".", "..", "/", "../" + filepath.Base(dir), "target/../target"}} {
		g.Subject.Outputs = outputs
		got, err := CheckedInArchives(dir, g)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(got, "target/app.jar") || !slices.Contains(got, "build/libs/app.jar") || !slices.Contains(got, "cache") {
			t.Errorf("outputs %q: archives = %q, want build output and the cache link listed", outputs, got)
		}
	}
}

// A build directory or user home at the checkout root is never an output, or the whole
// checkout would go unwalked.
func TestGradleOutputsNeverHoldTheRoot(t *testing.T) {
	dir := t.TempDir()
	out := gradleOutputs(dir, []gradleProject{{Path: ":", Dir: dir, BuildDir: dir, UserHome: dir}}, nil)
	if slices.Contains(out, ".") {
		t.Errorf("outputs = %q", out)
	}
}

func TestOrphanBuildFileLinks(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	writeFiles(t, dir, map[string]string{"settings.gradle": "", "store/tools.gradle": "", "store/tools.xml": ""})
	for name, target := range map[string]string{
		"tools/build.gradle": filepath.Join(dir, "store", "tools.gradle"),
		"tools/pom.xml":      filepath.Join(dir, "store", "tools.xml"),
		"shared":             outside,
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	via := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(dir, via); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{dir, via} {
		checkOrphanLinks(t, root)
	}
}

func checkOrphanLinks(t *testing.T, dir string) {
	t.Helper()
	gradle, err := gradleOrphanBuildFiles(dir, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	maven, err := mavenOrphanPOMs(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tools/build.gradle is a Gradle build file", "shared links to a directory outside the checkout"} {
		if !hasReason(gradle, want) {
			t.Errorf("gradle: want a reason with %q, got %q", want, gradle)
		}
	}
	for _, want := range []string{"tools/pom.xml is a POM the reactor does not read", "shared links to a directory outside the checkout"} {
		if !hasReason(maven, want) {
			t.Errorf("maven: want a reason with %q, got %q", want, maven)
		}
	}
}

// A project without a group records its aliases as ":name" or "null:name"; neither names a
// coordinate, so neither is kept.
func TestGradleModuleAliases(t *testing.T) {
	ms, err := gradleModule(gradleProject{Path: ":app", RootDir: "/r", Dir: "/r/app", Group: "com.acme", Name: "app", Version: "1",
		Aliases: []string{"com.acme:app", "com.acme:app-core", ":app-core", "null:app-core", "com.acme:", "com.acme:app-core"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ms[0].Aliases; !slices.Equal(got, []string{"com.acme:app-core"}) {
		t.Errorf("aliases = %q", got)
	}
}
