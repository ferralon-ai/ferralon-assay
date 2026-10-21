package buildgraph

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// fakeMaven answers each step the producer runs from files in $FAKE_DIR, writing the step's
// output where the producer asked, and fails the step named by $FAKE_FAIL with fail.txt. An
// evaluated expression's answer is eval/<expression>, or Maven's null text when there is none.
const fakeMaven = `#!/bin/sh
out=""; step=""; expr=""
for a in "$@"; do
  case "$a" in
    -v) step=version ;;
    *:active-profiles) step=active-profiles ;;
    *:effective-pom) step=effective-pom ;;
    *:tree) step=tree ;;
    *:list) step=list ;;
    *:evaluate) step=evaluate ;;
    -Dexpression=*) expr="${a#-Dexpression=}" ;;
    -Doutput=*) out="${a#-Doutput=}" ;;
    -DoutputFile=*) out="${a#-DoutputFile=}" ;;
  esac
done
echo "$step $*" >> "$FAKE_DIR/calls"
if [ "$FAKE_FAIL" = "$step" ]; then cat "$FAKE_DIR/fail.txt"; exit 1; fi
sub() { sed "s|@M2@|$FAKE_M2|g; s|@ROOT@|$FAKE_ROOT|g" "$1"; }
case "$step" in
  version) cat "$FAKE_DIR/version.txt" ;;
  tree) cat "$FAKE_DIR/tree.log"; cp "$FAKE_DIR/tree.json" "$out" ;;
  evaluate)
    if [ -f "$FAKE_DIR/eval/$expr" ]; then sub "$FAKE_DIR/eval/$expr" > "$out"
    else echo "null object or invalid expression" > "$out"; fi ;;
  *) sub "$FAKE_DIR/$step.txt" > "$out" ;;
esac
`

// fakeGradle copies $FAKE_DIR's project outputs into the -Dassay.out directory.
const fakeGradle = `#!/bin/sh
out=""
for a in "$@"; do
  case "$a" in -Dassay.out=*) out="${a#-Dassay.out=}" ;; esac
done
if [ -n "$FAKE_FAIL" ]; then cat "$FAKE_DIR/fail.txt"; exit 1; fi
for f in "$FAKE_DIR"/project*.json; do
  sed "s|@M2@|$FAKE_M2|g; s|@ROOT@|$FAKE_ROOT|g" "$f" > "$out/$(basename "$f")"
done
`

const mavenVersionOut = `Apache Maven 3.9.9 (8e8579a9e76f7d015ee5ec7bfcdc97d260186937)
Maven home: /opt/maven
Java version: 21.0.12.1, vendor: Eclipse Adoptium, runtime: /opt/jdk
Default locale: en_US, platform encoding: UTF-8
`

const mavenActiveProfiles = `
Active Profiles for Project 'com.example:root:pom:1.0.0':

The following profiles are active:

Active Profiles for Project 'com.example:module-a:jar:1.0.0':

The following profiles are active:

Active Profiles for Project 'com.example:module-c:jar:1.0.0':

The following profiles are active:

 - extra (source: com.example:module-c:1.0.0)
`

// mavenEffectivePOM gives module-c a repository the root does not declare, its system-scoped
// dependency's path, and <includes> that never reach dependency:tree: surefire's, and a
// dependency-plugin unpack execution's.
const mavenEffectivePOM = `<?xml version="1.0" encoding="UTF-8"?>
<projects>
  <project>
    <groupId>com.example</groupId>
    <artifactId>root</artifactId>
    <repositories>
      <repository><id>central</id><url>https://repo.maven.apache.org/maven2</url></repository>
    </repositories>
  </project>
  <project>
    <groupId>com.example</groupId>
    <artifactId>module-a</artifactId>
    <repositories>
      <repository><id>central</id><url>https://repo.maven.apache.org/maven2</url></repository>
    </repositories>
  </project>
  <project>
    <groupId>com.example</groupId>
    <artifactId>module-c</artifactId>
    <repositories>
      <repository><id>child-only</id><url>file:///srv/child-repo</url></repository>
      <repository><id>central</id><url>https://repo.maven.apache.org/maven2</url></repository>
    </repositories>
    <build>
      <plugins>
        <plugin>
          <artifactId>maven-surefire-plugin</artifactId>
          <configuration><includes><include>**/*IT.java</include></includes></configuration>
        </plugin>
        <plugin>
          <artifactId>maven-dependency-plugin</artifactId>
          <executions><execution><id>unpack-schemas</id><configuration><includes>**/*.xsd</includes></configuration></execution></executions>
        </plugin>
      </plugins>
    </build>
    <dependencies>
      <dependency>
        <groupId>com.example</groupId>
        <artifactId>sys</artifactId>
        <version>1</version>
        <scope>system</scope>
        <systemPath>@M2@/sys.jar</systemPath>
      </dependency>
    </dependencies>
  </project>
</projects>
`

const mavenTreeLog = `[INFO] Scanning for projects...
[INFO] ----------------------------< com.example:root >----------------------------
[INFO] Building root 1.0.0                                                    [1/3]
[INFO]   from pom.xml
[INFO] -------------------------< com.example:module-a >-------------------------
[INFO] Building module-a 1.0.0                                                [2/3]
[INFO]   from module-a/pom.xml
[INFO] -------------------------< com.example:module-c >-------------------------
[INFO] Building module-c 1.0.0                                                [3/3]
[INFO]   from module-c/pom.xml
[INFO] BUILD SUCCESS
`

// mavenTree has guava at two versions across modules, a classified artifact, a sibling, and a
// system-scoped jar. module-c's test-scoped guava 33 wins mediation, so module-a's guava 32 is
// not under it. optional is a string, as dependency:tree writes it.
const mavenTree = `{"groupId":"com.example","artifactId":"root","version":"1.0.0","type":"pom","scope":"","classifier":"","optional":"false"}
{"groupId":"com.example","artifactId":"module-a","version":"1.0.0","type":"jar","scope":"","classifier":"","optional":"false","children":[
  {"groupId":"com.google.guava","artifactId":"guava","version":"32.1.3-jre","type":"jar","scope":"compile","classifier":"","optional":"false","children":[
    {"groupId":"com.google.guava","artifactId":"failureaccess","version":"1.0.1","type":"jar","scope":"compile","classifier":"","optional":"false"}]},
  {"groupId":"org.lwjgl","artifactId":"lwjgl","version":"3.3.4","type":"jar","scope":"runtime","classifier":"natives-linux","optional":"true"}]}
{"groupId":"com.example","artifactId":"module-c","version":"1.0.0","type":"jar","scope":"","classifier":"","optional":"false","children":[
  {"groupId":"com.example","artifactId":"module-a","version":"1.0.0","type":"jar","scope":"compile","classifier":"","optional":"false"},
  {"groupId":"com.google.guava","artifactId":"guava","version":"33.0.0-jre","type":"jar","scope":"test","classifier":"","optional":"false"},
  {"groupId":"com.example","artifactId":"sys","version":"1","type":"jar","scope":"system","classifier":"","optional":"false"}]}
`

const mavenList = `
The following files have been resolved:
   com.google.guava:guava:jar:32.1.3-jre:compile:@M2@/guava-32.jar -- module com.google.common [auto]
   com.google.guava:failureaccess:jar:1.0.1:compile:@M2@/failureaccess.jar -- module failureaccess (auto)
   org.lwjgl:lwjgl:jar:natives-linux:3.3.4:runtime:@M2@/lwjgl-natives.jar


The following files have been resolved:
   com.google.guava:guava:jar:33.0.0-jre:test:@M2@/guava-33.jar -- module com.google.common [auto]

`

// mavenTreeLogBefore388 is mavenTreeLog as Maven 3.8.2 prints it: no "from" lines, so the
// module POMs come from the reactor_paths step's answers in mavenEval.
var mavenTreeLogBefore388 = regexp.MustCompile(`(?m)^\[INFO\]   from .*\n`).ReplaceAllString(mavenTreeLog, "")

var mavenEval = map[string]string{
	"eval/session.projects[0].id":   "com.example:root:pom:1.0.0",
	"eval/session.projects[0].file": "@ROOT@/pom.xml",
	"eval/session.projects[1].id":   "com.example:module-a:jar:1.0.0",
	"eval/session.projects[1].file": "@ROOT@/module-a/pom.xml",
	"eval/session.projects[2].id":   "com.example:module-c:jar:1.0.0",
	"eval/session.projects[2].file": "@ROOT@/module-c/pom.xml",
}

type fakeRepo struct {
	dir, fake, m2, work string
	env                 []string
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, "mvnw") || strings.HasSuffix(name, "gradlew") {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
}

// newFakeMaven is a three-module reactor whose ./mvnw is fakeMaven. fail names a step to fail
// with failOut; edit replaces any fake answer file.
func newFakeMaven(t *testing.T, fail, failOut string, edit map[string]string) fakeRepo {
	return newFakeMavenRepo(t, fail, failOut, edit, nil)
}

// newFakeMavenRepo is newFakeMaven with repo's files added to, or replacing, the checkout's.
func newFakeMavenRepo(t *testing.T, fail, failOut string, edit, repo map[string]string) fakeRepo {
	t.Helper()
	root := t.TempDir()
	r := fakeRepo{dir: filepath.Join(root, "repo"), fake: filepath.Join(root, "fake"), m2: filepath.Join(root, "m2"), work: filepath.Join(root, "work")}
	writeFiles(t, r.dir, map[string]string{
		"mvnw":              fakeMaven,
		"pom.xml":           "<project/>",
		"module-a/pom.xml":  "<project/>",
		"module-c/pom.xml":  "<project/>",
		".mvn/maven.config": "-ntp\n",
	})
	writeFiles(t, r.dir, repo)
	answers := map[string]string{
		"version.txt":         mavenVersionOut,
		"active-profiles.txt": mavenActiveProfiles,
		"effective-pom.txt":   mavenEffectivePOM,
		"tree.log":            mavenTreeLog,
		"tree.json":           mavenTree,
		"list.txt":            mavenList,
		"fail.txt":            failOut,
	}
	for k, v := range mavenEval {
		answers[k] = v
	}
	for k, v := range edit {
		answers[k] = v
	}
	writeFiles(t, r.fake, answers)
	writeFiles(t, r.m2, map[string]string{
		"guava-32.jar": "g32", "guava-33.jar": "g33", "failureaccess.jar": "fa", "lwjgl-natives.jar": "nat", "sys.jar": "sys",
	})
	r.env = []string{"PATH=/usr/bin:/bin", "FAKE_DIR=" + r.fake, "FAKE_M2=" + r.m2, "FAKE_ROOT=" + r.dir, "FAKE_FAIL=" + fail}
	return r
}

func (r fakeRepo) resolve(t *testing.T, tool string, c Conditions) (*Graph, error) {
	t.Helper()
	return Resolve(context.Background(), Request{Dir: r.dir, Tool: tool, Conditions: c, WorkDir: r.work, Env: r.env, Producer: Producer{Name: "test", Version: "0"}})
}

func cause(err error) string {
	var f *Failure
	if errors.As(err, &f) {
		return f.Cause()
	}
	if err == nil {
		return ""
	}
	return "untyped: " + err.Error()
}

func module(t *testing.T, g *Graph, id string) Module {
	t.Helper()
	for _, m := range g.Modules {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("no module %s", id)
	return Module{}
}

func node(t *testing.T, m Module, id string) Node {
	t.Helper()
	for _, n := range m.Nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("module %s has no node %s", m.ID, id)
	return Node{}
}

func TestMavenProducer(t *testing.T) {
	r := newFakeMaven(t, "", "", nil)
	g, err := r.resolve(t, ToolAuto, Conditions{Profiles: []string{"extra"}, Properties: map[string]string{"x": "1"}, JDK: "21"})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	if check := g.Validate(); check != "" {
		t.Fatalf("Validate: %s", check)
	}
	if g.Tool != (Tool{Name: "maven", Version: "3.9.9", Wrapper: true}) || g.JVM != (JVM{Version: "21.0.12.1", Vendor: "Eclipse Adoptium"}) {
		t.Fatalf("tool %+v jvm %+v", g.Tool, g.JVM)
	}

	paths := map[string]string{}
	for _, m := range g.Modules {
		paths[m.ID] = m.Path
	}
	if want := map[string]string{"com.example:root": ".", "com.example:module-a": "module-a", "com.example:module-c": "module-c"}; len(paths) != 3 || paths["com.example:root"] != want["com.example:root"] || paths["com.example:module-a"] != want["com.example:module-a"] || paths["com.example:module-c"] != want["com.example:module-c"] {
		t.Fatalf("module paths %v", paths)
	}

	c := module(t, g, "com.example:module-c")
	if strings.Join(c.ActiveProfiles, ",") != "extra" {
		t.Errorf("module-c active profiles %v", c.ActiveProfiles)
	}
	if n := node(t, c, "com.example:module-a:jar:1.0.0"); n.File != nil {
		t.Errorf("reactor sibling has a file: %+v", n.File)
	}
	if n := node(t, c, "com.example:sys:jar:1"); n.File == nil || n.File.Path != filepath.Join(r.m2, "sys.jar") {
		t.Errorf("system node file %+v", n.File)
	}
	if !hasEdge(c, "com.example:module-c:jar:1.0.0", "com.example:module-a:jar:1.0.0") || !hasEdge(c, "com.example:module-c:jar:1.0.0", "com.google.guava:guava:jar:33.0.0-jre") {
		t.Errorf("module-c edges %+v", c.Edges)
	}
	if n := node(t, c, "com.google.guava:guava:jar:33.0.0-jre"); n.Scope != "test" || n.File == nil || n.File.Path != filepath.Join(r.m2, "guava-33.jar") {
		t.Errorf("guava 33 %+v", n)
	}
	a := module(t, g, "com.example:module-a")
	nat := node(t, a, "org.lwjgl:lwjgl:jar:natives-linux:3.3.4")
	if !hasEdge(a, "com.google.guava:guava:jar:32.1.3-jre", "com.google.guava:failureaccess:jar:1.0.1") {
		t.Errorf("module-a edges %+v", a.Edges)
	}
	if !nat.Optional || nat.Classifier != "natives-linux" || nat.File == nil || nat.File.Path != filepath.Join(r.m2, "lwjgl-natives.jar") {
		t.Errorf("classified node %+v", nat)
	}
	if want, _ := sha256File(filepath.Join(r.m2, "lwjgl-natives.jar")); nat.File.SHA256 != want {
		t.Errorf("sha256 %q", nat.File.SHA256)
	}

	// The generated reactor pins each external node by full coordinate and scope, separates the
	// two guava versions, and carries the child-only repository and the .mvn configuration. The
	// system-scoped jar is read in place, so it is not in it.
	layer0 := readFile(t, filepath.Join(r.work, "resolve", "layer-0", "pom.xml"))
	layer1 := readFile(t, filepath.Join(r.work, "resolve", "layer-1", "pom.xml"))
	for _, want := range []string{
		"<classifier>natives-linux</classifier>", "<scope>runtime</scope>",
		"<id>child-only</id>", "<groupId>*</groupId><artifactId>*</artifactId>",
	} {
		if !strings.Contains(layer0, want) {
			t.Errorf("layer-0 lacks %s", want)
		}
	}
	if strings.Contains(layer0+layer1, "system") {
		t.Errorf("generated reactor declares the system-scoped jar:\n%s\n%s", layer0, layer1)
	}
	if strings.Count(layer0, "<artifactId>guava</artifactId>")+strings.Count(layer1, "<artifactId>guava</artifactId>") != 2 || !strings.Contains(layer1, "33.0.0-jre") {
		t.Errorf("guava versions not layered:\n%s\n%s", layer0, layer1)
	}
	if readFile(t, filepath.Join(r.work, "resolve", ".mvn", "maven.config")) != "-ntp\n" {
		t.Error(".mvn/maven.config not carried")
	}

	steps := []string{}
	for _, cmd := range g.Commands {
		steps = append(steps, cmd.Step)
		if cmd.Argv[0] != "./mvnw" || cmd.Argv[1] != "-B" || cmd.Argv[2] != "-P" || cmd.Argv[3] != "extra" || cmd.Argv[4] != "-Dx=1" {
			t.Errorf("%s argv %v", cmd.Step, cmd.Argv)
		}
		for _, a := range cmd.Argv {
			if strings.Contains(a, r.work) {
				t.Errorf("%s argv records the work dir: %v", cmd.Step, cmd.Argv)
			}
		}
	}
	if strings.Join(steps, ",") != "version,active-profiles,effective-pom,tree,list" {
		t.Errorf("steps %v", steps)
	}
	tree := strings.Join(g.Commands[3].Argv, " ")
	if !strings.HasSuffix(tree, "-Dverbose=false") {
		t.Errorf("tree argv %s", tree)
	}
	list := g.Commands[len(g.Commands)-1]
	if !strings.Contains(strings.Join(list.Argv, " "), "-f $OUT/resolve/pom.xml") {
		t.Errorf("list step does not name the generated reactor: %v", list.Argv)
	}

	var inputs []string
	for _, in := range g.Subject.Inputs {
		inputs = append(inputs, in.Path)
	}
	if strings.Join(inputs, ",") != ".mvn/maven.config,module-a/pom.xml,module-c/pom.xml,pom.xml" {
		t.Errorf("inputs %v", inputs)
	}
	if len(g.Sidecars) != 1 || g.Sidecars[0].Name != "effective-pom" {
		t.Errorf("sidecars %+v", g.Sidecars)
	}
}

func hasEdge(m Module, from, to string) bool {
	for _, e := range m.Edges {
		if e == (Edge{From: from, To: to}) {
			return true
		}
	}
	return false
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMavenProducerFailures(t *testing.T) {
	noSystemPath := strings.Replace(mavenEffectivePOM, "<systemPath>@M2@/sys.jar</systemPath>", "", 1)
	listMissing := strings.Replace(mavenList, "   org.lwjgl:lwjgl:jar:natives-linux:3.3.4:runtime:@M2@/lwjgl-natives.jar\n", "", 1)
	partialFrom := strings.Replace(mavenTreeLog, "[INFO]   from module-a/pom.xml\n", "", 1)
	guava31 := `{"groupId":"com.google.guava","artifactId":"guava","version":"31.0-jre","type":"jar","scope":"compile","classifier":"","optional":"false"}`
	sys := `"artifactId":"sys","version":"1","type":"jar","scope":"system","classifier":"","optional":"false"}`
	for _, tc := range []struct {
		name, fail, failOut string
		edit, repo          map[string]string
		env                 []string
		c                   Conditions
		want                string
	}{
		{name: "no java", fail: "version", failOut: "The JAVA_HOME environment variable is not defined correctly\n", want: "toolchain_absent"},
		{name: "jdk mismatch", c: Conditions{JDK: "17"}, want: "jdk_mismatch:17/21.0.12.1"},
		{name: "credentials", fail: "tree", failOut: "[ERROR] Failed to execute goal: Could not transfer artifact a:b:pom:1 from/to corp (https://maven.corp.example/repo): status code: 401, reason phrase: Unauthorized (401)\n", want: "credentials:corp"},
		{name: "credentials on list", fail: "list", failOut: "Could not transfer artifact a:b:jar:1 from/to child-only (file:///x): status code: 403, reason phrase: Forbidden\n", want: "credentials:child-only"},
		{name: "tree fails", fail: "tree", failOut: "[ERROR] BUILD FAILURE\n", want: "tool_failed:tree"},
		{name: "unreadable version", edit: map[string]string{"version.txt": "Maven something\n"}, want: "tool_failed:version"},
		{name: "unreadable tree", edit: map[string]string{"tree.json": "{"}, want: "tool_failed:tree"},
		{name: "tree for a module the log omits", edit: map[string]string{"tree.log": strings.Replace(mavenTreeLog, "[INFO] -------------------------< com.example:module-c >-------------------------\n[INFO] Building module-c 1.0.0                                                [3/3]\n[INFO]   from module-c/pom.xml\n", "", 1)}, want: "tool_failed:tree"},
		{name: "some modules without a POM", edit: map[string]string{"tree.log": partialFrom}, want: "tool_failed:tree"},
		{name: "reactor_paths evaluate fails", fail: "evaluate", failOut: "[ERROR] BUILD FAILURE\n", edit: map[string]string{"tree.log": mavenTreeLogBefore388}, want: "tool_failed:reactor_paths"},
		{name: "reactor_paths names another module", edit: map[string]string{"tree.log": mavenTreeLogBefore388, "eval/session.projects[1].id": "com.example:module-z:jar:1.0.0"}, want: "tool_failed:reactor_paths"},
		{name: "reactor_paths names a module twice", edit: map[string]string{"tree.log": mavenTreeLogBefore388, "eval/session.projects[2].id": "com.example:module-a:jar:1.0.0"}, want: "tool_failed:reactor_paths"},
		{name: "reactor_paths POM outside the repo", edit: map[string]string{"tree.log": mavenTreeLogBefore388, "eval/session.projects[2].file": "@M2@/sys.jar"}, want: "tool_failed:reactor_paths"},
		{name: "reactor_paths relative POM", edit: map[string]string{"tree.log": mavenTreeLogBefore388, "eval/session.projects[2].file": "module-c/pom.xml"}, want: "tool_failed:reactor_paths"},
		{name: "reactor_paths project past the log's", edit: map[string]string{"tree.log": mavenTreeLogBefore388, "eval/session.projects[3].id": "com.example:module-d:jar:1.0.0"}, want: "tool_failed:reactor_paths"},
		{name: "stated verbose", c: Conditions{Properties: map[string]string{"verbose": "true"}}, want: "tool_failed:conditions"},
		{name: "MAVEN_OPTS scope", env: []string{"MAVEN_OPTS=-Xmx1g -Dscope=compile"}, want: "tool_failed:conditions"},
		{name: "maven.config excludes", repo: map[string]string{".mvn/maven.config": "-ntp\n-Dexcludes=a:b\n"}, want: "tool_failed:conditions"},
		{name: "MAVEN_ARGS -D with a space", env: []string{"MAVEN_ARGS=-D verbose=true"}, want: "tool_failed:conditions"},
		{name: "JAVA_TOOL_OPTIONS --define=", env: []string{"JAVA_TOOL_OPTIONS=--define=scope=compile"}, want: "tool_failed:conditions"},
		{name: "jvm.config includes", repo: map[string]string{".mvn/jvm.config": "-Xmx1g -Dincludes=a:b\n"}, want: "tool_failed:conditions"},
		{name: "POM property scope", edit: map[string]string{"effective-pom.txt": strings.Replace(mavenEffectivePOM, "<artifactId>module-a</artifactId>", "<artifactId>module-a</artifactId>\n    <properties><scope>compile</scope></properties>", 1)}, want: "tool_failed:conditions"},
		{name: "dependency-plugin default-cli excludes", edit: map[string]string{"effective-pom.txt": strings.Replace(mavenEffectivePOM, "<artifactId>module-a</artifactId>", "<artifactId>module-a</artifactId>\n    <build><pluginManagement><plugins><plugin><artifactId>maven-dependency-plugin</artifactId><executions><execution><id>default-cli</id><configuration><excludes>a:b</excludes></configuration></execution></executions></plugin></plugins></pluginManagement></build>", 1)}, want: "tool_failed:conditions"},
		{name: "dependency-plugin config verbose", edit: map[string]string{"effective-pom.txt": strings.Replace(mavenEffectivePOM, "<artifactId>module-a</artifactId>", "<artifactId>module-a</artifactId>\n    <build><plugins><plugin><artifactId>maven-dependency-plugin</artifactId><configuration><verbose>true</verbose></configuration></plugin></plugins></build>", 1)}, want: "tool_failed:conditions"},
		{name: "one coordinate at two versions", edit: map[string]string{"tree.json": strings.Replace(mavenTree, sys, strings.TrimSuffix(sys, "}")+`,"children":[`+guava31+`]}`, 1)}, want: "tool_failed:tree"},
		{name: "published version of a sibling", edit: map[string]string{"tree.json": strings.Replace(mavenTree, `"artifactId":"module-a","version":"1.0.0","type":"jar","scope":"compile"`, `"artifactId":"module-a","version":"0.9.0","type":"jar","scope":"compile"`, 1)}, want: "tool_failed:list"},
		{name: "systemPath missing", edit: map[string]string{"effective-pom.txt": strings.Replace(mavenEffectivePOM, "@M2@/sys.jar", "@M2@/gone.jar", 1)}, want: "tool_failed:list"},
		{name: "systemPath relative", edit: map[string]string{"effective-pom.txt": strings.Replace(mavenEffectivePOM, "@M2@/sys.jar", "lib/sys.jar", 1)}, want: "tool_failed:list"},
		{name: "reactor POM missing", edit: map[string]string{"tree.log": strings.Replace(mavenTreeLog, "from module-c/pom.xml", "from module-x/pom.xml", 1)}, want: "tool_failed:inputs"},
		{name: "module POM outside the repo", edit: map[string]string{"tree.log": strings.Replace(mavenTreeLog, "from module-c/pom.xml", "from ../elsewhere/pom.xml", 1)}, want: "tool_failed:tree"},
		{name: "module without active-profiles", edit: map[string]string{"active-profiles.txt": strings.Replace(mavenActiveProfiles, "com.example:module-a:jar:1.0.0", "com.example:module-z:jar:1.0.0", 1)}, want: "tool_failed:active-profiles"},
		{name: "system dependency without systemPath", edit: map[string]string{"effective-pom.txt": noSystemPath}, want: "tool_failed:list"},
		{name: "node the generated reactor does not list", edit: map[string]string{"list.txt": listMissing}, want: "tool_failed:list"},
		{name: "node listed at two files", edit: map[string]string{"list.txt": mavenList + "   com.google.guava:guava:jar:32.1.3-jre:compile:@M2@/guava-33.jar\n"}, want: "tool_failed:list"},
		{name: "listed file missing", edit: map[string]string{"list.txt": strings.Replace(mavenList, "@M2@/guava-32.jar", "@M2@/gone.jar", 1)}, want: "tool_failed:list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFakeMavenRepo(t, tc.fail, tc.failOut, tc.edit, tc.repo)
			r.env = append(r.env, tc.env...)
			g, err := r.resolve(t, ToolMaven, tc.c)
			if got := cause(err); got != tc.want {
				t.Fatalf("cause %q, want %q (graph %v)", got, tc.want, g != nil)
			}
		})
	}
}

// TestMavenReactorPaths: a Maven that prints no "from" lines gets its module POMs from
// help:evaluate, one index at a time with the tree step's arguments, plus one probe past the end.
// A maven-dependency-plugin copy or unpack execution with artifactItems installs artifacts
// dependency:tree never lists, so the module records it as unlisted.
func TestMavenDependencyPluginArtifactItems(t *testing.T) {
	const items = "<artifactItems><artifactItem><groupId>io.opentelemetry.javaagent</groupId><artifactId>opentelemetry-javaagent</artifactId><version>2.10.0</version></artifactItem></artifactItems>"
	plugin := func(config, id, goal, execConfig string) string {
		return "<plugin><artifactId>maven-dependency-plugin</artifactId>" + config + "<executions><execution><id>" + id + "</id><goals><goal>" + goal + "</goal></goals>" + execConfig + "</execution></executions></plugin>"
	}
	for _, tc := range []struct {
		name  string
		build string
		want  []string
	}{
		{name: "copy with artifactItems", build: "<plugins>" + plugin("", "copy-agent", "copy", "<configuration>"+items+"</configuration>") + "</plugins>", want: []string{"maven-dependency-plugin execution copy-agent"}},
		{name: "unpack with plugin-level artifactItems", build: "<plugins>" + plugin("<configuration>"+items+"</configuration>", "unpack-ui", "unpack", "") + "</plugins>", want: []string{"maven-dependency-plugin execution unpack-ui"}},
		{name: "copy-dependencies", build: "<plugins>" + plugin("", "deps", "copy-dependencies", "<configuration><outputDirectory>lib</outputDirectory></configuration>") + "</plugins>"},
		{name: "copy without artifactItems", build: "<plugins>" + plugin("", "copy-none", "copy", "<configuration><outputDirectory>lib</outputDirectory></configuration>") + "</plugins>"},
		{name: "only managed", build: "<pluginManagement><plugins>" + plugin("", "copy-agent", "copy", "<configuration>"+items+"</configuration>") + "</plugins></pluginManagement>"},
		{name: "another plugin", build: "<plugins><plugin><artifactId>maven-assembly-plugin</artifactId><executions><execution><id>copy-agent</id><goals><goal>copy</goal></goals><configuration>" + items + "</configuration></execution></executions></plugin></plugins>"},
	} {
		pom := strings.Replace(mavenEffectivePOM, "<artifactId>module-a</artifactId>", "<artifactId>module-a</artifactId>\n    <build>"+tc.build+"</build>", 1)
		r := newFakeMaven(t, "", "", map[string]string{"effective-pom.txt": pom})
		g, err := r.resolve(t, ToolMaven, Conditions{})
		if err != nil {
			t.Fatalf("%s: resolve: %v", tc.name, cause(err))
		}
		for _, m := range g.Modules {
			want := []string(nil)
			if m.ID == "com.example:module-a" {
				want = tc.want
			}
			if !reflect.DeepEqual(m.Unlisted, want) {
				t.Errorf("%s: %s unlisted %q, want %q", tc.name, m.ID, m.Unlisted, want)
			}
		}
	}
}

func TestMavenReactorPaths(t *testing.T) {
	r := newFakeMaven(t, "", "", map[string]string{"tree.log": mavenTreeLogBefore388})
	g, err := r.resolve(t, ToolMaven, Conditions{Profiles: []string{"extra"}})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	paths := map[string]string{}
	for _, m := range g.Modules {
		paths[m.ID] = m.Path
	}
	if len(paths) != 3 || paths["com.example:root"] != "." || paths["com.example:module-a"] != "module-a" || paths["com.example:module-c"] != "module-c" {
		t.Fatalf("module paths %v", paths)
	}
	var exprs []string
	for _, cmd := range g.Commands {
		if cmd.Step != stepReactorPaths {
			continue
		}
		argv := strings.Join(cmd.Argv, " ")
		if !strings.HasPrefix(argv, "./mvnw -B -P extra ") || strings.Contains(argv, " -f ") {
			t.Errorf("reactor_paths argv %s", argv)
		}
		for _, a := range cmd.Argv {
			if e, ok := strings.CutPrefix(a, "-Dexpression="); ok {
				exprs = append(exprs, e)
			}
		}
	}
	want := "session.projects[0].id,session.projects[0].file,session.projects[1].id,session.projects[1].file,session.projects[2].id,session.projects[2].file,session.projects[3].id"
	if strings.Join(exprs, ",") != want {
		t.Errorf("evaluated %v", exprs)
	}
}

// TestMavenInputsUnderSkippedDir: a reactor POM under a directory the input walk skips is still
// an input.
func TestMavenInputsUnderSkippedDir(t *testing.T) {
	r := newFakeMavenRepo(t, "", "", map[string]string{"tree.log": strings.Replace(mavenTreeLog, "from module-c/pom.xml", "from build/module-c/pom.xml", 1)}, map[string]string{"build/module-c/pom.xml": "<project/>"})
	g, err := r.resolve(t, ToolMaven, Conditions{})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	var inputs []string
	for _, in := range g.Subject.Inputs {
		inputs = append(inputs, in.Path)
	}
	if strings.Join(inputs, ",") != ".mvn/maven.config,build/module-c/pom.xml,module-a/pom.xml,module-c/pom.xml,pom.xml" {
		t.Errorf("inputs %v", inputs)
	}
}

func TestSelectAndToolchain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		tool    string
		wrapper string
		want    string
	}{
		{name: "both build files", files: map[string]string{"pom.xml": "", "settings.gradle": ""}, want: "tool_failed:select"},
		{name: "no build file", files: map[string]string{"README": ""}, want: "tool_failed:select"},
		{name: "unknown tool", files: map[string]string{"pom.xml": ""}, tool: "ant", want: "tool_failed:select"},
		{name: "no wrapper, no mvn", files: map[string]string{"pom.xml": ""}, want: "toolchain_absent"},
		{name: "no wrapper, no gradle", files: map[string]string{"build.gradle.kts": ""}, want: "toolchain_absent"},
		{name: "wrapper not executable", files: map[string]string{"pom.xml": ""}, wrapper: "mvnw", want: "toolchain_absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, tc.files)
			if tc.wrapper != "" {
				// writeFiles makes wrappers executable.
				if err := os.WriteFile(filepath.Join(dir, tc.wrapper), []byte(fakeMaven), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Resolve(context.Background(), Request{Dir: dir, Tool: tc.tool, WorkDir: filepath.Join(t.TempDir(), "w"), Env: []string{"PATH=" + t.TempDir()}})
			if got := cause(err); got != tc.want {
				t.Fatalf("cause %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWorkDirMustBeEmpty(t *testing.T) {
	r := newFakeMaven(t, "", "", nil)
	writeFiles(t, r.work, map[string]string{"list.txt": "stale"})
	if got := cause(func() error { _, err := r.resolve(t, ToolMaven, Conditions{}); return err }()); got != "tool_failed:select" {
		t.Fatalf("cause %q", got)
	}
}

func TestWorkDirOutsideRepo(t *testing.T) {
	r := newFakeMaven(t, "", "", nil)
	r.work = filepath.Join(r.dir, "out")
	if got := cause(func() error { _, err := r.resolve(t, ToolMaven, Conditions{}); return err }()); got != "tool_failed:select" {
		t.Fatalf("cause %q", got)
	}
	if _, err := os.Stat(r.work); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("work dir inside the repo was created: %v", err)
	}
}

// TestMavenReactorPathsKeepsLinkedPath: reactor_paths records a module under a symlinked
// directory by the path Maven names, as a "from" line would.
func TestMavenReactorPathsKeepsLinkedPath(t *testing.T) {
	r := newFakeMaven(t, "", "", map[string]string{"tree.log": mavenTreeLogBefore388, "eval/session.projects[2].file": "@ROOT@/link-c/pom.xml"})
	if err := os.Symlink("module-c", filepath.Join(r.dir, "link-c")); err != nil {
		t.Fatal(err)
	}
	g, err := r.resolve(t, ToolMaven, Conditions{})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	if m := module(t, g, "com.example:module-c"); m.Path != "link-c" {
		t.Errorf("module-c at %q", m.Path)
	}
}

const gradleApp = `{"gradle":"8.14.6","java":"21.0.12.1","java_vendor":"Eclipse Adoptium","path":":app","dir":"@ROOT@/app","build_file":"@ROOT@/app/build.gradle","root_dir":"@ROOT@","group":"com.example","name":"app","version":"1.0.0",
"projects":{":":{"group":"","name":"multi","version":"unspecified"},":app":{"group":"com.example","name":"app","version":"1.0.0"},":lib":{"group":"com.example","name":"lib","version":"1.0.0"}},
"classpaths":{"runtimeClasspath":{
"components":[{"key":"project :app","id":{"project":":app","build":":"}},{"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"org.lwjgl:lwjgl:3.3.4","id":{"group":"org.lwjgl","name":"lwjgl","version":"3.3.4"}},{"key":"com.example:bom:1","id":{"group":"com.example","name":"bom","version":"1"}}],
"edges":[{"from":"project :app","to":"project :lib"},{"from":"project :lib","to":"org.lwjgl:lwjgl:3.3.4"},{"from":"project :app","to":"com.example:bom:1"}],
"unresolved":[],
"files":[{"component":"org.lwjgl:lwjgl:3.3.4","file":"@M2@/lwjgl-3.3.4.jar"},{"component":"org.lwjgl:lwjgl:3.3.4","file":"@M2@/lwjgl-3.3.4-natives-linux.jar"}]},
"compileClasspath":{
"components":[{"key":"project :app","id":{"project":":app","build":":"}},{"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"org.lwjgl:lwjgl:3.3.4","id":{"group":"org.lwjgl","name":"lwjgl","version":"3.3.4"}},{"key":"jakarta.servlet:jakarta.servlet-api:6.0.0","id":{"group":"jakarta.servlet","name":"jakarta.servlet-api","version":"6.0.0"}}],
"edges":[{"from":"project :app","to":"project :lib"},{"from":"project :lib","to":"org.lwjgl:lwjgl:3.3.4"},{"from":"project :app","to":"jakarta.servlet:jakarta.servlet-api:6.0.0"}],
"unresolved":[],
"files":[{"component":"project :lib","file":"@ROOT@/lib/build/classes"},{"component":"org.lwjgl:lwjgl:3.3.4","file":"@M2@/lwjgl-3.3.4.jar"},{"component":"jakarta.servlet:jakarta.servlet-api:6.0.0","file":"@M2@/jakarta.servlet-api-6.0.0.jar"}]},
"testRuntimeClasspath":{
"components":[{"key":"project :app","id":{"project":":app","build":":"}},{"key":"org.lwjgl:lwjgl:3.3.5","id":{"group":"org.lwjgl","name":"lwjgl","version":"3.3.5"}},{"key":"junit:junit:4.13.2","id":{"group":"junit","name":"junit","version":"4.13.2"}}],
"edges":[{"from":"project :app","to":"org.lwjgl:lwjgl:3.3.5"},{"from":"project :app","to":"junit:junit:4.13.2"},{"from":"junit:junit:4.13.2","to":"org.lwjgl:lwjgl:3.3.5"}],
"unresolved":[],
"files":[{"component":"org.lwjgl:lwjgl:3.3.5","file":"@M2@/lwjgl-3.3.5.jar"},{"component":"junit:junit:4.13.2","file":"@M2@/junit-4.13.2.jar"}]}}}`

const gradleLib = `{"gradle":"8.14.6","java":"21.0.12.1","java_vendor":"Eclipse Adoptium","path":":lib","dir":"@ROOT@/lib","build_file":"@ROOT@/lib/build.gradle","root_dir":"@ROOT@","group":"com.example","name":"lib","version":"1.0.0",
"projects":{":":{"group":"","name":"multi","version":"unspecified"},":app":{"group":"com.example","name":"app","version":"1.0.0"},":lib":{"group":"com.example","name":"lib","version":"1.0.0"}},
"classpaths":{"runtimeClasspath":{
"components":[{"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"org.lwjgl:lwjgl:3.3.4","id":{"group":"org.lwjgl","name":"lwjgl","version":"3.3.4"}}],
"edges":[{"from":"project :lib","to":"org.lwjgl:lwjgl:3.3.4"}],
"unresolved":[],
"files":[{"component":"org.lwjgl:lwjgl:3.3.4","file":"@M2@/lwjgl-3.3.4.jar"}]}}}`

const gradleRoot = `{"gradle":"8.14.6","java":"21.0.12.1","java_vendor":"Eclipse Adoptium","path":":","dir":"@ROOT@","build_file":"@ROOT@/build.gradle","root_dir":"@ROOT@","group":"","name":"multi","version":"unspecified",
"projects":{":":{"group":"","name":"multi","version":"unspecified"},":app":{"group":"com.example","name":"app","version":"1.0.0"},":lib":{"group":"com.example","name":"lib","version":"1.0.0"}},
"classpaths":{}}`

func newFakeGradle(t *testing.T, fail string, edit map[string]string) fakeRepo {
	t.Helper()
	root := t.TempDir()
	r := fakeRepo{dir: filepath.Join(root, "repo"), fake: filepath.Join(root, "fake"), m2: filepath.Join(root, "m2"), work: filepath.Join(root, "work")}
	writeFiles(t, r.dir, map[string]string{
		"gradlew": fakeGradle, "settings.gradle": "", "build.gradle": "", "app/build.gradle": "", "lib/build.gradle": "",
		"gradle/libs.versions.toml": "", "gradle/wrapper/gradle-wrapper.properties": "", "app/src/Main.java": "",
	})
	answers := map[string]string{"project_.json": gradleRoot, "project_app.json": gradleApp, "project_lib.json": gradleLib, "fail.txt": "FAILURE: Build failed with an exception.\n"}
	for k, v := range edit {
		answers[k] = v
	}
	writeFiles(t, r.fake, answers)
	writeFiles(t, r.m2, map[string]string{"lwjgl-3.3.4.jar": "l", "lwjgl-3.3.4-natives-linux.jar": "n", "lwjgl-3.3.5.jar": "l5", "lwjgl-3.3.6.jar": "l6", "jakarta.servlet-api-6.0.0.jar": "s", "junit-4.13.2.jar": "j"})
	r.env = []string{"PATH=/usr/bin:/bin", "FAKE_DIR=" + r.fake, "FAKE_M2=" + r.m2, "FAKE_ROOT=" + r.dir, "FAKE_FAIL=" + fail}
	return r
}

func TestGradleProducer(t *testing.T) {
	r := newFakeGradle(t, "", nil)
	g, err := r.resolve(t, ToolAuto, Conditions{Properties: map[string]string{"flavor": "x"}})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	if g.Tool != (Tool{Name: "gradle", Version: "8.14.6", Wrapper: true}) {
		t.Fatalf("tool %+v", g.Tool)
	}
	// The three projects, and :app's test classpath copy of the lwjgl its runtime classpath
	// resolves at another version.
	if len(g.Modules) != 4 {
		t.Fatalf("modules %+v", g.Modules)
	}
	node(t, module(t, g, ":app#testRuntimeClasspath"), "org.lwjgl:lwjgl:jar:3.3.5")
	if m := module(t, g, ":"); m.Path != "." || len(m.Nodes) != 1 {
		t.Errorf("root module %+v", m)
	}
	app := module(t, g, ":app")
	if app.Path != "app" || app.Root != "com.example:app:jar:1.0.0" {
		t.Errorf("app %+v", app)
	}
	if n := node(t, app, "com.example:lib:jar:1.0.0"); n.File != nil {
		t.Errorf("sibling has a file")
	}
	if n := node(t, app, "org.lwjgl:lwjgl:jar:natives-linux:3.3.4"); n.Classifier != "natives-linux" || n.File == nil || n.File.Path != filepath.Join(r.m2, "lwjgl-3.3.4-natives-linux.jar") {
		t.Errorf("classified node %+v", n)
	}
	// runtimeClasspath's version wins; compile-only is provided and test-only is test.
	for id, scope := range map[string]string{
		"com.example:lib:jar:1.0.0":                     "compile",
		"org.lwjgl:lwjgl:jar:3.3.4":                     "compile",
		"org.lwjgl:lwjgl:jar:natives-linux:3.3.4":       "runtime",
		"com.example:bom:pom:1":                         "runtime",
		"jakarta.servlet:jakarta.servlet-api:jar:6.0.0": "provided",
		"junit:junit:jar:4.13.2":                        "test",
	} {
		if n := node(t, app, id); n.Scope != scope {
			t.Errorf("%s scope %q, want %q", id, n.Scope, scope)
		}
	}
	if len(app.Nodes) != 7 {
		t.Errorf("nodes %+v", app.Nodes)
	}
	edges := map[Edge]bool{}
	for _, e := range app.Edges {
		edges[e] = true
	}
	for _, e := range []Edge{
		{From: "com.example:app:jar:1.0.0", To: "com.example:lib:jar:1.0.0"},
		{From: "com.example:lib:jar:1.0.0", To: "org.lwjgl:lwjgl:jar:3.3.4"},
		{From: "com.example:lib:jar:1.0.0", To: "org.lwjgl:lwjgl:jar:natives-linux:3.3.4"},
		{From: "com.example:app:jar:1.0.0", To: "com.example:bom:pom:1"},
		{From: "com.example:app:jar:1.0.0", To: "jakarta.servlet:jakarta.servlet-api:jar:6.0.0"},
		{From: "com.example:app:jar:1.0.0", To: "junit:junit:jar:4.13.2"},
		// The test classpath's lwjgl 3.3.5 edges land on the runtime node.
		{From: "com.example:app:jar:1.0.0", To: "org.lwjgl:lwjgl:jar:3.3.4"},
		{From: "junit:junit:jar:4.13.2", To: "org.lwjgl:lwjgl:jar:3.3.4"},
	} {
		if !edges[e] {
			t.Errorf("missing edge %+v", e)
		}
	}
	if len(app.Edges) != 8 {
		t.Errorf("edges %+v", app.Edges)
	}
	argv := strings.Join(g.Commands[0].Argv, " ")
	if !strings.HasPrefix(argv, "./gradlew -q --no-configuration-cache --project-cache-dir $OUT/pcache") || !strings.Contains(argv, "-Pflavor=x assayBuildGraph") {
		t.Errorf("argv %s", argv)
	}
	var inputs []string
	for _, in := range g.Subject.Inputs {
		inputs = append(inputs, in.Path)
	}
	if strings.Join(inputs, ",") != "app/build.gradle,build.gradle,gradle/libs.versions.toml,gradle/wrapper/gradle-wrapper.properties,lib/build.gradle,settings.gradle" {
		t.Errorf("inputs %v", inputs)
	}
}

// Beside runtimeClasspath, another runtime classpath folds in at test scope, so a copy only it
// resolves is in the graph.
func TestGradleOtherRuntimeClasspath(t *testing.T) {
	lib := strings.Replace(gradleLib, `"version":"1.0.0",
"projects"`, `"version":"1.0.0","other_runtime_classpaths":["integrationTestRuntimeClasspath","runtimeClasspath","testRuntimeClasspath"],
"projects"`, 1)
	lib = strings.TrimSuffix(lib, "}}") + `,
"integrationTestRuntimeClasspath":{
"components":[{"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"org.lwjgl:lwjgl:3.3.5","id":{"group":"org.lwjgl","name":"lwjgl","version":"3.3.5"}},{"key":"junit:junit:4.13.2","id":{"group":"junit","name":"junit","version":"4.13.2"}}],
"edges":[{"from":"project :lib","to":"org.lwjgl:lwjgl:3.3.5"},{"from":"project :lib","to":"junit:junit:4.13.2"}],
"unresolved":[],
"files":[{"component":"org.lwjgl:lwjgl:3.3.5","file":"@M2@/lwjgl-3.3.5.jar"},{"component":"junit:junit:4.13.2","file":"@M2@/junit-4.13.2.jar"}]}}}`
	r := newFakeGradle(t, "", map[string]string{"project_lib.json": lib})
	g, err := r.resolve(t, ToolGradle, Conditions{})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	m := module(t, g, ":lib")
	if n := node(t, m, "junit:junit:jar:4.13.2"); n.Scope != "test" {
		t.Errorf("junit scope %q, want test", n.Scope)
	}
	// runtimeClasspath's version wins the project.
	if n := node(t, m, "org.lwjgl:lwjgl:jar:3.3.4"); n.Scope != "runtime" {
		t.Errorf("lwjgl scope %q, want runtime", n.Scope)
	}
	if len(m.Nodes) != 3 {
		t.Errorf("nodes %+v", m.Nodes)
	}
	// The other version is kept in the classpath's copy, beside the project's root.
	c := module(t, g, ":lib#integrationTestRuntimeClasspath")
	if c.CopyOf != ":lib" || c.Path != m.Path || c.Root != m.Root {
		t.Errorf("copy at %s rooted %s, want %s rooted %s", c.Path, c.Root, m.Path, m.Root)
	}
	if n := node(t, c, "org.lwjgl:lwjgl:jar:3.3.5"); n.Scope != "test" || n.File == nil {
		t.Errorf("copy lwjgl %+v, want test scope with its file", n)
	}
	if len(c.Nodes) != 2 || !reflect.DeepEqual(c.Edges, []Edge{{From: m.Root, To: "org.lwjgl:lwjgl:jar:3.3.5"}}) {
		t.Errorf("copy nodes %+v edges %+v", c.Nodes, c.Edges)
	}
	if len(g.Modules) != 5 {
		t.Errorf("modules %d, want the three projects and a copy each for :app and :lib", len(g.Modules))
	}

	// An earlier classpath holding the same version keeps it; the later one adds no copy.
	withTest := func(v string) string {
		return strings.TrimSuffix(lib, "}}") + strings.ReplaceAll(`,
"testRuntimeClasspath":{
"components":[{"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"org.lwjgl:lwjgl:V","id":{"group":"org.lwjgl","name":"lwjgl","version":"V"}}],
"edges":[{"from":"project :lib","to":"org.lwjgl:lwjgl:V"}],
"unresolved":[],
"files":[{"component":"org.lwjgl:lwjgl:V","file":"@M2@/lwjgl-V.jar"}]}}}`, "V", v)
	}
	r = newFakeGradle(t, "", map[string]string{"project_lib.json": withTest("3.3.5")})
	if g, err = r.resolve(t, ToolGradle, Conditions{}); err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	node(t, module(t, g, ":lib#testRuntimeClasspath"), "org.lwjgl:lwjgl:jar:3.3.5")
	for _, m := range g.Modules {
		if m.ID == ":lib#integrationTestRuntimeClasspath" {
			t.Errorf("integrationTestRuntimeClasspath repeats the copy: %+v", m.Nodes)
		}
	}

	// Two later classpaths at two other versions each keep their own.
	r = newFakeGradle(t, "", map[string]string{"project_lib.json": withTest("3.3.6")})
	if g, err = r.resolve(t, ToolGradle, Conditions{}); err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	node(t, module(t, g, ":lib#testRuntimeClasspath"), "org.lwjgl:lwjgl:jar:3.3.6")
	node(t, module(t, g, ":lib#integrationTestRuntimeClasspath"), "org.lwjgl:lwjgl:jar:3.3.5")
}

// Every other configuration that declares a dependency folds in at ScopeOther, so a package a
// distribution copies in from one is in the graph. One that fails to resolve is recorded as
// unlisted rather than failing the graph.
func TestGradleExtraConfigurations(t *testing.T) {
	lib := strings.Replace(gradleLib, `"version":"1.0.0",
"projects"`, `"version":"1.0.0","extra_classpaths":{
"agent":{
"components":[{"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"io.opentelemetry.javaagent:opentelemetry-javaagent:2.10.0","id":{"group":"io.opentelemetry.javaagent","name":"opentelemetry-javaagent","version":"2.10.0"}},{"key":"org.lwjgl:lwjgl:3.3.4","id":{"group":"org.lwjgl","name":"lwjgl","version":"3.3.4"}}],
"edges":[{"from":"project :lib","to":"io.opentelemetry.javaagent:opentelemetry-javaagent:2.10.0"},{"from":"project :lib","to":"org.lwjgl:lwjgl:3.3.4"}],
"unresolved":[],
"files":[{"component":"io.opentelemetry.javaagent:opentelemetry-javaagent:2.10.0","file":"@M2@/opentelemetry-javaagent-2.10.0.jar"},{"component":"org.lwjgl:lwjgl:3.3.4","file":"@M2@/lwjgl-3.3.4.jar"}]},
"distLibs":{
"components":[{"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"org.lwjgl:lwjgl:3.3.5","id":{"group":"org.lwjgl","name":"lwjgl","version":"3.3.5"}}],
"edges":[{"from":"project :lib","to":"org.lwjgl:lwjgl:3.3.5"}],
"unresolved":[],
"files":[{"component":"org.lwjgl:lwjgl:3.3.5","file":"@M2@/lwjgl-3.3.5.jar"}]},
"drivers":{"components":[{"key":"project :lib","id":{"project":":lib","build":":"}}],"edges":[],"unresolved":[{"requested":"org.postgresql:postgresql:42.7.4","failure":"Could not find org.postgresql:postgresql:42.7.4."}],"files":[]},
"lint":{"failure":"Cannot choose between the available variants"}},
"projects"`, 1)
	r := newFakeGradle(t, "", map[string]string{"project_lib.json": lib})
	writeFiles(t, r.m2, map[string]string{"opentelemetry-javaagent-2.10.0.jar": "o"})
	g, err := r.resolve(t, ToolGradle, Conditions{})
	if err != nil {
		t.Fatalf("resolve: %v", cause(err))
	}
	m := module(t, g, ":lib")
	if n := node(t, m, "io.opentelemetry.javaagent:opentelemetry-javaagent:jar:2.10.0"); n.Scope != ScopeOther || n.File == nil {
		t.Errorf("agent %+v, want scope other with its file", n)
	}
	// A classpath's node keeps its scope.
	if n := node(t, m, "org.lwjgl:lwjgl:jar:3.3.4"); n.Scope != "runtime" {
		t.Errorf("lwjgl scope %q, want runtime", n.Scope)
	}
	if !hasEdge(m, m.Root, "io.opentelemetry.javaagent:opentelemetry-javaagent:jar:2.10.0") {
		t.Errorf("edges %+v", m.Edges)
	}
	if !reflect.DeepEqual(m.Unlisted, []string{"gradle configuration drivers", "gradle configuration lint"}) {
		t.Errorf("unlisted %q", m.Unlisted)
	}
	if n := node(t, module(t, g, ":lib#distLibs"), "org.lwjgl:lwjgl:jar:3.3.5"); n.Scope != ScopeOther {
		t.Errorf("copy lwjgl scope %q, want other", n.Scope)
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file, r.dir, Conditions{}); err != nil {
		t.Fatalf("Load: %v", cause(err))
	}
}

func TestGradleProducerFailures(t *testing.T) {
	// The init script joins the failure's cause chain one message per line, as Gradle 9 words it.
	unresolved := strings.Replace(gradleLib, `"unresolved":[]`, `"unresolved":[{"requested":"corp:x:1","failure":"Could not resolve corp:x:1.\nCould not get resource 'https://maven.corp.example/repo/corp/x/1/x-1.pom'.\nCould not GET 'https://maven.corp.example/repo/corp/x/1/x-1.pom'.\nReceived status code 401 from server: Unauthorized"}]`, 1)
	otherRoot := func(s string) string { return strings.Replace(s, `"root_dir":"@ROOT@"`, `"root_dir":"@ROOT@/.."`, 1) }
	unresolvedPlain := strings.Replace(gradleLib, `"unresolved":[]`, `"unresolved":[{"requested":"corp:x:1","failure":"Could not find corp:x:1."}]`, 1)
	for _, tc := range []struct {
		name, fail string
		edit       map[string]string
		c          Conditions
		want       string
	}{
		{name: "profiles stated", c: Conditions{Profiles: []string{"p"}}, want: "tool_failed:conditions"},
		{name: "build fails", fail: "1", want: "tool_failed:graph"},
		{name: "jdk mismatch", c: Conditions{JDK: "17"}, want: "jdk_mismatch:17/21.0.12.1"},
		{name: "unresolved for credentials", edit: map[string]string{"project_lib.json": unresolved}, want: "credentials:https://maven.corp.example"},
		{name: "unresolved", edit: map[string]string{"project_lib.json": unresolvedPlain}, want: "tool_failed:resolve"},
		{name: "a project wrote nothing", edit: map[string]string{"project_lib.json": "{}"}, want: "tool_failed:graph"},
		{name: "unreadable output", edit: map[string]string{"project_lib.json": "{"}, want: "tool_failed:graph"},
		{name: "edge to an unlisted component", edit: map[string]string{"project_lib.json": strings.Replace(gradleLib, `"to":"org.lwjgl:lwjgl:3.3.4"`, `"to":"x:y:1"`, 1)}, want: "tool_failed:graph"},
		{name: "file dependency", edit: map[string]string{"project_lib.json": strings.Replace(gradleLib, `"files":[`, `"files":[{"component":"lib/local.jar","file":"@ROOT@/lib/local.jar"},`, 1)}, want: "tool_failed:graph"},
		{name: "two files at one node", edit: map[string]string{"project_lib.json": strings.Replace(gradleLib, `"files":[`, `"files":[{"component":"org.lwjgl:lwjgl:3.3.4","file":"@M2@/lwjgl-3.3.4-natives-linux.jar","name":"lwjgl-3.3.4.jar"},`, 1)}, want: "tool_failed:graph"},
		{name: "build rooted elsewhere", edit: map[string]string{"project_.json": otherRoot(gradleRoot), "project_app.json": otherRoot(gradleApp), "project_lib.json": otherRoot(gradleLib)}, want: "tool_failed:graph"},
		{name: "unresolved on the test classpath", edit: map[string]string{"project_app.json": strings.Replace(gradleApp, `"unresolved":[],
"files":[{"component":"org.lwjgl:lwjgl:3.3.5"`, `"unresolved":[{"requested":"corp:x:1","failure":"Could not find corp:x:1."}],
"files":[{"component":"org.lwjgl:lwjgl:3.3.5"`, 1)}, want: "tool_failed:resolve"},
		{name: "file dependency on the compile classpath", edit: map[string]string{"project_app.json": strings.Replace(gradleApp, `"files":[{"component":"project :lib"`, `"files":[{"component":"lib/local.jar","file":"@ROOT@/lib/local.jar"},{"component":"project :lib"`, 1)}, want: "tool_failed:graph"},
		{name: "other runtime classpath not written", edit: map[string]string{"project_lib.json": strings.Replace(gradleLib, `"version":"1.0.0",
"projects"`, `"version":"1.0.0","other_runtime_classpaths":["integrationTestRuntimeClasspath","runtimeClasspath"],
"projects"`, 1)}, want: "tool_failed:graph"},
		{name: "other runtime classpaths only", edit: map[string]string{"project_.json": strings.Replace(gradleRoot, `"version":"unspecified",`, `"version":"unspecified","other_runtime_classpaths":["debugRuntimeClasspath","testRuntimeClasspath"],`, 1)}, want: "tool_failed:graph"},
		{name: "included build", edit: map[string]string{"project_lib.json": strings.Replace(gradleLib, `"key":"project :lib","id":{"project":":lib","build":":"}},`, `"key":"project :lib","id":{"project":":lib","build":":"}},{"key":"project :inc:x","id":{"project":":x","build":":inc"}},`, 1)}, want: "tool_failed:graph"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFakeGradle(t, tc.fail, tc.edit)
			_, err := r.resolve(t, ToolGradle, tc.c)
			if got := cause(err); got != tc.want {
				t.Fatalf("cause %q, want %q", got, tc.want)
			}
		})
	}
}
