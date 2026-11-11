package javaanalysis

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reactorRoot replaces the fixture's POM with a code-free aggregator, com.acme:parent:1.0.0.
func (a *appFixture) reactorRoot() {
	a.t.Helper()
	writeFileT(a.t, filepath.Join(a.build, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version><packaging>pom</packaging>
</project>`)
}

// appModule writes a reactor application module at dir: a POM naming com.acme.<pkg>.Main as the
// jar main class, that class's source, and its class output with main running code.
func (a *appFixture) appModule(dir, pkg string, code func(b *cpb) []byte) {
	a.t.Helper()
	writeFileT(a.t, filepath.Join(a.build, dir, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
  <artifactId>`+dir+`</artifactId>
  <build><plugins><plugin><artifactId>maven-jar-plugin</artifactId>
    <configuration><archive><manifest><mainClass>com.acme.`+pkg+`.Main</mainClass></manifest></archive></configuration>
  </plugin></plugins></build>
</project>`)
	a.source(dir+"/src/main/java/com/acme/"+pkg+"/Main.java", "package com.acme."+pkg+";\npublic class Main {\n    public static void main(String[] args) {}\n}\n")
	a.class(dir+"/target/classes", "com/acme/"+pkg+"/Main", mainCalling(code))
}

// libModule writes a reactor library module at dir: a POM applying no plugin, and
// com.acme.lib.Lib, whose static run() runs code.
func (a *appFixture) libModule(dir string, code func(b *cpb) []byte) {
	a.t.Helper()
	writeFileT(a.t, filepath.Join(a.build, dir, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
  <artifactId>`+dir+`</artifactId>
</project>`)
	a.source(dir+"/src/main/java/com/acme/lib/Lib.java", "package com.acme.lib;\npublic class Lib {\n    public static void run() {}\n}\n")
	a.class(dir+"/target/classes", "com/acme/lib/Lib", func(b *cpb) []xmethod {
		return []xmethod{{"run", "()V", accPublicStatic, code(b)}}
	})
}

// sibling adds of's own output to m's resolved tree in scope, as Maven lists a reactor sibling.
func sibling(m buildgraph.Module, of buildgraph.Module, scope string) buildgraph.Module {
	name := strings.TrimPrefix(of.ID, "com.example:")
	n := buildgraph.Node{ID: of.Root, Group: "com.example", Artifact: name, Version: "1", Type: "jar", Scope: scope}
	m.Nodes = append(m.Nodes, n)
	m.Edges = append(m.Edges, buildgraph.Edge{From: m.Root, To: n.ID})
	return m
}

// listedGraph is a Maven reactor graph that lists each module's runtime classpath whole: every
// module's JDK toolchains are known, the run's JDK is 21, and the class outputs and local
// repository are the build's outputs, so they hold no unlisted archive.
func listedGraph(t *testing.T, modules ...buildgraph.Module) Option {
	t.Helper()
	outputs := []string{".m2/repository"}
	for i := range modules {
		modules[i].JDKToolchainsKnown = true
		outputs = append(outputs, filepath.ToSlash(filepath.Join(modules[i].Path, "target")))
	}
	return writeGraph(t, buildgraph.Graph{
		Schema:     buildgraph.Schema,
		Tool:       buildgraph.Tool{Name: "maven", Version: "test"},
		JVM:        buildgraph.JVM{Version: "21.0.4"},
		Conditions: buildgraph.Conditions{JDK: "21.0.4"},
		Subject:    buildgraph.Subject{Outputs: outputs},
		Modules:    modules,
		Complete:   true,
	})
}

var callSharedLib = callStatic("com/acme/lib/Lib", "run")

func traceStart(pkg string) string { return mainTrace("com/acme/" + pkg + "/Main") }

func mainTrace(owner string) string { return "jvmref " + owner + "#main" + mainDescriptor }

// generator adds com.acme.lib.Generator, whose main runs code, to the library module at dir.
func (a *appFixture) generator(dir string, code func(b *cpb) []byte) {
	a.t.Helper()
	a.source(dir+"/src/main/java/com/acme/lib/Generator.java", "package com.acme.lib;\npublic class Generator {\n    public static void main(String[] args) {}\n}\n")
	a.class(dir+"/target/classes", "com/acme/lib/Generator", mainCalling(code))
}

// generatorPOM gives the library module at dir a POM naming com.acme.lib.Generator as its exec main.
func (a *appFixture) generatorPOM(dir string) {
	a.t.Helper()
	writeFileT(a.t, filepath.Join(a.build, dir, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
  <artifactId>`+dir+`</artifactId>
  <build><plugins><plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId>
    <configuration><mainClass>com.acme.lib.Generator</mainClass></configuration>
  </plugin></plugins></build>
</project>`)
}

// A reactor of two apps sharing a library is searched one app at a time, each over its own
// classes, its siblings' classes and the JARs its own module resolved. A library that names its
// own launch entry is a unit of its own, searched on its own classpath.
func TestUnitsReach_SearchedPerUnit(t *testing.T) {
	type want struct {
		path     string // the SCIP the one path's trace starts at, "" for no path
		searched bool
	}
	cases := map[string]struct {
		one, two         func(b *cpb) []byte // each app's main
		lib              func(b *cpb) []byte
		oneNetkit, twoNk bool
		twoUnlisted      bool                // two resolves a dependency whose JAR is not on disk
		libExtra         func(a *appFixture) // more in the library module
		want             want
	}{
		// Only app one resolves netkit; the path through the shared library is app one's.
		"path in the unit carrying the sink JAR": {one: callSharedLib, two: justReturn, lib: callFetch, oneNetkit: true, want: want{path: traceStart("one")}},
		// App two calls the sink but never resolved netkit. Code compiled against UrlFetcher had it
		// on some path two's listed tree does not show, so two's search withholds.
		"no cross-unit linking": {one: justReturn, two: callFetch, lib: justReturn, oneNetkit: true},
		"every unit clean":      {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{searched: true}},
		// App two's search is undetermined, so the build is not Searched though app one is clean.
		"one unclean unit withholds Searched": {one: justReturn, two: callUnloaded, lib: justReturn, oneNetkit: true, twoNk: true},
		// Absence counts only after a clean search: two's call into an unloaded class withholds.
		"an unclean unit without the sink JAR withholds": {one: callSharedLib, two: callUnloaded, lib: justReturn, oneNetkit: true},
		// App two's runtime classpath is fully listed and holds no netkit: it cannot carry the sink.
		"a listed unit without the sink JAR is searched": {one: callSharedLib, two: callSharedLib, lib: justReturn, oneNetkit: true, want: want{searched: true}},
		// A library class no root reaches names UrlFetcher: a JAR outside two's tree supplied it
		// at compile time and may at run time, so two's absence proves nothing.
		"a loaded class naming the absent sink withholds": {one: callSharedLib, two: callSharedLib, lib: justReturn, oneNetkit: true,
			libExtra: func(a *appFixture) {
				a.class("lib/target/classes", "com/acme/lib/Unused", func(b *cpb) []xmethod {
					return []xmethod{{"run", "()V", accPublicStatic, callFetch(b)}}
				})
			}},
		// A relocated copy of the sink's class (a shaded package) is the sink's code under another name.
		"a loaded class sharing the sink's simple name withholds": {one: callSharedLib, two: callSharedLib, lib: justReturn, oneNetkit: true,
			libExtra: func(a *appFixture) {
				a.class("lib/target/classes", "com/acme/lib/shaded/UrlFetcher", func(b *cpb) []xmethod {
					return []xmethod{{"fetch", fetchDesc, accPublic, ret}}
				})
			}},
		// Kotlin inline functions copy a callee's body without naming its class.
		"loaded Kotlin withholds an absent sink": {one: callSharedLib, two: callSharedLib, lib: justReturn, oneNetkit: true,
			libExtra: func(a *appFixture) {
				a.classA("lib/target/classes", "com/acme/lib/Inline", "java/lang/Object", nil, 0x0021, []string{"Lkotlin/Metadata;"},
					func(*cpb) []xmethod { return nil })
			}},
		// App two lists a dependency it has no JAR for, so netkit may be on its classpath unseen.
		"an unlisted unit without the sink JAR withholds": {one: callSharedLib, two: callSharedLib, lib: justReturn, oneNetkit: true, twoUnlisted: true},
		// A library's code generator main is no root of the apps that load the library.
		"a sibling's main is not a root": {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{searched: true},
			libExtra: func(a *appFixture) { a.generator("lib", callFetch) }},
		// A library naming its own launch entry ships on its own classpath, which carries netkit.
		"a sibling's POM main is its own unit, clean": {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{searched: true},
			libExtra: func(a *appFixture) { a.generatorPOM("lib"); a.generator("lib", justReturn) }},
		"a sibling's POM main is its own unit, reaching": {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{path: mainTrace("com/acme/lib/Generator")},
			libExtra: func(a *appFixture) { a.generatorPOM("lib"); a.generator("lib", callFetch) }},
		// The unit's own POM names a library class as its main: that main is the unit's root.
		"the unit's POM naming a sibling's main": {one: justReturn, two: justReturn, lib: justReturn, oneNetkit: true, twoNk: true, want: want{path: mainTrace("com/acme/lib/Generator")},
			libExtra: func(a *appFixture) { a.generatorPOM("one"); a.generator("lib", callFetch) }},
		"a sibling's manifest is its own unit, reaching": {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{path: mainTrace("com/acme/lib/Generator")},
			libExtra: func(a *appFixture) {
				writeFileT(a.t, filepath.Join(a.build, "lib", "target", "classes", "META-INF", "MANIFEST.MF"), "Manifest-Version: 1.0\nMain-Class: com.acme.lib.Generator\n")
				a.generator("lib", callFetch)
			}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.reactorRoot()
			a.appModule("one", "one", c.one)
			a.appModule("two", "two", c.two)
			a.libModule("lib", c.lib)
			if c.libExtra != nil {
				c.libExtra(a)
			}
			var oneDeps, twoDeps []graphDep
			if c.oneNetkit {
				oneDeps = append(oneDeps, netkitDep(a.build))
			}
			if c.twoNk {
				twoDeps = append(twoDeps, netkitDep(a.build))
			}
			if c.twoUnlisted {
				twoDeps = append(twoDeps, graphDep{group: "com.other", artifact: "gone", version: "1", jar: filepath.Join(a.build, "gone-1.jar")})
			}
			lib := testModule(t, "lib", "lib", netkitDep(a.build))
			one := sibling(testModule(t, "one", "one", oneDeps...), lib, "compile")
			two := sibling(testModule(t, "two", "two", twoDeps...), lib, "compile")
			a.graph = listedGraph(t, testModule(t, ".", "parent"), one, two, lib)

			res := a.reach(netkitSinkID)
			if hasReason(res.Partiality, reasonMultipleProjectsUnsupported) {
				t.Fatalf("a placeable reactor kept multiple_projects_unsupported: %+v", res.Partiality)
			}
			if c.want.path == "" && len(res.Paths) != 0 {
				t.Errorf("want no path, got %+v", res.Paths)
			}
			if c.want.path != "" {
				if len(res.Paths) != 1 {
					t.Fatalf("want one path, got %+v (partiality %+v)", res.Paths, res.Partiality)
				}
				if got := res.Paths[0].Trace[0].SCIP; got != c.want.path {
					t.Errorf("trace starts at %q, want %q", got, c.want.path)
				}
			}
			if got := len(res.Searched) == 1 && res.Searched[0] == netkitSinkID; got != c.want.searched {
				t.Errorf("Searched = %v, want searched %v (partiality %+v)", res.Searched, c.want.searched, res.Partiality)
			}
		})
	}
}

// libPOM is the library module's POM with an optional netkit dependency, packaging and build
// after its artifactId.
func libPOM(packaging, build string) string {
	if packaging != "" {
		packaging = "<packaging>" + packaging + "</packaging>"
	}
	return `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
  <artifactId>lib</artifactId>` + packaging + `
  <dependencies><dependency><groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version><optional>true</optional></dependency></dependencies>
  ` + build + `
</project>`
}

// plugins is a <build> applying one plugin with an execution of goal.
func plugins(plugin, goal string) string {
	return `<build><plugins><plugin>` + plugin + `
    <executions><execution><phase>package</phase><goals><goal>` + goal + `</goal></goals></execution></executions>
  </plugin></plugins></build>`
}

// callDriverManager is aconst_null; invokestatic DriverManager.getConnection(String); pop;
// return: a JDBC lookup, which loads whatever driver the classpath registers.
func callDriverManager(b *cpb) []byte {
	idx := b.mref("java/sql/DriverManager", "getConnection", "(Ljava/lang/String;)Ljava/sql/Connection;")
	return append([]byte{0x01, 0xB8}, append(be2(idx), 0x57, 0xB1)...)
}

// A reactor sibling that repackages its dependencies publishes an artifact carrying classes its
// class output does not, the optional netkit here: a unit that loads it runs those classes,
// however it reaches them, so its empty search is not Searched. App two loads lib, whose tree
// does not list netkit; its route to the sink is lib naming it at compile time, or a JDBC lookup
// that loads whatever driver the shaded jar registers, which no class names.
func TestUnitsReach_RepackagingSiblingWithholds(t *testing.T) {
	cases := map[string]struct {
		lib, two func(b *cpb) []byte
		libPOM   string
		root     string // more of the reactor root POM
		searched bool
	}{
		"a shaded sibling naming the sink":       {lib: callFetch, two: justReturn, libPOM: libPOM("", plugins(shadePluginXML, "shade"))},
		"a JDBC lookup through a shaded sibling": {lib: justReturn, two: callDriverManager, libPOM: libPOM("", plugins(shadePluginXML, "shade"))},
		"an assembly":                            {lib: justReturn, two: callDriverManager, libPOM: libPOM("", plugins(`<artifactId>maven-assembly-plugin</artifactId>`, "single"))},
		"a Boot repackage":                       {lib: justReturn, two: callDriverManager, libPOM: libPOM("", plugins(bootPluginXML, "repackage"))},
		"dependencies unpacked into the output":  {lib: justReturn, two: callDriverManager, libPOM: libPOM("", plugins(`<artifactId>maven-dependency-plugin</artifactId>`, "unpack-dependencies"))},
		"a bundle":                               {lib: justReturn, two: callDriverManager, libPOM: libPOM("bundle", "")},
		"a profile that shades":                  {lib: justReturn, two: callDriverManager, libPOM: libPOM("", "<profiles><profile><id>fat</id>"+plugins(shadePluginXML, "shade")+"</profile></profiles>")},
		"shading inherited from the root":        {lib: justReturn, two: callDriverManager, libPOM: libPOM("", ""), root: plugins(shadePluginXML, "shade")},
		"a parent that cannot be read": {lib: justReturn, two: callDriverManager,
			libPOM: strings.Replace(libPOM("", ""), "<artifactId>parent</artifactId>", "<artifactId>unknown</artifactId>", 1)},
		// Shading managed for children that do not apply it builds nothing.
		"shading managed, not applied": {lib: justReturn, two: callDriverManager, libPOM: libPOM("", ""),
			root: `<build><pluginManagement><plugins><plugin>` + shadePluginXML + `</plugin></plugins></pluginManagement></build>`, searched: true},
		"a plain library": {lib: justReturn, two: callDriverManager, libPOM: libPOM("", ""), searched: true},
	}
	for name, c := range cases {
		for _, listed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/listed=%v", name, listed), func(t *testing.T) {
				a := newApp(t, "", false)
				a.reactorRoot()
				if c.root != "" {
					writeFileT(t, filepath.Join(a.build, "pom.xml"), rootPOM(c.root))
				}
				a.appModule("one", "one", callSharedLib)
				a.appModule("two", "two", c.two)
				a.libModule("lib", c.lib)
				writeFileT(t, filepath.Join(a.build, "lib", "pom.xml"), c.libPOM)
				data, err := os.ReadFile(netkitJarPath(a.build))
				if err != nil {
					t.Fatal(err)
				}
				writeFileT(t, filepath.Join(a.build, "lib", "target", "lib-1.jar"), string(data))
				nk := netkitDep(a.build)
				nk.scope = "compile"
				lib := testModule(t, "lib", "lib", nk)
				mods := []buildgraph.Module{testModule(t, ".", "parent"),
					sibling(testModule(t, "one", "one", netkitDep(a.build)), lib, "compile"), sibling(testModule(t, "two", "two"), lib, "compile"), lib}
				if listed {
					a.graph = listedGraph(t, mods...)
				} else {
					a.graph = graphOption(t, "maven", mods...)
				}
				res := a.reach(netkitSinkID)
				// Unlisted, no sink is absent: two, whose classpath lacks the sink, never clears it.
				want := c.searched && listed
				if got := len(res.Searched) != 0; got != want {
					t.Errorf("Searched = %v, want searched %v (paths %d, partiality %+v)", res.Searched, want, len(res.Paths), res.Partiality)
				}
			})
		}
	}
}

// Code the plan cannot place as a unit or a sibling a unit loads leaves the whole build with the
// run-wide multiple_projects_unsupported; why names the placement that failed.
func TestUnitsReach_UnplacedCodeFailsClosed(t *testing.T) {
	cases := map[string]struct {
		setup func(a *appFixture) Option
		why   string
	}{
		"code module only a test dependency": {func(a *appFixture) Option {
			a.libModule("lib", justReturn)
			lib := testModule(t, "lib", "lib")
			one := sibling(testModule(t, "one", "one", netkitDep(a.build)), lib, "test")
			return graphOption(t, "maven", testModule(t, ".", "parent"), one, testModule(t, "two", "two"), lib)
		}, "lib has code no application unit loads"},
		"main source under no module with code": {func(a *appFixture) Option {
			a.source("tools/src/main/java/com/acme/Tool.java", "package com.acme;\npublic class Tool {}\n")
			return graphOption(t, "maven", testModule(t, ".", "parent"), testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "two"))
		}, "tools/src/main/java/com/acme/Tool.java is in no module the units load"},
		"class output under no module": {func(a *appFixture) Option {
			a.class("tools/target/classes", "com/acme/Tool", func(*cpb) []xmethod { return nil })
			return graphOption(t, "maven", testModule(t, ".", "parent"), testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "two"))
		}, "class output in tools is in no module the units load"},
		"reactor test-jar on the runtime classpath": {func(a *appFixture) Option {
			a.libModule("lib", justReturn)
			lib := testModule(t, "lib", "lib")
			one := testModule(t, "one", "one", netkitDep(a.build), graphDep{group: "com.example", artifact: "lib", version: "1", classifier: "tests", jar: netkitJarPath(a.build)})
			return graphOption(t, "maven", testModule(t, ".", "parent"), sibling(one, lib, "compile"), testModule(t, "two", "two"), lib)
		}, "one loads reactor artifact com.example:lib:jar:tests:1, not a module's own output"},
		// Two libraries loading each other, neither naming a launch entry: neither is outermost.
		"modules loading each other": {func(a *appFixture) Option {
			a.libModule("lib", justReturn)
			a.libModule("lib2", justReturn)
			lib, lib2 := testModule(t, "lib", "lib", netkitDep(a.build)), testModule(t, "lib2", "lib2")
			return graphOption(t, "maven", testModule(t, ".", "parent"), sibling(lib, lib2, "compile"), sibling(lib2, lib, "compile"))
		}, "no module with code is an application unit"},
		"two modules with one root": {func(a *appFixture) Option {
			return graphOption(t, "maven", testModule(t, ".", "parent"), testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "one"))
		}, "two modules with root com.example:one:jar:1"},
		"two modules at one path": {func(a *appFixture) Option {
			return graphOption(t, "maven", testModule(t, ".", "parent"), testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "two"), testModule(t, "one", "uno"))
		}, "two modules at one"},
		"classpath copy": {func(a *appFixture) Option {
			one := testModule(t, "one", "one", netkitDep(a.build))
			return graphOption(t, "maven", testModule(t, ".", "parent"), one, classpathCopy(t, one, "runtimeClasspath"), testModule(t, "two", "two"))
		}, "classpath copy com.example:one#runtimeClasspath"},
		"not a Maven graph": {func(a *appFixture) Option {
			return graphOption(t, "gradle", testModule(t, ".", "parent"), testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "two"))
		}, "not a Maven reactor (gradle)"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.reactorRoot()
			a.appModule("one", "one", justReturn)
			a.appModule("two", "two", justReturn)
			a.graph = c.setup(a)
			if plan, multi, why := reactorUnits(a.build, a.graph); plan != nil || !multi || !strings.HasSuffix(why, ": "+c.why) {
				t.Errorf("reactorUnits = %v, %v, %q; want refused with %q", plan, multi, why, c.why)
			}
			res := a.reach(netkitSinkID)
			if len(res.Searched) != 0 {
				t.Errorf("unplaced reactor listed Searched: %v", res.Searched)
			}
			if !hasReason(res.Partiality, reasonMultipleProjectsUnsupported) {
				t.Errorf("missing run-wide multiple_projects_unsupported: %+v", res.Partiality)
			}
		})
	}
}

// A unit's parent POM is read from the checkout at its relativePath when its coordinate matches
// the one the unit names; otherwise from the Maven cache as before. Outside a unit the checkout
// is never read.
func TestPomChain_CheckoutParent(t *testing.T) {
	const childPOM = `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version>%s</parent>
  <artifactId>one</artifactId></project>`
	cases := map[string]struct {
		parentGAV    string // the checkout parent's coordinate
		relativePath string // the child's <relativePath> element, verbatim
		unit         bool   // whether the reader reads a reactor unit
		cached       bool   // whether the Maven cache holds com.acme:parent:1.0.0
		complete     bool
		fromCheckout bool
	}{
		"matching coordinate":           {parentGAV: "com.acme:parent:1.0.0", unit: true, complete: true, fromCheckout: true},
		"explicit relativePath":         {parentGAV: "com.acme:parent:1.0.0", relativePath: "<relativePath>../pom.xml</relativePath>", unit: true, complete: true, fromCheckout: true},
		"relativePath names a dir":      {parentGAV: "com.acme:parent:1.0.0", relativePath: "<relativePath>..</relativePath>", unit: true, complete: true, fromCheckout: true},
		"version mismatch":              {parentGAV: "com.acme:parent:2.0.0", unit: true},
		"artifact mismatch":             {parentGAV: "com.acme:other:1.0.0", unit: true},
		"mismatch falls back to cache":  {parentGAV: "com.acme:parent:2.0.0", unit: true, cached: true, complete: true},
		"empty relativePath":            {parentGAV: "com.acme:parent:1.0.0", relativePath: "<relativePath/>", unit: true},
		"relativePath out of checkout":  {parentGAV: "com.acme:parent:1.0.0", relativePath: "<relativePath>../../pom.xml</relativePath>", unit: true},
		"not a unit":                    {parentGAV: "com.acme:parent:1.0.0"},
		"not a unit, cached":            {parentGAV: "com.acme:parent:1.0.0", cached: true, complete: true},
		"checkout preferred over cache": {parentGAV: "com.acme:parent:1.0.0", unit: true, cached: true, complete: true, fromCheckout: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			outer := t.TempDir()
			build := filepath.Join(outer, "build")
			gav := strings.Split(c.parentGAV, ":")
			writeFileT(t, filepath.Join(build, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>`+gav[0]+`</groupId><artifactId>`+gav[1]+`</artifactId><version>`+gav[2]+`</version><packaging>pom</packaging></project>`)
			// A parent outside the checkout, where "../../pom.xml" from the module would land.
			writeFileT(t, filepath.Join(outer, "pom.xml"), parentPOM(""))
			if c.cached {
				writeFileT(t, filepath.Join(build, ".m2", "repository", "com", "acme", "parent", "1.0.0", "parent-1.0.0.pom"), parentPOM(""))
			}
			child := filepath.Join(build, "one", "pom.xml")
			writeFileT(t, child, strings.Replace(childPOM, "%s", c.relativePath, 1))
			pom, ok := parseMavenPOM(child)
			if !ok {
				t.Fatal("child POM unreadable")
			}
			r := &entryReader{reasons: map[string]bool{}, named: map[string]bool{}, propKeys: map[string]bool{}, cache: newMavenCache(build)}
			if c.unit {
				r.checkout = build
			}
			chain, files, complete := r.pomChain(pom, child)
			if complete != c.complete {
				t.Fatalf("complete = %v, want %v (files %v)", complete, c.complete, files)
			}
			if got := len(files) == 2 && files[1] == filepath.Join(build, "pom.xml"); got != c.fromCheckout {
				t.Errorf("parent from checkout = %v, want %v (files %v)", got, c.fromCheckout, files)
			}
			if complete && len(chain) != 2 {
				t.Errorf("chain = %d POMs, want 2", len(chain))
			}
		})
	}
}

// parseMavenPOM keeps whether the parent names a relativePath, and what, so an empty element
// (no checkout lookup) differs from an absent one (the default).
func TestParseMavenPOM_RelativePath(t *testing.T) {
	for name, c := range map[string]struct {
		element string
		want    *string
	}{
		"absent":   {"", nil},
		"empty":    {"<relativePath/>", ptr("")},
		"explicit": {"<relativePath> ../parent/pom.xml </relativePath>", ptr("../parent/pom.xml")},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pom.xml")
			if err := os.WriteFile(path, []byte(`<project><parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version>`+c.element+`</parent><artifactId>c</artifactId></project>`), 0o644); err != nil {
				t.Fatal(err)
			}
			pom, ok := parseMavenPOM(path)
			if !ok {
				t.Fatal("unreadable")
			}
			got := pom.Parent.RelativePath
			if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Errorf("RelativePath = %v, want %v", got, c.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// A graph with one module, and a build with no graph, never enter unit mode.
func TestReactorUnits_SingleModuleUnchanged(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	for name, opt := range map[string]Option{
		"one module": graphOption(t, "maven", testModule(t, ".", "app", netkitDep(a.build))),
		"no graph":   func(*analyzer) {},
	} {
		t.Run(name, func(t *testing.T) {
			plan, multi, why := reactorUnits(a.build, opt)
			if plan != nil || multi || why != "" {
				t.Errorf("reactorUnits = %+v, %v, %q; want no plan", plan, multi, why)
			}
		})
	}
	res := a.reach(netkitSinkID)
	if len(res.Searched) != 1 || res.Searched[0] != netkitSinkID || hasReason(res.Partiality, reasonMultipleProjectsUnsupported) {
		t.Errorf("single module: Searched %v, partiality %+v", res.Searched, res.Partiality)
	}
}

// Searched-and-absent is a unit-mode answer: a single module whose listed classpath holds no
// sink class keeps the single-module answer, which does not list the sink.
func TestSingleModule_AbsentSinkUnchanged(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.graph = listedGraph(t, testModule(t, ".", "app"))
	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Errorf("single module listed an absent sink Searched: %v (partiality %+v)", res.Searched, res.Partiality)
	}
}

// writeNetkitAt writes com.evil:netkit:<ver> holding UrlFetcher.fetch, the sink, and Api.safe,
// which calls the sink when safeCalls, and returns the JAR's path.
func (a *appFixture) writeNetkitAt(ver string, safeCalls bool) string {
	a.t.Helper()
	b := &cpb{}
	uf := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}})
	b2 := &cpb{}
	body := ret
	if safeCalls {
		body = callFetch(b2)
	}
	api := emitClassX(b2, "com/evil/netkit/Api", "java/lang/Object", 0x0021, []xmethod{{"safe", "()V", accPublicStatic, body}})
	p := filepath.Join(a.build, ".m2", "repository", "com", "evil", "netkit", ver, "netkit-"+ver+".jar")
	writeJarEntries(a.t, p, map[string][]byte{"com/evil/netkit/UrlFetcher.class": uf, "com/evil/netkit/Api.class": api})
	return p
}

func unitPaths(plan *reactorPlan) []string {
	var out []string
	if plan != nil {
		for _, u := range plan.units {
			out = append(out, u.path)
		}
	}
	return out
}

// An application another application loads as a library still ships on its own: it is a unit,
// searched on the versions its own module resolved, not only on those the loading module's
// mediation picked.
func TestUnitsReach_DeployableSiblingOwnClasspath(t *testing.T) {
	cases := map[string]struct {
		oneVer, twoVer       string
		oneCalls, twoCalls   bool // whether that version's Api.safe calls the sink
		wantPath, wantSearch bool
	}{
		// one ships netkit 1.0.0, whose Api.safe reaches the sink; two's 2.0.0 does not.
		"one's own version reaches": {oneVer: "1.0.0", twoVer: "2.0.0", oneCalls: true, wantPath: true},
		"neither version reaches":   {oneVer: "1.0.0", twoVer: "2.0.0", wantSearch: true},
		"one version, clean":        {oneVer: "2.0.0", twoVer: "2.0.0", wantSearch: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.reactorRoot()
			j1 := a.writeNetkitAt(c.oneVer, c.oneCalls)
			j2 := j1
			if c.twoVer != c.oneVer {
				j2 = a.writeNetkitAt(c.twoVer, c.twoCalls)
			}
			a.appModule("one", "one", callStatic("com/evil/netkit/Api", "safe"))
			a.appModule("two", "two", justReturn)
			one := testModule(t, "one", "one", graphDep{group: "com.evil", artifact: "netkit", version: c.oneVer, jar: j1})
			two := sibling(testModule(t, "two", "two", graphDep{group: "com.evil", artifact: "netkit", version: c.twoVer, jar: j2}), one, "compile")
			a.graph = listedGraph(t, testModule(t, ".", "parent"), one, two)

			plan, multi, why := reactorUnits(a.build, a.graph)
			if got := unitPaths(plan); multi || strings.Join(got, " ") != "one two" {
				t.Fatalf("units = %v (refused %v: %q), want [one two]", got, multi, why)
			}
			res := a.reach(netkitSinkID)
			if c.wantPath != (len(res.Paths) == 1) || len(res.Paths) > 1 {
				t.Fatalf("paths = %+v, want a path %v", res.Paths, c.wantPath)
			}
			if c.wantPath {
				if got := res.Paths[0].Trace[0].SCIP; got != traceStart("one") {
					t.Errorf("trace starts at %q, want %q", got, traceStart("one"))
				}
			}
			if got := len(res.Searched) == 1; got != c.wantSearch {
				t.Errorf("Searched = %v, want searched %v (partiality %+v)", res.Searched, c.wantSearch, res.Partiality)
			}
		})
	}
}

// A module another module loads is a unit too when it carries any launch evidence of its own,
// resolved or not, or when what it carries cannot be read. A Boot plugin only managed, never
// applied, is no evidence.
func TestPlanUnits_LaunchEvidencePromotes(t *testing.T) {
	const parentGAV = `<groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version>`
	pom := func(packaging, build string) string {
		return `<project><modelVersion>4.0.0</modelVersion>
  <parent>` + parentGAV + `</parent>
  <artifactId>one</artifactId>` + packaging + build + `
</project>`
	}
	const boot = `<build><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build>`
	rootPOM := func(body string) string {
		return `<project><modelVersion>4.0.0</modelVersion>
  ` + parentGAV + `<packaging>pom</packaging>` + body + `
</project>`
	}
	cases := map[string]struct {
		setup    func(a *appFixture)
		promoted bool
	}{
		"no launch evidence":         {func(a *appFixture) { a.oneFile("pom.xml", pom("", "")) }, false},
		"Boot plugin in its own POM": {func(a *appFixture) { a.oneFile("pom.xml", pom("", boot)) }, true},
		"Boot plugin from the checkout parent": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			writeFileT(t, filepath.Join(a.build, "pom.xml"), rootPOM(boot))
		}, true},
		// mall's shape: the aggregator manages the Boot plugin; only the apps apply it.
		"Boot plugin only managed by the parent": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			writeFileT(t, filepath.Join(a.build, "pom.xml"), rootPOM(`<build><pluginManagement><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></pluginManagement></build>`))
		}, false},
		"war packaging": {func(a *appFixture) { a.oneFile("pom.xml", pom("<packaging>war</packaging>", "")) }, true},
		"ear packaging": {func(a *appFixture) { a.oneFile("pom.xml", pom("<packaging>ear</packaging>", "")) }, true},
		// Every packaging but a plain jar ships on its own, a value a property supplies included.
		"bundle packaging":       {func(a *appFixture) { a.oneFile("pom.xml", pom("<packaging>bundle</packaging>", "")) }, true},
		"hpi packaging":          {func(a *appFixture) { a.oneFile("pom.xml", pom("<packaging>hpi</packaging>", "")) }, true},
		"maven-plugin packaging": {func(a *appFixture) { a.oneFile("pom.xml", pom("<packaging>maven-plugin</packaging>", "")) }, true},
		"property packaging":     {func(a *appFixture) { a.oneFile("pom.xml", pom("<packaging>${packaging.type}</packaging>", "")) }, true},
		"jar packaging":          {func(a *appFixture) { a.oneFile("pom.xml", pom("<packaging>jar</packaging>", "")) }, false},
		"an unresolved mainClass": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", `<build><plugins><plugin><artifactId>maven-jar-plugin</artifactId><configuration><archive><manifest><mainClass>${start.class}</mainClass></manifest></archive></configuration></plugin></plugins></build>`))
		}, true},
		"a POM naming a manifest file": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", `<build><plugins><plugin><artifactId>maven-jar-plugin</artifactId><configuration><archive><manifestFile>src/main/MANIFEST.MF</manifestFile></archive></configuration></plugin></plugins></build>`))
		}, true},
		"a parent profile naming a main": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			writeFileT(t, filepath.Join(a.build, "pom.xml"), rootPOM(`<profiles><profile><id>tool</id><build><plugins><plugin><artifactId>exec-maven-plugin</artifactId><configuration><mainClass>com.acme.one.Core</mainClass></configuration></plugin></plugins></build></profile></profiles>`))
		}, true},
		// The profile wires the Boot start class the parent itself never sets.
		"a parent profile wiring the Boot start class": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			writeFileT(t, filepath.Join(a.build, "pom.xml"), rootPOM(`<profiles><profile><id>jar</id><build><plugins><plugin><artifactId>maven-jar-plugin</artifactId><configuration><archive><manifest><mainClass>${start-class}</mainClass></manifest></archive></configuration></plugin></plugins></build></profile></profiles>`))
		}, true},
		"a parent not read": {func(a *appFixture) {
			a.oneFile("pom.xml", strings.Replace(pom("", ""), "<artifactId>parent</artifactId>", "<artifactId>absent-parent</artifactId>", 1))
		}, true},
		"an unreadable POM": {func(a *appFixture) { a.oneFile("pom.xml", "<project><parent>") }, true},
		"a source manifest": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			a.oneFile("src/main/resources/META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.acme.one.Core\n")
		}, true},
		"a class output manifest": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			a.oneFile("target/classes/META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.acme.one.Core\n")
		}, true},
		"a built war": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			a.oneFile("target/one.war", "")
		}, true},
		"an unreadable built JAR": {func(a *appFixture) {
			a.oneFile("pom.xml", pom("", ""))
			a.oneFile("target/one.jar", "not a zip")
		}, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.reactorRoot()
			a.appModule("two", "two", justReturn)
			a.source("one/src/main/java/com/acme/one/Core.java", "package com.acme.one;\npublic class Core {}\n")
			a.class("one/target/classes", "com/acme/one/Core", func(*cpb) []xmethod { return nil })
			c.setup(a)
			one := testModule(t, "one", "one")
			two := sibling(testModule(t, "two", "two", netkitDep(a.build)), one, "compile")
			plan, multi, why := reactorUnits(a.build, graphOption(t, "maven", testModule(t, ".", "parent"), one, two))
			want := "two"
			if c.promoted {
				want = "one two"
			}
			if got := unitPaths(plan); multi || strings.Join(got, " ") != want {
				t.Errorf("units = %v (refused %v: %q), want [%s]", got, multi, why, want)
			}
		})
	}
}

// distPOM is a code-free module dist's POM loading lib and shading it with build as the rest of
// the shade configuration.
func distPOM(build string) string {
	return `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
  <artifactId>dist</artifactId>
  <dependencies><dependency><groupId>com.acme</groupId><artifactId>lib</artifactId><version>1.0.0</version></dependency></dependencies>
  <build><plugins><plugin><artifactId>maven-shade-plugin</artifactId>
    <executions><execution><phase>package</phase><goals><goal>shade</goal></goals>` + build + `</execution></executions>
  </plugin></plugins></build>
</project>`
}

// shadeMain is shade configuration naming main as the packaged JAR's Main-Class.
func shadeMain(main string) string {
	return `<configuration><transformers><transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer"><mainClass>` +
		main + `</mainClass></transformer></transformers></configuration>`
}

// rootPOM is the reactor root com.acme:parent:1.0.0 with body added.
func rootPOM(body string) string {
	return `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version><packaging>pom</packaging>` + body + `
</project>`
}

// startClassRoot sets start-class to the library's Generator and manages the Boot plugin with
// starter-parent's ${start-class} wiring, applying it to no module.
const startClassRoot = `<properties><start-class>com.acme.lib.Generator</start-class></properties>
  <build><pluginManagement><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId>
    <executions><execution><goals><goal>repackage</goal></goals></execution></executions>
    <configuration><mainClass>${start-class}</mainClass></configuration>
  </plugin></plugins></pluginManagement></build>`

// shadeRoot manages the shade plugin with the library's Generator as Main-Class, applying it to
// no module.
var shadeRoot = `<build><pluginManagement><plugins><plugin><artifactId>maven-shade-plugin</artifactId>
    <executions><execution><phase>package</phase><goals><goal>shade</goal></goals>` + shadeMain("com.acme.lib.Generator") + `</execution></executions>
  </plugin></plugins></pluginManagement></build>`

// bootRoot applies the Boot plugin to every module, naming no main.
const bootRoot = `<build><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build>`

const (
	bootPluginXML   = `<groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId>`
	shadePluginXML  = `<artifactId>maven-shade-plugin</artifactId>`
	jacocoPluginXML = `<groupId>org.jacoco</groupId><artifactId>jacoco-maven-plugin</artifactId>`
)

// launcherPOM is a code-free module dist's POM loading lib and applying plugin, with packaging
// and extra after its artifactId.
func launcherPOM(packaging, plugin, extra string) string {
	if packaging != "" {
		packaging = "<packaging>" + packaging + "</packaging>"
	}
	return `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
  <artifactId>dist</artifactId>` + packaging + extra + `
  <dependencies><dependency><groupId>com.acme</groupId><artifactId>lib</artifactId><version>1.0.0</version></dependency></dependencies>
  <build><plugins><plugin>` + plugin + `</plugin></plugins></build>
</project>`
}

// A module without code that names a launch and loads reactor siblings packages their classes as
// a program: it is a unit of its own. One that names none, or loads no sibling, is not.
func TestPlanUnits_CodeFreeLauncher(t *testing.T) {
	cases := map[string]struct {
		pom      string
		loadsLib bool
		rootBody string // more of the reactor root POM
		units    string
	}{
		"a shaded main":                 {pom: distPOM(shadeMain("com.acme.lib.Generator")), loadsLib: true, units: "dist one two"},
		"shading with no main":          {pom: distPOM(""), loadsLib: true, units: "one two"},
		"a named main, no sibling":      {pom: distPOM(shadeMain("com.acme.lib.Generator")), units: "one two"},
		"an exec plugin naming no main": {pom: strings.Replace(distPOM(""), "maven-shade-plugin", "exec-maven-plugin", 1) + "", loadsLib: true, units: "one two"},
		"assembly packaging, a main":    {pom: strings.Replace(distPOM(shadeMain("com.acme.lib.Generator")), "<artifactId>dist</artifactId>", "<artifactId>dist</artifactId><packaging>pom</packaging>", 1), loadsLib: true, units: "dist one two"},
		"an unresolved packaging":       {pom: strings.Replace(distPOM(""), "<artifactId>dist</artifactId>", "<artifactId>dist</artifactId><packaging>${p}</packaging>", 1), loadsLib: true, units: "dist one two"},
		"a profile naming a main":       {pom: strings.Replace(distPOM(""), "</dependencies>", "</dependencies><profiles><profile><id>tool</id><build><plugins><plugin><artifactId>exec-maven-plugin</artifactId><configuration><mainClass>com.acme.lib.Generator</mainClass></configuration></plugin></plugins></build></profile></profiles>", 1), loadsLib: true, units: "dist one two"},
		// A parent's profile can launch any child, the code-free one included.
		"a parent profile naming a main": {pom: distPOM(""), loadsLib: true, units: "dist lib one two",
			rootBody: `<profiles><profile><id>tool</id><build><plugins><plugin><artifactId>exec-maven-plugin</artifactId><configuration><mainClass>com.acme.lib.Generator</mainClass></configuration></plugin></plugins></build></profile></profiles>`},
		// A parent's plain configuration launches a child as its profiles do: start-class for the
		// Boot plugin the child applies, a managed plugin's main for the plugin the child applies.
		// The library inherits the same root, which may hand it a launch, so it is a unit too.
		"an inherited start-class, the Boot plugin":        {pom: launcherPOM("", bootPluginXML, ""), loadsLib: true, rootBody: startClassRoot, units: "dist lib one two"},
		"an inherited start-class, pom packaging":          {pom: launcherPOM("pom", bootPluginXML, ""), loadsLib: true, rootBody: startClassRoot, units: "dist lib one two"},
		"a managed shade main, shade applied":              {pom: launcherPOM("", shadePluginXML, ""), loadsLib: true, rootBody: shadeRoot, units: "dist lib one two"},
		"a start-class of its own, the Boot plugin":        {pom: launcherPOM("", bootPluginXML, "<properties><start-class>com.acme.lib.Generator</start-class></properties>"), loadsLib: true, units: "dist one two"},
		"an inherited start-class, the Boot plugin unused": {pom: launcherPOM("", jacocoPluginXML, ""), loadsLib: true, rootBody: startClassRoot, units: "lib one two"},
		"a managed shade main, shade unused":               {pom: launcherPOM("", jacocoPluginXML, ""), loadsLib: true, rootBody: shadeRoot, units: "lib one two"},
		// A coverage aggregator under a parent applying the Boot plugin with no main named.
		"a Boot parent, a coverage aggregator": {pom: launcherPOM("pom", jacocoPluginXML, ""), loadsLib: true, rootBody: bootRoot, units: "lib one two"},
		// An aggregator that also gathers dependencies names no launch: it ships nothing of its own.
		"pom packaging, no main":              {pom: strings.Replace(distPOM(""), "<artifactId>dist</artifactId>", "<artifactId>dist</artifactId><packaging>pom</packaging>", 1), loadsLib: true, units: "one two"},
		"the Boot plugin, no main of its own": {pom: strings.Replace(distPOM(""), "<artifactId>maven-shade-plugin</artifactId>", "<groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId>", 1), loadsLib: true, units: "one two"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.reactorRoot()
			a.appModule("one", "one", justReturn)
			a.appModule("two", "two", justReturn)
			a.libModule("lib", justReturn)
			a.generator("lib", justReturn)
			writeFileT(t, filepath.Join(a.build, "dist", "pom.xml"), c.pom)
			if c.rootBody != "" {
				writeFileT(t, filepath.Join(a.build, "pom.xml"), rootPOM(c.rootBody))
			}
			lib := testModule(t, "lib", "lib")
			dist := testModule(t, "dist", "dist")
			if c.loadsLib {
				dist = sibling(dist, lib, "compile")
			}
			mods := []buildgraph.Module{testModule(t, ".", "parent"),
				sibling(testModule(t, "one", "one"), lib, "compile"), sibling(testModule(t, "two", "two"), lib, "compile"), lib, dist}
			plan, multi, why := reactorUnits(a.build, graphOption(t, "maven", mods...))
			if got := strings.Join(unitPaths(plan), " "); multi || got != c.units {
				t.Errorf("units = %q (refused %v: %q), want %q", got, multi, why, c.units)
			}
		})
	}
}

// A code-free dist module launching a library's main is searched on its own classpath from that
// main, listed or not (every unit loads netkit, so no absence is relied on); a main nothing loaded
// defines withholds.
func TestUnitsReach_CodeFreeLauncher(t *testing.T) {
	type want struct {
		path     string
		searched bool
	}
	reaches := map[bool]want{true: {path: mainTrace("com/acme/lib/Generator")}, false: {path: mainTrace("com/acme/lib/Generator")}}
	cases := map[string]struct {
		gen  func(b *cpb) []byte
		main string
		root string        // more of the reactor root POM
		dist string        // dist's POM, distPOM(shadeMain(main)) when ""
		want map[bool]want // by listed
	}{
		"the main reaches the sink": {gen: callFetch, main: "com.acme.lib.Generator", want: reaches},
		// The main the launcher inherits is its root, as one it names itself is.
		"an inherited start-class reaches the sink":        {gen: callFetch, root: startClassRoot, dist: launcherPOM("", bootPluginXML, ""), want: reaches},
		"an inherited start-class, pom packaging, reaches": {gen: callFetch, root: startClassRoot, dist: launcherPOM("pom", bootPluginXML, ""), want: reaches},
		"a managed shade main reaches the sink":            {gen: callFetch, root: shadeRoot, dist: launcherPOM("", shadePluginXML, ""), want: reaches},
		"its own start-class reaches the sink": {gen: callFetch, want: reaches,
			dist: launcherPOM("", bootPluginXML, "<properties><start-class>com.acme.lib.Generator</start-class></properties>")},
		"the main is clean": {gen: justReturn, main: "com.acme.lib.Generator",
			want: map[bool]want{true: {searched: true}, false: {searched: true}}},
		"a main nothing loaded defines": {gen: justReturn, main: "com.other.Tool",
			want: map[bool]want{true: {}, false: {}}},
	}
	for name, c := range cases {
		for _, listed := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/listed=%v", name, listed), func(t *testing.T) {
				a := newApp(t, "", false)
				a.reactorRoot()
				a.appModule("one", "one", justReturn)
				a.appModule("two", "two", justReturn)
				a.libModule("lib", justReturn)
				a.generator("lib", c.gen)
				dist := c.dist
				if dist == "" {
					dist = distPOM(shadeMain(c.main))
				}
				writeFileT(t, filepath.Join(a.build, "dist", "pom.xml"), dist)
				if c.root != "" {
					writeFileT(t, filepath.Join(a.build, "pom.xml"), rootPOM(c.root))
				}
				lib := testModule(t, "lib", "lib", netkitDep(a.build))
				mods := []buildgraph.Module{testModule(t, ".", "parent"),
					sibling(testModule(t, "one", "one", netkitDep(a.build)), lib, "compile"),
					sibling(testModule(t, "two", "two", netkitDep(a.build)), lib, "compile"),
					lib, sibling(testModule(t, "dist", "dist", netkitDep(a.build)), lib, "compile")}
				if listed {
					a.graph = listedGraph(t, mods...)
				} else {
					a.graph = graphOption(t, "maven", mods...)
				}
				res := a.reach(netkitSinkID)
				w := c.want[listed]
				if w.path == "" && len(res.Paths) != 0 {
					t.Errorf("want no path, got %+v", res.Paths)
				}
				if w.path != "" && (len(res.Paths) != 1 || res.Paths[0].Trace[0].SCIP != w.path) {
					t.Errorf("want one path from %q, got %+v (partiality %+v)", w.path, res.Paths, res.Partiality)
				}
				if got := len(res.Searched) == 1; got != w.searched {
					t.Errorf("Searched = %v, want searched %v (partiality %+v)", res.Searched, w.searched, res.Partiality)
				}
			})
		}
	}
}

// oneFile writes rel under module one.
func (a *appFixture) oneFile(rel, body string) {
	a.t.Helper()
	writeFileT(a.t, filepath.Join(a.build, "one", filepath.FromSlash(rel)), body)
}

// A module has code when it has main sources under its own src/ or main class output; test
// sources, resources, and sources under a directory below it that is no module are not its code.
func TestPlanUnits_MainCode(t *testing.T) {
	cases := map[string]struct {
		setup func(a *appFixture) []buildgraph.Module
		units string // the planned units, "" when refused
		why   string // the refusal
	}{
		// An integration-test module: test sources only, loading one at test scope.
		"test sources only": {setup: func(a *appFixture) []buildgraph.Module {
			a.source("it/src/test/java/com/acme/it/ITest.java", "package com.acme.it;\npublic class ITest {}\n")
			return []buildgraph.Module{sibling(testModule(t, "it", "it"), testModule(t, "one", "one"), "test")}
		}, units: "one two"},
		"resources only": {setup: func(a *appFixture) []buildgraph.Module {
			writeFileT(t, filepath.Join(a.build, "conf", "src", "main", "resources", "app.yml"), "a: 1\n")
			return []buildgraph.Module{testModule(t, "conf", "conf")}
		}, units: "one two"},
		// Generated classes with no source: the output is the module's code, loaded by one.
		"class output only": {setup: func(a *appFixture) []buildgraph.Module {
			a.class("gen/target/classes", "com/acme/gen/Gen", func(*cpb) []xmethod { return nil })
			return []buildgraph.Module{testModule(t, "gen", "gen")}
		}, units: "one two"},
		"main sources below a module, outside its src": {setup: func(a *appFixture) []buildgraph.Module {
			a.source("x/tools/src/main/java/com/acme/T.java", "package com.acme;\npublic class T {}\n")
			return []buildgraph.Module{testModule(t, "x", "x")}
		}, why: "x/tools/src/main/java/com/acme/T.java is in no module the units load"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.reactorRoot()
			a.appModule("one", "one", justReturn)
			a.appModule("two", "two", justReturn)
			extra := c.setup(a)
			one := testModule(t, "one", "one", netkitDep(a.build))
			for _, m := range extra {
				if m.Path == "gen" {
					one = sibling(one, m, "compile")
				}
			}
			mods := append([]buildgraph.Module{testModule(t, ".", "parent"), one, testModule(t, "two", "two")}, extra...)
			plan, multi, why := reactorUnits(a.build, graphOption(t, "maven", mods...))
			if c.units != "" {
				if got := unitPaths(plan); multi || strings.Join(got, " ") != c.units {
					t.Errorf("units = %v (refused %v: %q), want [%s]", got, multi, why, c.units)
				}
				return
			}
			if plan != nil || !multi || !strings.HasSuffix(why, ": "+c.why) {
				t.Errorf("reactorUnits = %v, %v, %q; want refused with %q", unitPaths(plan), multi, why, c.why)
			}
		})
	}
}

// ResolveDependencySymbols leaves the run-wide multiple_projects_unsupported off a reactor the
// units plan places, and keeps it on one the plan refuses.
func TestResolveDependencySymbols_ReactorGate(t *testing.T) {
	for name, tool := range map[string]string{"planned": "maven", "refused": "gradle"} {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.reactorRoot()
			a.appModule("one", "one", justReturn)
			a.appModule("two", "two", justReturn)
			graph := graphOption(t, tool, testModule(t, ".", "parent"), testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "two"))
			res := resolveUnder(t, a.build, netkitPURL, graph, "com.evil.netkit.UrlFetcher.fetch")
			if len(res.Resolved) == 0 {
				t.Errorf("fetch not resolved: %+v", res)
			}
			if got := hasReason(res.Partiality, reasonMultipleProjectsUnsupported); got != (tool == "gradle") {
				t.Errorf("multiple_projects_unsupported = %v, want %v (partiality %+v)", got, tool == "gradle", res.Partiality)
			}
		})
	}
}

// An application at the checkout root beside a library nothing loads and nobody compiled: each
// is a unit, and the uncompiled library and unnamed launch keep the sink from Searched.
func TestUnitsReach_RootAppBesideUnloadedLib(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.source("lib/src/main/java/com/acme/Lib.java", "package com.acme;\npublic class Lib {}\n")
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.graph = graphOption(t, "maven", testModule(t, ".", "app", netkitDep(a.build)), testModule(t, "lib", "lib"))

	plan, multi, why := reactorUnits(a.build, a.graph)
	if got := unitPaths(plan); multi || strings.Join(got, " ") != ". lib" {
		t.Fatalf("units = %v (refused %v: %q), want [. lib]", got, multi, why)
	}
	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 || len(res.Paths) != 0 {
		t.Errorf("Searched %v, paths %+v; want neither", res.Searched, res.Paths)
	}
	want := []string{reasonFirstPartyBytecodeAbsent, plugin.PartialReasonNoIngress, reasonNoWholeProgramRoot, plugin.PartialReasonReachabilityUndetermined, reasonLaunchEntryUnnamed}
	got := slices.Clone(res.Partiality.Reasons)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("reasons = %v, want %v", got, want)
	}
}

// cacheClosure holds at most closureCacheCap engines and always keeps the one it stores.
func TestCacheClosure_Bounded(t *testing.T) {
	resetClosureCache()
	t.Cleanup(resetClosureCache)
	for i := range closureCacheCap * 2 {
		key := fmt.Sprintf("build-%d", i)
		cacheClosure(key, closureEntry{key: key})
		closureCache.Lock()
		n, kept := len(closureCache.m), closureCache.m[key].key == key
		closureCache.Unlock()
		if n > closureCacheCap || !kept {
			t.Fatalf("after storing %s: %d entries, newest kept %v", key, n, kept)
		}
	}
	// Restoring a key already held evicts nothing.
	held := fmt.Sprintf("build-%d", closureCacheCap)
	cacheClosure(held, closureEntry{key: held})
	closureCache.Lock()
	n := len(closureCache.m)
	closureCache.Unlock()
	if n != closureCacheCap {
		t.Errorf("re-storing a held key left %d entries, want %d", n, closureCacheCap)
	}
	// The oldest held entry, once looked up, outlives the next oldest: the least recently used goes.
	oldest, next := fmt.Sprintf("build-%d", closureCacheCap+1), fmt.Sprintf("build-%d", closureCacheCap+2)
	if _, ok := cachedClosure(oldest); !ok {
		t.Fatalf("%s not held", oldest)
	}
	cacheClosure("fresh", closureEntry{key: "fresh"})
	closureCache.Lock()
	defer closureCache.Unlock()
	if _, ok := closureCache.m[oldest]; !ok {
		t.Errorf("evicted %s, which was just looked up", oldest)
	}
	if _, ok := closureCache.m[next]; ok {
		t.Errorf("kept %s, the least recently used", next)
	}
}
