package javaanalysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
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

// libModule writes a reactor library module at dir holding com.acme.lib.Lib, whose static run()
// runs code.
func (a *appFixture) libModule(dir string, code func(b *cpb) []byte) {
	a.t.Helper()
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

var callSharedLib = callStatic("com/acme/lib/Lib", "run")

func traceStart(pkg string) string { return "jvmref com/acme/" + pkg + "/Main#main" + mainDescriptor }

// A reactor of two apps sharing a library is searched one app at a time, each over its own
// classes, its siblings' classes and the JARs its own module resolved.
func TestUnitsReach_SearchedPerUnit(t *testing.T) {
	type want struct {
		pathFrom string // the pkg whose Main a path starts at, "" for no path
		searched bool
	}
	cases := map[string]struct {
		one, two         func(b *cpb) []byte // each app's main
		lib              func(b *cpb) []byte
		oneNetkit, twoNk bool
		libExtra         func(a *appFixture) // more in the library module
		want             want
	}{
		// Only app one resolves netkit; the path through the shared library is app one's.
		"path in the unit carrying the sink JAR": {one: callSharedLib, two: justReturn, lib: callFetch, oneNetkit: true, want: want{pathFrom: "one"}},
		// App two calls the sink but never resolved netkit; app one's JAR is not linked into it.
		"no cross-unit linking": {one: justReturn, two: callFetch, lib: justReturn, oneNetkit: true},
		"every unit clean":      {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{searched: true}},
		// App two's search is undetermined, so the build is not Searched though app one is clean.
		"one unclean unit withholds Searched": {one: justReturn, two: callUnloaded, lib: justReturn, oneNetkit: true, twoNk: true},
		// A unit's launch entry is its own module's: a library's code generator main is not one.
		"a sibling's POM main is not the unit's": {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{searched: true},
			libExtra: func(a *appFixture) {
				writeFileT(a.t, filepath.Join(a.build, "lib", "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>
  <artifactId>lib</artifactId>
  <build><plugins><plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId>
    <configuration><mainClass>com.acme.lib.Generator</mainClass></configuration>
  </plugin></plugins></build>
</project>`)
			}},
		"a sibling's manifest is not the unit's": {one: justReturn, two: callSharedLib, lib: justReturn, oneNetkit: true, twoNk: true, want: want{searched: true},
			libExtra: func(a *appFixture) {
				writeFileT(a.t, filepath.Join(a.build, "lib", "target", "classes", "META-INF", "MANIFEST.MF"), "Manifest-Version: 1.0\nMain-Class: com.acme.lib.Generator\n")
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
			lib := testModule(t, "lib", "lib", netkitDep(a.build))
			one := sibling(testModule(t, "one", "one", oneDeps...), lib, "compile")
			two := sibling(testModule(t, "two", "two", twoDeps...), lib, "compile")
			a.graph = graphOption(t, "maven", testModule(t, ".", "parent"), one, two, lib)

			res := a.reach(netkitSinkID)
			if hasReason(res.Partiality, reasonMultipleProjectsUnsupported) {
				t.Fatalf("a placeable reactor kept multiple_projects_unsupported: %+v", res.Partiality)
			}
			if c.want.pathFrom == "" && len(res.Paths) != 0 {
				t.Errorf("want no path, got %+v", res.Paths)
			}
			if c.want.pathFrom != "" {
				if len(res.Paths) != 1 {
					t.Fatalf("want one path, got %+v (partiality %+v)", res.Paths, res.Partiality)
				}
				if got := res.Paths[0].Trace[0].SCIP; got != traceStart(c.want.pathFrom) {
					t.Errorf("trace starts at %q, want %q", got, traceStart(c.want.pathFrom))
				}
			}
			if got := len(res.Searched) == 1 && res.Searched[0] == netkitSinkID; got != c.want.searched {
				t.Errorf("Searched = %v, want searched %v (partiality %+v)", res.Searched, c.want.searched, res.Partiality)
			}
		})
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
		"class output under a module without code": {func(a *appFixture) Option {
			a.class("docs/target/classes", "com/acme/Doc", func(*cpb) []xmethod { return nil })
			return graphOption(t, "maven", testModule(t, ".", "parent"), testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "two"), testModule(t, "docs", "docs"))
		}, "class output in docs is in no module the units load"},
		"reactor test-jar on the runtime classpath": {func(a *appFixture) Option {
			a.libModule("lib", justReturn)
			lib := testModule(t, "lib", "lib")
			one := testModule(t, "one", "one", netkitDep(a.build), graphDep{group: "com.example", artifact: "lib", version: "1", classifier: "tests", jar: netkitJarPath(a.build)})
			return graphOption(t, "maven", testModule(t, ".", "parent"), sibling(one, lib, "compile"), testModule(t, "two", "two"), lib)
		}, "one loads reactor artifact com.example:lib:jar:tests:1, not a module's own output"},
		"modules loading each other": {func(a *appFixture) Option {
			one, two := testModule(t, "one", "one", netkitDep(a.build)), testModule(t, "two", "two")
			return graphOption(t, "maven", testModule(t, ".", "parent"), sibling(one, two, "compile"), sibling(two, one, "compile"))
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
