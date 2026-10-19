package javaanalysis

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// --- fixture: a Maven app depending on com.evil:netkit, its compiled classes and the
// netkit JAR, all built as real bytecode without a JDK. ---

// xmethod is one method of an emitted class; code nil emits no Code attribute (abstract).
type xmethod struct {
	name, desc string
	flags      uint16
	code       []byte
}

const (
	accPublicStatic   = 0x0009
	accPublic         = 0x0001
	accPublicAbstract = 0x0401
)

// emitClassX builds a .class for owner with the given super class and methods.
func emitClassX(b *cpb, owner, super string, flags uint16, methods []xmethod) []byte {
	return emitClassI(b, owner, super, nil, flags, methods)
}

// emitClassI is emitClassX with direct superinterfaces.
func emitClassI(b *cpb, owner, super string, ifaces []string, flags uint16, methods []xmethod) []byte {
	thisIdx := b.class(owner)
	superIdx := b.class(super)
	ifaceIdx := make([]uint16, len(ifaces))
	for i, n := range ifaces {
		ifaceIdx[i] = b.class(n)
	}
	codeAttr := b.utf8("Code")
	type built struct{ nameIdx, descIdx uint16 }
	bm := make([]built, len(methods))
	for i, m := range methods {
		bm[i] = built{b.utf8(m.name), b.utf8(m.desc)}
	}
	var buf bytes.Buffer
	buf.Write(be4(0xCAFEBABE))
	buf.Write(be2(0))
	buf.Write(be2(52))
	buf.Write(be2(uint16(len(b.entries) + 1)))
	for _, e := range b.entries {
		buf.Write(e)
	}
	buf.Write(be2(flags))
	buf.Write(be2(thisIdx))
	buf.Write(be2(superIdx))
	buf.Write(be2(uint16(len(ifaceIdx))))
	for _, i := range ifaceIdx {
		buf.Write(be2(i))
	}
	buf.Write(be2(0))
	buf.Write(be2(uint16(len(methods))))
	for i, m := range methods {
		buf.Write(be2(m.flags))
		buf.Write(be2(bm[i].nameIdx))
		buf.Write(be2(bm[i].descIdx))
		if m.code == nil {
			buf.Write(be2(0))
			continue
		}
		buf.Write(be2(1))
		var code bytes.Buffer
		code.Write(be2(8))
		code.Write(be2(8))
		code.Write(be4(uint32(len(m.code))))
		code.Write(m.code)
		code.Write(be2(0))
		code.Write(be2(0))
		buf.Write(be2(codeAttr))
		buf.Write(be4(uint32(code.Len())))
		buf.Write(code.Bytes())
	}
	buf.Write(be2(0))
	return buf.Bytes()
}

const fetchDesc = "(Ljava/lang/String;)Ljava/lang/String;"

var netkitSinkID = depEdgeSymbol(netkitFetch)

// callFetch is aconst_null; aconst_null; invokevirtual UrlFetcher.fetch; pop; return.
func callFetch(b *cpb) []byte {
	idx := b.mref("com/evil/netkit/UrlFetcher", "fetch", fetchDesc)
	return append([]byte{0x01, 0x01, 0xB6}, append(be2(idx), 0x57, 0xB1)...)
}

// callUnloaded is invokestatic com/other/Plugin.run()V; return — a call into a class no
// JAR on the closure defines.
func callUnloaded(b *cpb) []byte {
	idx := b.mref("com/other/Plugin", "run", "()V")
	return append([]byte{0xB8}, append(be2(idx), 0xB1)...)
}

var ret = []byte{0xB1}

type appFixture struct {
	t     *testing.T
	build string
}

// newApp writes a pom declaring netkit (plus extra dependency XML), and netkit's JAR and a
// dependency-free POM for it in the build-local cache, so netkit's own subtree is closed.
// abstractSink makes UrlFetcher.fetch abstract.
func newApp(t *testing.T, extraDeps string, abstractSink bool) *appFixture {
	t.Helper()
	build := t.TempDir()
	pom := `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version></dependency>
    ` + extraDeps + `
  </dependencies>
  <build><plugins><plugin><artifactId>maven-jar-plugin</artifactId>
    <configuration><archive><manifest><mainClass>com.acme.App</mainClass></manifest></archive></configuration>
  </plugin></plugins></build>
</project>`
	writeFileT(t, filepath.Join(build, "pom.xml"), pom)
	b := &cpb{}
	fetch := xmethod{"fetch", fetchDesc, accPublic, ret}
	flags := uint16(0x0021)
	if abstractSink {
		fetch = xmethod{"fetch", fetchDesc, accPublicAbstract, nil}
		flags = 0x0421
	}
	jar := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", flags, []xmethod{fetch})
	writeJar(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"), "com/evil/netkit/UrlFetcher.class", jar)
	writeFileT(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.pom"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version></project>`)
	return &appFixture{t: t, build: build}
}

// source writes a main source file under src/main/java (or under module/ when given).
func (a *appFixture) source(rel, body string) {
	a.t.Helper()
	writeFileT(a.t, filepath.Join(a.build, filepath.FromSlash(rel)), body)
}

// class writes a compiled class under rel's class output dir, dated after every source.
func (a *appFixture) class(outDir, owner string, methods func(b *cpb) []xmethod) {
	a.t.Helper()
	a.classI(outDir, owner, "java/lang/Object", nil, 0x0021, methods)
}

// classI is class with a chosen super class, superinterfaces and access flags.
func (a *appFixture) classI(outDir, owner, super string, ifaces []string, flags uint16, methods func(b *cpb) []xmethod) {
	a.t.Helper()
	b := &cpb{}
	data := emitClassI(b, owner, super, ifaces, flags, methods(b))
	p := filepath.Join(a.build, filepath.FromSlash(outDir), filepath.FromSlash(owner)+".class")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		a.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		a.t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(p, future, future); err != nil {
		a.t.Fatal(err)
	}
}

func (a *appFixture) reach(symbols ...string) plugin.ReachabilityResult {
	a.t.Helper()
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: a.build, Symbols: symbols})
	if err != nil {
		a.t.Fatalf("Reachability: %v", err)
	}
	return res
}

func writeFileT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const appSource = `package com.acme;
public class App {
    public static void main(String[] args) {}
}
`

const servletSource = `package com.acme;
public class Web extends javax.servlet.http.HttpServlet {
    public void doGet(Object req, Object resp) {}
}
`

func mainCalling(code func(b *cpb) []byte) func(b *cpb) []xmethod {
	return func(b *cpb) []xmethod {
		return []xmethod{{"main", mainDescriptor, accPublicStatic, code(b)}}
	}
}

func doGetCalling(code func(b *cpb) []byte) func(b *cpb) []xmethod {
	return func(b *cpb) []xmethod {
		return []xmethod{{"doGet", "(Ljava/lang/Object;Ljava/lang/Object;)V", accPublic, code(b)}}
	}
}

func justReturn(*cpb) []byte { return ret }

func hasScoped(p plugin.Partiality, reason, pkg string) bool {
	for _, s := range p.Scoped {
		if s.Reason == reason && s.Package == pkg {
			return true
		}
	}
	return false
}

// A main that calls the dependency sink is a candidate path; with no attacker-facing
// ingress on it, the answer still says so.
func TestBytecodeReach_MainCallsDependencySink(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callFetch))

	res := a.reach(netkitSinkID)
	if len(res.Paths) != 1 {
		t.Fatalf("want one path, got %+v (partiality %+v)", res.Paths, res.Partiality)
	}
	p := res.Paths[0]
	if p.Sink.SCIP != netkitSinkID || p.Ingress.SCIP != "" {
		t.Errorf("path = %+v", p)
	}
	if got := p.Trace[0].SCIP; got != "jvmref com/acme/App#main"+mainDescriptor {
		t.Errorf("trace starts at %q", got)
	}
	if len(res.Searched) != 0 {
		t.Errorf("a reached sink is never Searched: %v", res.Searched)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("main-only path must declare no_known_ingress: %+v", res.Partiality)
	}
}

// A plain main program that never calls the dependency lists the sink as Searched.
func TestBytecodeReach_UnusedDependencyIsSearched(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))

	res := a.reach(netkitSinkID)
	if !slices.Equal(res.Searched, []string{netkitSinkID}) {
		t.Fatalf("Searched = %v, partiality %+v", res.Searched, res.Partiality)
	}
	if len(res.Paths) != 0 || hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("a searched sink carries no path and no no_known_ingress: %+v %+v", res.Paths, res.Partiality)
	}
}

// Without a main, nothing licenses a negative.
func TestBytecodeReach_NoMainIsNoWholeProgramRoot(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", "package com.acme;\npublic class App { void run() {} static void main(int n) {} }\n")
	a.class("target/classes", "com/acme/App", func(b *cpb) []xmethod {
		return []xmethod{{"run", "()V", accPublic, ret}, {"main", "(I)V", accPublicStatic, ret}}
	})

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Fatalf("Searched without a main: %v", res.Searched)
	}
	for _, r := range []string{reasonNoWholeProgramRoot, plugin.PartialReasonNoIngress, plugin.PartialReasonReachabilityUndetermined} {
		if !hasReason(res.Partiality, r) {
			t.Errorf("missing %s: %+v", r, res.Partiality)
		}
	}
}

// A servlet ingress mapped to its compiled method yields a candidate path named by the
// lexical ingress id.
func TestBytecodeReach_IngressCandidate(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/Web.java", servletSource)
	a.class("target/classes", "com/acme/Web", doGetCalling(callFetch))

	res := a.reach(netkitSinkID)
	if len(res.Paths) != 1 {
		t.Fatalf("want one path, got %+v (partiality %+v)", res.Paths, res.Partiality)
	}
	want := methodSCIP("com.acme", []string{"Web"}, "doGet", 2)
	if got := res.Paths[0].Ingress.SCIP; got != want {
		t.Errorf("ingress = %q, want %q", got, want)
	}
	if hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("an ingress path declares no no_known_ingress: %+v", res.Partiality)
	}
}

// An ingress search that comes back empty never licenses a negative on its own.
func TestBytecodeReach_CleanIngressWithoutMainIsNotSearched(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/Web.java", servletSource)
	a.class("target/classes", "com/acme/Web", doGetCalling(justReturn))

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Fatalf("ingress-only search listed Searched: %v", res.Searched)
	}
	if !hasReason(res.Partiality, reasonNoWholeProgramRoot) {
		t.Errorf("missing no_whole_program_root: %+v", res.Partiality)
	}
}

// A hazard on the main's frontier makes the answer undetermined.
func TestBytecodeReach_HazardIsUndetermined(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callUnloaded))

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 || len(res.Paths) != 0 {
		t.Fatalf("hazard: Searched %v Paths %v", res.Searched, res.Paths)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("missing reachability_undetermined: %+v", res.Partiality)
	}
}

// A clean main does not outvote an ingress whose search hit a hazard.
func TestBytecodeReach_HazardousIngressBlocksSearched(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.source("src/main/java/com/acme/Web.java", servletSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.class("target/classes", "com/acme/Web", doGetCalling(callUnloaded))

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Fatalf("Searched despite a hazardous ingress: %v", res.Searched)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Errorf("missing reachability_undetermined: %+v", res.Partiality)
	}
}

// An ingress the source declares but the class output does not hold — no method of that
// name, or none with its parameter count — blocks Searched.
func TestBytecodeReach_UnmappedIngressBlocksSearched(t *testing.T) {
	for name, compiled := range map[string]xmethod{
		"other name":  {"doPost", "(Ljava/lang/Object;Ljava/lang/Object;)V", accPublic, ret},
		"other arity": {"doGet", "(Ljava/lang/Object;)V", accPublic, ret},
	} {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.source("src/main/java/com/acme/Web.java", servletSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
			a.class("target/classes", "com/acme/Web", func(b *cpb) []xmethod { return []xmethod{compiled} })

			res := a.reach(netkitSinkID)
			if len(res.Searched) != 0 {
				t.Fatalf("Searched despite an unmapped ingress: %v", res.Searched)
			}
			if !hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
				t.Errorf("missing reachability_undetermined: %+v", res.Partiality)
			}
		})
	}
}

// The closure cache never answers from bytecode that has since changed.
func TestBytecodeReach_RecompiledClassesAreReread(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	if res := a.reach(netkitSinkID); len(res.Searched) != 1 {
		t.Fatalf("first run: Searched %v", res.Searched)
	}
	a.class("target/classes", "com/acme/App", mainCalling(callFetch))
	if res := a.reach(netkitSinkID); len(res.Paths) != 1 || len(res.Searched) != 0 {
		t.Fatalf("after recompiling: Paths %v Searched %v", res.Paths, res.Searched)
	}
}

// A dependency JAR rewritten in place, same size and same modification time, is re-read: the
// cache is keyed by the bytes the lookup compared, not by what the file system says about them.
func TestBytecodeReach_RewrittenJarIsReread(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callFetch))
	if res := a.reach(netkitSinkID); len(res.Paths) != 1 {
		t.Fatalf("first run: Paths %v", res.Paths)
	}
	jarPath := filepath.Join(a.build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar")
	before, err := os.Stat(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	// Deflate output varies by a byte or so with the name; take the first rename that keeps the size.
	for _, name := range []string{"fetcx", "fetcy", "fetcz", "fetca", "xetch", "fxtch", "fexch", "fetxh"} {
		renamed := emitClassX(&cpb{}, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{name, fetchDesc, accPublic, ret}})
		writeJar(t, jarPath, "com/evil/netkit/UrlFetcher.class", renamed)
		if st, err := os.Stat(jarPath); err == nil && st.Size() == before.Size() {
			break
		}
	}
	if err := os.Chtimes(jarPath, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("setup: rewrite changed size or time (%d,%v -> %d,%v)", before.Size(), before.ModTime(), after.Size(), after.ModTime())
	}
	if res := a.reach(netkitSinkID); len(res.Paths) != 0 {
		t.Fatalf("after rewriting the JAR without fetch: Paths %v", res.Paths)
	}
}

func TestHazardReason(t *testing.T) {
	for why, want := range map[string]string{
		"reflection: java/lang/reflect/Method.invoke":                plugin.PartialReasonReflection,
		"invokedynamic (runtime-bound target): com/acme/App.main":    plugin.PartialReasonDynamicDispatch,
		"unloaded_dependency: com/other/Plugin.run()V":               "",
		"virtual/interface call on out-of-classpath receiver: x.y()": "",
	} {
		if got := hazardReason(why); got != want {
			t.Errorf("hazardReason(%q) = %q, want %q", why, got, want)
		}
	}
}

// An abstract sink stands for bodies the search never walked.
func TestBytecodeReach_AbstractSinkIsNotSearched(t *testing.T) {
	a := newApp(t, "", true)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))

	if res := a.reach(netkitSinkID); len(res.Searched) != 0 {
		t.Fatalf("abstract sink Searched: %v", res.Searched)
	}
}

// A closure JAR no cache holds hides code that can call its own closure and, through objects
// the build hands it, first-party code and everything that reaches. So the scoped
// maven_uncached_subtree is bounded by "", the JAR, its closure and the build's direct
// dependencies' closure, and is nil when the JAR's own POM is not cached either. Each scoped
// reason is also listed run-wide.
func TestBytecodeReach_UncachedJarIsScopedAndRunWide(t *testing.T) {
	const goneDep = `<dependency><groupId>com.dep</groupId><artifactId>gone</artifactId><version>1</version></dependency>`
	const gonePURL = "pkg:maven/com.dep/gone"
	for _, tc := range []struct {
		name        string
		jar, pom    bool
		wantScoped  bool
		wantTargets []string
	}{
		{name: "jar present", jar: true, pom: true},
		{name: "jar missing, closure known", pom: true, wantScoped: true,
			wantTargets: []string{"", gonePURL, "pkg:maven/com.dep/optdep", "pkg:maven/com.dep/profdep", "pkg:maven/com.dep/provdep", netkitPURL}},
		{name: "jar missing, metadata missing", wantScoped: true, wantTargets: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newApp(t, goneDep, false)
			writeNetkitOwnPom(t, a.build)
			dir := filepath.Join(a.build, ".m2", "repository", "com", "dep", "gone", "1")
			if tc.pom {
				writeFileT(t, filepath.Join(dir, "gone-1.pom"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.dep</groupId><artifactId>gone</artifactId><version>1</version></project>`)
			}
			if tc.jar {
				b := &cpb{}
				writeJar(t, filepath.Join(dir, "gone-1.jar"), "com/dep/gone/Gone.class", emitClassX(b, "com/dep/gone/Gone", "java/lang/Object", 0x0021, []xmethod{{"run", "()V", accPublic, ret}}))
			}
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))

			res := a.reach(netkitSinkID)
			var got []plugin.ScopedReason
			for _, s := range res.Partiality.Scoped {
				if s.Package == gonePURL {
					got = append(got, s)
				}
			}
			if !tc.wantScoped {
				if len(got) != 0 || hasReason(res.Partiality, reasonMavenUncachedSubtree) {
					t.Fatalf("a cached JAR costs a reason: %+v", res.Partiality)
				}
				return
			}
			if len(got) != 1 || got[0].Reason != reasonMavenUncachedSubtree || got[0].Path != "com.dep:gone:1" {
				t.Fatalf("want one scoped maven_uncached_subtree for gone, got %+v", res.Partiality.Scoped)
			}
			if !reflect.DeepEqual(got[0].Targets, tc.wantTargets) {
				t.Errorf("targets = %q, want %q", got[0].Targets, tc.wantTargets)
			}
			if !hasReason(res.Partiality, reasonMavenUncachedSubtree) || res.Partiality.Complete {
				t.Errorf("scoped reason not mirrored run-wide: %+v", res.Partiality)
			}
		})
	}
}

// A dependency declared with a classifier is never bound to the plain JAR: its code is
// unloaded, so a call into it is a hazard, not a path or a negative.
func TestBytecodeReach_VariantDependencyIsNotLoaded(t *testing.T) {
	build := t.TempDir()
	a := &appFixture{t: t, build: build}
	writeFileT(t, filepath.Join(build, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version><classifier>jdk8</classifier></dependency>
  </dependencies>
</project>`)
	b := &cpb{}
	jar := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}})
	writeJar(t, filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"), "com/evil/netkit/UrlFetcher.class", jar)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(callFetch))

	res := a.reach(netkitSinkID)
	if len(res.Paths) != 0 || len(res.Searched) != 0 {
		t.Fatalf("variant JAR was loaded: Paths %v Searched %v", res.Paths, res.Searched)
	}
	if !hasScoped(res.Partiality, reasonNoDependencyArtifact, netkitPURL) {
		t.Errorf("missing scoped no_dependency_artifact for the variant: %+v", res.Partiality.Scoped)
	}
}

// Two JARs defining one class: the second body is unseen, and says so.
func TestBytecodeReach_DuplicateClassIsScoped(t *testing.T) {
	a := newApp(t, `<dependency><groupId>com.dup</groupId><artifactId>fork</artifactId><version>1</version></dependency>`, false)
	b := &cpb{}
	dup := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}})
	writeJar(t, filepath.Join(a.build, ".m2", "repository", "com", "dup", "fork", "1", "fork-1.jar"), "com/evil/netkit/UrlFetcher.class", dup)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))

	res := a.reach(netkitSinkID)
	found := false
	for _, s := range res.Partiality.Scoped {
		if s.Reason == reasonDuplicateClass {
			found = true
		}
	}
	if !found || !hasReason(res.Partiality, reasonDuplicateClass) {
		t.Errorf("missing duplicate_class: %+v", res.Partiality)
	}
}

// No class output: today's lexical answer, plus first_party_bytecode_absent.
func TestBytecodeReach_NoClassesKeepsLexicalAnswer(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 || len(res.Paths) != 0 {
		t.Fatalf("no class output: Searched %v Paths %v", res.Searched, res.Paths)
	}
	if !hasReason(res.Partiality, reasonFirstPartyBytecodeAbsent) || !hasScoped(res.Partiality, reasonFirstPartyBytecodeAbsent, "") {
		t.Errorf("missing first_party_bytecode_absent: %+v", res.Partiality)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Errorf("lexical answer lost its no_known_ingress: %+v", res.Partiality)
	}
}

// Class output older than its source does not stand for the program.
func TestBytecodeReach_StaleClassesAreNotSearched(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(a.build, "target", "classes", "com", "acme", "App.class"), past, past); err != nil {
		t.Fatal(err)
	}

	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Fatalf("stale class output Searched: %v", res.Searched)
	}
	if !hasReason(res.Partiality, reasonFirstPartyBytecodeAbsent) {
		t.Errorf("missing first_party_bytecode_absent: %+v", res.Partiality)
	}
}

// Two modules — declared in the POM, or two class output trees — are not traced at all.
func TestBytecodeReach_TwoModulesAreUnsupported(t *testing.T) {
	cases := map[string]func(a *appFixture){
		"pom modules": func(a *appFixture) {
			pom, err := os.ReadFile(filepath.Join(a.build, "pom.xml"))
			if err != nil {
				t.Fatal(err)
			}
			withModules := strings.Replace(string(pom), "<dependencies>", "<modules><module>app</module><module>lib</module></modules><dependencies>", 1)
			writeFileT(t, filepath.Join(a.build, "pom.xml"), withModules)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
		},
		"two class outputs": func(a *appFixture) {
			a.source("app/src/main/java/com/acme/App.java", appSource)
			a.source("lib/src/main/java/com/acme/Lib.java", "package com.acme;\npublic class Lib {}\n")
			a.class("app/target/classes", "com/acme/App", mainCalling(justReturn))
			a.class("lib/target/classes", "com/acme/Lib", func(*cpb) []xmethod { return nil })
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, "", false)
			setup(a)
			res := a.reach(netkitSinkID)
			if len(res.Searched) != 0 {
				t.Fatalf("multi-module build listed Searched: %v", res.Searched)
			}
			if !hasReason(res.Partiality, reasonMultipleProjectsUnsupported) {
				t.Fatalf("missing run-wide multiple_projects_unsupported: %+v", res.Partiality)
			}
			if got := report.ClassifyPartialityReason(reasonMultipleProjectsUnsupported); got != report.PartialityDidNotRun {
				t.Errorf("multiple_projects_unsupported classifies as %v, want did_not_run", got)
			}
		})
	}
}

func TestDescriptorParamCount(t *testing.T) {
	for desc, want := range map[string]int{
		"()V":                       0,
		"(I)V":                      1,
		"([Ljava/lang/String;)V":    1,
		"(JLjava/lang/Object;[[I)Z": 3,
		"(Ljava/lang/String;D)V":    2,
		"V":                         -1,
		"(Ljava/lang/String":        -1,
	} {
		if got := descriptorParamCount(desc); got != want {
			t.Errorf("descriptorParamCount(%q) = %d, want %d", desc, got, want)
		}
	}
}

// withFetch builds a method whose body calls the netkit sink.
func withFetch(name, desc string, flags uint16) func(b *cpb) xmethod {
	return func(b *cpb) xmethod { return xmethod{name, desc, flags, callFetch(b)} }
}

// The JVM initializes the launch class, and every class its initialization closure names,
// before main runs, and constructs an instance main's receiver: code there runs with no call
// from main, so a main whose body never reaches the sink is still a path, never Searched.
func TestBytecodeReach_LaunchClassInitialization(t *testing.T) {
	const (
		accStatic       = 0x0008
		accInterface    = 0x0601
		appOut          = "target/classes"
		base, iface     = "com/acme/Base", "com/acme/Feature"
		clinit, initDsc = "<clinit>", "()V"
	)
	tests := []struct {
		name  string
		setup func(a *appFixture)
		path  bool
	}{
		{"empty static main: searched", func(a *appFixture) {
			a.class(appOut, "com/acme/App", mainCalling(justReturn))
		}, false},
		{"launch class <clinit>", func(a *appFixture) {
			a.class(appOut, "com/acme/App", func(b *cpb) []xmethod {
				return []xmethod{{"main", mainDescriptor, accPublicStatic, ret}, withFetch(clinit, initDsc, accStatic)(b)}
			})
		}, true},
		{"superclass <clinit>", func(a *appFixture) {
			a.classI(appOut, base, "java/lang/Object", nil, 0x0021, func(b *cpb) []xmethod {
				return []xmethod{withFetch(clinit, initDsc, accStatic)(b)}
			})
			a.classI(appOut, "com/acme/App", base, nil, 0x0021, mainCalling(justReturn))
		}, true},
		{"superinterface with a default method: <clinit>", func(a *appFixture) {
			a.classI(appOut, iface, "java/lang/Object", nil, accInterface, func(b *cpb) []xmethod {
				return []xmethod{{"feature", "()V", accPublic, ret}, withFetch(clinit, initDsc, accStatic)(b)}
			})
			a.classI(appOut, "com/acme/App", "java/lang/Object", []string{iface}, 0x0021, mainCalling(justReturn))
		}, true},
		{"instance main: receiver <init>", func(a *appFixture) {
			a.class(appOut, "com/acme/App", func(b *cpb) []xmethod {
				return []xmethod{{"main", mainDescriptor, accPublic, ret}, withFetch("<init>", initDsc, accPublic)(b)}
			})
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			tt.setup(a)
			res := a.reach(netkitSinkID)
			if !tt.path {
				if !slices.Equal(res.Searched, []string{netkitSinkID}) {
					t.Fatalf("Searched = %v, partiality %+v", res.Searched, res.Partiality)
				}
				return
			}
			if len(res.Searched) != 0 {
				t.Fatalf("initialization code reaches the sink, yet Searched = %v", res.Searched)
			}
			if len(res.Paths) != 1 || res.Paths[0].Sink.SCIP != netkitSinkID {
				t.Fatalf("want one path to the sink, got %+v (partiality %+v)", res.Paths, res.Partiality)
			}
		})
	}
}

// Every launch surface in the tree is scanned: an agent, an unmodeled JVM option, or a
// launch-time class the JVM loads by name runs code no main reaches, so an empty main-only
// search cannot refute it. The logging-config row is that framework ingress: the JVM
// constructs com.acme.Hidden at startup and its constructor calls the sink, while no
// recognizer maps the option to an ingress.
func TestBytecodeReach_LaunchOptionsWithholdSearched(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		hidden bool
		reason string // "" for the inert control, which stays Searched
	}{
		{"inert JAVA_OPTS: searched", map[string]string{
			"Dockerfile": "ENV JAVA_OPTS=\"-XX:MaxRAMPercentage=75 -Dfile.encoding=UTF-8\"\nENTRYPOINT exec java $JAVA_OPTS com.acme.App\n",
		}, false, ""},
		{"dockerfile -javaagent", map[string]string{
			"Dockerfile": `ENTRYPOINT ["java", "-javaagent:/otel.jar", "-jar", "/app.jar"]` + "\n",
		}, false, PartialReasonLaunchAgent},
		{"JAVA_TOOL_OPTIONS system class loader", map[string]string{
			".env": "JAVA_TOOL_OPTIONS=-Djava.system.class.loader=com.acme.Loader\n",
		}, false, PartialReasonLaunchOption},
		{"logging config class: unmapped framework ingress", map[string]string{
			"Dockerfile": "ENV JAVA_TOOL_OPTIONS=\"-Djava.util.logging.config.class=com.acme.Hidden\"\nENTRYPOINT exec java -jar /app.jar\n",
		}, true, PartialReasonLaunchOption},
		{"JAR manifest Launcher-Agent-Class", map[string]string{
			"target/app.jar": manifestJar("Manifest-Version: 1.0\r\nLauncher-Agent-Class: com.acme.Agent\r\n"),
		}, false, PartialReasonLaunchAgent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
			if tt.hidden {
				a.source("src/main/java/com/acme/Hidden.java", "package com.acme;\npublic class Hidden { public Hidden() {} }\n")
				a.class("target/classes", "com/acme/Hidden", func(b *cpb) []xmethod {
					return []xmethod{withFetch("<init>", "()V", accPublic)(b)}
				})
			}
			for rel, body := range tt.files {
				writeFileT(t, filepath.Join(a.build, filepath.FromSlash(rel)), body)
			}
			res := a.reach(netkitSinkID)
			if tt.reason == "" {
				if !slices.Equal(res.Searched, []string{netkitSinkID}) {
					t.Fatalf("inert launch options: Searched = %v, partiality %+v", res.Searched, res.Partiality)
				}
				return
			}
			if len(res.Searched) != 0 {
				t.Fatalf("Searched despite %s: %v", tt.reason, res.Searched)
			}
			if !hasReason(res.Partiality, tt.reason) {
				t.Errorf("missing %s: %+v", tt.reason, res.Partiality)
			}
		})
	}
}

// gradleApp is newApp's Gradle twin: a Java project whose build.gradle declares netkit (plus
// extra dependency lines), enforces locking and locks netkit, plus extra lockfile lines, on
// runtimeClasspath. netkit's JAR and POM sit in the build-local module cache. HOME is an empty
// directory so no machine cache answers for the build.
func gradleApp(t *testing.T, extraDeps, extraLocks string) *appFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	build := t.TempDir()
	writeFileT(t, filepath.Join(build, "settings.gradle"), "rootProject.name = 'app'\n")
	writeFileT(t, filepath.Join(build, "build.gradle"), "plugins {\n    id 'java'\n    id 'application'\n}\ndependencies {\n    implementation 'com.evil:netkit:1.0.0'\n"+extraDeps+"}\n"+
		"dependencyLocking { lockAllConfigurations() }\napplication { mainClass = 'com.acme.App' }\n")
	writeFileT(t, filepath.Join(build, "gradle.lockfile"), "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\n"+extraLocks+"empty=\n")
	b := &cpb{}
	jar := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}})
	gradleCacheArtifact(t, build, "com.evil", "netkit", "1.0.0", map[string][]byte{"com/evil/netkit/UrlFetcher.class": jar})
	return &appFixture{t: t, build: build}
}

// gradleCacheArtifact writes a dependency-free POM for group:artifact:version into the HOME
// Gradle module cache, where the lockfile inventory reads edges, and its JAR into the
// build-local module cache.
func gradleCacheArtifact(t *testing.T, build, group, artifact, version string, entries map[string][]byte) {
	t.Helper()
	rel := filepath.Join("caches", "modules-2", "files-2.1", group, artifact, version, "0123abcd")
	writeFileT(t, filepath.Join(os.Getenv("HOME"), ".gradle", rel, artifact+"-"+version+".pom"), "<project><modelVersion>4.0.0</modelVersion><groupId>"+group+
		"</groupId><artifactId>"+artifact+"</artifactId><version>"+version+"</version></project>")
	writeJarEntries(t, filepath.Join(build, ".gradle", rel, artifact+"-"+version+".jar"), entries)
}

// Graph and declaration reasons the closure carries withhold Searched on their own: a cached
// netkit whose own dependency's POM is not cached leaves netkit's subtree open, and a
// dependencies entry the scan cannot model (files()) puts unseen code on the classpath.
func TestBytecodeReach_ClosureReasonsWithholdSearched(t *testing.T) {
	mavenChild := func(childPOM bool) func(t *testing.T) *appFixture {
		return func(t *testing.T) *appFixture {
			a := newApp(t, "", false)
			repo := filepath.Join(a.build, ".m2", "repository")
			writeFileT(t, filepath.Join(repo, "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.pom"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version>
  <dependencies><dependency><groupId>com.evil</groupId><artifactId>child</artifactId><version>1</version></dependency></dependencies></project>`)
			b := &cpb{}
			writeJar(t, filepath.Join(repo, "com", "evil", "child", "1", "child-1.jar"), "com/evil/child/Child.class",
				emitClassX(b, "com/evil/child/Child", "java/lang/Object", 0x0021, []xmethod{{"run", "()V", accPublic, ret}}))
			if childPOM {
				writeFileT(t, filepath.Join(repo, "com", "evil", "child", "1", "child-1.pom"), `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.evil</groupId><artifactId>child</artifactId><version>1</version></project>`)
			}
			return a
		}
	}
	gradle := func(extraDeps string) func(t *testing.T) *appFixture {
		return func(t *testing.T) *appFixture { return gradleApp(t, extraDeps, "") }
	}
	tests := []struct {
		name   string
		build  func(t *testing.T) *appFixture
		out    string
		reason string // "" for a control, which stays Searched
	}{
		{"maven, child POM cached: searched", mavenChild(true), "target/classes", ""},
		{"maven, child POM uncached: maven_uncached_subtree", mavenChild(false), "target/classes", reasonMavenUncachedSubtree},
		{"gradle, locked: searched", gradle(""), "build/classes/java/main", ""},
		{"gradle, files() entry: gradle_unmodeled_dependency", gradle("    implementation files('libs/extra.jar')\n"), "build/classes/java/main", PartialReasonUnmodeledDependency},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.build(t)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class(tt.out, "com/acme/App", mainCalling(justReturn))
			res := a.reach(netkitSinkID)
			if tt.reason == "" {
				if !slices.Equal(res.Searched, []string{netkitSinkID}) {
					t.Fatalf("control: Searched = %v, partiality %+v", res.Searched, res.Partiality)
				}
				return
			}
			if len(res.Searched) != 0 {
				t.Fatalf("Searched despite %s: %v", tt.reason, res.Searched)
			}
			if !hasReason(res.Partiality, tt.reason) {
				t.Errorf("missing run-wide %s: %+v", tt.reason, res.Partiality)
			}
		})
	}
}

// libJar is com.dep:lib's JAR: a Lib with a no-op static run(), plus a second method when
// variant is set so two copies' bytes differ while both would answer the call.
func libJar(variant bool) map[string][]byte {
	methods := []xmethod{{"run", "()V", accPublicStatic, ret}}
	if variant {
		methods = append(methods, xmethod{"other", "()V", accPublicStatic, ret})
	}
	return map[string][]byte{"com/dep/lib/Lib.class": emitClassX(&cpb{}, "com/dep/lib/Lib", "java/lang/Object", 0x0021, methods)}
}

// callLib is invokestatic com/dep/lib/Lib.run()V; return.
func callLib(b *cpb) []byte {
	idx := b.mref("com/dep/lib/Lib", "run", "()V")
	return append([]byte{0xB8}, append(be2(idx), 0xB1)...)
}

// The search loads only the artifact the application runs with. main calls com.dep.lib's
// Lib.run, and every cached lib JAR answers it with a no-op: loading any of them on a row
// below would make the empty search Searched. A lib that is test-, processor- or kapt-only,
// ambiguous, a classifier variant, or held as differing cache copies stays unloaded, so the
// call is a hazard and the answer is undetermined. The unresolved-version case is
// TestBytecodeReach_UnresolvedVersionIsScopedAndRunWide: no JAR can be bound to it.
func TestBytecodeReach_RuntimeArtifactsWithholdSearched(t *testing.T) {
	const libPOM = `<project><modelVersion>4.0.0</modelVersion><groupId>com.dep</groupId><artifactId>lib</artifactId><version>1</version></project>`
	maven := func(depXML string, gradleCopy bool) func(t *testing.T) (*appFixture, string) {
		return func(t *testing.T) (*appFixture, string) {
			t.Setenv("HOME", t.TempDir())
			a := newApp(t, depXML, false)
			dir := filepath.Join(a.build, ".m2", "repository", "com", "dep", "lib", "1")
			writeFileT(t, filepath.Join(dir, "lib-1.pom"), libPOM)
			writeJarEntries(t, filepath.Join(dir, "lib-1.jar"), libJar(false))
			if gradleCopy {
				gradleCacheArtifact(t, a.build, "com.dep", "lib", "1", libJar(true))
			}
			return a, "target/classes"
		}
	}
	gradle := func(decl, locks string) func(t *testing.T) (*appFixture, string) {
		return func(t *testing.T) (*appFixture, string) {
			a := gradleApp(t, decl, locks)
			gradleCacheArtifact(t, a.build, "com.dep", "lib", "1", libJar(false))
			gradleCacheArtifact(t, a.build, "com.dep", "lib", "2", libJar(false))
			return a, "build/classes/java/main"
		}
	}
	const lib = `<dependency><groupId>com.dep</groupId><artifactId>lib</artifactId><version>1</version>`
	tests := []struct {
		name     string
		build    func(t *testing.T) (*appFixture, string)
		searched bool
	}{
		{"maven compile scope: loaded, searched", maven(lib+`</dependency>`, false), true},
		{"maven test scope", maven(lib+`<scope>test</scope></dependency>`, false), false},
		{"maven classifier variant", maven(lib+`<classifier>jdk8</classifier></dependency>`, false), false},
		{"maven, .m2 and Gradle cache copies differ", maven(lib+`</dependency>`, true), false},
		{"gradle runtimeClasspath: loaded, searched", gradle("    implementation 'com.dep:lib:1'\n", "com.dep:lib:1=compileClasspath,runtimeClasspath\n"), true},
		{"gradle testRuntimeClasspath only", gradle("    testImplementation 'com.dep:lib:1'\n", "com.dep:lib:1=testCompileClasspath,testRuntimeClasspath\n"), false},
		{"gradle annotationProcessor only", gradle("    annotationProcessor 'com.dep:lib:1'\n", "com.dep:lib:1=annotationProcessor\n"), false},
		// The Gradle allow-list admits no kapt declaration in a Java build (one makes the lock
		// unconfirmed, which withholds on its own), so this row carries only the lock line.
		{"gradle kapt only", gradle("", "com.dep:lib:1=kapt,kaptClasspath_kaptKotlin\n"), false},
		{"gradle two runtime versions", gradle("    implementation 'com.dep:lib:1'\n", "com.dep:lib:1=runtimeClasspath\ncom.dep:lib:2=runtimeClasspath\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, out := tt.build(t)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class(out, "com/acme/App", mainCalling(callLib))
			res := a.reach(netkitSinkID)
			if tt.searched {
				if !slices.Equal(res.Searched, []string{netkitSinkID}) {
					t.Fatalf("control: Searched = %v, partiality %+v", res.Searched, res.Partiality)
				}
				return
			}
			if len(res.Searched) != 0 {
				t.Fatalf("a non-runtime artifact answered the call: Searched = %v", res.Searched)
			}
			if !hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
				t.Errorf("missing reachability_undetermined: %+v", res.Partiality)
			}
			// A run-wide graph reason no scoped reason mirrors would withhold Searched before the
			// selection is ever tested.
			mirrored := map[string]bool{}
			for _, sr := range res.Partiality.Scoped {
				mirrored[sr.Reason] = true
			}
			for _, r := range res.Partiality.Reasons {
				if !mirrored[r] && (strings.HasPrefix(r, plugin.PartialReasonSourceUnpinned) || strings.HasPrefix(r, plugin.PartialReasonRelationshipUnexpressed)) {
					t.Errorf("row is withheld by %s, not by artifact selection: %+v", r, res.Partiality)
				}
			}
		})
	}
}

// editPOM rewrites the fixture pom.xml, failing when old is absent.
func (a *appFixture) editPOM(old, new string) {
	a.t.Helper()
	p := filepath.Join(a.build, "pom.xml")
	data, err := os.ReadFile(p)
	if err != nil {
		a.t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		a.t.Fatalf("pom.xml has no %q", old)
	}
	writeFileT(a.t, p, strings.Replace(string(data), old, new, 1))
}

const pomMainClass = `<mainClass>com.acme.App</mainClass>`

// callback writes a first-party class with the given ancestry and a no-op method, the shape
// of a class only a container calls.
func (a *appFixture) callback(owner, super string, ifaces ...string) {
	a.t.Helper()
	simple := owner[strings.LastIndex(owner, "/")+1:]
	a.source("src/main/java/"+owner+".java", "package com.acme;\npublic class "+simple+" { public void handle() {} }\n")
	a.classI("target/classes", owner, super, ifaces, 0x0021, func(b *cpb) []xmethod {
		return []xmethod{{"handle", "()V", accPublic, ret}}
	})
}

// A main licenses Searched only when the build names it as the launch entry and no other
// entry shape is present: an empty search from a trivial main says nothing about a filter,
// listener or war the container starts, or a dependency launcher that never calls main.
func TestBytecodeReach_LaunchEntryLicence(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(a *appFixture)
		reason string // "" for a control, which stays Searched
	}{
		{"build-named Main-Class: searched", func(*appFixture) {}, ""},
		{"Main-Class from a POM property: searched", func(a *appFixture) {
			a.editPOM(pomMainClass, `<mainClass>${app.main}</mainClass>`)
			a.editPOM(`<dependencies>`, `<properties><app.main>com.acme.App</app.main></properties><dependencies>`)
		}, ""},
		{"Spring Boot launcher with Start-Class: searched", func(a *appFixture) {
			a.editPOM(pomMainClass, "")
			writeFileT(t, filepath.Join(a.build, "src/main/resources/META-INF/MANIFEST.MF"),
				"Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.launch.JarLauncher\nStart-Class: com.acme.App\n")
		}, ""},
		{"no named entry: launch_entry_unnamed", func(a *appFixture) {
			a.editPOM(pomMainClass, "")
		}, reasonLaunchEntryUnnamed},
		{"javax Filter: container_callback", func(a *appFixture) {
			a.callback("com/acme/Gate", "java/lang/Object", "javax/servlet/Filter")
		}, reasonContainerCallback},
		{"javax ServletContextListener: container_callback", func(a *appFixture) {
			a.callback("com/acme/Boot", "java/lang/Object", "javax/servlet/ServletContextListener")
		}, reasonContainerCallback},
		{"jakarta Filter: container_callback", func(a *appFixture) {
			a.callback("com/acme/Gate", "java/lang/Object", "jakarta/servlet/Filter")
		}, reasonContainerCallback},
		{"jakarta session listener through a first-party base: container_callback", func(a *appFixture) {
			a.callback("com/acme/BaseListener", "java/lang/Object", "jakarta/servlet/http/HttpSessionListener")
			a.callback("com/acme/Sessions", "com/acme/BaseListener")
		}, reasonContainerCallback},
		{"JMS MessageListener: container_callback", func(a *appFixture) {
			a.callback("com/acme/Inbox", "java/lang/Object", "javax/jms/MessageListener")
		}, reasonContainerCallback},
		{"unreadable ancestor: container_callback", func(a *appFixture) {
			a.callback("com/acme/Hook", "com/other/Base")
		}, reasonContainerCallback},
		{"war packaging: war_packaging", func(a *appFixture) {
			a.editPOM(`<version>1.0.0</version>`, `<version>1.0.0</version><packaging>war</packaging>`)
		}, reasonWarPackaging},
		{"built .war: war_packaging", func(a *appFixture) {
			writeFileT(t, filepath.Join(a.build, "target", "app-1.0.0.war"), "")
		}, reasonWarPackaging},
		{"Vert.x Launcher with Main-Verticle: launch_entry_unmapped", func(a *appFixture) {
			a.editPOM(pomMainClass, `<manifestEntries><Main-Class>io.vertx.core.Launcher</Main-Class><Main-Verticle>com.acme.App</Main-Verticle></manifestEntries>`)
		}, reasonLaunchEntryUnmapped},
		{"shipped manifest naming a dependency launcher: launch_entry_unmapped", func(a *appFixture) {
			writeFileT(t, filepath.Join(a.build, "src/main/resources/META-INF/MANIFEST.MF"), "Manifest-Version: 1.0\nMain-Class: io.vertx.core.Launcher\n")
		}, reasonLaunchEntryUnmapped},
		{"Spring Boot launcher without Start-Class: launch_entry_unmapped", func(a *appFixture) {
			a.editPOM(pomMainClass, "")
			writeFileT(t, filepath.Join(a.build, "src/main/resources/META-INF/MANIFEST.MF"),
				"Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.JarLauncher\n")
		}, reasonLaunchEntryUnmapped},
		{"unresolved property: launch_entry_unmapped", func(a *appFixture) {
			a.editPOM(pomMainClass, `<mainClass>${start.class}</mainClass>`)
		}, reasonLaunchEntryUnmapped},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(justReturn))
			tt.setup(a)
			res := a.reach(netkitSinkID)
			if tt.reason == "" {
				if !slices.Equal(res.Searched, []string{netkitSinkID}) {
					t.Fatalf("control: Searched = %v, partiality %+v", res.Searched, res.Partiality)
				}
				return
			}
			if len(res.Searched) != 0 {
				t.Fatalf("Searched despite %s: %v", tt.reason, res.Searched)
			}
			if !hasReason(res.Partiality, tt.reason) {
				t.Errorf("missing run-wide %s: %+v", tt.reason, res.Partiality)
			}
		})
	}
}

// callStatic is invokestatic owner.name()V; return.
func callStatic(owner, name string) func(b *cpb) []byte {
	return func(b *cpb) []byte {
		idx := b.mref(owner, name, "()V")
		return append([]byte{0xB8}, append(be2(idx), 0xB1)...)
	}
}

// netkitRelease rewrites the netkit JAR with UrlFetcher, a base Util whose static run() is a
// no-op, and the extra entries given (multi-release overrides among them).
func (a *appFixture) netkitRelease(extra map[string][]byte) {
	a.t.Helper()
	b := &cpb{}
	entries := map[string][]byte{
		"com/evil/netkit/UrlFetcher.class": emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}}),
		"META-INF/MANIFEST.MF":             []byte("Manifest-Version: 1.0\nMulti-Release: true\n"),
	}
	b = &cpb{}
	entries["com/evil/netkit/Util.class"] = emitClassX(b, "com/evil/netkit/Util", "java/lang/Object", 0x0021, []xmethod{{"run", "()V", accPublicStatic, ret}})
	for k, v := range extra {
		entries[k] = v
	}
	writeJarEntries(a.t, filepath.Join(a.build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar"), entries)
}

// utilOverride is a META-INF/versions/11 Util with the given super class and run body.
func utilOverride(super string, run func(b *cpb) []byte, more ...xmethod) map[string][]byte {
	b := &cpb{}
	methods := append([]xmethod{{"run", "()V", accPublicStatic, run(b)}}, more...)
	return map[string][]byte{"META-INF/versions/11/com/evil/netkit/Util.class": emitClassX(b, "com/evil/netkit/Util", super, 0x0021, methods)}
}

// A JDK at release 11 or later runs a multi-release JAR's versions/11 body in place of the
// base class. The override is read and merged into the base, so a call only the override
// makes is a path; an override that cannot be merged soundly withholds Searched.
func TestBytecodeReach_MultiReleaseOverrides(t *testing.T) {
	tests := []struct {
		name   string
		extra  func() map[string][]byte
		call   string // the netkit class main calls run() on
		path   bool   // the sink is reached
		reason string // run-wide reason when withheld; "" with !path for a Searched control
	}{
		{"override reaching the sink: path", func() map[string][]byte {
			return utilOverride("java/lang/Object", callFetch)
		}, "com/evil/netkit/Util", true, ""},
		{"override not reaching the sink: searched", func() map[string][]byte {
			return utilOverride("java/lang/Object", justReturn, xmethod{"helper", "()V", 0x000A, ret})
		}, "com/evil/netkit/Util", false, ""},
		{"class only an override defines: path", func() map[string][]byte {
			b := &cpb{}
			return map[string][]byte{"META-INF/versions/9/com/evil/netkit/Extra.class": emitClassX(b, "com/evil/netkit/Extra", "java/lang/Object", 0x0021,
				[]xmethod{{"run", "()V", accPublicStatic, callFetch(b)}})}
		}, "com/evil/netkit/Extra", true, ""},
		{"override with another super class: multi_release_unmerged", func() map[string][]byte {
			return utilOverride("com/evil/netkit/UrlFetcher", justReturn)
		}, "com/evil/netkit/Util", false, reasonMultiReleaseUnmerged},
		{"one-sided method an ancestor declares: multi_release_unmerged", func() map[string][]byte {
			return utilOverride("java/lang/Object", justReturn, xmethod{"toString", "()Ljava/lang/String;", accPublic, []byte{0x01, 0xB0}})
		}, "com/evil/netkit/Util", false, reasonMultiReleaseUnmerged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.netkitRelease(tt.extra())
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(callStatic(tt.call, "run")))
			res := a.reach(netkitSinkID)
			switch {
			case tt.path:
				if len(res.Paths) != 1 || len(res.Searched) != 0 {
					t.Fatalf("want one path, got paths %+v searched %v (partiality %+v)", res.Paths, res.Searched, res.Partiality)
				}
			case tt.reason == "":
				if !slices.Equal(res.Searched, []string{netkitSinkID}) {
					t.Fatalf("control: Searched = %v, partiality %+v", res.Searched, res.Partiality)
				}
			default:
				if len(res.Searched) != 0 {
					t.Fatalf("Searched despite %s: %v", tt.reason, res.Searched)
				}
				if !hasReason(res.Partiality, tt.reason) || !hasScoped(res.Partiality, tt.reason, netkitPURL) {
					t.Errorf("missing run-wide and scoped %s: %+v", tt.reason, res.Partiality)
				}
			}
		})
	}
}

// A multi-release override in the first-party class output is not merged: it is a gap in the
// output, which withholds Searched.
func TestBytecodeReach_FirstPartyReleaseOverrideIsAGap(t *testing.T) {
	a := newApp(t, "", false)
	a.source("src/main/java/com/acme/App.java", appSource)
	a.class("target/classes", "com/acme/App", mainCalling(justReturn))
	a.class("target/classes/META-INF/versions/11", "com/acme/App", mainCalling(callFetch))
	res := a.reach(netkitSinkID)
	if len(res.Searched) != 0 {
		t.Fatalf("Searched with an unread first-party override: %v", res.Searched)
	}
	found := false
	for _, s := range res.Partiality.Scoped {
		if s.Reason == reasonFirstPartyBytecodeAbsent && strings.Contains(s.Path, "multi-release override not read") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing first_party_bytecode_absent for the override: %+v", res.Partiality.Scoped)
	}
}
