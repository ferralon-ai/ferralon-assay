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
	thisIdx := b.class(owner)
	superIdx := b.class(super)
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
	buf.Write(be2(0))
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
	b := &cpb{}
	data := emitClassX(b, owner, "java/lang/Object", 0x0021, methods(b))
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
