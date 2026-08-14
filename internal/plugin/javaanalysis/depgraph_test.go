package javaanalysis

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
)

// --- compact .class emitter: enough JVMS §4 to build a fixture dependency JAR of
// real bytecode without a JRE (a reduced sibling of the classfile package's own
// test builder, scoped to one class with several methods). ---

func be2(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func be4(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

type cpb struct {
	entries [][]byte
	intern  map[string]uint16
}

func (b *cpb) add(key string, raw []byte) uint16 {
	if b.intern == nil {
		b.intern = map[string]uint16{}
	}
	if idx, ok := b.intern[key]; ok {
		return idx
	}
	b.entries = append(b.entries, raw)
	idx := uint16(len(b.entries))
	b.intern[key] = idx
	return idx
}
func (b *cpb) utf8(s string) uint16 {
	return b.add("u:"+s, append(append([]byte{1}, be2(uint16(len(s)))...), []byte(s)...))
}
func (b *cpb) class(n string) uint16 { return b.add("c:"+n, append([]byte{7}, be2(b.utf8(n))...)) }
func (b *cpb) nt(name, desc string) uint16 {
	return b.add("nt:"+name+desc, append(append([]byte{12}, be2(b.utf8(name))...), be2(b.utf8(desc))...))
}
func (b *cpb) mref(owner, name, desc string) uint16 {
	return b.add("m:"+owner+name+desc, append(append([]byte{10}, be2(b.class(owner))...), be2(b.nt(name, desc))...))
}

type mspec struct {
	name, desc string
	code       []byte
}

// emitClass builds a valid .class for owner extending java/lang/Object with the
// given methods.
func emitClass(b *cpb, owner string, methods []mspec) []byte {
	thisIdx := b.class(owner)
	superIdx := b.class("java/lang/Object")
	codeAttr := b.utf8("Code")
	type built struct {
		nameIdx, descIdx uint16
		code             []byte
	}
	bm := make([]built, len(methods))
	for i, m := range methods {
		bm[i] = built{b.utf8(m.name), b.utf8(m.desc), m.code}
	}

	var buf bytes.Buffer
	buf.Write(be4(0xCAFEBABE))
	buf.Write(be2(0))
	buf.Write(be2(52))
	buf.Write(be2(uint16(len(b.entries) + 1)))
	for _, e := range b.entries {
		buf.Write(e)
	}
	buf.Write(be2(0x0021))
	buf.Write(be2(thisIdx))
	buf.Write(be2(superIdx))
	buf.Write(be2(0)) // interfaces
	buf.Write(be2(0)) // fields
	buf.Write(be2(uint16(len(methods))))
	for _, m := range bm {
		buf.Write(be2(0x0001))
		buf.Write(be2(m.nameIdx))
		buf.Write(be2(m.descIdx))
		buf.Write(be2(1)) // one attribute (Code)
		var code bytes.Buffer
		code.Write(be2(8)) // max_stack
		code.Write(be2(8)) // max_locals
		code.Write(be4(uint32(len(m.code))))
		code.Write(m.code)
		code.Write(be2(0)) // exception_table_length
		code.Write(be2(0)) // Code attributes
		buf.Write(be2(codeAttr))
		buf.Write(be4(uint32(code.Len())))
		buf.Write(code.Bytes())
	}
	buf.Write(be2(0)) // class attributes
	return buf.Bytes()
}

// writeJar packages one class file into a JAR at path.
func writeJar(t *testing.T, path, entryName string, classBytes []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(entryName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(classBytes); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

const netkitPom = `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version>
    </dependency>
  </dependencies>
</project>`

// buildNetkitFixture writes a build dir with a pom declaring com.evil:netkit:1.0.0
// and (unless omitJar) a project-local Maven cache holding a real-bytecode
// netkit-1.0.0.jar whose UrlFetcher has a String SSRF sink, a method that reaches
// it, and one that does not.
func buildNetkitFixture(t *testing.T, omitJar bool) string {
	t.Helper()
	build := t.TempDir()
	if err := os.WriteFile(filepath.Join(build, "pom.xml"), []byte(netkitPom), 0o644); err != nil {
		t.Fatal(err)
	}
	if omitJar {
		return build
	}
	b := &cpb{}
	sink := b.mref("com/evil/netkit/UrlFetcher", "fetch", "(Ljava/lang/String;)Ljava/lang/String;")
	classBytes := emitClass(b, "com/evil/netkit/UrlFetcher", []mspec{
		{"fetch", "(Ljava/lang/String;)Ljava/lang/String;", []byte{0xB1}},                           // sink: leaf
		{"entry", "()V", append(append([]byte{0x2a}, append([]byte{0xB6}, be2(sink)...)...), 0xB1)}, // aload_0; invokevirtual fetch; return
		{"safe", "()V", []byte{0xB1}}, // return only: never calls the sink
	})
	jarPath := filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar")
	writeJar(t, jarPath, "com/evil/netkit/UrlFetcher.class", classBytes)
	return build
}

func TestBuildDependencyGraph_OpensJarAndAnswersPoNE(t *testing.T) {
	build := buildNetkitFixture(t, false)
	dg, err := buildDependencyGraph(context.Background(), build)
	if err != nil {
		t.Fatalf("buildDependencyGraph: %v", err)
	}
	if !dg.Complete {
		t.Fatalf("want complete dependency closure, got gaps: %v", dg.Gaps)
	}
	sink := classfile.MethodRef{Owner: "com/evil/netkit/UrlFetcher", Name: "fetch", Descriptor: "(Ljava/lang/String;)Ljava/lang/String;"}
	entry := classfile.MethodRef{Owner: "com/evil/netkit/UrlFetcher", Name: "entry", Descriptor: "()V"}
	safe := classfile.MethodRef{Owner: "com/evil/netkit/UrlFetcher", Name: "safe", Descriptor: "()V"}

	if v := dg.Engine.Reach(entry, sink).Verdict; v != depreach.ReachableCandidate {
		t.Errorf("entry->sink over the opened JAR: want reachable_candidate, got %s", v)
	}
	if v := dg.Engine.Reach(safe, sink).Verdict; v != depreach.NotExploitable {
		t.Errorf("safe->sink over the opened JAR: want not_exploitable, got %s", v)
	}
}

// An uncached dependency is a Gap, never a silent complete graph: a not_exploitable
// must not be claimed while the sink could live in a JAR we never opened.
func TestBuildDependencyGraph_UncachedDependencyIsAGap(t *testing.T) {
	build := buildNetkitFixture(t, true) // pom declares netkit, but no JAR in cache
	dg, err := buildDependencyGraph(context.Background(), build)
	if err != nil {
		t.Fatalf("buildDependencyGraph: %v", err)
	}
	if dg.Complete {
		t.Fatal("want incomplete closure when the declared JAR is not cached")
	}
	var sawNetkit bool
	for _, g := range dg.Gaps {
		if strings.Contains(g, "com.evil:netkit") && strings.Contains(g, "not in local cache") {
			sawNetkit = true
		}
	}
	if !sawNetkit {
		t.Errorf("gap for the uncached netkit JAR not recorded: %v", dg.Gaps)
	}
}
