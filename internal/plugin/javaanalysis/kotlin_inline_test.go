package javaanalysis

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// kotlin_inline_test.go — a Java app on a Kotlin library whose advisory names an `inline fun`.
// kotlinc copies an inline body into each caller, so the library code the app calls holds no
// invoke of the sink, yet the sink's own JAR keeps a concrete method. Only the declaring
// class's @kotlin.Metadata says the method is inline.

// Class payloads (k=1): a string table of two records read from d2, then a Class with fq_name
// d2[0] and one Function named d2[1], flags 1030 (IS_INLINE, bit 10, over kotlinc's default 6)
// or the default 6.
var (
	inlineFetchD1 = []byte{0x04, 0x0A, 0x02, 0x08, 0x02, 0x18, 0x00, 0x4A, 0x05, 0x48, 0x86, 0x08, 0x10, 0x01}
	plainFetchD1  = []byte{0x04, 0x0A, 0x02, 0x08, 0x02, 0x18, 0x00, 0x4A, 0x04, 0x48, 0x06, 0x10, 0x01}
)

// kotlinD1 is a d1 payload as kotlinc writes it in UTF-8 mode: a U+0000 marker, then one
// char per byte, in the constant pool's modified UTF-8 (U+0000 as C0 80).
func kotlinD1(payload []byte) string {
	var b bytes.Buffer
	b.WriteString("\xc0\x80")
	for _, c := range payload {
		switch {
		case c == 0:
			b.WriteString("\xc0\x80")
		case c < 0x80:
			b.WriteByte(c)
		default:
			b.WriteByte(0xC0 | c>>6)
			b.WriteByte(0x80 | c&0x3F)
		}
	}
	return b.String()
}

// kotlinUrlFetcher is UrlFetcher with a concrete fetch and @kotlin.Metadata(k = 1, mv = {2, 2, 0}, d1, d2).
// emitClassX ends with an empty class attributes table; the metadata replaces it, its
// constants interned before the class is emitted.
func kotlinUrlFetcher(d1 []byte) []byte {
	b := &cpb{}
	rvaName := b.utf8("RuntimeVisibleAnnotations")
	var anno bytes.Buffer
	anno.Write(be2(1))
	anno.Write(be2(b.utf8("Lkotlin/Metadata;")))
	anno.Write(be2(4))
	anno.Write(be2(b.utf8("k")))
	anno.WriteByte('I')
	anno.Write(be2(b.add("int:1", append([]byte{3}, be4(1)...))))
	anno.Write(be2(b.utf8("mv")))
	anno.WriteByte('[')
	anno.Write(be2(3))
	for _, v := range []uint32{2, 2, 0} {
		anno.WriteByte('I')
		anno.Write(be2(b.add(fmt.Sprintf("int:%d", v), append([]byte{3}, be4(v)...))))
	}
	for _, arr := range []struct {
		name string
		vals []string
	}{{"d1", []string{kotlinD1(d1)}}, {"d2", []string{"com/evil/netkit/UrlFetcher", "fetch"}}} {
		anno.Write(be2(b.utf8(arr.name)))
		anno.WriteByte('[')
		anno.Write(be2(uint16(len(arr.vals))))
		for _, v := range arr.vals {
			anno.WriteByte('s')
			anno.Write(be2(b.utf8(v)))
		}
	}
	data := emitClassX(b, "com/evil/netkit/UrlFetcher", "java/lang/Object", 0x0021, []xmethod{{"fetch", fetchDesc, accPublic, ret}})
	data = append(data[:len(data)-2], be2(1)...)
	data = append(data, be2(rvaName)...)
	data = append(data, be4(uint32(anno.Len()))...)
	return append(data, anno.Bytes()...)
}

// main calls com.dep.lib's Lib.run, standing in for the Kotlin library function whose body
// holds the inlined copy of fetch: it invokes nothing.
func TestBytecodeReach_KotlinInlineSinkIsNeverSearched(t *testing.T) {
	tests := []struct {
		name     string
		d1       []byte // nil: UrlFetcher carries no metadata
		searched bool
	}{
		{name: "no metadata (javac-compiled): searched", searched: true},
		{name: "metadata, fetch not inline: searched", d1: plainFetchD1, searched: true},
		{name: "metadata marks fetch inline: withheld", d1: inlineFetchD1},
		{name: "undecodable metadata: withheld", d1: inlineFetchD1[:10]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			if tt.d1 != nil {
				writeJar(t, netkitJarPath(a.build), "com/evil/netkit/UrlFetcher.class", kotlinUrlFetcher(tt.d1))
			}
			jar := filepath.Join(a.build, ".m2", "repository", "com", "dep", "lib", "1", "lib-1.jar")
			writeJarEntries(t, jar, libJar())
			a.dep(graphDep{group: "com.dep", artifact: "lib", version: "1", scope: "compile", jar: jar})
			a.source("src/main/java/com/acme/App.java", appSource)
			a.class("target/classes", "com/acme/App", mainCalling(callLib))

			res := a.reach(netkitSinkID)
			if len(res.Paths) != 0 {
				t.Fatalf("paths = %+v, want none", res.Paths)
			}
			if got := slices.Contains(res.Searched, netkitSinkID); got != tt.searched {
				t.Fatalf("searched = %v, want %v (partiality %+v)", res.Searched, tt.searched, res.Partiality)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined); got == tt.searched {
				t.Fatalf("reachability_undetermined = %v, want %v (partiality %+v)", got, !tt.searched, res.Partiality)
			}
		})
	}
}
