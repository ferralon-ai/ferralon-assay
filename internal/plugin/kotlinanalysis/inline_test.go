package kotlinanalysis

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// inline_test.go — an advisory naming a Kotlin `inline fun` in a dependency. kotlinc copies
// an inline body into each caller, so no caller invokes it, yet the declaring JAR still holds
// a concrete method. Only the declaring class's @kotlin.Metadata says the method is inline.

const (
	inlineLibClass = "com/evil/inl/GKt"
	inlineSink     = inlineLibClass + ".g()V"
	inlineUserLib  = "com/acme/a/AKt"
	cpIntegerTag   = 3
)

// kotlinD1 is a d1 payload as kotlinc writes it in UTF-8 mode: a U+0000 marker, then one
// char per byte, each string in the constant pool's modified UTF-8.
func kotlinD1(payload []byte) []string {
	units := []uint16{0}
	for _, c := range payload {
		units = append(units, uint16(c))
	}
	var b strings.Builder
	for _, r := range utf16.Decode(units) {
		if r == 0 {
			b.WriteString("\xc0\x80")
			continue
		}
		b.WriteRune(r)
	}
	return []string{b.String()}
}

// Package payloads (k=2): a one-record string table, then one Function named d2[0] with
// flags 1030 (IS_INLINE, bit 10, over kotlinc's default 6) or the default 6.
var (
	inlineFunctionD1 = []byte{0x02, 0x0A, 0x00, 0x1A, 0x05, 0x48, 0x86, 0x08, 0x10, 0x00}
	plainFunctionD1  = []byte{0x02, 0x0A, 0x00, 0x1A, 0x04, 0x48, 0x06, 0x10, 0x00}
)

// addKotlinMetadata attaches @kotlin.Metadata(k = kind, d1 = d1, d2 = d2).
func (b *kclassBuilder) addKotlinMetadata(kind int32, d1, d2 []string) {
	out := append(be2(b.utf8("Lkotlin/Metadata;")), be2(3)...)
	k := b.add("int:k", append([]byte{cpIntegerTag}, be4(uint32(kind))...))
	out = append(append(append(out, be2(b.utf8("k"))...), 'I'), be2(k)...)
	for _, arr := range []struct {
		name string
		vals []string
	}{{"d1", d1}, {"d2", d2}} {
		out = append(append(append(out, be2(b.utf8(arr.name))...), '['), be2(uint16(len(arr.vals)))...)
		for _, v := range arr.vals {
			out = append(append(out, 's'), be2(b.utf8(v))...)
		}
	}
	b.rawClassAnnos = append(b.rawClassAnnos, out)
}

// inlineBuild: main calls dep A's AKt.f; f's body is the inlined copy of dep B's g, so it
// holds no invoke of g. Dep B declares g concretely; meta, when set, attaches its metadata.
func inlineBuild(t *testing.T, meta func(b *kclassBuilder)) string {
	t.Helper()
	dir := t.TempDir()
	writeBuildFile(t, dir, "build.gradle.kts", `
dependencies {
    implementation("com.acme:a:1.0")
    implementation("com.evil:inl:1.0")
}
`)
	lib := newKClassBuilder()
	lib.addMethod("g", "()V", []byte{opReturn})
	if meta != nil {
		meta(lib)
	}
	writeGradleCacheJar(t, dir, "com.evil", "inl", "1.0", map[string][]byte{
		inlineLibClass: lib.build(inlineLibClass, "java/lang/Object"),
	})
	user := newKClassBuilder()
	user.addMethod("f", "()V", []byte{opReturn})
	writeGradleCacheJar(t, dir, "com.acme", "a", "1.0", map[string][]byte{
		inlineUserLib: user.build(inlineUserLib, "java/lang/Object"),
	})
	writeMain(t, dir, func(b *kclassBuilder) []byte { return b.invokeStatic(inlineUserLib, "f", "()V") })
	return dir
}

func TestReachability_InlineSinkIsNeverSearched(t *testing.T) {
	tests := []struct {
		name         string
		meta         func(b *kclassBuilder)
		wantSearched bool
	}{{
		name:         "no metadata (javac-compiled): searched",
		wantSearched: true,
	}, {
		name:         "metadata, g not inline: searched",
		meta:         func(b *kclassBuilder) { b.addKotlinMetadata(2, kotlinD1(plainFunctionD1), []string{"g"}) },
		wantSearched: true,
	}, {
		name: "metadata marks g inline: withheld",
		meta: func(b *kclassBuilder) { b.addKotlinMetadata(2, kotlinD1(inlineFunctionD1), []string{"g"}) },
	}, {
		name: "undecodable metadata: withheld",
		meta: func(b *kclassBuilder) { b.addKotlinMetadata(2, kotlinD1(inlineFunctionD1[:7]), []string{"g"}) },
	}, {
		name: "multifile facade whose part is not loaded: withheld",
		meta: func(b *kclassBuilder) { b.addKotlinMetadata(4, []string{"com/evil/inl/GKt__Part"}, nil) },
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := reach(t, inlineBuild(t, tt.meta), inlineSink)
			if len(res.Paths) != 0 {
				t.Fatalf("paths = %+v, want none", res.Paths)
			}
			if got := slices.Contains(res.Searched, inlineSink); got != tt.wantSearched {
				t.Fatalf("searched = %v, want %v (reasons %v)", res.Searched, tt.wantSearched, res.Partiality.Reasons)
			}
			undetermined := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonReachabilityUndetermined)
			if undetermined == tt.wantSearched {
				t.Fatalf("reasons = %v, want reachability_undetermined %v", res.Partiality.Reasons, !tt.wantSearched)
			}
		})
	}
}
