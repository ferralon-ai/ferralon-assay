package kotlinanalysis

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// classemit_test.go — a deterministic minimal JVM .class emitter (K6 §1), built for the
// SAME reason javaanalysis/classfile's own test suite has one: no `kotlinc` (or any JVM
// toolchain) is present in this environment, so a genuine end-to-end fixture cannot be
// compiled. What CAN be done hermetically is emit valid JVMS §4 bytes directly — this
// gives real coverage through the actual classfile.ParseClass parser and the real
// depreach engine, not just hand-built classfile.Class structs.
//
// This mirrors internal/plugin/javaanalysis/classfile/classfile_test.go's classBuilder
// (that one is a package-internal test helper, unexported and unreachable from here) but
// is extended to emit MULTIPLE methods per class and MULTIPLE classes per program, which
// K6's reachability fixtures need (an ingress method calling a sink method, sometimes in
// a different class, sometimes not at all).
//
// Only the JVMS §4 constant-pool tags and opcodes this emitter actually uses are named
// here (classfile's tag/opcode constants are unexported, so they cannot be imported).

const (
	cpUtf8Tag       = 1
	cpClassTag      = 7
	cpNameAndType   = 12
	cpMethodrefTag  = 10
	opInvokeStatic  = 0xB8
	opReturn        = 0xB1
	accPublic       = 0x0001
	accPublicSuper  = 0x0021
	classMajorJava8 = 52
)

func be2(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func be4(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

// kclassBuilder accumulates constant-pool entries and methods for one emitted .class
// file. Only single-slot constants are used (no long/double), so every interned entry
// occupies exactly one pool slot — matching classfile_test.go's builder.
type kclassBuilder struct {
	entries    [][]byte
	intern     map[string]uint16
	methods    []kbuiltMethod
	classAnnos []kannotation
}

type kbuiltMethod struct {
	nameIdx, descIdx uint16
	code             []byte
	annos            []kannotation
}

// kannotation is a RuntimeVisibleAnnotations entry to emit: its type descriptor and any
// string-valued element pairs (the only element kind the Spring-ingress layer reads).
type kannotation struct {
	descriptor string
	elements   []kannoElem
}

type kannoElem struct{ name, value string }

func newKClassBuilder() *kclassBuilder { return &kclassBuilder{intern: map[string]uint16{}} }

func (b *kclassBuilder) add(key string, raw []byte) uint16 {
	if idx, ok := b.intern[key]; ok {
		return idx
	}
	b.entries = append(b.entries, raw)
	idx := uint16(len(b.entries)) // 1-indexed
	b.intern[key] = idx
	return idx
}

func (b *kclassBuilder) utf8(s string) uint16 {
	raw := append([]byte{cpUtf8Tag}, be2(uint16(len(s)))...)
	raw = append(raw, []byte(s)...)
	return b.add("utf8:"+s, raw)
}

func (b *kclassBuilder) class(name string) uint16 {
	ni := b.utf8(name)
	return b.add("class:"+name, append([]byte{cpClassTag}, be2(ni)...))
}

func (b *kclassBuilder) nameType(name, desc string) uint16 {
	ni, di := b.utf8(name), b.utf8(desc)
	raw := append([]byte{cpNameAndType}, be2(ni)...)
	raw = append(raw, be2(di)...)
	return b.add("nt:"+name+"|"+desc, raw)
}

// methodref interns a Methodref (invokestatic's operand kind).
func (b *kclassBuilder) methodref(owner, name, desc string) uint16 {
	ci, nt := b.class(owner), b.nameType(name, desc)
	raw := append([]byte{cpMethodrefTag}, be2(ci)...)
	raw = append(raw, be2(nt)...)
	return b.add("mref:"+owner+"."+name+desc, raw)
}

// invokeStatic encodes one `invokestatic <owner>.<name><desc>` instruction referencing a
// Methodref this builder has already interned.
func (b *kclassBuilder) invokeStatic(owner, name, desc string) []byte {
	idx := b.methodref(owner, name, desc)
	return append([]byte{opInvokeStatic}, be2(idx)...)
}

// addMethod registers a method with the given raw Code bytecode (no explicit return
// appended — callers supply their own `return`/`areturn`/etc.).
func (b *kclassBuilder) addMethod(name, desc string, code []byte) {
	b.methods = append(b.methods, kbuiltMethod{nameIdx: b.utf8(name), descIdx: b.utf8(desc), code: code})
}

// anno interns the constants a RuntimeVisibleAnnotations entry needs (its type descriptor
// and every element name/value) and returns the entry — all interning happens before
// build writes the constant-pool count, so no index shifts later.
func (b *kclassBuilder) anno(descriptor string, elems ...kannoElem) kannotation {
	b.utf8(descriptor)
	for _, e := range elems {
		b.utf8(e.name)
		b.utf8(e.value)
	}
	return kannotation{descriptor: descriptor, elements: elems}
}

// addClassAnnotation attaches a class-level annotation (e.g. @RestController).
func (b *kclassBuilder) addClassAnnotation(a kannotation) {
	b.classAnnos = append(b.classAnnos, a)
}

// addMethodAnnotated registers a method carrying one or more annotations (e.g.
// @GetMapping("/x")) alongside its Code.
func (b *kclassBuilder) addMethodAnnotated(name, desc string, code []byte, annos ...kannotation) {
	b.methods = append(b.methods, kbuiltMethod{nameIdx: b.utf8(name), descIdx: b.utf8(desc), code: code, annos: annos})
}

// encodeAnnotations emits a RuntimeVisibleAnnotations attribute body (num_annotations
// then each annotation) for the given entries. Every referenced utf8 was interned by
// anno(), so the lookups here add no new constants.
func (b *kclassBuilder) encodeAnnotations(annos []kannotation) []byte {
	var body bytes.Buffer
	body.Write(be2(uint16(len(annos))))
	for _, a := range annos {
		body.Write(be2(b.utf8(a.descriptor)))
		body.Write(be2(uint16(len(a.elements))))
		for _, e := range a.elements {
			body.Write(be2(b.utf8(e.name)))
			body.WriteByte('s') // string element_value tag
			body.Write(be2(b.utf8(e.value)))
		}
	}
	return body.Bytes()
}

// build emits the complete .class bytes for thisClass/superClass with every method
// registered via addMethod. All builder interning must happen before build (methodref
// indices referenced by earlier addMethod calls must already be assigned).
func (b *kclassBuilder) build(thisClass, superClass string) []byte {
	codeAttr := b.utf8("Code")
	// Intern the RuntimeVisibleAnnotations name only when some entry needs it, so a class
	// with no annotations emits a byte-for-byte identical constant pool as before.
	needRVA := len(b.classAnnos) > 0
	for _, m := range b.methods {
		if len(m.annos) > 0 {
			needRVA = true
		}
	}
	var rvaAttr uint16
	if needRVA {
		rvaAttr = b.utf8("RuntimeVisibleAnnotations")
	}
	thisIdx := b.class(thisClass)
	superIdx := b.class(superClass)

	var buf bytes.Buffer
	buf.Write(be4(0xCAFEBABE))
	buf.Write(be2(0))               // minor_version
	buf.Write(be2(classMajorJava8)) // major_version
	buf.Write(be2(uint16(len(b.entries) + 1)))
	for _, e := range b.entries {
		buf.Write(e)
	}
	buf.Write(be2(accPublicSuper))
	buf.Write(be2(thisIdx))
	buf.Write(be2(superIdx))
	buf.Write(be2(0)) // interfaces_count
	buf.Write(be2(0)) // fields_count
	buf.Write(be2(uint16(len(b.methods))))
	for _, m := range b.methods {
		var codeBody bytes.Buffer
		codeBody.Write(be2(16)) // max_stack
		codeBody.Write(be2(16)) // max_locals
		codeBody.Write(be4(uint32(len(m.code))))
		codeBody.Write(m.code)
		codeBody.Write(be2(0)) // exception_table_length
		codeBody.Write(be2(0)) // Code attributes_count

		buf.Write(be2(accPublic))
		buf.Write(be2(m.nameIdx))
		buf.Write(be2(m.descIdx))
		attrCount := 1
		if len(m.annos) > 0 {
			attrCount = 2
		}
		buf.Write(be2(uint16(attrCount))) // method attributes_count
		buf.Write(be2(codeAttr))
		buf.Write(be4(uint32(codeBody.Len())))
		buf.Write(codeBody.Bytes())
		if len(m.annos) > 0 {
			body := b.encodeAnnotations(m.annos)
			buf.Write(be2(rvaAttr))
			buf.Write(be4(uint32(len(body))))
			buf.Write(body)
		}
	}
	if len(b.classAnnos) > 0 {
		body := b.encodeAnnotations(b.classAnnos)
		buf.Write(be2(1)) // class attributes_count
		buf.Write(be2(rvaAttr))
		buf.Write(be4(uint32(len(body))))
		buf.Write(body)
	} else {
		buf.Write(be2(0)) // class attributes_count
	}
	return buf.Bytes()
}

// writeClassFixture writes an emitted .class under buildDir's conventional Gradle Kotlin
// output root (build/classes/kotlin/main/<internalName>.class), creating parent dirs as
// needed — the same layout firstPartyLoad walks (buildoutput.go firstPartyClassRoots).
func writeClassFixture(t *testing.T, buildDir, internalName string, data []byte) {
	t.Helper()
	path := filepath.Join(buildDir, "build", "classes", "kotlin", "main", internalName+".class")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture class: %v", err)
	}
}

// ---- K6 §2 reachability fixtures, driven through the REAL parser + depreach engine ----

// TestReachability_Fixture_ReachableEmitsOrderedPath is the reachable case (§8 row 8): a
// first-party entry (`main`) invokestatic-calls a "vulnerable dependency" symbol directly.
// depreach must find the path and Reachability must emit it, Complete (no hazard, no
// partiality) since nothing dynamic or out-of-classpath is on the frontier.
func TestReachability_Fixture_ReachableEmitsOrderedPath(t *testing.T) {
	dir := t.TempDir()

	main := newKClassBuilder()
	mainCode := main.invokeStatic("com/example/VulnKt", "sink", "()V")
	mainCode = append(mainCode, opReturn)
	main.addMethod("main", "()V", mainCode)
	writeClassFixture(t, dir, "com/example/MainKt", main.build("com/example/MainKt", "java/lang/Object"))

	vuln := newKClassBuilder()
	vuln.addMethod("sink", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/VulnKt", vuln.build("com/example/VulnKt", "java/lang/Object"))

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{"com/example/VulnKt.sink()V"},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if !res.Partiality.Complete {
		t.Fatalf("reachable case declared partiality it should not have: %+v", res.Partiality)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want exactly 1 reach path, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Ingress.Name != "main" {
		t.Errorf("path ingress = %+v, want Name=main", p.Ingress)
	}
	if p.Sink.Name != "sink" {
		t.Errorf("path sink = %+v, want Name=sink", p.Sink)
	}
	if len(p.Trace) < 2 || p.Trace[0].Name != "main" || p.Trace[len(p.Trace)-1].Name != "sink" {
		t.Errorf("path trace not ordered ingress->sink: %+v", p.Trace)
	}
}

// TestReachability_Fixture_UnreachableIsCompleteAndEmpty is the negative control V2
// needs (§8 row 10): the sink symbol genuinely exists in the compiled program, but no
// call edge from any ingress reaches it (main calls a sibling method instead). depreach
// must report a hazard-free empty search (NotExploitable), and Reachability must render
// that as Complete with zero paths — DISTINGUISHABLE from every failure mode, which is
// always Partiality.Complete == false.
func TestReachability_Fixture_UnreachableIsCompleteAndEmpty(t *testing.T) {
	dir := t.TempDir()

	main := newKClassBuilder()
	mainCode := main.invokeStatic("com/example/VulnKt", "other", "()V")
	mainCode = append(mainCode, opReturn)
	main.addMethod("main", "()V", mainCode)
	writeClassFixture(t, dir, "com/example/MainKt", main.build("com/example/MainKt", "java/lang/Object"))

	vuln := newKClassBuilder()
	vuln.addMethod("other", "()V", []byte{opReturn})
	vuln.addMethod("sink", "()V", []byte{opReturn}) // present, but never called from main
	writeClassFixture(t, dir, "com/example/VulnKt", vuln.build("com/example/VulnKt", "java/lang/Object"))

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{"com/example/VulnKt.sink()V"},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if !res.Partiality.Complete {
		t.Fatalf("unreachable-but-present sink must be a sound Complete result (negative control), got partiality: %+v", res.Partiality)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("want zero reach paths for a genuinely unreached sink, got %d: %+v", len(res.Paths), res.Paths)
	}
}

// TestReachability_Fixture_ToolUnavailableIsHonestPartiality is the tool-unavailable case
// (§8 row 11 / honest-absent): a build dir with no compiled .class output at all. This
// must NEVER be conflated with the negative control above — it declares
// tool_failure:no_build_output and Partiality.Complete == false, whereas the negative
// control declares Complete == true with zero paths. The two must be distinguishable by
// Partiality alone, which is exactly what V2's failure-mode matrix requires.
func TestReachability_Fixture_ToolUnavailableIsHonestPartiality(t *testing.T) {
	dir := t.TempDir()
	// A Kotlin source file with no compiled output: present-but-uncompiled, the
	// tool-unavailable frontier (distinct from a nonexistent build dir, which is a
	// hard error per loadProgram).
	if err := os.WriteFile(filepath.Join(dir, "Main.kt"), []byte("fun main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{"com/example/VulnKt.sink()V"},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if res.Partiality.Complete {
		t.Fatal("tool-unavailable case rendered Complete: honest-absent violated")
	}
	if !hasReason(res.Partiality, partialReasonNoBuildOutput) {
		t.Fatalf("partiality reasons %v missing %q", res.Partiality.Reasons, partialReasonNoBuildOutput)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("tool-unavailable case must carry no paths, got %d", len(res.Paths))
	}
}
