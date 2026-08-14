package classfile

import (
	"archive/zip"
	"bytes"
	"errors"
	"testing"
)

// ---- classfile builder: emits valid JVMS §4 bytes without a JRE ----
//
// The parser must be tested on genuine classfile bytes, but no JVM is present to
// compile a fixture. So the tests synthesize the bytes directly through a
// constant-pool-managing builder — which also documents the JVMS §4 layout the
// parser decodes. Only single-slot constants are used (no long/double), so every
// interned entry occupies exactly one pool slot.

func be2(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func be4(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

type classBuilder struct {
	entries [][]byte // raw cp entry bytes; entries[i] is pool slot i+1 (1-indexed)
	intern  map[string]uint16
}

func newClassBuilder() *classBuilder { return &classBuilder{intern: map[string]uint16{}} }

func (b *classBuilder) add(key string, raw []byte) uint16 {
	if idx, ok := b.intern[key]; ok {
		return idx
	}
	b.entries = append(b.entries, raw)
	idx := uint16(len(b.entries)) // 1-indexed
	b.intern[key] = idx
	return idx
}

func (b *classBuilder) utf8(s string) uint16 {
	raw := append([]byte{cpUtf8}, be2(uint16(len(s)))...)
	raw = append(raw, []byte(s)...)
	return b.add("utf8:"+s, raw)
}

func (b *classBuilder) class(name string) uint16 {
	ni := b.utf8(name)
	return b.add("class:"+name, append([]byte{cpClass}, be2(ni)...))
}

func (b *classBuilder) nameType(name, desc string) uint16 {
	ni, di := b.utf8(name), b.utf8(desc)
	raw := append([]byte{cpNameAndType}, be2(ni)...)
	raw = append(raw, be2(di)...)
	return b.add("nt:"+name+"|"+desc, raw)
}

// methodref interns a Methodref (cpTag 10) or InterfaceMethodref (cpTag 11).
func (b *classBuilder) methodref(cpTag byte, owner, name, desc string) uint16 {
	ci, nt := b.class(owner), b.nameType(name, desc)
	raw := append([]byte{cpTag}, be2(ci)...)
	raw = append(raw, be2(nt)...)
	return b.add(string(cpTag)+":mref:"+owner+"."+name+desc, raw)
}

// fieldref interns a Fieldref (cpTag 9), the operand of getstatic/putstatic.
func (b *classBuilder) fieldref(owner, name, desc string) uint16 {
	ci, nt := b.class(owner), b.nameType(name, desc)
	raw := append([]byte{cpFieldref}, be2(ci)...)
	raw = append(raw, be2(nt)...)
	return b.add("f:"+owner+"."+name+desc, raw)
}

// invokeDynamic interns a CONSTANT_InvokeDynamic; bootstrap_method_attr_index is 0
// (the parser reads only the NameAndType — the real target is bootstrap-decided).
func (b *classBuilder) invokeDynamic(name, desc string) uint16 {
	nt := b.nameType(name, desc)
	raw := append([]byte{cpInvokeDynamic}, be2(0)...)
	raw = append(raw, be2(nt)...)
	return b.add("indy:"+name+desc, raw)
}

// build emits a complete .class with one method carrying the given raw bytecode as
// its Code attribute. All builder interning must happen before calling build (the
// bytecode references cp indices handed out earlier); build only appends the
// class/method metadata constants, which never shifts an existing index.
func (b *classBuilder) build(thisClass, superClass, mName, mDesc string, code []byte) []byte {
	thisIdx := b.class(thisClass)
	superIdx := b.class(superClass)
	codeAttr := b.utf8("Code")
	mNameIdx := b.utf8(mName)
	mDescIdx := b.utf8(mDesc)

	var codeBody bytes.Buffer
	codeBody.Write(be2(16)) // max_stack
	codeBody.Write(be2(16)) // max_locals
	codeBody.Write(be4(uint32(len(code))))
	codeBody.Write(code)
	codeBody.Write(be2(0)) // exception_table_length
	codeBody.Write(be2(0)) // Code attributes_count

	var buf bytes.Buffer
	buf.Write(be4(0xCAFEBABE))
	buf.Write(be2(0))  // minor_version
	buf.Write(be2(52)) // major_version (Java 8)
	buf.Write(be2(uint16(len(b.entries) + 1)))
	for _, e := range b.entries {
		buf.Write(e)
	}
	buf.Write(be2(0x0021)) // access_flags: public super
	buf.Write(be2(thisIdx))
	buf.Write(be2(superIdx))
	buf.Write(be2(0))      // interfaces_count
	buf.Write(be2(0))      // fields_count
	buf.Write(be2(1))      // methods_count
	buf.Write(be2(0x0001)) // method access_flags: public
	buf.Write(be2(mNameIdx))
	buf.Write(be2(mDescIdx))
	buf.Write(be2(1)) // method attributes_count
	buf.Write(be2(codeAttr))
	buf.Write(be4(uint32(codeBody.Len())))
	buf.Write(codeBody.Bytes())
	buf.Write(be2(0)) // class attributes_count
	return buf.Bytes()
}

// ---- tests ----

func TestParseClass_ExtractsInvokeEdges(t *testing.T) {
	b := newClassBuilder()
	const sink = "(Ljava/lang/String;)Ljava/lang/String;"
	virt := b.methodref(cpMethodref, "com/example/net/UrlFetcher", "fetch", sink)
	iface := b.methodref(cpInterfaceMethodref, "com/example/svc/Service", "run", "()V")
	indy := b.invokeDynamic("apply", "()Ljava/util/function/Function;")

	// A decoy sipush whose 2-byte operand is 0xB6 0x07 — a naive byte scan would read
	// the operand as an invokevirtual opcode. The instruction walker must skip it.
	var code bytes.Buffer
	code.Write([]byte{0x11, 0xB6, 0x07})            // sipush 0xB607 (decoy)
	code.Write(append([]byte{0xB6}, be2(virt)...))  // invokevirtual UrlFetcher.fetch
	code.Write(append([]byte{0xB9}, be2(iface)...)) // invokeinterface Service.run ...
	code.Write([]byte{0x01, 0x00})                  //   count=1, 0
	code.Write(append([]byte{0xBA}, be2(indy)...))  // invokedynamic apply ...
	code.Write([]byte{0x00, 0x00})                  //   0, 0
	code.Write([]byte{0xB1})                        // return

	cls, err := ParseClass(b.build("com/example/app/App", "java/lang/Object", "handle", "()V", code.Bytes()))
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	if cls.Name != "com/example/app/App" || cls.Super != "java/lang/Object" {
		t.Fatalf("class identity wrong: name=%q super=%q", cls.Name, cls.Super)
	}
	if len(cls.Methods) != 1 {
		t.Fatalf("want 1 method, got %d", len(cls.Methods))
	}
	edges := cls.Methods[0].Edges
	if len(edges) != 3 {
		t.Fatalf("want exactly 3 edges (decoy operand must not become an edge), got %d: %+v", len(edges), edges)
	}
	want := []Edge{
		{To: MethodRef{"com/example/net/UrlFetcher", "fetch", sink}, Kind: EdgeVirtual},
		{To: MethodRef{"com/example/svc/Service", "run", "()V"}, Kind: EdgeInterface},
		{To: MethodRef{"", "apply", "()Ljava/util/function/Function;"}, Kind: EdgeDynamic},
	}
	for i, w := range want {
		if edges[i] != w {
			t.Errorf("edge %d = %+v, want %+v", i, edges[i], w)
		}
	}
}

// TestParseClass_CollectsInitTriggers proves the parser surfaces the classes whose
// static initializer this method triggers — new / getstatic / invokestatic — so the
// caller can walk into <clinit>. Without these a sink reachable only through a
// static initializer is invisible (the C8 HOLE-A regression).
func TestParseClass_CollectsInitTriggers(t *testing.T) {
	b := newClassBuilder()
	newC := b.class("com/example/Holder")
	sfield := b.fieldref("com/example/Config", "FLAG", "Z")
	scall := b.methodref(cpMethodref, "com/example/Util", "boot", "()V")
	virt := b.methodref(cpMethodref, "com/example/Obj", "toString", "()Ljava/lang/String;") // NOT a trigger

	var code bytes.Buffer
	code.Write(append([]byte{0xBB}, be2(newC)...))   // new Holder     -> triggers Holder.<clinit>
	code.Write(append([]byte{0xB2}, be2(sfield)...)) // getstatic FLAG -> triggers Config.<clinit>
	code.Write(append([]byte{0xB8}, be2(scall)...))  // invokestatic   -> triggers Util.<clinit>
	code.Write(append([]byte{0xB6}, be2(virt)...))   // invokevirtual  -> NOT a trigger
	code.WriteByte(0xB1)

	cls, err := ParseClass(b.build("com/example/App", "java/lang/Object", "m", "()V", code.Bytes()))
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	got := map[string]bool{}
	for _, o := range cls.Methods[0].InitTriggers {
		got[o] = true
	}
	for _, want := range []string{"com/example/Holder", "com/example/Config", "com/example/Util"} {
		if !got[want] {
			t.Errorf("missing init trigger %q; got %v", want, cls.Methods[0].InitTriggers)
		}
	}
	if got["com/example/Obj"] {
		t.Errorf("invokevirtual receiver must not be an init trigger; got %v", cls.Methods[0].InitTriggers)
	}
}

// TestParseClass_WalksVariableLengthInstructions proves the walker consumes a
// tableswitch (variable length, 4-byte aligned) without desyncing: the single real
// call after it is found, and no phantom edge is produced from the switch payload.
func TestParseClass_WalksVariableLengthInstructions(t *testing.T) {
	b := newClassBuilder()
	callee := b.methodref(cpMethodref, "com/example/util/Helper", "log", "()V")

	var code bytes.Buffer
	code.WriteByte(0xAA)                             // tableswitch at pc=0
	code.Write([]byte{0, 0, 0})                      // pad to 4-byte boundary (pc 1,2,3)
	code.Write(be4(0))                               // default
	code.Write(be4(0))                               // low = 0
	code.Write(be4(1))                               // high = 1  -> 2 entries
	code.Write(be4(0))                               // jump[0]
	code.Write(be4(0))                               // jump[1]
	code.Write(append([]byte{0xB8}, be2(callee)...)) // invokestatic Helper.log
	code.WriteByte(0xB1)                             // return

	cls, err := ParseClass(b.build("com/example/app/Sw", "java/lang/Object", "m", "()V", code.Bytes()))
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	edges := cls.Methods[0].Edges
	if len(edges) != 1 {
		t.Fatalf("want 1 edge after tableswitch, got %d: %+v", len(edges), edges)
	}
	if got := edges[0]; got.Kind != EdgeStatic || got.To.Name != "log" {
		t.Errorf("edge = %+v, want static Helper.log", got)
	}
}

// TestParseClass_IincDoesNotDesyncWalk is the regression guard for the P0 soundness
// bug Copilot caught on #3: iinc (0x84, non-wide) has two operand bytes (u1 index,
// s1 const) but was missing from the operand-length table, so the walker advanced
// past only the opcode and read the operand bytes as instructions. iinc is emitted
// for ordinary loop counters (i++), so the desync hits very common bytecode and can
// drop a following invoke edge — a dropped call edge is a short path set, which is a
// FALSE not_exploitable: a fail-OPEN Warrant violation.
//
// The operands are chosen so a desynced walk provably misses the invoke: with 0x84
// unsized, the walker lands on the index byte 0x11 (sipush, 2 operands) and consumes
// the following 0x00 AND the real invokestatic opcode as sipush's operand, skipping
// the call entirely. Correctly sized (pc += 3 over iinc), the walk lands exactly on
// the invokestatic and recovers the edge.
func TestParseClass_IincDoesNotDesyncWalk(t *testing.T) {
	b := newClassBuilder()
	callee := b.methodref(cpMethodref, "com/example/util/Counter", "tick", "()V")

	var code bytes.Buffer
	code.Write([]byte{0x84, 0x11, 0x00})             // iinc local#0x11 by 0 (a loop-counter i++)
	code.Write(append([]byte{0xB8}, be2(callee)...)) // invokestatic Counter.tick — must survive the iinc
	code.WriteByte(0xB1)                             // return

	cls, err := ParseClass(b.build("com/example/app/Loop", "java/lang/Object", "m", "()V", code.Bytes()))
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	edges := cls.Methods[0].Edges
	if len(edges) != 1 {
		t.Fatalf("iinc desynced the walk: want exactly 1 invoke edge after iinc, got %d: %+v", len(edges), edges)
	}
	if got := edges[0]; got.Kind != EdgeStatic || got.To.Owner != "com/example/util/Counter" || got.To.Name != "tick" {
		t.Errorf("edge = %+v, want static Counter.tick", got)
	}
}

func TestParseClass_MalformedInputsErrorNeverPanic(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		wantErr error // ErrBadMagic sentinel where applicable; nil means "some error"
	}{
		{"empty", nil, ErrBadMagic},
		{"short-magic", []byte{0xCA, 0xFE}, ErrBadMagic},
		{"wrong-magic", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 52}, ErrBadMagic},
		{"truncated-after-magic", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00}, nil},
		{"unknown-cp-tag", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 2, 99}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseClass(tc.data) // must not panic
			if err == nil {
				t.Fatalf("want an error for malformed input, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestParseClass_EveryTruncationIsSafe feeds every prefix of a valid class to the
// parser: none may panic (a panic on hostile dependency bytecode is a crash-DoS
// seam). The Go test runner fails the test if any call panics.
func TestParseClass_EveryTruncationIsSafe(t *testing.T) {
	b := newClassBuilder()
	callee := b.methodref(cpMethodref, "com/example/X", "y", "()V")
	code := append(append([]byte{0xB8}, be2(callee)...), 0xB1)
	good := b.build("com/example/app/App", "java/lang/Object", "m", "()V", code)
	for i := 0; i <= len(good); i++ {
		_, _ = ParseClass(good[:i]) // only assertion: no panic
	}
}

func TestLoadZip_ParsesClassesSkipsNonClassAndRecordsHazards(t *testing.T) {
	// good class
	gb := newClassBuilder()
	callee := gb.methodref(cpMethodref, "com/example/Dep", "sink", "()V")
	good := gb.build("com/example/app/Good", "java/lang/Object", "m", "()V",
		append(append([]byte{0xB8}, be2(callee)...), 0xB1))

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	writeEntry := func(name string, data []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	writeEntry("com/example/app/Good.class", good)
	writeEntry("META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\n"))             // ignored
	writeEntry("module-info.class", good)                                             // ignored
	writeEntry("com/example/app/Corrupt.class", []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00}) // hazard
	writeEntry("com/example/app/NotAClass.class", []byte{0x01, 0x02, 0x03, 0x04})     // bad magic -> skipped
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	res, err := loadZip(zr)
	if err != nil {
		t.Fatalf("loadZip: %v", err)
	}
	if len(res.Classes) != 1 || res.Classes[0].Name != "com/example/app/Good" {
		t.Fatalf("want exactly the Good class, got %+v", res.Classes)
	}
	// Good + Corrupt counted as .class entries (NotAClass bad-magic decremented,
	// META-INF and module-info excluded).
	if res.Entries != 2 {
		t.Errorf("Entries = %d, want 2", res.Entries)
	}
	if len(res.Failed) != 1 {
		t.Errorf("want 1 recorded hazard (Corrupt), got %d: %v", len(res.Failed), res.Failed)
	}
}
