package assembly

import (
	"bytes"
	"testing"
)

// tk builds a 4-byte little-endian token operand for hand-authored IL.
func tk(t Token) []byte { return le4(uint32(t)) }

// asm returns an empty assembly usable as the walkIL receiver (the walk needs no
// metadata; only isStaticTarget consults tables, and it degrades to false).
func emptyAsm() *Assembly { return &Assembly{} }

// TestWalk_OperandDecoy proves the instruction-walk is a WALK, not a byte scan: an
// operand whose bytes happen to equal call/callvirt/newobj opcodes must NOT be read
// as call sites. A naive byte scanner would hallucinate several; the walk sees one.
func TestWalk_OperandDecoy(t *testing.T) {
	callTok := makeToken(tMethodDef, 1)
	var b bytes.Buffer
	// ldc.i4 (0x20) with an operand made entirely of call-family opcode bytes.
	b.WriteByte(0x20)
	b.Write([]byte{0x28, 0x6F, 0x73, 0x28}) // decoy: call, callvirt, newobj, call
	// ldstr (0x72) whose token bytes also include 0x28.
	b.WriteByte(0x72)
	b.Write([]byte{0x28, 0x00, 0x00, 0x70})
	// one REAL call.
	b.WriteByte(0x28)
	b.Write(tk(callTok))
	b.WriteByte(0x2A) // ret
	code := b.Bytes()

	edges, _, err := emptyAsm().walkIL(code)
	if err != nil {
		t.Fatalf("walkIL: %v", err)
	}
	if len(edges) != 1 || edges[0].Kind != EdgeCall || edges[0].Token != callTok {
		t.Fatalf("walk found %d edges %+v, want exactly 1 real call", len(edges), edges)
	}
	// Desync detector: a naive byte scan counts every call-family opcode byte and
	// would report many more "edges" than the synced walk's 1.
	if n := naiveScanCount(code); n <= len(edges) {
		t.Fatalf("naive scan counted %d, expected far more than the walk's %d (decoy not exercised)", n, len(edges))
	}
}

// naiveScanCount is the WRONG algorithm (byte scan) used only to demonstrate desync:
// it counts any byte equal to a call-family opcode, operand bytes included.
func naiveScanCount(code []byte) int {
	n := 0
	for _, b := range code {
		if b == 0x28 || b == 0x6F || b == 0x73 {
			n++
		}
	}
	return n
}

// TestWalk_EveryOperandForm exercises inline-token, switch (variable length), the
// 0xFE two-byte opcode, and a constrained. callvirt, and asserts exact edge shape.
func TestWalk_EveryOperandForm(t *testing.T) {
	call := makeToken(tMethodDef, 1)
	cvirt := makeToken(tMemberRef, 2)
	nobj := makeToken(tMethodDef, 3)
	lftn := makeToken(tMethodDef, 4)
	calliSig := makeToken(tStandAloneSig, 1)
	ctype := makeToken(tTypeDef, 5)
	ccall := makeToken(tMethodDef, 6)

	var b bytes.Buffer
	b.WriteByte(0x28)
	b.Write(tk(call)) // call
	b.WriteByte(0x6F)
	b.Write(tk(cvirt)) // callvirt
	b.WriteByte(0x73)
	b.Write(tk(nobj)) // newobj
	b.WriteByte(0xFE)
	b.WriteByte(0x06)
	b.Write(tk(lftn)) // ldftn
	b.WriteByte(0x29)
	b.Write(tk(calliSig)) // calli
	// switch with 2 targets whose bytes look like opcodes but must be skipped.
	b.WriteByte(0x45)
	b.Write(le4(2))
	b.Write(le4(0x6F6F6F6F))
	b.Write(le4(0x28282828))
	// constrained. <type> ; callvirt <ccall>
	b.WriteByte(0xFE)
	b.WriteByte(0x16)
	b.Write(tk(ctype))
	b.WriteByte(0x6F)
	b.Write(tk(ccall))
	b.WriteByte(0x2A) // ret
	code := b.Bytes()

	edges, _, err := emptyAsm().walkIL(code)
	if err != nil {
		t.Fatalf("walkIL: %v", err)
	}
	want := []Edge{
		{Kind: EdgeCall, Token: call},
		{Kind: EdgeCallvirt, Token: cvirt},
		{Kind: EdgeNewobj, Token: nobj},
		{Kind: EdgeLdftn, Token: lftn},
		{Kind: EdgeCalli, Token: calliSig},
		{Kind: EdgeCallvirt, Token: ccall, Constrained: ctype},
	}
	if len(edges) != len(want) {
		t.Fatalf("got %d edges, want %d: %+v", len(edges), len(want), edges)
	}
	for i, w := range want {
		if edges[i].Kind != w.Kind || edges[i].Token != w.Token || edges[i].Constrained != w.Constrained {
			t.Errorf("edge %d = {%v %v cons=%v}, want {%v %v cons=%v}", i,
				edges[i].Kind, edges[i].Token, edges[i].Constrained, w.Kind, w.Token, w.Constrained)
		}
	}
}

// TestWalk_SwitchDesyncGuard is the sharp desync detector: the switch's single jump
// target is 0x0000006F. A correct walk (variable-length switch: 1 + 4 + 4*N) skips
// past it and yields ZERO edges; a walk that miscounts the switch length lands inside
// the target bytes, reads 0x6F as callvirt, and fabricates a phantom edge. K=0 here.
func TestWalk_SwitchDesyncGuard(t *testing.T) {
	var b bytes.Buffer
	b.WriteByte(0x45)
	b.Write(le4(1))          // N = 1
	b.Write(le4(0x0000006F)) // target byte 0x6F = callvirt opcode (the trap)
	b.WriteByte(0x2A)        // ret
	edges, _, err := emptyAsm().walkIL(b.Bytes())
	if err != nil {
		t.Fatalf("walkIL: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("synced walk must yield 0 edges; a desynced walk fabricates one. got %+v", edges)
	}
}

// TestWalk_JmpEmitsBoundary is the FIX 2 regression: `jmp <method>` (0x27) is a tail-transfer
// that hides a real call. It must be COLLECTED as an EdgeJmp — not silently skipped, not read
// as a normal call edge — and CHA must resolve it to a declared boundary with a reason.
func TestWalk_JmpEmitsBoundary(t *testing.T) {
	jmpTok := makeToken(tMethodDef, 1)
	var b bytes.Buffer
	b.WriteByte(0x27)
	b.Write(tk(jmpTok)) // jmp <method>
	b.WriteByte(0x2A)   // ret
	edges, _, err := emptyAsm().walkIL(b.Bytes())
	if err != nil {
		t.Fatalf("walkIL: %v", err)
	}
	if len(edges) != 1 || edges[0].Kind != EdgeJmp || edges[0].Token != jmpTok {
		t.Fatalf("jmp must be collected as exactly one EdgeJmp %v, got %+v", jmpTok, edges)
	}
	// The site is a declared boundary, never a dropped edge and never a normal call.
	res := (&CHA{}).ResolveDispatch(emptyAsm(), edges[0])
	if res.State != DispatchBoundary || res.Reason == "" {
		t.Fatalf("jmp edge must resolve to a boundary with a reason, got state=%v reason=%q", res.State, res.Reason)
	}
}

// TestWalk_InitTriggers records newobj / ldsfld / stsfld / static-call trigger sites.
func TestWalk_InitTriggers(t *testing.T) {
	fld := makeToken(tMemberRef, 7)
	ctor := makeToken(tMethodDef, 8)
	var b bytes.Buffer
	b.WriteByte(0x7E)
	b.Write(tk(fld)) // ldsfld
	b.WriteByte(0x80)
	b.Write(tk(fld)) // stsfld
	b.WriteByte(0x73)
	b.Write(tk(ctor)) // newobj
	b.WriteByte(0x2A)
	_, triggers, err := emptyAsm().walkIL(b.Bytes())
	if err != nil {
		t.Fatalf("walkIL: %v", err)
	}
	kinds := map[InitTriggerKind]int{}
	for _, tr := range triggers {
		kinds[tr.Kind]++
	}
	if kinds[InitStaticField] != 2 || kinds[InitNewobj] != 1 {
		t.Fatalf("init triggers = %+v, want 2 static-field + 1 newobj", triggers)
	}
}

// TestWalk_TruncatedOperandErrors: an instruction whose operand runs past the code
// region is an error, never a panic or a phantom edge.
func TestWalk_TruncatedOperandErrors(t *testing.T) {
	cases := map[string][]byte{
		"trunc-call":     {0x28, 0x01, 0x00},             // call with 2 of 4 token bytes
		"trunc-fe":       {0xFE},                         // dangling two-byte prefix
		"trunc-ldftn":    {0xFE, 0x06, 0x01},             // ldftn missing token bytes
		"switch-overrun": {0x45, 0xFF, 0xFF, 0xFF, 0x7F}, // N ~ 2^31, no targets present
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %s", name)
				}
			}()
			if _, _, err := emptyAsm().walkIL(code); err == nil {
				t.Fatalf("want an error for %s", name)
			}
		})
	}
}

// ---- ilBody header decode (tiny + fat) end-to-end via a synthesized image ----

type tbody struct {
	rid uint32 // MethodDef RID whose RVA is patched to this body
	il  []byte // IL code region (header is synthesized)
	fat bool
	raw []byte // if non-nil, placed verbatim (for malformed-header tests)
}

func encodeBody(mb tbody) []byte {
	if mb.raw != nil {
		return mb.raw
	}
	if !mb.fat {
		return append([]byte{byte(len(mb.il)<<2) | 0x02}, mb.il...)
	}
	h := le2(0x3003)         // Flags(0x3 fat) | Size(3 dwords)<<12
	h = append(h, le2(8)...) // MaxStack
	h = append(h, le4(uint32(len(mb.il)))...)
	h = append(h, le4(0)...) // LocalVarSigTok
	return append(h, mb.il...)
}

// wrapPEBodies lays out CLI header + metadata + method bodies in one .text section,
// patching each method's RVA. len(metadata) is invariant to the RVA VALUES (a fixed
// u4 column), so a measure-then-patch-then-rebuild pass is exact.
func wrapPEBodies(b *mdBuilder, heapSizes byte, bodies []tbody) []byte {
	const (
		peSigOff      = 0x80
		coffOff       = peSigOff + 4
		optOff        = coffOff + 20
		optSize       = 224
		secOff        = optOff + optSize
		rawStart      = 0x200
		sectionVA     = 0x2000
		cliHeaderSize = 72
	)
	metaLen := len(b.buildMetadata(heapSizes))
	base := sectionVA + cliHeaderSize + metaLen
	pad := (4 - base%4) % 4
	base += pad

	var blob []byte
	for _, mb := range bodies {
		for (base+len(blob))%4 != 0 {
			blob = append(blob, 0)
		}
		b.tables[tMethodDef][mb.rid-1][0] = uint32(base + len(blob))
		blob = append(blob, encodeBody(mb)...)
	}
	metadata := b.buildMetadata(heapSizes)

	var cli bytes.Buffer
	cli.Write(le4(72))
	cli.Write(le2(2))
	cli.Write(le2(5))
	cli.Write(le4(sectionVA + cliHeaderSize)) // MetaData RVA
	cli.Write(le4(uint32(len(metadata))))
	cli.Write(le4(0))          // Flags
	cli.Write(le4(0x06000001)) // EntryPointToken
	cli.Write(make([]byte, 48))

	raw := append(cli.Bytes(), metadata...)
	for len(raw) < cliHeaderSize+metaLen+pad {
		raw = append(raw, 0)
	}
	raw = append(raw, blob...)

	data := make([]byte, rawStart+len(raw))
	data[0], data[1] = 'M', 'Z'
	copy(data[0x3C:], le4(peSigOff))
	copy(data[peSigOff:], []byte{'P', 'E', 0, 0})
	copy(data[coffOff+2:], le2(1))
	copy(data[coffOff+16:], le2(optSize))
	copy(data[optOff:], le2(peMagicPE32))
	copy(data[optOff+92:], le4(16))
	dir14 := optOff + 96 + dirCLIHeader*8
	copy(data[dir14:], le4(sectionVA))
	copy(data[dir14+4:], le4(uint32(len(raw))))
	copy(data[secOff:], []byte(".text\x00\x00\x00"))
	copy(data[secOff+8:], le4(uint32(len(raw))))
	copy(data[secOff+12:], le4(sectionVA))
	copy(data[secOff+16:], le4(uint32(len(raw))))
	copy(data[secOff+20:], le4(rawStart))
	copy(data[rawStart:], raw)
	return data
}

// oneMethodFixture builds an assembly with a single type Widget owning one method
// (RID 1) whose IL body is `body`. Returns the parsed assembly and the method.
func oneMethodFixture(t *testing.T, heapSizes byte, body tbody) (*Assembly, *MethodDef) {
	t.Helper()
	b := newMDBuilder()
	nModule := b.str("Test.dll")
	nWidget := b.str("Widget")
	nModuleType := b.str("<Module>")
	nDo := b.str("Do")
	nAsm := b.str("TestAsm")
	sig := []byte{0x20, 0x00, 0x01}
	b.guid()
	b.addRow(tModule, 0, nModule, b.guid(), 0, 0)
	b.addRow(tMethodDef, 0, 0, 0x40, nDo, b.blob(sig), 1) // RVA patched by wrapPEBodies
	b.addRow(tTypeDef, 0, nModuleType, 0, 0, 1, 1)
	b.addRow(tTypeDef, 0x100001, nWidget, 0, 0, 1, 1)
	b.addRow(tAssembly, 0, 1, 0, 0, 0, 0, b.blob(nil), nAsm, 0)

	body.rid = 1
	data := wrapPEBodies(b, heapSizes, []tbody{body})
	a, err := Read(data)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return a, a.MethodByRID(1)
}

func TestILBody_TinyAndFat(t *testing.T) {
	callTok := makeToken(tMethodDef, 1)
	il := append([]byte{0x28}, tk(callTok)...) // call
	il = append(il, 0x2A)                      // ret

	for _, fat := range []bool{false, true} {
		name := "tiny"
		if fat {
			name = "fat"
		}
		t.Run(name, func(t *testing.T) {
			a, m := oneMethodFixture(t, 0x00, tbody{il: il, fat: fat})
			mb, err := a.MethodBody(m)
			if err != nil {
				t.Fatalf("MethodBody: %v", err)
			}
			if len(mb.Edges) != 1 || mb.Edges[0].Kind != EdgeCall || mb.Edges[0].Token != callTok {
				t.Fatalf("%s body edges = %+v, want one call", name, mb.Edges)
			}
		})
	}
}

func TestILBody_MalformedHeaderErrorsNeverPanic(t *testing.T) {
	cases := map[string][]byte{
		"native-format": {0xFD},                                                                        // low 2 bits = 01 (native), not IL
		"fat-oversize":  append(append(le2(0x3003), le2(8)...), append(le4(0xFFFFFFFF), le4(0)...)...), // codeSize huge
		"tiny-oversize": {0xFC},                                                                        // tiny claims 63 code bytes, none follow
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %s", name)
				}
			}()
			a, m := oneMethodFixture(t, 0x00, tbody{raw: raw})
			if _, err := a.MethodBody(m); err == nil {
				t.Fatalf("want an error for %s", name)
			}
		})
	}
}
