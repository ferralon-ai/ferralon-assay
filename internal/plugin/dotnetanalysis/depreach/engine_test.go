package depreach

// engine_test.go — hermetic tests for the two-trace PoNE verdict engine. Every fixture
// is a REAL parsed assembly: the test synthesizes valid PE32 + ECMA-335 metadata + IL
// bodies in-memory (NO SDK, no CLR, nothing loaded — bytes are parsed by
// assembly.Read), so the tests exercise the true production path IL-decode -> CHA ->
// resolveTargets -> Reach, exactly what the barrier-5 C8 reviewer attacks.
//
// The byte builder (peb) is a focused port of the barrier-1/2a synthesis discipline
// (assembly_test.go / il_test.go), which are unexported to this package. It emits only
// the tables these fixtures need; a wrong width would make assembly.Read fail loudly,
// so the builder is self-checking.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// ---- metadata table ids we emit (ECMA-335 §II.22) ----
const (
	xModule        = 0x00
	xTypeRef       = 0x01
	xTypeDef       = 0x02
	xMethodDef     = 0x06
	xInterfaceImpl = 0x09
	xMemberRef     = 0x0A
	xStandAloneSig = 0x11
	xAssembly      = 0x20
	xAssemblyRef   = 0x23
	xNumTables     = 64
)

// wideCols marks the 4-byte (u4) columns per table under the small-heap / small-row
// regime these fixtures use; every other column is 2 bytes — which is exactly what the
// reader computes, so a round-trip through both is a genuine cross-check.
var wideCols = map[int]map[int]bool{
	xTypeDef:     {0: true},          // Flags
	xMethodDef:   {0: true},          // RVA
	xAssembly:    {0: true, 5: true}, // HashAlgId, Flags
	xAssemblyRef: {4: true},          // Flags
}

func le2(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func le4(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func le8(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

func mtok(table int, rid uint32) assembly.Token {
	return assembly.Token(uint32(table)<<24 | (rid & 0x00FFFFFF))
}
func tok4(t assembly.Token) []byte { return le4(uint32(t)) }

// coded-index encoders (ECMA-335 §II.24.2.6): (rid << tagBits) | tag.
func cResScopeAsmRef(rid uint32) uint32 { return rid<<2 | 2 } // ResolutionScope, AssemblyRef tag=2
func cTypeDefOrRef(table int, rid uint32) uint32 {
	tag := map[int]uint32{xTypeDef: 0, xTypeRef: 1}[table]
	return rid<<2 | tag
}
func cMemberRefParent(table int, rid uint32) uint32 {
	tag := map[int]uint32{xTypeDef: 0, xTypeRef: 1, xMethodDef: 3}[table]
	return rid<<3 | tag
}

// ---- IL helpers (single instruction + ret) ----
const opRet = 0x2A

func ilCall(t assembly.Token) []byte     { return append([]byte{0x28}, tok4(t)...) }
func ilCallvirt(t assembly.Token) []byte { return append([]byte{0x6F}, tok4(t)...) }
func ilNewobj(t assembly.Token) []byte   { return append([]byte{0x73}, tok4(t)...) }
func ilCalli(t assembly.Token) []byte    { return append([]byte{0x29}, tok4(t)...) }

func body(instrs ...[]byte) []byte {
	var out []byte
	for _, in := range instrs {
		out = append(out, in...)
	}
	return append(out, opRet)
}

// ---- signature blobs (ECMA-335 §II.23.2.1) ----
var (
	sigInstVoid   = []byte{0x20, 0x00, 0x01} // HASTHIS, 0 params, ret void
	sigStaticVoid = []byte{0x00, 0x00, 0x01} // 0 params, ret void
)

// sigInstClassParam builds `HASTHIS void M(class <typeDefRID>)` — one reference-type
// parameter, for the re-entry rule.
func sigInstClassParam(typeDefRID uint32) []byte {
	coded := cTypeDefOrRef(xTypeDef, typeDefRID) // TypeDef tag=0; small rid => 1 compressed byte
	return []byte{0x20, 0x01, 0x01, 0x12, byte(coded)}
}

// sigInstClassParamRef builds `HASTHIS void M(class <typeRefRID>)` — one reference-type
// parameter whose type is an OUT-OF-SET TypeRef. This is the dominant .NET re-entry shape:
// an app object handed to a framework method typed as its out-of-set base class / interface
// (or System.Object). Both rid values here are small, so the coded index is one compressed byte.
func sigInstClassParamRef(typeRefRID uint32) []byte {
	coded := cTypeDefOrRef(xTypeRef, typeRefRID) // TypeRef tag=1; small rid => 1 compressed byte
	return []byte{0x20, 0x01, 0x01, 0x12, byte(coded)}
}

// ---- the byte builder ----

type mbody struct {
	rid uint32
	il  []byte
}

type peb struct {
	strs, blobs, guids []byte
	tables             map[int][][]uint32
	bodies             []mbody
}

func newPEB() *peb {
	return &peb{strs: []byte{0}, blobs: []byte{0}, tables: map[int][][]uint32{}}
}

func (b *peb) str(s string) uint32 {
	if s == "" {
		return 0
	}
	off := uint32(len(b.strs))
	b.strs = append(b.strs, s...)
	b.strs = append(b.strs, 0)
	return off
}
func (b *peb) blob(data []byte) uint32 {
	off := uint32(len(b.blobs))
	b.blobs = append(b.blobs, byte(len(data)))
	b.blobs = append(b.blobs, data...)
	return off
}
func (b *peb) guid() uint32 {
	g := make([]byte, 16)
	b.guids = append(b.guids, g...)
	return uint32(len(b.guids) / 16)
}
func (b *peb) row(table int, cols ...uint32) uint32 {
	b.tables[table] = append(b.tables[table], cols)
	return uint32(len(b.tables[table]))
}

// mspec is a method to add: name, MethodAttributes flags, signature, and IL body (nil
// => no managed body, RVA stays 0 — an abstract/pinvoke leaf).
type mspec struct {
	name  string
	flags uint32
	sig   []byte
	il    []byte
}

// addType appends a TypeDef and its methods (methods first, contiguously, so MethodList
// ranges stay monotone). Returns the TypeDef RID and each method's MethodDef RID.
func (b *peb) addType(flags uint32, name, ns string, extends uint32, methods []mspec) (uint32, []uint32) {
	first := uint32(len(b.tables[xMethodDef])) + 1
	var mrids []uint32
	for _, m := range methods {
		rid := b.row(xMethodDef, 0 /*RVA patched later*/, 0 /*ImplFlags*/, m.flags, b.str(m.name), b.blob(m.sig), 1)
		mrids = append(mrids, rid)
		if m.il != nil {
			b.bodies = append(b.bodies, mbody{rid, m.il})
		}
	}
	tRID := b.row(xTypeDef, flags, b.str(name), b.str(ns), extends, 1, first)
	return tRID, mrids
}

// scaffold seeds Module + the System.Runtime AssemblyRef and returns the peb.
func scaffold() *peb {
	b := newPEB()
	b.row(xModule, 0, b.str("Test.dll"), b.guid(), 0, 0)
	b.row(xAssemblyRef, 1, 0, 0, 0, 0, b.blob(nil), b.str("System.Runtime"), 0, b.blob(nil)) // RID 1
	return b
}

// extTypeRef adds an out-of-set TypeRef scoped to the System.Runtime AssemblyRef (RID 1).
func (b *peb) extTypeRef(ns, name string) uint32 {
	return b.row(xTypeRef, cResScopeAsmRef(1), b.str(name), b.str(ns))
}

// finish adds the Assembly row, patches method-body RVAs, wraps in a PE32 image, and
// parses it — returning the live assembly the engine consumes.
func (b *peb) finish(t *testing.T) *assembly.Assembly {
	t.Helper()
	b.row(xAssembly, 0, 1, 0, 0, 0, 0, b.blob(nil), b.str("TestAsm"), 0)
	data := b.wrap()
	a, err := assembly.Read(data)
	if err != nil {
		t.Fatalf("assembly.Read: %v", err)
	}
	return a
}

func (b *peb) buildTableStream(heapSizes byte) []byte {
	var present []int
	var valid uint64
	for tid := 0; tid < xNumTables; tid++ {
		if len(b.tables[tid]) > 0 {
			present = append(present, tid)
			valid |= uint64(1) << uint(tid)
		}
	}
	var buf bytes.Buffer
	buf.Write(le4(0))
	buf.WriteByte(2)
	buf.WriteByte(0)
	buf.WriteByte(heapSizes)
	buf.WriteByte(1)
	buf.Write(le8(valid))
	buf.Write(le8(0))
	for _, tid := range present {
		buf.Write(le4(uint32(len(b.tables[tid]))))
	}
	for _, tid := range present {
		for _, r := range b.tables[tid] {
			for i, v := range r {
				if wideCols[tid][i] {
					buf.Write(le4(v))
				} else {
					buf.Write(le2(uint16(v)))
				}
			}
		}
	}
	return buf.Bytes()
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func (b *peb) buildMetadata() []byte {
	tableStream := b.buildTableStream(0x00)
	type strm struct {
		name string
		data []byte
	}
	strms := []strm{
		{"#~", tableStream},
		{"#Strings", pad4(append([]byte{}, b.strs...))},
		{"#US", pad4([]byte{0})},
		{"#GUID", b.guids},
		{"#Blob", pad4(append([]byte{}, b.blobs...))},
	}
	version := pad4([]byte("v4.0.30319\x00"))
	var root bytes.Buffer
	root.Write(le4(0x424A5342)) // BSJB
	root.Write(le2(1))
	root.Write(le2(1))
	root.Write(le4(0))
	root.Write(le4(uint32(len(version))))
	root.Write(version)
	root.Write(le2(0))
	root.Write(le2(uint16(len(strms))))
	headerLen := root.Len()
	for _, s := range strms {
		headerLen += 8 + len(pad4(append([]byte(s.name), 0)))
	}
	offset := headerLen
	var blocks bytes.Buffer
	for _, s := range strms {
		root.Write(le4(uint32(offset)))
		root.Write(le4(uint32(len(s.data))))
		root.Write(pad4(append([]byte(s.name), 0)))
		blocks.Write(s.data)
		offset += len(s.data)
	}
	root.Write(blocks.Bytes())
	return root.Bytes()
}

func encodeTinyBody(il []byte) []byte {
	return append([]byte{byte(len(il)<<2) | 0x02}, il...)
}

// wrap lays out CLI header + metadata + method bodies in one .text section, patching
// each body method's RVA (measure-then-patch: the RVA column is a fixed u4, so the
// metadata length is invariant to the values written).
func (b *peb) wrap() []byte {
	const (
		peSigOff      = 0x80
		coffOff       = peSigOff + 4
		optOff        = coffOff + 20
		optSize       = 224
		secOff        = optOff + optSize
		rawStart      = 0x200
		sectionVA     = 0x2000
		cliHeaderSize = 72
		dirCLIHeader  = 14
		peMagicPE32   = 0x10b
	)
	metaLen := len(b.buildMetadata())
	base := sectionVA + cliHeaderSize + metaLen
	pad := (4 - base%4) % 4
	base += pad

	var blob []byte
	for _, mb := range b.bodies {
		for (base+len(blob))%4 != 0 {
			blob = append(blob, 0)
		}
		b.tables[xMethodDef][mb.rid-1][0] = uint32(base + len(blob))
		blob = append(blob, encodeTinyBody(mb.il)...)
	}
	metadata := b.buildMetadata()

	var cli bytes.Buffer
	cli.Write(le4(72))
	cli.Write(le2(2))
	cli.Write(le2(5))
	cli.Write(le4(sectionVA + cliHeaderSize))
	cli.Write(le4(uint32(len(metadata))))
	cli.Write(le4(0))
	cli.Write(le4(0x06000001))
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

// keyByRID fetches the engine MethodKey for a method by its MethodDef RID.
func keyByRID(t *testing.T, e *Engine, a *assembly.Assembly, rid uint32) MethodKey {
	t.Helper()
	m := a.MethodByRID(rid)
	if m == nil {
		t.Fatalf("no MethodDef RID %d", rid)
	}
	k, ok := e.keyOf(m)
	if !ok {
		t.Fatalf("method RID %d not indexed by engine", rid)
	}
	return k
}

// =====================================================================================
// Test 1 — direct reachable: ingress -call-> Mid.step -callvirt-> Sink.vuln.
// =====================================================================================

func TestReach_DirectReachable(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", ext, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	_, midM := b.addType(0, "Mid", "App", ext, []mspec{{name: "step", flags: 0x40, sig: sigInstVoid, il: body(ilCallvirt(vulnTok))}})
	stepTok := mtok(xMethodDef, midM[0])
	_, inM := b.addType(0, "Ingress", "App", ext, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(stepTok))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))

	if res.Verdict != ReachableCandidate {
		t.Fatalf("verdict = %v (%s), want reachable_candidate", res.Verdict, res.HazardWhy)
	}
	got := PathString(res.Path)
	if got != "Ingress.enter -> Mid.step -> Sink.vuln" {
		t.Fatalf("path = %q, want Ingress.enter -> Mid.step -> Sink.vuln", got)
	}
}

// =====================================================================================
// Test 2 — genuinely unreachable over a COMPLETE, hazard-free frontier => not_exploitable.
// This fixture can disprove the honesty boundary: it MUST be unreachable AND carry ZERO
// hazards (no init triggers, only resolved in-set instance calls).
// =====================================================================================

func TestReach_UnreachableComplete_NotExploitable(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", ext, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, leafM := b.addType(0, "Leaf", "App", ext, []mspec{{name: "noop", flags: 0, sig: sigInstVoid, il: body()}})
	noopTok := mtok(xMethodDef, leafM[0])
	_, midM := b.addType(0, "Mid", "App", ext, []mspec{{name: "step", flags: 0, sig: sigInstVoid, il: body(ilCall(noopTok))}})
	stepTok := mtok(xMethodDef, midM[0])
	_, inM := b.addType(0, "Ingress", "App", ext, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(stepTok))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))

	if res.Verdict != NotExploitable {
		t.Fatalf("verdict = %v (%s), want not_exploitable", res.Verdict, res.HazardWhy)
	}
	if res.HazardOnFrontier {
		t.Fatalf("not_exploitable frontier must be hazard-free; got hazard %q", res.HazardWhy)
	}
	if !res.SinkPresent {
		t.Fatalf("sink must be present (trace 1) for a real searched-and-empty result")
	}
}

// =====================================================================================
// Test 3 — .cctor-only reachability + mutation controls.
//   variant A: sink reachable ONLY through the triggered type's OWN .cctor.
//   variant B: sink reachable ONLY through a BASE type's .cctor.
// Mutation controls prove the closure walk is load-bearing (disabling it produces a
// false not_exploitable).
// =====================================================================================

// cctorFixtureA: Ingress.enter newobj Trig(); Trig.cctor -> Sink.vuln.
func cctorFixtureA(t *testing.T) (*assembly.Assembly, uint32, uint32) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", ext, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	_, trigM := b.addType(0, "Trig", "App", ext, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},                   // instance ctor, empty
		{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body(ilCall(vulnTok))}, // static type-init -> sink
	})
	ctorTok := mtok(xMethodDef, trigM[0])
	_, inM := b.addType(0, "Ingress", "App", ext, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilNewobj(ctorTok))}})

	a := b.finish(t)
	return a, inM[0], sinkM[0]
}

// cctorFixtureB: Ingress.enter newobj Trig(); Trig:Base; Trig.cctor is inert; Base.cctor -> Sink.vuln.
func cctorFixtureB(t *testing.T) (*assembly.Assembly, uint32, uint32) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	extObj := cTypeDefOrRef(xTypeRef, obj)

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	baseRID, _ := b.addType(0, "Base", "App", extObj, []mspec{
		{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body(ilCall(vulnTok))}, // base type-init -> sink
	})
	extBase := cTypeDefOrRef(xTypeDef, baseRID)
	_, trigM := b.addType(0, "Trig", "App", extBase, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body()}, // inert: does NOT reach sink
	})
	ctorTok := mtok(xMethodDef, trigM[0])
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilNewobj(ctorTok))}})

	a := b.finish(t)
	return a, inM[0], sinkM[0]
}

func TestReach_CctorOnly_VariantA(t *testing.T) {
	a, inRID, sinkRID := cctorFixtureA(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	if res.Verdict != ReachableCandidate {
		t.Fatalf("variant A verdict = %v (%s), want reachable_candidate", res.Verdict, res.HazardWhy)
	}
	if !strings.Contains(PathString(res.Path), ".cctor -> Sink.vuln") {
		t.Fatalf("variant A path = %q, want it to route through Trig..cctor -> Sink.vuln", PathString(res.Path))
	}

	// MUTATION CONTROL: disabling the whole init-closure channel flips the verdict to a
	// FALSE not_exploitable — proving the .cctor walk is load-bearing (a missed edge).
	e2 := NewEngine([]*assembly.Assembly{a})
	e2.disableInitClosure = true
	if got := e2.Reach(keyByRID(t, e2, a, inRID), keyByRID(t, e2, a, sinkRID)); got.Verdict != NotExploitable {
		t.Fatalf("mutation (disableInitClosure) verdict = %v, want the false not_exploitable that proves the walk matters", got.Verdict)
	}
}

func TestReach_CctorOnly_VariantB_BaseChain(t *testing.T) {
	a, inRID, sinkRID := cctorFixtureB(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	if res.Verdict != ReachableCandidate {
		t.Fatalf("variant B verdict = %v (%s), want reachable_candidate (via BASE .cctor)", res.Verdict, res.HazardWhy)
	}
	if !strings.Contains(PathString(res.Path), "Base..cctor -> Sink.vuln") {
		t.Fatalf("variant B path = %q, want it to route through Base..cctor -> Sink.vuln", PathString(res.Path))
	}

	// MUTATION CONTROL: keeping the triggered type's own .cctor but dropping the BASE
	// chain walk flips to a false not_exploitable — the exact hole cobalt closed
	// (ca18513): the base-type .cctor edge is load-bearing.
	e2 := NewEngine([]*assembly.Assembly{a})
	e2.disableBaseChainOnly = true
	if got := e2.Reach(keyByRID(t, e2, a, inRID), keyByRID(t, e2, a, sinkRID)); got.Verdict != NotExploitable {
		t.Fatalf("mutation (disableBaseChainOnly) verdict = %v, want the false not_exploitable that proves the base-chain walk matters", got.Verdict)
	}
}

// =====================================================================================
// Test 4 — each hazard channel => undetermined, with a negative control (the same shape
// with the hazard replaced by a RESOLVED in-set call) => not_exploitable. This proves
// the HAZARD, not the topology, drives abstention.
// =====================================================================================

// hazardFixture builds an assembly whose Ingress.enter body is `ingressIL` (built from
// the returned token set), with a present-but-unreachable Sink.vuln and the in-set
// members the hazard/negative cases reference. Returns (assembly, ingressRID, sinkRID).
type hzToks struct {
	activatorCreate assembly.Token // MemberRef System.Activator.CreateInstance
	objectToString  assembly.Token // MemberRef System.Object.ToString
	libRun          assembly.Token // MemberRef Ext.Lib.Run(MyDelegate)
	nativeExt       assembly.Token // MethodDef Native.ext (pinvoke)
	leafNoop        assembly.Token // MethodDef Leaf.noop (resolved in-set — the negative control)
	standAlone      assembly.Token // StandAloneSig (calli)
}

func hazardFixture(t *testing.T, ingressIL func(hzToks) []byte) (*assembly.Assembly, uint32, uint32) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	extObj := cTypeDefOrRef(xTypeRef, obj)
	mcDel := b.extTypeRef("System", "MulticastDelegate")
	activator := b.extTypeRef("System", "Activator")
	libType := b.extTypeRef("Ext", "Lib")

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, leafM := b.addType(0, "Leaf", "App", extObj, []mspec{{name: "noop", flags: 0, sig: sigInstVoid, il: body()}})
	// Native.ext: a P/Invoke method (PInvokeImpl|Static), no managed body (RVA 0).
	_, natM := b.addType(0, "Native", "App", extObj, []mspec{{name: "ext", flags: 0x2010, sig: sigStaticVoid, il: nil}})
	// MyDelegate: extends System.MulticastDelegate — an in-set delegate type (the re-entry callback).
	myDel, _ := b.addType(0x102, "MyDelegate", "App", cTypeDefOrRef(xTypeRef, mcDel), nil)

	// Out-of-set MemberRefs + a StandAloneSig for calli.
	toks := hzToks{
		activatorCreate: mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, activator), b.str("CreateInstance"), b.blob(sigStaticVoid))),
		objectToString:  mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, obj), b.str("ToString"), b.blob(sigInstVoid))),
		libRun:          mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, libType), b.str("Run"), b.blob(sigInstClassParam(myDel)))),
		nativeExt:       mtok(xMethodDef, natM[0]),
		leafNoop:        mtok(xMethodDef, leafM[0]),
		standAlone:      mtok(xStandAloneSig, b.row(xStandAloneSig, b.blob(sigStaticVoid))),
	}

	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: ingressIL(toks)}})
	a := b.finish(t)
	return a, inM[0], sinkM[0]
}

func TestReach_Hazards_Undetermined(t *testing.T) {
	cases := []struct {
		name    string
		il      func(hzToks) []byte
		wantWhy string // substring the recorded hazard reason must contain
	}{
		{"reflection", func(k hzToks) []byte { return body(ilCall(k.activatorCreate)) }, "reflection"},
		{"pinvoke", func(k hzToks) []byte { return body(ilCall(k.nativeExt)) }, "p/invoke"},
		{"calli", func(k hzToks) []byte { return body(ilCalli(k.standAlone)) }, "calli"},
		{"out-of-set-receiver", func(k hzToks) []byte { return body(ilCallvirt(k.objectToString)) }, "outside loaded"},
		{"reentry-delegate", func(k hzToks) []byte { return body(ilCall(k.libRun)) }, "re-entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, inRID, sinkRID := hazardFixture(t, tc.il)
			e := NewEngine([]*assembly.Assembly{a})
			res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
			if res.Verdict != Undetermined {
				t.Fatalf("%s verdict = %v, want undetermined (NEVER a false not_exploitable)", tc.name, res.Verdict)
			}
			if !res.HazardOnFrontier {
				t.Fatalf("%s must record a hazard on the frontier", tc.name)
			}
			if !strings.Contains(strings.ToLower(res.HazardWhy), tc.wantWhy) {
				t.Fatalf("%s hazard = %q, want it to mention %q", tc.name, res.HazardWhy, tc.wantWhy)
			}
		})
	}
}

// TestReach_Hazards_NegativeControl: the identical topology with the hazard edge
// replaced by a resolved in-set call (Leaf.noop) must be not_exploitable — proving the
// hazard drives abstention, not the graph shape.
func TestReach_Hazards_NegativeControl(t *testing.T) {
	a, inRID, sinkRID := hazardFixture(t, func(k hzToks) []byte { return body(ilCall(k.leafNoop)) })
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	if res.Verdict != NotExploitable {
		t.Fatalf("negative control verdict = %v (%s), want not_exploitable", res.Verdict, res.HazardWhy)
	}
	if res.HazardOnFrontier {
		t.Fatalf("negative control must be hazard-free; got %q", res.HazardWhy)
	}
}

// =====================================================================================
// Test 5 — ingress/sink not found => undetermined (never not_exploitable).
// =====================================================================================

func TestReach_NotFound_Undetermined(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)
	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", ext, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, inM := b.addType(0, "Ingress", "App", ext, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body()}})
	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})

	realIn := keyByRID(t, e, a, inM[0])
	realSink := keyByRID(t, e, a, sinkM[0])
	absent := MethodKey{Owner: "App.Ghost", Name: "missing", Sig: realSink.Sig}

	if got := e.Reach(absent, realSink); got.Verdict != Undetermined || !got.HazardOnFrontier {
		t.Fatalf("absent ingress verdict = %v (hazard=%v), want undetermined", got.Verdict, got.HazardOnFrontier)
	}
	if got := e.Reach(realIn, absent); got.Verdict != Undetermined || got.SinkPresent {
		t.Fatalf("absent sink verdict = %v (present=%v), want undetermined with SinkPresent=false", got.Verdict, got.SinkPresent)
	}
}

// =====================================================================================
// Test 6 — OUT-OF-SET DIRECT-CALL LEAF => hazard (barrier-2 engine review, BLOCKING #1/#2).
//
// A direct call/newobj to a callee whose body is not in the loaded set is UNREADABLE code
// on the frontier: the engine cannot prove it does not re-enter application code and reach
// the sink (via an app object handed as an out-of-set-typed / object argument, or a
// static/DI global). It is therefore a completeness hazard => undetermined, NEVER a false
// not_exploitable. The prior engine treated it as a clean leaf unless the narrow, in-set-
// only callbackParam recognizer fired — the under-approximation these three tests pin.
//
// NON-VACUITY: reverting the out-of-set-leaf->hazard change in resolveTargets (making the
// tgt.Method==nil branch a leaf again) re-reds all three below — each flips back to
// not_exploitable. The InSet control immediately after stays not_exploitable either way,
// so it is the discriminator between unreadable-callee abstention and a real empty search.
// =====================================================================================

// #1: App.Evil : Ext.BaseThing (out-of-set base) overrides bite() -> Sink.vuln;
// Ingress.enter -> call Ext.Lib.Run(class Ext.BaseThing). Runtime path Lib.Run(evil) ->
// evil.bite() -> Sink.vuln is invisible to the static graph (out-of-set Lib.Run), so the
// sound verdict is abstention, not not_exploitable.
func TestReach_OutOfSetCallWithOutOfSetBaseParam_Undetermined(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	extObj := cTypeDefOrRef(xTypeRef, obj)
	baseThing := b.extTypeRef("Ext", "BaseThing") // out-of-set base class
	libType := b.extTypeRef("Ext", "Lib")

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	// The real (invisible) re-entry sink path; never enqueued because nothing in-set edges to it.
	b.addType(0, "Evil", "App", cTypeDefOrRef(xTypeRef, baseThing), []mspec{
		{name: "bite", flags: 0x40, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	libRun := mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, libType), b.str("Run"), b.blob(sigInstClassParamRef(baseThing))))
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(libRun))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	if res.Verdict != Undetermined {
		t.Fatalf("verdict = %v (%s), want undetermined (out-of-set callee body is unreadable)", res.Verdict, res.HazardWhy)
	}
	if !res.HazardOnFrontier {
		t.Fatalf("out-of-set call must record a hazard on the frontier; got %q", res.HazardWhy)
	}
}

// #1: same shape, param typed System.Object — an app object with an overridden virtual
// (ToString/Equals) handed to a framework callback. System.Object is out-of-set, so the old
// callbackParam saw a plain leaf.
func TestReach_OutOfSetCallWithObjectParam_Undetermined(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	extObj := cTypeDefOrRef(xTypeRef, obj)
	libType := b.extTypeRef("Ext", "Lib")

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	libRun := mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, libType), b.str("Run"), b.blob(sigInstClassParamRef(obj))))
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(libRun))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	if res.Verdict != Undetermined {
		t.Fatalf("verdict = %v (%s), want undetermined (object param to out-of-set callee)", res.Verdict, res.HazardWhy)
	}
	if !res.HazardOnFrontier {
		t.Fatalf("must record a hazard on the frontier; got %q", res.HazardWhy)
	}
}

// #2: Ingress.enter -> call Ext.Lib.Process() — non-virtual instance call, 0 params,
// out-of-set body. A framework object whose instance method invokes an app-registered
// singleton reaches the sink at runtime; the old engine called this a silent leaf.
func TestReach_OutOfSetInstanceCall_Undetermined(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	extObj := cTypeDefOrRef(xTypeRef, obj)
	libType := b.extTypeRef("Ext", "Lib")

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	libProcess := mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, libType), b.str("Process"), b.blob(sigInstVoid)))
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(libProcess))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	if res.Verdict != Undetermined {
		t.Fatalf("verdict = %v (%s), want undetermined (out-of-set instance-call body)", res.Verdict, res.HazardWhy)
	}
	if !res.HazardOnFrontier {
		t.Fatalf("must record a hazard on the frontier; got %q", res.HazardWhy)
	}
}

// In-set control (mirrors the review's InSetBaseParam / test-2): a fully-in-set, genuinely
// unreachable, hazard-free graph must STILL be not_exploitable after the fix. The fix only
// touches out-of-set/unreadable callees; resolved in-set edges are unaffected, so a real
// empty search is preserved and distinguished from unreadable-callee abstention.
func TestReach_InSetUnreachable_NotExploitable_Control(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", ext, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, leafM := b.addType(0, "Leaf", "App", ext, []mspec{{name: "noop", flags: 0, sig: sigInstVoid, il: body()}})
	noopTok := mtok(xMethodDef, leafM[0])
	_, inM := b.addType(0, "Ingress", "App", ext, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(noopTok))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	if res.Verdict != NotExploitable {
		t.Fatalf("verdict = %v (%s), want not_exploitable (in-set unreachable, hazard-free)", res.Verdict, res.HazardWhy)
	}
	if res.HazardOnFrontier {
		t.Fatalf("in-set control must stay hazard-free; got %q", res.HazardWhy)
	}
}
