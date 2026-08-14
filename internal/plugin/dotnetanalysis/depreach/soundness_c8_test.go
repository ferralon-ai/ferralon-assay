package depreach

// soundness_c8_test.go — the INDEPENDENT, NON-AUTHOR barrier-5 (C8) soundness attack on
// the two-trace PoNE engine. Each test manufactures a fixture where the SINK is reachable
// (or its reachability is genuinely undecidable) ONLY through one .NET re-entry channel,
// then asserts the engine does NOT return a clean not_exploitable — either it emits a path
// (ReachableCandidate) or it soundly abstains (Undetermined). Over-approximation to
// Undetermined is SOUND; a clean NotExploitable on a reachable sink is the cardinal §3.1
// under-approximation. Where a channel has a benign in-set analogue, a NEGATIVE CONTROL
// proves the test discriminates (a genuinely-unreachable, hazard-free twin still earns a
// clean NE), so no assertion can pass vacuously.
//
// Every fixture is a REAL synthesized PE parsed by assembly.Read — the peb byte builder is
// the one from engine_test.go / spanning_test.go, extended here (test-only) with the
// MethodImpl / TypeSpec / MethodSpec / ldftn primitives these channels need.
//
// Channels 1-8 are engine-level and are all REPELLED here. The EntryPoint-rooting gap
// (channel 9) is an OP-level rooting defect and lives in the dotnetanalysis package
// (soundness_c8_op_test.go).

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// ---- peb extensions (test-only) for the C8 channels ----

const (
	xMethodImpl = 0x19
	xTypeSpec   = 0x1B
	xMethodSpec = 0x2B
)

// cMethodDefOrRef encodes a MethodDefOrRef coded index (ECMA-335 §II.24.2.6, tagBits=1):
// MethodDef tag 0, MemberRef tag 1.
func cMethodDefOrRef(table int, rid uint32) uint32 {
	tag := map[int]uint32{xMethodDef: 0, xMemberRef: 1}[table]
	return rid<<1 | tag
}

// cMRParentTypeSpec encodes a MemberRefParent coded index pointing at a TypeSpec (tag 4).
func cMRParentTypeSpec(rid uint32) uint32 { return rid<<3 | 4 }

// ilLdftn is the `ldftn <method>` instruction (0xFE 0x06 + 4-byte token) — delegate target
// capture.
func ilLdftn(t assembly.Token) []byte { return append([]byte{0xFE, 0x06}, tok4(t)...) }

// ifaceImpl adds an InterfaceImpl row wiring classRID to the in-set interface ifaceRID.
func (b *peb) ifaceImpl(classRID, ifaceRID uint32) uint32 {
	return b.row(xInterfaceImpl, classRID, cTypeDefOrRef(xTypeDef, ifaceRID))
}

// methodImplRow adds a MethodImpl row: type classRID's Body method (a MethodDef RID) satisfies
// the Declaration method (a MethodDef RID). Body is matched by the slot, never by name — the
// explicit-interface / .override channel.
func (b *peb) methodImplRow(classRID, bodyRID, declRID uint32) uint32 {
	return b.row(xMethodImpl, classRID, cMethodDefOrRef(xMethodDef, bodyRID), cMethodDefOrRef(xMethodDef, declRID))
}

// typeSpecRow adds a TypeSpec row (a constructed/generic type) with a signature blob.
func (b *peb) typeSpecRow(blob []byte) uint32 { return b.row(xTypeSpec, b.blob(blob)) }

// methodSpecRow adds a MethodSpec row: the open method (a MethodDef RID) plus the
// instantiation blob — the generic-method call-site descriptor.
func (b *peb) methodSpecRow(openMethodRID uint32, inst []byte) uint32 {
	return b.row(xMethodSpec, cMethodDefOrRef(xMethodDef, openMethodRID), b.blob(inst))
}

// a generic-method signature blob: GENERIC|HASTHIS, 1 generic param, 0 params, ret void.
var sigGenericVirtual = []byte{0x30, 0x01, 0x00, 0x01}

// a minimal GENERICINST TypeSpec blob (Gen<int32>): ELEMENT_TYPE_GENERICINST, class, a
// TypeDefOrRef coded to the open type, 1 arg, I4. Only its presence matters (IsSpec
// short-circuits resolution), so the exact operand is not load-bearing.
func genInstBlob(openTypeDefRID uint32) []byte {
	return []byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeDef, openTypeDefRID)), 0x01, 0x08}
}

// mustReach asserts a ReachableCandidate whose path mentions want.
func mustReach(t *testing.T, res Result, want string) {
	t.Helper()
	if res.Verdict != ReachableCandidate {
		t.Fatalf("verdict = %v (%s), want reachable_candidate", res.Verdict, res.HazardWhy)
	}
	if want != "" && !strings.Contains(PathString(res.Path), want) {
		t.Fatalf("path = %q, want it to route through %q", PathString(res.Path), want)
	}
}

// mustAbstain asserts Undetermined with a frontier hazard mentioning wantWhy.
func mustAbstain(t *testing.T, res Result, wantWhy string) {
	t.Helper()
	if res.Verdict != Undetermined {
		t.Fatalf("verdict = %v (%s), want undetermined (NEVER a clean not_exploitable)", res.Verdict, res.HazardWhy)
	}
	if !res.HazardOnFrontier {
		t.Fatalf("undetermined must record a hazard on the frontier; got none")
	}
	if wantWhy != "" && !strings.Contains(strings.ToLower(res.HazardWhy), strings.ToLower(wantWhy)) {
		t.Fatalf("hazard = %q, want it to mention %q", res.HazardWhy, wantWhy)
	}
}

// mustCleanNE asserts a clean, hazard-free NotExploitable (the earned confident-safe).
func mustCleanNE(t *testing.T, res Result) {
	t.Helper()
	if res.Verdict != NotExploitable {
		t.Fatalf("verdict = %v (%s), want not_exploitable (control must earn the clean NE)", res.Verdict, res.HazardWhy)
	}
	if res.HazardOnFrontier {
		t.Fatalf("clean NE must be hazard-free; got %q", res.HazardWhy)
	}
}

// =====================================================================================
// Channel 1b — GENERIC type static-initializer re-entry.
// A generic type instantiation appears at the call site as a TypeSpec; the type-init
// trigger cannot resolve the open type through it, so the closure over-approximates to a
// completeness hazard (undetermined) rather than silently clearing. The resolvable
// (non-spec) control proves the Gen.cctor->Sink edge is real and only the TypeSpec
// indirection drives the sound abstention.
// =====================================================================================

func TestC8_Channel1b_GenericCctor_TypeSpecTrigger_Undetermined(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	// Gen`1: an in-set generic type whose .cctor reaches the sink, plus a static noop for
	// the resolvable control.
	genRID, _ := b.addType(0, "Gen`1", "App", extObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body(ilCall(vulnTok))},
		{name: "noop", flags: 0x0016, sig: sigStaticVoid, il: body()}, // static
	})
	// Ingress: newobj Gen<int>::.ctor via a MemberRef whose parent is a TypeSpec.
	tsRID := b.typeSpecRow(genInstBlob(genRID))
	ctorSpecRef := mtok(xMemberRef, b.row(xMemberRef, cMRParentTypeSpec(tsRID), b.str(".ctor"), b.blob(sigInstVoid)))
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilNewobj(ctorSpecRef))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	// The generic .cctor->Sink path is real; the TypeSpec indirection is unreadable, so the
	// sound outcome is abstention, never a clean NE.
	mustAbstain(t, res, "")
}

func TestC8_Channel1b_GenericCctor_Resolvable_Control(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	genRID, genM := b.addType(0, "Gen`1", "App", extObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body(ilCall(vulnTok))},
		{name: "noop", flags: 0x0016, sig: sigStaticVoid, il: body()},
	})
	_ = genRID
	// A static call to Gen`1::noop is an InitStaticCall trigger with a resolvable MethodDef
	// token, so the type-init closure runs and reaches the sink through the .cctor.
	noopTok := mtok(xMethodDef, genM[2])
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(noopTok))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	mustReach(t, res, ".cctor -> Sink.vuln")
}

// =====================================================================================
// Channel 1c — beforefieldinit static-init timing.
// beforefieldinit relaxes WHEN the CLR runs a .cctor, not WHETHER; the engine models the
// edge regardless. A beforefieldinit type whose .cctor reaches the sink is still reached.
// =====================================================================================

const taBeforeFieldInit = 0x00100000

// channel1cFixture: Trig is beforefieldinit and extends an IN-SET root (null Extends), so
// the base chain terminates cleanly (no out-of-set-Object hazard) and the inert control can
// earn a genuine clean NE. When cctorReachesSink, Trig's .cctor calls the sink.
func channel1cFixture(t *testing.T, cctorReachesSink bool) (*assembly.Assembly, uint32, uint32) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	// In-set root with a null Extends: the base chain terminates here with no out-of-set link.
	rootRID, _ := b.addType(0, "Root", "App", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body()}})
	cctorIL := body()
	if cctorReachesSink {
		cctorIL = body(ilCall(vulnTok))
	}
	_, trigM := b.addType(taBeforeFieldInit, "Trig", "App", cTypeDefOrRef(xTypeDef, rootRID), []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: cctorIL},
	})
	ctorTok := mtok(xMethodDef, trigM[0])
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilNewobj(ctorTok))}})

	a := b.finish(t)
	return a, inM[0], sinkM[0]
}

func TestC8_Channel1c_BeforeFieldInit_Reachable(t *testing.T) {
	a, inRID, sinkRID := channel1cFixture(t, true)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	mustReach(t, res, ".cctor -> Sink.vuln")
}

func TestC8_Channel1c_BeforeFieldInit_InertControl_CleanNE(t *testing.T) {
	a, inRID, sinkRID := channel1cFixture(t, false)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	mustCleanNE(t, res)
}

// =====================================================================================
// Channel 2 — explicit-interface implementation (MethodImpl / .override).
// The sink is reachable only through the interface slot, whose implementing body is
// PRIVATELY NAMED (never named after the interface method). A name-only resolver misses
// it and returns a false NE; the MethodImpl slot map catches it. Negative control: the
// same explicit-impl slot routed to a NOOP body earns a clean NE — so the reach came from
// following the slot to the specific body, not from any blanket hazard.
// =====================================================================================

func channel2Fixture(t *testing.T, bodyReachesSink bool) (*assembly.Assembly, uint32, uint32) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, leafM := b.addType(0, "Leaf", "App", extObj, []mspec{{name: "noop", flags: 0, sig: sigInstVoid, il: body()}})
	// IFace: an interface with abstract slot M (RVA 0).
	ifaceRID, ifaceM := b.addType(0x000000A0, "IFace", "App", 0, []mspec{
		{name: "M", flags: 0x05C6, sig: sigInstVoid, il: nil},
	})
	mDeclTok := ifaceM[0] // MethodDef RID of IFace::M
	// Impl : IFace. Its implementing body is PRIVATELY NAMED "zz_priv" (not "M"), reachable
	// only via the MethodImpl slot. The body calls the sink (or a noop for the control).
	target := mtok(xMethodDef, sinkM[0])
	if !bodyReachesSink {
		target = mtok(xMethodDef, leafM[0])
	}
	implRID, implM := b.addType(0, "Impl", "App", extObj, []mspec{
		{name: "zz_priv", flags: 0x01E3, sig: sigInstVoid, il: body(ilCall(target))}, // private final virtual
	})
	b.ifaceImpl(implRID, ifaceRID)
	b.methodImplRow(implRID, implM[0], mDeclTok) // Body=Impl.zz_priv, Declaration=IFace::M
	// Ingress: callvirt IFace::M — dispatch must route through the explicit slot to zz_priv.
	mTok := mtok(xMethodDef, ifaceM[0])
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCallvirt(mTok))}})

	a := b.finish(t)
	return a, inM[0], sinkM[0]
}

func TestC8_Channel2_ExplicitInterfaceImpl_Reachable(t *testing.T) {
	a, inRID, sinkRID := channel2Fixture(t, true)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	// zz_priv is not named "M": reaching it PROVES the MethodImpl slot was followed.
	mustReach(t, res, "Impl.zz_priv -> Sink.vuln")
}

func TestC8_Channel2_ExplicitInterfaceImpl_NoopControl_CleanNE(t *testing.T) {
	a, inRID, sinkRID := channel2Fixture(t, false)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	mustCleanNE(t, res)
}

// =====================================================================================
// Channel 3 — generic virtual method dispatch (MethodSpec at the call site).
// callvirt through a MethodSpec must unwrap to the open method and expand the conservative
// override set; the derived override that reaches the sink must be found. Control: the
// override routed to a noop earns a clean NE.
// =====================================================================================

func channel3Fixture(t *testing.T, overrideReachesSink bool) (*assembly.Assembly, uint32, uint32) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, leafM := b.addType(0, "Leaf", "App", extObj, []mspec{{name: "noop", flags: 0, sig: sigInstVoid, il: body()}})
	// Base: abstract generic virtual M<T> (RVA 0 — the declaration slot).
	baseRID, baseM := b.addType(0x00000080, "Base", "App", extObj, []mspec{
		{name: "M", flags: 0x05C6, sig: sigGenericVirtual, il: nil},
	})
	// Impl : Base overrides M<T> with the SAME open signature; its body reaches the sink.
	target := mtok(xMethodDef, sinkM[0])
	if !overrideReachesSink {
		target = mtok(xMethodDef, leafM[0])
	}
	b.addType(0, "Impl", "App", cTypeDefOrRef(xTypeDef, baseRID), []mspec{
		{name: "M", flags: 0x01C6, sig: sigGenericVirtual, il: body(ilCall(target))},
	})
	// Ingress: callvirt <MethodSpec of Base::M<int>>.
	msRID := b.methodSpecRow(baseM[0], []byte{0x0A, 0x01, 0x08}) // GENERICINST, 1 arg, I4
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCallvirt(mtok(xMethodSpec, msRID)))}})

	a := b.finish(t)
	return a, inM[0], sinkM[0]
}

func TestC8_Channel3_GenericVirtual_Reachable(t *testing.T) {
	a, inRID, sinkRID := channel3Fixture(t, true)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	mustReach(t, res, "Impl.M -> Sink.vuln")
}

func TestC8_Channel3_GenericVirtual_NoopControl_CleanNE(t *testing.T) {
	a, inRID, sinkRID := channel3Fixture(t, false)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inRID), keyByRID(t, e, a, sinkRID))
	mustCleanNE(t, res)
}

// =====================================================================================
// Channel 4 — out-of-assembly-set receiver.
// (a) A callvirt whose declared OWNER is out-of-set is an open-world receiver => hazard.
// (b) An in-set interface WITH an in-set implementer that reaches the sink is a real path
//     (the CHA candidate set finds in-set overrides), so a reachable interface sink is a
//     PATH, never a missed NE.
// NOTE on the closed-world boundary: an in-set interface/abstract type with ZERO in-set
// implementers yields an empty candidate set and a clean NE. That is sound under the loaded
// SPANNING set's closed-world assumption (no loaded type can construct the receiver, so the
// call site is dead) and is backstopped at the op by the fact that any out-of-set receiver
// must arrive via an out-of-set construction/call — itself a frontier hazard. It is NOT a
// standalone engine defect; it is only exposed by rooting at an arbitrary handler that takes
// the interface as a parameter, which the op (Main-rooted) never does.
// =====================================================================================

func TestC8_Channel4_OutOfSetOwnerReceiver_Undetermined(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	toStringRef := mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, b.extTypeRef("System", "Object")), b.str("ToString"), b.blob(sigInstVoid)))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCallvirt(toStringRef))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	mustAbstain(t, res, "outside loaded")
}

func TestC8_Channel4_InSetInterfaceImplementer_Reachable(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	ifaceRID, ifaceM := b.addType(0x000000A0, "IFace", "App", 0, []mspec{
		{name: "M", flags: 0x05C6, sig: sigInstVoid, il: nil},
	})
	// Impl : IFace with a public M (implicit implementation) that reaches the sink.
	implRID, _ := b.addType(0, "Impl", "App", extObj, []mspec{
		{name: "M", flags: 0x01C6, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	b.ifaceImpl(implRID, ifaceRID)
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCallvirt(mtok(xMethodDef, ifaceM[0])))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	mustReach(t, res, "Impl.M -> Sink.vuln")
}

// =====================================================================================
// Channel 5 — delegate / function-pointer re-entry.
// An ldftn capture of a method that reaches the sink enqueues that method conservatively
// (the delegate could be invoked), so the sink is reached. An ldftn to an OUT-OF-SET target
// is an open-world capture => hazard. (calli is covered in engine_test.go.)
// =====================================================================================

func TestC8_Channel5_LdftnTargetReachesSink_Reachable(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	_, cbM := b.addType(0, "Handlers", "App", extObj, []mspec{{name: "cb", flags: 0x0016, sig: sigStaticVoid, il: body(ilCall(vulnTok))}})
	cbTok := mtok(xMethodDef, cbM[0])
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilLdftn(cbTok))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	mustReach(t, res, "Handlers.cb -> Sink.vuln")
}

func TestC8_Channel5_LdftnOutOfSetTarget_Undetermined(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	libType := b.extTypeRef("Ext", "Lib")
	extCbRef := mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, libType), b.str("Cb"), b.blob(sigStaticVoid)))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilLdftn(extCbRef))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	mustAbstain(t, res, "ldftn")
}

// =====================================================================================
// Channel 6 — P/Invoke. A [DllImport]/native target body is opaque (may re-enter managed
// via a callback) => hazard. (engine_test.go covers the direct-call form; this reinforces
// via a native target with a callback-shaped parameter.)
// =====================================================================================

func TestC8_Channel6_PInvokeCallbackParam_Undetermined(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	// native: PInvokeImpl|Static, no managed body.
	_, natM := b.addType(0, "Native", "App", extObj, []mspec{{name: "ext", flags: 0x2016, sig: sigStaticVoid, il: nil}})
	natTok := mtok(xMethodDef, natM[0])
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(natTok))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	mustAbstain(t, res, "p/invoke")
}

// =====================================================================================
// Channel 7 — DLR `dynamic`. A Microsoft.CSharp.RuntimeBinder-mediated call site resolves
// its real member at runtime => hazard.
// =====================================================================================

func TestC8_Channel7_DlrDynamic_Undetermined(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	binder := b.extTypeRef("Microsoft.CSharp.RuntimeBinder", "Binder")
	invokeRef := mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, binder), b.str("InvokeMember"), b.blob(sigStaticVoid)))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(invokeRef))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	mustAbstain(t, res, "dynamic")
}

// =====================================================================================
// Channel 8 — reflection. The named-reflection map is only a diagnostic sharpener; the
// load-bearing backstop is the out-of-set-owner rule. A reflection entry point NOT in the
// map (ConstructorInfo.Invoke) still abstains because its owner is out-of-set — proving the
// soundness does not depend on the enumerated map being complete.
// =====================================================================================

func TestC8_Channel8_ReflectionOffMapBackstop_Undetermined(t *testing.T) {
	b := scaffold()
	extObj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	ctorInfo := b.extTypeRef("System.Reflection", "ConstructorInfo") // NOT in reflectionSinks
	invokeRef := mtok(xMemberRef, b.row(xMemberRef, cMemberRefParent(xTypeRef, ctorInfo), b.str("Invoke"), b.blob(sigInstVoid)))

	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", extObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, inM := b.addType(0, "Ingress", "App", extObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCallvirt(invokeRef))}})

	a := b.finish(t)
	e := NewEngine([]*assembly.Assembly{a})
	res := e.Reach(keyByRID(t, e, a, inM[0]), keyByRID(t, e, a, sinkM[0]))
	// Off-map name, but the out-of-set owner backstops it to a boundary hazard.
	mustAbstain(t, res, "outside loaded")
}
