package dotnetanalysis

// soundness_c8_recert_test.go — barrier-5-FIX re-certification. Non-author attack on the
// runtimeRootKeys/combination fix in reachability_il.go, hunting a NEW false not_exploitable
// the fix introduces or still misses. Test-only, hermetic peb PEs, nothing executed.

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const xMethodImplRecert = 0x19

// cMethodDefOrRefRecert encodes a MethodDefOrRef coded index (tagBits=1): MethodDef 0, MemberRef 1.
func cMethodDefOrRefRecert(table int, rid uint32) uint32 {
	return rid<<1 | map[int]uint32{xMethodDef: 0, xMemberRef: 1}[table]
}

// methodImplRecert adds a MethodImpl row (§II.22.27): type classRID's Body method overrides
// the Declaration slot — the explicit-override shape whose body may be arbitrarily named.
func (b *peb) methodImplRecert(classRID, bodyCoded, declCoded uint32) uint32 {
	return b.row(xMethodImplRecert, classRID, bodyCoded, declCoded)
}

// =====================================================================================
// RECERT DEFECT (probe 2) — finalizer matcher UNDER-matches a mangled-name Finalize
// override. runtimeRootKeys recognizes a finalizer by NAME (m.Name=="Finalize"). But a
// Finalize override can carry ANY body name when wired through an explicit MethodImpl
// (.override [System.Runtime]System.Object::Finalize) — valid IL the GC still invokes, and
// a shape the engine's own candidateSet/explicitImpl already resolves for dispatch. The
// name-only matcher misses it, so the finalizer is not a root and its sink is cleared as a
// clean not_exploitable.
//
// FIX HYPOTHESIS: recognize a finalizer as ANY method that is the Body of a MethodImpl whose
// Declaration resolves to System.Object::Finalize (mirror the engine's explicitImpl), not by
// the body's name.
// =====================================================================================

func TestC8_Recert_MangledFinalizer_FalseNE(t *testing.T) {
	b := scaffold()
	// In-set Root with a null Extends so the newobj base chain terminates hazard-free.
	rootRID, _ := b.addType(0, "Root", "App", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body()}})
	inSetRoot := cTypeDefOrRef(xTypeDef, rootRID)
	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", inSetRoot, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	// Object::Finalize as an out-of-set MemberRef (the .override Declaration target).
	objFinalize := b.memberRef(b.extTypeRef("System", "Object"), "Finalize", sigInstVoid)
	// Bad : Root. zz_final is virtual and reaches the sink; it is a Finalize override wired by
	// MethodImpl, but is NOT named "Finalize".
	badRID, badM := b.addType(0, "Bad", "App", inSetRoot, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "zz_final", flags: 0x01C4, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	b.methodImplRecert(badRID,
		cMethodDefOrRefRecert(xMethodDef, badM[1]),              // Body = Bad.zz_final
		cMethodDefOrRefRecert(xMemberRef, objFinalize&0xFFFFFF)) // Declaration = System.Object::Finalize
	// Main allocates Bad (so it is genuinely instantiated and finalized) — hazard-free.
	_, inM := b.addType(0, "Ingress", "App", inSetRoot, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilNewobjOp(mtok(xMethodDef, badM[0])))}})
	b.entry = mtok(xMethodDef, inM[0])

	res := runReach(t, b.bytesNamed("App"), funcSCIP("App", []string{"Sink"}, "vuln", 0))
	if res.Partiality.Complete {
		t.Fatalf("FALSE not_exploitable: sink reachable only via a GC-invoked Finalize override wired by MethodImpl with a non-\"Finalize\" body name (zz_final) was cleared as Complete (%d paths). The name-only finalizer matcher misses it.", len(res.Paths))
	}
}

// =====================================================================================
// RECERT DEFECT (probe 4) — library (no Main) + any finalizer/module-init flips public-API
// sinks from undetermined to a clean NE. `hasRoot := mainOK || len(runtimeRoots) > 0`
// conflates the authoritative Main root with the over-approximated runtime roots. For a
// LIBRARY (mainOK=false) that has ANY finalizer (near-universal for IDisposable types), the
// !hasRoot degrade no longer fires, the Main block is skipped, and only the finalizer/
// module-init roots are consulted. A sink reachable via a PUBLIC API method (a consumer-
// invoked ingress, which is NOT a runtime root) is then cleared as clean NE — a regression
// from the pre-fix "library => every sink undetermined".
//
// FIX HYPOTHESIS: runtime roots must not, on their own, license a clean NE. When mainOK is
// false there is no authoritative program root, so degrade every sink to undetermined (as
// before), or root all public/exported methods too.
// =====================================================================================

func TestC8_Recert_LibraryWithFinalizer_FalseNE(t *testing.T) {
	b := scaffold()
	rootRID, _ := b.addType(0, "Root", "App", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body()}})
	inSetRoot := cTypeDefOrRef(xTypeDef, rootRID)
	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", inSetRoot, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	// Res: an ordinary IDisposable-style type with an INERT finalizer (does NOT reach the
	// sink) — its only role is to make runtimeRoots non-empty.
	b.addType(0, "Res", "App", inSetRoot, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "Finalize", flags: 0x01C4, sig: sigInstVoid, il: body()}, // inert finalizer
	})
	// Api.Handle: a PUBLIC library entry point (invoked by consumers) that reaches the sink.
	b.addType(0, "Api", "App", inSetRoot, []mspec{{name: "Handle", flags: 0x46, sig: sigInstVoid, il: body(ilCall(vulnTok))}})
	// NO EntryPoint (a library): b.entry stays 0.

	res := runReach(t, b.bytesNamed("App"), funcSCIP("App", []string{"Sink"}, "vuln", 0))
	if res.Partiality.Complete {
		t.Fatalf("FALSE not_exploitable: a LIBRARY (no Main) sink reachable via its public API (Api.Handle) was cleared as Complete (%d paths) because a finalizer made hasRoot=true and the public API is not a runtime root. Pre-fix this was undetermined.", len(res.Paths))
	}
}

// CONTROL: the SAME library WITHOUT any finalizer/module-init still degrades to undetermined
// (hasRoot=false), proving the defect above is specifically the finalizer/module-init flip —
// not a pre-existing library behavior.
func TestC8_Recert_LibraryNoFinalizer_Control_Undetermined(t *testing.T) {
	b := scaffold()
	rootRID, _ := b.addType(0, "Root", "App", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body()}})
	inSetRoot := cTypeDefOrRef(xTypeDef, rootRID)
	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", inSetRoot, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	b.addType(0, "Api", "App", inSetRoot, []mspec{{name: "Handle", flags: 0x46, sig: sigInstVoid, il: body(ilCall(vulnTok))}})

	res := runReach(t, b.bytesNamed("App"), funcSCIP("App", []string{"Sink"}, "vuln", 0))
	if res.Partiality.Complete {
		t.Fatalf("control regressed: a finalizer-free library must stay undetermined, got Complete")
	}
	if !hasILReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Fatalf("control: want reachability_undetermined, got %v", res.Partiality.Reasons)
	}
}
