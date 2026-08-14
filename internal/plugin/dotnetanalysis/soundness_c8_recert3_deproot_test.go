package dotnetanalysis

// soundness_c8_recert3_deproot_test.go — barrier-5 ROUND-3 re-certification. Non-author attack
// on the whole-set runtimeRootKeys enumeration (reachability_il.go). The round-3 delta widened
// the runtime-root enumeration from first-party-only to the ENTIRE loaded spanning set. These
// fixtures hunt a NEW false not_exploitable the widening still misses, and pin the precision
// cost it carries. Test-only, hermetic peb PEs, nothing executed.

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// PROBE (hypothesis 2b, dependency variant) — the whole-set MethodImpl walk must root a DEP
// finalizer that is a Finalize override wired by an explicit MethodImpl with a MANGLED body
// name (not literally "Finalize"). The name-only match (a) misses it; only the per-assembly
// a.MethodImpls walk (b), applied to the DEP's own tables, catches it. Under the round-2
// fp-only enumeration a dep MethodImpl finalizer was never a root, so a dep sink it reaches
// with no path from first-party Main was cleared as a clean NE. This is the discriminating
// dep analog of the (already-certified) first-party TestC8_Recert_MangledFinalizer_FalseNE:
// it fails against fp-only code and passes only when the walk spans the set. It asserts a
// candidate PATH is emitted, so the flip is genuine reachability through the rooted dep
// finalizer, not an incidental frontier hazard.
func TestC8_Recert3_DepMangledFinalizer_FalseNE(t *testing.T) {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	_, sinkM := db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()}})
	boomTok := mtok(xMethodDef, sinkM[0])
	// Object::Finalize as an out-of-set MemberRef — the .override Declaration target.
	objFinalize := db.memberRef(db.extTypeRef("System", "Object"), "Finalize", sigInstVoid)
	// Bad.zz_final: a virtual Finalize override reaching the sink, wired by MethodImpl but NOT
	// named "Finalize" — invisible to the name-only matcher.
	badRID, badM := db.addType(0, "Bad", "D", dObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "zz_final", flags: 0x01C4, sig: sigInstVoid, il: body(ilCall(boomTok))},
	})
	db.methodImplRecert(badRID,
		cMethodDefOrRefRecert(xMethodDef, badM[1]),              // Body = D.Bad.zz_final
		cMethodDefOrRefRecert(xMemberRef, objFinalize&0xFFFFFF)) // Declaration = System.Object::Finalize

	res := runReachSet(t, appEmptyMain(t), db.bytesNamed("Dep"), depSinkSCIP)
	if res.Partiality.Complete {
		t.Fatalf("FALSE not_exploitable: a dep sink reached only by a GC-invoked DEP Finalize override wired by MethodImpl with a non-\"Finalize\" body name (D.Bad.zz_final) was cleared as Complete (%d paths). The MethodImpl finalizer walk must span the whole set.", len(res.Paths))
	}
	if len(res.Paths) == 0 {
		t.Fatalf("expected a candidate path proving the dep MethodImpl finalizer was rooted and genuinely reaches the sink (not merely a frontier-hazard degrade), got 0")
	}
}

// PRECISION FLOOR (hypothesis 3, concrete) — rooting EVERY dep finalizer degrades an UNRELATED
// dep sink to undetermined whenever a dep finalizer's frontier touches out-of-set code. A
// realistic C# destructor compiles to Finalize() that calls base.Finalize() (System.Object::
// Finalize, out-of-set) in a finally — a frontier hazard. Reach(dep-finalizer, sink) then
// returns Undetermined for EVERY sink, so a dep sink the finalizer never reaches still clears
// off the confident-safe. This is SOUND (over-degrade, never a false NE), but it shows the
// deposited CleanNE control's INERT empty-body finalizer is unrepresentative of real deps:
// confident dep-sink NE is unreachable for any dep whose finalizer touches the framework
// boundary (near-universal). Documented as a precision limit, not a defect.
func TestC8_Recert3_DepRealisticFinalizer_PrecisionFloor(t *testing.T) {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()}})
	objFinalize := db.memberRef(db.extTypeRef("System", "Object"), "Finalize", sigInstVoid)
	// Res: an IDisposable-style type whose finalizer does NOT reach boom but DOES call the
	// out-of-set base System.Object::Finalize — the shape every real C# destructor emits.
	db.addType(0, "Res", "D", dObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "Finalize", flags: 0x01C4, sig: sigInstVoid, il: body(ilCallvirt(objFinalize))},
	})

	res := runReachSet(t, appEmptyMain(t), db.bytesNamed("Dep"), depSinkSCIP)
	if res.Partiality.Complete {
		t.Fatalf("expected undetermined: a dep finalizer calling out-of-set base.Finalize is a frontier hazard that degrades the dep sink, got Complete")
	}
	if !hasILReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Fatalf("precision floor: want reachability_undetermined from the dep finalizer's frontier hazard, got %v", res.Partiality.Reasons)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("frontier-hazard undetermined must emit NO path (the finalizer does not reach the sink), got %d", len(res.Paths))
	}
}
