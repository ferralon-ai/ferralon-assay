package dotnetanalysis

// soundness_c8_recert3_deproot_test.go — barrier-5 ROUND-3 re-certification. Non-author attack
// on the whole-set runtimeRootKeys enumeration (reachability_il.go). The round-3 delta widened
// the runtime-root enumeration from first-party-only to the ENTIRE loaded spanning set. These
// fixtures hunt a NEW false not_exploitable the widening still misses, and pin the precision
// cost it carries. Test-only, hermetic peb PEs, nothing executed.

import (
	"slices"
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

// REALISTIC FINALIZER (hypothesis 3, concrete) — a C# destructor compiles to Finalize() that
// calls base.Finalize() (System.Object::Finalize) in a finally. Rooting every dep finalizer is
// sound; whether an unrelated dep sink survives it depends on the framework model. On a
// .NET Core target, System.Object::Finalize is a shared-framework leaf with no re-entry into
// application code here, so the unrelated sink is searched. On a target the model does not
// cover, the base call leaves the loaded set and degrades every sink to undetermined.
func TestC8_Recert3_DepRealisticFinalizer(t *testing.T) {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()}})
	objFinalize := db.memberRef(db.extTypeRef("System", "Object"), "Finalize", sigInstVoid)
	// Res: an IDisposable-style type whose finalizer does NOT reach boom but DOES call the
	// base System.Object::Finalize — the shape every real C# destructor emits.
	db.addType(0, "Res", "D", dObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "Finalize", flags: 0x01C4, sig: sigInstVoid, il: body(ilCallvirt(objFinalize))},
	})
	dep := db.bytesNamed("Dep")

	t.Run("net8.0: framework leaf, sink searched", func(t *testing.T) {
		res := runReachSet(t, appEmptyMain(t), dep, depSinkSCIP)
		if !slices.Contains(res.Searched, depSinkSCIP) || len(res.Paths) != 0 {
			t.Fatalf("Searched=%v paths=%d partiality=%+v, want the unrelated sink searched", res.Searched, len(res.Paths), res.Partiality)
		}
	})
	t.Run("netstandard2.0: no framework model, undetermined", func(t *testing.T) {
		res := runReachSetAssets(t, appEmptyMain(t), dep, depAssetsJSONFor("netstandard2.0", "Dep/1.0.0"), depSinkSCIP)
		if res.Partiality.Complete || slices.Contains(res.Searched, depSinkSCIP) {
			t.Fatalf("expected undetermined: base.Finalize leaves the loaded set, got Searched=%v partiality=%+v", res.Searched, res.Partiality)
		}
		if !hasILReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
			t.Fatalf("want reachability_undetermined from the finalizer's frontier hazard, got %v", res.Partiality.Reasons)
		}
		if len(res.Paths) != 0 {
			t.Fatalf("frontier-hazard undetermined must emit NO path, got %d", len(res.Paths))
		}
	})
}
