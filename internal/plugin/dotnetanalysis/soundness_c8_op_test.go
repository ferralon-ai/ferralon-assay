package dotnetanalysis

// soundness_c8_op_test.go — the OP-level (Reachability) half of the barrier-5 (C8)
// non-author soundness attack: channel 9, the EntryPoint-rooting gap. ilReachability roots
// the two-trace search SOLELY at the first-party assembly EntryPoint (idx.entryKey = Main)
// and adds no other roots. That is sound for a plain console app, and it degrades correctly
// whenever reaching a non-Main entry requires an out-of-set call on Main's frontier (the
// realistic framework-host case, TestC8_Channel9_HostRunOrphan_Undetermined). But two
// runtime-invoked .NET entries run with NO call edge from Main AND no out-of-set hazard —
// the MODULE INITIALIZER (<Module>::.cctor, run unconditionally at load) and the FINALIZER
// (Object.Finalize override, invoked by the GC) — and the op clears a sink reachable only
// through them as a clean not_exploitable. Those are the two FALSE-NE repros below; per the
// dispatch they assert the SOUND expectation and therefore FAIL against the frozen op until
// a fixer roots those entries (test-only deposit — no production edit here).
//
// Every .dll is a real synthesized PE (the peb builder in reachability_il_c5_test.go),
// composed hermetically; nothing is executed, restored, or loaded.

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ilNewobjOp is the `newobj <ctor>` instruction (op-package local; the c5 builder exposes
// only ilCall/ilCallvirt).
func ilNewobjOp(t uint32) []byte { return append([]byte{0x73}, tok4(t)...) }

// runReach composes a single-first-party-dll BuildDir and runs the op for one sink SCIP.
func runReach(t *testing.T, appDLL []byte, sinkSCIP string) plugin.ReachabilityResult {
	t.Helper()
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":  []byte("<Project></Project>"),
		"bin/App.dll": appDLL,
	})
	res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sinkSCIP}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	return res
}

// =====================================================================================
// Channel 9 — REPELLED cases.
// =====================================================================================

// A realistic framework-hosted app: Main calls an OUT-OF-SET host (Ext.Host.Run) that
// invokes a Controller.Action reaching the sink. The out-of-set host call is a frontier
// hazard on Main's search, so the op degrades to undetermined — never a clean NE. This is
// why the op's Main-only rooting is sound for real framework apps.
func TestC8_Channel9_HostRunOrphan_Undetermined(t *testing.T) {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	host := b.extTypeRef("Ext", "Host")
	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", obj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	b.addType(0, "Controller", "App", obj, []mspec{{name: "Action", flags: 0x40, sig: sigInstVoid, il: body(ilCall(vulnTok))}})
	runRef := b.memberRef(host, "Run", sigStaticVoid)
	_, inM := b.addType(0, "Ingress", "App", obj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(runRef))}})
	b.entry = mtok(xMethodDef, inM[0])

	res := runReach(t, b.bytesNamed("App"), funcSCIP("App", []string{"Sink"}, "vuln", 0))
	if res.Partiality.Complete {
		t.Fatalf("out-of-set host bootstrap must degrade to undetermined, not a clean NE")
	}
	if !hasILReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Fatalf("want reachability_undetermined, got %v", res.Partiality.Reasons)
	}
}

// A LIBRARY assembly (no EntryPoint) has no addressable root, so every sink degrades to
// undetermined — never a clean NE from an unrooted search.
func TestC8_Channel9_LibraryNoEntry_Undetermined(t *testing.T) {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	// A reachable-looking topology, but no EntryPoint (b.entry stays 0).
	b.addType(0, "Sink", "App", obj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, 2)
	b.addType(0, "Api", "App", obj, []mspec{{name: "Handle", flags: 0x40, sig: sigInstVoid, il: body(ilCall(vulnTok))}})

	res := runReach(t, b.bytesNamed("App"), funcSCIP("App", []string{"Sink"}, "vuln", 0))
	if res.Partiality.Complete {
		t.Fatalf("a library (no EntryPoint) must never produce a clean NE; got Complete")
	}
	if !hasILReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Fatalf("want reachability_undetermined for the unrooted library, got %v", res.Partiality.Reasons)
	}
}

// =====================================================================================
// Channel 9 — FALSE-NE repros (FAILING until the op roots these entries).
// =====================================================================================

// DEFECT: module-initializer-reachable sink cleared as a clean not_exploitable.
// <Module>::.cctor (the module initializer) reaches the sink and is run UNCONDITIONALLY by
// the CLR at assembly load, before Main. Main itself is empty (hazard-free), so the op —
// rooted only at Main — never enqueues the module initializer and returns Complete with no
// path: a false not_exploitable for a sink that always executes.
//
// FIX HYPOTHESIS: ilReachability must add the first-party <Module>::.cctor as an additional
// search root (union with Main), or degrade any sink to undetermined when a module
// initializer is present and unreached from Main.
func TestC8_FalseNE_ModuleInitializer(t *testing.T) {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	// <Module>::.cctor is MethodDef RID 1; Sink.vuln is RID 2 (forward reference).
	vulnTok := mtok(xMethodDef, 2)
	b.addType(0, "<Module>", "", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body(ilCall(vulnTok))}})
	b.addType(0, "Sink", "App", obj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, inM := b.addType(0, "Ingress", "App", obj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body()}})
	b.entry = mtok(xMethodDef, inM[0])

	res := runReach(t, b.bytesNamed("App"), funcSCIP("App", []string{"Sink"}, "vuln", 0))
	if res.Partiality.Complete {
		t.Fatalf("FALSE not_exploitable: a sink reached by the module initializer (<Module>::.cctor, run at load before Main) was cleared as Complete (%d paths). The op roots only at Main and never enqueues the module initializer.", len(res.Paths))
	}
}

// DEFECT: finalizer-reachable sink cleared as a clean not_exploitable.
// Bad.Finalize (an Object.Finalize override) reaches the sink and is invoked by the GC, not
// on any call edge from Main. Main only allocates Bad (newobj). With an IN-SET base chain
// (as in a real spanning set that loads the framework reference assemblies), the newobj is
// hazard-free, Finalize is never enqueued, and the op returns Complete: a false NE for a
// classic finalizer gadget. (In the default hermetic fixture an out-of-set System.Object
// base incidentally masks this to undetermined; the in-set base here removes that mask.)
//
// FIX HYPOTHESIS: when a reachable-from-Main newobj constructs a type with a Finalize
// override, that finalizer must be added as a search root (or the sink degraded to
// undetermined).
func TestC8_FalseNE_Finalizer(t *testing.T) {
	b := scaffold()
	// In-set "System.Object" with a null Extends so the base chain terminates cleanly.
	objRID, _ := b.addType(0, "Object", "System", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body()}})
	inSetObj := cTypeDefOrRef(xTypeDef, objRID)
	b.addType(0, "<Module>", "", 0, nil)
	_, sinkM := b.addType(0, "Sink", "App", inSetObj, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	vulnTok := mtok(xMethodDef, sinkM[0])
	_, badM := b.addType(0, "Bad", "App", inSetObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "Finalize", flags: 0x01C4, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	_, inM := b.addType(0, "Ingress", "App", inSetObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilNewobjOp(mtok(xMethodDef, badM[0])))}})
	b.entry = mtok(xMethodDef, inM[0])

	res := runReach(t, b.bytesNamed("App"), funcSCIP("App", []string{"Sink"}, "vuln", 0))
	if res.Partiality.Complete {
		t.Fatalf("FALSE not_exploitable: a sink reached only by a GC-invoked finalizer (Bad.Finalize) was cleared as Complete (%d paths). The op roots only at Main and models no finalizer.", len(res.Paths))
	}
}
