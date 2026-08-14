package dotnetanalysis

// soundness_c8_deproot_test.go — barrier-5-fix round-3: the runtime-root enumeration must span
// the ENTIRE loaded spanning set, not just the first-party assembly. A DEPENDENCY's module
// initializer or finalizer can reach a DEPENDENCY sink with NO call path from first-party Main
// — the exact dep-CVE-sink class this product targets — and an fp-only enumeration would clear
// it as a clean not_exploitable. Two false-NE repros (dep module-init, dep finalizer) plus a
// precision CONTROL (a dep sink genuinely unreachable from Main AND every runtime root across
// the set still earns a clean NE). Hermetic peb PEs, multi-assembly BuildDir; nothing executed.

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// runReachSet composes an App.dll + Dep.dll BuildDir (Dep listed in project.assets.json so
// LoadSpanningSet loads it) and runs the op for one sink SCIP.
func runReachSet(t *testing.T, appDLL, depDLL []byte, sinkSCIP string) plugin.ReachabilityResult {
	t.Helper()
	dir := composeILBuildDir(t, map[string][]byte{
		"App.csproj":              []byte("<Project></Project>"),
		"bin/App.dll":             appDLL,
		"bin/Dep.dll":             depDLL,
		"obj/project.assets.json": depAssetsJSON("Dep/1.0.0"),
	})
	res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sinkSCIP}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	return res
}

// appEmptyMain builds App.dll whose EntryPoint (Ingress.enter) has an empty body: it reaches no
// sink and carries no frontier hazard, so Main's two-trace is a hazard-free NotExploitable.
func appEmptyMain(t *testing.T) []byte {
	t.Helper()
	ab := scaffold()
	aObj := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
	ab.addType(0, "<Module>", "", 0, nil)
	_, inM := ab.addType(0, "Ingress", "App", aObj, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body()}})
	ab.entry = mtok(xMethodDef, inM[0])
	return ab.bytesNamed("App")
}

var depSinkSCIP = funcSCIP("D", []string{"Sink"}, "boom", 0)

// DEFECT: a DEP module-initializer-reachable dep sink cleared as a clean not_exploitable.
// Dep's <Module>::.cctor runs unconditionally at Dep's load and reaches D.Sink.boom; first-party
// Main is empty and never enqueues it. An fp-only root enumeration returns Complete with no path.
func TestC8_DepModuleInitializer_FalseNE(t *testing.T) {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	// <Module>::.cctor is MethodDef RID 1; Sink.boom is RID 2 (forward reference).
	boomTok := mtok(xMethodDef, 2)
	db.addType(0, "<Module>", "", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body(ilCall(boomTok))}})
	db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()}})

	res := runReachSet(t, appEmptyMain(t), db.bytesNamed("Dep"), depSinkSCIP)
	if res.Partiality.Complete {
		t.Fatalf("FALSE not_exploitable: a dep sink reached by the DEP module initializer (Dep <Module>::.cctor) with no path from first-party Main was cleared as Complete (%d paths). The root enumeration must span the whole set.", len(res.Paths))
	}
}

// DEFECT: a DEP finalizer-reachable dep sink cleared as a clean not_exploitable.
// Dep's Bad.Finalize (an Object.Finalize override) is GC-invoked and reaches D.Sink.boom; there
// is no call edge from first-party Main. An fp-only enumeration never roots it.
func TestC8_DepFinalizer_FalseNE(t *testing.T) {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	_, sinkM := db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()}})
	boomTok := mtok(xMethodDef, sinkM[0])
	db.addType(0, "Bad", "D", dObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "Finalize", flags: 0x01C4, sig: sigInstVoid, il: body(ilCall(boomTok))},
	})

	res := runReachSet(t, appEmptyMain(t), db.bytesNamed("Dep"), depSinkSCIP)
	if res.Partiality.Complete {
		t.Fatalf("FALSE not_exploitable: a dep sink reached only by a GC-invoked DEP finalizer (Dep Bad.Finalize) was cleared as Complete (%d paths). The finalizer enumeration must span the whole set.", len(res.Paths))
	}
}

// CONTROL / precision: a dep sink genuinely unreachable from Main AND from EVERY runtime root
// across the set (Dep has an INERT module init and an INERT finalizer, neither reaching boom)
// STILL earns a clean not_exploitable. Proves round-3 searches dep runtime roots yet does not
// blanket-degrade every dep sink to undetermined — the confident-safe is preserved.
func TestC8_DepSink_Unreachable_Control_CleanNE(t *testing.T) {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	// Module init present but INERT (empty body — reaches nothing).
	db.addType(0, "<Module>", "", 0, []mspec{{name: ".cctor", flags: 0x1810, sig: sigStaticVoid, il: body()}})
	db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()}})
	// An ordinary IDisposable-style type with an INERT finalizer (does NOT reach boom).
	db.addType(0, "Res", "D", dObj, []mspec{
		{name: ".ctor", flags: 0x1806, sig: sigInstVoid, il: body()},
		{name: "Finalize", flags: 0x01C4, sig: sigInstVoid, il: body()},
	})

	res := runReachSet(t, appEmptyMain(t), db.bytesNamed("Dep"), depSinkSCIP)
	if !res.Partiality.Complete {
		t.Fatalf("precision lost: a dep sink unreachable from Main and every runtime root must STILL be a clean NE, got %v", res.Partiality.Reasons)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("clean NE must emit NO path, got %d", len(res.Paths))
	}
	if hasILReason(res.Partiality, plugin.PartialReasonReachabilityUndetermined) {
		t.Fatalf("clean NE must NOT carry reachability_undetermined, got %v", res.Partiality.Reasons)
	}
}
