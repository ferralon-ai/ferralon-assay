package dotnetanalysis

// reachability_searched_test.go — ReachabilityResult.Searched, the lane's positive claim the
// not_exploitable gate's arm A needs. A sink is searched only when it is a method of an
// assembly this run read, Main exists, and Main plus every runtime root reach none of its
// overloads over a hazard-free frontier. Each failing condition has a row here; dropping the
// condition from ilReachability turns its row red.

import (
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// depWithBoomOverloads builds Dep.dll with D.Sink.boom(int) and D.Sink.boom(string): two
// methods behind one SCIP (same name, same arity). moduleInitCallsBoom adds a <Module>
// .cctor that calls boom(int).
func depWithBoomOverloads(moduleInitCallsBoom bool) []byte {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	var cctor []mspec
	if moduleInitCallsBoom {
		cctor = []mspec{{name: ".cctor", flags: 0x1811, sig: sigStaticVoid, il: body(ilCall(mtok(xMethodDef, 2)))}}
	}
	db.addType(0, "<Module>", "", 0, cctor)
	db.addType(0, "Sink", "D", dObj, []mspec{
		{name: "boom", flags: 0x16, sig: sigStaticIntVoid, il: body()},
		{name: "boom", flags: 0x16, sig: sigStaticStringVoid, il: body()},
	})
	return db.bytesNamed("Dep")
}

// appCalling builds App.dll whose EntryPoint calls the given Dep.Sink.boom overload (nil =
// calls nothing) and, with hazard, an out-of-set System.Activator.CreateInstance. withMain
// false leaves the image without an EntryPoint.
func appCalling(boomSig []byte, hazard, withMain bool) []byte {
	ab := scaffold()
	aObj := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
	var calls [][]byte
	if boomSig != nil {
		sinkRef := ab.extTypeRefScoped(ab.asmRef("Dep"), "D", "Sink")
		calls = append(calls, ilCall(ab.memberRef(sinkRef, "boom", boomSig)))
	}
	if hazard {
		calls = append(calls, ilCall(ab.memberRef(ab.extTypeRef("System", "Activator"), "CreateInstance", sigStaticVoid)))
	}
	ab.addType(0, "<Module>", "", 0, nil)
	_, inM := ab.addType(0, "Ingress", "App", aObj, []mspec{{name: "enter", flags: 0x16, sig: sigStaticVoid, il: body(calls...)}})
	if withMain {
		ab.entry = mtok(xMethodDef, inM[0])
	}
	return ab.bytesNamed("App")
}

var boomSCIP = funcSCIP("D", []string{"Sink"}, "boom", 1)

func TestReachability_Searched(t *testing.T) {
	cases := []struct {
		name       string
		app, dep   []byte
		sink       string
		wantSearch bool
		wantPath   bool
	}{
		{"hazard-free unreached sink is searched", appCalling(nil, false, true), depWithBoomOverloads(false), boomSCIP, true, false},
		{"Main reaches boom(int)", appCalling(sigStaticIntVoid, false, true), depWithBoomOverloads(false), boomSCIP, false, true},
		{"Main reaches boom(string)", appCalling(sigStaticStringVoid, false, true), depWithBoomOverloads(false), boomSCIP, false, true},
		{"frontier hazard on Main", appCalling(nil, true, true), depWithBoomOverloads(false), boomSCIP, false, false},
		{"runtime root reaches the sink", appCalling(nil, false, true), depWithBoomOverloads(true), boomSCIP, false, true},
		{"no Main", appCalling(nil, false, false), depWithBoomOverloads(false), boomSCIP, false, false},
		{"sink names no loaded method", appCalling(nil, false, true), depWithBoomOverloads(false), funcSCIP("D", []string{"Sink"}, "absent", 0), false, false},
		{"arity mismatch names no loaded method", appCalling(nil, false, true), depWithBoomOverloads(false), funcSCIP("D", []string{"Sink"}, "boom", 0), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runReachSet(t, c.app, c.dep, c.sink)
			searched := slices.Contains(res.Searched, c.sink)
			if searched != c.wantSearch {
				t.Fatalf("searched = %v, want %v (Searched=%v, partiality=%+v)", searched, c.wantSearch, res.Searched, res.Partiality)
			}
			if (len(res.Paths) > 0) != c.wantPath {
				t.Fatalf("paths = %d, want path=%v", len(res.Paths), c.wantPath)
			}
			if c.wantSearch && !res.Partiality.Complete {
				t.Fatalf("searched sink with partiality %+v", res.Partiality)
			}
			if !c.wantSearch && !c.wantPath && res.Partiality.Complete {
				t.Fatalf("unsettled sink reported Complete with no path")
			}
		})
	}
}

// TestReachability_DependencyMissIsScoped: a dependency restore lists but whose code is not
// on disk is disclosed as a scoped limit bounded by it and its restore closure. It is run-wide
// only when that closure cannot be bounded: then the missing code could hide any package.
func TestReachability_DependencyMissIsScoped(t *testing.T) {
	cases := []struct {
		name        string
		goneDeps    string // Gone's dependencies object
		wantTargets []string
		wantRunWide bool
	}{
		{
			name:        "bounded closure: scoped only",
			goneDeps:    `{"Dep":"1.0.0"}`,
			wantTargets: []string{"pkg:nuget/dep", "pkg:nuget/gone"},
		},
		{
			name:        "a dependency restore did not resolve: unbounded, so run-wide too",
			goneDeps:    `{"Dep":"1.0.0","Lost":"3.0.0"}`,
			wantRunWide: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			assets := `{"version":3,"targets":{"net8.0":{` +
				`"Dep/1.0.0":{"type":"package"},` +
				`"Gone/2.0.0":{"type":"package","dependencies":` + c.goneDeps + `,"runtime":{"lib/net8.0/Gone.dll":{}}}}},` +
				`"libraries":{"Dep/1.0.0":{"type":"package","path":"dep/1.0.0"},"Gone/2.0.0":{"type":"package","path":"gone/2.0.0"}}}`
			dir := composeILBuildDir(t, map[string][]byte{
				"App.csproj":              restoredProject,
				"bin/App.dll":             appCalling(nil, false, true),
				"bin/Dep.dll":             depWithBoomOverloads(false),
				"obj/project.assets.json": []byte(assets),
			})
			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{boomSCIP}})
			if err != nil {
				t.Fatal(err)
			}
			want := []plugin.ScopedReason{{
				Reason:  partialReasonNoDependencyArtifact,
				Package: "pkg:nuget/gone",
				Path:    "Gone/2.0.0",
				Targets: c.wantTargets,
			}}
			if res.Partiality.Complete || !reflect.DeepEqual(res.Partiality.Scoped, want) {
				t.Fatalf("partiality = %+v, want scoped %+v", res.Partiality, want)
			}
			if got := hasILReason(res.Partiality, partialReasonNoDependencyArtifact); got != c.wantRunWide {
				t.Fatalf("run-wide %s = %v, want %v (reasons %v)", partialReasonNoDependencyArtifact, got, c.wantRunWide, res.Partiality.Reasons)
			}
			// The miss is not on any traced path (nothing calls Gone), so the sink is still
			// searched; whether the scoped limit blocks an advisory is the gate's call.
			if !slices.Contains(res.Searched, boomSCIP) {
				t.Fatalf("Searched = %v, want %s", res.Searched, boomSCIP)
			}
		})
	}
}

// absIface builds Abs.dll: interface A.IPlugin { void Run(); } and static
// A.Holder.Set(IPlugin), a registry the missing package could call back through.
func absIface() []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	ifc, _ := b.addType(0xA1, "IPlugin", "A", 0, []mspec{{name: "Run", flags: 0x5C6, sig: sigInstVoid}})
	b.addType(0x1, "Holder", "A", obj, []mspec{{name: "Set", flags: fStatic, sig: []byte{0x00, 0x01, 0x01, 0x12, byte(cTypeDefOrRef(xTypeDef, ifc))}, il: body()}})
	return b.bytesNamed("Abs")
}

// appHandsToMissing registers App.Impl (whose Run calls the sink) with A.Holder.Set, then
// makes a call whose generic instantiation names Gone.W.Worker, a type of the missing Gone
// package: Lazy<Worker>'s constructor (a framework generic) or, with lazy false, nothing.
func appHandsToMissing(lazy bool) []byte {
	a := newFWApp()
	absRef := a.asmRef("Abs")
	ifcRef := a.extTypeRefScoped(absRef, "A", "IPlugin")
	impl, im := a.addType(0, "Impl", "App", a.obj, []mspec{
		{name: "Run", flags: fIfaceImpl, sig: sigInstVoid, il: a.sinkIf(true)},
		{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
	})
	a.row(xInterfaceImpl, impl, cTypeDefOrRef(xTypeRef, ifcRef))
	set := a.memberRef(a.extTypeRefScoped(absRef, "A", "Holder"), "Set", []byte{0x00, 0x01, 0x01, 0x12, byte(cTypeDefOrRef(xTypeRef, ifcRef))})
	instrs := [][]byte{ilNewobjOp(mtok(xMethodDef, im[1])), ilCall(set)}
	if lazy {
		worker := a.extTypeRefScoped(a.asmRef("Gone"), "W", "Worker")
		lz := a.extTypeRef("System", "Lazy`1")
		spec := []byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeRef, lz)), 0x01, 0x12, byte(cTypeDefOrRef(xTypeRef, worker))}
		instrs = append(instrs, ilNewobjOp(a.specRef(spec, ".ctor", sigInstVoid)))
	}
	instrs = append(instrs, a.console())
	return a.main(instrs...)
}

// A missing package's scoped limit covers only its restore closure, so an advisory outside
// it is judged on Searched alone. The missing code can still run without a call edge into
// it: a framework generic constructs its type argument (new T()), and that code reaches the
// sink through a registry in a package the closure does not name. A generic instantiation
// over a type outside the loaded set is therefore a hazard.
func TestReachability_GenericInstantiationOverMissingType(t *testing.T) {
	for _, c := range []struct {
		name         string
		lazy         bool
		goneDeps     string
		wantSearched bool
	}{
		{"Lazy<missing type>, missing package depends on the registry", true, `{"Abs":"1.0.0"}`, false},
		{"Lazy<missing type>, missing package has no dependencies", true, `{}`, false},
		{"missing type never named: searched", false, `{"Abs":"1.0.0"}`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			assets := `{"version":3,"targets":{"net8.0":{` +
				`"Dep/1.0.0":{"type":"package"},"Abs/1.0.0":{"type":"package"},` +
				`"Gone/1.0.0":{"type":"package","dependencies":` + c.goneDeps + `,"runtime":{"lib/net8.0/Gone.dll":{}}}}},` +
				`"libraries":{"Dep/1.0.0":{"type":"package","path":"dep/1.0.0"},"Abs/1.0.0":{"type":"package","path":"abs/1.0.0"},"Gone/1.0.0":{"type":"package","path":"gone/1.0.0"}}}`
			dir := composeILBuildDir(t, map[string][]byte{
				"App.csproj":              restoredProject,
				"bin/App.dll":             appHandsToMissing(c.lazy),
				"bin/Dep.dll":             depBoom(),
				"bin/Abs.dll":             absIface(),
				"obj/project.assets.json": []byte(assets),
			})
			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{fwSink}})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(res.Searched, fwSink); got != c.wantSearched {
				t.Fatalf("searched=%v, want %v (reasons=%v scoped=%+v)", got, c.wantSearched, res.Partiality.Reasons, res.Partiality.Scoped)
			}
			if slices.Contains(res.Partiality.Reasons, partialReasonNoDependencyArtifact) {
				t.Errorf("bounded miss is run-wide: %v", res.Partiality.Reasons)
			}
		})
	}
}
