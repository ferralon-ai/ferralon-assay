package dotnetanalysis

// framework_test.go — the shared-framework model end to end through the Reachability op.
// Each row is one App.dll whose Main makes a few framework calls, over a Dep.dll holding
// the sink D.Sink.boom(). A row that expects the sink searched proves a framework call is
// a leaf; a row that expects it unsettled proves a hazard or re-entry root the model must
// keep. Removing any exception from depreach/framework.go or framework.go turns a row red.

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

const (
	fPublicCtor = 0x1886 // public hidebysig specialname rtspecialname
	fIfaceImpl  = 0x1E6  // public final virtual hidebysig newslot
	fOverride   = 0xC6   // public virtual hidebysig
	fNewSlot    = 0x1C6  // public virtual hidebysig newslot
	fStatic     = 0x16   // public static hidebysig
	xMethodSpec = 0x2B
	xField      = 0x04
)

var (
	sigCompare    = []byte{0x20, 0x02, 0x08, 0x1C, 0x1C} // instance int32 Compare(object, object)
	sigToString   = []byte{0x20, 0x00, 0x0E}             // instance string ToString()
	sigDelegateCt = []byte{0x20, 0x02, 0x01, 0x1C, 0x18} // instance void .ctor(object, native int)
	fwSink        = funcSCIP("D", []string{"Sink"}, "boom", 0)
)

func ilLdftn(t uint32) []byte { return append([]byte{0xFE, 0x06}, tok4(t)...) }

// depBoom builds Dep.dll with the sink, static D.Sink.boom().
func depBoom() []byte {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: fStatic, sig: sigStaticVoid, il: body()}})
	return db.bytesNamed("Dep")
}

// fwApp builds an App.dll. Types it adds go before Program, which main adds last.
type fwApp struct {
	*peb
	obj  uint32 // System.Object as an Extends coded index
	boom uint32 // MemberRef token of D.Sink::boom() in Dep
}

func newFWApp() *fwApp {
	b := scaffold()
	a := &fwApp{peb: b}
	a.obj = cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	a.boom = b.memberRef(b.extTypeRefScoped(b.asmRef("Dep"), "D", "Sink"), "boom", sigStaticVoid)
	b.addType(0, "<Module>", "", 0, nil)
	return a
}

// sinkIf is a body that calls the sink when calls is set, else an empty one.
func (a *fwApp) sinkIf(calls bool) []byte {
	if calls {
		return body(ilCall(a.boom))
	}
	return body()
}

// fwRef is a MemberRef on ns.typ in System.Runtime (AssemblyRef 1, a framework assembly).
func (a *fwApp) fwRef(ns, typ, name string, sig []byte) uint32 {
	return a.memberRef(a.extTypeRef(ns, typ), name, sig)
}

// refIn is a MemberRef on ns.typ in the assembly asm.
func (a *fwApp) refIn(asm, ns, typ, name string, sig []byte) uint32 {
	return a.memberRef(a.extTypeRefScoped(a.asmRef(asm), ns, typ), name, sig)
}

// specRef is a MemberRef whose parent is the TypeSpec spec.
func (a *fwApp) specRef(spec []byte, name string, sig []byte) uint32 {
	rid := a.row(xTypeSpec, a.blob(spec))
	return mtok(xMemberRef, a.row(xMemberRef, rid<<3|4, a.str(name), a.blob(sig)))
}

// implements records that the TypeDef rid implements ns.name from System.Runtime.
func (a *fwApp) implements(rid uint32, ns, name string) {
	a.row(xInterfaceImpl, rid, cTypeDefOrRef(xTypeRef, a.extTypeRef(ns, name)))
}

// comparer adds App.<name> implementing System.Collections.IComparer, whose Compare calls
// the sink when callsSink. A struct derives from System.ValueType. It returns the TypeDef
// rid and the parameterless constructor's token (0 when ctor is false).
func (a *fwApp) comparer(name string, valueType, callsSink, ctor bool) (uint32, uint32) {
	ext := a.obj
	if valueType {
		ext = cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "ValueType"))
	}
	ms := []mspec{{name: "Compare", flags: fIfaceImpl, sig: sigCompare, il: a.sinkIf(callsSink)}}
	if ctor {
		ms = append(ms, mspec{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()})
	}
	rid, m := a.addType(0, name, "App", ext, ms)
	a.implements(rid, "System.Collections", "IComparer")
	if ctor {
		return rid, mtok(xMethodDef, m[1])
	}
	return rid, 0
}

// main adds App.Program.Main running instrs as the EntryPoint and returns the image.
func (a *fwApp) main(instrs ...[]byte) []byte {
	_, m := a.addType(0, "Program", "App", a.obj, []mspec{{name: "Main", flags: fStatic, sig: sigStaticVoid, il: body(instrs...)}})
	a.entry = mtok(xMethodDef, m[0])
	return a.bytesNamed("App")
}

// console is a call to System.Console::WriteLine() in System.Console, a framework leaf.
func (a *fwApp) console() []byte {
	return ilCall(a.refIn("System.Console", "System", "Console", "WriteLine", sigStaticVoid))
}

// typeParam is a static signature taking one System.Type, returning ret.
func (a *fwApp) typeParam(ret byte) []byte {
	return []byte{0x00, 0x01, ret, 0x12, byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "Type")))}
}

// ---- fixtures ----

func appConsoleOnly() []byte { a := newFWApp(); return a.main(a.console()) }

func appComparer(valueType, construct, callsSink bool) []byte {
	a := newFWApp()
	_, ctor := a.comparer("Cmp", valueType, callsSink, !valueType)
	instrs := [][]byte{a.console()}
	if construct {
		instrs = append([][]byte{ilNewobjOp(ctor)}, instrs...)
	}
	return a.main(instrs...)
}

// appInterfaceDispatch constructs Cmp (Compare calls the sink) and calls it through the
// framework interface slot IComparer::Compare.
func appInterfaceDispatch() []byte {
	a := newFWApp()
	_, ctor := a.comparer("Cmp", false, true, true)
	cmp := a.fwRef("System.Collections", "IComparer", "Compare", sigCompare)
	return a.main(ilNewobjOp(ctor), ilCallvirt(cmp))
}

// appToString constructs App.Txt, whose ToString override calls the sink, then either
// calls System.Object::ToString on it or only calls the console.
func appToString(dispatch bool) []byte {
	a := newFWApp()
	_, m := a.addType(0, "Txt", "App", a.obj, []mspec{
		{name: "ToString", flags: fOverride, sig: sigToString, il: a.sinkIf(true)},
		{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
	})
	call := a.console()
	if dispatch {
		call = ilCallvirt(a.fwRef("System", "Object", "ToString", sigToString))
	}
	return a.main(ilNewobjOp(mtok(xMethodDef, m[1])), call)
}

// appGenericArg constructs a System.Collections.Generic.List<App.Gen>. Gen implements
// IComparer with Compare calling the sink; ctor gives it a parameterless constructor.
func appGenericArg(ctor bool) []byte {
	a := newFWApp()
	gen, _ := a.comparer("Gen", false, true, ctor)
	list := a.extTypeRef("System.Collections.Generic", "List`1")
	spec := []byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeRef, list)), 0x01, 0x12, byte(cTypeDefOrRef(xTypeDef, gen))}
	return a.main(ilNewobjOp(a.specRef(spec, ".ctor", sigInstVoid)))
}

// appGenericArgMember is appGenericArg where Gen has no constructor and the sink is
// reached from Gen's static constructor (cctor) or from a static method of a framework
// interface it implements (static abstract members).
func appGenericArgMember(cctor bool) []byte {
	a := newFWApp()
	var gen uint32
	if cctor {
		gen, _ = a.addType(0, "Gen", "App", a.obj, []mspec{{name: ".cctor", flags: 0x1811, sig: sigStaticVoid, il: a.sinkIf(true)}})
	} else {
		gen, _ = a.addType(0, "Gen", "App", a.obj, []mspec{{name: "Parse", flags: fStatic, sig: sigStaticVoid, il: a.sinkIf(true)}})
		a.implements(gen, "System", "IParsable`1")
	}
	list := a.extTypeRef("System.Collections.Generic", "List`1")
	spec := []byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeRef, list)), 0x01, 0x12, byte(cTypeDefOrRef(xTypeDef, gen))}
	return a.main(ilNewobjOp(a.specRef(spec, ".ctor", sigInstVoid)))
}

// appLdftnAction captures App.Handlers.Handle with ldftn into a System.Action and invokes it.
func appLdftnAction() []byte {
	a := newFWApp()
	_, h := a.addType(0, "Handlers", "App", a.obj, []mspec{{name: "Handle", flags: fStatic, sig: sigStaticVoid, il: a.sinkIf(true)}})
	ctor := a.fwRef("System", "Action", ".ctor", sigDelegateCt)
	invoke := a.fwRef("System", "Action", "Invoke", sigInstVoid)
	return a.main(ilLdftn(mtok(xMethodDef, h[0])), ilNewobjOp(ctor), ilCallvirt(invoke))
}

// appInSetDelegate declares a delegate App.Del (runtime-implemented .ctor and Invoke) and
// invokes a capture of App.Handlers.Handle, which does not reach the sink.
func appInSetDelegate() []byte {
	a := newFWApp()
	_, h := a.addType(0, "Handlers", "App", a.obj, []mspec{{name: "Handle", flags: fStatic, sig: sigStaticVoid, il: body()}})
	mcd := cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "MulticastDelegate"))
	_, d := a.addType(0x101, "Del", "App", mcd, []mspec{
		{name: ".ctor", flags: fPublicCtor, sig: sigDelegateCt},
		{name: "Invoke", flags: fNewSlot, sig: sigInstVoid},
	})
	for _, rid := range d {
		a.tables[xMethodDef][rid-1][1] = 0x0003 // MethodImplAttributes Runtime
	}
	return a.main(ilLdftn(mtok(xMethodDef, h[0])), ilNewobjOp(mtok(xMethodDef, d[0])), ilCallvirt(mtok(xMethodDef, d[1])))
}

// appInheritedFrameworkBody calls Flush on App.Foo : System.IO.Stream, which Foo inherits.
func appInheritedFrameworkBody() []byte {
	a := newFWApp()
	stream := cTypeDefOrRef(xTypeRef, a.extTypeRef("System.IO", "Stream"))
	foo, _ := a.addType(0, "Foo", "App", stream, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
	flush := mtok(xMemberRef, a.row(xMemberRef, cMemberRefParent(xTypeDef, foo), a.str("Flush"), a.blob(sigInstVoid)))
	return a.main(ilCallvirt(flush))
}

// appArrayGet reads an int32[,] element through the runtime's array accessor.
func appArrayGet() []byte {
	a := newFWApp()
	get := a.specRef([]byte{0x14, 0x08, 0x02, 0x00, 0x00}, "Get", []byte{0x20, 0x02, 0x08, 0x08, 0x08})
	return a.main(ilCall(get))
}

// appAsyncStart starts a state machine App.SM (a struct implementing IAsyncStateMachine,
// whose MoveNext calls the sink) through AsyncTaskMethodBuilder::Start<SM>.
func appAsyncStart() []byte {
	a := newFWApp()
	vt := cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "ValueType"))
	sm, _ := a.addType(0x100, "SM", "App", vt, []mspec{{name: "MoveNext", flags: fIfaceImpl, sig: sigInstVoid, il: a.sinkIf(true)}})
	a.implements(sm, "System.Runtime.CompilerServices", "IAsyncStateMachine")
	start := a.fwRef("System.Runtime.CompilerServices", "AsyncTaskMethodBuilder", "Start",
		[]byte{0x30, 0x01, 0x01, 0x01, 0x10, 0x1E, 0x00}) // instance void Start<T>(ref !!0)
	inst := []byte{0x0A, 0x01, 0x11, byte(cTypeDefOrRef(xTypeDef, sm))}
	spec := a.row(xMethodSpec, (start&0xFFFFFF)<<1|1, a.blob(inst))
	return a.main(ilCall(mtok(xMethodSpec, spec)))
}

// appLdvirtftn constructs App.Impl : App.Base, whose Run override calls the sink, and
// captures Base::Run with ldvirtftn into a System.Action it invokes.
func appLdvirtftn() []byte {
	a := newFWApp()
	base, bm := a.addType(0, "Base", "App", a.obj, []mspec{
		{name: "Run", flags: fNewSlot, sig: sigInstVoid, il: body()},
		{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
	})
	_, im := a.addType(0, "Impl", "App", cTypeDefOrRef(xTypeDef, base), []mspec{
		{name: "Run", flags: fOverride, sig: sigInstVoid, il: a.sinkIf(true)},
		{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
	})
	ctor := a.fwRef("System", "Action", ".ctor", sigDelegateCt)
	invoke := a.fwRef("System", "Action", "Invoke", sigInstVoid)
	ldvirtftn := append([]byte{0xFE, 0x07}, tok4(mtok(xMethodDef, bm[0]))...)
	return a.main(ilNewobjOp(mtok(xMethodDef, im[1])), ldvirtftn, ilNewobjOp(ctor), ilCallvirt(invoke))
}

// appInheritedInSet constructs App.Child : App.Base, where only Base declares Run (which
// calls the sink). viaInterface calls it through App.IRun, which Child implements and Base
// does not; otherwise through a reference to Child::Run.
func appInheritedInSet(viaInterface bool) []byte {
	a := newFWApp()
	base, _ := a.addType(0, "Base", "App", a.obj, []mspec{{name: "Run", flags: fIfaceImpl, sig: sigInstVoid, il: a.sinkIf(true)}})
	iface, ifm := a.addType(0xA0, "IRun", "App", 0, []mspec{{name: "Run", flags: 0x5C6, sig: sigInstVoid}})
	child, cm := a.addType(0, "Child", "App", cTypeDefOrRef(xTypeDef, base), []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
	var call uint32
	if viaInterface {
		a.row(xInterfaceImpl, child, cTypeDefOrRef(xTypeDef, iface))
		call = mtok(xMethodDef, ifm[0])
	} else {
		call = mtok(xMemberRef, a.row(xMemberRef, cMemberRefParent(xTypeDef, child), a.str("Run"), a.blob(sigInstVoid)))
	}
	return a.main(ilNewobjOp(mtok(xMethodDef, cm[0])), ilCallvirt(call))
}

// appInheritedUnloaded calls Flush on App.Foo : Ext.Base, which Foo inherits from an
// assembly that is neither loaded nor framework.
func appInheritedUnloaded() []byte {
	a := newFWApp()
	ext := cTypeDefOrRef(xTypeRef, a.extTypeRefScoped(a.asmRef("Ext"), "Ext", "Base"))
	foo, _ := a.addType(0, "Foo", "App", ext, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
	flush := mtok(xMemberRef, a.row(xMemberRef, cMemberRefParent(xTypeDef, foo), a.str("Flush"), a.blob(sigInstVoid)))
	return a.main(ilCallvirt(flush))
}

// appStaticField touches the static field App.Holder.f (ldsflda when addr, else ldsfld);
// Holder's static constructor calls the sink when cctorCallsSink.
func appStaticField(addr, cctorCallsSink bool) []byte {
	a := newFWApp()
	a.row(xField, 0x16, a.str("f"), a.blob([]byte{0x06, 0x08})) // public static int32 f
	a.addType(0, "Holder", "App", a.obj, []mspec{{name: ".cctor", flags: 0x1811, sig: sigStaticVoid, il: a.sinkIf(cctorCallsSink)}})
	op := byte(0x7E)
	if addr {
		op = 0x7F
	}
	prog, m := a.addType(0, "Program", "App", a.obj, []mspec{{name: "Main", flags: fStatic, sig: sigStaticVoid, il: body(append([]byte{op}, tok4(mtok(xField, 1))...))}})
	a.tables[xTypeDef][prog-1][4] = 2 // f is Holder's alone; Program's field run starts past it
	a.entry = mtok(xMethodDef, m[0])
	return a.bytesNamed("App")
}

// appGenericBase constructs App.Foo : App.GBase<int32>, whose constructor chains to the
// base constructor through the TypeSpec.
func appGenericBase() []byte {
	a := newFWApp()
	gb, _ := a.addType(0x1, "GBase`1", "App", a.obj, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
	specRID := a.row(xTypeSpec, a.blob([]byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeDef, gb)), 0x01, 0x08}))
	baseCtor := mtok(xMemberRef, a.row(xMemberRef, specRID<<3|4, a.str(".ctor"), a.blob(sigInstVoid)))
	_, fm := a.addType(0, "Foo", "App", specRID<<2|2, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body(ilCall(baseCtor))}})
	return a.main(ilNewobjOp(mtok(xMethodDef, fm[0])))
}

// depNested builds Dep.dll with the sink plus two types named Inner: a top-level one in
// the global namespace and one nested in D.Outer. nestedCallsSink picks which Go calls it.
func depNested(nestedCallsSink bool) []byte {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	db.addType(0, "<Module>", "", 0, nil)
	_, sm := db.addType(0, "Sink", "D", dObj, []mspec{{name: "boom", flags: fStatic, sig: sigStaticVoid, il: body()}})
	callBoom := body(ilCall(mtok(xMethodDef, sm[0])))
	topBody, nestedBody := callBoom, body()
	if nestedCallsSink {
		topBody, nestedBody = body(), callBoom
	}
	db.addType(0x1, "Inner", "", dObj, []mspec{{name: "Go", flags: fStatic, sig: sigStaticVoid, il: topBody}})
	outer, _ := db.addType(0x1, "Outer", "D", dObj, nil)
	nested, _ := db.addType(0x2, "Inner", "", dObj, []mspec{{name: "Go", flags: fStatic, sig: sigStaticVoid, il: nestedBody}})
	db.row(xNestedClass, nested, outer)
	return db.bytesNamed("Dep")
}

// appNestedCall calls Go on Dep's Inner: the one nested in D.Outer when nested, else the
// top-level one.
func appNestedCall(nested bool) []byte {
	a := newFWApp()
	dep := a.asmRef("Dep")
	var inner uint32
	if nested {
		outer := a.extTypeRefScoped(dep, "D", "Outer")
		inner = a.row(xTypeRef, outer<<2|3, a.str("Inner"), 0)
	} else {
		inner = a.extTypeRefScoped(dep, "", "Inner")
	}
	return a.main(ilCall(a.memberRef(inner, "Go", sigStaticVoid)))
}

// appDispatchFiltered calls IComparer::Compare through the framework slot where the only
// body that could fill it is excluded: a comparer never constructed (unconstructed), or a
// constructed App.Look whose virtual Compare matches the slot's name and signature but
// which has no framework ancestry.
func appDispatchFiltered(unconstructed bool) []byte {
	a := newFWApp()
	var instrs [][]byte
	if unconstructed {
		a.comparer("Cmp", false, true, true)
	} else {
		_, m := a.addType(0, "Look", "App", a.obj, []mspec{
			{name: "Compare", flags: fNewSlot, sig: sigCompare, il: a.sinkIf(true)},
			{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
		})
		instrs = append(instrs, ilNewobjOp(mtok(xMethodDef, m[1])))
	}
	instrs = append(instrs, ilCallvirt(a.fwRef("System.Collections", "IComparer", "Compare", sigCompare)))
	return a.main(instrs...)
}

// appExplicitImpl constructs App.Cmp implementing IComparer through a privately named body
// bound by a MethodImpl (an explicit interface implementation) that calls the sink, and
// calls IComparer::Compare when dispatch is set, else only the console.
func appExplicitImpl(dispatch bool) []byte {
	a := newFWApp()
	cmp := a.fwRef("System.Collections", "IComparer", "Compare", sigCompare)
	rid, m := a.addType(0, "Cmp", "App", a.obj, []mspec{
		{name: "System.Collections.IComparer.Compare", flags: 0x1E1, sig: sigCompare, il: a.sinkIf(true)}, // private final virtual newslot
		{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
	})
	a.implements(rid, "System.Collections", "IComparer")
	a.methodImplRecert(rid, cMethodDefOrRefRecert(xMethodDef, m[0]), cMethodDefOrRefRecert(xMemberRef, cmp&0xFFFFFF))
	call := a.console()
	if dispatch {
		call = ilCallvirt(cmp)
	}
	return a.main(ilNewobjOp(mtok(xMethodDef, m[1])), call)
}

// reflectionParam is a static signature whose one parameter wraps a framework type: as
// itself (shape 0), as an array of it (1), or as a List<> of it (2).
func (a *fwApp) reflectionParam(ns, name string, shape int) []byte {
	t := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef(ns, name)))
	switch shape {
	case 1:
		return []byte{0x00, 0x01, 0x01, 0x1D, 0x12, t}
	case 2:
		list := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System.Collections.Generic", "List`1")))
		return []byte{0x00, 0x01, 0x01, 0x15, 0x12, list, 0x01, 0x12, t}
	}
	return []byte{0x00, 0x01, 0x01, 0x12, t}
}

// appCall makes the single framework call built by ref.
func appCall(ref func(a *fwApp) uint32) []byte {
	a := newFWApp()
	return a.main(ilCall(ref(a)))
}

// fwAssets is depAssetsJSON for net8.0 with extra package rows (targets, libraries).
func fwAssets(targets, libraries string) []byte {
	return []byte(`{"version":3,"targets":{"net8.0":{"Dep/1.0.0":{"type":"package"},` + targets + `}},` +
		`"libraries":{"Dep/1.0.0":{"type":"package","path":"dep/1.0.0"},` + libraries + `}}`)
}

func TestFramework_Searched(t *testing.T) {
	cases := []struct {
		name         string
		app          []byte
		dep          []byte // nil: depBoom
		assets       []byte // nil: Dep alone, net8.0
		wantSearched bool
		wantPath     bool
		reason       string // when set, whether Reasons carries it must equal wantReason
		wantReason   bool
	}{
		// The model and when it applies.
		{name: "a console call is a framework leaf", app: appConsoleOnly(), wantSearched: true},
		{name: "netcoreapp3.1 has the model", app: appConsoleOnly(), assets: depAssetsJSONFor("netcoreapp3.1", "Dep/1.0.0"), wantSearched: true},
		{name: "net5.0 has the model", app: appConsoleOnly(), assets: depAssetsJSONFor("net5.0", "Dep/1.0.0"), wantSearched: true},
		{name: "netcoreapp3.0 has no model", app: appConsoleOnly(), assets: depAssetsJSONFor("netcoreapp3.0", "Dep/1.0.0")},
		{name: "netstandard2.0 has no model", app: appConsoleOnly(), assets: depAssetsJSONFor("netstandard2.0", "Dep/1.0.0")},
		{name: "net48 has no model", app: appConsoleOnly(), assets: depAssetsJSONFor("net48", "Dep/1.0.0")},
		{
			name:   "a framework name a package supplies is not framework",
			app:    appConsoleOnly(),
			assets: fwAssets(`"System.Console/4.3.0":{"type":"package","runtime":{"lib/net8.0/System.Console.dll":{}}}`, `"System.Console/4.3.0":{"type":"package","path":"system.console/4.3.0"}`),
		},
		{
			name:         "a package the framework supplies is not a miss",
			app:          appConsoleOnly(),
			assets:       fwAssets(`"System.Buffers/4.5.1":{"type":"package","compile":{"ref/netstandard2.0/System.Buffers.dll":{}},"runtime":{"lib/netcoreapp2.0/_._":{}}}`, `"System.Buffers/4.5.1":{"type":"package","path":"system.buffers/4.5.1"}`),
			wantSearched: true,
			reason:       partialReasonNoDependencyArtifact,
		},
		{
			name:         "a framework placeholder over a non-framework name stays a miss",
			app:          appConsoleOnly(),
			assets:       fwAssets(`"Not.Framework/1.0.0":{"type":"package","compile":{"ref/netstandard2.0/Not.Framework.dll":{}},"runtime":{"lib/netcoreapp2.0/_._":{}}}`, `"Not.Framework/1.0.0":{"type":"package","path":"not.framework/1.0.0"}`),
			wantSearched: true, // nothing calls it; the miss is disclosed, scoped to the package
			reason:       partialReasonNoDependencyArtifact,
			wantReason:   true,
		},
		{name: "a type the loaded set defines is not framework, whatever scope names it", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("D", "Sink", "boom", sigStaticVoid) // D.Sink is Dep's, referenced through System.Runtime
		}), wantPath: true},
		{name: "ASP.NET Core is not framework", app: appCall(func(a *fwApp) uint32 {
			return a.refIn("Microsoft.AspNetCore", "Microsoft.AspNetCore.Builder", "WebApplication", "Run", sigInstVoid)
		})},
		{name: "dependency injection is not framework", app: appCall(func(a *fwApp) uint32 {
			return a.refIn("Microsoft.Extensions.DependencyInjection.Abstractions", "Microsoft.Extensions.DependencyInjection", "ServiceProviderServiceExtensions", "GetService", sigStaticVoid)
		})},
		{name: "the dynamic binder's assembly is not framework", app: appCall(func(a *fwApp) uint32 {
			return a.refIn("Microsoft.CSharp", "Synthetic", "Late", "Bind", sigStaticVoid)
		})},
		{name: "the dynamic binder's namespace is a hazard in any framework assembly", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("Microsoft.CSharp.Synthetic", "Late", "Bind", sigStaticVoid)
		})},

		// Re-entry: framework code calling back into application objects.
		{name: "an instantiated comparer that reaches the sink is a re-entry", app: appComparer(false, true, true)},
		{name: "an instantiated comparer that does not reach it is searched", app: appComparer(false, true, false), wantSearched: true},
		{name: "a comparer never constructed is not a re-entry root", app: appComparer(false, false, true), wantSearched: true},
		{name: "a struct comparer counts as constructed", app: appComparer(true, false, true)},
		{name: "an Object virtual of an instantiated type is a re-entry root", app: appToString(false)},
		{name: "a generic argument with a default constructor counts as constructed", app: appGenericArg(true)},
		{name: "a generic argument without one is not constructed", app: appGenericArg(false), wantSearched: true},
		{name: "a generic argument's static constructor is a re-entry root", app: appGenericArgMember(true)},
		{name: "a generic argument's static interface member is a re-entry root", app: appGenericArgMember(false)},

		// Edges through framework slots.
		{name: "dispatch through a framework interface binds the implementation", app: appInterfaceDispatch(), wantPath: true},
		{name: "dispatch through Object binds the override", app: appToString(true), wantPath: true},
		{name: "a delegate captured with ldftn is searched", app: appLdftnAction(), wantPath: true},
		{name: "an async builder runs its state machine", app: appAsyncStart(), wantPath: true},
		{name: "an in-set delegate's runtime methods are not native code", app: appInSetDelegate(), wantSearched: true},
		{name: "a body inherited from a framework base is framework code", app: appInheritedFrameworkBody(), wantSearched: true},
		{name: "multi-dimensional array accessors are runtime code", app: appArrayGet(), wantSearched: true},

		// Application code the call graph has to bind exactly for a searched claim to hold.
		{name: "ldvirtftn binds the overrides", app: appLdvirtftn(), wantPath: true},
		{name: "a call through a subclass binds the inherited body", app: appInheritedInSet(false), wantPath: true},
		{name: "an interface implemented by a base method binds it", app: appInheritedInSet(true), wantPath: true},
		{name: "a body inherited from an unloaded base is unknown", app: appInheritedUnloaded()},
		{name: "ldsflda runs the static constructor", app: appStaticField(true, true), wantPath: true},
		{name: "ldsfld runs the static constructor", app: appStaticField(false, true), wantPath: true},
		{name: "an application field is not a hazard", app: appStaticField(false, false), wantSearched: true},
		{name: "a top-level type is not its nested namesake", app: appNestedCall(false), dep: depNested(true), wantSearched: true},
		{name: "a nested type is not its top-level namesake", app: appNestedCall(true), dep: depNested(false), wantSearched: true},
		{name: "a call reaches the top-level type", app: appNestedCall(false), dep: depNested(false), wantPath: true},
		{name: "a call reaches the nested type", app: appNestedCall(true), dep: depNested(true), wantPath: true},
		{name: "a generic application base is application code", app: appGenericBase(), wantSearched: true},
		{name: "a DLR call site on an instantiation", app: appCall(func(a *fwApp) uint32 {
			cs := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System.Runtime.CompilerServices", "CallSite`1")))
			return a.specRef([]byte{0x15, 0x12, cs, 0x01, 0x1C}, "Create", sigStaticVoid)
		})},

		{name: "a framework slot skips an unconstructed implementer", app: appDispatchFiltered(true), wantSearched: true},
		{name: "a framework slot skips a lookalike without framework ancestry", app: appDispatchFiltered(false), wantSearched: true},
		{name: "a framework slot binds an explicit implementation", app: appExplicitImpl(true), wantPath: true},
		{name: "an explicit implementation is a re-entry root", app: appExplicitImpl(false)},
		{name: "a call on a framework generic instantiation is a leaf", app: appCall(func(a *fwApp) uint32 {
			list := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System.Collections.Generic", "List`1")))
			return a.specRef([]byte{0x15, 0x12, list, 0x01, 0x08}, "Add", []byte{0x20, 0x01, 0x01, 0x13, 0x00})
		}), wantSearched: true},

		// Framework members that bind or build their target at run time.
		{name: "Activator", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Activator", "CreateInstanceFrom", []byte{0x00, 0x02, 0x1C, 0x0E, 0x0E})
		})},
		{name: "System.Reflection", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System.Reflection", "Assembly", "GetTypes", sigInstVoid)
		})},
		{name: "JsonSerializer", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System.Text.Json", "JsonSerializer", "Deserialize", []byte{0x00, 0x01, 0x1C, 0x0E})
		})},
		{name: "Delegate.DynamicInvoke", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Delegate", "DynamicInvoke", sigInstVoid)
		})},
		{name: "a constructing System.Type member", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Type", "GetConstructors", sigInstVoid)
		})},
		{name: "expression compilation", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System.Linq.Expressions", "LambdaExpression", "Compile", sigInstVoid)
		})},
		{name: "a DLR call site", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System.Runtime.CompilerServices", "CallSite`1", "Create", sigStaticVoid)
		})},
		{name: "a member taking a System.Type", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System.Runtime.InteropServices", "Marshal", "SizeOf", a.typeParam(0x08))
		})},
		{name: "a framework call with an undecodable signature", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Console", "WriteLine", []byte{0x00, 0x01, 0x01, 0x12})
		})},

		{name: "a member taking a reflection type", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Console", "Write", a.reflectionParam("System.Reflection", "MethodInfo", 0))
		})},
		{name: "a member taking a method handle", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Console", "Write", a.reflectionParam("System", "RuntimeMethodHandle", 0))
		})},
		{name: "a member taking an array of System.Type", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Console", "Write", a.reflectionParam("System", "Type", 1))
		})},
		{name: "a member taking a list of System.Type", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Console", "Write", a.reflectionParam("System", "Type", 2))
		})},

		// Members taking a type or handle that construct and invoke nothing.
		{name: "typeof", app: appCall(func(a *fwApp) uint32 {
			handle := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "RuntimeTypeHandle")))
			typ := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "Type")))
			return a.fwRef("System", "Type", "GetTypeFromHandle", []byte{0x00, 0x01, 0x12, typ, 0x11, handle})
		}), wantSearched: true},
		{name: "Type equality", app: appCall(func(a *fwApp) uint32 {
			typ := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "Type")))
			return a.fwRef("System", "Type", "op_Equality", []byte{0x00, 0x02, 0x02, 0x12, typ, 0x12, typ})
		}), wantSearched: true},
		{name: "an Enum member", app: appCall(func(a *fwApp) uint32 {
			return a.fwRef("System", "Enum", "IsDefined", a.typeParam(0x02))
		}), wantSearched: true},
		{name: "an array initializer", app: appCall(func(a *fwApp) uint32 {
			arr := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "Array")))
			fh := byte(cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "RuntimeFieldHandle")))
			return a.fwRef("System.Runtime.CompilerServices", "RuntimeHelpers", "InitializeArray", []byte{0x00, 0x02, 0x01, 0x12, arr, 0x11, fh})
		}), wantSearched: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			assets := c.assets
			if assets == nil {
				assets = depAssetsJSON("Dep/1.0.0")
			}
			dep := c.dep
			if dep == nil {
				dep = depBoom()
			}
			res := runReachSetAssets(t, c.app, dep, assets, fwSink)
			if got := slices.Contains(res.Searched, fwSink); got != c.wantSearched {
				t.Fatalf("searched = %v, want %v (paths=%d, partiality=%+v)", got, c.wantSearched, len(res.Paths), res.Partiality)
			}
			if got := len(res.Paths) > 0; got != c.wantPath {
				t.Fatalf("path = %v, want %v (partiality=%+v)", got, c.wantPath, res.Partiality)
			}
			if !c.wantSearched && !c.wantPath && res.Partiality.Complete {
				t.Fatalf("an unsettled sink reported Complete")
			}
			if c.reason != "" && hasILReason(res.Partiality, c.reason) != c.wantReason {
				t.Fatalf("reason %s present = %v, want %v (reasons=%v)", c.reason, !c.wantReason, c.wantReason, res.Partiality.Reasons)
			}
		})
	}
}

func TestFrameworkNames(t *testing.T) {
	loc, ok := assembly.ParseAssetsLocator(fwAssets(
		`"System.Console/4.3.0":{"type":"package","runtime":{"lib/net8.0/System.Console.dll":{}}},`+
			`"System.Buffers/4.5.1":{"type":"package","compile":{"ref/netstandard2.0/System.Buffers.dll":{}},"runtime":{"lib/netcoreapp2.0/_._":{}}}`,
		`"System.Console/4.3.0":{"type":"package","path":"system.console/4.3.0"},`+
			`"System.Buffers/4.5.1":{"type":"package","path":"system.buffers/4.5.1"}`))
	if !ok {
		t.Fatal("assets did not parse")
	}
	loaded := []*assembly.Assembly{{Name: "System.Collections"}}
	names := frameworkNames(firstPartyBuild{target: "net8.0"}, loc, loaded)
	cases := []struct {
		name string
		want bool
	}{
		{"System.Runtime", true},
		{"system.runtime", true},
		{"System.Threading.Tasks", true},
		{"System.Buffers", true}, // framework-supplied package: the framework's code
		{"Microsoft.CSharp", false},
		{"Microsoft.VisualBasic", false},
		{"Microsoft.VisualBasic.Core", false},
		{"System.Console", false},     // a package supplies it
		{"System.Collections", false}, // the loaded set supplies it
		{"Microsoft.AspNetCore", false},
		{"Microsoft.Extensions.DependencyInjection", false},
		{"Dep", false},
	}
	for _, c := range cases {
		if got := names[strings.ToLower(c.name)]; got != c.want {
			t.Errorf("framework[%s] = %v, want %v", c.name, got, c.want)
		}
	}
	if got := frameworkNames(firstPartyBuild{target: "netstandard2.0"}, loc, nil); got != nil {
		t.Errorf("netstandard2.0: model on (%d names), want off", len(got))
	}
	if got := frameworkNames(firstPartyBuild{target: "net8.0"}, nil, nil); got != nil {
		t.Errorf("no restore output: model on (%d names), want off", len(got))
	}
}

func TestNetCoreAppAtLeast31(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"netcoreapp3.1", true},
		{"netcoreapp3.0", false},
		{"netcoreapp2.2", false},
		{"net5.0", true},
		{"net8.0", true},
		{"net10.0", true},
		{"net8.0-windows", true},
		{"net8.0/linux-x64", true},
		{".NETCoreApp,Version=v3.1", true},
		{".NETCoreApp,Version=v2.1", false},
		{"netstandard2.1", false},
		{"net48", false},
		{"net472", false},
		{"", false},
		{"garbage", false},
	}
	for _, c := range cases {
		if got := netCoreAppAtLeast31(c.target); got != c.want {
			t.Errorf("netCoreAppAtLeast31(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}
