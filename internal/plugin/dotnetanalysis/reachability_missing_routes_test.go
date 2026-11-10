package dotnetanalysis

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Every app registers App.Impl (whose Run calls the sink in Dep) through A.Holder.Set in
// Abs, then takes one route into the missing package Gone. Gone depends on Abs, so Dep sits
// outside Gone's scoped closure and Searched alone decides the sink advisory: a route that
// can run Gone code must leave the sink unsearched.

type mrCtx struct {
	a       *fwApp
	gone    uint32 // AssemblyRef Gone
	worker  uint32 // TypeRef Gone.W.Worker (class)
	gstruct uint32 // TypeRef Gone.W.S (value type)

	lastStruct uint32 // TypeDef RID of the last mrStruct, whose field range ends at fieldEnd
	fieldEnd   uint32
}

func mrApp(route func(c *mrCtx) [][]byte) []byte {
	a := newFWApp()
	absRef := a.asmRef("Abs")
	ifcRef := a.extTypeRefScoped(absRef, "A", "IPlugin")
	impl, im := a.addType(0, "Impl", "App", a.obj, []mspec{
		{name: "Run", flags: fIfaceImpl, sig: sigInstVoid, il: a.sinkIf(true)},
		{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
	})
	a.row(xInterfaceImpl, impl, cTypeDefOrRef(xTypeRef, ifcRef))
	set := a.memberRef(a.extTypeRefScoped(absRef, "A", "Holder"), "Set", []byte{0x00, 0x01, 0x01, 0x12, byte(cTypeDefOrRef(xTypeRef, ifcRef))})
	c := &mrCtx{a: a}
	c.gone = a.asmRef("Gone")
	c.worker = a.extTypeRefScoped(c.gone, "W", "Worker")
	c.gstruct = a.extTypeRefScoped(c.gone, "W", "S")
	instrs := [][]byte{ilNewobjOp(mtok(xMethodDef, im[1])), ilCall(set)}
	instrs = append(instrs, route(c)...)
	instrs = append(instrs, a.console())
	_, m := a.addType(0, "Program", "App", a.obj, []mspec{{name: "Main", flags: fStatic, sig: sigStaticVoid, il: body(instrs...)}})
	a.entry = mtok(xMethodDef, m[0])
	if c.lastStruct != 0 {
		// FieldList starts a range: every type after the last struct starts past its fields.
		for _, row := range a.tables[xTypeDef][c.lastStruct:] {
			row[4] = c.fieldEnd
		}
	}
	return a.bytesNamed("App")
}

// mrStruct adds a sealed value type App.<name> with one instance field of each given type.
func mrStruct(c *mrCtx, name string, fieldTypes ...[]byte) uint32 {
	a := c.a
	first := uint32(len(a.tables[xField])) + 1
	for _, ft := range fieldTypes {
		a.row(xField, 0x06, a.str("f"), a.blob(append([]byte{0x06}, ft...)))
	}
	td, _ := a.addType(0x109, name, "App", cTypeDefOrRef(xTypeRef, a.extTypeRef("System", "ValueType")), nil)
	a.tables[xTypeDef][td-1][4] = first
	c.lastStruct, c.fieldEnd = td, uint32(len(a.tables[xField]))+1
	return td
}

// mrDIMFoo adds App.Foo : <framework iface>, Gone.W.IThing with no body for the framework
// interface's slots, and returns its constructor.
func mrDIMFoo(c *mrCtx, iface ...[]byte) (foo, ctor uint32) {
	a := c.a
	foo, fm := a.addType(0, "Foo", "App", a.obj, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
	if iface == nil {
		a.implements(foo, "System", "IDisposable")
	} else {
		a.row(xInterfaceImpl, foo, a.row(xTypeSpec, a.blob(iface[0]))<<2|2)
	}
	a.row(xInterfaceImpl, foo, cTypeDefOrRef(xTypeRef, a.extTypeRefScoped(c.gone, "W", "IThing")))
	return foo, mtok(xMethodDef, fm[0])
}

func mrDef(td uint32) []byte  { return []byte{0x12, byte(cTypeDefOrRef(xTypeDef, td))} }
func mrDefV(td uint32) []byte { return []byte{0x11, byte(cTypeDefOrRef(xTypeDef, td))} }

func mrOp(op []byte, t uint32) []byte { return append(append([]byte{}, op...), tok4(t)...) }

var mrPop = []byte{0x26}

func mrClass(tr uint32) []byte { return []byte{0x12, byte(cTypeDefOrRef(xTypeRef, tr))} }
func mrValue(tr uint32) []byte { return []byte{0x11, byte(cTypeDefOrRef(xTypeRef, tr))} }

func mrGenInst(owner []byte, args ...[]byte) []byte {
	out := append([]byte{0x15}, owner...)
	out = append(out, byte(len(args)))
	for _, a := range args {
		out = append(out, a...)
	}
	return out
}

// mrGenericWithCctor adds App.GH`1 whose .cctor runs `ldsflda f; constrained. !0 callvirt
// Object::ToString`, and returns an ldsfld of f on GH closed over arg.
func mrGenericWithCctor(a *fwApp, arg []byte) [][]byte {
	gh, _ := a.addType(0x1, "GH`1", "App", a.obj, nil)
	openSpec := a.row(xTypeSpec, a.blob([]byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeDef, gh)), 0x01, 0x13, 0x00}))
	fOpen := mtok(xMemberRef, a.row(xMemberRef, openSpec<<3|4, a.str("f"), a.blob([]byte{0x06, 0x13, 0x00})))
	var0 := a.row(xTypeSpec, a.blob([]byte{0x13, 0x00}))
	cctor := body(mrOp([]byte{0x7F}, fOpen), mrOp([]byte{0xFE, 0x16}, mtok(xTypeSpec, var0)), ilCallvirt(a.fwRef("System", "Object", "ToString", sigToString)), mrPop)
	a.addType(0x1, "GHc", "App", a.obj, []mspec{{name: ".cctor", flags: 0x1811, sig: sigStaticVoid, il: cctor}})
	// GH has no methods of its own: point its MethodList at the .cctor and GHc's past it.
	ghRow := a.tables[xTypeDef][gh-1]
	ghc := a.tables[xTypeDef][len(a.tables[xTypeDef])-1]
	ghRow[5] = ghc[5]
	ghc[5]++
	closed := a.row(xTypeSpec, a.blob(append([]byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeDef, gh)), 0x01}, arg...)))
	fClosed := mtok(xMemberRef, a.row(xMemberRef, closed<<3|4, a.str("f"), a.blob([]byte{0x06, 0x13, 0x00})))
	return [][]byte{mrOp([]byte{0x7E}, fClosed), mrPop}
}

func TestReachability_RoutesIntoMissingPackage(t *testing.T) {
	arrayEmpty := []byte{0x10, 0x01, 0x00, 0x1D, 0x1E, 0x00}
	keepAlive := []byte{0x00, 0x01, 0x01, 0x1C}
	getHashCode := []byte{0x20, 0x00, 0x08}
	boxHash := func(c *mrCtx, td uint32) [][]byte {
		return [][]byte{mrOp([]byte{0x8C}, mtok(xTypeDef, td)), ilCallvirt(c.a.fwRef("System", "Object", "GetHashCode", getHashCode)), mrPop}
	}
	staticGoneS := func(c *mrCtx) uint32 {
		return mtok(xField, c.a.row(xField, 0x16, c.a.str("s"), c.a.blob(append([]byte{0x06}, mrValue(c.gstruct)...))))
	}
	for _, r := range []struct {
		name         string
		route        func(c *mrCtx) [][]byte
		wantSearched bool
	}{
		{"no route: searched", func(c *mrCtx) [][]byte { return nil }, true},
		{"method instantiation only: Array.Empty<Gone.Worker>()", func(c *mrCtx) [][]byte {
			ref := c.a.fwRef("System", "Array", "Empty", arrayEmpty)
			spec := c.a.row(xMethodSpec, (ref&0xFFFFFF)<<1|1, c.a.blob(append([]byte{0x0A, 0x01}, mrClass(c.worker)...)))
			return [][]byte{ilCall(mtok(xMethodSpec, spec)), mrPop}
		}, false},
		{"nested method instantiation: Array.Empty<List<Gone.Worker>>()", func(c *mrCtx) [][]byte {
			ls := c.a.extTypeRef("System.Collections.Generic", "List`1")
			ref := c.a.fwRef("System", "Array", "Empty", arrayEmpty)
			spec := c.a.row(xMethodSpec, (ref&0xFFFFFF)<<1|1, c.a.blob(append([]byte{0x0A, 0x01}, mrGenInst(mrClass(ls), mrClass(c.worker))...)))
			return [][]byte{ilCall(mtok(xMethodSpec, spec)), mrPop}
		}, false},
		{"nested owner argument: Lazy<List<Gone.Worker>>", func(c *mrCtx) [][]byte {
			lz := c.a.extTypeRef("System", "Lazy`1")
			ls := c.a.extTypeRef("System.Collections.Generic", "List`1")
			return [][]byte{ilNewobjOp(c.a.specRef(mrGenInst(mrClass(lz), mrGenInst(mrClass(ls), mrClass(c.worker))), ".ctor", sigInstVoid)), mrPop}
		}, false},
		{"array argument: Lazy<Gone.Worker[]>", func(c *mrCtx) [][]byte {
			lz := c.a.extTypeRef("System", "Lazy`1")
			return [][]byte{ilNewobjOp(c.a.specRef(mrGenInst(mrClass(lz), append([]byte{0x1D}, mrClass(c.worker)...)), ".ctor", sigInstVoid)), mrPop}
		}, false},
		{"value-type argument: Lazy<Gone.S>", func(c *mrCtx) [][]byte {
			lz := c.a.extTypeRef("System", "Lazy`1")
			return [][]byte{ilNewobjOp(c.a.specRef(mrGenInst(mrClass(lz), mrValue(c.gstruct)), ".ctor", sigInstVoid)), mrPop}
		}, false},
		{"ldftn over a closed generic: Lazy<Gone.Worker>::get_Value", func(c *mrCtx) [][]byte {
			lz := c.a.extTypeRef("System", "Lazy`1")
			return [][]byte{ilLdftn(c.a.specRef(mrGenInst(mrClass(lz), mrClass(c.worker)), "get_Value", []byte{0x20, 0x00, 0x13, 0x00})), mrPop}
		}, false},
		{"in-set generic owner: new App.GB<Gone.Worker>", func(c *mrCtx) [][]byte {
			gb, _ := c.a.addType(0x1, "GB`1", "App", c.a.obj, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
			sp := append([]byte{0x15, 0x12, byte(cTypeDefOrRef(xTypeDef, gb)), 0x01}, mrClass(c.worker)...)
			return [][]byte{ilNewobjOp(c.a.specRef(sp, ".ctor", sigInstVoid)), mrPop}
		}, false},
		{"type init of an in-set generic over a missing type", func(c *mrCtx) [][]byte {
			return mrGenericWithCctor(c.a, mrValue(c.gstruct))
		}, false},
		{"type init of an in-set generic over a framework type: searched", func(c *mrCtx) [][]byte {
			return mrGenericWithCctor(c.a, []byte{0x08})
		}, true},
		{"box a missing struct, call Object::ToString", func(c *mrCtx) [][]byte {
			a := c.a
			a.row(xField, 0x16, a.str("s"), a.blob(append([]byte{0x06}, mrValue(c.gstruct)...)))
			return [][]byte{mrOp([]byte{0x7E}, mtok(xField, 1)), mrOp([]byte{0x8C}, mtok(xTypeRef, c.gstruct)), ilCallvirt(a.fwRef("System", "Object", "ToString", sigToString)), mrPop}
		}, false},
		{"box a missing struct, pass it to Console.WriteLine(object)", func(c *mrCtx) [][]byte {
			a := c.a
			a.row(xField, 0x16, a.str("s"), a.blob(append([]byte{0x06}, mrValue(c.gstruct)...)))
			wl := a.refIn("System.Console", "System", "Console", "WriteLine", []byte{0x00, 0x01, 0x01, 0x1C})
			return [][]byte{mrOp([]byte{0x7E}, mtok(xField, 1)), mrOp([]byte{0x8C}, mtok(xTypeRef, c.gstruct)), ilCall(wl)}
		}, false},
		{"box an in-set type, call Object::ToString: searched", func(c *mrCtx) [][]byte {
			a := c.a
			own, _ := a.addType(0x1, "Own", "App", a.obj, nil)
			return [][]byte{mrOp([]byte{0x8C}, mtok(xTypeDef, own)), ilCallvirt(a.fwRef("System", "Object", "ToString", sigToString)), mrPop}
		}, true},
		{"constrained. call on a missing struct", func(c *mrCtx) [][]byte {
			a := c.a
			a.row(xField, 0x16, a.str("s"), a.blob(append([]byte{0x06}, mrValue(c.gstruct)...)))
			return [][]byte{mrOp([]byte{0x7F}, mtok(xField, 1)), mrOp([]byte{0xFE, 0x16}, mtok(xTypeRef, c.gstruct)), ilCallvirt(a.fwRef("System", "Object", "ToString", sigToString)), mrPop}
		}, false},
		{"framework slot a missing interface's default method can fill", func(c *mrCtx) [][]byte {
			a := c.a
			foo, fm := a.addType(0, "Foo", "App", a.obj, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
			a.implements(foo, "System", "IDisposable")
			a.row(xInterfaceImpl, foo, cTypeDefOrRef(xTypeRef, a.extTypeRefScoped(c.gone, "W", "IThing")))
			return [][]byte{ilNewobjOp(mtok(xMethodDef, fm[0])), ilCallvirt(a.fwRef("System", "IDisposable", "Dispose", sigInstVoid))}
		}, false},
		{"default method slot, generic framework interface: IComparable<Foo>::CompareTo", func(c *mrCtx) [][]byte {
			a := c.a
			icmp := a.extTypeRef("System", "IComparable`1")
			foo, _ := c.a.addType(0, "Pre", "App", a.obj, nil)
			_ = foo
			cmp := mrGenInst(mrClass(icmp), mrDef(foo+1))
			_, ctor := mrDIMFoo(c, cmp)
			ct := a.specRef(cmp, "CompareTo", []byte{0x20, 0x01, 0x08, 0x13, 0x00})
			return [][]byte{ilNewobjOp(ctor), ilNewobjOp(ctor), ilCallvirt(ct), mrPop}
		}, false},
		{"default method slot, interfaces listed on an in-set base class", func(c *mrCtx) [][]byte {
			a := c.a
			base, _ := a.addType(0, "Base", "App", a.obj, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
			a.implements(base, "System", "IDisposable")
			a.row(xInterfaceImpl, base, cTypeDefOrRef(xTypeRef, a.extTypeRefScoped(c.gone, "W", "IThing")))
			_, fm := a.addType(0, "Foo", "App", cTypeDefOrRef(xTypeDef, base), []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
			return [][]byte{ilNewobjOp(mtok(xMethodDef, fm[0])), ilCallvirt(a.fwRef("System", "IDisposable", "Dispose", sigInstVoid))}
		}, false},
		{"default method slot through ldvirtftn", func(c *mrCtx) [][]byte {
			_, ctor := mrDIMFoo(c)
			return [][]byte{ilNewobjOp(ctor), mrOp([]byte{0xFE, 0x07}, c.a.fwRef("System", "IDisposable", "Dispose", sigInstVoid)), mrPop}
		}, false},
		{"default method slot the framework calls: GC.KeepAlive(Foo)", func(c *mrCtx) [][]byte {
			_, ctor := mrDIMFoo(c)
			return [][]byte{ilNewobjOp(ctor), ilCall(c.a.fwRef("System", "GC", "KeepAlive", keepAlive))}
		}, false},
		{"default method slot the framework calls: List<Foo>.Sort()", func(c *mrCtx) [][]byte {
			a := c.a
			icmp := a.extTypeRef("System", "IComparable`1")
			pre, _ := a.addType(0, "Pre", "App", a.obj, nil)
			fooSig := mrDef(pre + 1)
			_, ctor := mrDIMFoo(c, mrGenInst(mrClass(icmp), fooSig))
			lsFoo := mrGenInst(mrClass(a.extTypeRef("System.Collections.Generic", "List`1")), fooSig)
			return [][]byte{ilNewobjOp(ctor), mrPop, ilNewobjOp(a.specRef(lsFoo, ".ctor", sigInstVoid)), ilCallvirt(a.specRef(lsFoo, "Sort", sigInstVoid))}
		}, false},
		{"only a missing interface, handed to the framework: searched", func(c *mrCtx) [][]byte {
			a := c.a
			foo, fm := a.addType(0, "Foo", "App", a.obj, []mspec{{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()}})
			a.row(xInterfaceImpl, foo, cTypeDefOrRef(xTypeRef, a.extTypeRefScoped(c.gone, "W", "IThing")))
			return [][]byte{ilNewobjOp(mtok(xMethodDef, fm[0])), ilCall(a.fwRef("System", "GC", "KeepAlive", keepAlive))}
		}, true},
		{"constrained. over Nullable<Gone.S>", func(c *mrCtx) [][]byte {
			a := c.a
			f := staticGoneS(c)
			sp := a.row(xTypeSpec, a.blob(mrGenInst(mrValue(a.extTypeRef("System", "Nullable`1")), mrValue(c.gstruct))))
			return [][]byte{mrOp([]byte{0x7F}, f), mrOp([]byte{0xFE, 0x16}, mtok(xTypeSpec, sp)), ilCallvirt(a.fwRef("System", "Object", "ToString", sigToString)), mrPop}
		}, false},
		{"box a missing struct inside an in-set type initializer", func(c *mrCtx) [][]byte {
			a := c.a
			f := staticGoneS(c)
			cctor := body(mrOp([]byte{0x7E}, f), mrOp([]byte{0x8C}, mtok(xTypeRef, c.gstruct)), ilCallvirt(a.fwRef("System", "Object", "ToString", sigToString)), mrPop)
			_, m := a.addType(0, "Init", "App", a.obj, []mspec{
				{name: "M", flags: fStatic, sig: sigStaticVoid, il: body()},
				{name: ".cctor", flags: 0x1811, sig: sigStaticVoid, il: cctor},
			})
			return [][]byte{ilCall(mtok(xMethodDef, m[0]))}
		}, false},
		{"constrained. call on a missing struct (static abstract member)", func(c *mrCtx) [][]byte {
			return [][]byte{mrOp([]byte{0xFE, 0x16}, mtok(xTypeRef, c.gstruct)), ilCall(c.a.fwRef("System", "ISpanParsable", "M", sigStaticVoid))}
		}, false},
		{"array of a missing struct sorted by the framework", func(c *mrCtx) [][]byte {
			a := c.a
			arr := a.extTypeRef("System", "Array")
			sort := a.fwRef("System", "Array", "Sort", []byte{0x00, 0x01, 0x01, 0x12, byte(cTypeDefOrRef(xTypeRef, arr))})
			return [][]byte{{0x17}, mrOp([]byte{0x8D}, mtok(xTypeRef, c.gstruct)), ilCall(sort)}
		}, false},
		{"array of an in-set struct: searched", func(c *mrCtx) [][]byte {
			a := c.a
			key := mrStruct(c, "Key", []byte{0x08})
			arr := a.extTypeRef("System", "Array")
			sort := a.fwRef("System", "Array", "Sort", []byte{0x00, 0x01, 0x01, 0x12, byte(cTypeDefOrRef(xTypeRef, arr))})
			return [][]byte{{0x17}, mrOp([]byte{0x8D}, mtok(xTypeDef, key)), ilCall(sort)}
		}, true},
		{"box an in-set struct holding a missing struct", func(c *mrCtx) [][]byte {
			return boxHash(c, mrStruct(c, "Key", []byte{0x08}, mrValue(c.gstruct)))
		}, false},
		{"box an in-set struct holding one that holds a missing struct", func(c *mrCtx) [][]byte {
			inner := mrStruct(c, "Inner", mrValue(c.gstruct))
			return boxHash(c, mrStruct(c, "Key", mrDefV(inner)))
		}, false},
		{"in-set struct holding a missing struct as a Dictionary key", func(c *mrCtx) [][]byte {
			a := c.a
			key := mrStruct(c, "Key", mrValue(c.gstruct))
			dict := mrGenInst(mrClass(a.extTypeRef("System.Collections.Generic", "Dictionary`2")), mrDefV(key), []byte{0x08})
			return [][]byte{ilNewobjOp(a.specRef(dict, ".ctor", sigInstVoid)), mrPop}
		}, false},
		{"box an in-set struct holding a static missing struct and an int: searched", func(c *mrCtx) [][]byte {
			a := c.a
			key := mrStruct(c, "Key", []byte{0x08})
			// A static field of the missing type sits in Key's range but is not instance state.
			a.row(xField, 0x16, a.str("s"), a.blob(append([]byte{0x06}, mrValue(c.gstruct)...)))
			c.fieldEnd++
			return boxHash(c, key)
		}, true},
		// Precision cost: Foo fills Dispose itself, but the slots a framework interface carries
		// cannot be enumerated, so pairing it with a missing interface counts anyway.
		{"framework slot the type fills itself, paired with a missing interface: not searched", func(c *mrCtx) [][]byte {
			a := c.a
			foo, fm := a.addType(0, "Foo", "App", a.obj, []mspec{
				{name: ".ctor", flags: fPublicCtor, sig: sigInstVoid, il: body()},
				{name: "Dispose", flags: fIfaceImpl, sig: sigInstVoid, il: body()},
			})
			a.implements(foo, "System", "IDisposable")
			a.row(xInterfaceImpl, foo, cTypeDefOrRef(xTypeRef, a.extTypeRefScoped(c.gone, "W", "IThing")))
			return [][]byte{ilNewobjOp(mtok(xMethodDef, fm[0])), ilCallvirt(a.fwRef("System", "IDisposable", "Dispose", sigInstVoid))}
		}, false},
	} {
		t.Run(r.name, func(t *testing.T) {
			t.Setenv("NUGET_PACKAGES", t.TempDir())
			assets := `{"version":3,"targets":{"net8.0":{` +
				`"Dep/1.0.0":{"type":"package"},"Abs/1.0.0":{"type":"package"},` +
				`"Gone/1.0.0":{"type":"package","dependencies":{"Abs":"1.0.0"},"runtime":{"lib/net8.0/Gone.dll":{}}}}},` +
				`"libraries":{"Dep/1.0.0":{"type":"package","path":"dep/1.0.0"},"Abs/1.0.0":{"type":"package","path":"abs/1.0.0"},"Gone/1.0.0":{"type":"package","path":"gone/1.0.0"}}}`
			dir := composeILBuildDir(t, map[string][]byte{
				"App.csproj":              restoredProject,
				"bin/App.dll":             mrApp(r.route),
				"bin/Dep.dll":             depBoom(),
				"bin/Abs.dll":             absIface(),
				"obj/project.assets.json": []byte(assets),
			})
			res, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{fwSink}})
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Contains(res.Searched, fwSink); got != r.wantSearched {
				t.Fatalf("searched=%v, want %v (paths=%d reasons=%v)", got, r.wantSearched, len(res.Paths), res.Partiality.Reasons)
			}
		})
	}
}

func TestMissLimits_Edges(t *testing.T) {
	graph := parseAssetsGraph([]byte(`{"version":3,"targets":{"net8.0":{` +
		`"Abs/1.0.0":{"type":"package"},"Gone/1.0.0":{"type":"package","dependencies":{"Abs":"1.0.0"}}}}}`))
	gone := func(target string) assembly.DepMiss {
		return assembly.DepMiss{Dep: assembly.DepRef{Target: target, PkgKey: "Gone/1.0.0"}, Reason: assembly.MissRIDUnknown}
	}
	for _, c := range []struct {
		name          string
		misses        []assembly.DepMiss
		wantUnbounded []string
		wantScoped    map[string][]string // Path -> Targets
	}{
		{"unparseable package key: run-wide only",
			[]assembly.DepMiss{{Dep: assembly.DepRef{Target: "net8.0", PkgKey: ""}, Reason: assembly.MissRIDUnknown}},
			[]string{partialReasonRIDUnknown}, map[string][]string{}},
		{"one target bounds the closure, another does not: run-wide and still scoped",
			[]assembly.DepMiss{gone("net8.0/linux-x64"), gone("net8.0")},
			[]string{partialReasonRIDUnknown}, map[string][]string{"Gone/1.0.0": {"pkg:nuget/abs", "pkg:nuget/gone"}}},
		{"two unbounded misses: the reason once",
			[]assembly.DepMiss{gone("net8.0/linux-x64"), gone("net8.0/win-x64")},
			[]string{partialReasonRIDUnknown}, map[string][]string{"Gone/1.0.0": nil}},
		{"bounded miss: scoped only",
			[]assembly.DepMiss{gone("net8.0")},
			nil, map[string][]string{"Gone/1.0.0": {"pkg:nuget/abs", "pkg:nuget/gone"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			scoped, unbounded := missLimits(c.misses, graph)
			if !slices.Equal(unbounded, c.wantUnbounded) {
				t.Errorf("unbounded=%v, want %v", unbounded, c.wantUnbounded)
			}
			if len(scoped) != len(c.wantScoped) {
				t.Fatalf("scoped=%+v, want %v", scoped, c.wantScoped)
			}
			for _, s := range scoped {
				want, ok := c.wantScoped[s.Path]
				if !ok || !slices.Equal(s.Targets, want) {
					t.Errorf("scoped %s targets=%v, want %v", s.Path, s.Targets, want)
				}
			}
		})
	}
}
