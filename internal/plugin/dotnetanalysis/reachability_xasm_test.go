package dotnetanalysis

// reachability_xasm_test.go — a call site in one assembly binding to a method declared in
// another. The two spell a class-typed parameter differently (a TypeRef token in the caller,
// a TypeDef token in the declaring assembly), so binding by signature bytes drops the real
// target: a reached override is missed and its sink reported searched.

import (
	"slices"
	"testing"
)

const xInterfaceImpl = 0x09

// depCrossAsm builds Dep.dll: D.Arg, D.Other, D.Sink.boom() with D.Sink.take(class D.Arg)
// calling it, a class D.Base.Run(class D.Arg) overridden by D.Impl, and an interface
// D.IRun.Run(class D.Arg) implemented by D.IImpl. Both overrides call boom, as does the
// second of the overloads D.Sink.pick(class D.Arg) and D.Sink.pick(class D.Other).
func depCrossAsm() []byte {
	db := scaffold()
	dObj := cTypeDefOrRef(xTypeRef, db.extTypeRef("System", "Object"))
	// TypeRef rows 2 and 3 exist so that App's parameter token, read against Dep's tables
	// instead of App's, names a real but wrong type rather than nothing.
	db.extTypeRef("System", "ValueType")
	db.extTypeRef("System", "Enum")
	db.addType(0, "<Module>", "", 0, nil)
	argRID, _ := db.addType(0, "Arg", "D", dObj, nil)
	otherRID, _ := db.addType(0, "Other", "D", dObj, nil)
	argParam := byte(cTypeDefOrRef(xTypeDef, argRID))
	otherParam := byte(cTypeDefOrRef(xTypeDef, otherRID))
	runSig := []byte{0x20, 0x01, 0x01, 0x12, argParam}
	_, sinkM := db.addType(0, "Sink", "D", dObj, []mspec{
		{name: "boom", flags: 0x16, sig: sigStaticVoid, il: body()},
		{name: "take", flags: 0x16, sig: []byte{0x00, 0x01, 0x01, 0x12, argParam}, il: body(ilCall(mtok(xMethodDef, 1)))}, // boom: the first MethodDef
		{name: "pick", flags: 0x16, sig: []byte{0x00, 0x01, 0x01, 0x12, argParam}, il: body()},
		{name: "pick", flags: 0x16, sig: []byte{0x00, 0x01, 0x01, 0x12, otherParam}, il: body(ilCall(mtok(xMethodDef, 1)))},
	})
	callBoom := body(ilCall(mtok(xMethodDef, sinkM[0])))
	baseRID, _ := db.addType(0, "Base", "D", dObj, []mspec{{name: "Run", flags: 0x1C6, sig: runSig, il: body()}})
	db.addType(0, "Impl", "D", cTypeDefOrRef(xTypeDef, baseRID), []mspec{{name: "Run", flags: 0xC6, sig: runSig, il: callBoom}})
	ifaceRID, _ := db.addType(0xA0, "IRun", "D", 0, []mspec{{name: "Run", flags: 0x5C6, sig: runSig}})
	iimplRID, _ := db.addType(0, "IImpl", "D", dObj, []mspec{{name: "Run", flags: 0x1E6, sig: runSig, il: callBoom}})
	db.row(xInterfaceImpl, iimplRID, cTypeDefOrRef(xTypeDef, ifaceRID))
	return db.bytesNamed("Dep")
}

// appCrossAsm builds App.dll whose Main makes one call into Dep: opcode on owner::method,
// with the parameter spelled as a TypeRef to D.<argType>, or, with argType "", as a
// function pointer (a shape the signature matcher does not decode).
func appCrossAsm(callvirt bool, owner, method, argType string) []byte {
	ab := scaffold()
	aObj := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
	dep := ab.asmRef("Dep")
	ownerRef := ab.extTypeRefScoped(dep, "D", owner)
	param := []byte{0x1B, 0x00, 0x00, 0x01} // FNPTR to void()
	if argType != "" {
		param = []byte{0x12, byte(cTypeDefOrRef(xTypeRef, ab.extTypeRefScoped(dep, "D", argType)))}
	}
	cc, op := byte(0x00), ilCall
	if callvirt {
		cc, op = 0x20, ilCallvirt
	}
	m := ab.memberRef(ownerRef, method, append([]byte{cc, 0x01, 0x01}, param...))
	ab.addType(0, "<Module>", "", 0, nil)
	_, inM := ab.addType(0, "Program", "App", aObj, []mspec{{name: "Main", flags: 0x16, sig: sigStaticVoid, il: body(op(m))}})
	ab.entry = mtok(xMethodDef, inM[0])
	return ab.bytesNamed("App")
}

func TestReachability_CrossAssemblySignatures(t *testing.T) {
	sink := funcSCIP("D", []string{"Sink"}, "boom", 0)
	cases := []struct {
		name     string
		app      []byte
		wantPath bool
	}{
		{"class virtual reaches the override", appCrossAsm(true, "Base", "Run", "Arg"), true},
		{"interface call reaches the implementation", appCrossAsm(true, "IRun", "Run", "Arg"), true},
		{"direct call binds the declared method", appCrossAsm(false, "Sink", "take", "Arg"), true},
		{"a parameter naming another type binds nothing", appCrossAsm(false, "Sink", "take", "Other"), false},
		{"an undecoded parameter binds every overload of that arity", appCrossAsm(false, "Sink", "pick", ""), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runReachSet(t, c.app, depCrossAsm(), sink)
			if got := len(res.Paths) > 0; got != c.wantPath {
				t.Fatalf("path = %v, want %v (Searched=%v, partiality=%+v)", got, c.wantPath, res.Searched, res.Partiality)
			}
			// Neither a reached sink nor an unbound call is ever a searched one.
			if slices.Contains(res.Searched, sink) {
				t.Fatalf("Searched = %v, want %s unsettled", res.Searched, sink)
			}
		})
	}
}
