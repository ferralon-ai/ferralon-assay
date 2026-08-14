package assembly

import "testing"

// dispatchFixture builds a single-assembly hierarchy exercising every CHA/dispatch
// path without needing IL bodies (ResolveDispatch is driven with hand-built Edges):
//
//	Animal(abstract Speak) <- Dog(override), Cat(override), Rock(no override)
//	IGreeter(Greet)        <- Robot(EXPLICIT MethodImpl, privately named), Mute(no impl)
//	IShape(Area)           <- Point(struct: extends System.ValueType, implements Area)
//	Helpers.Run(static)    ;  MemberRef System.Object.ToString (out-of-set owner)
func dispatchFixture(t *testing.T) *Assembly {
	t.Helper()
	b := newMDBuilder()
	sigInst := []byte{0x20, 0x00, 0x01}   // HASTHIS, 0 params, void
	sigStatic := []byte{0x00, 0x00, 0x01} // static, 0 params, void

	nMod := b.str("Test.dll")
	nAsm := b.str("Asm")
	nSystem := b.str("System")
	nObject := b.str("Object")
	nValueType := b.str("ValueType")
	nToString := b.str("ToString")
	b.addRow(tModule, 0, nMod, b.guid(), 0, 0)
	ridAsmRef := b.addRow(tAssemblyRef, 1, 0, 0, 0, 0, b.blob(nil), b.str("System.Runtime"), 0, b.blob(nil))
	scope := coded2(ciResolutionScope, tAssemblyRef, ridAsmRef)
	ridObject := b.addRow(tTypeRef, scope, nObject, nSystem)
	ridValueType := b.addRow(tTypeRef, scope, nValueType, nSystem)

	// MethodDef rows, in owning-type order (RID1..8).
	b.addRow(tMethodDef, 0, 0, 0x440, b.str("Speak"), b.blob(sigInst), 1)              // 1 Animal.Speak (abstract)
	b.addRow(tMethodDef, 0x2100, 0, 0x40, b.str("Speak"), b.blob(sigInst), 1)          // 2 Dog.Speak
	b.addRow(tMethodDef, 0x2100, 0, 0x40, b.str("Speak"), b.blob(sigInst), 1)          // 3 Cat.Speak
	b.addRow(tMethodDef, 0, 0, 0x440, b.str("Greet"), b.blob(sigInst), 1)              // 4 IGreeter.Greet (abstract)
	b.addRow(tMethodDef, 0x2100, 0, 0x40, b.str("IGreeter.Greet"), b.blob(sigInst), 1) // 5 Robot explicit impl (private name)
	b.addRow(tMethodDef, 0, 0, 0x440, b.str("Area"), b.blob(sigInst), 1)               // 6 IShape.Area (abstract)
	b.addRow(tMethodDef, 0x2100, 0, 0x40, b.str("Area"), b.blob(sigInst), 1)           // 7 Point.Area
	b.addRow(tMethodDef, 0x2100, 0, 0x10, b.str("Run"), b.blob(sigStatic), 1)          // 8 Helpers.Run (static)

	ext := func(tbl int, rid uint32) uint32 { return coded2(ciTypeDefOrRef, tbl, rid) }
	// TypeDef rows (RID1..11); MethodList column ties methods to owners.
	b.addRow(tTypeDef, 0, b.str("<Module>"), 0, 0, 1, 1)
	ridAnimal := b.addRow(tTypeDef, 0, b.str("Animal"), 0, ext(tTypeRef, ridObject), 1, 1)
	b.addRow(tTypeDef, 0, b.str("Dog"), 0, ext(tTypeDef, ridAnimal), 1, 2)
	b.addRow(tTypeDef, 0, b.str("Cat"), 0, ext(tTypeDef, ridAnimal), 1, 3)
	b.addRow(tTypeDef, 0, b.str("Rock"), 0, ext(tTypeDef, ridAnimal), 1, 4)
	ridIGreeter := b.addRow(tTypeDef, 0x20, b.str("IGreeter"), 0, 0, 1, 4)
	ridRobot := b.addRow(tTypeDef, 0, b.str("Robot"), 0, ext(tTypeRef, ridObject), 1, 5)
	ridMute := b.addRow(tTypeDef, 0, b.str("Mute"), 0, ext(tTypeRef, ridObject), 1, 6)
	ridIShape := b.addRow(tTypeDef, 0x20, b.str("IShape"), 0, 0, 1, 6)
	ridPoint := b.addRow(tTypeDef, 0, b.str("Point"), 0, ext(tTypeRef, ridValueType), 1, 7)
	b.addRow(tTypeDef, 0, b.str("Helpers"), 0, ext(tTypeRef, ridObject), 1, 8)

	// InterfaceImpl: Robot & Mute implement IGreeter; Point implements IShape.
	b.addRow(tInterfaceImpl, ridRobot, ext(tTypeDef, ridIGreeter))
	b.addRow(tInterfaceImpl, ridMute, ext(tTypeDef, ridIGreeter))
	b.addRow(tInterfaceImpl, ridPoint, ext(tTypeDef, ridIShape))

	// MethodImpl: Robot's privately-named body (MethodDef 5) satisfies IGreeter.Greet (MethodDef 4).
	b.addRow(tMethodImpl, ridRobot, coded2(ciMethodDefOrRef, tMethodDef, 5), coded2(ciMethodDefOrRef, tMethodDef, 4))

	// MemberRef System.Object.ToString — the out-of-set dispatch owner (RID1).
	b.addRow(tMemberRef, coded2(ciMemberRefParent, tTypeRef, ridObject), nToString, b.blob(sigInst))

	b.addRow(tStandAloneSig, b.blob([]byte{0x00, 0x00, 0x01})) // for a calli site
	b.addRow(tAssembly, 0, 1, 0, 0, 0, 0, b.blob(nil), nAsm, 0)

	a, err := Read(wrapPE(b.buildMetadata(0x00)).data)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return a
}

func methodRIDs(ts []Target) map[uint32]*Target {
	m := map[uint32]*Target{}
	for i := range ts {
		if ts[i].Method != nil {
			m[ts[i].Method.RID] = &ts[i]
		}
	}
	return m
}

// TestCHA_VirtualDispatch: positive candidate set (two overrides) + negative
// near-miss (a non-overriding subtype is NOT fabricated into the set).
func TestCHA_VirtualDispatch(t *testing.T) {
	a := dispatchFixture(t)
	cha := NewCHA(a)
	res := cha.ResolveDispatch(a, Edge{Kind: EdgeCallvirt, Token: makeToken(tMethodDef, 1)}) // callvirt Animal.Speak

	if res.State != DispatchConservative || !res.Conservative {
		t.Fatalf("Animal.Speak state = %v (conservative=%v), want conservative-candidate-set", res.State, res.Conservative)
	}
	got := methodRIDs(res.Targets)
	if len(got) != 2 || got[2] == nil || got[3] == nil {
		t.Fatalf("candidate set = %+v, want exactly Dog.Speak(2)+Cat.Speak(3)", res.Targets)
	}
	// Negative near-miss: Rock (RID5 TypeDef) declares no override — the abstract base
	// (MethodDef 1) is not runnable — so neither appears as a fabricated target.
	if got[1] != nil {
		t.Errorf("abstract Animal.Speak (RID1) must not be a candidate")
	}
	for _, tg := range res.Targets {
		if tg.Type != nil && tg.Type.Name == "Rock" {
			t.Errorf("Rock has no override; it must be an absence, not a phantom edge")
		}
	}
}

// TestCHA_InterfaceExplicitMethodImpl: the resolver finds an EXPLICIT MethodImpl whose
// body is privately named ("IGreeter.Greet") — a name-only resolver would miss it, and
// the near-miss implementer Mute (no impl) is not fabricated.
func TestCHA_InterfaceExplicitMethodImpl(t *testing.T) {
	a := dispatchFixture(t)
	cha := NewCHA(a)
	res := cha.ResolveDispatch(a, Edge{Kind: EdgeCallvirt, Token: makeToken(tMethodDef, 4)}) // callvirt IGreeter.Greet

	if res.State != DispatchConservative {
		t.Fatalf("IGreeter.Greet state = %v, want conservative", res.State)
	}
	if len(res.Targets) != 1 || res.Targets[0].Method == nil || res.Targets[0].Method.RID != 5 {
		t.Fatalf("interface candidate set = %+v, want Robot's explicit body (MethodDef 5)", res.Targets)
	}
	// The load-bearing assertion: the resolved body's name is NOT the interface member
	// name — proof it came from the MethodImpl table, not a name+sig match.
	if res.Targets[0].Method.Name != "IGreeter.Greet" {
		t.Errorf("resolved body name = %q; a name-only resolver would never reach a private impl", res.Targets[0].Method.Name)
	}
	for _, tg := range res.Targets {
		if tg.Type != nil && tg.Type.Name == "Mute" {
			t.Errorf("Mute implements IGreeter but not Greet; must not be fabricated")
		}
	}
}

// classVirtualImplFixture builds a class hierarchy exercising the FIX 1 path:
//
//	Base{ abstract virtual Foo }  <-  Derived{ body "_impl", .override Base::Foo via MethodImpl }
//
// Base.Foo is abstract (RVA 0, not runnable) so it is not itself a candidate; Derived
// carries NO method named Foo — its override body is the privately-named "_impl", reachable
// ONLY through the MethodImpl table. A class-path resolver that matches by name+sig alone
// (matchMethod) drops it, yielding a false-empty candidate set for callvirt Base::Foo.
func classVirtualImplFixture(t *testing.T) *Assembly {
	t.Helper()
	b := newMDBuilder()
	sigInst := []byte{0x20, 0x00, 0x01} // HASTHIS, 0 params, void

	nMod := b.str("Test.dll")
	nAsm := b.str("Asm")
	nSystem := b.str("System")
	nObject := b.str("Object")
	b.addRow(tModule, 0, nMod, b.guid(), 0, 0)
	ridAsmRef := b.addRow(tAssemblyRef, 1, 0, 0, 0, 0, b.blob(nil), b.str("System.Runtime"), 0, b.blob(nil))
	scope := coded2(ciResolutionScope, tAssemblyRef, ridAsmRef)
	ridObject := b.addRow(tTypeRef, scope, nObject, nSystem)

	// MethodDef rows (RID1..2): RVA, ImplFlags, Flags, Name, Sig, ParamList.
	b.addRow(tMethodDef, 0, 0, 0x440, b.str("Foo"), b.blob(sigInst), 1)       // 1 Base.Foo (abstract virtual, RVA 0)
	b.addRow(tMethodDef, 0x2100, 0, 0x40, b.str("_impl"), b.blob(sigInst), 1) // 2 Derived._impl (privately named override body)

	ext := func(tbl int, rid uint32) uint32 { return coded2(ciTypeDefOrRef, tbl, rid) }
	// TypeDef rows (RID1..3); MethodList ties methods to owners.
	b.addRow(tTypeDef, 0, b.str("<Module>"), 0, 0, 1, 1)
	ridBase := b.addRow(tTypeDef, 0, b.str("Base"), 0, ext(tTypeRef, ridObject), 1, 1)
	ridDerived := b.addRow(tTypeDef, 0, b.str("Derived"), 0, ext(tTypeDef, ridBase), 1, 2)

	// MethodImpl: Derived's body (_impl, MethodDef 2) explicitly overrides Base.Foo (MethodDef 1).
	b.addRow(tMethodImpl, ridDerived, coded2(ciMethodDefOrRef, tMethodDef, 2), coded2(ciMethodDefOrRef, tMethodDef, 1))

	b.addRow(tAssembly, 0, 1, 0, 0, 0, 0, b.blob(nil), nAsm, 0)

	a, err := Read(wrapPE(b.buildMetadata(0x00)).data)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return a
}

// TestCHA_ClassVirtualExplicitMethodImpl is the FIX 1 regression: a class-virtual override
// declared via an explicit MethodImpl with a differently/privately-named body ("_impl") must
// enter the candidate set for callvirt Base::Foo. It is asserted by the resolved body's
// identity (MethodDef 2, name "_impl"), proving it came from the MethodImpl table and not a
// name+sig match on the interface path.
//
// NON-VACUITY: reverting the fix — re-gating explicitImpl behind ownerIsIface, i.e. dropping
// the class-path explicitImpl consult in candidateSet — turns this test RED (empty candidate
// set, false conservative-with-no-targets). Proven by scratch-revert per the dispatch.
func TestCHA_ClassVirtualExplicitMethodImpl(t *testing.T) {
	a := classVirtualImplFixture(t)
	cha := NewCHA(a)
	res := cha.ResolveDispatch(a, Edge{Kind: EdgeCallvirt, Token: makeToken(tMethodDef, 1)}) // callvirt Base::Foo

	if res.State != DispatchConservative || !res.Conservative {
		t.Fatalf("Base.Foo state = %v (conservative=%v), want conservative-candidate-set", res.State, res.Conservative)
	}
	got := methodRIDs(res.Targets)
	if got[2] == nil {
		t.Fatalf("candidate set = %+v, want it to CONTAIN Derived._impl (MethodDef 2) via the MethodImpl table", res.Targets)
	}
	// Load-bearing: the resolved body's name is NOT the dispatched member name — proof it
	// came from the MethodImpl table, not a name+sig match. A name-only class resolver drops it.
	if got[2].Method.Name != "_impl" {
		t.Errorf("resolved body name = %q, want %q (the privately-named MethodImpl body)", got[2].Method.Name, "_impl")
	}
	// Abstract Base.Foo (RID1, RVA 0) is not runnable, so it must not be fabricated as a target.
	if got[1] != nil {
		t.Errorf("abstract Base.Foo (RID1) must not be a candidate")
	}
}

// TestCHA_ThreeState: resolved-single (static call, with the negative control that it
// is NOT the conservative state), conservative (genuine virtual), and unresolved-
// boundary (out-of-set owner, and calli).
func TestCHA_ThreeState(t *testing.T) {
	a := dispatchFixture(t)
	cha := NewCHA(a)

	static := cha.ResolveDispatch(a, Edge{Kind: EdgeCall, Token: makeToken(tMethodDef, 8)}) // call Helpers.Run
	if static.State != DispatchResolved {
		t.Fatalf("static call state = %v, want resolved-single", static.State)
	}
	if static.State == DispatchConservative {
		t.Fatalf("negative control failed: a statically-decidable site must NOT be conservative")
	}
	if len(static.Targets) != 1 || static.Targets[0].Method == nil || static.Targets[0].Method.RID != 8 {
		t.Fatalf("resolved target = %+v, want Helpers.Run (MethodDef 8)", static.Targets)
	}

	virtual := cha.ResolveDispatch(a, Edge{Kind: EdgeCallvirt, Token: makeToken(tMethodDef, 1)})
	if virtual.State != DispatchConservative {
		t.Fatalf("virtual call state = %v, want conservative", virtual.State)
	}

	boundary := cha.ResolveDispatch(a, Edge{Kind: EdgeCallvirt, Token: makeToken(tMemberRef, 1)}) // Object.ToString
	if boundary.State != DispatchBoundary || boundary.Reason == "" || len(boundary.Targets) != 0 {
		t.Fatalf("out-of-set owner = %+v, want unresolved-boundary with a reason and no targets", boundary)
	}

	calli := cha.ResolveDispatch(a, Edge{Kind: EdgeCalli, Token: makeToken(tStandAloneSig, 1)})
	if calli.State != DispatchBoundary || calli.Reason == "" {
		t.Fatalf("calli = %+v, want unresolved-boundary", calli)
	}
}

// TestCHA_ConstrainedValueType: caveat 3 — a constrained. callvirt on a value type is
// a STATIC resolution (resolved-single); the identical site WITHOUT constrained. is a
// conservative set. Missing the prefix would over-approximate.
func TestCHA_ConstrainedValueType(t *testing.T) {
	a := dispatchFixture(t)
	cha := NewCHA(a)

	// Point (TypeDef RID10) is a struct implementing IShape.Area (MethodDef 6 -> Point.Area 7).
	pointTok := makeToken(tTypeDef, 10)
	constrained := cha.ResolveDispatch(a, Edge{Kind: EdgeCallvirt, Token: makeToken(tMethodDef, 6), Constrained: pointTok})
	if constrained.State != DispatchResolved {
		t.Fatalf("constrained. callvirt on a value type = %v, want resolved-single", constrained.State)
	}
	if len(constrained.Targets) != 1 || constrained.Targets[0].Method == nil || constrained.Targets[0].Method.RID != 7 {
		t.Fatalf("constrained target = %+v, want Point.Area (MethodDef 7)", constrained.Targets)
	}

	unconstrained := cha.ResolveDispatch(a, Edge{Kind: EdgeCallvirt, Token: makeToken(tMethodDef, 6)})
	if unconstrained.State != DispatchConservative {
		t.Fatalf("without constrained., state = %v, want conservative (the prefix is what flips it)", unconstrained.State)
	}
}

// TestCHA_GenericInstantiationCarried: caveat 2 — a MethodSpec call carries its
// instantiation blob on the target descriptor (carry, not erase) while CHA resolves
// the open method.
func TestCHA_GenericInstantiationCarried(t *testing.T) {
	a := dispatchFixture(t)
	cha := NewCHA(a)
	// Synthesize a MethodSpec over the open static method Run (MethodDef 8).
	a.MethodSpecs = append(a.MethodSpecs, MethodSpec{
		RID:               uint32(len(a.MethodSpecs)),
		Method:            makeToken(tMethodDef, 8),
		InstantiationBlob: []byte{0x0a, 0x01, 0x0e}, // GENERICINST, 1 arg, String
	})
	specTok := makeToken(tMethodSpec, uint32(len(a.MethodSpecs)-1))
	res := cha.ResolveDispatch(a, Edge{Kind: EdgeCall, Token: specTok})
	if res.State != DispatchResolved || len(res.Targets) != 1 || res.Targets[0].Method == nil || res.Targets[0].Method.RID != 8 {
		t.Fatalf("methodspec call = %+v, want resolved open method Run(8)", res)
	}
	if len(res.Targets[0].Instantiation) == 0 {
		t.Errorf("instantiation blob must be CARRIED on the target descriptor (caveat 2), got empty")
	}
}

// TestCHA_LdftnDelegateCapture: caveat 4 — the ldftn target is captured as a resolved
// single, flagged for barrier-2's Invoke wiring; never a dropped edge.
func TestCHA_LdftnDelegateCapture(t *testing.T) {
	a := dispatchFixture(t)
	cha := NewCHA(a)
	res := cha.ResolveDispatch(a, Edge{Kind: EdgeLdftn, Token: makeToken(tMethodDef, 8)})
	if res.State != DispatchResolved || len(res.Targets) != 1 || res.Targets[0].Method == nil || res.Targets[0].Method.RID != 8 {
		t.Fatalf("ldftn capture = %+v, want resolved Run(8)", res)
	}
	if res.Reason == "" {
		t.Errorf("ldftn capture should carry the barrier-2 wiring note")
	}
}
