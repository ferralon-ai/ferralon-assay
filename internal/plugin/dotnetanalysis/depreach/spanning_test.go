package depreach

// spanning_test.go — the C2 CROSS-BOUNDARY proof (PLAN-350 barrier-3b, deliverable 2).
//
// Three hermetic synthesized assemblies wired first-party → A → B by AssemblyRef +
// cross-assembly-TypeRef MemberRef (NO SDK, no CLR, nothing loaded — assembly.Read
// parses the bytes). The spanning CHA already exists (NewEngine → NewCHA over the whole
// set; a TypeRef scoped to an AssemblyRef resolves against the CHA's global type index;
// the method join is name + signature-blob BYTES). This proves that stitch actually
// spans a real AssemblyRef boundary, that the join is by symbol (MethodKey) equality not
// string containment (an overload mutation MOVES the resolved edge), and that a crossing
// into a genuinely out-of-set assembly stays `undetermined` — never a false
// not_exploitable (the symbol-norm A2 deferral is conservative, not a hole).
//
// The peb builder (engine_test.go) is extended here — as the dispatch directs, kept in
// the test file — with AssemblyRef rows scoped to arbitrary target assemblies, a
// scope-parameterised cross-assembly TypeRef, and a name-parameterised finish.

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// ---- peb extensions for multi-assembly fixtures ----

// asmRef adds an AssemblyRef row (table 0x23) naming another assembly, returning its RID
// (a cross-assembly resolution scope). Mirrors scaffold's System.Runtime ref layout;
// col 6 is the Name the reader reads back as the TypeRef scope.
func (b *peb) asmRef(name string) uint32 {
	return b.row(xAssemblyRef, 1, 0, 0, 0, 0, b.blob(nil), b.str(name), 0, b.blob(nil))
}

// extTypeRefScoped adds a TypeRef resolved against a SPECIFIC AssemblyRef (asmRefRID) —
// i.e. a reference to a type owned by another loaded assembly. This is the whole point:
// the CHA resolves it against its global type index (by name, scope-disambiguated).
func (b *peb) extTypeRefScoped(asmRefRID uint32, ns, name string) uint32 {
	return b.row(xTypeRef, cResScopeAsmRef(asmRefRID), b.str(name), b.str(ns))
}

// finishNamed is finish with an explicit assembly Name, so a loaded set has distinct
// Assembly.Name values (the CHA's scope disambiguation, and the report's addressing,
// key on them).
func (b *peb) finishNamed(t *testing.T, name string) *assembly.Assembly {
	t.Helper()
	b.row(xAssembly, 0, 1, 0, 0, 0, 0, b.blob(nil), b.str(name), 0)
	a, err := assembly.Read(b.wrap())
	if err != nil {
		t.Fatalf("assembly.Read(%s): %v", name, err)
	}
	return a
}

// sigInstI4Param is `HASTHIS void M(int32)` — a one-primitive-param overload whose blob
// bytes are assembly-independent (I4 references no TypeRef), so the caller-side MemberRef
// blob and the callee-side MethodDef blob byte-match across the boundary. Distinct from
// sigInstVoid, so the two same-named overloads decode to DISTINCT signature keys.
var sigInstI4Param = []byte{0x20, 0x01, 0x01, 0x08} // HASTHIS, 1 param, ret void, param I4

// ---- the three-assembly fixture ----

type c2Set struct {
	f, a, b  *assembly.Assembly
	enterRID uint32 // AsmF: Ft.Ingress.enter  (first-party ingress)
	stepRID  uint32 // AsmA: At.Mid.step
	boom1RID uint32 // AsmB: Bt.Sink.boom()       (sig1)
	boom2RID uint32 // AsmB: Bt.Sink.boom(int32)  (sig2)
	deepRID  uint32 // AsmA: At.Deep.vuln — an in-set sink reachable ONLY across the boundary
}

// buildC2Set synthesizes {AsmF, AsmA, AsmB}. AsmB owns Bt.Sink with TWO same-name
// overloads boom()/boom(int32). AsmA's At.Mid.step `call`s Bt.Sink.boom via an
// AssemblyRef→AsmB TypeRef + MemberRef whose signature blob is callSig (which overload
// the call site names). AsmF's Ft.Ingress.enter `call`s At.Mid.step the same way
// (AssemblyRef→AsmA). At.Deep.vuln is an in-set sink nothing in-set edges to — the
// negative control's present-but-cross-boundary-only target.
func buildC2Set(t *testing.T, callSig []byte) c2Set {
	// --- AsmB: the leaf sink assembly ---
	bb := scaffold()
	bext := cTypeDefOrRef(xTypeRef, bb.extTypeRef("System", "Object"))
	bb.addType(0, "<Module>", "", 0, nil)
	_, sinkM := bb.addType(0, "Sink", "Bt", bext, []mspec{
		{name: "boom", flags: 0x40, sig: sigInstVoid, il: body()},    // overload 1: boom()
		{name: "boom", flags: 0x40, sig: sigInstI4Param, il: body()}, // overload 2: boom(int32)
	})
	bAsm := bb.finishNamed(t, "AsmB")

	// --- AsmA: A.step calls into AsmB across the AssemblyRef boundary ---
	ab := scaffold()
	aext := cTypeDefOrRef(xTypeRef, ab.extTypeRef("System", "Object"))
	refB := ab.asmRef("AsmB")
	sinkRefInA := ab.extTypeRefScoped(refB, "Bt", "Sink")
	boomRef := mtok(xMemberRef, ab.row(xMemberRef, cMemberRefParent(xTypeRef, sinkRefInA), ab.str("boom"), ab.blob(callSig)))
	ab.addType(0, "<Module>", "", 0, nil)
	_, deepM := ab.addType(0, "Deep", "At", aext, []mspec{{name: "vuln", flags: 0x40, sig: sigInstVoid, il: body()}})
	_, midM := ab.addType(0, "Mid", "At", aext, []mspec{{name: "step", flags: 0x40, sig: sigInstVoid, il: body(ilCall(boomRef))}})
	aAsm := ab.finishNamed(t, "AsmA")

	// --- AsmF: first-party ingress calls into AsmA across the AssemblyRef boundary ---
	fb := scaffold()
	fext := cTypeDefOrRef(xTypeRef, fb.extTypeRef("System", "Object"))
	refA := fb.asmRef("AsmA")
	midRefInF := fb.extTypeRefScoped(refA, "At", "Mid")
	stepRef := mtok(xMemberRef, fb.row(xMemberRef, cMemberRefParent(xTypeRef, midRefInF), fb.str("step"), fb.blob(sigInstVoid)))
	fb.addType(0, "<Module>", "", 0, nil)
	_, inM := fb.addType(0, "Ingress", "Ft", fext, []mspec{{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(stepRef))}})
	fAsm := fb.finishNamed(t, "AsmF")

	return c2Set{f: fAsm, a: aAsm, b: bAsm, enterRID: inM[0], stepRID: midM[0], boom1RID: sinkM[0], boom2RID: sinkM[1], deepRID: deepM[0]}
}

// TestReach_CrossAssembly_C2 is the C2 criterion: a first-party→A→B chain resolves
// across two real AssemblyRef boundaries, joined by symbol (MethodKey) equality.
func TestReach_CrossAssembly_C2(t *testing.T) {
	// -------------------------------------------------------------------------------
	// both cross-boundary edges present + the join is MethodKey equality (not substring)
	// -------------------------------------------------------------------------------
	t.Run("both_edges_and_symbol_join", func(t *testing.T) {
		s := buildC2Set(t, sigInstVoid) // A's call site names boom() (overload 1)
		e := NewEngine([]*assembly.Assembly{s.f, s.a, s.b})
		ingress := keyByRID(t, e, s.f, s.enterRID)
		step := keyByRID(t, e, s.a, s.stepRID)
		boom1 := keyByRID(t, e, s.b, s.boom1RID)
		boom2 := keyByRID(t, e, s.b, s.boom2RID)

		res := e.Reach(ingress, boom1)
		if res.Verdict != ReachableCandidate {
			t.Fatalf("verdict = %v (%s), want reachable_candidate across the F→A→B chain", res.Verdict, res.HazardWhy)
		}
		// Both cross-boundary edges present, as a two-hop path spanning three assemblies.
		if len(res.Path) != 3 {
			t.Fatalf("path = %v, want exactly [ingress, A.step, B.boom()] (both cross edges)", PathString(res.Path))
		}
		if res.Path[0] != ingress || res.Path[1] != step || res.Path[2] != boom1 {
			t.Fatalf("path = %v, want F.enter → A.step → B.boom() by MethodKey", PathString(res.Path))
		}
		// The join is by symbol equality: the resolved A→B target is B's SPECIFIC overload
		// (boom(), not boom(int32)) — assert on the MethodKey, and that the two overloads
		// have DISTINCT keys so a name-only join could not have produced this.
		if boom1 == boom2 {
			t.Fatalf("overloads must have distinct MethodKeys; both = %s", boom1)
		}
		if res.Path[2] == boom2 {
			t.Fatal("resolved A→B target is boom(int32); want the boom() overload the call site named")
		}
		// The OTHER overload is present in B but NOT reached in this config — a hazard-free
		// searched-and-empty result (proves the sig join, not the topology, picked boom()).
		if got := e.Reach(ingress, boom2); got.Verdict != NotExploitable || got.HazardOnFrontier {
			t.Fatalf("Reach(ingress, boom(int32)) = %v hazard=%v, want not_exploitable hazard-free (edge is at boom() only)", got.Verdict, got.HazardOnFrontier)
		}
	})

	// -------------------------------------------------------------------------------
	// overload mutation control: move the call-site MemberRef signature to the OTHER
	// overload and the resolved cross-boundary edge MOVES with it. A name-only join
	// would resolve both configs to the first boom() and this assertion would fail.
	// -------------------------------------------------------------------------------
	t.Run("overload_mutation_moves_edge", func(t *testing.T) {
		// Config 1: call site names boom()  → boom() reachable, boom(int32) not.
		s1 := buildC2Set(t, sigInstVoid)
		e1 := NewEngine([]*assembly.Assembly{s1.f, s1.a, s1.b})
		in1 := keyByRID(t, e1, s1.f, s1.enterRID)
		if got := e1.Reach(in1, keyByRID(t, e1, s1.b, s1.boom1RID)); got.Verdict != ReachableCandidate {
			t.Fatalf("config boom(): Reach→boom() = %v, want reachable_candidate", got.Verdict)
		}
		if got := e1.Reach(in1, keyByRID(t, e1, s1.b, s1.boom2RID)); got.Verdict != NotExploitable {
			t.Fatalf("config boom(): Reach→boom(int32) = %v, want not_exploitable", got.Verdict)
		}

		// Config 2 (the mutation): call site names boom(int32) → the edge MOVES.
		// boom(int32) is now reachable and boom() is not — the signature blob is load-bearing.
		s2 := buildC2Set(t, sigInstI4Param)
		e2 := NewEngine([]*assembly.Assembly{s2.f, s2.a, s2.b})
		in2 := keyByRID(t, e2, s2.f, s2.enterRID)
		if got := e2.Reach(in2, keyByRID(t, e2, s2.b, s2.boom2RID)); got.Verdict != ReachableCandidate {
			t.Fatalf("mutation boom(int32): Reach→boom(int32) = %v, want reachable_candidate (edge moved)", got.Verdict)
		}
		if got := e2.Reach(in2, keyByRID(t, e2, s2.b, s2.boom1RID)); got.Verdict != NotExploitable {
			t.Fatalf("mutation boom(int32): Reach→boom() = %v, want not_exploitable (edge left boom()); a name-only join would keep it here", got.Verdict)
		}
	})

	// -------------------------------------------------------------------------------
	// negative control: an out-of-set crossing stays `undetermined`. Drop AsmB from the
	// loaded set; A.step's call into Bt.Sink is now a crossing into a genuinely out-of-set
	// assembly. The in-set sink At.Deep.vuln is present but reachable only across that
	// unreadable boundary ⇒ hazard ⇒ undetermined, NEVER a false not_exploitable. This is
	// the loader's declared-miss soundness boundary and shows the symbol-norm A2 deferral
	// is conservative, not a hole.
	// -------------------------------------------------------------------------------
	t.Run("out_of_set_crossing_undetermined", func(t *testing.T) {
		s := buildC2Set(t, sigInstVoid)
		e := NewEngine([]*assembly.Assembly{s.f, s.a}) // AsmB deliberately omitted (a declared miss)
		ingress := keyByRID(t, e, s.f, s.enterRID)
		deep := keyByRID(t, e, s.a, s.deepRID)

		res := e.Reach(ingress, deep)
		if res.Verdict != Undetermined {
			t.Fatalf("verdict = %v (%s), want undetermined (crossing into out-of-set AsmB is unreadable)", res.Verdict, res.HazardWhy)
		}
		if !res.HazardOnFrontier {
			t.Fatalf("out-of-set crossing must record a hazard on the frontier; got %q", res.HazardWhy)
		}
		if !res.SinkPresent {
			t.Fatal("At.Deep.vuln is in-set: SinkPresent must be true, so undetermined comes from the crossing hazard, not an absent sink")
		}
	})
}
