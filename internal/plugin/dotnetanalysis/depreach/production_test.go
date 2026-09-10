package depreach

// production_test.go — C1 for barrier-4a: the first-party BackingEdge production pass and
// the generated-code → source state-machine mapping. Every fixture is a REAL synthesized
// PE parsed by assembly.Read (NO SDK/CLR/network) — the peb builder from engine_test.go,
// extended here (test-only) to emit CustomAttribute + NestedClass rows so [Extension] /
// [CompilerGenerated] and the nested state-machine → outer-type link are observable.
//
// Each mapping case is paired with a NEGATIVE near-miss that must NOT trigger the mapping.
// The near-miss is the load-bearing proof that the mapping keys on the OBSERVABLE attribute
// / name-mangle, not a name substring: a method literally named `MoveNext` on a normal type,
// or a source name that equals a decoded lambda name, is not decoded or partial-flagged.

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// ---- peb extensions for CustomAttribute (0x0C) + NestedClass (0x29) rows ----

const (
	xCustomAttribute = 0x0C
	xNestedClass     = 0x29
)

// cHasCustomAttribute encodes a CustomAttribute Parent (HasCustomAttribute coded index,
// 5 tag bits): MethodDef tag=0, TypeDef tag=3 (ECMA-335 §II.24.2.6).
func cHasCustomAttribute(table int, rid uint32) uint32 {
	tag := map[int]uint32{xMethodDef: 0, xTypeDef: 3}[table]
	return rid<<5 | tag
}

// cCustomAttributeType encodes a CustomAttribute Type (CustomAttributeType coded index,
// 3 tag bits): MethodDef tag=2, MemberRef tag=3.
func cCustomAttributeType(table int, rid uint32) uint32 {
	tag := map[int]uint32{xMethodDef: 2, xMemberRef: 3}[table]
	return rid<<3 | tag
}

// attrCtorRef adds an out-of-set attribute TypeRef (scoped to System.Runtime) and a
// ".ctor" MemberRef on it, returning the MemberRef RID (the attribute ctor).
func (b *peb) attrCtorRef(ns, name string) uint32 {
	tr := b.extTypeRef(ns, name)
	return b.row(xMemberRef, cMemberRefParent(xTypeRef, tr), b.str(".ctor"), b.blob(sigInstVoid))
}

// annotate adds a CustomAttribute row tying attribute ctor `ctorRef` (a MemberRef RID) to
// the element at (parentTable, parentRID).
func (b *peb) annotate(parentTable int, parentRID, ctorRef uint32) {
	b.row(xCustomAttribute,
		cHasCustomAttribute(parentTable, parentRID),
		cCustomAttributeType(xMemberRef, ctorRef),
		b.blob(nil))
}

// nest adds a NestedClass row: `nested` is declared inside `enclosing` (both TypeDef RIDs).
func (b *peb) nest(nested, enclosing uint32) {
	b.row(xNestedClass, nested, enclosing)
}

// ---- shared helpers ----

func edgesFrom(edges []BackingEdge, method assembly.Token) []BackingEdge {
	var out []BackingEdge
	for _, e := range edges {
		if e.Origin.Method == method {
			out = append(out, e)
		}
	}
	return out
}

// edgeTo finds the single edge (from a filtered slice) whose callee name matches.
func edgeTo(t *testing.T, edges []BackingEdge, calleeName string) BackingEdge {
	t.Helper()
	for _, e := range edges {
		if e.To.Name == calleeName {
			return e
		}
	}
	t.Fatalf("no edge with callee %q among %d edges", calleeName, len(edges))
	return BackingEdge{}
}

const (
	nsCG  = "System.Runtime.CompilerServices"
	extAt = "ExtensionAttribute"
	cgAt  = "CompilerGeneratedAttribute"
)

// =====================================================================================
// Extension methods: [Extension] static method attributes correctly; near-miss: the same
// static shape WITHOUT [Extension] is not one.
// =====================================================================================

func TestExtensionMethodMapping(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)
	b.addType(0, "<Module>", "", 0, nil)

	_, tgtM := b.addType(0, "Target", "App", ext, []mspec{{name: "Vuln", flags: 0x10, sig: sigStaticVoid, il: body()}})
	vulnTok := mtok(xMethodDef, tgtM[0])

	// Extension class: Shout is [Extension] static; Plain is the same shape WITHOUT it.
	_, extM := b.addType(0x80, "StringExt", "App", ext, []mspec{
		{name: "Shout", flags: 0x10, sig: sigStaticVoid, il: body(ilCall(vulnTok))},
		{name: "Plain", flags: 0x10, sig: sigStaticVoid, il: body(ilCall(vulnTok))},
	})
	shoutRID, plainRID := extM[0], extM[1]
	extCtor := b.attrCtorRef(nsCG, extAt)
	b.annotate(xMethodDef, shoutRID, extCtor)

	a := b.finish(t)

	// The accessor keys on the observable attribute, not the method shape.
	if !a.IsExtensionMethod(a.MethodByRID(shoutRID)) {
		t.Fatalf("Shout ([Extension] static) should be an extension method")
	}
	if a.IsExtensionMethod(a.MethodByRID(plainRID)) {
		t.Fatalf("near-miss: Plain (static, NO [Extension]) must NOT be an extension method")
	}

	edges := ProduceBackingEdges(a, []*assembly.Assembly{a})
	e := edgeTo(t, edgesFrom(edges, mtok(xMethodDef, shoutRID)), "Vuln")
	if e.Confidence != ConfResolved || e.Producer != producerCHA || e.Partial {
		t.Fatalf("Shout->Vuln edge = %+v; want resolved/cha/non-partial", e)
	}
}

// =====================================================================================
// Async state machine: an edge routed through <FetchAsync>d__0.MoveNext maps back to
// source App.Widget.FetchAsync AND is declared-partial. Near-miss: a hand-named MoveNext
// on a normal type is neither decoded nor partial-flagged.
// =====================================================================================

func TestAsyncStateMachineMapping(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)
	b.addType(0, "<Module>", "", 0, nil)

	_, tgtM := b.addType(0, "Target", "App", ext, []mspec{{name: "Vuln", flags: 0x10, sig: sigStaticVoid, il: body()}})
	vulnTok := mtok(xMethodDef, tgtM[0])

	widgetRID, _ := b.addType(0, "Widget", "App", ext, nil)
	smRID, smM := b.addType(0, "<FetchAsync>d__0", "", ext, []mspec{
		{name: "MoveNext", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	moveNextTok := mtok(xMethodDef, smM[0])
	b.annotate(xTypeDef, smRID, b.attrCtorRef(nsCG, cgAt))
	b.nest(smRID, widgetRID)

	// Near-miss: a normal type with a hand-written MoveNext calling the same sink.
	_, nmM := b.addType(0, "Runner", "App", ext, []mspec{
		{name: "MoveNext", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	nmTok := mtok(xMethodDef, nmM[0])

	a := b.finish(t)
	edges := ProduceBackingEdges(a, []*assembly.Assembly{a})

	// Positive: MoveNext in the state machine maps to source Widget.FetchAsync, partial.
	e := edgeTo(t, edgesFrom(edges, moveNextTok), "Vuln")
	if e.From.Enclosing != "App.Widget" || e.From.Name != "FetchAsync" {
		t.Fatalf("state-machine From = %s/%s, want App.Widget/FetchAsync", e.From.Enclosing, e.From.Name)
	}
	if e.From.Generated {
		t.Fatalf("mapped SOURCE method must carry Generated=false (SYMBOLS.md ⚑SM)")
	}
	if !e.Partial || e.PartialReason == "" {
		t.Fatalf("state-machine-routed edge must be declared-partial, got %+v", e)
	}

	// Near-miss: MoveNext on Runner is NOT decoded and NOT partial (keys on the mangle,
	// not the substring "MoveNext").
	nm := edgeTo(t, edgesFrom(edges, nmTok), "Vuln")
	if nm.From.Name != "MoveNext" || nm.From.Enclosing != "App.Runner" {
		t.Fatalf("near-miss From = %s/%s, want App.Runner/MoveNext (undecoded)", nm.From.Enclosing, nm.From.Name)
	}
	if nm.Partial || nm.From.Generated {
		t.Fatalf("near-miss MoveNext on a normal type must NOT be partial/generated, got %+v", nm)
	}
}

// =====================================================================================
// Iterator state machine: identical shape (<Enumerate>d__1.MoveNext) maps to source
// App.Collection.Enumerate and is partial; near-miss as above.
// =====================================================================================

func TestIteratorStateMachineMapping(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)
	b.addType(0, "<Module>", "", 0, nil)

	_, tgtM := b.addType(0, "Target", "App", ext, []mspec{{name: "Vuln", flags: 0x10, sig: sigStaticVoid, il: body()}})
	vulnTok := mtok(xMethodDef, tgtM[0])

	collRID, _ := b.addType(0, "Collection", "App", ext, nil)
	smRID, smM := b.addType(0, "<Enumerate>d__1", "", ext, []mspec{
		{name: "MoveNext", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	moveNextTok := mtok(xMethodDef, smM[0])
	b.annotate(xTypeDef, smRID, b.attrCtorRef(nsCG, cgAt))
	b.nest(smRID, collRID)

	_, nmM := b.addType(0, "Sequence", "App", ext, []mspec{
		{name: "MoveNext", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	nmTok := mtok(xMethodDef, nmM[0])

	a := b.finish(t)
	edges := ProduceBackingEdges(a, []*assembly.Assembly{a})

	e := edgeTo(t, edgesFrom(edges, moveNextTok), "Vuln")
	if e.From.Enclosing != "App.Collection" || e.From.Name != "Enumerate" || e.From.Generated {
		t.Fatalf("iterator From = %s/%s gen=%v, want App.Collection/Enumerate/false", e.From.Enclosing, e.From.Name, e.From.Generated)
	}
	if !e.Partial {
		t.Fatalf("iterator state-machine-routed edge must be declared-partial")
	}

	nm := edgeTo(t, edgesFrom(edges, nmTok), "Vuln")
	if nm.Partial || nm.From.Name != "MoveNext" {
		t.Fatalf("near-miss Sequence.MoveNext must NOT map/partial, got %+v", nm)
	}
}

// =====================================================================================
// Generated code: a [CompilerGenerated] display class <>c with a lambda body
// <Handle>b__0_0 maps to source App.Service.Handle; near-miss: a normal method (whose
// name even equals a decoded lambda source) is not mis-decoded.
// =====================================================================================

func TestGeneratedClosureMapping(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)
	b.addType(0, "<Module>", "", 0, nil)

	_, tgtM := b.addType(0, "Target", "App", ext, []mspec{{name: "Vuln", flags: 0x10, sig: sigStaticVoid, il: body()}})
	vulnTok := mtok(xMethodDef, tgtM[0])

	serviceRID, _ := b.addType(0, "Service", "App", ext, nil)
	dcRID, dcM := b.addType(0, "<>c", "", ext, []mspec{
		{name: "<Handle>b__0_0", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	lambdaTok := mtok(xMethodDef, dcM[0])
	b.annotate(xTypeDef, dcRID, b.attrCtorRef(nsCG, cgAt))
	b.nest(dcRID, serviceRID)

	// Near-miss: a normal type with an ordinary method named "Handle" (same source name a
	// lambda would decode to) — must NOT be decoded/generated.
	_, nmM := b.addType(0, "Helper", "App", ext, []mspec{
		{name: "Handle", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok))},
	})
	nmTok := mtok(xMethodDef, nmM[0])

	// Direct decode assertions (the substring guard).
	if s, ok := assembly.DecodeGeneratedName("<Handle>b__0_0"); !ok || s != "Handle" {
		t.Fatalf("decode lambda = (%q,%v), want (Handle,true)", s, ok)
	}
	if _, ok := assembly.DecodeGeneratedName("Handle"); ok {
		t.Fatalf("near-miss: a bare name \"Handle\" must NOT decode")
	}
	if _, ok := assembly.DecodeGeneratedName("MoveNext"); ok {
		t.Fatalf("near-miss: a bare name \"MoveNext\" must NOT decode")
	}

	a := b.finish(t)
	edges := ProduceBackingEdges(a, []*assembly.Assembly{a})

	e := edgeTo(t, edgesFrom(edges, lambdaTok), "Vuln")
	if e.From.Enclosing != "App.Service" || e.From.Name != "Handle" || e.From.Generated {
		t.Fatalf("lambda From = %s/%s gen=%v, want App.Service/Handle/false", e.From.Enclosing, e.From.Name, e.From.Generated)
	}

	nm := edgeTo(t, edgesFrom(edges, nmTok), "Vuln")
	if nm.From.Enclosing != "App.Helper" || nm.From.Name != "Handle" || nm.From.Generated {
		t.Fatalf("near-miss From = %s/%s gen=%v, want App.Helper/Handle/false", nm.From.Enclosing, nm.From.Name, nm.From.Generated)
	}
}

// =====================================================================================
// Provenance is populated at production: every produced edge carries a non-empty
// Producer + Origin and a valid Confidence, and Compact() drops all of it.
// =====================================================================================

func TestBackingEdgeProvenancePopulated(t *testing.T) {
	b := scaffold()
	obj := b.extTypeRef("System", "Object")
	ext := cTypeDefOrRef(xTypeRef, obj)
	b.addType(0, "<Module>", "", 0, nil)

	_, tgtM := b.addType(0, "Target", "App", ext, []mspec{{name: "Vuln", flags: 0x10, sig: sigStaticVoid, il: body()}})
	vulnTok := mtok(xMethodDef, tgtM[0])
	// A callvirt to an out-of-set receiver → a boundary edge (never dropped).
	extRef := b.extTypeRef("Ext", "Widget")
	extMember := b.row(xMemberRef, cMemberRefParent(xTypeRef, extRef), b.str("Do"), b.blob(sigInstVoid))
	_, _ = b.addType(0, "Ingress", "App", ext, []mspec{
		{name: "enter", flags: 0, sig: sigInstVoid, il: body(ilCall(vulnTok), ilCallvirt(mtok(xMemberRef, extMember)))},
	})

	a := b.finish(t)
	edges := ProduceBackingEdges(a, []*assembly.Assembly{a})
	if len(edges) == 0 {
		t.Fatal("no edges produced")
	}
	sawBoundary := false
	for _, e := range edges {
		if e.Producer == "" {
			t.Fatalf("edge %+v has empty Producer", e)
		}
		if e.Origin.Assembly == "" || e.Origin.Method.IsNull() {
			t.Fatalf("edge %+v has empty Origin", e)
		}
		if e.Confidence.String() == "unknown" {
			t.Fatalf("edge %+v has invalid Confidence", e)
		}
		if e.Confidence == ConfBoundary {
			sawBoundary = true
		}
		// Compact() drops provenance — only endpoints remain.
		if c := e.Compact(); c.Caller != e.From || c.Callee != e.To {
			t.Fatalf("Compact endpoints drifted: %+v", c)
		}
	}
	if !sawBoundary {
		t.Fatal("expected an out-of-set callvirt to produce a boundary edge (never dropped)")
	}
}
