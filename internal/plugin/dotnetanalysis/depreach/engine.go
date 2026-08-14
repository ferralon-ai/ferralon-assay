package depreach

// engine.go — the .NET two-trace proof-of-non-exploitability (PoNE) verdict engine
// over the CHA graph of a loaded assembly set. It is the SOUNDNESS CORE: a missed
// edge here becomes a false not_exploitable, the cardinal §3.1 violation. It is the
// .NET realisation of cobalt's landed javaanalysis/depreach engine; structure and
// honesty boundary are mirrored, JVM semantics translated to .NET (below).
//
// The honesty boundary (identical to cobalt / the Go SSA path): not_exploitable is
// emitted ONLY from a search that RAN over a hazard-free, complete frontier and found
// nothing. Any hazard on the searched frontier, an empty/failed graph, or an
// unfound ingress/sink degrades to `undetermined` — never a false not_exploitable.
// Over-approximation is sound; under-approximation is the bug.
//
// Where the JVM CHA gift does NOT transfer (translated from cobalt, called out for
// the barrier-5 C8 reviewer):
//   - .cctor type-init closure walks the Extends BASE chain ONLY — .NET does not
//     cascade interface .cctors the way the JVM cascades superinterface <clinit>s
//     (ECMA-335 §II.10.5.3). See handleTrigger.
//   - an out-of-set base type in the init closure is UNREADABLE code on the frontier
//     ⇒ a hazard, NOT a clean leaf (the reading that would reintroduce cobalt's
//     twice-confirmed hole). See handleTrigger.
//   - reflection / P-Invoke / DLR-dynamic / calli / out-of-set-receiver / re-entry
//     callbacks are the completeness hazards enumerated in resolveTargets.

import (
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// metadata table ids used to classify a raw call/field operand token (ECMA-335
// §II.22). Re-declared here (the assembly package keeps them unexported) so token
// dispatch reads by name rather than magic number.
const (
	tblField      = 0x04
	tblMethodDef  = 0x06
	tblMemberRef  = 0x0A
	tblMethodSpec = 0x2B
)

// MethodAttributes / MethodImplAttributes bits (ECMA-335 §II.23.1.10/.11) the engine
// reads directly off a MethodDef.
const (
	maStatic      uint16 = 0x0010 // MethodAttributes.Static
	maPInvokeImpl uint16 = 0x2000 // MethodAttributes.PInvokeImpl (DllImport/extern)
	miaCodeType   uint16 = 0x0003 // MethodImplAttributes CodeTypeMask: 0=IL,1=Native,3=Runtime
	miaUnmanaged  uint16 = 0x0004 // MethodImplAttributes.Unmanaged
)

// taInterface is TypeAttributes.Interface (ECMA-335 §II.23.1.15).
const taInterface uint32 = 0x20

// MethodKey is the resolvable, name-carrying identity a caller uses to name an
// ingress or a vulnerable sink: the declaring type's display name, the method name,
// and the ECMA-335 signature key (name-independent, from signature.go). trace 1
// matches a sink by (Owner, Name, Sig) against the declared methods of the resolved
// set. Node identity inside the graph is the *assembly.MethodDef POINTER (unique and
// precise); MethodKey is only the external addressing scheme — a signature-key
// collision between two same-named methods over-approximates (merges the lookup),
// which is sound, never a dropped edge.
type MethodKey struct {
	Owner string // declaring type "Namespace.Name"
	Name  string // method name (".cctor", ".ctor", or the ordinary name)
	Sig   string // MethodSignature.SignatureKey()
}

func (k MethodKey) String() string { return k.Owner + "::" + k.Name + " " + k.Sig }

// Verdict is the three-valued reachability outcome. not_exploitable is emitted ONLY
// from a search that ran and found nothing over a hazard-free frontier.
type Verdict string

const (
	ReachableCandidate Verdict = "reachable_candidate"
	NotExploitable     Verdict = "not_exploitable"
	Undetermined       Verdict = "undetermined"
)

// Result is one two-trace PoNE query outcome. It is LANE-LOCAL: the plugin does not
// decide Warrant verdicts (trigger.finding does); barrier-4 maps Undetermined to the
// frozen plugin.PartialReasonReachabilityUndetermined.
type Result struct {
	Verdict          Verdict
	Path             []MethodKey // ingress..sink, present when ReachableCandidate
	SinkPresent      bool        // trace 1: the sink exists in the resolved set (by MethodKey)
	HazardOnFrontier bool        // a completeness hazard lay on the searched frontier
	HazardWhy        string      // the first such hazard, for the soundness reviewer
	Reached          int         // nodes visited (search size, diagnostics)
}

// typeEntry is one in-set type with its owning assembly, for base-chain and
// callback-shape resolution the assembly package's unexported CHA nodes do not expose.
type typeEntry struct {
	asm *assembly.Assembly
	td  *assembly.TypeDef
}

// methodNode is a graph node: one declared method, its identity key, and its lazily
// decoded IL body (edges + init triggers). Bodies are decoded on first visit so the
// engine never walks IL for unreachable methods.
type methodNode struct {
	key   MethodKey
	asm   *assembly.Assembly
	def   *assembly.MethodDef
	owner typeEntry

	decoded bool
	body    *assembly.MethodBody
}

// Engine is the CHA call graph over a loaded assembly set plus the two-trace PoNE.
type Engine struct {
	cha        *assembly.CHA
	nodes      map[*assembly.MethodDef]*methodNode // pointer identity
	byKey      map[MethodKey][]*methodNode         // external ingress/sink addressing
	ownerOf    map[*assembly.MethodDef]typeEntry
	typeByName map[string][]typeEntry            // "Namespace.Name" -> in-set types (scope-disambiguated on collision)
	subOf      map[*assembly.TypeDef][]typeEntry // direct subclasses + interface implementers (for re-entry)

	// Test seams for the barrier-5 mutation controls. Production leaves BOTH false.
	// disableInitClosure removes the whole .cctor channel (proves the closure is
	// load-bearing: it flips a .cctor-only-reachable sink to a false not_exploitable).
	// disableBaseChainOnly keeps the triggered type's own .cctor but drops the base
	// walk (proves the BASE-CHAIN walk specifically closes cobalt's hole).
	disableInitClosure   bool
	disableBaseChainOnly bool
}

// NewEngine builds the spanning CHA over the loaded set and indexes every method by
// pointer and by MethodKey. An assembly with Failed==true (a reader parse-hazard) is
// skipped by NewCHA; its types are therefore out-of-set, so every call into it
// resolves to a boundary hazard rather than a silently dropped edge — the taint is
// carried, not lost.
func NewEngine(asms []*assembly.Assembly) *Engine {
	e := &Engine{
		cha:        assembly.NewCHA(asms...),
		nodes:      map[*assembly.MethodDef]*methodNode{},
		byKey:      map[MethodKey][]*methodNode{},
		ownerOf:    map[*assembly.MethodDef]typeEntry{},
		typeByName: map[string][]typeEntry{},
		subOf:      map[*assembly.TypeDef][]typeEntry{},
	}
	// Pass 1: index types and methods.
	for _, a := range asms {
		if a == nil || a.Failed {
			continue
		}
		for i := range a.Types {
			td := &a.Types[i]
			te := typeEntry{asm: a, td: td}
			e.typeByName[typeKeyName(td.Namespace, td.Name)] = append(e.typeByName[typeKeyName(td.Namespace, td.Name)], te)
			for _, m := range td.Methods {
				sigKey := ""
				if sig, err := DecodeMethodSig(m.SigBlob, a); err == nil {
					sigKey = sig.SignatureKey()
				}
				n := &methodNode{
					key:   MethodKey{Owner: typeDisplayTD(td), Name: m.Name, Sig: sigKey},
					asm:   a,
					def:   m,
					owner: te,
				}
				e.nodes[m] = n
				e.ownerOf[m] = te
				e.byKey[n.key] = append(e.byKey[n.key], n)
			}
		}
	}
	// Pass 2: reverse hierarchy edges (subclasses + interface implementers) for the
	// re-entry callback rule.
	for _, a := range asms {
		if a == nil || a.Failed {
			continue
		}
		for i := range a.Types {
			td := &a.Types[i]
			me := typeEntry{asm: a, td: td}
			if base, ok := e.lookupTypeRef(a, td.Extends); ok {
				e.subOf[base.td] = append(e.subOf[base.td], me)
			}
			for _, ifaceRef := range td.Interfaces {
				if iface, ok := e.lookupTypeRef(a, ifaceRef); ok {
					e.subOf[iface.td] = append(e.subOf[iface.td], me)
				}
			}
		}
	}
	return e
}

// keyOf returns a method's MethodKey (white-box test helper for building an ingress/
// sink identity without hand-encoding a signature key).
func (e *Engine) keyOf(m *assembly.MethodDef) (MethodKey, bool) {
	if n, ok := e.nodes[m]; ok {
		return n.key, true
	}
	return MethodKey{}, false
}

// resolveTargets is THE soundness seam: it turns one IL call-site edge into the set of
// in-set callee nodes to enqueue, plus whether the edge is a completeness HAZARD (a
// call whose real target the static graph cannot enumerate) and a reason. Each rule is
// a place a missed edge = false not_exploitable; ALL are pre-baked (not deferred to
// C8). Over-approximation is sound.
//
// It returns resolved NODES rather than bare MethodKeys (the dispatch's nominal shape):
// nodes preserve pointer identity, so a signature-key collision cannot silently merge
// two distinct callees. Each node's .key is its MethodKey.
func (e *Engine) resolveTargets(edge assembly.Edge, fromAsm *assembly.Assembly) (targets []*methodNode, hazard bool, why string) {
	// Name-decided channels first — reflection and the DLR resolve their real callee
	// at runtime from a string/handle, invisible to a static graph. Matched on the
	// callee's owner+name via the resolved MethodRef, BEFORE CHA (whose out-of-set
	// resolution would otherwise mask them as a plain leaf).
	owner, name := e.calleeName(fromAsm, edge.Token)
	if w, ok := reflectionHazard(owner, name); ok {
		return nil, true, w
	}
	if w, ok := dynamicHazard(owner); ok {
		return nil, true, w + "::" + name
	}

	dr := e.cha.ResolveDispatch(fromAsm, edge)
	if dr.State == assembly.DispatchBoundary {
		// calli (indirect/unmanaged), jmp tail-transfer, an out-of-set callvirt/interface
		// RECEIVER (open-world overrides), or an unresolvable token — all open-world.
		return nil, true, "unresolved-boundary: " + dr.Reason
	}

	// DispatchResolved / DispatchConservative: enumerate the concrete targets.
	for _, tgt := range dr.Targets {
		if tgt.Method == nil {
			// Named but OUT-OF-SET target: a direct call/callvirt/newobj whose callee body
			// is not in the loaded set, so we cannot walk it. This is a COMPLETENESS HAZARD,
			// never a clean leaf. We cannot prove the unreadable body does not re-enter
			// application code and reach the sink: it may do so through an app object handed
			// as an argument — even one typed as an out-of-set base class / out-of-set
			// interface, or System.Object with an overridden virtual (the dominant .NET
			// re-entry shape) — or through a static / DI-registered global the CHA cannot
			// see. Treating it as a leaf infers safety from missing evidence, the §3.1
			// cardinal false-not_exploitable. Over-approximation is the correct trade for the
			// soundness core, so the edge is UNCONDITIONALLY a hazard here.
			//
			// CONSERVATIVE INTERIM of the trusted-framework-boundary question (escalated as
			// nickel-q25). This intentionally raises the `undetermined` rate for programs that
			// call unreadable framework code, in exchange for NEVER a false not_exploitable.
			// The precise relaxation — trusting the framework boundary for a callee with no
			// in-set-assignable reference parameter, guarded by a COMPLETE callback recognizer
			// — is a fleet policy decision; if approved it lands as a follow-up, with the
			// callback-recognizer completion as its guard, NOT here. See PLAN-354/450. The
			// reentryHazard recognizer below is retained ONLY to sharpen the diagnostic `why`
			// when it already names a specific callback shape; it no longer gates the hazard
			// (its old in-set-only coverage was exactly the under-approximation this closes).
			hazard = true
			if why == "" {
				if w, ok := e.reentryHazard(fromAsm, edge.Token); ok {
					why = w
				} else {
					why = "out-of-set call: callee body unreadable, may re-enter"
				}
			}
			continue
		}
		// In-set target with a body candidate.
		if isNativeOrPInvoke(tgt.Method) {
			// DllImport/extern or runtime-implemented: the callee body is opaque native
			// code, not IL we can walk. Treat as a frontier hazard, not a clean leaf.
			hazard = true
			if why == "" {
				why = "p/invoke/native target (opaque body): " + tgt.OwnerDisplay + "::" + tgt.Name
			}
			continue
		}
		if n := e.nodes[tgt.Method]; n != nil {
			targets = append(targets, n)
		}
	}
	return targets, hazard, why
}

// reentryHazard reports whether an out-of-set callee (named by tok in fromAsm) takes a
// parameter it could invoke to re-enter application code: a delegate, or an
// app-implemented interface / app-subclassed class present in the loaded set. An
// undecodable callee signature is itself a hazard — the conservative reading, since a
// callback we cannot rule out is a callback we must assume.
func (e *Engine) reentryHazard(fromAsm *assembly.Assembly, tok assembly.Token) (string, bool) {
	blob := calleeSigBlob(fromAsm, tok)
	if len(blob) == 0 {
		return "", false
	}
	sig, err := DecodeMethodSig(blob, fromAsm)
	if err != nil || sig.Malformed {
		return "higher-order re-entry: out-of-set callee with undecodable signature", true
	}
	for _, rp := range sig.RefParams {
		if kind, ok := e.callbackParam(fromAsm, rp); ok {
			return "higher-order re-entry: out-of-set call takes " + kind + " " + rp.Name, true
		}
	}
	return "", false
}

// callbackParam classifies a reference-type parameter as a re-entry callback: an
// in-set delegate type, an in-set interface some in-set type implements, or an in-set
// class some in-set type subclasses (an application object could be passed and its
// virtual/interface method invoked by the out-of-set callee). Well-known out-of-set
// delegate roots (System.Delegate/MulticastDelegate) also count.
func (e *Engine) callbackParam(fromAsm *assembly.Assembly, rp RefParam) (string, bool) {
	if te, ok := e.lookupTypeRef(fromAsm, rp.Ref); ok {
		if isDelegateType(te) {
			return "delegate", true
		}
		if te.td.Flags&taInterface != 0 && e.hasInSetSubtype(te) {
			return "app-implemented interface", true
		}
		if e.hasInSetSubtype(te) {
			return "app-subclassed type", true
		}
		return "", false
	}
	// Out-of-set param type: only the delegate ROOTS are an unconditional callback.
	if rp.Ref.Namespace == "System" && (rp.Ref.Name == "Delegate" || rp.Ref.Name == "MulticastDelegate") {
		return "delegate", true
	}
	return "", false
}

// hasInSetSubtype reports whether any in-set type is a (transitive) proper subtype or
// implementer of te — i.e. an application object of te's shape could exist and be
// passed as a callback the out-of-set callee invokes. Any such subtype (even an
// abstract intermediate) signals the shape is populated; over-approximation is sound.
func (e *Engine) hasInSetSubtype(te typeEntry) bool {
	seen := map[*assembly.TypeDef]bool{te.td: true}
	stack := []typeEntry{te}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, sub := range e.subOf[cur.td] {
			if seen[sub.td] {
				continue
			}
			return true // a distinct in-set subtype/implementer exists
		}
	}
	return false
}

// Reach runs the two-trace PoNE from ingress to sink.
//
//	trace 1 (sink present): the sink exists in the resolved set, matched by MethodKey.
//	trace 2 (reachability): BFS ingress->sink over resolveTargets edges + the .cctor
//	    init closure, recording whether any completeness hazard lay on the frontier.
//
// Verdict — the honesty boundary:
//   - a path found                                    ⇒ reachable_candidate (path returned)
//   - NO path AND NO hazard on the searched frontier  ⇒ not_exploitable   (real empty search)
//   - NO path BUT a hazard could have hidden one       ⇒ undetermined      (sound abstention)
//
// not_exploitable is therefore emitted ONLY from a hazard-free searched-and-empty
// frontier. An unfound ingress or sink is a search that never ran → undetermined.
func (e *Engine) Reach(ingress, sink MethodKey) Result {
	res := Result{}
	sinkNodes := e.byKey[sink]
	res.SinkPresent = len(sinkNodes) > 0
	startNodes := e.byKey[ingress]

	if len(startNodes) == 0 {
		// The search never began; absence proves nothing.
		res.Verdict = Undetermined
		res.HazardOnFrontier = true
		res.HazardWhy = "ingress not found in loaded set: " + ingress.String()
		return res
	}
	if !res.SinkPresent {
		// trace 1 fails: we cannot even locate the vulnerable method to search for.
		res.Verdict = Undetermined
		res.HazardOnFrontier = true
		res.HazardWhy = "sink not found in loaded set: " + sink.String()
		return res
	}

	sinkSet := map[*methodNode]bool{}
	for _, n := range sinkNodes {
		sinkSet[n] = true
	}
	startSet := map[*methodNode]bool{}
	for _, n := range startNodes {
		startSet[n] = true
	}

	visited := map[*methodNode]bool{}
	prev := map[*methodNode]*methodNode{}
	var queue []*methodNode
	var found *methodNode

	markHazard := func(why string) {
		res.HazardOnFrontier = true
		if res.HazardWhy == "" {
			res.HazardWhy = why
		}
	}
	enqueue := func(from, t *methodNode) {
		if t == nil {
			return
		}
		if _, ok := prev[t]; !ok && from != nil && !startSet[t] {
			prev[t] = from
		}
		if !visited[t] {
			visited[t] = true
			queue = append(queue, t)
		}
		if sinkSet[t] && found == nil {
			found = t
		}
	}

	for _, s := range startNodes {
		if !visited[s] {
			visited[s] = true
			queue = append(queue, s)
		}
		if sinkSet[s] {
			found = s // the ingress itself is the sink
		}
	}

	for len(queue) > 0 && found == nil {
		cur := queue[0]
		queue = queue[1:]
		body := e.bodyOf(cur)
		if body == nil {
			// No walkable IL (abstract, or a native/pinvoke node reached as a callee):
			// a leaf. Its opacity as a TARGET is charged in resolveTargets, caller-side.
			continue
		}
		for _, edge := range body.Edges {
			targets, hazard, why := e.resolveTargets(edge, cur.asm)
			if hazard {
				markHazard(why)
			}
			for _, t := range targets {
				enqueue(cur, t)
			}
			if found != nil {
				break
			}
		}
		if found == nil {
			for _, tr := range body.InitTriggers {
				e.handleTrigger(cur, tr, enqueue, markHazard)
				if found != nil {
					break
				}
			}
		}
	}
	res.Reached = len(visited)

	switch {
	case found != nil:
		res.Verdict = ReachableCandidate
		res.Path = reconstruct(prev, startSet, found)
	case res.HazardOnFrontier:
		res.Verdict = Undetermined
	default:
		res.Verdict = NotExploitable
	}
	return res
}

// handleTrigger walks the .cctor type-init closure for one init-trigger site. A .cctor
// is never an explicit call target, so a sink reachable only through a static
// initializer would be invisible without this. The CLR runs a type's .cctor on first
// active use (newobj / static field / static call) AND runs the BASE type's .cctor
// first (ECMA-335 §II.10.5.3), so the whole Extends chain is enqueued — a base class's
// .cctor reaching the sink is a real runtime path the derived class has no edge to.
//
// TWO .NET-specific rules the C8 reviewer must confirm:
//  1. The closure is the Extends BASE chain ONLY. .NET does NOT cascade interface
//     .cctors the way the JVM cascades superinterface <clinit>s — walking implemented
//     interfaces here would be the WRONG (Java) rule. (Extra interface .cctors would
//     only over-flag, never hide a path, but the correct .NET model is base-chain-only.)
//  2. An out-of-set base type in the chain is UNREADABLE code on the frontier ⇒ a
//     HAZARD, not a clean leaf. Reading it as a leaf is exactly the hole (a base .cctor
//     we cannot see might reach the sink). beforefieldinit relaxes WHEN the CLR runs a
//     .cctor, not WHETHER — the path is modelled regardless; over-approx is sound.
func (e *Engine) handleTrigger(cur *methodNode, tr assembly.InitTrigger, enqueue func(from, t *methodNode), markHazard func(string)) {
	if e.disableInitClosure {
		return // test seam: prove the whole .cctor channel is load-bearing.
	}
	te, inSet, resolvable := e.triggerType(cur.asm, tr.Token)
	if !resolvable {
		// The declaring type of the trigger could not be resolved (e.g. a local Field
		// token with no parsed owner): a .cctor we cannot enqueue is a path we cannot
		// rule out. Conservative hazard.
		markHazard("unresolved type-init trigger (declaring type unknown)")
		return
	}
	if !inSet {
		// The triggered type itself is out-of-set: its .cctor is unreadable. Hazard.
		markHazard("out-of-set type-init trigger: unreadable .cctor")
		return
	}
	seen := map[*assembly.TypeDef]bool{}
	c := te
	for {
		if seen[c.td] {
			return // guard a malformed cyclic Extends chain.
		}
		seen[c.td] = true
		if cc := e.cctorOf(c); cc != nil {
			enqueue(cur, cc)
		}
		if e.disableBaseChainOnly {
			return // test seam: prove the BASE-CHAIN walk (not just the direct .cctor) matters.
		}
		ext := c.td.Extends
		if ext.Token.IsNull() {
			return // reached a root type (no base): a clean end of the chain.
		}
		base, ok := e.lookupTypeRef(c.asm, ext)
		if !ok {
			// Base type is out-of-set: its .cctor is unreadable ⇒ hazard, NOT a clean
			// leaf (the reading that reopens cobalt's twice-confirmed hole).
			markHazard("out-of-set base type in .cctor init closure: " + typeRefDisplay(ext))
			return
		}
		c = base
	}
}

// cctorOf returns te's static type initializer node (the method named ".cctor" with
// MethodAttributes.Static), or nil when the type has none.
func (e *Engine) cctorOf(te typeEntry) *methodNode {
	for _, m := range te.td.Methods {
		if m.Name == ".cctor" && m.Flags&maStatic != 0 {
			return e.nodes[m]
		}
	}
	return nil
}

// triggerType resolves the declaring type an init-trigger token initializes.
//   - a MethodDef trigger (newobj/static-call of an in-set method) → its owner type.
//   - a MemberRef trigger → its parent type (in-set or, resolvably, out-of-set).
//   - a MethodSpec → its open method, recursively.
//   - a local Field token → the Field->Type ownership is not parsed, so the declaring
//     type is unknown (resolvable=false → conservative hazard at the caller).
func (e *Engine) triggerType(asm *assembly.Assembly, tok assembly.Token) (te typeEntry, inSet, resolvable bool) {
	switch tok.Table() {
	case tblMethodDef:
		if m := asm.MethodByRID(tok.RID()); m != nil {
			if oe, ok := e.ownerOf[m]; ok {
				return oe, true, true
			}
		}
	case tblMemberRef:
		if mr := asm.MemberRef(tok.RID()); mr != nil {
			tr := asm.TypeRefFor(mr.ParentToken)
			if oe, ok := e.lookupTypeRef(asm, tr); ok {
				return oe, true, true
			}
			return typeEntry{}, false, true // out-of-set parent, but a known identity
		}
	case tblMethodSpec:
		if int(tok.RID()) < len(asm.MethodSpecs) {
			return e.triggerType(asm, asm.MethodSpecs[tok.RID()].Method)
		}
	case tblField:
		return typeEntry{}, false, false // no Field->Type ownership in the model
	}
	return typeEntry{}, false, false
}

// calleeName resolves a call operand token to its callee's (owner display, method
// name) for the name-decided hazard channels (reflection, DLR).
func (e *Engine) calleeName(asm *assembly.Assembly, tok assembly.Token) (owner, name string) {
	switch tok.Table() {
	case tblMethodDef:
		if m := asm.MethodByRID(tok.RID()); m != nil {
			if oe, ok := e.ownerOf[m]; ok {
				owner = typeDisplayTD(oe.td)
			}
			return owner, m.Name
		}
	case tblMemberRef:
		if mr := asm.MemberRef(tok.RID()); mr != nil {
			return mr.Type, mr.Name // mr.Type is the parent's "Namespace.Name" display
		}
	case tblMethodSpec:
		if int(tok.RID()) < len(asm.MethodSpecs) {
			return e.calleeName(asm, asm.MethodSpecs[tok.RID()].Method)
		}
	}
	return "", ""
}

// calleeSigBlob returns the raw signature blob of a call operand's callee, for the
// re-entry rule's RefParams decode.
func calleeSigBlob(asm *assembly.Assembly, tok assembly.Token) []byte {
	switch tok.Table() {
	case tblMethodDef:
		if m := asm.MethodByRID(tok.RID()); m != nil {
			return m.SigBlob
		}
	case tblMemberRef:
		if mr := asm.MemberRef(tok.RID()); mr != nil {
			return mr.SigBlob
		}
	case tblMethodSpec:
		if int(tok.RID()) < len(asm.MethodSpecs) {
			return calleeSigBlob(asm, asm.MethodSpecs[tok.RID()].Method)
		}
	}
	return nil
}

// lookupTypeRef resolves a TypeRef to an in-set type. A TypeSpec (generic
// instantiation) or a null token is not an open-type node here → not in-set. On a
// namespace.name collision across assemblies, the resolution scope disambiguates.
func (e *Engine) lookupTypeRef(asm *assembly.Assembly, tr assembly.TypeRef) (typeEntry, bool) {
	if tr.Token.IsNull() || tr.IsSpec {
		return typeEntry{}, false
	}
	cands := e.typeByName[typeKeyName(tr.Namespace, tr.Name)]
	switch len(cands) {
	case 0:
		return typeEntry{}, false
	case 1:
		return cands[0], true
	}
	if tr.Scope != "" {
		for _, c := range cands {
			if c.asm.Name == tr.Scope {
				return c, true
			}
		}
	}
	return cands[0], true
}

// bodyOf decodes and caches a node's IL body. A method with no managed body (RVA 0:
// abstract/pinvoke/runtime) or one whose walk errors has no out-edges — a leaf.
func (e *Engine) bodyOf(n *methodNode) *assembly.MethodBody {
	if n.decoded {
		return n.body
	}
	n.decoded = true
	if n.def.RVA == 0 {
		return nil
	}
	if mb, err := n.asm.MethodBody(n.def); err == nil {
		n.body = mb
	}
	return n.body
}

// reconstruct walks predecessors from the found sink back to a start node and returns
// the path in ingress->sink order.
func reconstruct(prev map[*methodNode]*methodNode, startSet map[*methodNode]bool, sink *methodNode) []MethodKey {
	var rev []*methodNode
	for cur := sink; cur != nil; {
		rev = append(rev, cur)
		if startSet[cur] {
			break
		}
		cur = prev[cur]
	}
	out := make([]MethodKey, len(rev))
	for i, n := range rev {
		out[len(rev)-1-i] = n.key
	}
	return out
}

// PathString renders a MethodKey path compactly for diagnostics.
func PathString(path []MethodKey) string {
	parts := make([]string, len(path))
	for i, k := range path {
		owner := k.Owner
		if j := strings.LastIndexByte(owner, '.'); j >= 0 {
			owner = owner[j+1:]
		}
		parts[i] = owner + "." + k.Name
	}
	return strings.Join(parts, " -> ")
}

// ---- hazard classification data (MATCH TARGETS, not calls: string literals here are
// data the resolver compares against, never invocations) ----

type nameKey struct{ owner, name string }

// reflectionSinks are the reflection entry points whose real callee is decided at
// runtime from a string/handle/loaded assembly — invisible to a static graph, so each
// is a completeness hazard (erring toward undetermined over a false not_exploitable).
var reflectionSinks = map[nameKey]bool{
	{"System.Activator", "CreateInstance"}:     true,
	{"System.Type", "GetMethod"}:               true,
	{"System.Type", "InvokeMember"}:            true,
	{"System.Type", "GetType"}:                 true,
	{"System.Type", "MakeGenericMethod"}:       true,
	{"System.Reflection.MethodInfo", "Invoke"}: true,
	{"System.Reflection.MethodBase", "Invoke"}: true,
	{"System.Reflection.Assembly", "Load"}:     true,
}

func reflectionHazard(owner, name string) (string, bool) {
	if reflectionSinks[nameKey{owner, name}] {
		return "reflection (runtime-bound target): " + owner + "::" + name, true
	}
	return "", false
}

// dynamicHazard flags the DLR (C# `dynamic`) call sites, whose binder resolves the
// real member at runtime.
func dynamicHazard(owner string) (string, bool) {
	if strings.HasPrefix(owner, "Microsoft.CSharp.RuntimeBinder") || strings.HasPrefix(owner, "System.Dynamic") {
		return "dynamic (DLR runtime-bound target): " + owner, true
	}
	return "", false
}

// isNativeOrPInvoke reports whether a target's body is opaque native code: a P/Invoke
// (DllImport/extern) method or one implemented in native/runtime code rather than IL.
func isNativeOrPInvoke(m *assembly.MethodDef) bool {
	if m.Flags&maPInvokeImpl != 0 {
		return true
	}
	if m.ImplFlags&miaCodeType != 0 { // 1=Native, 3=Runtime (0=IL is clean)
		return true
	}
	if m.ImplFlags&miaUnmanaged != 0 {
		return true
	}
	return false
}

// isDelegateType reports whether an in-set type is a delegate (directly extends
// System.MulticastDelegate or System.Delegate — the compiler-emitted delegate base).
func isDelegateType(te typeEntry) bool {
	ext := te.td.Extends
	return ext.Namespace == "System" && (ext.Name == "MulticastDelegate" || ext.Name == "Delegate")
}

func typeKeyName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "." + name
}

func typeDisplayTD(td *assembly.TypeDef) string { return typeKeyName(td.Namespace, td.Name) }

func typeRefDisplay(tr assembly.TypeRef) string {
	d := typeKeyName(tr.Namespace, tr.Name)
	if tr.Scope != "" {
		return tr.Scope + "!" + d
	}
	return d
}
