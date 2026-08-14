package assembly

// chagraph.go — Class-Hierarchy Analysis + virtual/interface dispatch resolution.
//
// CHA indexes the loaded assembly set's type hierarchy (Extends base chain,
// InterfaceImpl, and the .NET-unique explicit-interface MethodImpl slot map) and
// turns an IL call-site Edge into one of three DISTINGUISHABLE dispatch states:
// resolved-single, conservative-candidate-set, or unresolved-boundary. Barrier-2's
// verdict engine reuses ResolveDispatch; barrier-1 lands the primitive + C1.
//
// Four places the JVM CHA gift does NOT transfer, handled here (01-plan Barrier-1):
//  1. Explicit-interface MethodImpl — resolved via the table (explicitImpl), never
//     by name alone: an explicit impl body may be privately named, so a name-only
//     resolver reports a false absence.
//  2. Generics — CHA runs over the OPEN (uninstantiated) type; a MethodSpec's
//     instantiation is CARRIED on the target descriptor (Target.Instantiation), not
//     erased. Choice: carry-arity (the instantiation blob rides the edge for the
//     symbol-norm predecessor, A2) rather than erase.
//  3. Value types — a constrained. callvirt on a value type is a STATIC resolution
//     (resolved-single), not a dispatch expansion. Honored in ResolveDispatch.
//  4. Delegates — the target is the ldftn/ldvirtftn operand captured at delegate
//     construction, not the later Invoke. Barrier-1 records the ldftn target as a
//     resolved-single capture and flags the un-wired Invoke as a boundary, never a
//     dropped edge; barrier-2 wires ldftn → newobj(delegate) → Invoke.
//
// (jmp 0x27, an InlineMethod tail-transfer, is collected as an EdgeJmp and resolved to
// a declared DispatchBoundary — it hides a real call in the obfuscation threat model,
// so it is never a dropped edge; compilers rarely emit it.)

import "strings"

// DispatchState is one of the three C3 outcomes.
type DispatchState int

const (
	DispatchResolved     DispatchState = iota // exactly one statically-bound target
	DispatchConservative                      // virtual/interface: a conservative candidate set
	DispatchBoundary                          // a named boundary with a reason, never a dropped edge
)

func (s DispatchState) String() string {
	switch s {
	case DispatchResolved:
		return "resolved-single"
	case DispatchConservative:
		return "conservative-candidate-set"
	case DispatchBoundary:
		return "unresolved-boundary"
	}
	return "?"
}

// Target is one resolved call target. Method is nil when the target is named but
// out-of-set (a direct call whose body is not in the loaded set — still a single
// resolved target). Instantiation carries a MethodSpec's generic type args (caveat 2).
type Target struct {
	Asm           *Assembly
	Type          *TypeDef
	Method        *MethodDef
	OwnerDisplay  string
	Name          string
	Instantiation []byte
}

// DispatchResult is the outcome of resolving one call site.
type DispatchResult struct {
	State        DispatchState
	Kind         EdgeKind
	Targets      []Target
	Conservative bool
	Reason       string // set for DispatchBoundary and for the delegate/value-type notes
}

// typeNode is a type in the hierarchy graph with resolved base/interface links and
// the reverse (derived/implementer) edges the candidate-set BFS walks.
type typeNode struct {
	asm     *Assembly
	def     *TypeDef
	key     string
	base    *typeNode
	ifaces  []*typeNode
	derived []*typeNode // direct subclasses + direct implementers (reverse of base/ifaces)
	isValue bool        // extends System.ValueType/System.Enum (caveat 3)
}

func (n *typeNode) isInterface() bool { return n.def.Flags&0x20 != 0 } // TypeAttributes.Interface

// CHA is the class-hierarchy index over a loaded assembly set.
type CHA struct {
	asms        []*Assembly
	byKey       map[string][]*typeNode
	methodOwner map[*MethodDef]*typeNode
}

func typeKey(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "." + name
}

// NewCHA builds the hierarchy over the given assemblies (barrier-1: a single loaded
// set; the join keys on namespace+name, disambiguated by resolution scope when a
// name collides across assemblies).
func NewCHA(asms ...*Assembly) *CHA {
	c := &CHA{
		asms:        asms,
		byKey:       map[string][]*typeNode{},
		methodOwner: map[*MethodDef]*typeNode{},
	}
	// Pass 1: create nodes, index by key and by method ownership.
	for _, a := range asms {
		if a == nil || a.Failed {
			continue
		}
		for i := range a.Types {
			td := &a.Types[i]
			n := &typeNode{
				asm:     a,
				def:     td,
				key:     typeKey(td.Namespace, td.Name),
				isValue: td.Extends.Namespace == "System" && (td.Extends.Name == "ValueType" || td.Extends.Name == "Enum"),
			}
			c.byKey[n.key] = append(c.byKey[n.key], n)
			for _, m := range td.Methods {
				c.methodOwner[m] = n
			}
		}
	}
	// Pass 2: resolve base + interfaces, wire reverse edges.
	for _, nodes := range c.byKey {
		for _, n := range nodes {
			if b := c.lookup(n.def.Extends); b != nil {
				n.base = b
				b.derived = append(b.derived, n)
			}
			for _, ifaceRef := range n.def.Interfaces {
				if iface := c.lookup(ifaceRef); iface != nil {
					n.ifaces = append(n.ifaces, iface)
					iface.derived = append(iface.derived, n)
				}
			}
		}
	}
	return c
}

// lookup resolves a TypeRef to an in-set node, or nil if the type is out-of-set
// (a different, unloaded assembly) or a TypeSpec (generic instantiation — CHA runs
// over the open type, so a raw spec at a call owner is a boundary here).
func (c *CHA) lookup(tr TypeRef) *typeNode {
	if tr.Token.IsNull() || tr.IsSpec {
		return nil
	}
	nodes := c.byKey[typeKey(tr.Namespace, tr.Name)]
	switch len(nodes) {
	case 0:
		return nil
	case 1:
		return nodes[0]
	}
	if tr.Scope != "" {
		for _, n := range nodes {
			if n.asm.Name == tr.Scope {
				return n
			}
		}
	}
	return nodes[0]
}

// ResolveDispatch classifies one call site into the three C3 states.
func (c *CHA) ResolveDispatch(asm *Assembly, e Edge) DispatchResult {
	switch e.Kind {
	case EdgeCalli:
		return DispatchResult{State: DispatchBoundary, Kind: e.Kind,
			Reason: "calli: indirect call through a StandAloneSig, target not statically known"}
	case EdgeJmp:
		return DispatchResult{State: DispatchBoundary, Kind: e.Kind,
			Reason: "jmp_tail_transfer: method-body tail-transfers to another method; a hidden call, not a normal edge"}
	case EdgeLdftn, EdgeLdvirtftn:
		owner, name, sig, disp, ok := c.methodRef(asm, e.Token)
		if !ok {
			return DispatchResult{State: DispatchBoundary, Kind: e.Kind, Reason: "ldftn: unresolvable target token"}
		}
		tgt := c.exactTarget(owner, asm, e.Token, name, sig, disp, nil)
		if tgt.Method == nil {
			return DispatchResult{State: DispatchBoundary, Kind: e.Kind,
				Reason: "ldftn target " + disp + " outside loaded assembly set; delegate Invoke wiring deferred to barrier-2"}
		}
		return DispatchResult{State: DispatchResolved, Kind: e.Kind, Targets: []Target{tgt},
			Reason: "delegate target capture; Invoke wiring deferred to barrier-2"}
	}

	// Generics (caveat 2): unwrap a MethodSpec to its OPEN method; CARRY the instantiation.
	token := e.Token
	var inst []byte
	if token.Table() == tMethodSpec && token.RID() > 0 && int(token.RID()) < len(asm.MethodSpecs) {
		ms := asm.MethodSpecs[token.RID()]
		inst = ms.InstantiationBlob
		token = ms.Method
	}

	owner, name, sig, disp, ok := c.methodRef(asm, token)
	if !ok {
		return DispatchResult{State: DispatchBoundary, Kind: e.Kind, Reason: "unresolvable call token"}
	}

	switch e.Kind {
	case EdgeNewobj, EdgeCall:
		// newobj binds an EXACT constructor (never virtual); call is a direct bind.
		// Both are resolved-single — one named target, even if its body is out-of-set.
		tgt := c.exactTarget(owner, asm, token, name, sig, disp, inst)
		return DispatchResult{State: DispatchResolved, Kind: e.Kind, Targets: []Target{tgt}}

	case EdgeCallvirt:
		// Caveat 3: constrained. on a value type flips callvirt to a STATIC resolution.
		if !e.Constrained.IsNull() {
			if cn := c.lookup(asm.TypeRefFor(e.Constrained)); cn != nil && cn.isValue {
				m := c.matchMethod(cn, name, sig)
				tgt := Target{Asm: cn.asm, Type: cn.def, Method: m, OwnerDisplay: cn.key, Name: name, Instantiation: inst}
				return DispatchResult{State: DispatchResolved, Kind: e.Kind, Targets: []Target{tgt},
					Reason: "constrained. value-type static dispatch"}
			}
		}
		// Genuine virtual/interface dispatch.
		if owner == nil {
			return DispatchResult{State: DispatchBoundary, Kind: e.Kind,
				Reason: "callvirt owner " + disp + " outside loaded assembly set (open-world receiver)"}
		}
		targets := c.candidateSet(owner, name, sig, inst)
		return DispatchResult{State: DispatchConservative, Kind: e.Kind, Targets: targets, Conservative: true}
	}
	return DispatchResult{State: DispatchBoundary, Kind: e.Kind, Reason: "unhandled edge kind"}
}

// methodRef resolves a MethodDefOrRef-shaped call token to (owner node — nil if
// out-of-set, method name, signature blob, owner display, ok). It never fabricates:
// an unresolvable token returns ok=false.
func (c *CHA) methodRef(asm *Assembly, t Token) (owner *typeNode, name string, sig []byte, disp string, ok bool) {
	switch t.Table() {
	case tMethodDef:
		m := asm.MethodByRID(t.RID())
		if m == nil {
			return nil, "", nil, "", false
		}
		owner = c.methodOwner[m]
		if owner != nil {
			disp = owner.key
		}
		return owner, m.Name, m.SigBlob, disp, true
	case tMemberRef:
		mr := asm.MemberRef(t.RID())
		if mr == nil {
			return nil, "", nil, "", false
		}
		tr := asm.TypeRefFor(mr.ParentToken)
		owner = c.lookup(tr)
		disp = typeDisplay(tr)
		if disp == "" && owner != nil {
			disp = owner.key
		}
		return owner, mr.Name, mr.SigBlob, disp, true
	}
	return nil, "", nil, "", false
}

// exactTarget builds the single resolved target for a call/newobj/ldftn. A MethodDef
// token resolves to the local method directly; a MemberRef resolves within its owner
// if in-set, else stays a named-only target (Method nil) — a resolved-single boundary
// the caller (or barrier-2) treats as an out-of-set hazard.
func (c *CHA) exactTarget(owner *typeNode, asm *Assembly, t Token, name string, sig []byte, disp string, inst []byte) Target {
	if t.Table() == tMethodDef {
		m := asm.MethodByRID(t.RID())
		var td *TypeDef
		if owner != nil {
			td = owner.def
		}
		return Target{Asm: asm, Type: td, Method: m, OwnerDisplay: disp, Name: name, Instantiation: inst}
	}
	// MemberRef: bind within the owner type if it is in-set.
	if owner != nil {
		if m := c.declaredMethod(owner, name, sig); m != nil {
			return Target{Asm: owner.asm, Type: owner.def, Method: m, OwnerDisplay: disp, Name: name, Instantiation: inst}
		}
	}
	return Target{Asm: asm, Type: nil, Method: nil, OwnerDisplay: disp, Name: name, Instantiation: inst}
}

// candidateSet is the conservative virtual/interface candidate set: every in-set
// type that derives from / implements the declared owner AND has a runnable matching
// override. Interface members are resolved through MethodImpl (explicit impl) as well
// as by implicit name+sig — the caveat-1 correctness point.
func (c *CHA) candidateSet(owner *typeNode, name string, sig []byte, inst []byte) []Target {
	ownerIsIface := owner.isInterface()
	var targets []Target
	seen := map[*MethodDef]bool{}

	// BFS the reverse edges: owner + all transitive subclasses/implementers.
	queue := []*typeNode{owner}
	visited := map[*typeNode]bool{owner: true}
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]

		// Collect t's runnable target(s) for this slot. Interface members resolve
		// through interfaceTarget (explicit MethodImpl, then implicit name+sig). A
		// class virtual resolves by implicit name+sig override AND — the FIX 1 point —
		// by an explicit MethodImpl whose Declaration names the owner's slot up the
		// Extends chain, catching a differently/privately-named override body that
		// name-only matching drops. Both are collected (deduped by seen): a genuine
		// override joins the conservative set, never fabricating a target.
		var ms []*MethodDef
		if ownerIsIface {
			if m := c.interfaceTarget(t, owner, name, sig); m != nil {
				ms = append(ms, m)
			}
		} else {
			if m := c.matchMethod(t, name, sig); m != nil {
				ms = append(ms, m)
			}
			if m := c.explicitImpl(t, name, sig, func(o *typeNode) bool { return c.extendsRelated(o, owner) }); m != nil {
				ms = append(ms, m)
			}
		}
		for _, m := range ms {
			if !seen[m] {
				seen[m] = true
				targets = append(targets, Target{Asm: t.asm, Type: t.def, Method: m, OwnerDisplay: t.key, Name: name, Instantiation: inst})
			}
		}
		for _, d := range t.derived {
			if !visited[d] {
				visited[d] = true
				queue = append(queue, d)
			}
		}
	}
	return targets
}

// interfaceTarget resolves how type t satisfies interface member iface.name/sig:
// an EXPLICIT MethodImpl slot first (a privately-named body a name-only resolver
// misses — caveat 1), else an IMPLICIT public name+sig method.
func (c *CHA) interfaceTarget(t, iface *typeNode, name string, sig []byte) *MethodDef {
	if m := c.explicitImpl(t, name, sig, func(o *typeNode) bool { return o == iface }); m != nil {
		return m
	}
	return c.matchMethod(t, name, sig)
}

// explicitImpl looks up t's MethodImpl rows for a slot whose Declaration matches the
// dispatched member by name+sig AND whose (in-set) declaring owner satisfies ownerOK —
// the body is NEVER matched by name, since an explicit impl body may be arbitrarily/
// privately named (caveat 1). For an interface member ownerOK is identity with the
// interface node; for a class virtual it is Extends-chain membership with the owner,
// so an override declared against any ancestor slot is caught. An out-of-set (nil)
// declaration owner is accepted on name+sig alone, matching the interface path.
// Returns the implementing Body method.
func (c *CHA) explicitImpl(t *typeNode, name string, sig []byte, ownerOK func(*typeNode) bool) *MethodDef {
	for _, mi := range t.asm.MethodImpls {
		if mi.Class.Table() != tTypeDef || mi.Class.RID() != t.def.RID {
			continue
		}
		dOwner, dName, dSig, _, ok := c.methodRef(t.asm, mi.Declaration)
		if !ok || dName != name || !bytesEqual(dSig, sig) {
			continue
		}
		if dOwner != nil && !ownerOK(dOwner) {
			continue
		}
		if mi.Body.Table() == tMethodDef {
			if m := t.asm.MethodByRID(mi.Body.RID()); m != nil && m.RVA != 0 {
				return m
			}
		}
	}
	return nil
}

// extendsRelated reports whether a and b lie on the same class Extends lineage (a is b,
// or one is an ancestor of the other). It is the sound over-approximate test for whether
// a class MethodImpl.Declaration against type a targets the virtual slot dispatched
// through owner b: candidateSet only visits t in owner's derived closure, and a valid
// class MethodImpl.Declaration names a base of t, so both a and b are ancestors of t and
// therefore colinear under single inheritance. Ambiguity resolves toward inclusion — a
// candidate is never dropped silently (FIX 1: class-virtual explicit override).
func (c *CHA) extendsRelated(a, b *typeNode) bool {
	for n := b; n != nil; n = n.base {
		if n == a {
			return true
		}
	}
	for n := a; n != nil; n = n.base {
		if n == b {
			return true
		}
	}
	return false
}

// matchMethod returns t's own runnable method matching name+sig (a concrete override),
// or nil. Abstract/no-body methods are not candidates — a candidate must be a body
// that could actually run.
func (c *CHA) matchMethod(t *typeNode, name string, sig []byte) *MethodDef {
	for _, m := range t.def.Methods {
		if m.Name == name && bytesEqual(m.SigBlob, sig) && m.Flags&0x400 == 0 && m.RVA != 0 {
			return m
		}
	}
	return nil
}

// declaredMethod returns t's method matching name+sig regardless of abstractness
// (used for an exact direct-call bind, where an abstract target is still the name).
func (c *CHA) declaredMethod(t *typeNode, name string, sig []byte) *MethodDef {
	for _, m := range t.def.Methods {
		if m.Name == name && bytesEqual(m.SigBlob, sig) {
			return m
		}
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lookupType exposes the type index for tests/diagnostics: resolve a namespace.name
// (optionally scope-qualified as "scope!ns.name") to its TypeDef, or nil.
func (c *CHA) lookupType(display string) *TypeDef {
	scope := ""
	if i := strings.IndexByte(display, '!'); i >= 0 {
		scope, display = display[:i], display[i+1:]
	}
	nodes := c.byKey[display]
	for _, n := range nodes {
		if scope == "" || n.asm.Name == scope {
			return n.def
		}
	}
	return nil
}
