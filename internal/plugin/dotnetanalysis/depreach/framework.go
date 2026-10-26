package depreach

// framework.go — the shared-framework model.
//
// Without it, every call into Microsoft.NETCore.App (Console.WriteLine, List<T>.Sort,
// string.Concat) is an out-of-set call and therefore a hazard, so no real program can be
// shown not_exploitable. With it, a call into an assembly the caller names as shared
// framework is a leaf, except where the framework can run application code the static
// graph does not see:
//
//   - reflection, dynamic loading, serializers and the DLR decide their callee at run
//     time: those owners and members are hazards (frameworkHazard), as is any framework
//     member taking a System.Type, a runtime handle or a System.Reflection type
//     (paramHazard), since that is how code hands the framework a type to instantiate or
//     a member to invoke;
//   - some framework members resolve a type from a name and construct it: a provider
//     invariant name, a CryptoConfig algorithm name, an assembly-qualified name, a
//     converter or editor declared by attribute. Those are hazards too (frameworkHazard,
//     nameHazard), because the type they construct is never seen constructed, so its
//     overrides are not re-entry roots. The list comes from walking the implementation IL
//     of the Microsoft.NETCore.App runtime pack back from Type.GetType, Activator,
//     Assembly/AssemblyLoadContext loading and RuntimeType activation to the public
//     members that reach them, keeping those whose name or type input the caller controls;
//   - the framework calls back into application objects it is given: a comparer's
//     Compare, an enumerable's GetEnumerator, an override of ToString. Those callbacks
//     are the re-entry roots (reentryRoots): every virtual of a type that is instantiated
//     and has framework ancestry, plus the Object virtuals of every instantiated type;
//   - the framework also reads the properties of objects it is given, by reflection and
//     without virtual dispatch: serializers, formatters, binders and diagnostic payload
//     fetchers run the accessors of whatever object they were handed. So every property
//     getter and setter of an instantiated type, of any visibility, static or instance, is
//     a re-entry root as well. Accessors are the methods the MethodSemantics table binds to
//     a property, which is what reflection runs; their get_/set_ names are a compiler
//     convention and are not consulted. Which framework member did the reading does not
//     matter, so this class needs no list of reflecting members.
//     A search that touched framework code is not_exploitable only if the sink is
//     unreachable from the re-entry roots as well; otherwise it is undetermined.
//   - delegates the framework invokes were captured by an ldftn/ldvirtftn in code the
//     search reaches, and those captures are edges, so the delegate's target is searched.
//
// "Instantiated" is a rapid-type-analysis fixpoint over the program roots (SetProgramRoots):
// types constructed by newobj, every value type, and generic arguments the framework could
// construct, in code reachable from the roots or from the re-entry roots. If that closure
// hits any hazard, a reflective construction could be hiding in it, so the filter is off
// and every in-set type counts as instantiated. Queries from any other ingress use the
// unfiltered set too.

import (
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

const (
	maVirtual  uint16 = 0x0040 // MethodAttributes.Virtual
	maAbstract uint16 = 0x0400 // MethodAttributes.Abstract
	taAbstract uint32 = 0x80   // TypeAttributes.Abstract
	miaRuntime uint16 = 0x0003 // MethodImplAttributes CodeType Runtime
	tblTypeDef        = 0x02
)

// fwModel is the engine's shared-framework state. names is nil while the model is off.
type fwModel struct {
	names map[string]bool

	progRoots map[*methodNode]bool
	progCtx   *searchCtx // nil when the program-root closure was not complete
	allCtx    *searchCtx
	rtaWhy    string // why the instantiated filter is off, when it is
	nextGen   int

	ancestry  map[*assembly.TypeDef][]typeEntry
	oos       map[*assembly.TypeDef]oosFacts
	overrides map[ovKey][]*methodNode
	reentry   map[int][]*methodNode
	phaseB    map[string]searchOut
}

func (f *fwModel) active() bool { return f.names != nil }

// searchCtx is the instantiated-type view a search resolves framework dispatch against.
// A nil map means every in-set type counts.
type searchCtx struct {
	gen    int
	inst   map[*assembly.TypeDef]bool
	genArg map[*assembly.TypeDef]bool
}

func (c *searchCtx) counts(td *assembly.TypeDef) bool { return c.inst == nil || c.inst[td] }
func (c *searchCtx) isGenArg(td *assembly.TypeDef) bool {
	return c.genArg == nil || c.genArg[td]
}

type ovKey struct {
	asm *assembly.Assembly
	tok assembly.Token
	gen int
}

// oosFacts records whether a type's ancestry leaves the loaded set: through a base other
// than Object/ValueType/Enum, or through an interface.
type oosFacts struct {
	base, iface bool
}

func (o oosFacts) any() bool { return o.base || o.iface }

// SetFramework turns the shared-framework model on. names are the simple names of the
// assemblies whose code is the platform's; the caller decides them (and must leave out
// any assembly the loaded set supplies); they compare case-insensitively. A type that resolves in the loaded set is never
// treated as framework, whatever its assembly's name.
func (e *Engine) SetFramework(names map[string]bool) {
	if len(names) == 0 {
		e.fw = fwModel{}
		return
	}
	lower := make(map[string]bool, len(names))
	for n, ok := range names {
		if ok {
			lower[strings.ToLower(n)] = true
		}
	}
	e.fw = fwModel{
		names:     lower,
		ancestry:  map[*assembly.TypeDef][]typeEntry{},
		oos:       map[*assembly.TypeDef]oosFacts{},
		overrides: map[ovKey][]*methodNode{},
		reentry:   map[int][]*methodNode{},
		phaseB:    map[string]searchOut{},
	}
	e.fw.allCtx = e.newCtx(nil, nil)
}

// FrameworkActive reports whether SetFramework turned the model on.
func (e *Engine) FrameworkActive() bool { return e.fw.active() }

// InstantiatedFilterOff returns why the program-root instantiated-type filter is off, or
// "" when it is on (or the model is inactive, or no program roots were set).
func (e *Engine) InstantiatedFilterOff() string { return e.fw.rtaWhy }

func (e *Engine) newCtx(inst, genArg map[*assembly.TypeDef]bool) *searchCtx {
	e.fw.nextGen++
	return &searchCtx{gen: e.fw.nextGen, inst: inst, genArg: genArg}
}

// ctxFor picks the instantiated view for a search from starts: the program-root fixpoint
// when every start is a program root and that fixpoint was complete, else every type.
func (e *Engine) ctxFor(starts []*methodNode) *searchCtx {
	if !e.fw.active() {
		return nil
	}
	if e.fw.progCtx == nil {
		return e.fw.allCtx
	}
	for _, s := range starts {
		if !e.fw.progRoots[s] {
			return e.fw.allCtx
		}
	}
	return e.fw.progCtx
}

// SetProgramRoots names the methods the host runs (Main and the runtime roots) and
// computes the instantiated-type fixpoint over them. It does nothing while the framework
// model is off.
func (e *Engine) SetProgramRoots(keys []MethodKey) {
	if !e.fw.active() {
		return
	}
	e.fw.progRoots = map[*methodNode]bool{}
	var roots []*methodNode
	for _, k := range keys {
		for _, n := range e.byKey[k] {
			if !e.fw.progRoots[n] {
				e.fw.progRoots[n] = true
				roots = append(roots, n)
			}
		}
	}
	e.fw.progCtx, e.fw.rtaWhy = nil, ""
	if len(roots) == 0 {
		e.fw.rtaWhy = "no program roots in the loaded set"
		return
	}

	inst := map[*assembly.TypeDef]bool{}
	genArg := map[*assembly.TypeDef]bool{}
	why := ""
	incomplete := func(w string) {
		if why == "" {
			why = w
		}
	}
	var addInst, addGenArg func(te typeEntry)
	specArgs := func(asm *assembly.Assembly, tr assembly.TypeRef) {
		if !tr.IsSpec {
			return
		}
		tes, ok := e.typesInSig(asm, tr.SpecBlob, false)
		if !ok {
			incomplete("undecodable type specification")
		}
		for _, te := range tes {
			addGenArg(te)
		}
	}
	addInst = func(te typeEntry) {
		if inst[te.td] {
			return
		}
		inst[te.td] = true
		specArgs(te.asm, te.td.Extends)
		for _, i := range te.td.Interfaces {
			specArgs(te.asm, i)
		}
	}
	addGenArg = func(te typeEntry) {
		if genArg[te.td] {
			return
		}
		genArg[te.td] = true
		// A generic argument with a parameterless constructor may be constructed by the
		// framework (new T() compiles to a reflective construction inside it).
		if te.td.Flags&(taAbstract|taInterface) == 0 && e.defaultCtor(te) != nil {
			addInst(te)
		}
	}
	for _, te := range e.types {
		if isValueTypeEntry(te) {
			addInst(te)
		}
	}
	tokenFacts := func(asm *assembly.Assembly, tok assembly.Token, newobj bool) {
		if tok.Table() == tblMethodSpec {
			if int(tok.RID()) >= len(asm.MethodSpecs) {
				incomplete("unresolvable method specification")
				return
			}
			ms := asm.MethodSpecs[tok.RID()]
			tes, ok := e.typesInSig(asm, ms.InstantiationBlob, true)
			if !ok {
				incomplete("undecodable method instantiation")
			}
			for _, te := range tes {
				addGenArg(te)
			}
			tok = ms.Method
		}
		var owner typeEntry
		var inSet bool
		switch tok.Table() {
		case tblMethodDef:
			if m := asm.MethodByRID(tok.RID()); m != nil {
				owner, inSet = e.ownerOf[m]
			}
		case tblMemberRef:
			if mr := asm.MemberRef(tok.RID()); mr != nil {
				tr := asm.TypeRefFor(mr.ParentToken)
				specArgs(asm, tr)
				owner, inSet = e.lookupTypeRef(asm, tr)
			}
		}
		if newobj && inSet {
			addInst(owner)
		}
	}
	visit := func(n *methodNode, body *assembly.MethodBody) {
		if body == nil {
			return
		}
		for _, ed := range body.Edges {
			tokenFacts(n.asm, ed.Token, ed.Kind == assembly.EdgeNewobj)
		}
		for _, tr := range body.InitTriggers {
			tokenFacts(n.asm, tr.Token, false)
		}
	}

	var ctx *searchCtx
	for pass := 0; ; pass++ {
		size := len(inst) + len(genArg)
		ctx = e.newCtx(inst, genArg)
		starts := append(append([]*methodNode{}, roots...), e.reentryRoots(ctx)...)
		out := e.walk(starts, nil, ctx, visit)
		if out.hazard {
			incomplete(out.why)
		}
		if len(inst)+len(genArg) == size {
			break
		}
		if pass == 64 {
			incomplete("instantiated-type fixpoint did not converge")
			break
		}
	}
	if why != "" {
		e.fw.rtaWhy = "instantiated-type closure is not complete: " + why
		return
	}
	// The final pass added nothing, so its cached overrides and roots are consistent.
	e.fw.progCtx = ctx
}

// isFrameworkType reports whether tr (read in asm) is a type the framework model treats as
// platform code: not in the loaded set, and defined by an assembly named as framework.
func (e *Engine) isFrameworkType(asm *assembly.Assembly, tr assembly.TypeRef) bool {
	if !e.fw.active() || asm == nil {
		return false
	}
	if _, ok := e.lookupTypeRef(asm, tr); ok {
		return false
	}
	name, ok := asm.DefiningAssembly(tr.Token)
	return ok && e.fw.names[strings.ToLower(name)]
}

// isDelegateRuntimeMethod reports whether tgt is one of the runtime-implemented members
// of an in-set delegate type.
func (e *Engine) isDelegateRuntimeMethod(tgt assembly.Target) bool {
	if tgt.Type == nil || tgt.Method == nil {
		return false
	}
	if !isDelegateType(typeEntry{asm: tgt.Asm, td: tgt.Type}) || tgt.Method.ImplFlags&miaCodeType != miaRuntime {
		return false
	}
	switch tgt.Method.Name {
	case "Invoke", "BeginInvoke", "EndInvoke", ".ctor":
		return true
	}
	return false
}

// frameworkEdge resolves a call site whose callee is a shared-framework member. ok is
// false when the callee is not one (CHA resolves it as before).
func (e *Engine) frameworkEdge(edge assembly.Edge, fromAsm *assembly.Assembly, ctx *searchCtx) (edgeOut, bool) {
	if !e.fw.active() {
		return edgeOut{}, false
	}
	switch edge.Kind {
	case assembly.EdgeCall, assembly.EdgeCallvirt, assembly.EdgeNewobj, assembly.EdgeLdftn, assembly.EdgeLdvirtftn:
	default:
		return edgeOut{}, false
	}
	tok := edge.Token
	var inst []byte
	if tok.Table() == tblMethodSpec {
		if int(tok.RID()) >= len(fromAsm.MethodSpecs) {
			return edgeOut{}, false
		}
		ms := fromAsm.MethodSpecs[tok.RID()]
		inst, tok = ms.InstantiationBlob, ms.Method
	}
	if tok.Table() != tblMemberRef {
		return edgeOut{}, false
	}
	mr := fromAsm.MemberRef(tok.RID())
	if mr == nil {
		return edgeOut{}, false
	}
	parent := fromAsm.TypeRefFor(mr.ParentToken)
	if isArraySpec(parent) {
		switch mr.Name {
		case "Get", "Set", "Address", ".ctor":
			// The runtime's own multi-dimensional array accessors: no code of anyone's.
			return edgeOut{}, true
		}
	}
	if !e.isFrameworkType(fromAsm, parent) {
		return edgeOut{}, false
	}
	owner, name := parent.Qualified(), mr.Name
	if w, ok := frameworkHazard(owner, name); ok {
		return edgeOut{hazard: true, why: w}, true
	}
	sig, err := DecodeMethodSig(mr.SigBlob, fromAsm)
	if err != nil || sig.Malformed {
		return edgeOut{hazard: true, why: "framework call with an undecodable signature: " + owner + "::" + name}, true
	}
	if !paramExempt(owner, name) {
		if p, ok := paramHazard(sig); ok {
			return edgeOut{hazard: true, why: "framework call takes " + p + " (a type or member handed to the framework): " + owner + "::" + name}, true
		}
	}
	if nameHazard(owner, name, sig, inst != nil) {
		return edgeOut{hazard: true, why: "framework reflection over a named or generic type: " + owner + "::" + name}, true
	}
	out := edgeOut{fw: true}
	if inst != nil && isAsyncBuilderStep(owner, name) {
		// The builder runs the state machine it was handed: an edge to its MoveNext.
		tes, _ := e.typesInSig(fromAsm, inst, true)
		for _, te := range tes {
			for _, m := range te.td.Methods {
				if m.Name == "MoveNext" && m.RVA != 0 {
					if n := e.nodes[m]; n != nil {
						out.targets = append(out.targets, n)
					}
				}
			}
		}
	}
	if edge.Kind == assembly.EdgeCallvirt || edge.Kind == assembly.EdgeLdvirtftn {
		out.targets = append(out.targets, e.frameworkOverrides(ctx, fromAsm, tok, owner, name, mr.SigBlob)...)
	}
	return out, true
}

// isArraySpec reports whether tr is an array TypeSpec (ARRAY or SZARRAY).
func isArraySpec(tr assembly.TypeRef) bool {
	return tr.IsSpec && len(tr.SpecBlob) > 0 && (tr.SpecBlob[0] == etArray || tr.SpecBlob[0] == etSzArray)
}

// frameworkOverrides is a virtual dispatch through a framework-declared slot: the in-set
// instantiated types whose body can fill it. For System.Object/ValueType/Enum that is any
// type's override of the member; otherwise only a type with framework ancestry can sit
// behind a framework-typed receiver, and its body is a same-named virtual or a MethodImpl
// naming the member, declared on the type or inherited from an in-set ancestor.
func (e *Engine) frameworkOverrides(ctx *searchCtx, fromAsm *assembly.Assembly, tok assembly.Token, owner, name string, sig []byte) []*methodNode {
	key := ovKey{asm: fromAsm, tok: tok, gen: ctx.gen}
	if r, ok := e.fw.overrides[key]; ok {
		return r
	}
	objectSlot := owner == "System.Object" || owner == "System.ValueType" || owner == "System.Enum"
	var out []*methodNode
	seen := map[*methodNode]bool{}
	add := func(m *assembly.MethodDef) {
		if n := e.nodes[m]; n != nil && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, te := range e.types {
		if te.td.Flags&taInterface != 0 || !ctx.counts(te.td) {
			continue
		}
		if !objectSlot && !e.outOfSet(te).any() {
			continue
		}
		for _, a := range e.ancestryOf(te) {
			for _, m := range a.td.Methods {
				if m.Name == name && m.Flags&maVirtual != 0 && m.RVA != 0 && assembly.SigCompatible(fromAsm, sig, a.asm, m.SigBlob) {
					add(m)
				}
			}
			for _, mi := range a.asm.MethodImpls {
				if mi.Class.Table() == tblTypeDef && mi.Class.RID() == a.td.RID && methodTokName(a.asm, mi.Declaration) == name {
					if m := a.asm.MethodByRID(mi.Body.RID()); mi.Body.Table() == tblMethodDef && m != nil && m.RVA != 0 {
						add(m)
					}
				}
			}
		}
	}
	e.fw.overrides[key] = out
	return out
}

// reentryRoots are the methods framework code can call on application objects it holds:
// for an instantiated type with framework ancestry, every virtual body it has or inherits
// in-set (and every MethodImpl body); for any other instantiated type, its Object virtuals;
// and for every instantiated type, each property getter and setter it has or inherits
// in-set, as the MethodSemantics table names them.
// A generic argument's static constructor and parameterless constructor are roots too
// (the framework constructs a T through new T()), and its static methods when it
// implements a framework interface (static abstract members).
func (e *Engine) reentryRoots(ctx *searchCtx) []*methodNode {
	if r, ok := e.fw.reentry[ctx.gen]; ok {
		return r
	}
	var out []*methodNode
	seen := map[*methodNode]bool{}
	add := func(m *assembly.MethodDef) {
		if n := e.nodes[m]; n != nil && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, te := range e.types {
		if te.td.Flags&taInterface != 0 {
			continue
		}
		oos := e.outOfSet(te)
		if ctx.counts(te.td) {
			for _, a := range e.ancestryOf(te) {
				for _, m := range a.td.Methods {
					if m.RVA != 0 && a.asm.PropertyAccessor(m.RID) {
						add(m)
					}
					if m.Flags&maVirtual == 0 || m.RVA == 0 {
						continue
					}
					if oos.any() {
						add(m)
						continue
					}
					switch m.Name {
					case "ToString", "Equals", "GetHashCode", "Finalize":
						add(m)
					}
				}
				if oos.any() {
					for _, mi := range a.asm.MethodImpls {
						if mi.Class.Table() == tblTypeDef && mi.Class.RID() == a.td.RID && mi.Body.Table() == tblMethodDef {
							if m := a.asm.MethodByRID(mi.Body.RID()); m != nil && m.RVA != 0 {
								add(m)
							}
						}
					}
				}
			}
		}
		if ctx.isGenArg(te.td) {
			if cc := e.cctorOf(te); cc != nil {
				add(cc.def)
			}
			if c := e.defaultCtor(te); c != nil {
				add(c)
			}
			if oos.iface {
				for _, m := range te.td.Methods {
					if m.Flags&maStatic != 0 && m.RVA != 0 {
						add(m)
					}
				}
			}
		}
	}
	e.fw.reentry[ctx.gen] = out
	return out
}

// reentrySearch searches from the re-entry roots, cached per instantiated view and sink set.
func (e *Engine) reentrySearch(sinks []MethodKey, sinkSet map[*methodNode]bool, ctx *searchCtx) searchOut {
	var b strings.Builder
	b.WriteString(strconv.Itoa(ctx.gen))
	for _, k := range sinks {
		b.WriteByte('|')
		b.WriteString(k.String())
	}
	key := b.String()
	if r, ok := e.fw.phaseB[key]; ok {
		return r
	}
	r := e.search(e.reentryRoots(ctx), sinkSet, ctx)
	e.fw.phaseB[key] = r
	return r
}

// ancestryOf is te, its in-set base classes, and every in-set interface any of them
// implements (transitively): the in-set types whose bodies an instance of te can run.
func (e *Engine) ancestryOf(te typeEntry) []typeEntry {
	if r, ok := e.fw.ancestry[te.td]; ok {
		return r
	}
	var out []typeEntry
	seen := map[*assembly.TypeDef]bool{}
	var addIfaces func(t typeEntry)
	addIfaces = func(t typeEntry) {
		for _, ir := range t.td.Interfaces {
			if it, ok := e.lookupTypeRef(t.asm, ir); ok && !seen[it.td] {
				seen[it.td] = true
				out = append(out, it)
				addIfaces(it)
			}
		}
	}
	for c, ok := te, true; ok && !seen[c.td]; c, ok = e.lookupTypeRef(c.asm, c.td.Extends) {
		seen[c.td] = true
		out = append(out, c)
		addIfaces(c)
	}
	e.fw.ancestry[te.td] = out
	return out
}

// outOfSet reports how te's ancestry leaves the loaded set.
func (e *Engine) outOfSet(te typeEntry) oosFacts {
	if r, ok := e.fw.oos[te.td]; ok {
		return r
	}
	var f oosFacts
	for _, a := range e.ancestryOf(te) {
		if ext := a.td.Extends; !ext.Token.IsNull() {
			if _, ok := e.lookupTypeRef(a.asm, ext); !ok {
				switch ext.Qualified() {
				case "System.Object", "System.ValueType", "System.Enum":
				default:
					f.base = true
				}
			}
		}
		for _, ir := range a.td.Interfaces {
			if _, ok := e.lookupTypeRef(a.asm, ir); !ok {
				f.iface = true
			}
		}
	}
	e.fw.oos[te.td] = f
	return f
}

// defaultCtor is te's parameterless instance constructor, or nil.
func (e *Engine) defaultCtor(te typeEntry) *assembly.MethodDef {
	for _, m := range te.td.Methods {
		if m.Name != ".ctor" || m.Flags&maStatic != 0 || m.RVA == 0 {
			continue
		}
		if sig, err := DecodeMethodSig(m.SigBlob, te.asm); err == nil && len(sig.Params) == 0 {
			return m
		}
	}
	return nil
}

func isValueTypeEntry(te typeEntry) bool {
	ext := te.td.Extends
	return ext.Namespace == "System" && (ext.Name == "ValueType" || ext.Name == "Enum") && te.td.Flags&taInterface == 0
}

// typesInSig returns the in-set types named anywhere in a TypeSpec blob (one Type) or a
// MethodSpec instantiation blob (GENERICINST count, then that many Types). ok is false
// when the blob does not decode.
func (e *Engine) typesInSig(asm *assembly.Assembly, blob []byte, methodSpec bool) ([]typeEntry, bool) {
	r := &sigReader{b: blob}
	n := uint32(1)
	if methodSpec {
		if b, ok := r.byte(); !ok || b != 0x0A {
			return nil, false
		}
		n, _ = r.compressedUint()
	}
	var out []typeEntry
	seen := map[*assembly.TypeDef]bool{}
	var collect func(t TypeSig)
	collect = func(t TypeSig) {
		if !t.Token.IsNull() {
			if te, ok := e.lookupTypeRef(asm, t.Ref); ok && !seen[te.td] {
				seen[te.td] = true
				out = append(out, te)
			}
		}
		if t.Inner != nil {
			collect(*t.Inner)
		}
		for _, a := range t.Args {
			collect(a)
		}
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		collect(r.typeSig(asm))
	}
	return out, r.err == nil
}

func methodTokName(asm *assembly.Assembly, tok assembly.Token) string {
	switch tok.Table() {
	case tblMethodDef:
		if m := asm.MethodByRID(tok.RID()); m != nil {
			return m.Name
		}
	case tblMemberRef:
		if mr := asm.MemberRef(tok.RID()); mr != nil {
			return mr.Name
		}
	}
	return ""
}

// ---- framework hazard data (MATCH TARGETS: strings the resolver compares against) ----

// fwHazardNamespaces: every member of a type in these namespaces (or with this
// qualified-name prefix) binds or builds its target at run time.
var fwHazardNamespaces = []string{
	"System.Reflection",
	"System.Runtime.Loader",
	"System.Runtime.Serialization",
	"System.Xml.Serialization",
	"System.Xml.Xsl",
	"System.Dynamic",
	"Microsoft.CSharp",
	"Microsoft.VisualBasic",
	"System.Text.Json.Serialization",
	"System.Runtime.CompilerServices.CallSite", // CallSite, CallSite`1, CallSiteBinder, CallSiteHelpers
	"System.ComponentModel.DataAnnotations",    // validation attributes read off the user type
	"System.Net.Http.Json",                     // JsonSerializer over the caller's type
}

// fwHazardTypes: every member of these types is a hazard.
var fwHazardTypes = map[string]bool{
	"System.Activator": true,
	"System.Runtime.InteropServices.NativeLibrary":           true,
	"System.Runtime.InteropServices.ComWrappers":             true,
	"System.Text.Json.JsonSerializer":                        true,
	"System.ComponentModel.TypeDescriptor":                   true,
	"System.ComponentModel.PropertyDescriptor":               true,
	"System.ComponentModel.EventDescriptor":                  true,
	"System.ComponentModel.MemberDescriptor":                 true,
	"System.ComponentModel.ICustomTypeDescriptor":            true,
	"System.ComponentModel.BindingList`1":                    true, // TypeDescriptor over T
	"System.Resources.ResourceReader":                        true,
	"System.Data.Common.DbProviderFactories":                 true, // provider type by invariant or assembly-qualified name
	"System.Security.Cryptography.CryptoConfig":              true, // algorithm type by name, falling back to Type.GetType
	"System.Security.Cryptography.PasswordDeriveBytes":       true, // hash by name through CryptoConfig
	"System.Security.Cryptography.PKCS1MaskGenerationMethod": true,
	"System.Security.Cryptography.SignatureDescription":      true,
}

// fwHazardMembers: these members of otherwise-trusted types are hazards.
var fwHazardMembers = map[nameKey]bool{
	{"System.AppDomain", "CreateInstance"}:                                       true,
	{"System.AppDomain", "CreateInstanceAndUnwrap"}:                              true,
	{"System.AppDomain", "CreateInstanceFrom"}:                                   true,
	{"System.AppDomain", "CreateInstanceFromAndUnwrap"}:                          true,
	{"System.AppDomain", "ExecuteAssembly"}:                                      true,
	{"System.AppDomain", "ExecuteAssemblyByName"}:                                true,
	{"System.AppDomain", "Load"}:                                                 true,
	{"System.Delegate", "CreateDelegate"}:                                        true,
	{"System.Delegate", "DynamicInvoke"}:                                         true,
	{"System.MulticastDelegate", "DynamicInvoke"}:                                true,
	{"System.Attribute", "GetCustomAttribute"}:                                   true,
	{"System.Attribute", "GetCustomAttributes"}:                                  true,
	{"System.Runtime.CompilerServices.RuntimeHelpers", "RunClassConstructor"}:    true,
	{"System.Runtime.CompilerServices.RuntimeHelpers", "RunModuleConstructor"}:   true,
	{"System.Runtime.CompilerServices.RuntimeHelpers", "GetUninitializedObject"}: true,
	{"System.Runtime.InteropServices.Marshal", "PtrToStructure"}:                 true,
	{"System.Runtime.InteropServices.Marshal", "GetDelegateForFunctionPointer"}:  true,
	{"System.Runtime.InteropServices.Marshal", "GetObjectForIUnknown"}:           true,
	{"System.Runtime.InteropServices.Marshal", "GetTypedObjectForIUnknown"}:      true,
	{"System.Runtime.InteropServices.Marshal", "GetUniqueObjectForIUnknown"}:     true,
	{"System.Runtime.InteropServices.Marshal", "CreateWrapperOfType"}:            true,
	{"System.Runtime.InteropServices.Marshal", "GetObjectForNativeVariant"}:      true,
	{"System.Runtime.InteropServices.Marshal", "GetObjectsForNativeVariants"}:    true,
	{"System.Runtime.InteropServices.Marshal", "BindToMoniker"}:                  true,
	{"System.Runtime.InteropServices.Marshal", "GetActiveObject"}:                true,
	{"System.Data.DataSet", "ReadXml"}:                                           true,
	{"System.Data.DataSet", "ReadXmlSchema"}:                                     true,
	{"System.Data.DataTable", "ReadXml"}:                                         true,
	{"System.Data.DataTable", "ReadXmlSchema"}:                                   true,
	{"System.Resources.ResourceManager", "GetObject"}:                            true,
	{"System.Resources.ResourceSet", "GetObject"}:                                true,
	{"System.Data.DataSet", "InferXmlSchema"}:                                    true,
	{"System.Data.DataSet", "ReadXmlSerializable"}:                               true,
	{"System.Data.DataTable", "ReadXmlSerializable"}:                             true,
	{"System.ComponentModel.TypeConverter", "GetProperties"}:                     true, // TypeDescriptor over the value
	{"System.ComponentModel.ExpandableObjectConverter", "GetProperties"}:         true,
	{"System.ComponentModel.ComponentConverter", "GetProperties"}:                true,
	{"System.Data.Common.DbConnectionStringBuilder", "GetProperties"}:            true,
	{"System.ComponentModel.Container", "Add"}:                                   true, // TypeDescriptor over the component
	{"System.ComponentModel.Container", "ValidateName"}:                          true,
}

// nameHazard reports the hazards a member name alone does not settle: a cryptography
// factory's Create(string), which builds whatever CryptoConfig resolves the name to, and
// the generic members that reflect over their type argument (EventSource.Write<T> reads
// T's properties, JsonValue.Create<T> serializes T later).
func nameHazard(owner, name string, sig MethodSignature, generic bool) bool {
	if name == "Create" && strings.HasPrefix(owner, "System.Security.Cryptography.") &&
		!strings.Contains(owner[len("System.Security.Cryptography."):], ".") &&
		len(sig.Params) == 1 && sig.Params[0].Elem == etString && !sig.Params[0].ByRef {
		return true
	}
	if generic {
		switch (nameKey{owner, name}) {
		case nameKey{"System.Diagnostics.Tracing.EventSource", "Write"}, nameKey{"System.Text.Json.Nodes.JsonValue", "Create"}:
			return true
		}
	}
	return false
}

// typeMemberExempt: System.Type members that neither construct nor invoke anything.
var typeMemberExempt = map[string]bool{
	"GetTypeFromHandle": true, "op_Equality": true, "op_Inequality": true, "Equals": true,
	"GetHashCode": true, "ToString": true, "IsAssignableFrom": true, "IsAssignableTo": true,
	"IsSubclassOf": true, "IsEquivalentTo": true, "IsInstanceOfType": true,
	"get_Name": true, "get_FullName": true, "get_Namespace": true, "get_AssemblyQualifiedName": true,
	"get_IsValueType": true, "get_IsEnum": true, "get_IsInterface": true, "get_IsClass": true,
	"get_IsAbstract": true, "get_IsSealed": true, "get_IsArray": true, "get_IsPrimitive": true,
	"get_IsGenericType": true, "get_IsGenericTypeDefinition": true, "get_TypeHandle": true,
}

// frameworkHazard reports whether a framework member binds or builds its target at run
// time.
func frameworkHazard(owner, name string) (string, bool) {
	for _, ns := range fwHazardNamespaces {
		if owner == ns || strings.HasPrefix(owner, ns+".") || (strings.HasSuffix(ns, "CallSite") && strings.HasPrefix(owner, ns)) {
			return "framework reflection/dynamic binding: " + owner + "::" + name, true
		}
	}
	if fwHazardTypes[owner] || fwHazardMembers[nameKey{owner, name}] {
		return "framework reflection/dynamic binding: " + owner + "::" + name, true
	}
	if owner == "System.Type" && !typeMemberExempt[name] {
		return "framework reflection: " + owner + "::" + name, true
	}
	if strings.HasPrefix(owner, "System.Linq.Expressions.") && strings.HasPrefix(name, "Compile") {
		return "framework expression compilation: " + owner + "::" + name, true
	}
	return "", false
}

// paramExempt: framework members whose type/handle parameters are not a way to hand the
// framework something to construct or invoke.
func paramExempt(owner, name string) bool {
	switch owner {
	case "System.Type":
		return typeMemberExempt[name]
	case "System.Enum":
		return true // an enum carries no code
	case "System.Runtime.CompilerServices.RuntimeHelpers":
		return name == "InitializeArray" || name == "CreateSpan" // array/span initializers read static data
	}
	return false
}

// paramHazard reports the first parameter (at any depth of a generic or array type) that
// is System.Type, a runtime handle, or a System.Reflection type.
func paramHazard(sig MethodSignature) (string, bool) {
	var check func(t TypeSig) (string, bool)
	check = func(t TypeSig) (string, bool) {
		if !t.Token.IsNull() {
			q := t.Ref.Qualified()
			switch {
			case q == "System.Type", q == "System.RuntimeTypeHandle", q == "System.RuntimeMethodHandle", q == "System.RuntimeFieldHandle":
				return q, true
			case strings.HasPrefix(q, "System.Reflection."):
				return q, true
			}
		}
		if t.Inner != nil {
			if q, ok := check(*t.Inner); ok {
				return q, true
			}
		}
		for _, a := range t.Args {
			if q, ok := check(a); ok {
				return q, true
			}
		}
		return "", false
	}
	for _, p := range sig.Params {
		if q, ok := check(p); ok {
			return q, true
		}
	}
	return "", false
}

// isAsyncBuilderStep reports whether owner::name is a compiler async/iterator builder
// method that runs the state machine passed as its generic argument.
func isAsyncBuilderStep(owner, name string) bool {
	if !strings.HasPrefix(owner, "System.Runtime.CompilerServices.") || !strings.Contains(owner, "MethodBuilder") {
		return false
	}
	switch name {
	case "Start", "AwaitOnCompleted", "AwaitUnsafeOnCompleted", "MoveNext":
		return true
	}
	return false
}
