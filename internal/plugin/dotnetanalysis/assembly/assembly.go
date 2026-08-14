package assembly

import "fmt"

// Token is a metadata token: the high byte is the table id (§II.22) and the low 24
// bits are the 1-based row index (RID). It is the currency 02b's IL walk resolves —
// a call/callvirt operand is exactly such a token — so every coded-index and simple
// index in the model is exposed as a Token, and null references have RID 0.
type Token uint32

func makeToken(table int, rid uint32) Token { return Token(uint32(table)<<24 | (rid & 0x00FFFFFF)) }

// Table returns the metadata table id the token points into.
func (t Token) Table() int { return int(t >> 24) }

// RID returns the 1-based row index (0 for a null reference).
func (t Token) RID() uint32 { return uint32(t) & 0x00FFFFFF }

// IsNull reports whether the token is a null reference (RID 0).
func (t Token) IsNull() bool { return t.RID() == 0 }

// TypeRef is a resolved reference to a type — the model's uniform view of a
// TypeDef (this assembly), a TypeRef (another module/assembly), or a TypeSpec
// (a generic instantiation). Token carries the precise underlying reference so
// 02b's CHA can resolve it exactly; Scope/Namespace/Name are the best-effort
// display resolution. For a TypeSpec, Name is empty and SpecBlob holds the
// instantiation signature (CHA runs over the open type — a barrier-2 concern).
type TypeRef struct {
	Scope     string // resolution scope (AssemblyRef/Module/ModuleRef name); "" for this assembly
	Namespace string
	Name      string
	Token     Token
	IsSpec    bool   // came from a TypeSpec (generic instantiation)
	SpecBlob  []byte // TypeSpec signature blob when IsSpec
}

// MethodDef is a method defined in this assembly. RVA points at the IL body in the
// PE (0 for abstract/pinvoke/runtime methods) — 02b reads the method-body header
// there. SigBlob is the raw #Blob calling-convention signature (02b decodes params).
type MethodDef struct {
	RID          uint32
	Token        Token
	Name         string
	RVA          uint32 // IL body RVA (0 => no managed body)
	Flags        uint16 // MethodAttributes (§II.23.1.10)
	ImplFlags    uint16 // MethodImplAttributes (§II.23.1.11): native/runtime/managed
	SigBlob      []byte
	ParamListRID uint32 // first Param row; range ends at the next method's ParamList
}

// TypeDef is a type defined in this assembly, with the CHA inputs 02b needs:
// Extends (base type) and Interfaces (from the InterfaceImpl table). Methods are
// the type's declared methods in RID order.
type TypeDef struct {
	RID        uint32
	Token      Token
	Namespace  string
	Name       string
	Flags      uint32 // TypeAttributes (§II.23.1.15)
	Extends    TypeRef
	Methods    []*MethodDef
	Interfaces []TypeRef
}

// MethodRef is a MemberRef resolved to a call target the way a call site names it:
// the parent type (Assembly scope + Type name) and the method Name + signature.
// ParentToken carries the exact MemberRefParent target (TypeRef/TypeSpec/TypeDef/
// ModuleRef/MethodDef) for 02b to resolve against the hierarchy.
type MethodRef struct {
	RID         uint32
	Assembly    string // resolution-scope name of the parent type ("" if this assembly)
	Type        string // parent type display name (namespace.name); "" for a TypeSpec parent
	Name        string
	SigBlob     []byte
	ParentToken Token
}

// MethodImpl is one row of the MethodImpl table (§II.22.27): the .NET-unique
// explicit-interface body→declaration map. callvirt IFoo.Bar resolves through THIS,
// not name+signature — Body is the implementing method, Declaration the interface
// (or overridden) method, both MethodDefOrRef tokens. Java has no analog; missing
// this yields a false absence in interface dispatch (plan §Barrier-1 caveat 1).
type MethodImpl struct {
	Class       Token // TypeDef declaring the implementation
	Body        Token // MethodDefOrRef: the implementing method
	Declaration Token // MethodDefOrRef: the interface/overridden method it satisfies
}

// NestedClass is one row of the NestedClass table (§II.22.32): a nested type and its
// enclosing type, both TypeDef tokens (02b builds the enclosing-qualified name).
type NestedClass struct {
	Nested    Token
	Enclosing Token
}

// TypeSpec is one row of the TypeSpec table: a signature blob describing a
// constructed type (generic instantiation, array, pointer). RID is 1-based.
type TypeSpec struct {
	RID  uint32
	Blob []byte
}

// MethodSpec is one row of the MethodSpec table (§II.22.29): a generic-method
// instantiation — Method is the open MethodDefOrRef, InstantiationBlob the type args.
type MethodSpec struct {
	RID               uint32
	Method            Token
	InstantiationBlob []byte
}

// Assembly is the parsed typed model of one managed assembly. On the batch path a
// parse failure yields Assembly{Failed:true, FailReason:...} so the caller degrades
// to a completeness hazard (plan criterion C5) rather than dropping the artifact —
// the cobalt JarResult.Failed analog. Types/tables are empty in that case.
type Assembly struct {
	Name       string
	Flags      uint32 // CLI header flags (COMIMAGE_FLAGS_*)
	EntryPoint uint32 // EntryPointToken from the CLI header
	Types      []TypeDef

	// Tables 02b's IL walk + CHA consume, 1-indexed by RID (index 0 is a zero
	// placeholder so mr[rid] is a direct lookup).
	MemberRefs  []MethodRef
	TypeSpecs   []TypeSpec
	MethodSpecs []MethodSpec
	MethodImpls []MethodImpl
	NestedTypes []NestedClass

	Failed     bool
	FailReason string

	methodsByRID map[uint32]*MethodDef
	md           *mdTables
}

// MethodByRID resolves a MethodDef RID (e.g. the low bits of a MethodDefOrRef
// token) to the declared method, or nil.
func (a *Assembly) MethodByRID(rid uint32) *MethodDef { return a.methodsByRID[rid] }

// MemberRef resolves a MemberRef RID to its MethodRef, or nil.
func (a *Assembly) MemberRef(rid uint32) *MethodRef {
	if int(rid) <= 0 || int(rid) >= len(a.MemberRefs) {
		return nil
	}
	return &a.MemberRefs[rid]
}

// TypeRefFor resolves any TypeDefOrRef-shaped token (TypeDef/TypeRef/TypeSpec) to a
// TypeRef. This is the coded-index resolution helper 02b's CHA uses to turn a call
// operand's parent into a named type. A null or unknown token yields a zero TypeRef.
func (a *Assembly) TypeRefFor(tok Token) TypeRef {
	if tok.IsNull() {
		return TypeRef{}
	}
	rid := tok.RID()
	switch tok.Table() {
	case tTypeDef:
		return TypeRef{Namespace: a.rowStr(tTypeDef, rid, 2), Name: a.rowStr(tTypeDef, rid, 1), Token: tok}
	case tTypeRef:
		scope := decodeCoded(ciResolutionScope, a.rowVal(tTypeRef, rid, 0))
		return TypeRef{Scope: a.scopeName(scope), Namespace: a.rowStr(tTypeRef, rid, 2), Name: a.rowStr(tTypeRef, rid, 1), Token: tok}
	case tTypeSpec:
		return TypeRef{IsSpec: true, SpecBlob: a.md.blob(a.rowVal(tTypeSpec, rid, 0)), Token: tok}
	}
	return TypeRef{Token: tok}
}

// Read parses a managed assembly's bytes into the typed model. It never loads the
// assembly into any runtime — it parses bytes only. A malformed PE or metadata
// returns a descriptive error (never a panic); use ReadResult for the batch path
// that needs the degrade-not-fail Assembly{Failed} instead.
func Read(data []byte) (*Assembly, error) {
	pe, err := parsePE(data)
	if err != nil {
		return nil, err
	}
	m, err := parseMetadata(pe)
	if err != nil {
		return nil, err
	}
	return buildModel(pe, m)
}

// ReadResult is the batch-path wrapper: on any parse failure it returns an
// Assembly{Failed:true, FailReason} tagged with name, so the caller records a
// completeness hazard and continues rather than aborting the whole scan.
func ReadResult(name string, data []byte) *Assembly {
	a, err := Read(data)
	if err != nil {
		return &Assembly{Name: name, Failed: true, FailReason: err.Error()}
	}
	if a.Name == "" {
		a.Name = name
	}
	return a
}

// ---- row accessors (bounds-safe; RID is 1-based, rows are 0-based) ----

func (a *Assembly) row(table int, rid uint32) []uint32 {
	rows := a.md.rows[table]
	if rid == 0 || int(rid) > len(rows) {
		return nil
	}
	return rows[rid-1]
}

func (a *Assembly) rowVal(table int, rid uint32, col int) uint32 {
	r := a.row(table, rid)
	if col < 0 || col >= len(r) {
		return 0
	}
	return r[col]
}

func (a *Assembly) rowStr(table int, rid uint32, col int) string {
	return a.md.str(a.rowVal(table, rid, col))
}

// scopeName resolves a ResolutionScope token to the referenced module/assembly name.
// A TypeRef scope (a nested type's enclosing type) resolves to the enclosing type's
// name — an approximation the plan flags for the symbol-norm predecessor to refine.
func (a *Assembly) scopeName(tok Token) string {
	switch tok.Table() {
	case tAssemblyRef:
		return a.rowStr(tAssemblyRef, tok.RID(), 6)
	case tModuleRef:
		return a.rowStr(tModuleRef, tok.RID(), 0)
	case tModule:
		return a.rowStr(tModule, tok.RID(), 1)
	case tTypeRef:
		return a.rowStr(tTypeRef, tok.RID(), 1) // enclosing type name (nested TypeRef)
	}
	return ""
}

func typeDisplay(t TypeRef) string {
	if t.Namespace == "" {
		return t.Name
	}
	return t.Namespace + "." + t.Name
}

// buildModel turns the parsed metadata tables into the typed Assembly model.
func buildModel(pe *peFile, m *mdTables) (*Assembly, error) {
	a := &Assembly{
		Flags:        pe.cli.flags,
		EntryPoint:   pe.cli.entryPoint,
		md:           m,
		methodsByRID: map[uint32]*MethodDef{},
	}

	// Assembly name: prefer the Assembly table, fall back to the Module name.
	if n := m.rowCount[tAssembly]; n >= 1 {
		a.Name = a.rowStr(tAssembly, 1, 7)
	}
	if a.Name == "" && m.rowCount[tModule] >= 1 {
		a.Name = a.rowStr(tModule, 1, 1)
	}

	// MethodDef table → methods, indexed by RID. Ownership by type is wired below.
	nMethods := m.rowCount[tMethodDef]
	methods := make([]*MethodDef, nMethods+1) // 1-indexed
	for rid := uint32(1); rid <= nMethods; rid++ {
		md := &MethodDef{
			RID:          rid,
			Token:        makeToken(tMethodDef, rid),
			RVA:          a.rowVal(tMethodDef, rid, 0),
			ImplFlags:    uint16(a.rowVal(tMethodDef, rid, 1)),
			Flags:        uint16(a.rowVal(tMethodDef, rid, 2)),
			Name:         a.rowStr(tMethodDef, rid, 3),
			SigBlob:      m.blob(a.rowVal(tMethodDef, rid, 4)),
			ParamListRID: a.rowVal(tMethodDef, rid, 5),
		}
		methods[rid] = md
		a.methodsByRID[rid] = md
	}

	// TypeDef table → types; each owns methods [MethodList_i, MethodList_{i+1}).
	nTypes := m.rowCount[tTypeDef]
	a.Types = make([]TypeDef, 0, nTypes)
	for rid := uint32(1); rid <= nTypes; rid++ {
		start := a.rowVal(tTypeDef, rid, 5) // MethodList
		end := nMethods + 1
		if rid < nTypes {
			end = a.rowVal(tTypeDef, rid+1, 5)
		}
		var owned []*MethodDef
		for mr := start; mr < end && mr >= 1 && mr <= nMethods; mr++ {
			owned = append(owned, methods[mr])
		}
		extends := decodeCoded(ciTypeDefOrRef, a.rowVal(tTypeDef, rid, 3))
		a.Types = append(a.Types, TypeDef{
			RID:       rid,
			Token:     makeToken(tTypeDef, rid),
			Flags:     a.rowVal(tTypeDef, rid, 0),
			Name:      a.rowStr(tTypeDef, rid, 1),
			Namespace: a.rowStr(tTypeDef, rid, 2),
			Extends:   a.TypeRefFor(extends),
			Methods:   owned,
		})
	}

	// InterfaceImpl table → attach interfaces to their declaring TypeDef.
	typeByRID := map[uint32]*TypeDef{}
	for i := range a.Types {
		typeByRID[a.Types[i].RID] = &a.Types[i]
	}
	for rid := uint32(1); rid <= m.rowCount[tInterfaceImpl]; rid++ {
		classRID := a.rowVal(tInterfaceImpl, rid, 0)
		ifaceTok := decodeCoded(ciTypeDefOrRef, a.rowVal(tInterfaceImpl, rid, 1))
		if td := typeByRID[classRID]; td != nil {
			td.Interfaces = append(td.Interfaces, a.TypeRefFor(ifaceTok))
		}
	}

	// MemberRef table → call targets, 1-indexed by RID.
	nMember := m.rowCount[tMemberRef]
	a.MemberRefs = make([]MethodRef, nMember+1)
	for rid := uint32(1); rid <= nMember; rid++ {
		parent := decodeCoded(ciMemberRefParent, a.rowVal(tMemberRef, rid, 0))
		tr := a.TypeRefFor(parent)
		a.MemberRefs[rid] = MethodRef{
			RID:         rid,
			Assembly:    tr.Scope,
			Type:        typeDisplay(tr),
			Name:        a.rowStr(tMemberRef, rid, 1),
			SigBlob:     m.blob(a.rowVal(tMemberRef, rid, 2)),
			ParentToken: parent,
		}
	}

	// MethodImpl table → explicit-interface body→declaration slots.
	for rid := uint32(1); rid <= m.rowCount[tMethodImpl]; rid++ {
		a.MethodImpls = append(a.MethodImpls, MethodImpl{
			Class:       makeToken(tTypeDef, a.rowVal(tMethodImpl, rid, 0)),
			Body:        decodeCoded(ciMethodDefOrRef, a.rowVal(tMethodImpl, rid, 1)),
			Declaration: decodeCoded(ciMethodDefOrRef, a.rowVal(tMethodImpl, rid, 2)),
		})
	}

	// NestedClass table.
	for rid := uint32(1); rid <= m.rowCount[tNestedClass]; rid++ {
		a.NestedTypes = append(a.NestedTypes, NestedClass{
			Nested:    makeToken(tTypeDef, a.rowVal(tNestedClass, rid, 0)),
			Enclosing: makeToken(tTypeDef, a.rowVal(tNestedClass, rid, 1)),
		})
	}

	// TypeSpec / MethodSpec tables, 1-indexed by RID.
	nSpec := m.rowCount[tTypeSpec]
	a.TypeSpecs = make([]TypeSpec, nSpec+1)
	for rid := uint32(1); rid <= nSpec; rid++ {
		a.TypeSpecs[rid] = TypeSpec{RID: rid, Blob: m.blob(a.rowVal(tTypeSpec, rid, 0))}
	}
	nMSpec := m.rowCount[tMethodSpec]
	a.MethodSpecs = make([]MethodSpec, nMSpec+1)
	for rid := uint32(1); rid <= nMSpec; rid++ {
		a.MethodSpecs[rid] = MethodSpec{
			RID:               rid,
			Method:            decodeCoded(ciMethodDefOrRef, a.rowVal(tMethodSpec, rid, 0)),
			InstantiationBlob: m.blob(a.rowVal(tMethodSpec, rid, 1)),
		}
	}

	if a.Name == "" {
		return nil, fmt.Errorf("assembly: no Assembly or Module name")
	}
	return a, nil
}
