// Package depreach builds the .NET whole-program reachability layer over the parsed
// assembly model and answers the two-trace proof-of-non-exploitability the free
// Assess tier rests on. This file is barrier-2's first half: the ECMA-335 §II.23.2
// signature-blob decoder (so sinks match by signature, not by name) plus the
// reference-type parameter extraction the re-entry hazard rule reads. The verdict
// engine, two-trace/.cctor/hazard logic, and edge production live in sibling files.
package depreach

import (
	"fmt"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// ELEMENT_TYPE_* codes (ECMA-335 §II.23.1.16).
const (
	etEnd         byte = 0x00
	etVoid        byte = 0x01
	etBool        byte = 0x02
	etChar        byte = 0x03
	etI1          byte = 0x04
	etU1          byte = 0x05
	etI2          byte = 0x06
	etU2          byte = 0x07
	etI4          byte = 0x08
	etU4          byte = 0x09
	etI8          byte = 0x0A
	etU8          byte = 0x0B
	etR4          byte = 0x0C
	etR8          byte = 0x0D
	etString      byte = 0x0E
	etPtr         byte = 0x0F
	etByRef       byte = 0x10
	etValueType   byte = 0x11
	etClass       byte = 0x12
	etVar         byte = 0x13
	etArray       byte = 0x14
	etGenericInst byte = 0x15
	etTypedByRef  byte = 0x16
	etI           byte = 0x18
	etU           byte = 0x19
	etFnPtr       byte = 0x1B
	etObject      byte = 0x1C
	etSzArray     byte = 0x1D
	etMVar        byte = 0x1E
	etCmodReqd    byte = 0x1F
	etCmodOpt     byte = 0x20
	etSentinel    byte = 0x41
	etPinned      byte = 0x45
)

// Signature calling-convention flags (ECMA-335 §II.23.2.3).
const (
	ccDefault  byte = 0x00
	ccVararg   byte = 0x05
	ccGeneric  byte = 0x10 // GENERIC bit (a compressed GenParamCount follows)
	ccHasThis  byte = 0x20
	ccExplicit byte = 0x40
)

// TypeResolver resolves an embedded TypeDefOrRef(OrSpec) token from a signature blob
// to the assembly's uniform TypeRef view. *assembly.Assembly satisfies it; tests pass
// a hand-authored fake so signature decoding is exercised without a real assembly.
type TypeResolver interface {
	TypeRefFor(tok assembly.Token) assembly.TypeRef
}

// RefParam is one reference-type parameter surfaced for the re-entry hazard rule: a
// parameter whose type an in-set application type could implement is a callback an
// out-of-set method may invoke, re-entering application code from a leaf the CHA
// graph does not traverse (the .NET analog of cobalt's parseParamRefTypes). Ref is
// the resolved TypeDefOrRef for CLASS/GENERICINST params; its Token is null for the
// intrinsic reference types (string/object) that carry no token in the blob.
type RefParam struct {
	Name string           // canonical type name for stable comparison/diagnostics
	Ref  assembly.TypeRef // resolved TypeDefOrRef (zero Token for string/object)
}

// TypeSig is a decoded signature Type (ECMA-335 §II.23.2.12). It is deliberately a
// small tree: enough to render a stable key and to classify reference-type params,
// not a full type model.
type TypeSig struct {
	Elem     byte             // ELEMENT_TYPE code after stripping a leading BYREF
	ByRef    bool             // parameter/return passed by reference
	Token    assembly.Token   // CLASS/VALUETYPE and GENERICINST base type token
	Ref      assembly.TypeRef // resolved Token
	Inner    *TypeSig         // SZARRAY/ARRAY/PTR element type
	Args     []TypeSig        // GENERICINST type arguments
	VarIdx   uint32           // VAR/MVAR index
	Rank     uint32           // ARRAY rank (>=1)
	BaseElem byte             // GENERICINST: CLASS(0x12) or VALUETYPE(0x11)
}

// MethodSignature is a decoded MethodDefSig/StandAloneMethodSig (§II.23.2.1/.3). The
// engine matches sinks on SignatureKey and reads RefParams for the re-entry rule.
// Malformed is the hazard signal: a blob that could not be fully decoded degrades to
// a conservative descriptor (Malformed=true, a non-nil error from DecodeMethodSig),
// never a confident empty parameter list.
type MethodSignature struct {
	HasThis       bool
	ExplicitThis  bool
	CallKind      string // "default" | "vararg" | "c" | "stdcall" | ...
	Generic       bool
	GenParamCount uint32
	Return        TypeSig
	Params        []TypeSig
	RefParams     []RefParam
	Malformed     bool
}

// sigReader is a bounds-checked cursor over a signature blob. Every read checks the
// remaining length before indexing, so the decoder never panics on a truncated or
// malformed blob — it latches the first error and the caller degrades to a hazard.
type sigReader struct {
	b   []byte
	pos int
	err error
}

func (r *sigReader) fail(what string) {
	if r.err == nil {
		r.err = fmt.Errorf("signature: %s at offset %d (len %d)", what, r.pos, len(r.b))
	}
}

func (r *sigReader) byte() (byte, bool) {
	if r.err != nil || r.pos >= len(r.b) {
		r.fail("truncated byte")
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

func (r *sigReader) peek() (byte, bool) {
	if r.err != nil || r.pos >= len(r.b) {
		return 0, false
	}
	return r.b[r.pos], true
}

// compressedUint decodes a compressed unsigned integer (§II.23.2): 1/2/4 bytes
// selected by the high bits of the first byte.
func (r *sigReader) compressedUint() (uint32, bool) {
	b0, ok := r.byte()
	if !ok {
		return 0, false
	}
	switch {
	case b0&0x80 == 0: // 0b0xxxxxxx — 1 byte
		return uint32(b0), true
	case b0&0xC0 == 0x80: // 0b10xxxxxx — 2 bytes
		b1, ok := r.byte()
		if !ok {
			return 0, false
		}
		return uint32(b0&0x3F)<<8 | uint32(b1), true
	case b0&0xE0 == 0xC0: // 0b110xxxxx — 4 bytes
		b1, ok1 := r.byte()
		b2, ok2 := r.byte()
		b3, ok3 := r.byte()
		if !ok1 || !ok2 || !ok3 {
			return 0, false
		}
		return uint32(b0&0x1F)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3), true
	default:
		r.fail("invalid compressed-int prefix")
		return 0, false
	}
}

// ReadCompressedUint decodes one compressed unsigned integer from the front of b,
// returning the value and the number of bytes consumed. Exported for round-trip
// tests over the 1/2/4-byte width forms.
func ReadCompressedUint(b []byte) (value uint32, n int, err error) {
	r := &sigReader{b: b}
	v, ok := r.compressedUint()
	if !ok {
		return 0, r.pos, r.err
	}
	return v, r.pos, nil
}

// decodeTypeDefOrRef decodes a TypeDefOrRefOrSpecEncoded token (§II.23.2.8): the low
// two bits are the tag (0=TypeDef, 1=TypeRef, 2=TypeSpec), the rest the RID. This is
// the signature-blob coded index, distinct from the metadata-table coded indexes, so
// it is decoded here rather than reusing the assembly package's table decoder.
func decodeTypeDefOrRef(coded uint32) assembly.Token {
	rid := (coded >> 2) & 0x00FFFFFF
	var table uint32
	switch coded & 0x3 {
	case 0:
		table = 0x02 // TypeDef
	case 1:
		table = 0x01 // TypeRef
	case 2:
		table = 0x1B // TypeSpec
	default:
		return 0
	}
	return assembly.Token(table<<24 | rid)
}

func callKindName(k byte) string {
	switch k {
	case ccDefault:
		return "default"
	case 0x01:
		return "c"
	case 0x02:
		return "stdcall"
	case 0x03:
		return "thiscall"
	case 0x04:
		return "fastcall"
	case ccVararg:
		return "vararg"
	default:
		return fmt.Sprintf("cc#0x%x", k)
	}
}

// DecodeMethodSig decodes a MethodDefSig/StandAloneMethodSig blob. res may be nil, in
// which case CLASS/VALUETYPE tokens are left unresolved (names render from the token).
// A truncated or undecodable blob returns a partial descriptor with Malformed=true and
// a non-nil error; it never panics.
func DecodeMethodSig(blob []byte, res TypeResolver) (MethodSignature, error) {
	var sig MethodSignature
	if len(blob) == 0 {
		sig.Malformed = true
		return sig, fmt.Errorf("signature: empty blob")
	}
	r := &sigReader{b: blob}

	cc, _ := r.byte()
	sig.HasThis = cc&ccHasThis != 0
	sig.ExplicitThis = cc&ccExplicit != 0
	sig.Generic = cc&ccGeneric != 0
	sig.CallKind = callKindName(cc & 0x0F)

	if sig.Generic {
		sig.GenParamCount, _ = r.compressedUint()
	}
	paramCount, _ := r.compressedUint()

	sig.Return = r.retOrParam(res)
	for i := uint32(0); i < paramCount && r.err == nil; i++ {
		p := r.retOrParam(res)
		sig.Params = append(sig.Params, p)
		collectRefParams(&sig.RefParams, p, res)
	}

	if r.err != nil {
		sig.Malformed = true
		return sig, r.err
	}
	return sig, nil
}

// skipPrefixes consumes leading custom modifiers and SENTINEL/PINNED prefixes that may
// precede a Type in a Param/RetType.
func (r *sigReader) skipPrefixes() {
	for r.err == nil {
		b, ok := r.peek()
		if !ok {
			return
		}
		switch b {
		case etCmodOpt, etCmodReqd:
			r.byte()           // the modifier byte
			r.compressedUint() // its TypeDefOrRefOrSpec token
		case etSentinel, etPinned:
			r.byte()
		default:
			return
		}
	}
}

// retOrParam decodes a RetType/Param: custom mods, an optional BYREF, then a Type
// (VOID and TYPEDBYREF are handled as ordinary element types by typeSig).
func (r *sigReader) retOrParam(res TypeResolver) TypeSig {
	r.skipPrefixes()
	var byref bool
	if b, ok := r.peek(); ok && b == etByRef {
		r.byte()
		byref = true
	}
	t := r.typeSig(res)
	t.ByRef = byref
	return t
}

// typeSig decodes one Type (§II.23.2.12).
func (r *sigReader) typeSig(res TypeResolver) TypeSig {
	et, ok := r.byte()
	if !ok {
		return TypeSig{}
	}
	t := TypeSig{Elem: et}
	switch et {
	case etVoid, etBool, etChar, etI1, etU1, etI2, etU2, etI4, etU4,
		etI8, etU8, etR4, etR8, etString, etI, etU, etObject, etTypedByRef:
		// leaf primitive / intrinsic reference type
	case etClass, etValueType:
		coded, _ := r.compressedUint()
		t.Token = decodeTypeDefOrRef(coded)
		if res != nil {
			t.Ref = res.TypeRefFor(t.Token)
		}
	case etVar, etMVar:
		t.VarIdx, _ = r.compressedUint()
	case etSzArray:
		r.skipPrefixes()
		inner := r.typeSig(res)
		t.Inner = &inner
	case etArray:
		inner := r.typeSig(res)
		t.Inner = &inner
		r.arrayShape(&t)
	case etGenericInst:
		base, _ := r.byte() // CLASS or VALUETYPE
		t.BaseElem = base
		coded, _ := r.compressedUint()
		t.Token = decodeTypeDefOrRef(coded)
		if res != nil {
			t.Ref = res.TypeRefFor(t.Token)
		}
		argc, _ := r.compressedUint()
		for i := uint32(0); i < argc && r.err == nil; i++ {
			t.Args = append(t.Args, r.typeSig(res))
		}
	case etPtr:
		r.skipPrefixes()
		inner := r.typeSig(res)
		t.Inner = &inner
	case etFnPtr:
		// Function pointers embed a full MethodDefSig/MethodRefSig; decoding it is
		// deferred. Latch a hazard rather than risk desyncing the cursor.
		r.fail("FNPTR deferred")
	default:
		r.fail(fmt.Sprintf("unknown element type 0x%x", et))
	}
	return t
}

// arrayShape consumes an ArrayShape (§II.23.2.13): Rank NumSizes Size* NumLoBounds
// LoBound*. Only Rank is retained; sizes/lobounds are consumed to keep the cursor
// aligned.
func (r *sigReader) arrayShape(t *TypeSig) {
	t.Rank, _ = r.compressedUint()
	numSizes, _ := r.compressedUint()
	for i := uint32(0); i < numSizes && r.err == nil; i++ {
		r.compressedUint()
	}
	numLo, _ := r.compressedUint()
	for i := uint32(0); i < numLo && r.err == nil; i++ {
		r.compressedUint()
	}
}

// collectRefParams appends the reference-type parameters of t to out: STRING, OBJECT,
// CLASS, GENERICINST-of-CLASS, and the reference element types of array parameters.
// Primitive and valuetype parameters (and the return type, which is never passed here)
// are ignored — the direct analog of cobalt's parseParamRefTypes.
func collectRefParams(out *[]RefParam, t TypeSig, res TypeResolver) {
	switch t.Elem {
	case etString:
		*out = append(*out, RefParam{Name: "System.String"})
	case etObject:
		*out = append(*out, RefParam{Name: "System.Object"})
	case etClass:
		*out = append(*out, RefParam{Name: typeName(t.Ref, t.Token), Ref: t.Ref})
	case etGenericInst:
		if t.BaseElem == etClass {
			*out = append(*out, RefParam{Name: typeName(t.Ref, t.Token), Ref: t.Ref})
		}
	case etSzArray, etArray:
		if t.Inner != nil {
			collectRefParams(out, *t.Inner, res)
		}
	}
}

// typeName renders a stable name for a resolved-or-raw type token.
func typeName(ref assembly.TypeRef, tok assembly.Token) string {
	if ref.Name != "" {
		if ref.Namespace != "" {
			return ref.Namespace + "." + ref.Name
		}
		return ref.Name
	}
	if ref.IsSpec || (!tok.IsNull() && tok.Table() == 0x1B) {
		return fmt.Sprintf("typespec#%d", tok.RID())
	}
	if tok.IsNull() {
		return "?"
	}
	return fmt.Sprintf("token:%d/%d", tok.Table(), tok.RID())
}

// SignatureKey renders a stable, comparable descriptor: calling convention (kind +
// hasthis + generic arity), then the return type, then the parameter types. Sink
// equality keys on this string, so the match is by signature — the blob carries no
// method name, and two methods with the same signature produce the same key.
func (s MethodSignature) SignatureKey() string {
	var b strings.Builder
	b.WriteString(s.CallKind)
	if s.HasThis {
		b.WriteString("+hasthis")
	}
	if s.Generic {
		fmt.Fprintf(&b, "+g%d", s.GenParamCount)
	}
	b.WriteByte('|')
	b.WriteString(typeKey(s.Return))
	b.WriteByte('|')
	for i, p := range s.Params {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(typeKey(p))
	}
	return b.String()
}

// typeKey renders one TypeSig canonically for SignatureKey.
func typeKey(t TypeSig) string {
	var s string
	switch t.Elem {
	case etVoid:
		s = "void"
	case etBool:
		s = "bool"
	case etChar:
		s = "char"
	case etI1:
		s = "i1"
	case etU1:
		s = "u1"
	case etI2:
		s = "i2"
	case etU2:
		s = "u2"
	case etI4:
		s = "i4"
	case etU4:
		s = "u4"
	case etI8:
		s = "i8"
	case etU8:
		s = "u8"
	case etR4:
		s = "r4"
	case etR8:
		s = "r8"
	case etI:
		s = "i"
	case etU:
		s = "u"
	case etString:
		s = "string"
	case etObject:
		s = "object"
	case etTypedByRef:
		s = "typedbyref"
	case etClass:
		s = "class:" + typeName(t.Ref, t.Token)
	case etValueType:
		s = "valuetype:" + typeName(t.Ref, t.Token)
	case etVar:
		s = fmt.Sprintf("!%d", t.VarIdx)
	case etMVar:
		s = fmt.Sprintf("!!%d", t.VarIdx)
	case etSzArray:
		s = innerKey(t.Inner) + "[]"
	case etArray:
		rank := int(t.Rank)
		if rank < 1 {
			rank = 1
		}
		s = innerKey(t.Inner) + "[" + strings.Repeat(",", rank-1) + "]"
	case etPtr:
		s = innerKey(t.Inner) + "*"
	case etGenericInst:
		base := "class"
		if t.BaseElem == etValueType {
			base = "valuetype"
		}
		args := make([]string, len(t.Args))
		for i, a := range t.Args {
			args[i] = typeKey(a)
		}
		s = fmt.Sprintf("%s:%s<%s>", base, typeName(t.Ref, t.Token), strings.Join(args, ","))
	default:
		s = fmt.Sprintf("et#0x%x", t.Elem)
	}
	if t.ByRef {
		s = "&" + s
	}
	return s
}

func innerKey(t *TypeSig) string {
	if t == nil {
		return "?"
	}
	return typeKey(*t)
}
