package assembly

// sigmatch.go — whether a call site's signature can name a declared method.
//
// A signature blob is not portable between assemblies: a class-typed parameter is a
// TypeDef token in the declaring assembly and a TypeRef token in every caller, and an
// override in a generic subclass spells the base's !0 as its concrete argument. Comparing
// blobs byte for byte therefore drops real targets. sigCompatible decodes both sides in
// their own assembly and compares class types by name, treating generic parameters and
// anything it cannot decode as matching: an extra candidate is sound, a dropped one is not.

import "strconv"

const (
	etVoid        = 0x01
	etString      = 0x0E
	etPtr         = 0x0F
	etByRef       = 0x10
	etValueType   = 0x11
	etClass       = 0x12
	etVar         = 0x13
	etArray       = 0x14
	etGenericInst = 0x15
	etTypedByRef  = 0x16
	etI           = 0x18
	etU           = 0x19
	etFnPtr       = 0x1B
	etObject      = 0x1C
	etSzArray     = 0x1D
	etMVar        = 0x1E
	etCmodReqd    = 0x1F
	etCmodOpt     = 0x20
	etSentinel    = 0x41
	etPinned      = 0x45

	sigHasThis = 0x20
	sigGeneric = 0x10
)

// sigType is one decoded signature type. wild marks a type that matches anything: a
// generic parameter, or a shape this decoder does not model.
type sigType struct {
	elem  byte
	name  string // CLASS / VALUETYPE / GENERICINST: the type's namespace-qualified name
	inner []sigType
	wild  bool
}

// methodSigShape is a decoded method signature; ok is false when the blob did not decode.
type methodSigShape struct {
	hasThis  bool
	genArity uint32
	ret      sigType
	params   []sigType
	ok       bool
}

func decodeMethodSigShape(asm *Assembly, blob []byte) methodSigShape {
	r := &reader{b: blob}
	cc := r.u1()
	s := methodSigShape{hasThis: cc&sigHasThis != 0}
	if cc&sigGeneric != 0 {
		s.genArity, _ = r.compressedUint()
	}
	n, ok := r.compressedUint()
	if !ok || r.err != nil || int(n) > len(blob) {
		return methodSigShape{}
	}
	s.ret = decodeSigType(asm, r)
	for i := uint32(0); i < n && r.err == nil; i++ {
		s.params = append(s.params, decodeSigType(asm, r))
	}
	s.ok = r.err == nil
	return s
}

// decodeSigType reads one Param/RetType/Type. Custom modifiers and pinned/sentinel
// markers are skipped; BYREF is kept as a wrapper.
func decodeSigType(asm *Assembly, r *reader) sigType {
	for r.err == nil {
		b := r.u1()
		switch b {
		case etCmodReqd, etCmodOpt:
			r.compressedUint()
			continue
		case etSentinel, etPinned:
			continue
		case etVar, etMVar:
			r.compressedUint()
			return sigType{elem: b, wild: true}
		case etClass, etValueType:
			coded, _ := r.compressedUint()
			return sigType{elem: b, name: sigTypeName(asm, coded)}
		case etGenericInst:
			r.u1() // CLASS or VALUETYPE
			coded, _ := r.compressedUint()
			argc, _ := r.compressedUint()
			t := sigType{elem: b, name: sigTypeName(asm, coded)}
			for i := uint32(0); i < argc && r.err == nil; i++ {
				t.inner = append(t.inner, decodeSigType(asm, r))
			}
			return t
		case etByRef, etSzArray, etPtr:
			return sigType{elem: b, inner: []sigType{decodeSigType(asm, r)}}
		case etArray:
			inner := decodeSigType(asm, r)
			rank, _ := r.compressedUint()
			sizes, _ := r.compressedUint()
			for i := uint32(0); i < sizes && r.err == nil; i++ {
				r.compressedUint()
			}
			los, _ := r.compressedUint()
			for i := uint32(0); i < los && r.err == nil; i++ {
				r.compressedUint()
			}
			return sigType{elem: b, name: strconv.FormatUint(uint64(rank), 10), inner: []sigType{inner}}
		case etFnPtr:
			r.fail("assembly: function pointer in signature")
			return sigType{wild: true}
		default:
			if b >= etVoid && b <= etTypedByRef || b == etI || b == etU || b == etObject {
				return sigType{elem: b}
			}
			r.fail("assembly: unknown element type 0x%x", b)
			return sigType{wild: true}
		}
	}
	return sigType{wild: true}
}

// sigTypeName renders a TypeDefOrRef coded value by namespace and name, without the
// resolution scope: type forwarding moves a type's assembly but not its name.
func sigTypeName(asm *Assembly, coded uint32) string {
	tok := decodeCoded(ciTypeDefOrRef, coded)
	tr := asm.TypeRefFor(tok)
	if tr.IsSpec || tr.Name == "" {
		return ""
	}
	return typeDisplay(tr)
}

func (a sigType) matches(b sigType) bool {
	if a.wild || b.wild {
		return true
	}
	if a.elem != b.elem {
		return false
	}
	if a.name != b.name && a.name != "" && b.name != "" {
		return false
	}
	if len(a.inner) != len(b.inner) {
		return false
	}
	for i := range a.inner {
		if !a.inner[i].matches(b.inner[i]) {
			return false
		}
	}
	return true
}

// sigCompatible reports whether the signature sigA (read in asmA) can name the method
// whose signature is sigB (read in asmB), as a virtual call names an override. Calling
// convention, generic arity and parameter count must agree, and parameter types must agree
// by name where both sides are concrete. Return types are not compared: a covariant
// override returns a narrower type. A blob that does not decode is compatible with
// anything.
func sigCompatible(asmA *Assembly, sigA []byte, asmB *Assembly, sigB []byte) bool {
	return sigMatch(asmA, sigA, asmB, sigB, false)
}

// sigExact is sigCompatible for a direct bind (call, newobj, ldftn), where the call site
// names one declared method and its return type is part of that name: overloads that
// differ only in return type (op_Explicit, op_Implicit) are told apart.
func sigExact(asmA *Assembly, sigA []byte, asmB *Assembly, sigB []byte) bool {
	return sigMatch(asmA, sigA, asmB, sigB, true)
}

func sigMatch(asmA *Assembly, sigA []byte, asmB *Assembly, sigB []byte, withReturn bool) bool {
	if asmA == asmB && bytesEqual(sigA, sigB) {
		return true
	}
	a, b := decodeMethodSigShape(asmA, sigA), decodeMethodSigShape(asmB, sigB)
	if !a.ok || !b.ok {
		return true
	}
	if a.hasThis != b.hasThis || a.genArity != b.genArity || len(a.params) != len(b.params) {
		return false
	}
	if withReturn && !a.ret.matches(b.ret) {
		return false
	}
	for i := range a.params {
		if !a.params[i].matches(b.params[i]) {
			return false
		}
	}
	return true
}
