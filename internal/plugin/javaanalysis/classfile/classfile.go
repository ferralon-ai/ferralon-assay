// Package classfile is a pure-Go, stdlib-only parser for JVM .class bytecode
// (JVMS §4), extracting the call edges an Assess-tier dependency-reachability
// analysis needs. No JVM, no scip-java, no cgo: the analyzer reads the customer's
// already-cached dependency bytecode and never executes it.
//
// It is deliberately defensive. The input is third-party dependency bytecode —
// possibly obfuscated, truncated, or hostile — so no parse path panics: every read
// is bounds-checked and a malformed class returns an error, never a crash and never
// a silently-wrong graph. A class that fails to parse is a completeness hazard for
// the caller to declare, not a false "nothing here".
package classfile

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Constant-pool tags (JVMS §4.4).
const (
	cpUtf8               = 1
	cpInteger            = 3
	cpFloat              = 4
	cpLong               = 5
	cpDouble             = 6
	cpClass              = 7
	cpString             = 8
	cpFieldref           = 9
	cpMethodref          = 10
	cpInterfaceMethodref = 11
	cpNameAndType        = 12
	cpMethodHandle       = 15
	cpMethodType         = 16
	cpDynamic            = 17
	cpInvokeDynamic      = 18
	cpModule             = 19
	cpPackage            = 20
)

// Method access flags (JVMS §4.6) we care about for graph soundness.
const (
	accNative   = 0x0100
	accAbstract = 0x0400
)

// MethodRef is a resolved call target (or declared method), named the way the JVM
// names it: internal owner class, method name, and JVM descriptor. Identity is all
// three — descriptor, not arity, distinguishes same-name same-arity overloads.
type MethodRef struct {
	Owner      string // internal class name, e.g. "com/example/net/UrlFetcher"
	Name       string // method name, e.g. "fetch" or "<init>"
	Descriptor string // JVM descriptor, e.g. "(Ljava/lang/String;)Ljava/lang/String;"
}

func (m MethodRef) String() string { return m.Owner + "." + m.Name + m.Descriptor }

// EdgeKind records how a call site dispatches — the axis that decides whether an
// edge is statically resolvable (special/static) or needs class-hierarchy analysis
// (virtual/interface) or is a completeness hazard (dynamic).
type EdgeKind int

const (
	EdgeStatic    EdgeKind = iota // invokestatic
	EdgeSpecial                   // invokespecial (ctor/super/private): exact target
	EdgeVirtual                   // invokevirtual: CHA over subtypes
	EdgeInterface                 // invokeinterface: CHA over implementors
	EdgeDynamic                   // invokedynamic: bootstrap-resolved; the static graph cannot see the real target
)

func (k EdgeKind) String() string {
	switch k {
	case EdgeStatic:
		return "static"
	case EdgeSpecial:
		return "special"
	case EdgeVirtual:
		return "virtual"
	case EdgeInterface:
		return "interface"
	case EdgeDynamic:
		return "dynamic"
	}
	return "?"
}

// Edge is one call site: the referenced callee and its dispatch kind. For a
// dynamic edge the callee Owner is "" — the real target is bootstrap-decided and
// invisible to a static graph, which is why the caller must treat it as a hazard.
type Edge struct {
	To   MethodRef
	Kind EdgeKind
}

// Method is a declared method with its extracted call edges. Native and Abstract
// methods have no Code attribute (no bytecode body); the caller treats a call into
// a native method as an un-traversable leaf.
type Method struct {
	Ref      MethodRef
	Native   bool
	Abstract bool
	Edges    []Edge
	// InitTriggers are the internal names of classes whose static initializer
	// (<clinit>) this method's bytecode triggers — via new / getstatic / putstatic /
	// invokestatic (JVMS §5.5). <clinit> is never an explicit invoke target, so a
	// caller building a call graph must add an edge into each triggered class's
	// <clinit> or a sink reachable only through static initialization is invisible.
	InitTriggers []string
	// Annotations are the method's RuntimeVisibleAnnotations (JVMS §4.7.16), decoded
	// to their type descriptors plus string-valued element pairs. Populated only when
	// the attribute is present; framework-ingress detection (e.g. Spring @GetMapping)
	// reads it. Never a source of edges — advisory metadata only.
	Annotations []Annotation
}

// Class is one parsed .class: its own internal name, its superclass and directly
// implemented interfaces (the CHA hierarchy inputs), and its methods.
type Class struct {
	Name       string
	Super      string
	Interfaces []string
	Methods    []Method
	// Annotations are the class's RuntimeVisibleAnnotations (JVMS §4.7.16), decoded
	// the same way as Method.Annotations. Populated only when present; the class-level
	// stereotype markers a framework-ingress layer needs (e.g. Spring @RestController)
	// live here.
	Annotations []Annotation
}

// Annotation is one decoded RuntimeVisibleAnnotations entry: the annotation type as a
// JVM field descriptor (e.g. "Lorg/springframework/web/bind/annotation/RestController;")
// and any string-valued element pairs (e.g. a route path). Only string element values
// are retained — the framework-ingress layer needs the type and an optional route path,
// nothing more; non-string values are traversed only to keep the parser in sync.
type Annotation struct {
	Type     string
	Elements []AnnotationElement // string-valued element pairs, in file order (deterministic)
}

// AnnotationElement is one decoded string-valued element pair of an annotation, e.g.
// Name="value", Value="/users". The Elements slice preserves file order so encode paths
// stay deterministic (no map iteration).
type AnnotationElement struct {
	Name  string
	Value string
}

// attrRuntimeVisibleAnnotations is the JVMS §4.7.16 attribute name carrying the
// class/method annotations the framework-ingress layer reads.
const attrRuntimeVisibleAnnotations = "RuntimeVisibleAnnotations"

// ErrBadMagic is returned when the input does not begin with the 0xCAFEBABE magic —
// most commonly a non-class JAR entry the caller should skip, not fail on.
var ErrBadMagic = errors.New("classfile: bad magic (not a .class)")

// cpEntry is one constant-pool slot. Only the fields the edge extractor needs are
// retained; unused structured constants keep just their tag.
type cpEntry struct {
	tag   uint8
	utf8  string
	ref1  uint16 // class_index / name_index / reference_index
	ref2  uint16 // name_and_type_index / descriptor_index
	valid bool
}

type constPool []cpEntry

// reader is a bounds-checked big-endian cursor. On the first short read it records
// err and every subsequent read is a no-op returning zero, so callers can decode a
// whole structure and check err once at the boundary — no panics, no per-read error
// threading (JVMS §4 structures are deeply nested).
type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, args...)
	}
}

func (r *reader) has(n int) bool {
	if r.err != nil {
		return false
	}
	if r.pos+n > len(r.b) {
		r.fail("classfile: truncated: want %d bytes at offset %d of %d", n, r.pos, len(r.b))
		return false
	}
	return true
}

func (r *reader) u1() uint8 {
	if !r.has(1) {
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u2() uint16 {
	if !r.has(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *reader) u4() uint32 {
	if !r.has(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *reader) skip(n int) {
	if n < 0 {
		r.fail("classfile: negative skip %d", n)
		return
	}
	if !r.has(n) {
		return
	}
	r.pos += n
}

func (r *reader) bytes(n int) []byte {
	if n < 0 {
		r.fail("classfile: negative length %d", n)
		return nil
	}
	if !r.has(n) {
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

// at safely returns the constant-pool entry at idx, reporting whether it is a valid
// in-range slot. All cross-references between constants route through it so a
// corrupt index yields an error rather than an out-of-range panic.
func (cp constPool) at(idx uint16) (cpEntry, bool) {
	if int(idx) <= 0 || int(idx) >= len(cp) || !cp[idx].valid {
		return cpEntry{}, false
	}
	return cp[idx], true
}

// utf8 resolves a Utf8 constant by index, "" if absent or wrong tag.
func (cp constPool) utf8(idx uint16) string {
	if e, ok := cp.at(idx); ok && e.tag == cpUtf8 {
		return e.utf8
	}
	return ""
}

// className resolves a Class constant to its internal name, "" for index 0 (the
// absent-superclass case for java/lang/Object) or a malformed entry.
func (cp constPool) className(idx uint16) string {
	if idx == 0 {
		return ""
	}
	if e, ok := cp.at(idx); ok && e.tag == cpClass {
		return cp.utf8(e.ref1)
	}
	return ""
}

// fieldOwner resolves a Fieldref constant to the internal name of the class that
// declares the field — the class whose <clinit> a getstatic/putstatic triggers.
func (cp constPool) fieldOwner(idx uint16) string {
	if e, ok := cp.at(idx); ok && e.tag == cpFieldref {
		return cp.className(e.ref1)
	}
	return ""
}

// ParseClass parses one .class file into a Class with per-method call edges. It
// never panics: a bad magic returns ErrBadMagic (caller skips), any other
// structural fault returns a descriptive error (caller declares a hazard).
func ParseClass(data []byte) (Class, error) {
	r := &reader{b: data}
	if r.u4() != 0xCAFEBABE {
		return Class{}, ErrBadMagic
	}
	r.u2() // minor_version
	r.u2() // major_version
	cp, err := parseConstPool(r)
	if err != nil {
		return Class{}, err
	}

	r.u2() // access_flags
	thisClass := cp.className(r.u2())
	superClass := cp.className(r.u2())

	ifaceCount := int(r.u2())
	ifaces := make([]string, 0, ifaceCount)
	for i := 0; i < ifaceCount; i++ {
		ifaces = append(ifaces, cp.className(r.u2()))
		if r.err != nil {
			return Class{}, r.err
		}
	}

	// fields — skipped; a field carries no call edges.
	fieldCount := int(r.u2())
	for i := 0; i < fieldCount; i++ {
		r.u2() // access_flags
		r.u2() // name_index
		r.u2() // descriptor_index
		skipAttributes(r)
		if r.err != nil {
			return Class{}, r.err
		}
	}

	methodCount := int(r.u2())
	methods := make([]Method, 0, methodCount)
	for i := 0; i < methodCount; i++ {
		acc := r.u2()
		name := cp.utf8(r.u2())
		desc := cp.utf8(r.u2())
		m := Method{
			Ref:      MethodRef{Owner: thisClass, Name: name, Descriptor: desc},
			Native:   acc&accNative != 0,
			Abstract: acc&accAbstract != 0,
		}
		attrCount := int(r.u2())
		for a := 0; a < attrCount; a++ {
			attrName := cp.utf8(r.u2())
			attrLen := int(r.u4())
			body := r.bytes(attrLen)
			if r.err != nil {
				return Class{}, r.err
			}
			if attrName == "Code" {
				edges, triggers, err := parseCode(body, cp)
				if err != nil {
					return Class{}, fmt.Errorf("classfile: %s%s Code: %w", name, desc, err)
				}
				m.Edges = edges
				m.InitTriggers = triggers
			}
			if attrName == attrRuntimeVisibleAnnotations {
				annos, err := parseAnnotations(cp, body)
				if err != nil {
					return Class{}, fmt.Errorf("classfile: %s%s annotations: %w", name, desc, err)
				}
				m.Annotations = annos
			}
		}
		methods = append(methods, m)
		if r.err != nil {
			return Class{}, r.err
		}
	}

	if r.err != nil {
		return Class{}, r.err
	}
	if thisClass == "" {
		return Class{}, errors.New("classfile: missing this_class name")
	}

	// Class-level attributes table. Previously unread (the edge graph needs nothing
	// past the methods); it is now walked only to decode the class's
	// RuntimeVisibleAnnotations — every other attribute is skipped by length exactly as
	// before, so a class carrying no annotations parses identically.
	classAnnos, err := parseClassAnnotations(r, cp)
	if err != nil {
		return Class{}, err
	}

	return Class{Name: thisClass, Super: superClass, Interfaces: ifaces, Methods: methods, Annotations: classAnnos}, nil
}

// parseClassAnnotations walks the class-level attributes table (which begins at r's
// current position) and returns any RuntimeVisibleAnnotations found. A truncated table
// or a malformed annotation body is a completeness hazard, not a panic: it surfaces as
// an error so the caller records the class as Failed (declared partiality), never a
// silently-dropped annotation. Non-annotation attributes are skipped by length.
func parseClassAnnotations(r *reader, cp constPool) ([]Annotation, error) {
	n := int(r.u2())
	var annos []Annotation
	for i := 0; i < n; i++ {
		attrName := cp.utf8(r.u2())
		attrLen := int(r.u4())
		body := r.bytes(attrLen)
		if r.err != nil {
			return nil, r.err
		}
		if attrName == attrRuntimeVisibleAnnotations {
			a, err := parseAnnotations(cp, body)
			if err != nil {
				return nil, fmt.Errorf("classfile: class annotations: %w", err)
			}
			annos = append(annos, a...)
		}
	}
	return annos, nil
}

// parseAnnotations decodes a RuntimeVisibleAnnotations attribute body (JVMS §4.7.16)
// into annotation type descriptors and their string-valued element pairs. It runs over a
// SUB-READER of just the attribute body, so a malformed table cannot desync the enclosing
// class parse; a short read is reported as an error (the caller turns it into a declared
// hazard). Non-string element values are traversed but not retained.
func parseAnnotations(cp constPool, body []byte) ([]Annotation, error) {
	br := &reader{b: body}
	n := int(br.u2())
	annos := make([]Annotation, 0, n)
	for i := 0; i < n; i++ {
		a := parseOneAnnotation(br, cp)
		if br.err != nil {
			return nil, br.err
		}
		annos = append(annos, a)
	}
	return annos, nil
}

// parseOneAnnotation decodes a single annotation structure: its type descriptor followed
// by the element-value pairs. String-valued elements are captured; all other value kinds
// are traversed only to advance the cursor. Errors surface via br.err.
func parseOneAnnotation(br *reader, cp constPool) Annotation {
	typeIdx := br.u2()
	numPairs := int(br.u2())
	a := Annotation{Type: cp.utf8(typeIdx)}
	for p := 0; p < numPairs; p++ {
		nameIdx := br.u2()
		val, hasStr := parseElementValue(br, cp)
		if br.err != nil {
			return a
		}
		if hasStr {
			a.Elements = append(a.Elements, AnnotationElement{Name: cp.utf8(nameIdx), Value: val})
		}
	}
	return a
}

// parseElementValue traverses one element_value (JVMS §4.7.16.1). It returns a decoded
// string when the value — or the first element of a string array — is a string constant;
// every tag is handled so the cursor advances correctly, and an unknown tag fails the
// sub-reader (a malformed table the caller declares).
func parseElementValue(br *reader, cp constPool) (string, bool) {
	switch tag := br.u1(); tag {
	case 's': // String constant
		return cp.utf8(br.u2()), true
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z': // primitive constant
		br.u2()
		return "", false
	case 'e': // enum: type_name_index, const_name_index
		br.u2()
		br.u2()
		return "", false
	case 'c': // class_info_index
		br.u2()
		return "", false
	case '@': // nested annotation
		parseOneAnnotation(br, cp)
		return "", false
	case '[': // array: capture the first string element, if any
		num := int(br.u2())
		var first string
		var has bool
		for i := 0; i < num; i++ {
			s, ok := parseElementValue(br, cp)
			if br.err != nil {
				break
			}
			if ok && !has {
				first, has = s, true
			}
		}
		return first, has
	default:
		br.fail("classfile: unknown annotation element tag %d", tag)
		return "", false
	}
}

// parseConstPool decodes the 1-indexed constant pool. Long and Double each occupy
// two slots (JVMS §4.4.5). An unknown tag is an error, not a panic — the input is
// untrusted.
func parseConstPool(r *reader) (constPool, error) {
	count := int(r.u2())
	if count < 1 {
		return nil, fmt.Errorf("classfile: constant_pool_count %d < 1", count)
	}
	cp := make(constPool, count) // slot 0 is unused (the pool is 1-indexed)
	for i := 1; i < count; i++ {
		tag := r.u1()
		e := cpEntry{tag: tag, valid: true}
		switch tag {
		case cpUtf8:
			n := int(r.u2())
			e.utf8 = string(r.bytes(n))
		case cpInteger, cpFloat:
			r.u4()
		case cpLong, cpDouble:
			r.u4()
			r.u4()
		case cpClass, cpString, cpMethodType, cpModule, cpPackage:
			e.ref1 = r.u2()
		case cpFieldref, cpMethodref, cpInterfaceMethodref, cpNameAndType, cpDynamic, cpInvokeDynamic:
			e.ref1 = r.u2()
			e.ref2 = r.u2()
		case cpMethodHandle:
			r.u1() // reference_kind
			e.ref1 = r.u2()
		default:
			return nil, fmt.Errorf("classfile: unknown constant pool tag %d at slot %d", tag, i)
		}
		if r.err != nil {
			return nil, r.err
		}
		cp[i] = e
		if tag == cpLong || tag == cpDouble {
			i++ // the next slot is unusable
		}
	}
	return cp, nil
}

// skipAttributes advances past an attributes table (used for fields and the class).
func skipAttributes(r *reader) {
	n := int(r.u2())
	for i := 0; i < n; i++ {
		r.u2()           // attribute_name_index
		l := int(r.u4()) // attribute_length
		r.skip(l)
		if r.err != nil {
			return
		}
	}
}

// resolveMethodRef turns a Methodref/InterfaceMethodref/InvokeDynamic constant into
// a MethodRef. For invokedynamic/dynamic the owner is "" — the real target is
// decided by a bootstrap method the static graph cannot follow, so the caller
// treats the edge as a completeness hazard rather than a resolved call. ok is false
// for any other constant kind or a corrupt index.
func resolveMethodRef(cp constPool, idx uint16) (MethodRef, bool) {
	e, ok := cp.at(idx)
	if !ok {
		return MethodRef{}, false
	}
	switch e.tag {
	case cpMethodref, cpInterfaceMethodref:
		classE, ok := cp.at(e.ref1)
		if !ok || classE.tag != cpClass {
			return MethodRef{}, false
		}
		nt, ok := cp.at(e.ref2)
		if !ok || nt.tag != cpNameAndType {
			return MethodRef{}, false
		}
		return MethodRef{Owner: cp.utf8(classE.ref1), Name: cp.utf8(nt.ref1), Descriptor: cp.utf8(nt.ref2)}, true
	case cpInvokeDynamic, cpDynamic:
		nt, ok := cp.at(e.ref2)
		if !ok || nt.tag != cpNameAndType {
			return MethodRef{}, false
		}
		return MethodRef{Owner: "", Name: cp.utf8(nt.ref1), Descriptor: cp.utf8(nt.ref2)}, true
	}
	return MethodRef{}, false
}
