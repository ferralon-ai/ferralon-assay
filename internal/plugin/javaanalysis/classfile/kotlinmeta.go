package classfile

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// kotlinmeta.go — the @kotlin.Metadata annotation, read far enough to say which methods
// kotlinc inlines. A call to an inline function (or an inline property accessor) leaves no
// invoke in the caller's bytecode: kotlinc copies the body into the call site. The declaring
// class still holds a concrete method, so an empty search for that method proves nothing.
// Only the metadata records that a method is inline; the method itself carries no flag.
//
// The format is kotlinc's: d1 is protobuf (metadata.proto, jvm_metadata.proto) packed into
// strings by BitEncoding, and d2 is the string table its name indices point into, resolved
// through the StringTableTypes records d1 opens with (JvmNameResolver).

// KotlinMetadata is a class's @kotlin.Metadata, with its declaration data kept whole.
type KotlinMetadata struct {
	// Kind is k: 1 class, 2 file facade, 3 synthetic class, 4 multifile facade, 5
	// multifile class part. kotlinc's default, 1, when the element is absent.
	Kind int
	// Version is mv, the metadata version.
	Version []int
	// Data1 and Data2 are d1 and d2, each string as the constant pool holds it (modified
	// UTF-8). For a multifile facade Data1 names the part classes.
	Data1, Data2 []string
	// Extra is xi, the extra flags.
	Extra int
	// malformed names the element whose value had the wrong shape. A metadata with a
	// malformed element answers nothing.
	malformed string
}

const kotlinMetadataType = "Lkotlin/Metadata;"

// kelem is one decoded element_value: a string ('s'), an int ('I'), an array ('['), or a
// kind the metadata does not use (tag only).
type kelem struct {
	tag   byte
	s     string
	sok   bool
	i     int32
	iok   bool
	array []kelem
}

// readKElement decodes one element_value, keeping strings, ints and arrays whole. Any
// other kind is traversed by parseElementValue.
func readKElement(br *reader, cp constPool) kelem {
	tag := br.u1()
	if br.err != nil {
		return kelem{}
	}
	switch tag {
	case 's':
		e, ok := cp.at(br.u2())
		return kelem{tag: tag, s: e.utf8, sok: ok && e.tag == cpUtf8}
	case 'I':
		e, ok := cp.at(br.u2())
		return kelem{tag: tag, i: e.ival, iok: ok && e.tag == cpInteger}
	case '[':
		n := int(br.u2())
		el := kelem{tag: tag}
		for i := 0; i < n && br.err == nil; i++ {
			el.array = append(el.array, readKElement(br, cp))
		}
		return el
	}
	br.pos--
	parseElementValue(br, cp)
	return kelem{tag: tag}
}

// parseKotlinMetadata finds @kotlin.Metadata in a RuntimeVisibleAnnotations body that
// parseAnnotations already accepted, and returns it; nil when the class carries none.
func parseKotlinMetadata(cp constPool, body []byte) *KotlinMetadata {
	br := &reader{b: body}
	n := int(br.u2())
	for i := 0; i < n && br.err == nil; i++ {
		typ := cp.utf8(br.u2())
		pairs := int(br.u2())
		if typ != kotlinMetadataType {
			for p := 0; p < pairs && br.err == nil; p++ {
				br.u2()
				parseElementValue(br, cp)
			}
			continue
		}
		km := &KotlinMetadata{Kind: 1}
		for p := 0; p < pairs && br.err == nil; p++ {
			name := cp.utf8(br.u2())
			v := readKElement(br, cp)
			if br.err != nil {
				break
			}
			var ok bool
			switch name {
			case "k":
				km.Kind, ok = int(v.i), v.tag == 'I' && v.iok
			case "xi":
				km.Extra, ok = int(v.i), v.tag == 'I' && v.iok
			case "mv":
				km.Version, ok = kelemInts(v)
			case "d1":
				km.Data1, ok = kelemStrings(v)
			case "d2":
				km.Data2, ok = kelemStrings(v)
			default:
				ok = true
			}
			if !ok && km.malformed == "" {
				km.malformed = name
			}
		}
		if br.err != nil {
			km.malformed = "annotation"
		}
		return km
	}
	return nil
}

func kelemInts(v kelem) ([]int, bool) {
	if v.tag != '[' {
		return nil, false
	}
	out := make([]int, 0, len(v.array))
	for _, e := range v.array {
		if e.tag != 'I' || !e.iok {
			return nil, false
		}
		out = append(out, int(e.i))
	}
	return out, true
}

func kelemStrings(v kelem) ([]string, bool) {
	if v.tag != '[' {
		return nil, false
	}
	out := make([]string, 0, len(v.array))
	for _, e := range v.array {
		if e.tag != 's' || !e.sok {
			return nil, false
		}
		out = append(out, e.s)
	}
	return out, true
}

// KotlinInline reports whether calls to ref may be missing from compiled callers because
// kotlinc copies the body of the Kotlin declaration behind it into each call site: an inline
// function or an inline property accessor of ref's owner, matched by JVM method name, so
// every overload of an inline name counts. class looks up a loaded class by internal name.
//
// An owner with no @kotlin.Metadata is not Kotlin, and its methods are never inline. An
// error means the metadata of the owner, or of a class it defers to (a multifile facade's
// parts, a class's companion object, an interface behind its DefaultImpls), could not be
// read or is not loaded; the caller treats ref as possibly inline.
func KotlinInline(ref MethodRef, class func(name string) (*Class, bool)) (bool, error) {
	owner, ok := class(ref.Owner)
	if !ok || owner.KotlinMetadata == nil {
		return false, nil
	}
	names, err := kotlinInlineNames(owner, class)
	if err != nil {
		return false, fmt.Errorf("classfile: %s @kotlin.Metadata: %w", owner.Name, err)
	}
	return names[ref.Name], nil
}

// KotlinInlineWithheld reports whether an empty search for ref says nothing because ref may
// be inlined: KotlinInline answered yes, or could not answer. Every lane that lists a sink
// as searched consults it.
func KotlinInlineWithheld(ref MethodRef, class func(name string) (*Class, bool)) bool {
	inline, err := KotlinInline(ref, class)
	return inline || err != nil
}

// kotlinInlineNames returns the JVM names of the methods c's metadata declares inline.
func kotlinInlineNames(c *Class, class func(name string) (*Class, bool)) (map[string]bool, error) {
	m := c.KotlinMetadata
	if m.malformed != "" {
		return nil, fmt.Errorf("malformed element %s", m.malformed)
	}
	switch m.Kind {
	case 1, 2, 5:
		d, err := m.decode()
		if err != nil {
			return nil, err
		}
		if d.companion == "" {
			return d.inline, nil
		}
		// A @JvmStatic member of the companion also has a static copy on the class, which
		// the class's own metadata does not list.
		comp, err := deferredMetadata(class, c.Name+"$"+d.companion, 1)
		if err != nil {
			return nil, err
		}
		cd, err := comp.decode()
		if err != nil {
			return nil, err
		}
		for n := range cd.inline {
			d.inline[n] = true
		}
		return d.inline, nil
	case 3:
		// A synthetic class declares nothing, except that an interface's DefaultImpls holds
		// its members' bodies.
		iface, ok := strings.CutSuffix(c.Name, "$DefaultImpls")
		if !ok {
			return map[string]bool{}, nil
		}
		im, err := deferredMetadata(class, iface, 1)
		if err != nil {
			return nil, err
		}
		d, err := im.decode()
		if err != nil {
			return nil, err
		}
		return d.inline, nil
	case 4:
		// A multifile facade's members are declared by the parts d1 names.
		out := map[string]bool{}
		for _, part := range m.Data1 {
			pm, err := deferredMetadata(class, part, 5)
			if err != nil {
				return nil, err
			}
			d, err := pm.decode()
			if err != nil {
				return nil, err
			}
			for n := range d.inline {
				out[n] = true
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown kind %d", m.Kind)
}

// deferredMetadata returns the metadata of the loaded class name, which must be of kind.
func deferredMetadata(class func(name string) (*Class, bool), name string, kind int) (*KotlinMetadata, error) {
	c, ok := class(name)
	if !ok {
		return nil, fmt.Errorf("class %s is not loaded", name)
	}
	m := c.KotlinMetadata
	if m == nil || m.malformed != "" || m.Kind != kind {
		return nil, fmt.Errorf("class %s has no readable kind-%d metadata", name, kind)
	}
	return m, nil
}

// Flag bits (kotlinc Flags): a function's IS_INLINE and a property accessor's
// IS_INLINE_ACCESSOR.
const (
	kotlinFunctionInline = 1 << 10
	kotlinAccessorInline = 1 << 8
)

// kotlinDecls is what one class's metadata declares that the inline guard reads.
type kotlinDecls struct {
	inline    map[string]bool // JVM method names
	companion string          // the companion object's simple name; "" when there is none
}

// decode reads a kind 1 (Class), 2 or 5 (Package) metadata's functions and properties.
func (m *KotlinMetadata) decode() (kotlinDecls, error) {
	d := kotlinDecls{inline: map[string]bool{}}
	data, err := kotlinDecodeBytes(m.Data1)
	if err != nil {
		return d, err
	}
	in := &pbReader{b: data}
	types, err := in.delimited()
	if err != nil {
		return d, fmt.Errorf("string table: %w", err)
	}
	strs, err := newKotlinStrings(types, m.Data2)
	if err != nil {
		return d, err
	}
	fnField, propField, companionField := 3, 4, 0 // Package
	if m.Kind == 1 {
		fnField, propField, companionField = 9, 10, 4 // Class
	}
	msg := &pbReader{b: data[in.pos:]}
	for !msg.done() {
		field, wire, err := msg.next()
		if err != nil {
			return d, err
		}
		switch {
		case field == fnField && wire == pbBytes:
			b, err := msg.bytes()
			if err != nil {
				return d, err
			}
			if err := d.function(b, strs); err != nil {
				return d, fmt.Errorf("function: %w", err)
			}
		case field == propField && wire == pbBytes:
			b, err := msg.bytes()
			if err != nil {
				return d, err
			}
			if err := d.property(b, strs); err != nil {
				return d, fmt.Errorf("property: %w", err)
			}
		case companionField != 0 && field == companionField && wire == pbVarint:
			v, err := msg.varint()
			if err != nil {
				return d, err
			}
			name, err := strs.get(int(int32(v)))
			if err != nil {
				return d, fmt.Errorf("companion name: %w", err)
			}
			d.companion = name
		default:
			if err := msg.skip(wire); err != nil {
				return d, err
			}
		}
	}
	return d, nil
}

// function reads one Function message: flags (9; old_flags 1 only in pre-release
// metadata), name (2), and the JVM signature extension (100: JvmMethodSignature, whose
// name (1) is set when the JVM name differs, e.g. @JvmName or a mangled name).
func (d *kotlinDecls) function(b []byte, strs *kotlinStrings) error {
	flags, hasFlags, hasOld := uint64(6), false, false
	name, jvmName := -1, -1
	p := &pbReader{b: b}
	for !p.done() {
		field, wire, err := p.next()
		if err != nil {
			return err
		}
		switch {
		case field == 9 && wire == pbVarint:
			if flags, err = p.varint(); err != nil {
				return err
			}
			hasFlags = true
		case field == 1 && wire == pbVarint:
			if _, err := p.varint(); err != nil {
				return err
			}
			hasOld = true
		case field == 2 && wire == pbVarint:
			v, err := p.varint()
			if err != nil {
				return err
			}
			name = int(int32(v))
		case field == 100 && wire == pbBytes:
			sig, err := p.bytes()
			if err != nil {
				return err
			}
			if jvmName, err = signatureName(sig); err != nil {
				return err
			}
		default:
			if err := p.skip(wire); err != nil {
				return err
			}
		}
	}
	if hasOld && !hasFlags {
		return errors.New("old_flags only")
	}
	if flags&kotlinFunctionInline == 0 {
		return nil
	}
	idx := name
	if jvmName >= 0 {
		idx = jvmName
	}
	n, err := strs.get(idx)
	if err != nil {
		return err
	}
	d.inline[n] = true
	d.inline[n+"$default"] = true
	return nil
}

// property reads one Property message: name (2), getter_flags (7), setter_flags (8), and
// the JVM signature extension (100: JvmPropertySignature, getter 3 and setter 4). Only the
// accessors carry IS_INLINE_ACCESSOR; absent accessor flags are the defaults, never inline.
func (d *kotlinDecls) property(b []byte, strs *kotlinStrings) error {
	name := -1
	var getterFlags, setterFlags uint64
	getterName, setterName := -1, -1
	p := &pbReader{b: b}
	for !p.done() {
		field, wire, err := p.next()
		if err != nil {
			return err
		}
		switch {
		case field == 2 && wire == pbVarint:
			v, err := p.varint()
			if err != nil {
				return err
			}
			name = int(int32(v))
		case field == 7 && wire == pbVarint:
			if getterFlags, err = p.varint(); err != nil {
				return err
			}
		case field == 8 && wire == pbVarint:
			if setterFlags, err = p.varint(); err != nil {
				return err
			}
		case field == 100 && wire == pbBytes:
			sig, err := p.bytes()
			if err != nil {
				return err
			}
			if getterName, setterName, err = propertySignatureNames(sig); err != nil {
				return err
			}
		default:
			if err := p.skip(wire); err != nil {
				return err
			}
		}
	}
	for _, acc := range []struct {
		flags  uint64
		jvm    int
		setter bool
	}{{getterFlags, getterName, false}, {setterFlags, setterName, true}} {
		if acc.flags&kotlinAccessorInline == 0 {
			continue
		}
		if acc.jvm >= 0 {
			n, err := strs.get(acc.jvm)
			if err != nil {
				return err
			}
			d.inline[n] = true
			continue
		}
		units, err := strs.units(name)
		if err != nil {
			return err
		}
		for _, n := range accessorNames(units, acc.setter) {
			d.inline[n] = true
		}
	}
	return nil
}

// accessorNames are the JVM names kotlinc may give a property's getter or setter when the
// metadata carries no signature for it: the JavaBean forms, with and without capitalizing,
// and for an is-prefixed property its own name (getter) or the name without "is" (setter).
func accessorNames(prop []uint16, setter bool) []string {
	prefix := "get"
	if setter {
		prefix = "set"
	}
	base := [][]uint16{prop}
	isPrefixed := len(prop) > 2 && prop[0] == 'i' && prop[1] == 's'
	if isPrefixed {
		base = append(base, prop[2:])
	}
	var out []string
	if isPrefixed && !setter {
		out = append(out, encodeMUTF8(prop))
	}
	for _, b := range base {
		out = append(out, prefix+encodeMUTF8(b))
		if len(b) > 0 && (b[0] < 0xD800 || b[0] > 0xDFFF) {
			up := append([]uint16{uint16(unicode.ToUpper(rune(b[0])))}, b[1:]...)
			out = append(out, prefix+encodeMUTF8(up))
		}
	}
	return out
}

// signatureName reads a JvmMethodSignature's name index (1); -1 when it has none.
func signatureName(b []byte) (int, error) {
	name := -1
	p := &pbReader{b: b}
	for !p.done() {
		field, wire, err := p.next()
		if err != nil {
			return -1, err
		}
		if field == 1 && wire == pbVarint {
			v, err := p.varint()
			if err != nil {
				return -1, err
			}
			name = int(int32(v))
			continue
		}
		if err := p.skip(wire); err != nil {
			return -1, err
		}
	}
	return name, nil
}

// propertySignatureNames reads a JvmPropertySignature's getter (3) and setter (4) method
// signature names; -1 for each that is absent or unnamed.
func propertySignatureNames(b []byte) (getter, setter int, err error) {
	getter, setter = -1, -1
	p := &pbReader{b: b}
	for !p.done() {
		field, wire, err := p.next()
		if err != nil {
			return -1, -1, err
		}
		if (field == 3 || field == 4) && wire == pbBytes {
			sig, err := p.bytes()
			if err != nil {
				return -1, -1, err
			}
			n, err := signatureName(sig)
			if err != nil {
				return -1, -1, err
			}
			if field == 3 {
				getter = n
			} else {
				setter = n
			}
			continue
		}
		if err := p.skip(wire); err != nil {
			return -1, -1, err
		}
	}
	return getter, setter, nil
}

// kotlinRecord is one StringTableTypes.Record, describing how to read the d2 entry at its
// index.
type kotlinRecord struct {
	str           []uint16
	hasStr        bool
	hasPredefined bool
	op            uint64
	substring     []int32
	replaceChar   []int32
}

// maxKotlinRecords bounds the expanded record list a hostile range could inflate.
const maxKotlinRecords = 1 << 20

// kotlinStrings resolves name indices the way kotlinc's JvmNameResolver does.
type kotlinStrings struct {
	records []*kotlinRecord // one per index, ranges expanded
	d2      []string
}

func newKotlinStrings(types []byte, d2 []string) (*kotlinStrings, error) {
	t := &kotlinStrings{d2: d2}
	p := &pbReader{b: types}
	for !p.done() {
		field, wire, err := p.next()
		if err != nil {
			return nil, err
		}
		if field != 1 || wire != pbBytes {
			if err := p.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		b, err := p.bytes()
		if err != nil {
			return nil, err
		}
		r, rng, err := parseKotlinRecord(b)
		if err != nil {
			return nil, err
		}
		if rng < 0 || len(t.records)+int(rng) > maxKotlinRecords {
			return nil, fmt.Errorf("record range %d out of bounds", rng)
		}
		for i := int32(0); i < rng; i++ {
			t.records = append(t.records, r)
		}
	}
	return t, nil
}

func parseKotlinRecord(b []byte) (*kotlinRecord, int32, error) {
	r := &kotlinRecord{}
	rng := int32(1)
	p := &pbReader{b: b}
	for !p.done() {
		field, wire, err := p.next()
		if err != nil {
			return nil, 0, err
		}
		switch {
		case field == 1 && wire == pbVarint:
			v, err := p.varint()
			if err != nil {
				return nil, 0, err
			}
			rng = int32(v)
		case field == 2 && wire == pbVarint:
			if _, err := p.varint(); err != nil {
				return nil, 0, err
			}
			r.hasPredefined = true
		case field == 6 && wire == pbBytes:
			s, err := p.bytes()
			if err != nil {
				return nil, 0, err
			}
			r.str, r.hasStr = utf16Units(string(s)), true
		case field == 3 && wire == pbVarint:
			if r.op, err = p.varint(); err != nil {
				return nil, 0, err
			}
		case field == 4 && (wire == pbVarint || wire == pbBytes):
			if r.substring, err = p.int32s(wire, r.substring); err != nil {
				return nil, 0, err
			}
		case field == 5 && (wire == pbVarint || wire == pbBytes):
			if r.replaceChar, err = p.int32s(wire, r.replaceChar); err != nil {
				return nil, 0, err
			}
		default:
			if err := p.skip(wire); err != nil {
				return nil, 0, err
			}
		}
	}
	return r, rng, nil
}

// get resolves index idx to a name, in the constant pool's modified UTF-8 form so it
// compares equal to MethodRef.Name.
func (t *kotlinStrings) get(idx int) (string, error) {
	u, err := t.units(idx)
	if err != nil {
		return "", err
	}
	return encodeMUTF8(u), nil
}

// units resolves index idx to UTF-16 code units: the record's own string, else the d2
// entry, then its substring, character replacement and operation. A predefined string is
// not resolved: no name the guard reads uses one, and resolving it wrongly could hide an
// inline method, so it is an error.
func (t *kotlinStrings) units(idx int) ([]uint16, error) {
	if idx < 0 || idx >= len(t.records) {
		return nil, fmt.Errorf("string %d has no record", idx)
	}
	r := t.records[idx]
	var s []uint16
	switch {
	case r.hasStr:
		s = r.str
	case r.hasPredefined:
		return nil, fmt.Errorf("string %d is predefined", idx)
	case idx < len(t.d2):
		var err error
		if s, err = decodeMUTF8(t.d2[idx]); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("string %d is past d2", idx)
	}
	if len(r.substring) >= 2 {
		begin, end := int(r.substring[0]), int(r.substring[1])
		if 0 <= begin && begin <= end && end <= len(s) {
			s = s[begin:end]
		}
	}
	if len(r.replaceChar) >= 2 {
		from, to := uint16(r.replaceChar[0]), uint16(r.replaceChar[1])
		s = replaceUnit(s, from, to)
	}
	switch r.op {
	case 0: // NONE
	case 1: // INTERNAL_TO_CLASS_ID
		s = replaceUnit(s, '$', '.')
	case 2: // DESC_TO_CLASS_ID
		if len(s) >= 2 {
			s = s[1 : len(s)-1]
		}
		s = replaceUnit(s, '$', '.')
	default:
		return nil, fmt.Errorf("string %d has unknown operation %d", idx, r.op)
	}
	return s, nil
}

func replaceUnit(s []uint16, from, to uint16) []uint16 {
	out := make([]uint16, len(s))
	for i, u := range s {
		if u == from {
			u = to
		}
		out[i] = u
	}
	return out
}

// kotlinDecodeBytes is kotlinc's BitEncoding.decodeBytes. A leading U+0000 marks UTF-8
// mode: every char is one byte. Otherwise (after an optional U+FFFF marker) the chars are
// 7-bit groups, each shifted by one, packing the bytes 8-to-7.
func kotlinDecodeBytes(d1 []string) ([]byte, error) {
	var units []uint16
	for i, s := range d1 {
		u, err := decodeMUTF8(s)
		if err != nil {
			return nil, err
		}
		if i == 0 && len(u) > 0 {
			switch u[0] {
			case 0:
				var out []byte
				for _, s := range d1 {
					u, err := decodeMUTF8(s)
					if err != nil {
						return nil, err
					}
					for _, c := range u {
						if c > 0xFF {
							return nil, fmt.Errorf("d1: char %#x in UTF-8 mode", c)
						}
						out = append(out, byte(c))
					}
				}
				return out[1:], nil
			case 0xFFFF:
				u = u[1:]
			}
		}
		units = append(units, u...)
	}
	data := make([]byte, len(units))
	for i, c := range units {
		data[i] = (byte(c) + 0x7F) & 0x7F
	}
	return decode7to8(data), nil
}

// decode7to8 unpacks 8-bit bytes from 7-bit groups, low bits first.
func decode7to8(data []byte) []byte {
	n := 7 * len(data) / 8
	out := make([]byte, n)
	idx, bit := 0, 0
	for i := 0; i < n; i++ {
		first := int(data[idx]) >> bit
		idx++
		second := (int(data[idx]) & (1<<(bit+1) - 1)) << (7 - bit)
		out[i] = byte(first + second)
		if bit == 6 {
			idx++
			bit = 0
		} else {
			bit++
		}
	}
	return out
}

// decodeMUTF8 decodes a constant-pool string (JVMS §4.4.7 modified UTF-8) to UTF-16 code
// units.
func decodeMUTF8(s string) ([]uint16, error) {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c < 0x80:
			out = append(out, uint16(c))
			i++
		case c&0xE0 == 0xC0 && i+1 < len(s) && s[i+1]&0xC0 == 0x80:
			out = append(out, uint16(c&0x1F)<<6|uint16(s[i+1]&0x3F))
			i += 2
		case c&0xF0 == 0xE0 && i+2 < len(s) && s[i+1]&0xC0 == 0x80 && s[i+2]&0xC0 == 0x80:
			out = append(out, uint16(c&0x0F)<<12|uint16(s[i+1]&0x3F)<<6|uint16(s[i+2]&0x3F))
			i += 3
		default:
			return nil, fmt.Errorf("bad modified UTF-8 at byte %d", i)
		}
	}
	return out, nil
}

// encodeMUTF8 is the inverse of decodeMUTF8: U+0000 as two bytes, each surrogate on its own.
func encodeMUTF8(u []uint16) string {
	var b strings.Builder
	for _, c := range u {
		switch {
		case c != 0 && c < 0x80:
			b.WriteByte(byte(c))
		case c < 0x800:
			b.WriteByte(0xC0 | byte(c>>6))
			b.WriteByte(0x80 | byte(c&0x3F))
		default:
			b.WriteByte(0xE0 | byte(c>>12))
			b.WriteByte(0x80 | byte(c>>6&0x3F))
			b.WriteByte(0x80 | byte(c&0x3F))
		}
	}
	return b.String()
}

// utf16Units converts a protobuf (standard UTF-8) string to UTF-16 code units.
func utf16Units(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
			continue
		}
		out = append(out, uint16(r))
	}
	return out
}

// Protobuf wire types.
const (
	pbVarint  = 0
	pbFixed64 = 1
	pbBytes   = 2
	pbFixed32 = 5
)

// pbReader is a bounds-checked protobuf wire reader. Every fault is an error.
type pbReader struct {
	b   []byte
	pos int
}

func (p *pbReader) done() bool { return p.pos >= len(p.b) }

func (p *pbReader) varint() (uint64, error) {
	var v uint64
	for shift := 0; shift < 64; shift += 7 {
		if p.pos >= len(p.b) {
			return 0, errors.New("protobuf: truncated varint")
		}
		c := p.b[p.pos]
		p.pos++
		v |= uint64(c&0x7F) << shift
		if c < 0x80 {
			return v, nil
		}
	}
	return 0, errors.New("protobuf: varint too long")
}

// next reads a field key.
func (p *pbReader) next() (field, wire int, err error) {
	k, err := p.varint()
	if err != nil {
		return 0, 0, err
	}
	if k>>3 == 0 || k>>3 > 1<<29 {
		return 0, 0, fmt.Errorf("protobuf: bad field key %d", k)
	}
	return int(k >> 3), int(k & 7), nil
}

func (p *pbReader) bytes() ([]byte, error) {
	n, err := p.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(p.b)-p.pos) {
		return nil, errors.New("protobuf: truncated bytes")
	}
	b := p.b[p.pos : p.pos+int(n)]
	p.pos += int(n)
	return b, nil
}

// delimited reads a length-prefixed message, as parseDelimitedFrom does.
func (p *pbReader) delimited() ([]byte, error) { return p.bytes() }

// int32s appends a repeated int32 field's values, packed (wire 2) or not (wire 0).
func (p *pbReader) int32s(wire int, out []int32) ([]int32, error) {
	if wire == pbVarint {
		v, err := p.varint()
		return append(out, int32(v)), err
	}
	b, err := p.bytes()
	if err != nil {
		return nil, err
	}
	q := &pbReader{b: b}
	for !q.done() {
		v, err := q.varint()
		if err != nil {
			return nil, err
		}
		out = append(out, int32(v))
	}
	return out, nil
}

func (p *pbReader) skip(wire int) error {
	switch wire {
	case pbVarint:
		_, err := p.varint()
		return err
	case pbBytes:
		_, err := p.bytes()
		return err
	case pbFixed64, pbFixed32:
		n := 8
		if wire == pbFixed32 {
			n = 4
		}
		if len(p.b)-p.pos < n {
			return errors.New("protobuf: truncated fixed field")
		}
		p.pos += n
		return nil
	}
	return fmt.Errorf("protobuf: unsupported wire type %d", wire)
}
