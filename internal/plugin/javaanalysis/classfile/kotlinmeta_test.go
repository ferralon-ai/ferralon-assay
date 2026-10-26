package classfile

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// ---- @kotlin.Metadata builders ----
//
// kotlinc writes d1 as protobuf: a length-delimited StringTableTypes, then the Class or
// Package message. These helpers write the same wire format by hand.

func pbKey(field, wire int) []byte { return pbUvarint(uint64(field<<3 | wire)) }

func pbUvarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

// pv is a varint field; pl a length-delimited field.
func pv(field int, v uint64) []byte { return append(pbKey(field, pbVarint), pbUvarint(v)...) }

func pl(field int, parts ...[]byte) []byte {
	body := cat(parts...)
	out := append(pbKey(field, pbBytes), pbUvarint(uint64(len(body)))...)
	return append(out, body...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// packed is a packed repeated varint field.
func packed(field int, vs ...uint64) []byte {
	var body []byte
	for _, v := range vs {
		body = append(body, pbUvarint(v)...)
	}
	return pl(field, body)
}

// d1Payload is the decoded d1: the delimited StringTableTypes holding records, then msg.
func d1Payload(records [][]byte, msg []byte) []byte {
	var types []byte
	for _, r := range records {
		types = append(types, pl(1, r)...)
	}
	return cat(pbUvarint(uint64(len(types))), types, msg)
}

// plainRecords is one record per d2 entry, each read straight from d2.
func plainRecords(n int) [][]byte {
	if n == 0 {
		return nil
	}
	return [][]byte{pv(1, uint64(n))}
}

// d1UTF8 encodes payload in kotlinc's UTF-8 mode (a U+0000 marker, then one char per
// byte), split across strings of at most 5 chars, as the constant pool holds them.
func d1UTF8(payload []byte) []string {
	units := []uint16{0}
	for _, c := range payload {
		units = append(units, uint16(c))
	}
	return splitUnits(units, 5)
}

// d1Packed encodes payload in kotlinc's 8-to-7 mode: 7-bit groups, low bits first, each
// shifted by one; marker prefixes U+FFFF.
func d1Packed(payload []byte, marker bool) []string {
	var units []uint16
	if marker {
		units = append(units, 0xFFFF)
	}
	var acc, nbits uint
	for _, c := range payload {
		acc |= uint(c) << nbits
		nbits += 8
		for nbits >= 7 {
			units = append(units, uint16((acc&0x7F+1)&0x7F))
			acc >>= 7
			nbits -= 7
		}
	}
	if nbits > 0 {
		units = append(units, uint16((acc&0x7F+1)&0x7F))
	}
	return splitUnits(units, 4)
}

func splitUnits(units []uint16, n int) []string {
	var out []string
	for len(units) > n {
		out = append(out, encodeMUTF8(units[:n]))
		units = units[n:]
	}
	return append(out, encodeMUTF8(units))
}

// mutf8 is s as the constant pool holds it.
func mutf8(s string) string { return encodeMUTF8(utf16.Encode([]rune(s))) }

func meta(kind int, records [][]byte, msg []byte, d2 ...string) *KotlinMetadata {
	m := &KotlinMetadata{Kind: kind, Version: kmv, Data1: d1UTF8(d1Payload(records, msg))}
	for _, s := range d2 {
		m.Data2 = append(m.Data2, mutf8(s))
	}
	return m
}

// kmv is the metadata version kotlinc 2.2 writes.
var kmv = []int{2, 2, 0}

const (
	inlineFlags = 6 | kotlinFunctionInline
	plainFlags  = 6
)

// fn is a Function message (Package field 3, Class field 9 are supplied by the caller).
func fn(flags uint64, name int, extra ...[]byte) []byte {
	return cat(append([][]byte{pv(9, flags), pv(2, uint64(name))}, extra...)...)
}

func jvmSig(name int) []byte { return pl(100, pv(1, uint64(name))) }

type classes map[string]*Class

func (cs classes) lookup(name string) (*Class, bool) { c, ok := cs[name]; return c, ok }

func (cs classes) add(name string, m *KotlinMetadata) classes {
	cs[name] = &Class{Name: name, KotlinMetadata: m}
	return cs
}

// ---- tests ----

func TestKotlinInline(t *testing.T) {
	facadeFns := cat(pl(3, fn(inlineFlags, 0)), pl(3, fn(plainFlags, 1)))
	tests := []struct {
		name    string
		cs      classes
		owner   string
		methods map[string]bool // method name → want inline
		wantErr bool
	}{{
		name:    "file facade: inline function, its $default bridge, and a plain one",
		cs:      classes{}.add("p/BKt", meta(2, plainRecords(2), facadeFns, "g", "h")),
		owner:   "p/BKt",
		methods: map[string]bool{"g": true, "g$default": true, "h": false, "absent": false},
	}, {
		name:  "bodies kotlinc derives from an inline name: $default, $$forInline, atomicfu",
		cs:    classes{}.add("p/BKt", meta(2, plainRecords(2), facadeFns, "g", "h")),
		owner: "p/BKt",
		methods: map[string]bool{
			"g$$forInline": true, "g$atomicfu": true, "g$atomicfu$array": true,
			"h$default": false, "h$$forInline": false, "gg": false, "$g": false,
		},
	}, {
		name:    "metadata without a version fails closed",
		cs:      classes{}.add("p/BKt", withVersion(meta(2, plainRecords(1), pl(3, fn(plainFlags, 0)), "g"), nil)),
		owner:   "p/BKt",
		wantErr: true,
	}, {
		name:    "metadata of a later major version fails closed",
		cs:      classes{}.add("p/BKt", withVersion(meta(2, plainRecords(1), pl(3, fn(plainFlags, 0)), "g"), []int{3, 0, 0})),
		owner:   "p/BKt",
		wantErr: true,
	}, {
		name:    "an earlier major version is read",
		cs:      classes{}.add("p/BKt", withVersion(meta(2, plainRecords(1), pl(3, fn(inlineFlags, 0)), "g"), []int{1, 9, 0})),
		owner:   "p/BKt",
		methods: map[string]bool{"g": true},
	}, {
		name: "multifile facade with a part of a later version fails closed",
		cs: classes{}.
			add("p/BKt", &KotlinMetadata{Kind: 4, Version: kmv, Data1: []string{"p/BKt__X"}}).
			add("p/BKt__X", withVersion(meta(5, plainRecords(1), pl(3, fn(plainFlags, 0)), "g"), []int{3, 0, 0})),
		owner:   "p/BKt",
		wantErr: true,
	}, {
		name:    "absent flags are kotlinc's default, not inline",
		cs:      classes{}.add("p/BKt", meta(2, plainRecords(1), pl(3, pv(2, 0)), "g")),
		owner:   "p/BKt",
		methods: map[string]bool{"g": false},
	}, {
		name:    "@JvmName: the JVM name is the one withheld",
		cs:      classes{}.add("p/BKt", meta(2, plainRecords(2), pl(3, fn(inlineFlags, 0, jvmSig(1))), "g", "jvmG")),
		owner:   "p/BKt",
		methods: map[string]bool{"jvmG": true, "g": false},
	}, {
		name:    "class: functions are field 9, package-only field 3 ignored",
		cs:      classes{}.add("p/B", meta(1, plainRecords(2), cat(pl(9, fn(inlineFlags, 0)), pl(3, fn(inlineFlags, 1))), "g", "h")),
		owner:   "p/B",
		methods: map[string]bool{"g": true, "h": false},
	}, {
		name:    "multifile part (k=5) reads as a package",
		cs:      classes{}.add("p/BKt__X", meta(5, plainRecords(2), facadeFns, "g", "h")),
		owner:   "p/BKt__X",
		methods: map[string]bool{"g": true, "h": false},
	}, {
		name: "multifile facade (k=4) unions its parts",
		cs: classes{}.
			add("p/BKt", &KotlinMetadata{Kind: 4, Version: kmv, Data1: []string{"p/BKt__X", "p/BKt__Y"}}).
			add("p/BKt__X", meta(5, plainRecords(1), pl(3, fn(inlineFlags, 0)), "g")).
			add("p/BKt__Y", meta(5, plainRecords(1), pl(3, fn(inlineFlags, 0)), "k")),
		owner:   "p/BKt",
		methods: map[string]bool{"g": true, "k": true, "h": false},
	}, {
		name: "multifile facade with a part not loaded fails closed",
		cs: classes{}.
			add("p/BKt", &KotlinMetadata{Kind: 4, Version: kmv, Data1: []string{"p/BKt__X", "p/BKt__Y"}}).
			add("p/BKt__X", meta(5, plainRecords(1), pl(3, fn(plainFlags, 0)), "g")),
		owner:   "p/BKt",
		wantErr: true,
	}, {
		name: "multifile facade with a part of the wrong kind fails closed",
		cs: classes{}.
			add("p/BKt", &KotlinMetadata{Kind: 4, Version: kmv, Data1: []string{"p/BKt__X"}}).
			add("p/BKt__X", meta(2, plainRecords(1), pl(3, fn(plainFlags, 0)), "g")),
		owner:   "p/BKt",
		wantErr: true,
	}, {
		name: "class with a companion unions the companion's inline functions",
		cs: classes{}.
			add("p/B", meta(1, plainRecords(2), cat(pv(4, 1), pl(9, fn(plainFlags, 0))), "g", "Companion")).
			add("p/B$Companion", meta(1, plainRecords(1), pl(9, fn(inlineFlags, 0)), "make")),
		owner:   "p/B",
		methods: map[string]bool{"make": true, "g": false},
	}, {
		name:    "class whose companion is not loaded fails closed",
		cs:      classes{}.add("p/B", meta(1, plainRecords(2), cat(pv(4, 1), pl(9, fn(plainFlags, 0))), "g", "Companion")),
		owner:   "p/B",
		wantErr: true,
	}, {
		name: "DefaultImpls answers from its interface",
		cs: classes{}.
			add("p/I$DefaultImpls", &KotlinMetadata{Kind: 3, Version: kmv}).
			add("p/I", meta(1, plainRecords(1), pl(9, fn(inlineFlags, 0)), "g")),
		owner:   "p/I$DefaultImpls",
		methods: map[string]bool{"g": true},
	}, {
		name:    "DefaultImpls whose interface is not loaded fails closed",
		cs:      classes{}.add("p/I$DefaultImpls", &KotlinMetadata{Kind: 3, Version: kmv}),
		owner:   "p/I$DefaultImpls",
		wantErr: true,
	}, {
		name:    "other synthetic classes declare nothing",
		cs:      classes{}.add("p/B$f$1", &KotlinMetadata{Kind: 3, Version: kmv}),
		owner:   "p/B$f$1",
		methods: map[string]bool{"invoke": false},
	}, {
		name:    "unknown kind fails closed",
		cs:      classes{}.add("p/B", &KotlinMetadata{Kind: 6, Version: kmv}),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "malformed annotation element fails closed",
		cs:      classes{}.add("p/B", &KotlinMetadata{Kind: 2, Version: kmv, unreadable: "malformed element d1"}),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "a malformed element fails closed even when d1 decodes",
		cs:      classes{}.add("p/B", withMalformed(meta(2, plainRecords(1), pl(3, fn(plainFlags, 0)), "g"), "xi")),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "truncated protobuf fails closed",
		cs:      classes{}.add("p/B", &KotlinMetadata{Kind: 2, Version: kmv, Data1: d1UTF8(d1Payload(plainRecords(1), pl(3, fn(inlineFlags, 0)))[:6]), Data2: []string{"g"}}),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "pre-release old_flags without flags fails closed",
		cs:      classes{}.add("p/B", meta(2, plainRecords(1), pl(3, cat(pv(1, 1<<10), pv(2, 0))), "g")),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "a name index with no record fails closed",
		cs:      classes{}.add("p/B", meta(2, plainRecords(1), pl(3, fn(inlineFlags, 3)), "g")),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "a predefined inline name fails closed",
		cs:      classes{}.add("p/B", meta(2, [][]byte{pv(2, 7)}, pl(3, fn(inlineFlags, 0)))),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "a predefined inline name fails closed even when d2 has an entry at its index",
		cs:      classes{}.add("p/B", meta(2, [][]byte{pv(2, 7)}, pl(3, fn(inlineFlags, 0)), "g")),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "an inline name past d2 with no string of its own fails closed",
		cs:      classes{}.add("p/B", meta(2, [][]byte{pv(1, 2)}, pl(3, fn(inlineFlags, 1)), "h")),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "an inline name with an unknown string operation fails closed",
		cs:      classes{}.add("p/B", meta(2, [][]byte{pv(3, 5)}, pl(3, fn(inlineFlags, 0)), "g")),
		owner:   "p/B",
		wantErr: true,
	}, {
		name:    "a predefined name on a plain function is not needed",
		cs:      classes{}.add("p/B", meta(2, [][]byte{pv(2, 7)}, pl(3, fn(plainFlags, 0)))),
		owner:   "p/B",
		methods: map[string]bool{"g": false},
	}, {
		name:    "an owner without metadata is not Kotlin",
		cs:      classes{"p/J": {Name: "p/J"}},
		owner:   "p/J",
		methods: map[string]bool{"g": false},
	}, {
		name:    "an owner not loaded answers nothing",
		cs:      classes{},
		owner:   "p/Missing",
		methods: map[string]bool{"g": false},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				if _, err := KotlinInline(MethodRef{Owner: tt.owner, Name: "g"}, tt.cs.lookup); err == nil {
					t.Fatal("want an error")
				}
				return
			}
			for m, want := range tt.methods {
				got, err := KotlinInline(MethodRef{Owner: tt.owner, Name: m}, tt.cs.lookup)
				if err != nil {
					t.Fatalf("%s: %v", m, err)
				}
				if got != want {
					t.Errorf("%s: inline = %v, want %v", m, got, want)
				}
			}
		})
	}
}

func TestKotlinInlineProperties(t *testing.T) {
	// Property: flags 11, name 2, getter_flags 7, setter_flags 8, signature 100
	// (JvmPropertySignature getter 3, setter 4).
	accInline := uint64(kotlinAccessorInline | 6)
	tests := []struct {
		name    string
		prop    []byte
		d2      []string
		methods map[string]bool
	}{{
		name:    "inline getter without a signature: every getter form",
		prop:    cat(pv(2, 0), pv(7, accInline)),
		d2:      []string{"size"},
		methods: map[string]bool{"getSize": true, "getsize": true, "setSize": false, "size": false},
	}, {
		name:    "inline setter only",
		prop:    cat(pv(2, 0), pv(7, 6), pv(8, accInline)),
		d2:      []string{"size"},
		methods: map[string]bool{"setSize": true, "getSize": false},
	}, {
		name:    "is-prefixed property keeps its own name for the getter",
		prop:    cat(pv(2, 0), pv(7, accInline), pv(8, accInline)),
		d2:      []string{"isOpen"},
		methods: map[string]bool{"isOpen": true, "setOpen": true, "setIsOpen": true},
	}, {
		name:    "signature names win",
		prop:    cat(pv(2, 0), pv(7, accInline), pl(100, pl(3, pv(1, 1)), pl(4, pv(1, 2)))),
		d2:      []string{"size", "sizeOf", "putSize"},
		methods: map[string]bool{"sizeOf": true, "getSize": false, "putSize": false},
	}, {
		name:    "non-inline accessors",
		prop:    cat(pv(2, 0), pv(7, 6), pv(8, 6)),
		d2:      []string{"size"},
		methods: map[string]bool{"getSize": false, "setSize": false},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := classes{}.add("p/BKt", meta(2, plainRecords(len(tt.d2)), pl(4, tt.prop), tt.d2...))
			for m, want := range tt.methods {
				got, err := KotlinInline(MethodRef{Owner: "p/BKt", Name: m}, cs.lookup)
				if err != nil {
					t.Fatalf("%s: %v", m, err)
				}
				if got != want {
					t.Errorf("%s: inline = %v, want %v", m, got, want)
				}
			}
		})
	}
}

// TestKotlinStringTable covers JvmNameResolver: ranges, the record's own string,
// substring, character replacement, operations, and names outside ASCII.
func TestKotlinStringTable(t *testing.T) {
	records := [][]byte{
		pv(1, 2),                      // 0,1: d2 as is
		pl(6, []byte("own")),          // 2: the record's string
		packed(4, 1, 4),               // 3: d2[3][1:4]
		cat(packed(5, '_', '$')),      // 4: '_' → '$'
		cat(pv(5, '_'), pv(5, '-')),   // 5: replace_char, unpacked
		pv(3, 1),                      // 6: INTERNAL_TO_CLASS_ID, '$' → '.'
		pv(3, 2),                      // 7: DESC_TO_CLASS_ID
		pl(6, []byte("f\U0001D523x")), // 8: supplementary char in the record string
		cat(packed(4, 0, 99)),         // 9: substring out of range is ignored
	}
	d2 := []string{"a", "b\x00c", "", "xgyz", "p_q", "r_s", "A$B", "LA$B;", "", "whole", "\U0001D523"}
	tbl, err := newKotlinStrings(cat(func() []byte {
		var b []byte
		for _, r := range records {
			b = append(b, pl(1, r)...)
		}
		return b
	}()), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d2 {
		tbl.d2 = append(tbl.d2, mutf8(s))
	}
	want := []string{"a", "b\x00c", "own", "gyz", "p$q", "r-s", "A.B", "A.B", "f\U0001D523x", "whole"}
	for i, w := range want {
		got, err := tbl.get(i)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if got != mutf8(w) {
			t.Errorf("%d: got %q, want %q", i, got, mutf8(w))
		}
	}
	if _, err := tbl.get(10); err == nil {
		t.Error("index 10 has no record: want an error")
	}
}

func TestKotlinNonASCIIName(t *testing.T) {
	// The method name the constant pool holds is modified UTF-8: U+0000 as C0 80 and a
	// supplementary character as two 3-byte surrogates.
	name := "inl\x00\U0001D523é"
	cs := classes{}.add("p/BKt", meta(2, plainRecords(1), pl(3, fn(inlineFlags, 0)), name))
	got, err := KotlinInline(MethodRef{Owner: "p/BKt", Name: mutf8(name)}, cs.lookup)
	if err != nil || !got {
		t.Fatalf("inline = %v, %v; want true", got, err)
	}
	if !strings.Contains(mutf8(name), "\xc0\x80") {
		t.Fatal("fixture name is not in modified UTF-8")
	}
}

func TestKotlinDecodeBytesModes(t *testing.T) {
	payload := d1Payload(plainRecords(2), cat(pl(3, fn(inlineFlags, 0)), pl(3, fn(plainFlags, 1))))
	for name, d1 := range map[string][]string{
		"utf8":             d1UTF8(payload),
		"8to7 with marker": d1Packed(payload, true),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := kotlinDecodeBytes(d1)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, payload) {
				t.Fatalf("decoded %x, want %x", got, payload)
			}
			cs := classes{}.add("p/BKt", &KotlinMetadata{Kind: 2, Version: kmv, Data1: d1, Data2: []string{"g", "h"}})
			if in, err := KotlinInline(MethodRef{Owner: "p/BKt", Name: "g"}, cs.lookup); err != nil || !in {
				t.Fatalf("g inline = %v, %v", in, err)
			}
		})
	}
	// Without a marker the first char must not be U+0000, so the first byte's low 7 bits
	// must not be 0x7F.
	p := []byte{0x01, 0x7F, 0x02, 0xFE}
	got, err := kotlinDecodeBytes(d1Packed(p, false))
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("8to7 without marker: %x, %v", got, err)
	}
	if _, err := kotlinDecodeBytes([]string{"\xc0\x80\xe4\xb8\x80"}); err == nil {
		t.Error("a char above 0xFF in UTF-8 mode: want an error")
	}
}

// TestKotlinMetadataNeverPanics feeds arbitrary d1 and d2 through the decoder: every
// outcome is an answer or an error.
func TestKotlinMetadataNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	valid := d1Payload(plainRecords(2), cat(pl(3, fn(inlineFlags, 0)), pl(4, cat(pv(2, 1), pv(7, 1<<8)))))
	for i := 0; i < 5000; i++ {
		var payload []byte
		if i%2 == 0 {
			payload = append([]byte(nil), valid...)
			for j := 0; j < 1+rng.Intn(4); j++ {
				payload[rng.Intn(len(payload))] = byte(rng.Intn(256))
			}
			payload = payload[:rng.Intn(len(payload)+1)]
		} else {
			payload = make([]byte, rng.Intn(40))
			rng.Read(payload)
		}
		d1 := d1UTF8(payload)
		if i%3 == 0 {
			d1 = d1Packed(payload, true)
		}
		for _, k := range []int{1, 2, 5} {
			cs := classes{}.add("p/B", &KotlinMetadata{Kind: k, Version: kmv, Data1: d1, Data2: []string{"g", "x"}})
			_, _ = KotlinInline(MethodRef{Owner: "p/B", Name: "g"}, cs.lookup)
		}
	}
}

// ---- the annotation as ParseClass reads it ----

func (b *classBuilder) intConst(v int32) uint16 {
	return b.add("int:"+string(be4(uint32(v))), append([]byte{cpInteger}, be4(uint32(v))...))
}

func (b *classBuilder) annInt(name string, v int32) []byte {
	return cat(be2(b.utf8(name)), []byte{'I'}, be2(b.intConst(v)))
}

func (b *classBuilder) annIntArray(name string, vs ...int32) []byte {
	out := cat(be2(b.utf8(name)), []byte{'['}, be2(uint16(len(vs))))
	for _, v := range vs {
		out = cat(out, []byte{'I'}, be2(b.intConst(v)))
	}
	return out
}

func (b *classBuilder) annStringArray(name string, ss ...string) []byte {
	out := cat(be2(b.utf8(name)), []byte{'['}, be2(uint16(len(ss))))
	for _, s := range ss {
		out = cat(out, []byte{'s'}, be2(b.utf8(s)))
	}
	return out
}

func TestParseClass_KotlinMetadata(t *testing.T) {
	d1 := d1UTF8(d1Payload(plainRecords(1), pl(3, fn(inlineFlags, 0))))
	b := newClassBuilder()
	rva := rvaBody(
		b.annotation("Lother/Anno;", b.annStringArray("value", "x", "y"), b.annInt("n", 3)),
		b.annotation(kotlinMetadataType,
			b.annIntArray("mv", 2, 2, 0),
			b.annInt("k", 2),
			b.annInt("xi", 48),
			b.annStringArray("d1", d1...),
			b.annStringArray("d2", "g", "Lkotlin/Unit;"),
			b.annString("pn", "p"),
		),
	)
	data := b.assembleClass("p/BKt", "java/lang/Object", nil, nil, nil, [][]byte{b.attr(attrRuntimeVisibleAnnotations, rva)})
	c, err := ParseClass(data)
	if err != nil {
		t.Fatal(err)
	}
	m := c.KotlinMetadata
	if m == nil {
		t.Fatal("no KotlinMetadata")
	}
	want := &KotlinMetadata{Kind: 2, Version: []int{2, 2, 0}, Data1: d1, Data2: []string{"g", "Lkotlin/Unit;"}, Extra: 48}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %+v, want %+v", m, want)
	}
	if len(c.Annotations) != 2 || c.Annotations[1].Type != kotlinMetadataType {
		t.Fatalf("annotations = %+v", c.Annotations)
	}
	cs := classes{"p/BKt": &c}
	if in, err := KotlinInline(MethodRef{Owner: "p/BKt", Name: "g"}, cs.lookup); err != nil || !in {
		t.Fatalf("g inline = %v, %v", in, err)
	}

	t.Run("absent k defaults to a class", func(t *testing.T) {
		b := newClassBuilder()
		rva := rvaBody(b.annotation(kotlinMetadataType, b.annStringArray("d2")))
		c, err := ParseClass(b.assembleClass("p/B", "java/lang/Object", nil, nil, nil, [][]byte{b.attr(attrRuntimeVisibleAnnotations, rva)}))
		if err != nil || c.KotlinMetadata == nil || c.KotlinMetadata.Kind != 1 {
			t.Fatalf("got %+v, %v", c.KotlinMetadata, err)
		}
	})

	t.Run("a mistyped element fails closed", func(t *testing.T) {
		b := newClassBuilder()
		rva := rvaBody(b.annotation(kotlinMetadataType, b.annString("k", "2"), b.annStringArray("d1", d1...), b.annStringArray("d2", "g")))
		c, err := ParseClass(b.assembleClass("p/B", "java/lang/Object", nil, nil, nil, [][]byte{b.attr(attrRuntimeVisibleAnnotations, rva)}))
		if err != nil {
			t.Fatal(err)
		}
		cs := classes{"p/B": &c}
		if _, err := KotlinInline(MethodRef{Owner: "p/B", Name: "g"}, cs.lookup); err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("a javac class has none", func(t *testing.T) {
		b := newClassBuilder()
		rva := rvaBody(b.annotation("Lother/Anno;", b.annString("value", "x")))
		c, err := ParseClass(b.assembleClass("p/J", "java/lang/Object", nil, nil, nil, [][]byte{b.attr(attrRuntimeVisibleAnnotations, rva)}))
		if err != nil || c.KotlinMetadata != nil {
			t.Fatalf("got %+v, %v", c.KotlinMetadata, err)
		}
	})
}

func withVersion(m *KotlinMetadata, v []int) *KotlinMetadata { m.Version = v; return m }

func withMalformed(m *KotlinMetadata, elem string) *KotlinMetadata {
	m.unreadable = "malformed element " + elem
	return m
}

// A multi-release JAR's override is merged into its base class; the merged class answers
// with the base's metadata only when the override carries the same.
func TestReleaseMerge_KotlinMetadata(t *testing.T) {
	plain := func() *KotlinMetadata { return meta(2, plainRecords(1), pl(3, fn(plainFlags, 0)), "g") }
	inline := func() *KotlinMetadata { return meta(2, plainRecords(1), pl(3, fn(inlineFlags, 0)), "g") }
	tests := []struct {
		name       string
		base, over *KotlinMetadata
		wantInline bool
		wantErr    bool
	}{
		{name: "identical metadata: the base answers", base: plain(), over: plain()},
		{name: "identical inline metadata: inline", base: inline(), over: inline(), wantInline: true},
		{name: "base not inline, override inline: withheld", base: plain(), over: inline(), wantErr: true},
		{name: "override without metadata: withheld", base: plain(), wantErr: true},
		{name: "base without metadata: withheld", over: inline(), wantErr: true},
		{name: "neither carries metadata: not Kotlin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const name = "p/BKt"
			all := []Class{{Name: name, Super: "java/lang/Object", KotlinMetadata: tt.base}}
			m := NewReleaseMerge(all)
			if err := m.Merge(VersionedClass{Release: 11, Entry: "META-INF/versions/11/p/BKt.class", Class: Class{Name: name, Super: "java/lang/Object", KotlinMetadata: tt.over}}); err != nil {
				t.Fatal(err)
			}
			got, err := KotlinInline(MethodRef{Owner: name, Name: "g"}, m.Lookup)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if got != tt.wantInline {
				t.Fatalf("inline = %v, want %v", got, tt.wantInline)
			}
		})
	}
}
