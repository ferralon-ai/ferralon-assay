package classfile

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// methodHandle interns a CONSTANT_MethodHandle of the given kind over a constant-pool
// reference (a Methodref/InterfaceMethodref index, or a Fieldref for field kinds).
func (b *classBuilder) methodHandle(kind byte, ref uint16) uint16 {
	raw := append([]byte{cpMethodHandle, kind}, be2(ref)...)
	return b.add("mh:"+string(kind)+":"+string(be2(ref)), raw)
}

// methodType interns a CONSTANT_MethodType.
func (b *classBuilder) methodType(desc string) uint16 {
	di := b.utf8(desc)
	return b.add("mt:"+desc, append([]byte{cpMethodType}, be2(di)...))
}

// stringConst interns a CONSTANT_String.
func (b *classBuilder) stringConst(s string) uint16 {
	si := b.utf8(s)
	return b.add("str:"+s, append([]byte{cpString}, be2(si)...))
}

// invokeDynamicAt interns a CONSTANT_InvokeDynamic naming BootstrapMethods entry bsm.
func (b *classBuilder) invokeDynamicAt(bsm uint16, name, desc string) uint16 {
	nt := b.nameType(name, desc)
	raw := append([]byte{cpInvokeDynamic}, be2(bsm)...)
	raw = append(raw, be2(nt)...)
	return b.add("indy:"+string(be2(bsm))+":"+name+desc, raw)
}

// testMethod is one method for buildClass.
type testMethod struct {
	access     uint16
	name, desc string
	code       []byte // nil: no Code attribute
}

// bootstrapEntry is one raw BootstrapMethods entry: constant-pool indices.
type bootstrapEntry struct {
	method uint16
	args   []uint16
}

// bootstrapAttr encodes a BootstrapMethods attribute body.
func bootstrapAttr(entries []bootstrapEntry) []byte {
	var body bytes.Buffer
	body.Write(be2(uint16(len(entries))))
	for _, e := range entries {
		body.Write(be2(e.method))
		body.Write(be2(uint16(len(e.args))))
		for _, a := range e.args {
			body.Write(be2(a))
		}
	}
	return body.Bytes()
}

// buildClass emits a class with the given access flags, methods and class attributes
// (name -> body). As with build, all interning a method's code relies on must happen first.
func (b *classBuilder) buildClass(thisClass, superClass string, access uint16, methods []testMethod, attrs map[string][]byte) []byte {
	thisIdx := b.class(thisClass)
	superIdx := b.class(superClass)
	codeAttr := b.utf8("Code")
	type mIdx struct{ name, desc uint16 }
	var mi []mIdx
	for _, m := range methods {
		mi = append(mi, mIdx{b.utf8(m.name), b.utf8(m.desc)})
	}
	var attrNames []string
	for n := range attrs {
		attrNames = append(attrNames, n)
	}
	attrIdx := map[string]uint16{}
	for _, n := range attrNames {
		attrIdx[n] = b.utf8(n)
	}

	var buf bytes.Buffer
	buf.Write(be4(0xCAFEBABE))
	buf.Write(be2(0))
	buf.Write(be2(52))
	buf.Write(be2(uint16(len(b.entries) + 1)))
	for _, e := range b.entries {
		buf.Write(e)
	}
	buf.Write(be2(access))
	buf.Write(be2(thisIdx))
	buf.Write(be2(superIdx))
	buf.Write(be2(0)) // interfaces_count
	buf.Write(be2(0)) // fields_count
	buf.Write(be2(uint16(len(methods))))
	for i, m := range methods {
		buf.Write(be2(m.access))
		buf.Write(be2(mi[i].name))
		buf.Write(be2(mi[i].desc))
		if m.code == nil {
			buf.Write(be2(0))
			continue
		}
		var codeBody bytes.Buffer
		codeBody.Write(be2(16))
		codeBody.Write(be2(16))
		codeBody.Write(be4(uint32(len(m.code))))
		codeBody.Write(m.code)
		codeBody.Write(be2(0))
		codeBody.Write(be2(0))
		buf.Write(be2(1))
		buf.Write(be2(codeAttr))
		buf.Write(be4(uint32(codeBody.Len())))
		buf.Write(codeBody.Bytes())
	}
	buf.Write(be2(uint16(len(attrNames))))
	for _, n := range attrNames {
		buf.Write(be2(attrIdx[n]))
		buf.Write(be4(uint32(len(attrs[n]))))
		buf.Write(attrs[n])
	}
	return buf.Bytes()
}

func indyInsn(idx uint16) []byte { return append(append([]byte{0xBA}, be2(idx)...), 0, 0) }

const (
	lmfMetafactoryDesc = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
	concatDesc         = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"
)

// TestParseClass_BindsBootstrapMethods: each invokedynamic edge carries the bootstrap entry its
// constant names, with the bootstrap handle and every static argument decoded, regardless of
// the order the sites and entries appear in.
func TestParseClass_BindsBootstrapMethods(t *testing.T) {
	b := newClassBuilder()
	lmf := b.methodHandle(RefInvokeStatic, b.methodref(cpMethodref, "java/lang/invoke/LambdaMetafactory", "metafactory", lmfMetafactoryDesc))
	concat := b.methodHandle(RefInvokeStatic, b.methodref(cpMethodref, "java/lang/invoke/StringConcatFactory", "makeConcatWithConstants", concatDesc))
	impl := b.methodHandle(RefInvokeStatic, b.methodref(cpMethodref, "com/example/App", "lambda$run$0", "()V"))
	ifaceImpl := b.methodHandle(RefInvokeInterface, b.methodref(cpInterfaceMethodref, "com/example/Svc", "call", "()V"))
	field := b.methodHandle(RefGetField, b.fieldref("com/example/App", "f", "I"))
	samType := b.methodType("()V")
	recipe := b.stringConst("\x01!")
	cls := b.class("com/example/Marker")
	// Site 0 names entry 1 (concat), site 1 names entry 0 (lambda), site 2 names a missing entry.
	s0 := b.invokeDynamicAt(1, "makeConcatWithConstants", "(Lcom/example/App;)Ljava/lang/String;")
	s1 := b.invokeDynamicAt(0, "run", "()Ljava/lang/Runnable;")
	s2 := b.invokeDynamicAt(7, "run", "()Ljava/lang/Runnable;")

	var code bytes.Buffer
	code.Write(indyInsn(s0))
	code.Write(indyInsn(s1))
	code.Write(indyInsn(s2))
	code.WriteByte(0xB1)
	data := b.buildClass("com/example/App", "java/lang/Object", 0x0021,
		[]testMethod{{access: 0x0001, name: "go", desc: "()V", code: code.Bytes()}},
		map[string][]byte{attrBootstrapMethods: bootstrapAttr([]bootstrapEntry{
			{method: lmf, args: []uint16{samType, impl, samType}},
			{method: concat, args: []uint16{recipe, ifaceImpl, field, cls}},
		})})
	got, err := ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	edges := got.Methods[0].Edges
	if len(edges) != 3 {
		t.Fatalf("want 3 edges, got %+v", edges)
	}
	wantLambda := &Bootstrap{
		Method: MethodHandle{Kind: RefInvokeStatic, Ref: MethodRef{"java/lang/invoke/LambdaMetafactory", "metafactory", lmfMetafactoryDesc}},
		Args: []BootstrapArg{
			{MethodType: "()V"},
			{Handle: &MethodHandle{Kind: RefInvokeStatic, Ref: MethodRef{"com/example/App", "lambda$run$0", "()V"}}},
			{MethodType: "()V"},
		},
	}
	wantConcat := &Bootstrap{
		Method: MethodHandle{Kind: RefInvokeStatic, Ref: MethodRef{"java/lang/invoke/StringConcatFactory", "makeConcatWithConstants", concatDesc}},
		Args: []BootstrapArg{
			{},
			{Handle: &MethodHandle{Kind: RefInvokeInterface, Ref: MethodRef{"com/example/Svc", "call", "()V"}}},
			{Handle: &MethodHandle{Kind: RefGetField}},
			{Class: "com/example/Marker"},
		},
	}
	for i, want := range []*Bootstrap{wantConcat, wantLambda, nil} {
		if !reflect.DeepEqual(edges[i].Bootstrap, want) {
			t.Errorf("edge %d Bootstrap = %+v, want %+v", i, edges[i].Bootstrap, want)
		}
		if edges[i].Kind != EdgeDynamic || edges[i].To.Owner != "" {
			t.Errorf("edge %d = %+v, want a dynamic edge with no owner", i, edges[i])
		}
	}
}

// TestParseClass_AccessFlags: abstract classes and interfaces are Abstract; static and private
// methods are flagged.
func TestParseClass_AccessFlags(t *testing.T) {
	tests := []struct {
		name         string
		access       uint16
		wantAbstract bool
	}{
		{"concrete class", 0x0021, false},
		{"abstract class", 0x0421, true},
		{"interface", 0x0601, true},
		{"interface without ACC_ABSTRACT", 0x0201, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newClassBuilder()
			got, err := ParseClass(b.buildClass("com/example/C", "java/lang/Object", tt.access, []testMethod{
				{access: 0x0009, name: "s", desc: "()V", code: []byte{0xB1}},
				{access: 0x0002, name: "p", desc: "()V", code: []byte{0xB1}},
				{access: 0x0001, name: "v", desc: "()V", code: []byte{0xB1}},
			}, nil))
			if err != nil {
				t.Fatalf("ParseClass: %v", err)
			}
			if got.Abstract != tt.wantAbstract {
				t.Errorf("Abstract = %v, want %v", got.Abstract, tt.wantAbstract)
			}
			flags := func(m Method) [2]bool { return [2]bool{m.Static, m.Private} }
			want := [][2]bool{{true, false}, {false, true}, {false, false}}
			for i, m := range got.Methods {
				if flags(m) != want[i] {
					t.Errorf("%s: (Static, Private) = %v, want %v", m.Ref.Name, flags(m), want[i])
				}
			}
		})
	}
}

// TestParseClass_MalformedBootstrapMethodsError: a BootstrapMethods table that cannot be decoded
// fails the class (declared partiality), never a silently dropped or guessed bootstrap.
func TestParseClass_MalformedBootstrapMethodsError(t *testing.T) {
	tests := []struct {
		name  string
		entry func(b *classBuilder) []byte
		want  string
	}{
		{
			name: "bootstrap is not a method handle",
			entry: func(b *classBuilder) []byte {
				return bootstrapAttr([]bootstrapEntry{{method: b.methodType("()V")}})
			},
			want: "not a method handle",
		},
		{
			name: "method-kind handle over a field",
			entry: func(b *classBuilder) []byte {
				return bootstrapAttr([]bootstrapEntry{{method: b.methodHandle(RefInvokeStatic, b.fieldref("a/B", "f", "I"))}})
			},
			want: "not a method handle",
		},
		{
			name: "unknown handle kind",
			entry: func(b *classBuilder) []byte {
				return bootstrapAttr([]bootstrapEntry{{method: b.methodHandle(10, b.methodref(cpMethodref, "a/B", "m", "()V"))}})
			},
			want: "not a method handle",
		},
		{
			name: "argument outside the pool",
			entry: func(b *classBuilder) []byte {
				h := b.methodHandle(RefInvokeStatic, b.methodref(cpMethodref, "a/B", "m", "()V"))
				return bootstrapAttr([]bootstrapEntry{{method: h, args: []uint16{0x7FFF}}})
			},
			want: "bad constant index",
		},
		{
			name: "malformed handle argument",
			entry: func(b *classBuilder) []byte {
				h := b.methodHandle(RefInvokeStatic, b.methodref(cpMethodref, "a/B", "m", "()V"))
				bad := b.methodHandle(RefInvokeVirtual, b.fieldref("a/B", "f", "I"))
				return bootstrapAttr([]bootstrapEntry{{method: h, args: []uint16{bad}}})
			},
			want: "malformed method handle",
		},
		{
			name: "truncated table",
			entry: func(b *classBuilder) []byte {
				h := b.methodHandle(RefInvokeStatic, b.methodref(cpMethodref, "a/B", "m", "()V"))
				full := bootstrapAttr([]bootstrapEntry{{method: h, args: []uint16{h, h}}})
				return full[:len(full)-1]
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newClassBuilder()
			attr := tt.entry(b)
			_, err := ParseClass(b.buildClass("com/example/C", "java/lang/Object", 0x0021, nil, map[string][]byte{attrBootstrapMethods: attr}))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
