package classfile

import (
	"archive/zip"
	"bytes"
	"testing"
)

// ---- annotation/field/parameter builder helpers ----
//
// These extend the classBuilder in classfile_test.go with the JVMS §4.7.16/§4.7.18
// structures the bean-model parser additions decode. As there, every helper interns
// its cp entries as a side effect, so all body bytes must be built before the class
// header's constant_pool_count is emitted (assembleClass does exactly that).

// attr wraps a prebuilt attribute body with its name_index + u4 length.
func (b *classBuilder) attr(name string, body []byte) []byte {
	out := be2(b.utf8(name))
	out = append(out, be4(uint32(len(body)))...)
	return append(out, body...)
}

// annString is one string-valued element_value_pair: name_index + 's' + utf8 index.
func (b *classBuilder) annString(name, val string) []byte {
	out := be2(b.utf8(name))
	out = append(out, 's')
	return append(out, be2(b.utf8(val))...)
}

// annClass is one class-valued element_value_pair: name_index + 'c' + descriptor utf8.
func (b *classBuilder) annClass(name, desc string) []byte {
	out := be2(b.utf8(name))
	out = append(out, 'c')
	return append(out, be2(b.utf8(desc))...)
}

// annEnum is one enum-valued element_value_pair: name_index + 'e' + type + const utf8.
func (b *classBuilder) annEnum(name, typeDesc, constName string) []byte {
	out := be2(b.utf8(name))
	out = append(out, 'e')
	out = append(out, be2(b.utf8(typeDesc))...)
	return append(out, be2(b.utf8(constName))...)
}

// annArrayClass is one array element_value_pair holding class constants: name + '[' +
// count + each ('c' + descriptor utf8).
func (b *classBuilder) annArrayClass(name string, descs ...string) []byte {
	out := be2(b.utf8(name))
	out = append(out, '[')
	out = append(out, be2(uint16(len(descs)))...)
	for _, d := range descs {
		out = append(out, 'c')
		out = append(out, be2(b.utf8(d))...)
	}
	return out
}

// annotation assembles one annotation structure: type_index + num_pairs + pairs.
func (b *classBuilder) annotation(typeDesc string, pairs ...[]byte) []byte {
	out := be2(b.utf8(typeDesc))
	out = append(out, be2(uint16(len(pairs)))...)
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

// rvaBody is a RuntimeVisibleAnnotations attribute body: num_annotations + annotations.
func rvaBody(annos ...[]byte) []byte {
	out := be2(uint16(len(annos)))
	for _, a := range annos {
		out = append(out, a...)
	}
	return out
}

// paramAnnos is one parameter's annotation list: num_annotations + annotations.
func paramAnnos(annos ...[]byte) []byte {
	out := be2(uint16(len(annos)))
	for _, a := range annos {
		out = append(out, a...)
	}
	return out
}

// rvpaBody is a RuntimeVisibleParameterAnnotations attribute body: a u1 parameter
// count followed by each parameter's annotation list (built with paramAnnos).
func rvpaBody(params ...[]byte) []byte {
	out := []byte{byte(len(params))}
	for _, p := range params {
		out = append(out, p...)
	}
	return out
}

// field assembles one field_info: access_flags + name + descriptor + attributes.
func (b *classBuilder) field(access uint16, name, desc string, attrs ...[]byte) []byte {
	out := be2(access)
	out = append(out, be2(b.utf8(name))...)
	out = append(out, be2(b.utf8(desc))...)
	out = append(out, be2(uint16(len(attrs)))...)
	for _, a := range attrs {
		out = append(out, a...)
	}
	return out
}

// method assembles one method_info with no Code (bodyless): access + name + desc +
// attributes. Used to attach RuntimeVisibleParameterAnnotations without bytecode.
func (b *classBuilder) method(access uint16, name, desc string, attrs ...[]byte) []byte {
	out := be2(access)
	out = append(out, be2(b.utf8(name))...)
	out = append(out, be2(b.utf8(desc))...)
	out = append(out, be2(uint16(len(attrs)))...)
	for _, a := range attrs {
		out = append(out, a...)
	}
	return out
}

// assembleClass emits a complete .class from prebuilt field/method/class-attribute
// byte blocks. Every helper that produced those blocks has already interned its cp
// entries; the class/super/interface names are interned here (appended, never
// shifting an existing index) before the constant_pool_count is written.
func (b *classBuilder) assembleClass(thisClass, superClass string, ifaces []string, fields, methods, classAttrs [][]byte) []byte {
	thisIdx := b.class(thisClass)
	superIdx := b.class(superClass)
	ifaceIdxs := make([]uint16, len(ifaces))
	for i, f := range ifaces {
		ifaceIdxs[i] = b.class(f)
	}

	var buf bytes.Buffer
	buf.Write(be4(0xCAFEBABE))
	buf.Write(be2(0))
	buf.Write(be2(52))
	buf.Write(be2(uint16(len(b.entries) + 1)))
	for _, e := range b.entries {
		buf.Write(e)
	}
	buf.Write(be2(0x0021))
	buf.Write(be2(thisIdx))
	buf.Write(be2(superIdx))
	buf.Write(be2(uint16(len(ifaceIdxs))))
	for _, ii := range ifaceIdxs {
		buf.Write(be2(ii))
	}
	buf.Write(be2(uint16(len(fields))))
	for _, f := range fields {
		buf.Write(f)
	}
	buf.Write(be2(uint16(len(methods))))
	for _, m := range methods {
		buf.Write(m)
	}
	buf.Write(be2(uint16(len(classAttrs))))
	for _, a := range classAttrs {
		buf.Write(a)
	}
	return buf.Bytes()
}

// ---- tests ----

// TestParseClass_FieldAnnotationsAndDescriptor proves the field loop now retains a
// field's name, declared type descriptor, and RuntimeVisibleAnnotations (the surface
// @Autowired/@Value/@Qualifier field injection reads), instead of discarding them.
func TestParseClass_FieldAnnotationsAndDescriptor(t *testing.T) {
	b := newClassBuilder()
	autowired := b.annotation("Lorg/springframework/beans/factory/annotation/Autowired;")
	qualifier := b.annotation("Lorg/springframework/beans/factory/annotation/Qualifier;",
		b.annString("value", "primary"))
	fSvc := b.field(0x0002, "svc", "Lcom/example/Svc;", b.attr(attrRuntimeVisibleAnnotations, rvaBody(autowired, qualifier)))
	fPlain := b.field(0x0002, "count", "I") // no annotations, still retained

	cls, err := ParseClass(b.assembleClass("com/example/App", "java/lang/Object", nil,
		[][]byte{fSvc, fPlain}, nil, nil))
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	if len(cls.Fields) != 2 {
		t.Fatalf("want 2 fields, got %d: %+v", len(cls.Fields), cls.Fields)
	}
	svc := cls.Fields[0]
	if svc.Name != "svc" || svc.Descriptor != "Lcom/example/Svc;" {
		t.Errorf("field 0 = {%q %q}, want {svc Lcom/example/Svc;}", svc.Name, svc.Descriptor)
	}
	if len(svc.Annotations) != 2 {
		t.Fatalf("want 2 field annotations, got %d: %+v", len(svc.Annotations), svc.Annotations)
	}
	if svc.Annotations[0].Type != "Lorg/springframework/beans/factory/annotation/Autowired;" {
		t.Errorf("anno 0 type = %q", svc.Annotations[0].Type)
	}
	q := svc.Annotations[1]
	if len(q.Elements) != 1 || q.Elements[0].Name != "value" || q.Elements[0].Value != "primary" {
		t.Errorf("@Qualifier elements = %+v, want value=primary", q.Elements)
	}
	if cls.Fields[1].Name != "count" || cls.Fields[1].Descriptor != "I" || len(cls.Fields[1].Annotations) != 0 {
		t.Errorf("plain field = %+v, want {count I, no annos}", cls.Fields[1])
	}
}

// TestParseClass_ParameterAnnotations proves RuntimeVisibleParameterAnnotations
// (JVMS §4.7.18) decodes into one annotation list per formal parameter, in order, so
// a constructor-injection @Qualifier is keyed to its parameter slot.
func TestParseClass_ParameterAnnotations(t *testing.T) {
	b := newClassBuilder()
	qA := b.annotation("Lorg/springframework/beans/factory/annotation/Qualifier;", b.annString("value", "a"))
	ctor := b.method(0x0001, "<init>", "(Lcom/example/Svc;Ljava/lang/String;)V",
		b.attr(attrRuntimeVisibleParameterAnnotations, rvpaBody(paramAnnos(qA), paramAnnos())))

	cls, err := ParseClass(b.assembleClass("com/example/App", "java/lang/Object", nil,
		nil, [][]byte{ctor}, nil))
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	if len(cls.Methods) != 1 {
		t.Fatalf("want 1 method, got %d", len(cls.Methods))
	}
	pa := cls.Methods[0].ParameterAnnotations
	if len(pa) != 2 {
		t.Fatalf("want 2 parameter slots, got %d: %+v", len(pa), pa)
	}
	if len(pa[0]) != 1 || pa[0][0].Type != "Lorg/springframework/beans/factory/annotation/Qualifier;" {
		t.Errorf("param 0 annos = %+v, want one @Qualifier", pa[0])
	}
	if len(pa[0][0].Elements) != 1 || pa[0][0].Elements[0].Value != "a" {
		t.Errorf("param 0 @Qualifier value = %+v, want a", pa[0][0].Elements)
	}
	if len(pa[1]) != 0 {
		t.Errorf("param 1 annos = %+v, want none", pa[1])
	}
}

// TestParseClass_AnnotationElementKinds is the table-driven guard for element-value
// decoding: string ('s') lands in Elements, class ('c') lands in ClassElements as an
// internal name, a class array captures the first class element, and enum ('e') is
// still discarded (traversed only).
func TestParseClass_AnnotationElementKinds(t *testing.T) {
	tests := []struct {
		name      string
		pair      func(b *classBuilder) []byte
		wantStr   []AnnotationElement
		wantClass []AnnotationElement
	}{
		{
			name:      "string element retained",
			pair:      func(b *classBuilder) []byte { return b.annString("value", "/users") },
			wantStr:   []AnnotationElement{{Name: "value", Value: "/users"}},
			wantClass: nil,
		},
		{
			name:      "class element retained as internal name",
			pair:      func(b *classBuilder) []byte { return b.annClass("value", "Lcom/example/Foo;") },
			wantStr:   nil,
			wantClass: []AnnotationElement{{Name: "value", Value: "com/example/Foo"}},
		},
		{
			name:      "class array captures first class element",
			pair:      func(b *classBuilder) []byte { return b.annArrayClass("value", "Lcom/example/A;", "Lcom/example/B;") },
			wantStr:   nil,
			wantClass: []AnnotationElement{{Name: "value", Value: "com/example/A"}},
		},
		{
			name:      "enum element discarded",
			pair:      func(b *classBuilder) []byte { return b.annEnum("mode", "Lcom/example/Mode;", "FAST") },
			wantStr:   nil,
			wantClass: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newClassBuilder()
			anno := b.annotation("Lcom/example/Ann;", tc.pair(b))
			cls, err := ParseClass(b.assembleClass("com/example/App", "java/lang/Object", nil,
				nil, nil, [][]byte{b.attr(attrRuntimeVisibleAnnotations, rvaBody(anno))}))
			if err != nil {
				t.Fatalf("ParseClass: %v", err)
			}
			if len(cls.Annotations) != 1 {
				t.Fatalf("want 1 class annotation, got %d", len(cls.Annotations))
			}
			got := cls.Annotations[0]
			if !equalElems(got.Elements, tc.wantStr) {
				t.Errorf("Elements = %+v, want %+v", got.Elements, tc.wantStr)
			}
			if !equalElems(got.ClassElements, tc.wantClass) {
				t.Errorf("ClassElements = %+v, want %+v", got.ClassElements, tc.wantClass)
			}
		})
	}
}

func equalElems(a, b []AnnotationElement) bool {
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

// TestLoadZip_ReadsSelectedResources proves LoadJarWithResources' resource capability:
// a non-.class entry matching the predicate is read into Resources, the .class parse
// and Entries accounting are unchanged, and a nil predicate collects nothing
// (byte-identical to LoadJar).
func TestLoadZip_ReadsSelectedResources(t *testing.T) {
	gb := newClassBuilder()
	callee := gb.methodref(cpMethodref, "com/example/Dep", "sink", "()V")
	good := gb.build("com/example/app/Good", "java/lang/Object", "m", "()V",
		append(append([]byte{0xB8}, be2(callee)...), 0xB1))

	factories := []byte("org.springframework.boot.autoconfigure.EnableAutoConfiguration=com.example.MyAutoConfig\n")
	imports := []byte("com.example.MyAutoConfig\n")

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	writeEntry := func(name string, data []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	writeEntry("com/example/app/Good.class", good)
	writeEntry("META-INF/spring.factories", factories)
	writeEntry("META-INF/spring/com.example.MyAutoConfig.imports", imports)
	writeEntry("META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\n")) // not requested
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	want := func(name string) bool {
		return name == "META-INF/spring.factories" ||
			(len(name) > len("META-INF/spring/") && name[:len("META-INF/spring/")] == "META-INF/spring/")
	}
	res, err := loadZip(zr, want)
	if err != nil {
		t.Fatalf("loadZip: %v", err)
	}
	if len(res.Classes) != 1 || res.Classes[0].Name != "com/example/app/Good" {
		t.Fatalf("want exactly the Good class, got %+v", res.Classes)
	}
	if res.Entries != 1 {
		t.Errorf("Entries = %d, want 1 (resources must not count)", res.Entries)
	}
	if len(res.Resources) != 2 {
		t.Fatalf("want 2 resources, got %d: %v", len(res.Resources), keysOf(res.Resources))
	}
	if !bytes.Equal(res.Resources["META-INF/spring.factories"], factories) {
		t.Errorf("spring.factories bytes mismatch")
	}
	if !bytes.Equal(res.Resources["META-INF/spring/com.example.MyAutoConfig.imports"], imports) {
		t.Errorf("AutoConfiguration.imports bytes mismatch")
	}
	if _, ok := res.Resources["META-INF/MANIFEST.MF"]; ok {
		t.Errorf("MANIFEST.MF must not be collected (predicate did not select it)")
	}

	// nil predicate: byte-identical to LoadJar — no resources.
	zr2, _ := zip.NewReader(bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()))
	res2, err := loadZip(zr2, nil)
	if err != nil {
		t.Fatalf("loadZip nil: %v", err)
	}
	if res2.Resources != nil {
		t.Errorf("nil predicate must collect no resources, got %v", keysOf(res2.Resources))
	}
	if len(res2.Classes) != 1 || res2.Entries != 1 {
		t.Errorf("nil-predicate class/entry accounting changed: %d classes, %d entries", len(res2.Classes), res2.Entries)
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
