package jvmingress

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

func anno(name string, path string) classfile.Annotation {
	a := classfile.Annotation{Type: "Lorg/springframework/web/bind/annotation/" + name + ";"}
	if path != "" {
		a.Elements = []classfile.AnnotationElement{{Name: "value", Value: path}}
	}
	return a
}

func meth(name, desc string, annos ...classfile.Annotation) classfile.Method {
	return classfile.Method{Ref: ref("", name, desc), Annotations: annos}
}

func ref(owner, name, desc string) classfile.MethodRef {
	return classfile.MethodRef{Owner: owner, Name: name, Descriptor: desc}
}

func cls(name, super string, ifaces []string, annos []classfile.Annotation, methods ...classfile.Method) classfile.Class {
	for i := range methods {
		methods[i].Ref.Owner = name
	}
	return classfile.Class{Name: name, Super: super, Interfaces: ifaces, Annotations: annos, Methods: methods}
}

func abstract(m classfile.Method) classfile.Method { m.Abstract = true; return m }

func lookupOf(classes []classfile.Class) func(string) (*classfile.Class, bool) {
	by := map[string]*classfile.Class{}
	for i := range classes {
		by[classes[i].Name] = &classes[i]
	}
	return func(n string) (*classfile.Class, bool) { c, ok := by[n]; return c, ok }
}

func TestCompiled(t *testing.T) {
	const obj = "java/lang/Object"
	get := func(p string) classfile.Annotation { return anno("GetMapping", p) }
	tests := []struct {
		name    string
		classes []classfile.Class
		want    map[string]string // method ref -> selector
	}{
		{"own method", []classfile.Class{
			cls("a/C", obj, nil, nil, meth("list", "()V", get("/pets"))),
		}, map[string]string{"a/C.list()V": "GET /pets"}},
		{"interface inherited", []classfile.Class{
			cls("a/Api", obj, nil, nil, abstract(meth("list", "()V", get("/pets")))),
			cls("a/Impl", obj, []string{"a/Api"}, nil, meth("list", "()V")),
		}, map[string]string{"a/Impl.list()V": "GET /pets"}},
		{"abstract superclass inherited", []classfile.Class{
			cls("a/Base", obj, nil, nil, abstract(meth("list", "()V", get("/pets")))),
			cls("a/Impl", "a/Base", nil, nil, meth("list", "()V")),
		}, map[string]string{"a/Impl.list()V": "GET /pets"}},
		{"transitive interface", []classfile.Class{
			cls("a/Root", obj, nil, nil, abstract(meth("list", "()V", get("/pets")))),
			cls("a/Mid", obj, []string{"a/Root"}, nil),
			cls("a/Base", obj, []string{"a/Mid"}, nil),
			cls("a/Impl", "a/Base", nil, nil, meth("list", "()V")),
		}, map[string]string{"a/Impl.list()V": "GET /pets"}},
		{"default method not overridden", []classfile.Class{
			cls("a/Api", obj, nil, nil, meth("list", "()V", get("/pets"))),
			cls("a/Impl", obj, []string{"a/Api"}, nil),
		}, map[string]string{"a/Api.list()V": "GET /pets"}},
		{"generic interface with bridge", []classfile.Class{
			cls("a/Api", obj, nil, nil, abstract(meth("put", "(Ljava/lang/Object;)V", anno("PutMapping", "/pets")))),
			cls("a/Impl", obj, []string{"a/Api"}, nil,
				meth("put", "(La/Pet;)V"),
				meth("put", "(Ljava/lang/Object;)V")), // synthetic bridge
		}, map[string]string{"a/Impl.put(La/Pet;)V": "PUT /pets", "a/Impl.put(Ljava/lang/Object;)V": "PUT /pets"}},
		{"class-level base path", []classfile.Class{
			cls("a/Api", obj, nil, []classfile.Annotation{anno("RequestMapping", "/v1")}, abstract(meth("list", "()V", get("/pets")))),
			cls("a/Impl", obj, []string{"a/Api"}, nil, meth("list", "()V")),
		}, map[string]string{"a/Impl.list()V": "GET /v1/pets"}},
		{"non-entry annotation not rooted", []classfile.Class{
			cls("a/Api", obj, nil, nil, abstract(meth("list", "()V", anno("Deprecated", "")))),
			cls("a/Impl", obj, []string{"a/Api"}, nil, meth("list", "()V"), meth("other", "()V", anno("Autowired", ""))),
		}, map[string]string{}},
		{"different parameter count not inherited", []classfile.Class{
			cls("a/Api", obj, nil, nil, abstract(meth("list", "(I)V", get("/pets")))),
			cls("a/Impl", obj, []string{"a/Api"}, nil, meth("list", "()V")),
		}, map[string]string{}},
		{"static and private do not inherit", []classfile.Class{
			cls("a/Api", obj, nil, nil, abstract(meth("list", "()V", get("/pets")))),
			cls("a/Impl", obj, []string{"a/Api"}, nil,
				func() classfile.Method { m := meth("list", "()V"); m.Static = true; return m }()),
		}, map[string]string{}},
		{"unloaded supertype contributes nothing here", []classfile.Class{
			cls("a/Impl", obj, []string{"gen/Api"}, nil, meth("list", "()V")),
		}, map[string]string{}},
		{"delegate-pattern generated controller", []classfile.Class{
			cls("gen/PetsApi", obj, nil, []classfile.Annotation{anno("RequestMapping", "/api")}, meth("getPets", "()V", get("/pets"))),
			cls("a/Delegate", obj, nil, nil, meth("getPets", "()V")),
		}, map[string]string{"gen/PetsApi.getPets()V": "GET /api/pets"}},
		{"route preferred over lifecycle", []classfile.Class{
			cls("a/Api", obj, nil, nil, abstract(meth("x", "()V", anno("PostConstruct", ""), get("/x")))),
			cls("a/Impl", obj, []string{"a/Api"}, nil, meth("x", "()V")),
		}, map[string]string{"a/Impl.x()V": "GET /x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]string{}
			for _, e := range Compiled(tt.classes, lookupOf(tt.classes)) {
				got[e.Ref.Owner+"."+e.Ref.Name+e.Ref.Descriptor] = e.Selector
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if g, ok := got[k]; !ok || g != v {
					t.Errorf("%s = %q (present %v), want %q; all %v", k, g, ok, v, got)
				}
			}
		})
	}
}

func TestUnresolvedSupertype(t *testing.T) {
	const obj = "java/lang/Object"
	tests := []struct {
		name    string
		classes []classfile.Class
		target  string
		want    bool
	}{
		{"all resolved", []classfile.Class{cls("a/Api", obj, nil, nil), cls("a/Impl", obj, []string{"a/Api"}, nil, meth("m", "()V"))}, "a/Impl", false},
		{"unloaded interface", []classfile.Class{cls("a/Impl", obj, []string{"gen/Api"}, nil, meth("m", "()V"))}, "a/Impl", true},
		{"unloaded transitive", []classfile.Class{cls("a/Mid", obj, []string{"gen/Api"}, nil), cls("a/Impl", "a/Mid", nil, nil, meth("m", "()V"))}, "a/Impl", true},
		{"platform supertype is not unresolved", []classfile.Class{cls("a/Impl", obj, []string{"java/io/Serializable"}, nil, meth("m", "()V"))}, "a/Impl", false},
		{"no concrete method, nothing to root", []classfile.Class{cls("a/Impl", obj, []string{"gen/Api"}, nil, abstract(meth("m", "()V")))}, "a/Impl", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lk := lookupOf(tt.classes)
			c, _ := lk(tt.target)
			if got := UnresolvedSupertype(c, lk); got != tt.want {
				t.Errorf("UnresolvedSupertype = %v, want %v", got, tt.want)
			}
		})
	}
}
