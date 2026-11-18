package kotlinanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A handler that carries no mapping of its own is an ingress when the superclass method it
// overrides declares one, as Spring resolves the mapping; a method that overrides nothing
// mapped is not.
func TestFindIngresses_InheritedRoute(t *testing.T) {
	dir := t.TempDir()
	base := newKClassBuilder()
	base.addClassAnnotation(base.anno("Lorg/springframework/web/bind/annotation/RequestMapping;", kannoElem{name: "value", value: "/v1"}))
	base.addMethodAnnotated("list", "()V", []byte{opReturn}, base.anno(descGetMapping, kannoElem{name: "value", value: "/pets"}))
	writeClassFixture(t, dir, "com/example/api/PetsBase", base.build("com/example/api/PetsBase", "java/lang/Object"))

	impl := newKClassBuilder()
	impl.addMethod("list", "()V", []byte{opReturn})
	impl.addMethod("other", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/api/PetsImpl", impl.build("com/example/api/PetsImpl", "com/example/api/PetsBase"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	got := map[string]string{}
	for _, in := range res.Ingresses {
		got[in.Symbol.Package+"."+in.Symbol.Enclosing+"."+in.Symbol.Name] = in.Selector
	}
	want := map[string]string{
		"com.example.api.PetsBase.list": "GET /v1/pets",
		"com.example.api.PetsImpl.list": "GET /v1/pets",
	}
	if len(got) != len(want) {
		t.Fatalf("ingresses = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s selector = %q, want %q (all %v)", k, got[k], v, got)
		}
	}
}

// A route declared on an interface in a dependency JAR (a generated API published as its own
// artifact) roots the first-party override that implements it.
func TestReachability_RouteInheritedFromDependency(t *testing.T) {
	dir := gradleJacksonBuild(t, `    implementation("com.example:pets-api:1.0")`)
	api := newKClassBuilder()
	api.addMethodAnnotated("parse", "()V", []byte{opReturn},
		api.anno(descGetMapping, kannoElem{name: "value", value: "/parse"}))
	writeGradleCacheJar(t, dir, "com.example", "pets-api", "1.0", map[string][]byte{
		"com/example/api/PetsApi": api.build("com/example/api/PetsApi", "java/lang/Object"),
	})
	ctrl := newKClassBuilder()
	ctrl.addMethod("parse", "()V", append(ctrl.invokeVirtual(objectMapper, "readValue", readValueDesc), opReturn))
	writeClassFixture(t, dir, "com/example/web/PetsController",
		ctrl.buildWithInterfaces("com/example/web/PetsController", "java/lang/Object", "com/example/api/PetsApi"))

	res := reach(t, dir, readValueSink)
	if len(res.Paths) != 1 {
		t.Fatalf("paths = %v, want one from PetsController.parse (reasons %v)", res.Paths, res.Partiality.Reasons)
	}
	if got := res.Paths[0].Ingress.Name; got != "parse" {
		t.Errorf("ingress = %+v, want PetsController.parse", res.Paths[0].Ingress)
	}
}

// A route declared on a concrete method of a dependency superclass, or on a default method of a
// dependency interface, that the first-party class does not override is the class's handler:
// the search roots it on the dependency's method and the listing names it.
func TestReachability_RouteNotOverriddenFromDependency(t *testing.T) {
	tests := []struct {
		name  string
		super string
		ifc   string
	}{
		{"superclass concrete method", "com/example/api/PetsBase", ""},
		{"interface default method", "java/lang/Object", "com/example/api/PetsApi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := gradleJacksonBuild(t, `    implementation("com.example:pets-api:1.0")`)
			lib := tt.super
			if tt.ifc != "" {
				lib = tt.ifc
			}
			api := newKClassBuilder()
			api.addMethodAnnotated("parse", "()V", append(api.invokeVirtual(objectMapper, "readValue", readValueDesc), opReturn),
				api.anno(descGetMapping, kannoElem{name: "value", value: "/parse"}))
			libBytes := api.build(lib, "java/lang/Object")
			if tt.ifc != "" {
				libBytes = asInterface(api, libBytes)
			}
			writeGradleCacheJar(t, dir, "com.example", "pets-api", "1.0", map[string][]byte{lib: libBytes})
			ctrl := newKClassBuilder()
			ctrl.addMethod("other", "()V", []byte{opReturn})
			if tt.ifc != "" {
				writeClassFixture(t, dir, "com/example/web/PetsController", ctrl.buildWithInterfaces("com/example/web/PetsController", "java/lang/Object", tt.ifc))
			} else {
				writeClassFixture(t, dir, "com/example/web/PetsController", ctrl.build("com/example/web/PetsController", tt.super))
			}

			res := reach(t, dir, readValueSink)
			if len(res.Paths) != 1 {
				t.Fatalf("paths = %v, want one rooted at the dependency's parse (reasons %v)", res.Paths, res.Partiality.Reasons)
			}
			if got := res.Paths[0].Ingress; got.Name != "parse" || got.Enclosing != "PetsBase" && got.Enclosing != "PetsApi" {
				t.Errorf("ingress = %+v, want the dependency's parse", got)
			}

			ing, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir}, cacheGraph(t, dir))
			if err != nil {
				t.Fatalf("FindIngresses: %v", err)
			}
			listed := false
			for _, in := range ing.Ingresses {
				listed = listed || in.Symbol.Name == "parse" && in.Selector == "GET /parse"
			}
			if !listed {
				t.Errorf("listing lacks the dependency's parse: %+v", ing.Ingresses)
			}
		})
	}
}

// asInterface rewrites built's access_flags to ACC_PUBLIC|ACC_INTERFACE|ACC_ABSTRACT, so
// a method it carries is an interface default method rather than a class method.
func asInterface(b *kclassBuilder, built []byte) []byte {
	const accInterfaceAbstractPublic = 0x0601
	off := 10
	for _, e := range b.entries {
		off += len(e)
	}
	out := append([]byte{}, built...)
	copy(out[off:], be2(accInterfaceAbstractPublic))
	return out
}
