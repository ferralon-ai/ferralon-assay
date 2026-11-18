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
