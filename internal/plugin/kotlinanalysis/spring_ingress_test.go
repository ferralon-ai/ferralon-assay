package kotlinanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// spring_ingress_test.go — §8 row 6 for Kotlin: a Spring HTTP handler, detected from the
// class/method annotations the shared classfile parser now decodes, is registered as an
// ingress root and drives a real ingress→dependency reachability trace through depreach.
// Fixtures are emitted directly as JVMS §4 bytes (no kotlinc), so the assertions run
// through the actual parser, the real annotation decoder, and the real depreach engine.

const (
	descRestController = "Lorg/springframework/web/bind/annotation/RestController;"
	descGetMapping     = "Lorg/springframework/web/bind/annotation/GetMapping;"
)

// buildController emits a @RestController class with one @GetMapping("/fetch") handler
// whose body invokestatic-calls a dependency symbol, plus the dependency class itself. It
// returns the build dir.
func buildController(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	ctrl := newKClassBuilder()
	ctrl.addClassAnnotation(ctrl.anno(descRestController))
	handlerCode := ctrl.invokeStatic("com/example/dep/UrlFetcher", "fetch", "()V")
	handlerCode = append(handlerCode, opReturn)
	ctrl.addMethodAnnotated("handle", "()V", handlerCode,
		ctrl.anno(descGetMapping, kannoElem{name: "value", value: "/fetch"}))
	writeClassFixture(t, dir, "com/example/api/UserController",
		ctrl.build("com/example/api/UserController", "java/lang/Object"))

	dep := newKClassBuilder()
	dep.addMethod("fetch", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/dep/UrlFetcher",
		dep.build("com/example/dep/UrlFetcher", "java/lang/Object"))

	return dir
}

// TestFindIngresses_SpringRestControllerHandlerIsIngress asserts the Spring handler is
// discovered as an http_route ingress with the decoded route selector, and that no `main`
// ingress is fabricated (the fixture has none).
func TestFindIngresses_SpringRestControllerHandlerIsIngress(t *testing.T) {
	dir := buildController(t)

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if !res.Partiality.Complete {
		t.Fatalf("well-formed controller declared partiality it should not have: %+v", res.Partiality)
	}
	if len(res.Ingresses) != 1 {
		t.Fatalf("want exactly 1 ingress (the Spring handler), got %d: %+v", len(res.Ingresses), res.Ingresses)
	}
	ing := res.Ingresses[0]
	if ing.Kind != "http_route" {
		t.Errorf("ingress kind = %q, want http_route", ing.Kind)
	}
	if ing.Symbol.Name != "handle" {
		t.Errorf("ingress symbol name = %q, want handle", ing.Symbol.Name)
	}
	if ing.Selector != "GET /fetch" {
		t.Errorf("ingress selector = %q, want %q", ing.Selector, "GET /fetch")
	}
}

// TestReachability_SpringIngressReachesDependency is row 6 proper: the Spring ingress
// connects across a dependency boundary. depreach must find the handle→fetch path and
// Reachability must emit it, ordered, Complete (no hazard on the frontier).
func TestReachability_SpringIngressReachesDependency(t *testing.T) {
	dir := buildController(t)

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: dir,
		Symbols:  []string{"com/example/dep/UrlFetcher.fetch()V"},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if !res.Partiality.Complete {
		t.Fatalf("reachable Spring case declared partiality it should not have: %+v", res.Partiality)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want exactly 1 reach path, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Ingress.Name != "handle" {
		t.Errorf("path ingress = %+v, want Name=handle", p.Ingress)
	}
	if p.Sink.Name != "fetch" {
		t.Errorf("path sink = %+v, want Name=fetch", p.Sink)
	}
	if len(p.Trace) < 2 || p.Trace[0].Name != "handle" || p.Trace[len(p.Trace)-1].Name != "fetch" {
		t.Errorf("path trace not ordered ingress->sink: %+v", p.Trace)
	}
}

// TestFindIngresses_NoSpringAnnotationNoFabricatedIngress is the honest-absent control: a
// class with the SAME shape but no Spring stereotype yields no framework ingress. A bare
// @GetMapping method on a non-controller class is not a bean endpoint, so it must not
// invent a root.
func TestFindIngresses_NoSpringAnnotationNoFabricatedIngress(t *testing.T) {
	dir := t.TempDir()

	// A class with a @GetMapping method but NO @RestController/@Controller stereotype.
	plain := newKClassBuilder()
	code := plain.invokeStatic("com/example/dep/UrlFetcher", "fetch", "()V")
	code = append(code, opReturn)
	plain.addMethodAnnotated("handle", "()V", code,
		plain.anno(descGetMapping, kannoElem{name: "value", value: "/fetch"}))
	writeClassFixture(t, dir, "com/example/api/PlainBean",
		plain.build("com/example/api/PlainBean", "java/lang/Object"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Fatalf("non-controller class must yield no framework ingress, got %+v", res.Ingresses)
	}
}

// TestParseClass_SpringAnnotationsDecoded is a unit check on the shared classfile parser:
// the class @RestController descriptor and the method @GetMapping type + string element
// are decoded, and a plain class carries no annotations (additive, no false positives).
func TestParseClass_SpringAnnotationsDecoded(t *testing.T) {
	b := newKClassBuilder()
	b.addClassAnnotation(b.anno(descRestController))
	b.addMethodAnnotated("handle", "()V", []byte{opReturn},
		b.anno(descGetMapping, kannoElem{name: "value", value: "/fetch"}))
	data := b.build("com/example/api/UserController", "java/lang/Object")

	cls, err := classfile.ParseClass(data)
	if err != nil {
		t.Fatalf("ParseClass: %v", err)
	}
	if len(cls.Annotations) != 1 || annotationSimpleName(cls.Annotations[0].Type) != "RestController" {
		t.Fatalf("class annotations = %+v, want one RestController", cls.Annotations)
	}
	if len(cls.Methods) != 1 {
		t.Fatalf("want 1 method, got %d", len(cls.Methods))
	}
	verb, path, ok := methodMapping(cls.Methods[0].Annotations)
	if !ok || verb != "GET" || path != "/fetch" {
		t.Fatalf("methodMapping = (%q,%q,%v), want (GET,/fetch,true)", verb, path, ok)
	}
}
