package kotlinanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// ingress_parity_test.go — Kotlin parity families gained by the shared jvmingress registry
// (C3): servlet, JAX-RS, @Scheduled, @EventListener, @PostConstruct/@PreDestroy, and the
// Kafka/JMS/Rabbit message listeners. Every fixture is emitted as raw JVMS §4 bytes via the
// kclassBuilder (classemit_test.go) — no kotlinc, no checked-in .class files — so assertions
// run through the real parser and the real recognizer in internal/plugin/kotlinanalysis/ingress.go.

// TestFindIngresses_FamilyAnnotationCases is the C3 census table: one row per newly-gained
// Kotlin family, asserting the exact Kind the registry-fed recognizer emits.
func TestFindIngresses_FamilyAnnotationCases(t *testing.T) {
	cases := []struct {
		name string
		desc string
		kind string
	}{
		{"Scheduled", "Lorg/springframework/scheduling/annotation/Scheduled;", "scheduled"},
		{"EventListener", "Lorg/springframework/context/event/EventListener;", "event_listener"},
		{"PostConstruct", "Ljavax/annotation/PostConstruct;", "lifecycle"},
		{"PreDestroy", "Ljavax/annotation/PreDestroy;", "lifecycle"},
		{"KafkaListener", "Lorg/springframework/kafka/annotation/KafkaListener;", "message_listener"},
		{"JmsListener", "Lorg/springframework/jms/annotation/JmsListener;", "message_listener"},
		{"RabbitListener", "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;", "message_listener"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newKClassBuilder()
			anno := b.anno(tc.desc)
			className := "com/example/entrypoint/" + tc.name + "Bean"
			dir := t.TempDir()
			b.addMethodAnnotated("handle", "()V", []byte{opReturn}, anno)
			writeClassFixture(t, dir, className, b.build(className, "java/lang/Object"))

			res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("FindIngresses: %v", err)
			}
			if len(res.Ingresses) != 1 {
				t.Fatalf("want exactly 1 ingress for @%s, got %d: %+v", tc.name, len(res.Ingresses), res.Ingresses)
			}
			ing := res.Ingresses[0]
			if ing.Kind != tc.kind {
				t.Errorf("@%s ingress kind = %q, want %q", tc.name, ing.Kind, tc.kind)
			}
			if ing.Symbol.Name != "handle" {
				t.Errorf("@%s ingress symbol name = %q, want handle", tc.name, ing.Symbol.Name)
			}
		})
	}
}

// TestFindIngresses_JaxRsPathAndGetIsHttpRoute mirrors the Java lexical parity test
// (javaanalysis/ingress_test.go TestFindIngresses_JaxRsPathAndVerbs): a class-level @Path
// plus a method-level @GET together identify an http_route ingress. The recognizer's
// methodMapping matches the FIRST route annotation found on the method's own annotation list
// (it does not merge multiple route annotations on one method), so the selector reflects
// whichever one the fixture lists first — asserted as observed, not assumed.
func TestFindIngresses_JaxRsPathAndGetIsHttpRoute(t *testing.T) {
	dir := t.TempDir()
	b := newKClassBuilder()
	b.addClassAnnotation(b.anno("Ljavax/ws/rs/Path;", kannoElem{name: "value", value: "/res"}))
	getAnno := b.anno("Ljavax/ws/rs/GET;")
	b.addMethodAnnotated("read", "()V", []byte{opReturn}, getAnno)
	writeClassFixture(t, dir, "com/example/jaxrs/Resource", b.build("com/example/jaxrs/Resource", "java/lang/Object"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 1 {
		t.Fatalf("want exactly 1 ingress (the @GET method), got %d: %+v", len(res.Ingresses), res.Ingresses)
	}
	ing := res.Ingresses[0]
	if ing.Kind != "http_route" {
		t.Errorf("JAX-RS @GET ingress kind = %q, want http_route", ing.Kind)
	}
	if ing.Symbol.Name != "read" {
		t.Errorf("JAX-RS ingress symbol name = %q, want read", ing.Symbol.Name)
	}
	// @GET carries no value/path element of its own, and classRequestMappingPath only reads
	// @RequestMapping (Spring) for a class-level base path — JAX-RS's class-level @Path is
	// not consulted for the base. So the only observed selector content is the verb.
	if ing.Selector != "GET" {
		t.Errorf("JAX-RS @GET selector = %q, want %q (verb-only: class-level @Path base is not read by this adapter)", ing.Selector, "GET")
	}
}

// TestFindIngresses_JaxRsPostIsHttpRoute confirms the second JAX-RS verb the dispatch names
// (@Path+@POST), independent of the @GET case above.
func TestFindIngresses_JaxRsPostIsHttpRoute(t *testing.T) {
	dir := t.TempDir()
	b := newKClassBuilder()
	b.addClassAnnotation(b.anno("Ljavax/ws/rs/Path;", kannoElem{name: "value", value: "/res"}))
	postAnno := b.anno("Ljavax/ws/rs/POST;")
	b.addMethodAnnotated("write", "()V", []byte{opReturn}, postAnno)
	writeClassFixture(t, dir, "com/example/jaxrs/Resource", b.build("com/example/jaxrs/Resource", "java/lang/Object"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 1 {
		t.Fatalf("want exactly 1 ingress (the @POST method), got %d: %+v", len(res.Ingresses), res.Ingresses)
	}
	ing := res.Ingresses[0]
	if ing.Kind != "http_route" {
		t.Errorf("JAX-RS @POST ingress kind = %q, want http_route", ing.Kind)
	}
	if ing.Selector != "POST" {
		t.Errorf("JAX-RS @POST selector = %q, want %q", ing.Selector, "POST")
	}
}

// TestFindIngresses_ServletDoGetDetected mirrors the Java lexical test: a doGet method on a
// class whose direct superclass name ends in HttpServlet is a servlet ingress. Kind: servlet.
func TestFindIngresses_ServletDoGetDetected(t *testing.T) {
	dir := t.TempDir()
	b := newKClassBuilder()
	b.addMethod("doGet", "()V", []byte{opReturn})
	b.addMethod("doPost", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/web/FetchServlet",
		b.build("com/example/web/FetchServlet", "javax/servlet/http/HttpServlet"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 2 {
		t.Fatalf("want exactly 2 ingresses (doGet + doPost), got %d: %+v", len(res.Ingresses), res.Ingresses)
	}
	for _, ing := range res.Ingresses {
		if ing.Kind != "servlet" {
			t.Errorf("servlet method ingress kind = %q, want servlet (ingress: %+v)", ing.Kind, ing)
		}
		if ing.Symbol.Name != "doGet" && ing.Symbol.Name != "doPost" {
			t.Errorf("unexpected servlet ingress symbol name = %q", ing.Symbol.Name)
		}
	}
}

// TestFindIngresses_NonServletDoGetNotIngress mirrors the Java negative: a doGet on a class
// that does NOT extend *HttpServlet is not a servlet ingress (and carries no other recognized
// annotation, so it is not any kind of ingress).
func TestFindIngresses_NonServletDoGetNotIngress(t *testing.T) {
	dir := t.TempDir()
	b := newKClassBuilder()
	b.addMethod("doGet", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/web/NotAServlet",
		b.build("com/example/web/NotAServlet", "java/lang/Object"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Errorf("non-servlet doGet must not be an ingress; got %+v", res.Ingresses)
	}
}

// TestFindIngresses_TransitiveServletSuperNotRecognized pins the "direct-superclass, no
// transitive resolution" contract the schema calls out explicitly: a class extending an
// intermediate class that itself extends HttpServlet is NOT recognized, because
// superClassMatchesSuffix (ingress.go) only inspects the class's own direct Super field —
// it never walks up more than one level. This is the implemented behavior, asserted as
// observed (matching Java's isServletBase, which is equally name-only/non-transitive).
func TestFindIngresses_TransitiveServletSuperNotRecognized(t *testing.T) {
	dir := t.TempDir()

	// BaseServlet extends HttpServlet directly but declares no doGet of its own.
	base := newKClassBuilder()
	base.addMethod("init", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/web/BaseServlet",
		base.build("com/example/web/BaseServlet", "javax/servlet/http/HttpServlet"))

	// MyServlet extends BaseServlet (intermediate) — NOT HttpServlet directly.
	my := newKClassBuilder()
	my.addMethod("doGet", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/web/MyServlet",
		my.build("com/example/web/MyServlet", "com/example/web/BaseServlet"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Errorf("MyServlet.doGet extends an intermediate (BaseServlet), not HttpServlet directly; "+
			"the implemented recognizer does name-only DIRECT-superclass matching with no transitive "+
			"resolution, so this must NOT be recognized as a servlet ingress. got %+v", res.Ingresses)
	}
}

// TestFindIngresses_NoRecognizedAnnotationOrServletSuperNoFabrication is the Kotlin inv.5
// no-fabrication case: a class with methods, but none carrying a recognized entrypoint
// annotation and no servlet supertype, must yield zero ingresses. This is the negative
// counterpart to TestFindIngresses_MappingWithoutStereotypeIsIngress
// (spring_ingress_test.go), which already pins the deliberate positive parity change
// (a @GetMapping alone, with no stereotype, IS an ingress) — not duplicated here.
func TestFindIngresses_NoRecognizedAnnotationOrServletSuperNoFabrication(t *testing.T) {
	dir := t.TempDir()
	b := newKClassBuilder()
	b.addMethod("helper", "()V", []byte{opReturn})
	b.addMethod("compute", "()V", []byte{opReturn})
	writeClassFixture(t, dir, "com/example/plain/PlainBean",
		b.build("com/example/plain/PlainBean", "java/lang/Object"))

	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Errorf("plain class with no recognized annotation and no servlet supertype must yield zero ingresses; got %+v", res.Ingresses)
	}
}
