package kotlinanalysis

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// beanwire_test.go — overlay #K unit coverage. wireBeanEdges operates on the loaded
// []classfile.Class (Kotlin's bytecode-native input model), so it is exercised directly on
// hand-built classfile.Class values — the same struct-level style the Java lane's
// beanmerge/beanmodel tests use. No kotlinc/JVM toolchain exists in this environment; the
// classfile shape here is exactly what the production classfile parser yields.

func anno(desc string) classfile.Annotation { return classfile.Annotation{Type: desc} }

const (
	svcAnno       = "Lorg/springframework/stereotype/Service;"
	autowiredAnno = "Lorg/springframework/beans/factory/annotation/Autowired;"
	primaryAnno   = "Lorg/springframework/context/annotation/Primary;"
	greeterType   = "com/ex/Greeter"
	greeterImpl   = "com/ex/GreeterImpl"
	greetName     = "greet"
	greetDesc     = "()Ljava/lang/String;"
	mailerType    = "com/ex/Mailer"
	sendName      = "send"
	sendDesc      = "()V"
)

// greeterInterface is the declared interface bean type — an abstract method, no body.
func greeterInterface() classfile.Class {
	return classfile.Class{
		Name:    greeterType,
		Super:   "java/lang/Object",
		Methods: []classfile.Method{{Ref: classfile.MethodRef{Owner: greeterType, Name: greetName, Descriptor: greetDesc}, Abstract: true}},
	}
}

// greeterImplClass is the concrete @Service impl declaring greet().
func greeterImplClass() classfile.Class {
	return classfile.Class{
		Name:        greeterImpl,
		Super:       "java/lang/Object",
		Interfaces:  []string{greeterType},
		Annotations: []classfile.Annotation{anno(svcAnno)},
		Methods:     []classfile.Method{{Ref: classfile.MethodRef{Owner: greeterImpl, Name: greetName, Descriptor: greetDesc}}},
	}
}

// helloCaller is a class with an @Autowired Greeter field whose h() dispatches through the
// interface (invokeinterface Greeter.greet) — the site the wiring must bridge to the impl.
func helloCaller() classfile.Class {
	return classfile.Class{
		Name:  "com/ex/Hello",
		Super: "java/lang/Object",
		Fields: []classfile.Field{{
			Name:        "greeter",
			Descriptor:  "L" + greeterType + ";",
			Annotations: []classfile.Annotation{anno(autowiredAnno)},
		}},
		Methods: []classfile.Method{{
			Ref:   classfile.MethodRef{Owner: "com/ex/Hello", Name: "h", Descriptor: "()V"},
			Edges: []classfile.Edge{{To: classfile.MethodRef{Owner: greeterType, Name: greetName, Descriptor: greetDesc}, Kind: classfile.EdgeInterface}},
		}},
	}
}

func hasEdge(edges []plugin.CallEdge, callerSub, calleeSub string) bool {
	for _, e := range edges {
		if strings.Contains(e.Caller.SCIP, callerSub) && strings.Contains(e.Callee.SCIP, calleeSub) {
			return true
		}
	}
	return false
}

func hasStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestWireBeanEdges_UniqueResolvesEdge: an @Autowired interface field with a single
// concrete impl is bridged — the resolved caller→impl edge appears and no bean_ambiguous
// is declared (the wiring is certain).
func TestWireBeanEdges_UniqueResolvesEdge(t *testing.T) {
	classes := []classfile.Class{greeterInterface(), greeterImplClass(), helloCaller()}

	edges, reasons := wireBeanEdges(classes)

	if !hasEdge(edges, "Hello.h", "GreeterImpl.greet") {
		t.Errorf("resolved bean edge Hello.h → GreeterImpl.greet not emitted; edges=%+v", edges)
	}
	if hasStr(reasons, plugin.PartialReasonBeanAmbiguous) {
		t.Errorf("bean_ambiguous wrongly declared on a unique resolution: %v", reasons)
	}
}

// TestWireBeanEdges_AmbiguousStaysPartial: two impls of an interface with no @Primary/
// @Qualifier is honest residue — NO edge is emitted and bean_ambiguous is declared. inv.5:
// never guess a bean.
func TestWireBeanEdges_AmbiguousStaysPartial(t *testing.T) {
	mailer := classfile.Class{
		Name:    mailerType,
		Super:   "java/lang/Object",
		Methods: []classfile.Method{{Ref: classfile.MethodRef{Owner: mailerType, Name: sendName, Descriptor: sendDesc}, Abstract: true}},
	}
	impl := func(name string) classfile.Class {
		return classfile.Class{
			Name:        name,
			Super:       "java/lang/Object",
			Interfaces:  []string{mailerType},
			Annotations: []classfile.Annotation{anno(svcAnno)},
			Methods:     []classfile.Method{{Ref: classfile.MethodRef{Owner: name, Name: sendName, Descriptor: sendDesc}}},
		}
	}
	notifier := classfile.Class{
		Name:        "com/ex/Notifier",
		Super:       "java/lang/Object",
		Annotations: []classfile.Annotation{anno(svcAnno)},
		Fields: []classfile.Field{{
			Name:        "mailer",
			Descriptor:  "L" + mailerType + ";",
			Annotations: []classfile.Annotation{anno(autowiredAnno)},
		}},
		Methods: []classfile.Method{{
			Ref:   classfile.MethodRef{Owner: "com/ex/Notifier", Name: "go", Descriptor: "()V"},
			Edges: []classfile.Edge{{To: classfile.MethodRef{Owner: mailerType, Name: sendName, Descriptor: sendDesc}, Kind: classfile.EdgeInterface}},
		}},
	}
	classes := []classfile.Class{mailer, impl("com/ex/SmtpMailer"), impl("com/ex/SesMailer"), notifier}

	edges, reasons := wireBeanEdges(classes)

	if hasEdge(edges, "Notifier.go", "Mailer") || hasEdge(edges, "Notifier.go", "SmtpMailer") || hasEdge(edges, "Notifier.go", "SesMailer") {
		t.Errorf("an ambiguous injection was guessed to an edge (inv.5 violation); edges=%+v", edges)
	}
	if !hasStr(reasons, plugin.PartialReasonBeanAmbiguous) {
		t.Errorf("bean_ambiguous localizer not declared for the ambiguous injection: %v", reasons)
	}
}

// TestWireBeanEdges_PrimaryResolvesAmbiguity: the same two impls, one @Primary, resolves to
// a unique edge — @Primary is honored, the edge lands, and no ambiguity is declared.
func TestWireBeanEdges_PrimaryResolvesAmbiguity(t *testing.T) {
	mailer := classfile.Class{
		Name:    mailerType,
		Super:   "java/lang/Object",
		Methods: []classfile.Method{{Ref: classfile.MethodRef{Owner: mailerType, Name: sendName, Descriptor: sendDesc}, Abstract: true}},
	}
	impl := func(name string, primary bool) classfile.Class {
		annos := []classfile.Annotation{anno(svcAnno)}
		if primary {
			annos = append(annos, anno(primaryAnno))
		}
		return classfile.Class{
			Name:        name,
			Super:       "java/lang/Object",
			Interfaces:  []string{mailerType},
			Annotations: annos,
			Methods:     []classfile.Method{{Ref: classfile.MethodRef{Owner: name, Name: sendName, Descriptor: sendDesc}}},
		}
	}
	notifier := classfile.Class{
		Name:        "com/ex/Notifier",
		Super:       "java/lang/Object",
		Annotations: []classfile.Annotation{anno(svcAnno)},
		Fields: []classfile.Field{{
			Name:        "mailer",
			Descriptor:  "L" + mailerType + ";",
			Annotations: []classfile.Annotation{anno(autowiredAnno)},
		}},
		Methods: []classfile.Method{{
			Ref:   classfile.MethodRef{Owner: "com/ex/Notifier", Name: "go", Descriptor: "()V"},
			Edges: []classfile.Edge{{To: classfile.MethodRef{Owner: mailerType, Name: sendName, Descriptor: sendDesc}, Kind: classfile.EdgeInterface}},
		}},
	}
	classes := []classfile.Class{mailer, impl("com/ex/SmtpMailer", true), impl("com/ex/SesMailer", false), notifier}

	edges, reasons := wireBeanEdges(classes)

	if !hasEdge(edges, "Notifier.go", "SmtpMailer.send") {
		t.Errorf("@Primary impl edge Notifier.go → SmtpMailer.send not emitted; edges=%+v", edges)
	}
	if hasStr(reasons, plugin.PartialReasonBeanAmbiguous) {
		t.Errorf("bean_ambiguous wrongly declared once @Primary broke the tie: %v", reasons)
	}
}

// TestWireBeanEdges_NoBeansByteIdentical: with no stereotype/@Bean classes present, the
// overlay is a strict no-op — no edges, no reasons — so the call graph is byte-identical to
// today (the inv.5 "no beans" floor).
func TestWireBeanEdges_NoBeansByteIdentical(t *testing.T) {
	// Interface + caller, but the impl carries no stereotype annotation → no beans.
	plainImpl := greeterImplClass()
	plainImpl.Annotations = nil
	classes := []classfile.Class{greeterInterface(), plainImpl, helloCaller()}

	edges, reasons := wireBeanEdges(classes)

	if edges != nil {
		t.Errorf("no-bean overlay emitted edges: %+v", edges)
	}
	if reasons != nil {
		t.Errorf("no-bean overlay declared reasons: %v", reasons)
	}
}
