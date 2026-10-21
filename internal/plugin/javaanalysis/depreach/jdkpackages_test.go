package depreach

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

func TestBootOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		jdk  int
		want bool
	}{
		{"java/util/Hashtable", 0, true},
		{"java/util/Hashtable", 21, true},
		{"javax/xml/parsers/SAXParser", 21, true},
		{"javax/xml/parsers/SAXParser", 8, true},
		{"javax/xml/parsers/SAXParser", 0, true},
		{"org/w3c/dom/Node", 17, true},
		{"org/xml/sax/helpers/DefaultHandler", 11, true},
		{"javax/servlet/GenericServlet", 0, false},
		{"org/w3c/dom/svg/SVGDocument", 21, false},
		// javax.annotation left the JDK in 11 (JEP 320).
		{"javax/annotation/PostConstruct", 8, true},
		{"javax/annotation/PostConstruct", 17, false},
		{"javax/annotation/PostConstruct", 0, true},
		{"javax/annotation/PostConstruct", 23, false},
		{"javax/annotation/PostConstruct", 12, true}, // a release the table does not cover
		{"javax/servlet/GenericServlet", 12, false},
		// A release after the newest covered one may have added any package under the JDK's namespaces.
		{"javax/servlet/GenericServlet", 99, true},
		{"org/w3c/dom/svg/SVGDocument", 99, true},
		{"jdk/incubator/foo/Bar", 99, true},
		{"javax/xml/parsers/SAXParser", 99, true},
		{"com/acme/Foo", 99, false},
		{"javaxx/Foo", 99, false},
		{"Unpackaged", 0, false},
	} {
		if got := BootOnly(tc.name, tc.jdk); got != tc.want {
			t.Errorf("BootOnly(%q, %d) = %v, want %v", tc.name, tc.jdk, got, tc.want)
		}
	}
}

// TestJDKPackages_CoverPlatform: every package the engine takes for the JDK 21 boot layer's is one
// jdkPackages has JDK 21 define, so a classpath copy of it is never walked on 21.
func TestJDKPackages_CoverPlatform(t *testing.T) {
	if want := [...]int{8, 11, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}; jdkReleases != want {
		t.Fatalf("jdkReleases = %v, want %v", jdkReleases, want)
	}
	bit := uint16(1) << slices.Index(jdkReleases[:], 21)
	for p := range platformPackages {
		if jdkPackages[p]&bit == 0 {
			t.Errorf("%s is a JDK 21 platform package jdkPackages lacks", p)
		}
	}
	for p, mask := range jdkPackages {
		if mask == 0 || mask>>len(jdkReleases) != 0 {
			t.Errorf("%s: mask %b names no covered release", p, mask)
		}
	}
}

// TestReach_JDKPackageCopies: a JAR's copy of a class in a package the JDK defines may not be the
// body that runs, so a call into it is unopened rather than walked; a package the JDK does not
// define is walked.
func TestReach_JDKPackageCopies(t *testing.T) {
	const (
		parser  = "javax/xml/parsers/SAXParser"
		parse   = "(Lorg/xml/sax/InputSource;Lorg/xml/sax/helpers/DefaultHandler;)V"
		handler = "com/acme/Handler"
	)
	// xml-apis' SAXParser.parse never calls the handler; the JDK's runs the parse that does.
	xmlAPIs := []classfile.Class{
		mainCalls(
			edge(classfile.EdgeSpecial, handler, "<init>", "()V"),
			edge(classfile.EdgeVirtual, parser, "parse", parse),
		),
		{Name: parser, Super: objectClass, Abstract: true, Public: true, Methods: []classfile.Method{
			pubMethod(parser, "<init>", "()V"),
			pubMethod(parser, "parse", parse),
		}},
		{Name: handler, Super: objectClass, Public: true, Methods: []classfile.Method{
			pubMethod(handler, "<init>", "()V"),
			emptyFinalize(handler),
			callsSink(handler, "startElement", "(Ljava/lang/String;)V"),
		}},
	}
	staticSink := func(owner string) classfile.Class {
		m := callsSink(owner, "run", "()V")
		m.Static = true
		return classfile.Class{Name: owner, Super: objectClass, Public: true, Methods: []classfile.Method{m}}
	}
	callsRun := func(owner string) classfile.Class {
		return mainCalls(edge(classfile.EdgeStatic, owner, "run", "()V"))
	}
	const servlet, annotation, parsers = "javax/servlet/Lib", "javax/annotation/Lib", "javax/xml/parsers/Lib"
	runHoleCases(t, []holeCase{
		{
			// Nothing else on the classpath lists the package: the copy itself defines it, so a call
			// with no argument to call back through is unopened, not a JDK leaf.
			name:    "a JAR's own class in a JDK package is not taken for the JDK's leaf",
			classes: []classfile.Class{callsRun(parsers), staticSink(parsers)},
			cp:      Classpath{JDK: 21},
			want:    Undetermined, why: parsers,
		},
		{
			name:    "a JAR's own javax/xml/parsers/SAXParser does not stand in for the JDK's",
			classes: xmlAPIs,
			cp:      Classpath{JDK: 21},
			want:    Undetermined, why: parser,
		},
		{
			name:    "the same on an unrecorded JDK",
			classes: xmlAPIs,
			want:    Undetermined, why: parser,
		},
		{
			name:    "a JAR's javax/servlet class is walked",
			classes: []classfile.Class{callsRun(servlet), staticSink(servlet)},
			want:    ReachableCandidate, via: "Lib.run",
		},
		{
			name:    "a JAR's javax/annotation class is walked on a JDK without the package",
			classes: []classfile.Class{callsRun(annotation), staticSink(annotation)},
			cp:      Classpath{JDK: 17},
			want:    ReachableCandidate, via: "Lib.run",
		},
		{
			name:    "the same on JDK 8, which defines the package, is unopened",
			classes: []classfile.Class{callsRun(annotation), staticSink(annotation)},
			cp:      Classpath{JDK: 8},
			want:    Undetermined, why: annotation,
		},
		{
			name:    "the same on an unrecorded JDK",
			classes: []classfile.Class{callsRun(annotation), staticSink(annotation)},
			want:    Undetermined, why: annotation,
		},
		{
			name:    "a JAR's javax/servlet class is unopened on a JDK newer than the table",
			classes: []classfile.Class{callsRun(servlet), staticSink(servlet)},
			cp:      Classpath{JDK: 99},
			want:    Undetermined, why: servlet,
		},
	})
}
