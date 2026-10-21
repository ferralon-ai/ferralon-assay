package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// A JAR's copy of a class the JVM may load from the JDK instead is not concrete: the search over
// it cannot refute the sink.
func TestReachClosureIndex_SkipsBootOnlyCopies(t *testing.T) {
	stub := classfile.MethodRef{Owner: "java/util/Hashtable", Name: "put", Descriptor: "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"}
	own := classfile.MethodRef{Owner: "com/example/Lib", Name: "run", Descriptor: "()V"}
	parser := classfile.MethodRef{Owner: "javax/xml/parsers/SAXParser", Name: "parse", Descriptor: "(Lorg/xml/sax/InputSource;Lorg/xml/sax/helpers/DefaultHandler;)V"}
	annotation := classfile.MethodRef{Owner: "javax/annotation/Lib", Name: "run", Descriptor: "()V"}
	rc := &reachClosure{}
	rc.index([]classfile.Class{
		{Name: stub.Owner, Methods: []classfile.Method{{Ref: stub}}},
		{Name: own.Owner, Methods: []classfile.Method{{Ref: own}}},
		{Name: parser.Owner, Methods: []classfile.Method{{Ref: parser}}},
		{Name: annotation.Owner, Methods: []classfile.Method{{Ref: annotation}}},
	}, 17)
	if rc.concrete(stub) {
		t.Error("a classpath copy of a java/ method counts as concrete")
	}
	if _, ok := rc.class(stub.Owner); ok {
		t.Error("a classpath copy of a java/ class is indexed")
	}
	if rc.concrete(parser) {
		t.Error("a classpath copy of a javax/xml/parsers method counts as concrete")
	}
	if !rc.concrete(own) {
		t.Error("a dependency's own method is not concrete")
	}
	if !rc.concrete(annotation) {
		t.Error("a javax/annotation method is not concrete on JDK 17, which lacks the package")
	}
}
