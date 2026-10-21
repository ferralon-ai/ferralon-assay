package kotlinanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// A JAR's copy of a java/ class never runs, so a sink it declares is not concrete.
func TestConcreteMethods_SkipsBootOnlyCopies(t *testing.T) {
	stub := classfile.MethodRef{Owner: "java/util/Hashtable", Name: "put", Descriptor: "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"}
	own := classfile.MethodRef{Owner: "com/example/Lib", Name: "run", Descriptor: "()V"}
	got := concreteMethods([]classfile.Class{
		{Name: stub.Owner, Methods: []classfile.Method{{Ref: stub}}},
		{Name: own.Owner, Methods: []classfile.Method{{Ref: own}}},
	})
	if got[stub.String()] {
		t.Error("a classpath copy of a java/ method counts as concrete")
	}
	if !got[own.String()] {
		t.Error("a dependency's own method is not concrete")
	}
}
