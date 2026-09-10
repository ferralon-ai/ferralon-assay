package classfile

import (
	"archive/zip"
	"bytes"
	"testing"
)

// TestParseClass_UnresolvableInvokeIsError_NotSilentDrop is the parser-hardening
// guard the C8 re-review's out-of-scope finding asked for: a class that parses far
// enough to walk its Code but whose invoke site references a corrupt constant-pool
// index must be a PARSE ERROR, not a silently dropped edge. A well-formed invoke
// always resolves; an unresolvable one is malformed bytecode, and silently omitting
// the edge would hide the call path it carries — a false not_exploitable seam. The
// honest behavior is to surface it so the class becomes a completeness hazard (Gap).
func TestParseClass_UnresolvableInvokeIsError_NotSilentDrop(t *testing.T) {
	b := newClassBuilder()
	// invokevirtual #0xFFFF — an out-of-range constant-pool index no well-formed class
	// emits — followed by return.
	code := []byte{0xB6, 0xFF, 0xFF, 0xB1}
	data := b.build("com/example/Corrupt", "java/lang/Object", "m", "()V", code)

	if _, err := ParseClass(data); err == nil {
		t.Fatal("invoke referencing a corrupt constant-pool index must be a parse error, not a silently dropped edge")
	}
}

// TestLoadZip_MalformedInvokeBecomesAGapNotSilentComplete carries the same guarantee
// to the JAR layer that feeds the dependency graph: a class whose only defect is a
// corrupt invoke ref lands in Failed (a completeness hazard the caller declares),
// never in Classes as if it were fully searched. This is what keeps buildDependencyGraph
// from reading such a JAR as a silent-complete closure and licensing a false
// not_exploitable (inv.5).
func TestLoadZip_MalformedInvokeBecomesAGapNotSilentComplete(t *testing.T) {
	// A structurally valid class whose method body issues invokevirtual against an
	// out-of-range constant-pool index.
	mb := newClassBuilder()
	corrupt := mb.build("com/example/app/Corrupt", "java/lang/Object", "m", "()V",
		[]byte{0xB6, 0xFF, 0xFF, 0xB1})

	// A good class alongside it, to prove one malformed class does not blind the rest.
	gb := newClassBuilder()
	callee := gb.methodref(cpMethodref, "com/example/Dep", "sink", "()V")
	good := gb.build("com/example/app/Good", "java/lang/Object", "m", "()V",
		append(append([]byte{0xB8}, be2(callee)...), 0xB1))

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for name, data := range map[string][]byte{
		"com/example/app/Good.class":    good,
		"com/example/app/Corrupt.class": corrupt,
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	res, err := loadZip(zr, nil)
	if err != nil {
		t.Fatalf("loadZip: %v", err)
	}
	if len(res.Classes) != 1 || res.Classes[0].Name != "com/example/app/Good" {
		t.Fatalf("want exactly the Good class parsed, got %+v", res.Classes)
	}
	if len(res.Failed) != 1 {
		t.Fatalf("malformed-invoke class must be recorded as a Failed hazard, got Failed=%v", res.Failed)
	}
	if !bytes.Contains([]byte(res.Failed[0]), []byte("Corrupt.class")) {
		t.Errorf("Failed entry should name the corrupt class, got %q", res.Failed[0])
	}
}
