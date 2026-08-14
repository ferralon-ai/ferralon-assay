//go:build jvmcorpus

// This file is OPT-IN behind the `jvmcorpus` build tag: it parses a REAL Maven JAR
// of genuine javac bytecode to prove the parser holds at scale on output no
// hand-built fixture can match. It is excluded from the default `go test ./...`
// because it needs a JAR supplied out-of-band (no binary blob is committed):
//
//	FERRALON_TEST_JAR=/path/to/some.jar go test -tags jvmcorpus \
//	    ./internal/plugin/javaanalysis/classfile/
//
// The parse itself is offline — the JAR is read, never executed, and in production
// it comes from the customer's per-build cache (zero-egress preserved).
package classfile

import (
	"os"
	"testing"
)

func TestLoadJar_RealBytecodeParsesCleanly(t *testing.T) {
	jar := os.Getenv("FERRALON_TEST_JAR")
	if jar == "" {
		t.Skip("set FERRALON_TEST_JAR to a real .jar to run the scale proof")
	}
	res, err := LoadJar(jar)
	if err != nil {
		t.Fatalf("LoadJar(%q): %v", jar, err)
	}
	if len(res.Classes) == 0 {
		t.Fatalf("parsed no classes from %q", jar)
	}
	// Every application .class entry must parse: a real dependency JAR is exactly the
	// input the analyzer must read without walling, so any Failed entry is a defect
	// to see, not tolerate.
	if len(res.Failed) != 0 {
		t.Errorf("%d/%d class entries failed to parse (want 0):", len(res.Failed), res.Entries)
		for _, f := range res.Failed {
			t.Errorf("  %s", f)
		}
	}

	var methods, edges, dynamic int
	for _, c := range res.Classes {
		for _, m := range c.Methods {
			methods++
			for _, e := range m.Edges {
				edges++
				if e.Kind == EdgeDynamic {
					dynamic++
				}
			}
		}
	}
	t.Logf("parsed %d/%d classes, %d methods, %d edges, %d invokedynamic sites",
		len(res.Classes), res.Entries, methods, edges, dynamic)
	if edges == 0 {
		t.Errorf("extracted 0 call edges from real bytecode — the walker is not finding invokes")
	}
}
