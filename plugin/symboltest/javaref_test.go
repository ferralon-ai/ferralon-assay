package symboltest

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// indexJavaRef drives the REAL first-party Java producer (javaanalysis.IndexSymbols)
// over the offline testdata/javaref fixture. It is pure-Go lexical source parsing —
// no JVM, no scip-java, no toolchain on PATH, no network — so unlike goref (which
// gates on `go`), it runs unconditionally. It reads the fixture as text and
// executes none of it (§C6).
func indexJavaRef(t *testing.T) []plugin.Symbol {
	t.Helper()
	res, err := javaanalysis.IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{
		BuildDir: "testdata/javaref",
	})
	if err != nil {
		t.Fatalf("IndexSymbols on testdata/javaref: %v", err)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("IndexSymbols emitted no symbols for the javaref fixture")
	}
	return res.Symbols
}

// TestJavaReferenceProfile is the C2 MEASURED-RED golden table. Driven against the
// real lexical producer it FAILS on merge, by design: four must-match rows target
// a canonical Want the current producer cannot satisfy (see JavaReferenceProfile /
// execution/golden-red-reasons.md). This RED is the Phase-0 deliverable — the
// benchmark that fails for the expected current gaps — and PLAN-242 turns it green
// by populating the structured identity. A green here before PLAN-242 would mean
// the profile was written down to match today's arity-based emitter, which §C2's
// inverse control forbids. The companion TestJavaReferenceProfile_RedSetIsExactly
// proves the failure set is EXACTLY the enumerated four and nothing else.
func TestJavaReferenceProfile(t *testing.T) {
	AssertProfile(t, JavaReferenceProfile(), indexJavaRef(t))
}

// TestJavaReferenceProfile_RedSetIsExactly automates §C2's acceptance check: run
// the golden target, capture the regression set, and diff it against the reason
// list — the two sets must be EQUAL, not merely overlapping. It calls Evaluate
// directly (the pure decision core, no testing.T) so it can assert on the findings
// without itself going red, and it stays GREEN precisely when the measured red is
// the intended one. A new gap (extra regression) or a silently-closed one (missing
// regression) fails it, catching drift the always-red TestJavaReferenceProfile
// cannot distinguish.
func TestJavaReferenceProfile_RedSetIsExactly(t *testing.T) {
	findings := Evaluate(JavaReferenceProfile(), indexJavaRef(t))

	got := map[string]bool{}
	for _, f := range findings {
		if f.Kind != FindingRegression {
			// Any non-regression failure (missing category, row-state conflict,
			// silent closure) is an authoring/producer fault, not a measured gap.
			if f.IsFailure() {
				t.Errorf("unexpected non-regression failure: %s", f.Message)
			}
			continue
		}
		got[f.Category+"|"+f.Construct] = true
	}

	for key := range javaReferenceRedReasons {
		if !got[key] {
			t.Errorf("expected measured-red row %q (reason %s) did NOT regress: the gap closed silently — promote it or fix the deposit", key, javaReferenceRedReasons[key])
		}
	}
	for key := range got {
		if _, ok := javaReferenceRedReasons[key]; !ok {
			t.Errorf("unmeasured red row %q has no reason in execution/golden-red-reasons.md (§C2: every failing row needs a named reason)", key)
		}
	}

	if t.Failed() {
		t.Logf("regression set:\n%s", renderSet(got))
		t.Logf("reason set:\n%s", renderReasons(javaReferenceRedReasons))
	}
}

func renderSet(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		out += "  " + k + "\n"
	}
	return out
}

func renderReasons(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		out += fmt.Sprintf("  %s -> %s\n", k, m[k])
	}
	return out
}
