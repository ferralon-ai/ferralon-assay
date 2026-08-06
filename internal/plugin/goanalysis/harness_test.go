package goanalysis

import (
	"context"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// assertParses asserts the generated source is structurally valid Go (the
// skeleton "compiles structurally" claim), without requiring the deps resolve.
func assertParses(t *testing.T, src string) {
	t.Helper()
	if _, err := parser.ParseFile(token.NewFileSet(), "harness_test.go", src, parser.AllErrors); err != nil {
		t.Errorf("generated harness must be structurally valid Go: %v\n%s", err, src)
	}
}

// TestGenerateHarness_EmitsSkeletonCallingSink asserts the emitted source imports
// the sink's package and calls the sink symbol, is declared a SKELETON (not a
// working exploit), and carries a TODO for attacker-controlled input.
func TestGenerateHarness_EmitsSkeletonCallingSink(t *testing.T) {
	sink := "scip-go gomod tegron.test/fixturemod . tegron.test/fixturemod/util/Sink()."
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{
		Sink: sink,
		Kind: "unit",
	})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if res.Source == "" {
		t.Fatal("expected generated source, got empty")
	}
	if !res.Skeleton {
		t.Error("harness must be declared a skeleton")
	}
	if !strings.Contains(res.Source, "tegron.test/fixturemod/util") {
		t.Errorf("source must import the sink package; got:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "Sink") {
		t.Errorf("source must call the sink symbol; got:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "TODO") {
		t.Errorf("source must mark attacker-controlled input with a TODO; got:\n%s", res.Source)
	}
	// A skeleton that does not prove exploitability is declared Partial, never Complete.
	if res.Partiality.Complete {
		t.Error("a reproducer skeleton must declare Partial (not a working exploit)")
	}
	if hasReason(res.Partiality.Reasons, plugin.PartialReasonUnsupported) {
		t.Error("harness is real now; must not use unsupported_phase1")
	}
	assertParses(t, res.Source)
}

// TestGenerateHarness_MethodSinkUsesReceiverType asserts a method sink SCIP
// (receiver-qualified) yields source that references the receiver type.
func TestGenerateHarness_MethodSink(t *testing.T) {
	sink := "scip-go gomod tegron.test/fixturemod . tegron.test/fixturemod/service/Service#Handle()."
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{Sink: sink, Kind: "unit"})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if !strings.Contains(res.Source, "service") || !strings.Contains(res.Source, "Handle") {
		t.Errorf("method sink source must reference receiver pkg + method; got:\n%s", res.Source)
	}
	if !res.Skeleton {
		t.Error("must be a skeleton")
	}
}

// TestGenerateHarness_UnparseableSinkIsPartial asserts that a sink id that cannot
// be parsed into package+symbol declares Partial with a reason, not an error.
func TestGenerateHarness_UnparseableSinkIsPartial(t *testing.T) {
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{
		Sink: "not-a-scip-id",
		Kind: "unit",
	})
	if err != nil {
		t.Fatalf("GenerateHarness: unparseable sink is declared partial, not a hard error: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("unparseable sink must declare Partial")
	}
	if len(res.Partiality.Reasons) == 0 {
		t.Error("unparseable sink must carry a partiality reason")
	}
}
