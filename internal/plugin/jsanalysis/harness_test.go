package jsanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestGenerateHarness_EmitsSkeletonCallingModuleFunc asserts the emitted source
// require()s the sink's module and calls a module-level sink function, is declared a
// SKELETON (not a working exploit), and carries a TODO for attacker-controlled input.
func TestGenerateHarness_EmitsSkeletonCallingModuleFunc(t *testing.T) {
	sink := "scip-typescript npm . . src/util/handler()."
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
	if !strings.Contains(res.Source, `require("./src/util")`) {
		t.Errorf("source must require the sink module; got:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "handler(") {
		t.Errorf("source must call the sink symbol; got:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "TODO") {
		t.Errorf("source must mark attacker-controlled input with a TODO; got:\n%s", res.Source)
	}
	// A skeleton that does not prove exploitability is declared Partial, never Complete.
	if res.Partiality.Complete {
		t.Error("a reproducer skeleton must declare Partial (not a working exploit)")
	}
	if hasReason(res.Partiality, plugin.PartialReasonUnsupported) {
		t.Error("harness is real now; must not use unsupported_phase1")
	}
}

// TestGenerateHarness_MethodSinkConstructsReceiver asserts a method sink SCIP
// (class-qualified) yields source that constructs the enclosing class and calls the
// method.
func TestGenerateHarness_MethodSinkConstructsReceiver(t *testing.T) {
	sink := "scip-typescript npm . . src/service/FetchService#handle(1)."
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{Sink: sink, Kind: "unit"})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if !strings.Contains(res.Source, "new service.FetchService()") {
		t.Errorf("method sink source must construct the enclosing class; got:\n%s", res.Source)
	}
	if !strings.Contains(res.Source, "recv.handle(") {
		t.Errorf("method sink source must call the method on the receiver; got:\n%s", res.Source)
	}
	if !res.Skeleton {
		t.Error("must be a skeleton")
	}
	if res.Partiality.Complete {
		t.Error("must declare Partial")
	}
}

// TestGenerateHarness_FuzzKind asserts the fuzz kind emits a jsfuzz-compatible entry
// and stays a Partial skeleton.
func TestGenerateHarness_FuzzKind(t *testing.T) {
	sink := "scip-typescript npm . . src/util/handler()."
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{Sink: sink, Kind: "fuzz"})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if !strings.Contains(res.Source, "module.exports.fuzz") {
		t.Errorf("fuzz kind must emit a jsfuzz-compatible entry; got:\n%s", res.Source)
	}
	if !res.Skeleton || res.Partiality.Complete {
		t.Error("fuzz harness must be a Partial skeleton")
	}
	// A recognized kind must NOT carry tool_failure.
	if hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("recognized fuzz kind must not declare tool_failure; got %+v", res.Partiality)
	}
}

// TestGenerateHarness_UnknownKindDeclaresToolFailure asserts an unrecognized kind
// still renders a skeleton but adds tool_failure to the partiality reasons.
func TestGenerateHarness_UnknownKindDeclaresToolFailure(t *testing.T) {
	sink := "scip-typescript npm . . src/util/handler()."
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{Sink: sink, Kind: "bogus"})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if res.Source == "" || !res.Skeleton {
		t.Error("unknown kind must still emit a skeleton")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("unknown kind must declare tool_failure; got %+v", res.Partiality)
	}
	if res.Partiality.Complete {
		t.Error("must declare Partial")
	}
}

// TestGenerateHarness_DefaultKindIsUnit asserts an empty kind defaults to unit
// (node:test) rather than an error or tool_failure.
func TestGenerateHarness_DefaultKindIsUnit(t *testing.T) {
	sink := "scip-typescript npm . . src/util/handler()."
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{Sink: sink})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if !strings.Contains(res.Source, `require("node:test")`) {
		t.Errorf("default kind must emit a node:test unit skeleton; got:\n%s", res.Source)
	}
	if hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("default (unit) kind must not declare tool_failure; got %+v", res.Partiality)
	}
}

// TestGenerateHarness_RootModuleRequiresPackageEntry asserts a sink in the build
// root ("_root_") requires the package entry ".".
func TestGenerateHarness_RootModuleRequiresPackageEntry(t *testing.T) {
	sink := "scip-typescript npm . . _root_/handler()."
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{Sink: sink, Kind: "unit"})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if !strings.Contains(res.Source, `require(".")`) {
		t.Errorf("root-module sink must require the package entry; got:\n%s", res.Source)
	}
}

// TestGenerateHarness_UnparseableSinkIsPartial asserts that a sink id that cannot be
// parsed into module+symbol declares a Partial(tool_failure) skeleton, not an error.
func TestGenerateHarness_UnparseableSinkIsPartial(t *testing.T) {
	for _, sink := range []string{
		"not-a-scip-id",
		"scip-typescript npm . . src/util/FooType#", // bare type, not callable
		"scip-typescript npm . . nomodule().",       // no module/ prefix
		"",
	} {
		res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{
			Sink: sink,
			Kind: "unit",
		})
		if err != nil {
			t.Fatalf("GenerateHarness(%q): unparseable sink is declared partial, not a hard error: %v", sink, err)
		}
		if res.Partiality.Complete {
			t.Errorf("GenerateHarness(%q): unparseable sink must declare Partial", sink)
		}
		if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
			t.Errorf("GenerateHarness(%q): unparseable sink must carry tool_failure; got %+v", sink, res.Partiality)
		}
		if !res.Skeleton {
			t.Errorf("GenerateHarness(%q): unparseable sink still declares a skeleton", sink)
		}
	}
}

// TestGenerateHarness_RealIndexedSink round-trips a SCIP id emitted by the real
// indexer through the parser, ensuring the harness grammar matches the emitter.
func TestGenerateHarness_RealIndexedSink(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"src/util.js": "function handler(x) { return x; }\nmodule.exports = { handler };\n",
	})
	idx, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	var sink string
	for _, s := range idx.Symbols {
		if strings.Contains(s.SCIP, "handler") {
			sink = s.SCIP
			break
		}
	}
	if sink == "" {
		t.Fatalf("indexer emitted no handler symbol; symbols=%+v", idx.Symbols)
	}
	res, err := GenerateHarness(context.Background(), plugin.GenerateHarnessRequest{Sink: sink, Kind: "unit"})
	if err != nil {
		t.Fatalf("GenerateHarness: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("a real-indexed sink harness must still declare Partial")
	}
	if hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("a well-formed indexed sink must parse cleanly (no tool_failure); got %+v", res.Partiality)
	}
	if !strings.Contains(res.Source, "handler(") {
		t.Errorf("harness must call the indexed sink; got:\n%s", res.Source)
	}
}
