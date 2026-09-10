package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	taintFixtureDir   = "testdata/taintmod"
	reflectFixtureDir = "testdata/taintreflectmod"
)

// sinkSCIPIn resolves the real emitted SCIP id of a callee whose id contains sub
// within the call graph of dir, so a taint test traces toward the same identity
// the call graph emits.
func sinkSCIPIn(t *testing.T, dir, sub string) string {
	t.Helper()
	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph(%s): %v", dir, err)
	}
	for _, e := range cg.Edges {
		if strings.Contains(e.Callee.SCIP, sub) {
			return e.Callee.SCIP
		}
	}
	t.Fatalf("no callee containing %q in %s call graph edges", sub, dir)
	return ""
}

// TestComputeTaint_PositiveValueFlowNonPartial is proof #1: an ingress-tainted
// arg (the *http.Request method) reaches Sink through SSA value flow on a clean
// graph, so ComputeTaint reports a real source->sink taint path and is
// NON-Partial (the precision upgrade over call-graph path-presence).
func TestComputeTaint_PositiveValueFlowNonPartial(t *testing.T) {
	sink := sinkSCIPIn(t, taintFixtureDir, "/Sink().")
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: taintFixtureDir,
		Sinks:    []string{sink},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) == 0 {
		t.Fatalf("expected a source->sink taint path for %q; got none: %+v", sink, res)
	}
	p := res.Paths[0]
	if p.Sink.SCIP != sink {
		t.Errorf("path Sink = %q, want %q", p.Sink.SCIP, sink)
	}
	if p.Ingress == (plugin.Symbol{}) {
		t.Errorf("expected a non-empty ingress for a tainted sink; got %+v", p)
	}
	if !strings.Contains(p.Ingress.SCIP, "TaintedHandler") {
		t.Errorf("expected the TaintedHandler ingress to reach Sink; got ingress %q", p.Ingress.SCIP)
	}
	if !res.Partiality.Complete {
		t.Errorf("a fully-resolved clean value-flow path must be NON-Partial; got reasons %v", res.Partiality.Reasons)
	}
	for _, r := range res.Partiality.Reasons {
		if r == "safe" || r == "unreachable" || r == "not_reachable" {
			t.Errorf("taint must never emit a safe/unreachable reason; got %q", r)
		}
	}
	if res.PrecisionNote == "" {
		t.Error("taint must carry a PrecisionNote describing the analysis")
	}
}

// TestComputeTaint_SanitizerClears is proof #2: the same source/sink shape routed
// through a modeled sanitizer (strconv.Atoi) yields NO taint path to the sink —
// a true negative that must not be reported. The sink is reached only by the
// SanitizedHandler in this fixture, so a no_known_ingress partiality is expected
// (never "safe"), with zero reported paths.
func TestComputeTaint_SanitizerClears(t *testing.T) {
	// Resolve the sink from the sanitized-only fixture so the test does not
	// depend on the positive handler's presence.
	sink := sinkSCIPIn(t, sanitizerOnlyDir(t), "/Sink().")
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: sanitizerOnlyDir(t),
		Sinks:    []string{sink},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	for _, p := range res.Paths {
		if p.Sink.SCIP == sink {
			t.Fatalf("sanitized flow must yield NO taint path to %q; got %+v", sink, p)
		}
	}
	if res.Partiality.Complete {
		t.Error("a sink with no tainted (only sanitized) flow is no_known_ingress, never reported complete/safe (inv.5)")
	}
	if !hasReason(res.Partiality.Reasons, plugin.PartialReasonNoIngress) {
		t.Errorf("want no_known_ingress for a sanitized-only sink; got %v", res.Partiality.Reasons)
	}
}

// TestComputeTaint_PartialityHonesty is proof #3: a tainted flow whose path
// crosses a reflection call reports the taint path AND declares
// Partial(reflection) — honesty over reach (inv.5).
func TestComputeTaint_PartialityHonesty(t *testing.T) {
	sink := sinkSCIPIn(t, reflectFixtureDir, "/Sink().")
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: reflectFixtureDir,
		Sinks:    []string{sink},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) == 0 {
		t.Fatalf("expected a taint path even on a reflection-degraded flow; got none: %+v", res)
	}
	if res.Partiality.Complete {
		t.Fatal("a tainted path crossing reflection must NOT be complete (inv.5)")
	}
	if !hasReason(res.Partiality.Reasons, plugin.PartialReasonReflection) {
		t.Errorf("want reflection reason on a reflection-crossing path; got %v", res.Partiality.Reasons)
	}
}

// TestComputeTaint_GoldenCorpusNoRegression is proof #4: the existing Go
// reachability corpus (fixturemod) still loads and its sink is traced without
// error; ComputeTaint emits a precision note and never fabricates a "safe"
// reason. The fixturemod sink is reached by hardcoded literals, not ingress
// input, so no tainted path is expected — but the op must remain honest
// (no_known_ingress, never safe) and contract-shaped.
func TestComputeTaint_GoldenCorpusNoRegression(t *testing.T) {
	sink := sinkSCIPIn(t, fixtureDir, "/Sink().")
	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: fixtureDir,
		Sinks:    []string{sink},
	})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if res.PrecisionNote == "" {
		t.Error("taint must carry a PrecisionNote")
	}
	for _, r := range res.Partiality.Reasons {
		if r == "safe" || r == "unreachable" || r == "not_reachable" {
			t.Errorf("taint must never emit a safe/unreachable reason; got %q", r)
		}
	}
	if res.Partiality.Complete {
		t.Error("fixturemod sink is reached by literals, not ingress input: expected no_known_ingress, never complete/safe")
	}
	if !hasReason(res.Partiality.Reasons, plugin.PartialReasonNoIngress) {
		t.Errorf("want no_known_ingress for a sink reached only by literal flow; got %v", res.Partiality.Reasons)
	}
}

// TestComputeTaint_BrokenDirIsHardError asserts a load failure is a hard error
// (inv.4), never a silent empty result.
func TestComputeTaint_BrokenDirIsHardError(t *testing.T) {
	_, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: "testdata/does-not-exist",
		Sinks:    []string{"scip:whatever"},
	})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir (inv.4)")
	}
}

// sanitizerOnlyDir returns the build dir for the sanitizer proof. The taintmod
// fixture contains BOTH a tainted and a sanitized handler reaching the same Sink,
// which would let the tainted handler's path mask the sanitizer. The sanitizer
// proof therefore uses a dedicated single-handler fixture.
func sanitizerOnlyDir(t *testing.T) string {
	t.Helper()
	return "testdata/sanitizermod"
}
