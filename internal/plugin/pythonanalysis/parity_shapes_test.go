package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Benchmark-corpus shape fixtures for PLAN-070 (C3/C4/C5). Each test runs the REAL
// pure-Go scanner over a committed repro tree under corpus/testdata/repros/ and asserts
// the distinct verdict arm that makes the fixture that shape. No target code is executed;
// the scanner reads the vendored first-party source only. Sink paths are the /src roots,
// matching the Airflow precedent (firstparty_test.go).
const (
	reachableReproSrc   = "../../../corpus/testdata/repros/TEGRON-PY-SSRF-0001-REACHABLE/src"
	unreachableReproSrc = "../../../corpus/testdata/repros/TEGRON-PY-SSRF-0001-UNREACHABLE/src"
	toolfailReproSrc    = "../../../corpus/testdata/repros/TEGRON-PY-SSRF-0001-TOOLFAIL/src"
)

// resolveSingleSink resolves an advisory symbol name against a repro tree and requires it
// to resolve to exactly one first-party symbol (the sink is PRESENT), returning its SCIP.
func resolveSingleSink(t *testing.T, src, advisorySymbol string) string {
	t.Helper()
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        src,
		AdvisorySymbols: []string{advisorySymbol},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols(%s): %v", src, err)
	}
	if len(res.Resolved) != 1 {
		t.Fatalf("advisory symbol %q must resolve to exactly one PRESENT sink in %s; got %d: %+v",
			advisorySymbol, src, len(res.Resolved), res.Resolved)
	}
	return res.Resolved[0].SCIP
}

// TestParityShape_Reachable asserts the reachable arm: a recognized Flask route ingress
// transitively reaches the vulnerable sink open_conn via unique (name,arity) edges, so
// reachability appends a non-empty ReachPath (reachability.go:91) with a real ingress, AND
// still declares Partial(dynamic_dispatch) (reachability.go:52) -- Python reachability is a
// candidate narrower, never Complete. F-B1: "transitive" is metadata-only, the arm is
// exercised honestly as first-party.
func TestParityShape_Reachable(t *testing.T) {
	sink := resolveSingleSink(t, reachableReproSrc, "open_conn")

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: reachableReproSrc,
		Symbols:  []string{sink},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("reachable shape must yield exactly one ReachPath to the sink; got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Sink.SCIP != sink {
		t.Fatalf("path sink = %q, want %q", p.Sink.SCIP, sink)
	}
	if p.Ingress.SCIP == "" {
		t.Fatal("reachable shape: path must carry a non-empty ingress (the Flask route handler)")
	}
	if p.Ingress.SCIP != p.Trace[0].SCIP {
		t.Fatalf("ingress %q must be the first trace frame %q", p.Ingress.SCIP, p.Trace[0].SCIP)
	}
	if p.Trace[len(p.Trace)-1].SCIP != sink {
		t.Fatalf("final trace frame must be the sink; got %q", p.Trace[len(p.Trace)-1].SCIP)
	}
	if len(p.Trace) < 3 {
		t.Fatalf("expected multi-hop trace proxy_view->fetch_url->open_conn; got %v", p.Trace)
	}
	if res.Partiality.Complete {
		t.Fatal("Python reachability must NEVER be Complete, even with a path found (reachability.go:52)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Fatalf("reachable shape must still carry dynamic_dispatch; got %v", res.Partiality.Reasons)
	}
}

// TestParityShape_InstalledButUnreachable asserts the installed-but-unreachable arm: the
// vulnerable sink is PRESENT (resolves to exactly one first-party symbol) but no ingress or
// root reaches it, so reachability yields NO path AND declares no_known_ingress
// (reachability.go:84) -- UNKNOWN, never a confident "safe". The sink being present (not
// absent) is what makes this satisfy C3.
func TestParityShape_InstalledButUnreachable(t *testing.T) {
	sink := resolveSingleSink(t, unreachableReproSrc, "open_conn") // asserts PRESENT

	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: unreachableReproSrc,
		Symbols:  []string{sink},
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("installed-but-unreachable: an unreached sink must yield NO path; got %+v", res.Paths)
	}
	if res.Partiality.Complete {
		t.Fatal("an unreached sink must be Partial, never a confident not-reachable")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Fatalf("installed-but-unreachable must declare no_known_ingress; got %v", res.Partiality.Reasons)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Fatalf("must still carry the standing dynamic_dispatch reason; got %v", res.Partiality.Reasons)
	}
}

// TestParityShape_ArtifactUnavailable asserts the tool-failure arm: one source file the
// directory walk lists (a committed dangling *.py symlink) fails os.ReadFile, so the index
// degrades to Partial(tool_failure) (index.go:62-64,80-82) rather than a hard error or a
// silently-complete index. The readable file's symbols are still emitted, proving this is a
// declared-partial result, not an empty success. F-B3 resolved: the dangling-symlink route
// is portable (git mode 120000, survives fresh checkout).
func TestParityShape_ArtifactUnavailable(t *testing.T) {
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: toolfailReproSrc})
	if err != nil {
		t.Fatalf("IndexSymbols must NOT hard-error on a read failure (declared partiality, inv.4/5); got %v", err)
	}
	if res.Partiality.Complete {
		t.Fatal("a read failure must degrade to Partial, never a Complete index")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Fatalf("artifact-unavailable shape must declare tool_failure; got %v", res.Partiality.Reasons)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("tool_failure must NOT be an empty successful index: the readable file's symbols must still be present")
	}
	if !hasDisplay(res, "open_conn(1)") {
		t.Fatalf("the readable file's sink symbol open_conn must still be indexed; got %+v", res.Symbols)
	}

	// The same read failure propagates through the call graph (callgraph.go:198-200).
	cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: toolfailReproSrc})
	if err != nil {
		t.Fatalf("CallGraph must not hard-error on a read failure; got %v", err)
	}
	if !hasReason(cg.Partiality, plugin.PartialReasonToolFailure) {
		t.Fatalf("call graph must also carry tool_failure; got %v", cg.Partiality.Reasons)
	}
}
