package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestTaint_SourceToSinkReportsPartial proves the tainted Python source→sink case: the
// Flask route ingress reaches the sink over the call graph, so ComputeTaint reports a path
// — and it is ALWAYS declared Partial by construction (a lexical scanner has no value-flow
// precision, and Python dispatch is dynamic), with the standing PrecisionNote.
func TestTaint_SourceToSinkReportsPartial(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	sink := funcSCIP("app", nil, "open_conn", 1)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("tainted source→sink must report exactly one path; got %d: %+v", len(res.Paths), res.Paths)
	}
	if res.Partiality.Complete {
		t.Fatal("lexical Python taint is ALWAYS Partial by construction — never Complete")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Fatalf("taint must carry the dynamic_dispatch precision marker; got %v", res.Partiality.Reasons)
	}
	if res.PrecisionNote == "" {
		t.Fatal("taint result must carry the standing PrecisionNote stating the value-flow limit")
	}
	p := res.Paths[0]
	if p.Sink.SCIP != sink || p.Ingress.SCIP == "" || p.Ingress.SCIP != p.Trace[0].SCIP {
		t.Fatalf("taint path malformed: %+v", p)
	}
}

// TestTaint_SinkCleanReportsNothing proves the negative: a sink with no source path reports
// NO path (and still declares Partial with no_known_ingress — an unreached sink is UNKNOWN,
// never asserted "not tainted").
func TestTaint_SinkCleanReportsNothing(t *testing.T) {
	src := `
@app.route('/ok')
def route():
    return harmless(1)

def harmless(x):
    return x

def orphan_sink(u):
    return u
`
	dir := writeTree(t, map[string]string{"clean.py": src})
	sink := funcSCIP("clean", nil, "orphan_sink", 1)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("a sink-clean case must report NO taint path; got %+v", res.Paths)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Fatalf("an unreached sink must declare no_known_ingress (UNKNOWN, never safe); got %v", res.Partiality.Reasons)
	}
}

func TestTaint_MissingBuildDirIsHardError(t *testing.T) {
	_, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: "testdata/does-not-exist",
		Sinks:    []string{"whatever"},
	})
	if err == nil {
		t.Fatal("a load failure must be a hard error (inv.4), not partiality")
	}
}
