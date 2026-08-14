package dotnetanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestComputeTaint_PathPresentIsAlwaysPartial mirrors the reachability honesty proof for the
// taint op: the [HttpGet] controller ingress (Handle) reaches the sink (OpenConn) over the
// lexical call graph, so a path is reported — but the result is Partial(dynamic_dispatch)
// even with a path found, and carries the value-flow PrecisionNote. A lexical scan proves
// path presence, never that the tainted VALUE flows to the sink argument.
func TestComputeTaint_PathPresentIsAlwaysPartial(t *testing.T) {
	dir := writeTree(t, map[string]string{"FetchController.cs": controllerApp})
	sink := funcSCIP("Acme.Web", []string{"FetchController"}, "OpenConn", 1)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want exactly one taint path to the sink, got %d: %+v", len(res.Paths), res.Paths)
	}
	if res.Paths[0].Sink.SCIP != sink {
		t.Fatalf("path sink = %q, want %q", res.Paths[0].Sink.SCIP, sink)
	}
	// The critical C# invariant: path presence is STILL Partial (never Complete).
	if res.Partiality.Complete {
		t.Fatal("C# taint must NEVER return Complete, even when a path is present (path presence ≠ value flow)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Fatalf("C# taint must always carry dynamic_dispatch; got %v", res.Partiality.Reasons)
	}
	if !strings.Contains(res.PrecisionNote, "path presence") {
		t.Fatalf("taint result must carry the value-flow PrecisionNote; got %q", res.PrecisionNote)
	}
}

// TestComputeTaint_NotReachedIsUnknownNeverSafe proves the inv.5 boundary for taint: a sink
// no ingress/root reaches yields NO path and declares no_known_ingress — UNKNOWN, never a
// confident "not tainted".
func TestComputeTaint_NotReachedIsUnknownNeverSafe(t *testing.T) {
	src := `
namespace Acme.Web
{
    public class HomeController
    {
        [HttpGet]
        public string Route()
        {
            return Harmless(1);
        }

        private string Harmless(int x)
        {
            return "";
        }

        private string OrphanSink(string u)
        {
            return u;
        }
    }
}
`
	dir := writeTree(t, map[string]string{"HomeController.cs": src})
	sink := funcSCIP("Acme.Web", []string{"HomeController"}, "OrphanSink", 1)

	res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) != 0 {
		t.Fatalf("an unreached sink must yield NO taint path; got %+v", res.Paths)
	}
	if res.Partiality.Complete {
		t.Fatal("an unreached sink must be Partial, never a confident not-tainted")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonNoIngress) {
		t.Fatalf("an unreached sink must declare no_known_ingress (UNKNOWN, never safe); got %v", res.Partiality.Reasons)
	}
}

func TestComputeTaint_MissingBuildDirIsHardError(t *testing.T) {
	_, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
		BuildDir: "testdata/does-not-exist",
		Sinks:    []string{"whatever"},
	})
	if err == nil {
		t.Fatal("a load failure in the call graph must be a hard error (inv.4), not partiality")
	}
}
