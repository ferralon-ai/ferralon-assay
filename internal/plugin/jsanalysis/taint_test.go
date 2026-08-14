package jsanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestTaint_SourceToSinkReportsPartial proves the tainted JS source→sink case: the Express
// route ingress reaches the SSRF sink over the call graph, so ComputeTaint reports a path —
// and it is ALWAYS declared Partial by construction (a lexical scanner has no value-flow
// precision), with the standing PrecisionNote.
func TestTaint_SourceToSinkReportsPartial(t *testing.T) {
	ctx := context.Background()
	src := "../../../corpus/testdata/repros/TEGRON-JS-SSRF-0001-vulnerable/src"
	sink := resolveSink(t, src, "fetchUrl")

	res, err := ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: src, Sinks: []string{sink}})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("tainted source→sink must report exactly one path; got %d: %+v", len(res.Paths), res.Paths)
	}
	if res.Partiality.Complete {
		t.Fatal("lexical taint is ALWAYS declared Partial by construction — never Complete")
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
// never asserted "safe"). Here the sink is a free function no ingress reaches.
func TestTaint_SinkCleanReportsNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// orphanSink is declared but no route/ingress reaches it; the only ingress (route)
	// calls a different function. So taint finds no source→sink path.
	const src = `'use strict';
const http = require('http');

function orphanSink(u) {
    return http.get(u);   // a real sink, but unreachable from any ingress
}

function harmless(x) {
    return x + 1;
}

const app = makeApp();
app.get('/ok', route);

function route(req, res) {
    return harmless(req.query.x);
}
`
	if err := os.WriteFile(filepath.Join(dir, "clean.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := resolveSink(t, dir, "orphanSink")

	res, err := ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
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
