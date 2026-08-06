//go:build live

// gogs_reach_gate_live_test.go — the A-vs-B reachability gate for the pone-gogs
// platform-verdict cycle. It is OPT-IN via the `live` build tag and drives the REAL
// Go analysis engine (goanalysis, the same code linked into tegron-plugin-go) over a
// REAL gogs source tree — NOT a stub plugin. The hermetic firstparty_reach_test.go
// proves the SEAM with a stub; this test proves the seam RESOLVES THE REAL gogs sink.
//
// The load-bearing question (architect-build-design.md §1, the A-vs-B fork): can the
// Go plugin, over the real gogs module, (1) resolve the first-party sink
// gogs.io/gogs/internal/db.UpdateRepoFile (in AdvisoryTable under both halves of the
// gogs chain — CVE-2024-55947 and CVE-2025-8110 share this sink) to a SCIP; (2) recognize the macaron repo file-edit route handler as
// an ingress; and (3) walk firstPartyReachPaths from an ingress to that sink? All three
// yes ⇒ Option A (real gogs) is viable. Any no that is not a bounded plugin fix ⇒
// Option B (reproducer) fallback.
//
// The gogs tree is NOT vendored (heavy, third-party). Point the test at a checkout via:
//
//	TEGRON_GOGS_DIR=/path/to/gogs go test -tags live -run TestGogsReachGate \
//	    ./ferralon-assay/pipeline/ -v -count=1
//
// Get the tree (v0.13.4 = the patched leg the demo proves non-exploitable):
//
//	git clone --depth 1 --branch v0.13.4 https://github.com/gogs/gogs "$TEGRON_GOGS_DIR"
//
// The load runs offline against the tree's own go.mod (GOWORK=off inside LoadProgram),
// so gogs's deps must be resolvable from the module cache/GOPROXY. Wall-clock: dominated
// by go/packages + SSA build over the full gogs module — expect 1–4 min on a warm cache.

package pipeline

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	gogsPURL       = "pkg:golang/gogs.io/gogs/internal/db"
	gogsSinkSymbol = "UpdateRepoFile"
	// The successor: v0.13.4 (the tree this gate loads) is the release that closes
	// CVE-2025-8110, and it is the CVE the gogs demo fixtures are keyed to. Both chain
	// entries declare the same PURL and sink symbol, so the gate resolves identically
	// either way — this names the one the tree actually corresponds to.
	gogsVulnID = "CVE-2025-8110"
)

// TestGogsReachGate is the A-vs-B decision gate. PASS ⇒ Option A viable. It emits three
// GATE lines the orchestrator greps; the final PASS/FAIL is the standard go test verdict.
func TestGogsReachGate(t *testing.T) {
	dir := os.Getenv("TEGRON_GOGS_DIR")
	if dir == "" {
		t.Skip("set TEGRON_GOGS_DIR to a gogs source checkout (git clone --branch v0.13.4 https://github.com/gogs/gogs)")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("TEGRON_GOGS_DIR %q not a directory: %v", dir, err)
	}
	ctx := context.Background()

	// (1) Resolve the first-party sink UpdateRepoFile over the REAL gogs module.
	res, err := goanalysis.ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
		BuildDir:        dir,
		VulnID:          gogsVulnID,
		PURL:            gogsPURL,
		AdvisorySymbols: []string{gogsSinkSymbol},
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols (real gogs) hard error: %v", err)
	}
	var sinkSCIP string
	for _, sym := range res.Resolved {
		if strings.Contains(sym.DisplayName, gogsSinkSymbol) {
			sinkSCIP = sym.SCIP
			t.Logf("GATE resolve: DisplayName=%q Package=%q SCIP=%q", sym.DisplayName, sym.Package, sym.SCIP)
			break
		}
	}
	if sinkSCIP == "" {
		t.Errorf("GATE-1 SINK-RESOLVE: FAIL — %s not resolved to a SCIP over the real gogs module (resolved %d symbols)", gogsSinkSymbol, len(res.Resolved))
	} else {
		t.Logf("GATE-1 SINK-RESOLVE: PASS — %s => %s", gogsSinkSymbol, sinkSCIP)
	}

	// (2) Recognize the macaron repo file-edit route handler as an ingress. The macaron
	// verb registrars are already recognized (ingress.go:243). We assert at least one
	// http_route ingress mentions the file-edit handler (editFilePost / the v1 contents
	// API); if not, that is the one possible net-new bit (a macaron route recognizer),
	// but the recognizer already exists — a miss here means the handler name/route shape
	// isn't statically resolvable, which is Option-B signal.
	ing, err := goanalysis.FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses (real gogs) hard error: %v", err)
	}
	fileEditIngress := ""
	httpRoutes := 0
	for _, in := range ing.Ingresses {
		if in.Kind == "http_route" {
			httpRoutes++
		}
		s := strings.ToLower(in.Symbol)
		if strings.Contains(s, "editfile") || strings.Contains(s, "updatefile") || strings.Contains(s, "createfile") {
			fileEditIngress = in.Symbol
		}
	}
	t.Logf("GATE ingress: %d total ingresses, %d http_route", len(ing.Ingresses), httpRoutes)
	if fileEditIngress == "" {
		t.Errorf("GATE-2 INGRESS: FAIL — no file-edit route handler recognized as an ingress (macaron recognizer exists; handler may not be statically resolvable)")
	} else {
		t.Logf("GATE-2 INGRESS: PASS — file-edit ingress %s", fileEditIngress)
	}

	// (3) firstPartyReachPaths must walk an ingress→sink path to the resolved sink.
	if sinkSCIP == "" {
		t.Fatalf("GATE-3 REACH: FAIL (skipped, no sink SCIP from GATE-1)")
	}
	cg, err := goanalysis.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph (real gogs) hard error: %v", err)
	}
	t.Logf("GATE callgraph: %d edges, %d roots", len(cg.Edges), len(cg.Roots))
	paths := firstPartyReachPaths(cg, ing, sinkSCIP)
	if len(paths) == 0 {
		t.Errorf("GATE-3 REACH: FAIL — firstPartyReachPaths produced no ingress→sink path for %s", sinkSCIP)
	} else {
		p := paths[0]
		t.Logf("GATE-3 REACH: PASS — ingress=%q trace_len=%d sink=%q", p.Ingress, len(p.Trace), p.Sink)
	}
}
