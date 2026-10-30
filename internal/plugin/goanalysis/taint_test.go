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

// TestComputeTaint_SanitizedSinks is proof #2: a sink only a sanitized flow reaches comes back with
// no path and, on its account, complete; it grades control_flow_only, still a finding and never a
// safe verdict (inv.5). A sink no flow reaches at all stays no_known_ingress.
func TestComputeTaint_SanitizedSinks(t *testing.T) {
	for _, c := range []struct {
		name, dir, sink string
		wantComplete    bool
		wantNoIngr      bool
	}{
		// The ingress's only flow to Sink is html.EscapeString's result.
		{name: "sanitized only", dir: sanitizerOnlyDir(t), sink: "/Sink().", wantComplete: true},
		// The sanitized value reaches Opaque through strconv.Itoa, a dependency call whose
		// result carries what it was handed.
		{name: "sanitized through a dependency call", dir: sanitizerOnlyDir(t), sink: "/Opaque().", wantComplete: true},
		// A raw flow reaches Sink through a recovered panic the pass does not follow: the
		// sanitized flow it does observe is not enough.
		{name: "sanitized beside a dropped flow", dir: "testdata/taintlostmod", sink: "/Sink().", wantNoIngr: true},
		// Sink is reached by literals, never by ingress input.
		{name: "no flow", dir: fixtureDir, sink: "/Sink().", wantNoIngr: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			sink := sinkSCIPIn(t, c.dir, c.sink)
			res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{
				BuildDir: c.dir,
				Sinks:    []string{sink},
			})
			if err != nil {
				t.Fatalf("ComputeTaint: %v", err)
			}
			if len(res.Paths) != 0 {
				t.Errorf("want no taint path to %q; got %+v", sink, res.Paths)
			}
			if res.Partiality.Complete != c.wantComplete {
				t.Errorf("Complete = %v, want %v (reasons %v)", res.Partiality.Complete, c.wantComplete, res.Partiality.Reasons)
			}
			if got := hasReason(res.Partiality.Reasons, plugin.PartialReasonNoIngress); got != c.wantNoIngr {
				t.Errorf("no_known_ingress = %v, want %v (reasons %v)", got, c.wantNoIngr, res.Partiality.Reasons)
			}
		})
	}
}

// TestComputeTaint_RawFlowBesideSanitized pins that a raw flow beside a sanitized one always yields
// a taint path, whatever shape carries it: a sink is never complete with zero paths while an
// unsanitized flow reaches it.
func TestComputeTaint_RawFlowBesideSanitized(t *testing.T) {
	const dir = "testdata/taintflowmod"
	for _, c := range []struct{ name, sink string }{
		{name: "dependency call", sink: "/Upper()."},
		{name: "append then index", sink: "/Appended()."},
		{name: "copy", sink: "/Copied()."},
		{name: "field set in a callee", sink: "/Field()."},
		{name: "concatenation", sink: "/Concat()."},
		{name: "one branch sanitized", sink: "/Branch()."},
	} {
		t.Run(c.name, func(t *testing.T) {
			sink := sinkSCIPIn(t, dir, c.sink)
			res, err := ComputeTaint(context.Background(), plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
			if err != nil {
				t.Fatalf("ComputeTaint: %v", err)
			}
			if len(res.Paths) != 1 || res.Paths[0].Sink.SCIP != sink {
				t.Errorf("want one taint path to %q; got %+v (reasons %v)", sink, res.Paths, res.Partiality.Reasons)
			}
		})
	}
}

// TestTaintClosureResult_SanitizedPredicate pins the per-sink rule over a closure: a tainted hit
// always reports its path, a sanitized-only sink adds nothing, and a sink with neither is
// no_known_ingress.
func TestTaintClosureResult_SanitizedPredicate(t *testing.T) {
	const sink, ingress = "scip:sink", "scip:ing"
	for _, c := range []struct {
		name       string
		closure    taintClosure
		wantPaths  int
		wantNoIngr bool
	}{
		{name: "sanitized only", closure: taintClosure{Sanitized: []string{sink}}},
		{name: "no flow", closure: taintClosure{}, wantNoIngr: true},
		{name: "sanitized elsewhere", closure: taintClosure{Sanitized: []string{"scip:other"}}, wantNoIngr: true},
		{name: "mixed sanitized and unsanitized", closure: taintClosure{Hits: map[string]string{sink: ingress}, Sanitized: []string{sink}}, wantPaths: 1},
		{name: "unsanitized", closure: taintClosure{Hits: map[string]string{sink: ingress}}, wantPaths: 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := c.closure.result([]string{sink})
			if len(res.Paths) != c.wantPaths {
				t.Fatalf("paths = %+v, want %d", res.Paths, c.wantPaths)
			}
			if c.wantPaths > 0 && (res.Paths[0].Sink.SCIP != sink || res.Paths[0].Ingress.SCIP != ingress) {
				t.Errorf("path = %+v, want %s -> %s", res.Paths[0], ingress, sink)
			}
			if got := hasReason(res.Partiality.Reasons, plugin.PartialReasonNoIngress); got != c.wantNoIngr {
				t.Errorf("no_known_ingress = %v, want %v", got, c.wantNoIngr)
			}
			if res.Partiality.Complete == c.wantNoIngr {
				t.Errorf("Complete = %v with no other reason, want %v", res.Partiality.Complete, !c.wantNoIngr)
			}
		})
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

// TestRunTaint_AttributesLowestIngress pins that a sink two ingresses reach is attributed to the
// lowest ingress symbol on every run, not to whichever the ingress map yields first, including a sink
// reached only through another ingress's parameters.
func TestRunTaint_AttributesLowestIngress(t *testing.T) {
	const dir = "testdata/taintmultimod"
	ctx := context.Background()
	sink := sinkSCIPIn(t, dir, "/Sink().")
	deep := sinkSCIPIn(t, dir, "/Deep().")
	sp, _, err := loadSSA(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ingresses := sp.resolveIngressFuncs(ing.Ingresses)
	var alpha, zeta, helper bool
	for sym := range ingresses {
		alpha = alpha || strings.Contains(sym, "AlphaHandler")
		zeta = zeta || strings.Contains(sym, "ZetaHandler")
		helper = helper || strings.Contains(sym, "zetaHelper")
	}
	if !alpha || !zeta || !helper {
		t.Fatalf("want AlphaHandler, ZetaHandler and zetaHelper as resolved ingresses; got %v", ingresses)
	}
	for run := range 20 {
		hits, _, _ := runTaint(sp, ingresses, map[string]bool{sink: true, deep: true})
		if len(hits) != 2 || !strings.Contains(hits[sink], "AlphaHandler") || !strings.Contains(hits[deep], "AlphaHandler") {
			t.Fatalf("run %d: want Sink and Deep attributed to AlphaHandler; got %v", run, hits)
		}
	}
}

// sanitizerOnlyDir returns the build dir for the sanitizer proof: a single handler whose every flow
// to a sink passes through a sanitizer.
func sanitizerOnlyDir(t *testing.T) string {
	t.Helper()
	return "testdata/sanitizermod"
}

// TestResolveIngressFuncs_DeclaredMethod pins that a method handler's ingress resolves to the method
// itself, never to its bound wrapper, which shares the method's SCIP id: seeding the wrapper would
// report the method as a sink its own ingress reaches, on whichever runs map order picked it.
func TestResolveIngressFuncs_DeclaredMethod(t *testing.T) {
	const dir = "testdata/chimod"
	ctx := context.Background()
	sp, _, err := loadSSA(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	methods := 0
	for run := range 20 {
		for id, fn := range sp.resolveIngressFuncs(ing.Ingresses) {
			if fn.Signature.Recv() != nil {
				methods++
			}
			if fn.Synthetic != "" {
				t.Fatalf("run %d: %s resolved to %s (%s)", run, id, fn, fn.Synthetic)
			}
		}
	}
	if methods == 0 {
		t.Fatal("no method handler resolved; the fixture proves nothing")
	}
}
