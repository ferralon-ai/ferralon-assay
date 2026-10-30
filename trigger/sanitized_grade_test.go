package trigger

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestReachabilityEvidence_TaintResultGrades pins how the sink's taint result grades a candidate
// whose reach path runs through an attacker-controllable ingress. A complete result with no path
// (every flow to the sink sanitized) grades control_flow_only and keeps the reach path's frames; a
// taint path grades attacker_tainted; a Partial result or no result leaves the grade to the reach
// path.
func TestReachabilityEvidence_TaintResultGrades(t *testing.T) {
	const ing, sink = "ing", "sink"
	taintPath := plugin.ReachPath{Sink: plugin.Symbol{SCIP: sink}, Ingress: plugin.Symbol{SCIP: ing}, Trace: []plugin.Symbol{{SCIP: ing}, {SCIP: sink}}}
	for _, c := range []struct {
		name       string
		taint      *plugin.TaintResult
		wantGrade  report.ReachabilityGrade
		wantFrames []string
	}{
		{
			name:       "sanitized: complete, zero paths",
			taint:      &plugin.TaintResult{Partiality: plugin.Complete()},
			wantGrade:  report.GradeControlFlowOnly,
			wantFrames: []string{ing, "mid", sink},
		},
		{
			name:       "unsanitized: taint path",
			taint:      &plugin.TaintResult{Partiality: plugin.Complete(), Paths: []plugin.ReachPath{taintPath}},
			wantGrade:  report.GradeAttackerTainted,
			wantFrames: []string{ing, sink},
		},
		{
			name:       "partial, zero paths: reach fallback",
			taint:      &plugin.TaintResult{Partiality: plugin.Partial(plugin.PartialReasonNoIngress)},
			wantGrade:  report.GradeAttackerTainted,
			wantFrames: []string{ing, "mid", sink},
		},
		{
			name:       "no taint artifact: reach fallback",
			wantGrade:  report.GradeAttackerTainted,
			wantFrames: []string{ing, "mid", sink},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			const aid = "a"
			putJSON(t, store, aid, artifact.TypeIngressMap, plugin.IngressResult{
				Ingresses: []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: ing}, Selector: "GET /x"}},
			})
			putJSON(t, store, aid, artifact.TypeReachability, struct {
				Reachability plugin.ReachabilityResult `json:"reachability"`
			}{Reachability: plugin.ReachabilityResult{Paths: []plugin.ReachPath{{
				Sink: plugin.Symbol{SCIP: sink}, Ingress: plugin.Symbol{SCIP: ing},
				Trace: []plugin.Symbol{{SCIP: ing}, {SCIP: "mid"}, {SCIP: sink}},
			}}}})
			if c.taint != nil {
				putJSON(t, store, aid, artifact.TypeTaint, struct {
					Result plugin.TaintResult `json:"result"`
				}{Result: *c.taint})
			}

			grade, entry, frames := reachabilityEvidence(store, aid)
			if grade != c.wantGrade {
				t.Errorf("grade = %q, want %q", grade, c.wantGrade)
			}
			if entry == nil || entry.Symbol != "GET /x" {
				t.Errorf("entry = %+v, want GET /x", entry)
			}
			if got := frameSymbols(frames); strings.Join(got, ",") != strings.Join(c.wantFrames, ",") {
				t.Errorf("frames = %v, want %v", got, c.wantFrames)
			}
		})
	}
}

// TestReachabilityEvidence_GoSanitizedFlow runs the Go taint op over a handler whose only flow to
// Sink is html.EscapeString's result, and grades it: control_flow_only, with the reach frames.
func TestReachabilityEvidence_GoSanitizedFlow(t *testing.T) {
	const dir = "../internal/plugin/goanalysis/testdata/sanitizermod"
	ctx := context.Background()
	cg, err := goanalysis.CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	var sink, handler string
	for _, e := range cg.Edges {
		if strings.Contains(e.Callee.SCIP, "/Sink().") {
			sink, handler = e.Callee.SCIP, e.Caller.SCIP
		}
	}
	if sink == "" {
		t.Fatal("no edge to Sink in the fixture's call graph")
	}
	taint, err := goanalysis.ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
	if err != nil {
		t.Fatal(err)
	}

	store := artifact.NewMemStore()
	const aid = "a"
	putJSON(t, store, aid, artifact.TypeIngressMap, plugin.IngressResult{
		Ingresses: []plugin.Ingress{{Kind: "http_route", Symbol: plugin.Symbol{SCIP: handler}, Selector: "/sanitized"}},
	})
	putJSON(t, store, aid, artifact.TypeReachability, struct {
		Reachability plugin.ReachabilityResult `json:"reachability"`
	}{Reachability: plugin.ReachabilityResult{Paths: []plugin.ReachPath{{
		Sink: plugin.Symbol{SCIP: sink}, Ingress: plugin.Symbol{SCIP: handler},
		Trace: []plugin.Symbol{{SCIP: handler}, {SCIP: sink}},
	}}}})
	putJSON(t, store, aid, artifact.TypeTaint, struct {
		Result plugin.TaintResult `json:"result"`
	}{Result: taint})

	grade, _, frames := reachabilityEvidence(store, aid)
	if grade != report.GradeControlFlowOnly {
		t.Errorf("grade = %q, want control_flow_only (taint result %+v)", grade, taint)
	}
	if len(frames) != 2 {
		t.Errorf("frames = %v, want the reach path's two", frameSymbols(frames))
	}
}

func frameSymbols(frames []report.CallFrame) []string {
	out := make([]string, 0, len(frames))
	for _, f := range frames {
		out = append(out, f.Symbol)
	}
	return out
}
