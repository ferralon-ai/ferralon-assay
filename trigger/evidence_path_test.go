package trigger

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_LabelTraceEntryFromOnePath drives finding() over seeded stores and checks that the
// reachable_path label, the call path and the entry point are read from one path, and that the
// verdict is the one the candidate arm has always given these inputs.
func TestFinding_LabelTraceEntryFromOnePath(t *testing.T) {
	const (
		mainSym  = "scip-go gomod example.com/m . example.com/m/main()."
		fetchSym = "scip-go gomod example.com/m . example.com/m/fetchHandler()."
		listSym  = "scip-go gomod example.com/m . example.com/m/listHandler()."
		cliSym   = "scip-go gomod example.com/m . example.com/m/runCommand()."
		midSym   = "scip-go gomod example.com/m . example.com/m/load()."
		sinkSym  = "scip-go gomod net/http . net/http/Get()."
	)
	sym := func(s string) plugin.Symbol { return plugin.Symbol{SCIP: s} }
	path := func(ingress string, trace ...string) plugin.ReachPath {
		p := plugin.ReachPath{Sink: sym(sinkSym), Ingress: sym(ingress)}
		for _, s := range trace {
			p.Trace = append(p.Trace, sym(s))
		}
		return p
	}
	twoRoutes := plugin.IngressResult{Ingresses: []plugin.Ingress{
		{Kind: "http_route", Symbol: sym(fetchSym), Selector: "/fetch"},
		{Kind: "http_route", Symbol: sym(listSym), Selector: "/list"},
	}}
	routeAndCLI := plugin.IngressResult{Ingresses: []plugin.Ingress{
		{Kind: "http_route", Symbol: sym(fetchSym), Selector: "/fetch"},
		{Kind: "http_route", Symbol: sym(listSym), Selector: "/list"},
		{Kind: "cli", Symbol: sym(cliSym)},
	}}
	oneRoute := plugin.IngressResult{Ingresses: []plugin.Ingress{
		{Kind: "http_route", Symbol: sym(fetchSym), Selector: "/fetch"},
	}}
	internal := path("", mainSym, midSym, sinkSym)
	viaList := path(listSym, listSym, midSym, sinkSym)
	viaFetch := path(fetchSym, fetchSym, sinkSym)
	viaCLI := path(cliSym, cliSym, midSym, sinkSym)

	tests := []struct {
		name      string
		ingresses any
		taint     []plugin.ReachPath
		reach     []plugin.ReachPath
		// stubReach stores the plugin-less reachability shape, which records no path.
		stubReach bool
		wantLabel string
		wantEntry *report.EntryPoint
		wantTrace []string
		wantGrade report.ReachabilityGrade
	}{
		{
			name:      "two ingresses, first reach path internal",
			ingresses: twoRoutes,
			reach:     []plugin.ReachPath{internal, viaList},
			wantLabel: "entrypoint → advisory symbol",
			wantEntry: &report.EntryPoint{Symbol: "/list", Kind: "http_route", AttackerControllable: true},
			wantTrace: []string{listSym, midSym, sinkSym},
			wantGrade: report.GradeAttackerTainted,
		},
		{
			name:      "two ingresses, internal path first, then a non-attacker ingress",
			ingresses: routeAndCLI,
			reach:     []plugin.ReachPath{internal, viaCLI},
			wantLabel: "entrypoint → advisory symbol",
			wantEntry: &report.EntryPoint{Symbol: cliSym, Kind: "cli"},
			wantTrace: []string{cliSym, midSym, sinkSym},
			wantGrade: report.GradeControlFlowOnly,
		},
		{
			name:      "internal taint path, anchored reach path",
			ingresses: twoRoutes,
			taint:     []plugin.ReachPath{internal},
			reach:     []plugin.ReachPath{internal, viaList},
			wantLabel: "entrypoint → advisory symbol",
			wantEntry: &report.EntryPoint{Symbol: "/list", Kind: "http_route", AttackerControllable: true},
			wantTrace: []string{listSym, midSym, sinkSym},
			wantGrade: report.GradeAttackerTainted,
		},
		{
			name:      "anchored taint path wins over anchored reach path",
			ingresses: twoRoutes,
			taint:     []plugin.ReachPath{internal, viaFetch},
			reach:     []plugin.ReachPath{viaList},
			wantLabel: "entrypoint → advisory symbol",
			wantEntry: &report.EntryPoint{Symbol: "/fetch", Kind: "http_route", AttackerControllable: true},
			wantTrace: []string{fetchSym, sinkSym},
			wantGrade: report.GradeAttackerTainted,
		},
		{
			name:      "anchored taint path, internal reach path",
			ingresses: twoRoutes,
			taint:     []plugin.ReachPath{viaFetch},
			reach:     []plugin.ReachPath{internal},
			wantLabel: "entrypoint → advisory symbol",
			wantEntry: &report.EntryPoint{Symbol: "/fetch", Kind: "http_route", AttackerControllable: true},
			wantTrace: []string{fetchSym, sinkSym},
			wantGrade: report.GradeAttackerTainted,
		},
		{
			name:      "no anchored path, two ingresses",
			ingresses: twoRoutes,
			reach:     []plugin.ReachPath{internal, internal},
			wantLabel: "advisory symbol reachable",
			wantTrace: []string{mainSym, midSym, sinkSym},
			wantGrade: report.GradeControlFlowOnly,
		},
		{
			name:      "single anchored path",
			ingresses: oneRoute,
			reach:     []plugin.ReachPath{viaFetch},
			wantLabel: "entrypoint → advisory symbol",
			wantEntry: &report.EntryPoint{Symbol: "/fetch", Kind: "http_route", AttackerControllable: true},
			wantTrace: []string{fetchSym, sinkSym},
			wantGrade: report.GradeAttackerTainted,
		},
		{
			name:      "single internal path",
			ingresses: twoRoutes,
			reach:     []plugin.ReachPath{internal},
			wantLabel: "advisory symbol reachable",
			wantTrace: []string{mainSym, midSym, sinkSym},
			wantGrade: report.GradeControlFlowOnly,
		},
		{
			name:      "no recorded path",
			ingresses: map[string]string{"entrypoint": "GET /"},
			stubReach: true,
			wantLabel: "entrypoint → advisory symbol",
			wantEntry: &report.EntryPoint{Symbol: "GET /", Kind: "http_route", AttackerControllable: true},
			wantGrade: report.GradeControlFlowOnly,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			const aid = "a1"
			putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, map[string]any{
				"affected_ranges": []map[string]string{{"upper_exclusive": "99.0.0"}},
			})
			putJSON(t, store, aid, artifact.TypeIngressMap, tc.ingresses)
			if tc.stubReach {
				putJSON(t, store, aid, artifact.TypeReachability, map[string]bool{"reachable": true})
				putJSON(t, store, aid, artifact.TypeCandidatePair, artifact.CandidatePair{Ingress: &artifact.Ref{}})
			} else {
				putJSON(t, store, aid, artifact.TypeReachability, struct {
					Reachability plugin.ReachabilityResult `json:"reachability"`
				}{plugin.ReachabilityResult{Paths: tc.reach}})
				// One pair per reach path, carrying an ingress exactly when the path does, as
				// reachability_ingress writes them.
				for _, p := range tc.reach {
					pair := artifact.CandidatePair{}
					if p.Ingress.SCIP != "" {
						pair.Ingress = &artifact.Ref{}
					}
					putJSON(t, store, aid, artifact.TypeCandidatePair, pair)
				}
			}
			if tc.taint != nil {
				putJSON(t, store, aid, artifact.TypeTaint, taintDiscoveryFor(tc.taint))
			}

			f := finding(store, aid, report.Advisory{ID: "GO-2026-0001"}, nil)
			if f.Verdict != report.VerdictReachableCandidate {
				t.Fatalf("verdict = %q, want %q", f.Verdict, report.VerdictReachableCandidate)
			}
			ev := f.Evidence
			if ev.ReachablePath != tc.wantLabel {
				t.Errorf("reachable_path = %q, want %q", ev.ReachablePath, tc.wantLabel)
			}
			var trace []string
			for _, fr := range ev.CallPath {
				trace = append(trace, fr.Symbol)
			}
			if !slices.Equal(trace, tc.wantTrace) {
				t.Errorf("call_path = %v, want %v", trace, tc.wantTrace)
			}
			switch {
			case tc.wantEntry == nil && ev.EntryPoint != nil:
				t.Errorf("entry_point = %+v, want nil", ev.EntryPoint)
			case tc.wantEntry != nil && (ev.EntryPoint == nil || *ev.EntryPoint != *tc.wantEntry):
				t.Errorf("entry_point = %+v, want %+v", ev.EntryPoint, tc.wantEntry)
			}
			if ev.Grade != tc.wantGrade {
				t.Errorf("grade = %q, want %q", ev.Grade, tc.wantGrade)
			}
			// The label names an entrypoint exactly when the shown trace starts at one.
			if anchored := len(trace) > 0 && trace[0] != mainSym; len(trace) > 0 && anchored != (ev.ReachablePath == "entrypoint → advisory symbol") {
				t.Errorf("label %q disagrees with the trace head %q", ev.ReachablePath, trace[0])
			}
		})
	}
}

func taintDiscoveryFor(paths []plugin.ReachPath) any {
	return struct {
		Result plugin.TaintResult `json:"result"`
	}{plugin.TaintResult{Paths: paths}}
}
