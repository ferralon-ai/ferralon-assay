package pipeline

import (
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func symPath(ids ...string) []plugin.Symbol {
	out := make([]plugin.Symbol, len(ids))
	for i, id := range ids {
		out[i] = plugin.Symbol{SCIP: id}
	}
	return out
}

func reachPath(ids ...string) plugin.ReachPath {
	t := symPath(ids...)
	return plugin.ReachPath{Sink: t[len(t)-1], Ingress: t[0], Trace: t}
}

func taintPath(ingress, sink string) plugin.ReachPath {
	return plugin.ReachPath{Sink: plugin.Symbol{SCIP: sink}, Ingress: plugin.Symbol{SCIP: ingress}, Trace: symPath(ingress, sink)}
}

func TestTaintSinks(t *testing.T) {
	paths := []plugin.ReachPath{reachPath("main", "a", "dep", "vuln"), reachPath("main", "b", "vuln"), {}}
	got := taintSinks("vuln", paths)
	if want := []string{"vuln", "main", "a", "dep", "b"}; !slices.Equal(got, want) {
		t.Errorf("taintSinks = %v, want %v", got, want)
	}
	if got := taintSinks("vuln", nil); !slices.Equal(got, []string{"vuln"}) {
		t.Errorf("taintSinks with no path = %v, want the sink alone", got)
	}
}

func TestTaintOntoReachPaths(t *testing.T) {
	reach := []plugin.ReachPath{reachPath("main", "a", "dep", "vuln"), reachPath("handler", "b", "dep", "vuln")}
	for _, tc := range []struct {
		name  string
		taint []plugin.ReachPath
		want  []string // each path's trace, joined by ">"
		noted bool
	}{
		{name: "no taint path", taint: nil, want: nil},
		{name: "path to the sink stands alone", taint: []plugin.ReachPath{taintPath("handler", "a"), taintPath("handler", "vuln")}, want: []string{"handler>vuln"}},
		{name: "frame hit is carried to the sink", taint: []plugin.ReachPath{taintPath("other", "dep")}, want: []string{"other>dep>vuln"}, noted: true},
		{name: "a path that holds the ingress wins", taint: []plugin.ReachPath{taintPath("handler", "dep")}, want: []string{"handler>b>dep>vuln"}, noted: true},
		{name: "ingress earlier on the path keeps the path's own frames", taint: []plugin.ReachPath{taintPath("handler", "b")}, want: []string{"handler>b>dep>vuln"}, noted: true},
		{name: "ingress is the frame", taint: []plugin.ReachPath{taintPath("a", "a")}, want: []string{"a>dep>vuln"}, noted: true},
		{name: "same built path once", taint: []plugin.ReachPath{taintPath("other", "dep"), taintPath("other", "dep")}, want: []string{"other>dep>vuln"}, noted: true},
		{name: "a hit off every path is dropped", taint: []plugin.ReachPath{taintPath("handler", "elsewhere")}, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := taintOntoReachPaths(plugin.TaintResult{Paths: tc.taint, PrecisionNote: "lane note"}, "vuln", reach)
			var got []string
			for _, p := range res.Paths {
				var ids []string
				for _, f := range p.Trace {
					ids = append(ids, f.SCIP)
				}
				got = append(got, strings.Join(ids, ">"))
				if p.Sink.SCIP != "vuln" {
					t.Errorf("path sink = %q, want the vulnerable symbol", p.Sink.SCIP)
				}
				if p.Ingress.SCIP != ids[0] {
					t.Errorf("path ingress = %q, trace starts at %q", p.Ingress.SCIP, ids[0])
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("paths = %v, want %v", got, tc.want)
			}
			if noted := strings.Contains(res.PrecisionNote, taintFramePrecisionNote); noted != tc.noted {
				t.Errorf("precision note qualified = %v, want %v (%q)", noted, tc.noted, res.PrecisionNote)
			}
			if !strings.HasPrefix(res.PrecisionNote, "lane note") {
				t.Errorf("the lane's own note was lost: %q", res.PrecisionNote)
			}
		})
	}
}
