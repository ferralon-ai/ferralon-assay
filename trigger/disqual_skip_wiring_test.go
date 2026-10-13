package trigger

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// analysisCountingPlugin is the hermetic stub with a count of the symbol and reach operations S4/S5
// make.
type analysisCountingPlugin struct {
	plugin.StubPlugin
	calls *atomic.Int32
}

func (p analysisCountingPlugin) ResolveDependencySymbols(ctx context.Context, req plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	p.calls.Add(1)
	return p.StubPlugin.ResolveDependencySymbols(ctx, req)
}

func (p analysisCountingPlugin) CallGraph(ctx context.Context, req plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	p.calls.Add(1)
	return p.StubPlugin.CallGraph(ctx, req)
}

func (p analysisCountingPlugin) FindIngresses(ctx context.Context, req plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	p.calls.Add(1)
	return p.StubPlugin.FindIngresses(ctx, req)
}

func (p analysisCountingPlugin) Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	p.calls.Add(1)
	return p.StubPlugin.Reachability(ctx, req)
}

// TestAssessSkipsAnalysisForDisqualified pins that every run mode's assess skips the symbol and reach
// work for an advisory S3 disqualified, so the saving can't silently regress. The advisory names
// golang.org/x/text; a go.mod without it disqualifies at intake, and one that requires it does not
// and must still make the calls.
func TestAssessSkipsAnalysisForDisqualified(t *testing.T) {
	for _, tc := range []struct {
		name         string
		goMod        string
		disqualified bool
	}{
		{"disqualified", "module example.com/target\n\ngo 1.21\n", true},
		{"not disqualified", "module example.com/target\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.6\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			store, id, err := assess(context.Background(), assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "GO-2021-0113", Source: "osv"},
				Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "main"},
			},
				pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, tc.goMod), lang: "go"}),
				pipeline.WithPlugin(analysisCountingPlugin{calls: &calls}),
			)
			if err != nil {
				t.Fatalf("assess: %v", err)
			}
			if got, reason := disqualResult(store, id); got != tc.disqualified {
				t.Fatalf("disqualified = %v (reason %q), want %v", got, reason, tc.disqualified)
			}
			if n := calls.Load(); tc.disqualified && n != 0 {
				t.Errorf("disqualified advisory made %d symbol/reach calls, want 0", n)
			} else if !tc.disqualified && n == 0 {
				t.Error("advisory that is not disqualified made no symbol/reach calls")
			}
		})
	}
}
