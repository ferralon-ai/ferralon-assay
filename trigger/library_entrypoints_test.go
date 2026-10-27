package trigger

import (
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_RefutationAssumptionsReachEvidence: a not_exploitable grounded on a refutation that
// holds only under a declaration states it on the finding; one that rests on the scan alone states none.
func TestFinding_RefutationAssumptionsReachEvidence(t *testing.T) {
	const assumption = `library-entrypoints "none": no code outside the build imports example.com/m/lib, which reach golang.org/x/net`
	fx := netNotReached()
	if f := fx.finding(t); f.Verdict != report.VerdictNotExploitable || len(f.Evidence.Assumptions) > 0 {
		t.Fatalf("got %s with assumptions %q, want not_exploitable with none", f.Verdict, f.Evidence.Assumptions)
	}
	fx.reach.Refutation.Assumptions = []string{assumption}
	f := fx.finding(t)
	if f.Verdict != report.VerdictNotExploitable {
		t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
	}
	if !slices.Equal(f.Evidence.Assumptions, []string{assumption}) {
		t.Errorf("assumptions = %q, want %q", f.Evidence.Assumptions, []string{assumption})
	}
	if err := report.NewBuilder(report.Subject{ResolvedCommit: "c"}).AddFinding(f).Build().Validate(); err != nil {
		t.Errorf("the finding should validate: %v", err)
	}
}

// TestLibraryEntrypoints_ReadsReachabilityRecord: the resolved set comes off the reachability
// artifact, and is nil when the lane resolved none.
func TestLibraryEntrypoints_ReadsReachabilityRecord(t *testing.T) {
	want := &plugin.ResolvedLibraryEntrypoints{Source: plugin.LibraryEntrypointsSourceDeclared, Input: "pkg/api", Packages: []string{"example.com/m/pkg/api"}}
	store := artifact.NewMemStore()
	seedReachArtifact(t, store, "a", plugin.CallGraphResult{Partiality: plugin.Complete()}, plugin.ReachabilityResult{Partiality: plugin.Complete(), LibraryEntrypoints: want})
	got := libraryEntrypoints(store, "a")
	if got == nil || got.Source != want.Source || got.Input != want.Input || !slices.Equal(got.Packages, want.Packages) {
		t.Errorf("libraryEntrypoints = %+v, want %+v", got, want)
	}
	seedReachArtifact(t, store, "b", plugin.CallGraphResult{Partiality: plugin.Complete()}, plugin.ReachabilityResult{Partiality: plugin.Complete()})
	if got := libraryEntrypoints(store, "b"); got != nil {
		t.Errorf("libraryEntrypoints with none resolved = %+v, want nil", got)
	}
	if got := libraryEntrypoints(store, "missing"); got != nil {
		t.Errorf("libraryEntrypoints with no artifact = %+v, want nil", got)
	}
}
