package trigger

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

func TestNestedRoots_LimitsFor(t *testing.T) {
	const (
		lib   = "pkg:golang/example.com/lib"
		other = "pkg:golang/example.com/other"
	)
	nestedLimit := func(sr ...plugin.ScopedReason) plugin.DependencyInventory {
		return plugin.DependencyInventory{Partiality: plugin.Partiality{Scoped: sr}}
	}
	mod := func(path string, targets ...string) plugin.ScopedReason {
		return plugin.ScopedReason{Reason: plugin.PartialReasonNestedModule, Path: path, Targets: targets}
	}
	cleared := report.AdvisoryFinding{
		Verdict:  report.VerdictNotExploitable,
		Package:  &report.Package{Ecosystem: "Go", Name: "example.com/lib", Version: "v1.0.0", PURL: lib + "@v1.0.0"},
		Evidence: report.EvidenceSummary{Basis: verdict.BasisSymbolUnreachable, Detail: "unreached"},
	}
	candidate := cleared
	candidate.Verdict, candidate.Evidence = report.VerdictReachableCandidate, report.EvidenceSummary{}

	tests := []struct {
		name        string
		inv         plugin.DependencyInventory
		dir         string
		f           report.AdvisoryFinding
		purls       []string
		settles     map[string]bool
		wantAsked   []string
		wantPath    string
		wantTargets []string
		wantSettled []string
		wantVerdict report.Verdict
	}{
		{
			name: "the one covering module settles: the limit is dropped", inv: nestedLimit(mod("a", lib), mod("b", other)), dir: "/r",
			f: cleared, purls: []string{lib}, settles: map[string]bool{"a": true},
			wantAsked: []string{"a"}, wantSettled: []string{"a"}, wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "a covering module that does not settle keeps the limit, bounded to it", inv: nestedLimit(mod("a", lib), mod("b", lib, other)), dir: "/r",
			f: cleared, purls: []string{lib}, settles: map[string]bool{"a": true},
			wantAsked: []string{"a", "b"}, wantPath: "b", wantTargets: []string{lib, other}, wantSettled: []string{"a"}, wantVerdict: report.VerdictUndetermined,
		},
		{
			name: "an unbounded module is never assessed and keeps the limit unbounded", inv: nestedLimit(mod("a", lib), mod("old")), dir: "/r",
			f: cleared, purls: []string{lib}, settles: map[string]bool{"a": true, "old": true},
			wantAsked: []string{"a"}, wantPath: "old", wantSettled: []string{"a"}, wantVerdict: report.VerdictUndetermined,
		},
		{
			name: "no module settles: the limit is unchanged", inv: nestedLimit(mod("a", lib), mod("b", other)), dir: "/r",
			f: cleared, purls: []string{lib},
			wantAsked: []string{"a"}, wantPath: "a, b", wantTargets: []string{lib, other}, wantVerdict: report.VerdictUndetermined,
		},
		{
			name: "a run-wide nested-module limit is unchanged",
			inv:  plugin.DependencyInventory{Partiality: plugin.Partiality{Reasons: []string{plugin.PartialReasonNestedModule}, Scoped: []plugin.ScopedReason{mod("a", lib)}}}, dir: "/r",
			f: cleared, purls: []string{lib}, settles: map[string]bool{"a": true},
			wantPath: "a", wantVerdict: report.VerdictUndetermined,
		},
		{
			name: "an unknown build root is unchanged", inv: nestedLimit(mod("a", lib)),
			f: cleared, purls: []string{lib}, settles: map[string]bool{"a": true},
			wantPath: "a", wantTargets: []string{lib}, wantVerdict: report.VerdictUndetermined,
		},
		{
			name: "a row with unknown packages is unchanged", inv: nestedLimit(mod("a", lib)), dir: "/r",
			f: cleared, settles: map[string]bool{"a": true},
			wantPath: "a", wantTargets: []string{lib}, wantVerdict: report.VerdictUndetermined,
		},
		{
			name: "a candidate row is never assessed in nested modules", inv: nestedLimit(mod("a", lib)), dir: "/r",
			f: candidate, purls: []string{lib}, settles: map[string]bool{"a": true},
			wantPath: "a", wantTargets: []string{lib}, wantVerdict: report.VerdictReachableCandidate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, notes := sbomFromInventory(tt.inv, "Go")
			n := newNestedRoots(context.Background(), assessment.CodebaseRef{}, nil, tt.dir, tt.inv)
			var asked []string
			n.settle = func(_ assessment.VulnRef, rel string) bool {
				asked = append(asked, rel)
				return tt.settles[rel]
			}
			limits, settled := n.limitsFor(assessment.VulnRef{ID: "GO-test"}, tt.f, notes, tt.purls)
			if !slices.Equal(asked, tt.wantAsked) {
				t.Errorf("assessed modules %v, want %v", asked, tt.wantAsked)
			}
			if !slices.Equal(settled, tt.wantSettled) {
				t.Errorf("settled %v, want %v", settled, tt.wantSettled)
			}
			var path string
			var targets []string
			for _, l := range limits {
				if l.Reason == plugin.PartialReasonNestedModule {
					path, targets = l.Path, l.Targets
				}
			}
			if path != tt.wantPath || !slices.Equal(targets, tt.wantTargets) {
				t.Errorf("nested-module limit path %q targets %v, want %q %v", path, targets, tt.wantPath, tt.wantTargets)
			}
			got := withNestedRoots(withInventoryLimits(tt.f, limits, tt.purls), settled)
			if got.Verdict != tt.wantVerdict {
				t.Errorf("verdict %s, want %s", got.Verdict, tt.wantVerdict)
			}
		})
	}
}
