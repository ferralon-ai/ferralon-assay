package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestFinding_PackageNotImportedGroundsSymbolAbsent: a lane refutation saying the build imports none
// of the advisory's vulnerable packages grounds not_exploitable on vulnerable_symbol_absent, where a
// search that reached no symbol grounds vulnerable_symbol_unreachable.
func TestFinding_PackageNotImportedGroundsSymbolAbsent(t *testing.T) {
	tests := []struct {
		basis string
		want  verdict.NonExploitableBasis
	}{
		{plugin.RefutationAnalyzerPackageNotImported, verdict.BasisSymbolAbsent},
		{plugin.RefutationAnalyzerSymbolNotReached, verdict.BasisSymbolUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.basis, func(t *testing.T) {
			f := symbolProvenanceFinding(t, spRecord{provenance: "diff-lexed", refutation: &plugin.Refutation{
				Basis: tt.basis, Package: spPURL, Detail: "the analyzer traced no call",
			}})
			if f.Verdict != report.VerdictNotExploitable || f.Evidence.Basis != tt.want {
				t.Fatalf("verdict = %q basis %q (reason %q), want not_exploitable on %q", f.Verdict, f.Evidence.Basis, f.UndeterminedReason, tt.want)
			}
			if want := "Newtonsoft.Json@12.0.3: the analyzer traced no call (" + tt.basis + ")"; f.Evidence.Detail != want {
				t.Errorf("detail = %q, want %q", f.Evidence.Detail, want)
			}
		})
	}
}
