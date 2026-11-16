package report

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestValidateGroundsPerVerdict: a not_exploitable rests on a refutation basis and a disqualified on
// a version, symbol or intake basis. No basis, an unknown one, or one from the other verdict's set
// that the two do not share is rejected.
func TestValidateGroundsPerVerdict(t *testing.T) {
	ne := map[verdict.NonExploitableBasis]bool{
		verdict.BasisVersionNotAffected:        true,
		verdict.BasisSymbolAbsent:              true,
		verdict.BasisSymbolUnreachable:         true,
		verdict.BasisStaticRefutation:          true,
		verdict.BasisAdvisoryEcosystemMismatch: false,
		verdict.BasisNoManifestEntry:           false,
		verdict.BasisNone:                      false,
		"looked_hard":                          false,
	}
	disq := map[verdict.NonExploitableBasis]bool{
		verdict.BasisVersionNotAffected:        true,
		verdict.BasisSymbolAbsent:              true,
		verdict.BasisAdvisoryEcosystemMismatch: true,
		verdict.BasisNoManifestEntry:           true,
		verdict.BasisSymbolUnreachable:         false,
		verdict.BasisStaticRefutation:          false,
		verdict.BasisNone:                      false,
		"looked_hard":                          false,
	}
	for v, cases := range map[Verdict]map[verdict.NonExploitableBasis]bool{VerdictNotExploitable: ne, VerdictDisqualified: disq} {
		for basis, wantOK := range cases {
			t.Run(string(v)+"/"+string(basis), func(t *testing.T) {
				f := AdvisoryFinding{Advisory: Advisory{ID: "X", Source: "osv"}, Verdict: v,
					Evidence: EvidenceSummary{Basis: basis, Detail: "grounds"}}
				err := NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(f).Build().Validate()
				if wantOK && err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				if !wantOK && err == nil {
					t.Fatal("want rejected, got nil")
				}
			})
		}
	}
}
