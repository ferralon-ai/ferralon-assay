package report

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// Disqualified used to fill verdict.BasisVersionNotAffected for every disqualification it
// recorded, so a caller could not express one that was never adjudicated on the version or
// symbol axis — the builder would assert a version comparison on its behalf. The basis is a
// parameter now, and none of it is inferred.
func TestBuilderDisqualified_RecordsTheBasisItIsGiven(t *testing.T) {
	for _, basis := range []verdict.NonExploitableBasis{
		verdict.BasisVersionNotAffected,
		verdict.BasisSymbolAbsent,
		verdict.BasisNone,
	} {
		r := NewBuilder(Subject{Repo: "github.com/example/widget"}).
			Disqualified(Advisory{ID: "GO-2021-0001", Source: "osv"}, nil, basis, "grounds").
			Build()

		if len(r.Advisories) != 1 {
			t.Fatalf("findings: got %d, want 1", len(r.Advisories))
		}
		f := r.Advisories[0]
		if f.Verdict != VerdictDisqualified {
			t.Errorf("basis %q: verdict = %q, want %q", basis, f.Verdict, VerdictDisqualified)
		}
		if f.Evidence.Basis != basis {
			t.Errorf("basis = %q, want %q", f.Evidence.Basis, basis)
		}
	}
}
