package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// A disqualification on the symbol axis used to emit a self-contradicting pair of fields:
//
//	basis:  version_not_in_affected_range
//	detail: the vulnerable symbol is absent from the built artifact
//
// verdict.BasisSymbolAbsent already declares the right value. Each grounded axis states the
// grounds it actually stands on.
func TestDisqualBasis_GroundedAxesStateTheirOwnGrounds(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   verdict.NonExploitableBasis
	}{
		{pipeline.ReasonVersionNotInRange, verdict.BasisVersionNotAffected},
		{pipeline.ReasonSymbolAbsent, verdict.BasisSymbolAbsent},
	} {
		f := disqualFinding(t, tc.reason)
		if f.Evidence.Basis != tc.want {
			t.Errorf("reason %q: basis = %q, want %q", tc.reason, f.Evidence.Basis, tc.want)
		}
		if string(f.Evidence.Basis) != tc.reason {
			t.Errorf("reason %q: basis %q names a different axis than the reason code",
				tc.reason, f.Evidence.Basis)
		}
	}
}
