package cfamilyanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestResolveDependencySymbols_SymbolAbsent covers P1.4 on the plugin side: a request naming no
// symbol (the C/C++ advisory norm) declares advisory_symbol_absent, loud, with an empty result;
// one naming a symbol is left to the graph engine.
func TestResolveDependencySymbols_SymbolAbsent(t *testing.T) {
	for _, c := range []struct {
		name    string
		symbols []string
		want    string
	}{
		{"nil", nil, plugin.PartialReasonAdvisorySymbolAbsent},
		{"blank", []string{"", "  "}, plugin.PartialReasonAdvisorySymbolAbsent},
		{"named", []string{"inflate"}, plugin.PartialReasonUnsupported},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{AdvisorySymbols: c.symbols})
			if err != nil {
				t.Fatal(err)
			}
			if res.Partiality.Complete || len(res.Partiality.Reasons) != 1 || res.Partiality.Reasons[0] != c.want {
				t.Errorf("partiality = %+v, want Partial(%s)", res.Partiality, c.want)
			}
			if len(res.Resolved) != 0 {
				t.Errorf("resolved = %v, want none", res.Resolved)
			}
		})
	}
}
