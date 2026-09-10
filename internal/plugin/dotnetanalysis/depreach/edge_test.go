package depreach

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestBackingEdgeCompactDropsProvenance(t *testing.T) {
	caller := plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: "app", Name: "Ingress"}
	callee := plugin.Symbol{Kind: plugin.SymbolKindMethod, Package: "dep", Name: "Sink"}
	be := BackingEdge{
		From:       caller,
		To:         callee,
		Kind:       assembly.EdgeCallvirt,
		Producer:   "cha",
		Origin:     EdgeOrigin{Assembly: "dep.dll", Method: assembly.Token(0x0600_0001), ILOffset: 0x2a},
		Confidence: ConfConservative,
	}

	got := be.Compact()
	if got.Caller != caller || got.Callee != callee {
		t.Fatalf("compact endpoints = %+v, want caller=%+v callee=%+v", got, caller, callee)
	}

	// The public projection is exactly {Caller, Callee} — it carries no provenance.
	fields := map[string]bool{}
	rt := reflect.TypeOf(plugin.CallEdge{})
	for i := 0; i < rt.NumField(); i++ {
		fields[rt.Field(i).Name] = true
	}
	if len(fields) != 2 || !fields["Caller"] || !fields["Callee"] {
		t.Fatalf("plugin.CallEdge fields = %v, want exactly {Caller, Callee}", fields)
	}
	for _, banned := range []string{"Producer", "Origin", "Confidence", "Kind"} {
		if fields[banned] {
			t.Fatalf("plugin.CallEdge unexpectedly carries provenance field %q", banned)
		}
	}
}

func TestConfidenceStatesDistinct(t *testing.T) {
	all := []Confidence{ConfResolved, ConfConservative, ConfBoundary}
	seenVal := map[Confidence]bool{}
	seenStr := map[string]bool{}
	for _, c := range all {
		if seenVal[c] {
			t.Fatalf("duplicate Confidence value %d", c)
		}
		if seenStr[c.String()] {
			t.Fatalf("duplicate Confidence string %q", c.String())
		}
		seenVal[c] = true
		seenStr[c.String()] = true
	}
	if ConfResolved.String() != "resolved" || ConfConservative.String() != "conservative" || ConfBoundary.String() != "boundary" {
		t.Fatalf("unexpected Confidence strings: %q %q %q", ConfResolved, ConfConservative, ConfBoundary)
	}
}
