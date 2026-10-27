package report

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// TestValidateAssumptionsOnlyOnNotExploitable: a declaration only ever lets a refutation stand, so an
// assumption may qualify a not_exploitable and nothing else.
func TestValidateAssumptionsOnlyOnNotExploitable(t *testing.T) {
	assumptions := []string{`library-entrypoints "none": no code outside the build imports example.com/m/lib, which reach example.com/v`}
	ne := NewBuilder(Subject{ResolvedCommit: "c"}).
		AddFinding(AdvisoryFinding{
			Advisory: Advisory{ID: "X", Source: "osv"},
			Verdict:  VerdictNotExploitable,
			Evidence: EvidenceSummary{Basis: verdict.BasisSymbolAbsent, Detail: "d", Assumptions: assumptions},
		}).Build()
	if err := ne.Validate(); err != nil {
		t.Fatalf("a not_exploitable carrying an assumption should validate, got: %v", err)
	}
	for _, f := range []AdvisoryFinding{
		{Verdict: VerdictReachableCandidate, Evidence: EvidenceSummary{ReachablePath: "a → b", Assumptions: assumptions}},
		{Verdict: VerdictUndetermined, UndeterminedReason: ReasonVulnerableSymbolUnresolved,
			Evidence: EvidenceSummary{Detail: UndeterminedDetail(ReasonVulnerableSymbolUnresolved), Assumptions: assumptions}},
	} {
		f.Advisory = Advisory{ID: "X", Source: "osv"}
		r := NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(f).Build()
		if err := r.Validate(); err == nil {
			t.Errorf("verdict %q: expected Validate to reject an assumption", f.Verdict)
		}
		f.Evidence.Assumptions = nil
		if err := NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(f).Build().Validate(); err != nil {
			t.Errorf("verdict %q without the assumption should validate, got: %v", f.Verdict, err)
		}
	}
}

// TestBuilderLibraryEntrypoints: the first resolved set recorded for an ecosystem stands, each
// ecosystem keeps its own, the list is sorted by ecosystem, and it survives the report's JSON.
func TestBuilderLibraryEntrypoints(t *testing.T) {
	golang := plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceDeclared, Input: "none", Packages: []string{}}
	maven := plugin.ResolvedLibraryEntrypoints{Ecosystem: "maven", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto", Packages: []string{"com.example:lib"}}
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		WithLibraryEntrypoints().
		WithLibraryEntrypoints(maven, golang).
		WithLibraryEntrypoints(plugin.ResolvedLibraryEntrypoints{Ecosystem: "golang", Source: plugin.LibraryEntrypointsSourceAuto, Input: "auto"}).
		Build()
	want := []plugin.ResolvedLibraryEntrypoints{golang, maven}
	if !reflect.DeepEqual(r.LibraryEntrypoints, want) {
		t.Fatalf("LibraryEntrypoints = %+v, want %+v", r.LibraryEntrypoints, want)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.LibraryEntrypoints, want) {
		t.Errorf("round trip = %+v, want %+v", back.LibraryEntrypoints, want)
	}
	if empty := NewBuilder(Subject{ResolvedCommit: "c"}).Build(); empty.LibraryEntrypoints != nil {
		t.Errorf("no set recorded, got %+v", empty.LibraryEntrypoints)
	}
}
