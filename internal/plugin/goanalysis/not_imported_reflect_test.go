package goanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestWithholdForReflectReach_NotImported: reflection runs only code the build compiles in, so a
// refutation resting on the build importing none of the vulnerable packages stands against a reach
// that is unknown or holds the module's symbols, where one resting on no path found is withheld.
func TestWithholdForReflectReach_NotImported(t *testing.T) {
	const module = "example.com/vulnmod"
	holds := map[string][]string{module + "/ssh": {"Dial"}}
	scanned := vulnScan{imports: map[string][]string{module: {module + "/ssh"}}, symbols: map[string][]string{module + "/ssh": {"Dial"}}}
	for _, tc := range []struct {
		name     string
		basis    string
		reach    map[string][]string
		withheld bool
	}{
		{"not imported, reach unknown", plugin.RefutationAnalyzerPackageNotImported, nil, false},
		{"not imported, reach holds the symbol", plugin.RefutationAnalyzerPackageNotImported, holds, false},
		{"not reached, reach unknown", plugin.RefutationAnalyzerSymbolNotReached, nil, true},
		{"not reached, reach holds the symbol", plugin.RefutationAnalyzerSymbolNotReached, holds, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := plugin.ReachabilityResult{Partiality: plugin.Complete(), Refutation: &plugin.Refutation{Basis: tc.basis, Package: "pkg:golang/" + module}}
			got := withholdForReflectReach(res, scanned, tc.reach)
			declared := slices.Contains(got.Partiality.Reasons, plugin.PartialReasonReflectiveCall)
			if (got.Refutation == nil) != tc.withheld || declared != tc.withheld {
				t.Errorf("refutation = %+v, reasons = %v, want withheld = %v", got.Refutation, got.Partiality.Reasons, tc.withheld)
			}
		})
	}
}

// TestResultFromGraph_NotImportedStandsAgainstUnknownReflectReach: on a complete load that imports
// none of the vulnerable packages, the lane's result keeps its refutation with the reflect reach
// unknown, and declares none of the limits that rest on reaching those packages.
func TestResultFromGraph_NotImportedStandsAgainstUnknownReflectReach(t *testing.T) {
	dir := writeTree(t, narrowedModule)
	loaded, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded.buildGoVersion = loaded.goVersion
	scanned := vulnScan{
		imports:  narrowedScans.narrow.imports,
		symbols:  map[string][]string{"example.com/vulnmod/ssh": {"Dial"}},
		findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0"}}}},
	}
	g := reconcileGraph{CallGraph: plugin.CallGraphResult{Partiality: plugin.Complete()}}
	ctx := WithRunCacheDir(context.Background(), t.TempDir())
	res, err := resultFromGraph(ctx, scanned, g, dir, summaryEnv(), func() (*LoadResult, error) { return loaded, nil }, plugin.LibraryEntrypoints{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refutation == nil || res.Refutation.Basis != plugin.RefutationAnalyzerPackageNotImported {
		t.Fatalf("refutation = %+v (partiality %+v), want one on %s", res.Refutation, res.Partiality, plugin.RefutationAnalyzerPackageNotImported)
	}
	for _, r := range []string{plugin.PartialReasonReflectiveCall, plugin.PartialReasonUnsearchedMethods, plugin.PartialReasonLibraryEscape} {
		if slices.Contains(res.Partiality.Reasons, r) {
			t.Errorf("declared %s beside the refutation: %v", r, res.Partiality.Reasons)
		}
	}
}
