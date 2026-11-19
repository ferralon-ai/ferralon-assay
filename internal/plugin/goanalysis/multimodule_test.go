package goanalysis

import (
	"context"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestResultPerModule is an advisory govulncheck matched to two modules of the build at module
// level. Each module is refuted on its own findings; a symbol finding in either refutes neither, and
// a module whose refutation is withheld is not refuted beside the first.
func TestResultPerModule(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/amod v0.0.0\n\texample.com/bmod v0.0.0\n)\n\n" +
			"replace example.com/amod => ./_amod\n\nreplace example.com/bmod => ./_bmod\n",
		"main.go":       "package main\n\nimport (\n\t\"example.com/amod\"\n\t\"example.com/bmod\"\n)\n\nfunc main() { amod.Safe(); bmod.Safe() }\n",
		"_amod/go.mod":  "module example.com/amod\n\ngo 1.22\n",
		"_amod/amod.go": "package amod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
		"_bmod/go.mod":  "module example.com/bmod\n\ngo 1.22\n",
		"_bmod/bmod.go": "package bmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
	}
	at := func(module string, fn string) vulnFinding {
		f := vulnFinding{OSV: "GO-1", Trace: []vulnFrame{{Module: module, Version: "v0.0.0", Package: module}}}
		f.Trace[0].Function = fn
		return f
	}
	const a, b = "example.com/amod", "example.com/bmod"
	tests := []struct {
		name     string
		findings []vulnFinding
		symbols  map[string][]string
		first    string
		beside   []string
		extra    map[string]string
		scoped   bool
	}{
		{"one module", []vulnFinding{at(a, "")}, map[string][]string{a: {"Bad"}}, "pkg:golang/" + a, nil, nil, false},
		{"two modules, path order", []vulnFinding{at(b, ""), at(a, "")}, map[string][]string{a: {"Bad"}, b: {"Bad"}}, "pkg:golang/" + a, []string{"pkg:golang/" + b}, nil, false},
		{"two modules, another platform's file calls the second", []vulnFinding{at(a, ""), at(b, "")}, map[string][]string{a: {"Bad"}, b: {"Bad"}}, "pkg:golang/" + a, []string{"pkg:golang/" + b},
			map[string]string{"main_windows.go": "package main\n\nimport \"example.com/bmod\"\n\nfunc init() { bmod.Bad() }\n"}, true},
		{"two modules, a linkname file of another platform calls the second", []vulnFinding{at(a, ""), at(b, "")}, map[string][]string{a: {"Bad"}, b: {"Bad"}}, "", nil,
			map[string]string{"main_windows.go": "package main\n\nimport (\n\t_ \"unsafe\"\n\n\t\"example.com/bmod\"\n)\n\n//go:linkname x example.com/bmod.Bad\nfunc x()\n\nfunc init() { bmod.Bad(); x() }\n"}, false},
		{"two modules, only the second's package imported", []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: a, Version: "v0.0.0"}}}, at(b, "")}, map[string][]string{a: {"Bad"}, b: {"Bad"}}, "pkg:golang/" + a, []string{"pkg:golang/" + b}, nil, false},
		{"two modules, a symbol finding in the first", []vulnFinding{at(a, "Bad"), at(b, "")}, map[string][]string{a: {"Bad"}, b: {"Bad"}}, "", nil, nil, false},
		{"two modules, a symbol finding in the second", []vulnFinding{at(a, ""), at(b, "Bad")}, map[string][]string{a: {"Bad"}, b: {"Bad"}}, "", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := maps.Clone(files)
			maps.Copy(tree, tt.extra)
			dir := writeTree(t, tree)
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			scanned := vulnScan{findings: tt.findings, symbols: tt.symbols}
			res, err := reconciledResult(context.Background(), scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if res.Refutation != nil {
				got = res.Refutation.Package
			}
			if got != tt.first {
				t.Errorf("Refutation names %q, want %q (result %+v)", got, tt.first, res)
			}
			var beside []string
			for _, r := range res.Refutations {
				beside = append(beside, r.Package)
				if r.Basis != plugin.RefutationAnalyzerSymbolNotReached || r.Detail == "" {
					t.Errorf("refutation of %s = %+v, want an analyzer_symbol_not_reached refutation with a detail", r.Package, r)
				}
			}
			for _, r := range res.Refutations {
				if scoped := strings.Contains(r.Detail, "scope:"); scoped != tt.scoped {
					t.Errorf("refutation of %s states a platform scope = %v, want %v (detail %q)", r.Package, scoped, tt.scoped, r.Detail)
				}
			}
			if res.Refutation != nil && strings.Contains(res.Refutation.Detail, "scope:") {
				t.Errorf("the first module's refutation states a scope no file of its own gave it: %q", res.Refutation.Detail)
			}
			if res.Refutation != nil {
				imported := !strings.Contains(res.Refutation.Detail, "is not imported")
				if want := tt.findings[0].Trace[0].Package != "" || tt.findings[0].Trace[0].Module != a; imported != want {
					t.Errorf("the first module's refutation says its package is imported = %v, want %v (detail %q)", imported, want, res.Refutation.Detail)
				}
			}
			const scope = plugin.PartialReasonExcludedFilesBuildConstraint
			if declared := slices.Contains(res.Partiality.Reasons, scope); declared != tt.scoped || declared && res.Partiality.Complete {
				t.Errorf("result declares %s = %v (complete %v), want %v: %+v", scope, declared, res.Partiality.Complete, tt.scoped, res.Partiality)
			}
			if !slices.Equal(beside, tt.beside) {
				t.Errorf("Refutations name %q, want %q", beside, tt.beside)
			}
		})
	}
}

// TestStatePluginScope_OtherModules: beside plugin_load:cgo_off every refutation the result holds
// states the cgo scope, the first module's or not, and the program view's too, so a binary-scoped
// refutation is never less qualified than the library's; the input's list and view are left as they were.
func TestStatePluginScope_OtherModules(t *testing.T) {
	other := []plugin.Refutation{
		{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/b", Detail: "no call path"},
		{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/c"},
	}
	first := &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/a", Detail: "no call path"}
	cases := []struct {
		name    string
		reasons []string
		first   *plugin.Refutation
		want    []string
	}{
		{"beside plugin_load:cgo_off", []string{plugin.PartialReasonPluginLoadCgoOff}, first, []string{"no call path; " + pluginScopeDetail, pluginScopeDetail}},
		{"with the first module withheld", []string{plugin.PartialReasonPluginLoadCgoOff}, nil, []string{"no call path; " + pluginScopeDetail, pluginScopeDetail}},
		{"beside plugin_load", []string{plugin.PartialReasonPluginLoad}, first, []string{"no call path", ""}},
		{"beside dropped cgo files", nil, first, []string{"no call path; " + cgoFilesScopeDetail, cgoFilesScopeDetail}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := &plugin.ProgramView{Module: "example.com/m", Binaries: []string{"."}, Refutation: plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/a", Detail: "no call path"}}
			in := plugin.ReachabilityResult{Partiality: plugin.Partial(tc.reasons...), Refutation: tc.first, Refutations: slices.Clone(other), ProgramView: view}
			if tc.reasons == nil {
				in.Partiality = plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonCgoFilesDropped, Package: "pkg:golang/example.com/cgomod"}}}
			}
			got := statePluginScope(in)
			var details []string
			for _, r := range got.Refutations {
				details = append(details, r.Detail)
			}
			if !slices.Equal(details, tc.want) {
				t.Errorf("details = %q, want %q", details, tc.want)
			}
			if !reflect.DeepEqual(in.Refutations, other) {
				t.Error("the input refutations were changed in place")
			}
			if got.ProgramView == nil || got.ProgramView.Refutation.Detail != tc.want[0] {
				t.Errorf("program view = %+v, want its detail %q", got.ProgramView, tc.want[0])
			}
			if view.Refutation.Detail != "no call path" {
				t.Error("the input program view was changed in place")
			}
			if (got.Refutation == nil) != (tc.first == nil) {
				t.Errorf("first refutation = %+v, want nil: %v", got.Refutation, tc.first == nil)
			}
		})
	}
}
