package goanalysis

import (
	"context"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestResultPerModule is an advisory govulncheck matched to two modules of the build at module
// level. Each module is refuted on its own findings; a symbol finding in either refutes neither.
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
			if !slices.Equal(beside, tt.beside) {
				t.Errorf("Refutations name %q, want %q", beside, tt.beside)
			}
		})
	}
}
