package goanalysis

import (
	"context"
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestResultPerModule_NotImported is an advisory naming two modules of the build, one whose
// vulnerable package the build imports and never calls into, one whose vulnerable package no file
// imports. A module after the first is restated as not imported on its own findings. The first
// keeps analyzer_symbol_not_reached beside another module's package-level finding, which its
// restate reads as a finding it cannot place.
func TestResultPerModule_NotImported(t *testing.T) {
	const a, b = "example.com/amod", "example.com/bmod"
	tree := func(imported string) map[string]string {
		return map[string]string{
			"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/amod v0.0.0\n\texample.com/bmod v0.0.0\n)\n\n" +
				"replace example.com/amod => ./_amod\n\nreplace example.com/bmod => ./_bmod\n",
			"main.go":       "package main\n\nimport x \"" + imported + "\"\n\nfunc main() { x.Safe() }\n",
			"_amod/go.mod":  "module example.com/amod\n\ngo 1.22\n",
			"_amod/amod.go": "package amod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
			"_bmod/go.mod":  "module example.com/bmod\n\ngo 1.22\n",
			"_bmod/bmod.go": "package bmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
		}
	}
	const reached, absent = plugin.RefutationAnalyzerSymbolNotReached, plugin.RefutationAnalyzerPackageNotImported
	tests := []struct {
		name          string
		imported      string
		first, beside string
	}{
		{"the first module's package is imported", a, reached, absent},
		{"the second module's package is imported", b, reached, reached},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tree(tt.imported))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			module := func(m string) vulnFinding {
				f := vulnFinding{OSV: "GO-1", Trace: []vulnFrame{{Module: m, Version: "v0.0.0"}}}
				if m == tt.imported {
					f.Trace[0].Package = m
				}
				return f
			}
			scanned := vulnScan{
				findings: []vulnFinding{module(a), module(b)},
				symbols:  map[string][]string{a: {"Bad"}, b: {"Bad"}},
				imports:  map[string][]string{a: {a}, b: {b}},
			}
			res, err := reconciledResult(context.Background(), scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
			if err != nil {
				t.Fatal(err)
			}
			if res.Refutation == nil || res.Refutation.Package != "pkg:golang/"+a || res.Refutation.Basis != tt.first {
				t.Errorf("Refutation = %+v, want %s refuted as %s", res.Refutation, a, tt.first)
			}
			if len(res.Refutations) != 1 || res.Refutations[0].Package != "pkg:golang/"+b || res.Refutations[0].Basis != tt.beside {
				t.Errorf("Refutations = %+v, want %s refuted as %s", res.Refutations, b, tt.beside)
			}
		})
	}
}
