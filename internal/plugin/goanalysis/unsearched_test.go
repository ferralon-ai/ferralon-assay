package goanalysis

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestScanResult_WithholdsForUnsearchedMethods: an exported method govulncheck never searches (one
// of a generic type, or one promoted from a type outside its entry points) withholds a refutation
// when the package declaring it imports the refuted module, directly or through other packages, and
// leaves it standing otherwise.
func TestScanResult_WithholdsForUnsearchedMethods(t *testing.T) {
	base := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n\ntype T struct{}\n\nfunc (T) M() { Bad() }\n",
	}
	const lib = "package lib\n\nimport \"example.com/vulnmod\"\n\n"
	moduleFinding := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}}
	stdlibFinding := vulnScan{
		findings: []vulnFinding{{OSV: "GO-2", Trace: []vulnFrame{{Module: "stdlib", Version: "v1.22.0"}}}},
		imports:  map[string][]string{"stdlib": {"net/http"}},
	}
	cases := []struct {
		name     string
		files    map[string]string
		scanned  vulnScan
		withheld bool
	}{
		{"an exported method of a library type, which govulncheck searches", map[string]string{
			"lib/lib.go": lib + "type S struct{}\n\nfunc (S) Dispatch() { vulnmod.Bad() }\n",
		}, moduleFinding, false},
		{"an exported method of a generic library type", map[string]string{
			"lib/lib.go": lib + "type Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() { vulnmod.Bad() }\n",
		}, moduleFinding, true},
		{"an exported pointer method of a generic library type", map[string]string{
			"lib/lib.go": lib + "type Box[T any] struct{ v T }\n\nfunc (*Box[T]) Dispatch() { vulnmod.Bad() }\n",
		}, moduleFinding, true},
		{"a generic library type whose package reaches the module through another package", map[string]string{
			"lib/lib.go":     "package lib\n\nimport \"example.com/m/inner\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() { inner.Run() }\n",
			"inner/inner.go": "package inner\n\nimport \"example.com/vulnmod\"\n\nfunc Run() { vulnmod.Bad() }\n",
		}, moduleFinding, true},
		{"a generic library type whose package does not import the module", map[string]string{
			"lib/lib.go": "package lib\n\nimport \"strings\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() string { return strings.ToUpper(\"x\") }\n",
		}, moduleFinding, false},
		{"an unexported method of a generic library type", map[string]string{
			"lib/lib.go": lib + "type Box[T any] struct{ v T }\n\nfunc (Box[T]) dispatch() { vulnmod.Bad() }\n\nfunc Run() { Box[int]{}.dispatch() }\n\nvar _ = vulnmod.Safe\n",
		}, moduleFinding, false},
		{"a generic type in the main package", map[string]string{
			"main.go": "package main\n\nimport \"example.com/vulnmod\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() { vulnmod.Bad() }\n\nfunc main() { vulnmod.Safe() }\n",
		}, moduleFinding, false},
		{"a method promoted from the module's type", map[string]string{
			"lib/lib.go": lib + "type S struct{ vulnmod.T }\n",
		}, moduleFinding, true},
		{"a method promoted into a type declared in a library function", map[string]string{
			"lib/lib.go": lib + "func New() any {\n\ttype s struct{ vulnmod.T }\n\treturn s{}\n}\n",
		}, moduleFinding, true},
		{"standard-library refutation, a generic type's package imports the vulnerable package", map[string]string{
			"lib/lib.go": "package lib\n\nimport \"net/http\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Serve() error { return http.ListenAndServe(\":0\", nil) }\n",
		}, stdlibFinding, true},
		{"standard-library refutation, a generic type's package imports another standard package", map[string]string{
			"lib/lib.go": "package lib\n\nimport \"strings\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() string { return strings.ToUpper(\"x\") }\n",
		}, stdlibFinding, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(base, tc.files))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			res, err := scanResult(context.Background(), tc.scanned, load, dir, append(os.Environ(), "GOWORK=off"))
			if err != nil {
				t.Fatal(err)
			}
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("refutation withheld = %v, want %v (result %+v)", withheld, tc.withheld, res)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonUnsearchedMethods); declared != tc.withheld {
				t.Errorf("unsearched_methods declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
			if slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles) {
				t.Errorf("excluded_files declared with nothing left out (partiality %+v)", res.Partiality)
			}
		})
	}
}
