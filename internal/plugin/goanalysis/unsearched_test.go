package goanalysis

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestScanResult_WithholdsForUnsearchedMethods: an exported method govulncheck never searches (one
// of a generic type, or one promoted from a type outside its entry points) withholds a refutation
// when the package declaring it imports the refuted module, directly or through other packages, and
// leaves it standing otherwise. The library packages are internal, so library_escape stays out of it.
func TestScanResult_WithholdsForUnsearchedMethods(t *testing.T) {
	base := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n\ntype T struct{}\n\nfunc (T) M() { Bad() }\n\ntype G[X any] struct{ v X }\n\nfunc (G[X]) M() { Bad() }\n",
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
			"internal/lib/lib.go": lib + "type S struct{}\n\nfunc (S) Dispatch() { vulnmod.Bad() }\n",
		}, moduleFinding, false},
		{"an exported method of a generic library type", map[string]string{
			"internal/lib/lib.go": lib + "type Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() { vulnmod.Bad() }\n",
		}, moduleFinding, true},
		{"an exported pointer method of a generic library type", map[string]string{
			"internal/lib/lib.go": lib + "type Box[T any] struct{ v T }\n\nfunc (*Box[T]) Dispatch() { vulnmod.Bad() }\n",
		}, moduleFinding, true},
		{"a generic library type whose package reaches the module through another package", map[string]string{
			"internal/lib/lib.go":     "package lib\n\nimport \"example.com/m/internal/inner\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() { inner.Run() }\n",
			"internal/inner/inner.go": "package inner\n\nimport \"example.com/vulnmod\"\n\nfunc Run() { vulnmod.Bad() }\n",
		}, moduleFinding, true},
		{"a generic library type whose package does not import the module", map[string]string{
			"internal/lib/lib.go": "package lib\n\nimport \"strings\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() string { return strings.ToUpper(\"x\") }\n",
		}, moduleFinding, false},
		{"an unexported method of a generic library type", map[string]string{
			"internal/lib/lib.go": lib + "type Box[T any] struct{ v T }\n\nfunc (Box[T]) dispatch() { vulnmod.Bad() }\n\nfunc Run() { Box[int]{}.dispatch() }\n\nvar _ = vulnmod.Safe\n",
		}, moduleFinding, false},
		{"a generic type in the main package", map[string]string{
			"main.go": "package main\n\nimport \"example.com/vulnmod\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() { vulnmod.Bad() }\n\nfunc main() { vulnmod.Safe() }\n",
		}, moduleFinding, false},
		{"a method promoted from the module's type", map[string]string{
			"internal/lib/lib.go": lib + "type S struct{ vulnmod.T }\n",
		}, moduleFinding, true},
		{"a method promoted into a type declared in a library function", map[string]string{
			"internal/lib/lib.go": lib + "func New() any {\n\ttype s struct{ vulnmod.T }\n\treturn s{}\n}\n",
		}, moduleFinding, true},
		{"an alias to an instantiation of the module's generic type", map[string]string{
			"internal/lib/lib.go": lib + "type A = vulnmod.G[int]\n",
		}, moduleFinding, true},
		{"a generic alias to the module's generic type", map[string]string{
			"go.mod":              "module example.com/m\n\ngo 1.24\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
			"internal/lib/lib.go": lib + "type A[X any] = vulnmod.G[X]\n",
		}, moduleFinding, true},
		{"an alias to a struct embedding the module's type", map[string]string{
			"internal/lib/lib.go": lib + "type A = struct{ vulnmod.T }\n",
		}, moduleFinding, true},
		{"an alias to a type from a package that does not import the module", map[string]string{
			"internal/lib/lib.go": "package lib\n\nimport \"strings\"\n\ntype A = strings.Builder\n",
		}, moduleFinding, false},
		{"standard-library refutation, a generic type's package imports the vulnerable package", map[string]string{
			"internal/lib/lib.go": "package lib\n\nimport \"net/http\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Serve() error { return http.ListenAndServe(\":0\", nil) }\n",
		}, stdlibFinding, true},
		{"standard-library refutation, a generic type's package imports another standard package", map[string]string{
			"internal/lib/lib.go": "package lib\n\nimport \"strings\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Dispatch() string { return strings.ToUpper(\"x\") }\n",
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

// TestScanResult_WithholdsForLibraryEscape: a refutation is withheld whenever an importable package
// reaches the refuted module, however it hands a value of it to its importer and whether or not a
// main package is in the build, and stands when only main or internal packages do.
func TestScanResult_WithholdsForLibraryEscape(t *testing.T) {
	base := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/neutral v0.0.0\n\texample.com/vulnmod v0.0.0\n)\n\nreplace example.com/vulnmod => ./_vulnmod\n\nreplace example.com/neutral => ./_neutral\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Bad() {}\n\ntype I interface{ M() }\n\ntype T struct{}\n\nfunc (T) M() { Bad() }\n\nfunc (T) Close() error { Bad(); return nil }\n",
		"_neutral/go.mod":     "module example.com/neutral\n\ngo 1.22\n",
		"_neutral/neutral.go": "package neutral\n\ntype Runner struct{ F func() }\n\nfunc (r Runner) Run() { r.F() }\n\ntype I interface{ M() }\n\ntype Caller struct{ I }\n\nfunc (c Caller) Call() { c.I.M() }\n",
	}
	const lib = "package lib\n\nimport \"example.com/vulnmod\"\n\n"
	const libNeutral = "package lib\n\nimport (\n\t\"example.com/neutral\"\n\t\"example.com/vulnmod\"\n)\n\n"
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
		{"a result of an interface type the module's type implements", map[string]string{
			"lib/lib.go": "package lib\n\nimport (\n\t\"io\"\n\n\t\"example.com/vulnmod\"\n)\n\nfunc New() io.Closer { return vulnmod.T{} }\n",
		}, moduleFinding, true},
		{"a result of a function type", map[string]string{
			"lib/lib.go": lib + "func Get() func() { return vulnmod.Bad }\n",
		}, moduleFinding, true},
		{"an exported var", map[string]string{
			"lib/lib.go": lib + "var Handler = vulnmod.Bad\n",
		}, moduleFinding, true},
		{"an embedded interface of the module", map[string]string{
			"lib/lib.go": lib + "type S struct{ vulnmod.I }\n\nfunc New() S { return S{vulnmod.T{}} }\n",
		}, moduleFinding, true},
		{"an embedded struct carrying the module's function", map[string]string{
			"lib/lib.go": libNeutral + "type L struct{ neutral.Runner }\n\nfunc New() L { return L{neutral.Runner{F: vulnmod.Bad}} }\n",
		}, moduleFinding, true},
		{"an embedded struct carrying the module's type as an interface", map[string]string{
			"lib/lib.go": libNeutral + "type L struct{ neutral.Caller }\n\nfunc New() L { return L{neutral.Caller{I: vulnmod.T{}}} }\n",
		}, moduleFinding, true},
		{"an embedded generic struct of a package that does not import the module", map[string]string{
			"util/util.go": "package util\n\ntype GRunner[T any] struct{ F func() }\n\nfunc (g GRunner[T]) Run() { g.F() }\n",
			"lib/lib.go":   "package lib\n\nimport (\n\t\"example.com/m/util\"\n\t\"example.com/vulnmod\"\n)\n\ntype L struct{ util.GRunner[int] }\n\nfunc New() L { return L{util.GRunner[int]{F: vulnmod.Bad}} }\n",
		}, moduleFinding, true},
		{"a package reaching the module through a dependency's package", map[string]string{
			"_neutral/go.mod":       "module example.com/neutral\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
			"_neutral/wrap/wrap.go": "package wrap\n\nimport \"example.com/vulnmod\"\n\nfunc Get() func() { return vulnmod.Bad }\n",
			"lib/lib.go":            "package lib\n\nimport \"example.com/neutral/wrap\"\n\nfunc Get() func() { return wrap.Get() }\n",
		}, moduleFinding, true},
		{"no package reaches the module", map[string]string{
			"lib/lib.go": "package lib\n\nimport \"strings\"\n\nfunc Upper(s string) string { return strings.ToUpper(s) }\n",
		}, moduleFinding, false},
		{"a package that does not type-check", map[string]string{
			"lib/lib.go": "package lib\n\nvar N int = \"x\"\n",
		}, moduleFinding, true},
		{"a main package beside an importable package that reaches the module", map[string]string{
			"pkg/lib/lib.go": lib + "func Get() func() { return vulnmod.Bad }\n",
			"cmd/x/main.go":  "package main\n\nimport \"example.com/m/pkg/lib\"\n\nfunc main() { _ = lib.Get() }\n",
		}, moduleFinding, true},
		{"a main package beside only internal packages that reach the module", map[string]string{
			"internal/lib/lib.go": lib + "func Get() func() { return vulnmod.Bad }\n",
			"cmd/x/main.go":       "package main\n\nimport \"example.com/m/internal/lib\"\n\nfunc main() { _ = lib.Get() }\n",
		}, moduleFinding, false},
		{"a module whose own path has an internal element", map[string]string{
			"go.mod":     strings.Replace(base["go.mod"], "module example.com/m\n", "module example.com/internal/m\n", 1),
			"lib/lib.go": lib + "func Get() func() { return vulnmod.Bad }\n",
		}, moduleFinding, true},
		{"an internal package of a module whose own path has an internal element", map[string]string{
			"go.mod":              strings.Replace(base["go.mod"], "module example.com/m\n", "module example.com/internal/m\n", 1),
			"internal/lib/lib.go": lib + "func Get() func() { return vulnmod.Bad }\n",
			"cmd/x/main.go":       "package main\n\nimport \"example.com/internal/m/internal/lib\"\n\nfunc main() { _ = lib.Get() }\n",
		}, moduleFinding, false},
		{"a main package that reaches the module itself", map[string]string{
			"cmd/x/main.go": "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { _ = vulnmod.T{} }\n",
		}, moduleFinding, false},
		{"a directory holding only a test in package main", map[string]string{
			"pkg/lib/lib.go":   lib + "func Get() func() { return vulnmod.Bad }\n",
			"e2e/main_test.go": "package main\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
		}, moduleFinding, true},
		{"a directory holding only a test in package main, nothing reaching the module", map[string]string{
			"lib/lib.go":       "package lib\n\nimport \"strings\"\n\nfunc Upper(s string) string { return strings.ToUpper(s) }\n",
			"e2e/main_test.go": "package main\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
		}, moduleFinding, false},
		{"standard-library refutation, a package imports the vulnerable package", map[string]string{
			"lib/lib.go": "package lib\n\nimport \"net/http\"\n\nfunc Handler() http.Handler { return http.NotFoundHandler() }\n",
		}, stdlibFinding, true},
		{"standard-library refutation, no package imports the vulnerable package", map[string]string{
			"lib/lib.go": "package lib\n\nimport \"strings\"\n\nfunc Upper(s string) string { return strings.ToUpper(s) }\n",
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
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonLibraryEscape); declared != tc.withheld {
				t.Errorf("library_escape declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
			if slices.Contains(res.Partiality.Reasons, plugin.PartialReasonUnsearchedMethods) {
				t.Errorf("unsearched_methods declared with no unsearched method reaching the module (partiality %+v)", res.Partiality)
			}
		})
	}
}
