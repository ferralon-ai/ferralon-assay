package goanalysis

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReconciledResult_WithholdsForUnsearchedMethods: an exported method govulncheck never searches (one
// of a generic type, or one promoted from a type outside its entry points) withholds a refutation
// when the package declaring it imports the refuted module, directly or through other packages, and
// leaves it standing otherwise. The library packages are internal, so library_escape stays out of it.
func TestReconciledResult_WithholdsForUnsearchedMethods(t *testing.T) {
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
		imports:  map[string][]string{"stdlib": {"encoding/xml"}},
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
			"internal/lib/lib.go": "package lib\n\nimport \"encoding/xml\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Decode() *xml.Decoder { return xml.NewDecoder(nil) }\n",
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
			res, err := reconciledResult(context.Background(), tc.scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
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

// TestReconciledResult_WithholdsForLibraryEscape: a refutation is withheld whenever an importable package
// reaches the refuted module, however it hands a value of it to its importer and whether or not a
// main package is in the build, and stands when only main or internal packages do.
func TestReconciledResult_WithholdsForLibraryEscape(t *testing.T) {
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
		imports:  map[string][]string{"stdlib": {"encoding/xml"}},
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
			"lib/lib.go": "package lib\n\nimport \"encoding/xml\"\n\nfunc New() *xml.Decoder { return xml.NewDecoder(nil) }\n",
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
			res, err := reconciledResult(context.Background(), tc.scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
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

// narrowedModule is a dependency module whose advisory names one vulnerable package, ssh, beside
// packages that do not reach it (blake, iface) and packages that do (wrap, alias, emb). ssh's type
// satisfies iface's interface without iface importing ssh, and ssh's init registers a value of it in
// iface: a value of the vulnerable package's type held by a package that does not reach it.
var narrowedModule = map[string]string{
	"go.mod":                "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
	"main.go":               "package main\n\nimport \"example.com/vulnmod/blake\"\n\nfunc main() { blake.Sum() }\n",
	"_vulnmod/go.mod":       "module example.com/vulnmod\n\ngo 1.22\n",
	"_vulnmod/ssh/ssh.go":   "package ssh\n\nimport \"example.com/vulnmod/iface\"\n\ntype Client struct{}\n\nfunc (Client) Dial() {}\n\nfunc Dial() {}\n\nfunc init() { iface.Default = Client{} }\n",
	"_vulnmod/blake/b.go":   "package blake\n\ntype T struct{}\n\nfunc (T) Sum() {}\n\nfunc Sum() {}\n",
	"_vulnmod/iface/i.go":   "package iface\n\ntype Dialer interface{ Dial() }\n\nvar Default Dialer\n",
	"_vulnmod/wrap/wrap.go": "package wrap\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc Get() func() { return ssh.Dial }\n",
	"_vulnmod/alias/a.go":   "package alias\n\nimport \"example.com/vulnmod/ssh\"\n\ntype C = ssh.Client\n",
	"_vulnmod/emb/emb.go":   "package emb\n\nimport \"example.com/vulnmod/ssh\"\n\ntype T struct{ ssh.Client }\n",
}

// narrowedScans are the advisory's statements about example.com/vulnmod: one naming ssh as its
// vulnerable package; one that also lists the module with no packages (wholeModule); and none at all,
// with only a finding naming ssh. The last two make every package of the module count.
var narrowedScans = struct{ narrow, wholeModule, noEntry vulnScan }{
	narrow:      vulnScan{imports: map[string][]string{"example.com/vulnmod": {"example.com/vulnmod/ssh"}}},
	wholeModule: vulnScan{imports: map[string][]string{"example.com/vulnmod": {"example.com/vulnmod/ssh"}}, wholeModule: map[string]bool{"example.com/vulnmod": true}},
	noEntry:     vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod/ssh"}}}}},
}

func narrowedRefutation() plugin.ReachabilityResult {
	return plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod"},
	}
}

// TestWithholdForUnsearchedMethods_VulnerablePackages: when the advisory names the module's vulnerable
// packages, an unsearched method withholds only when its declaring package reaches one of them; the
// module's other packages do not count, unless the advisory lists the module whole or not at all.
// A method promoted from, or named by an alias of, the vulnerable package's type is declared there.
func TestWithholdForUnsearchedMethods_VulnerablePackages(t *testing.T) {
	const box = "type Box[T any] struct{ v T }\n\n"
	s := narrowedScans
	cases := []struct {
		name     string
		lib      string
		scanned  vulnScan
		withheld bool
	}{
		{"a generic type's package imports another package of the module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\n" + box + "func (Box[T]) Run() { blake.Sum() }\n", s.narrow, false},
		{"a generic type's package imports the vulnerable package",
			"package lib\n\nimport \"example.com/vulnmod/ssh\"\n\n" + box + "func (Box[T]) Run() { ssh.Dial() }\n", s.narrow, true},
		{"a generic type's package reaches the vulnerable package through another package of the module",
			"package lib\n\nimport \"example.com/vulnmod/wrap\"\n\n" + box + "func (Box[T]) Run() { wrap.Get()() }\n", s.narrow, true},
		{"the advisory also lists the whole module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\n" + box + "func (Box[T]) Run() { blake.Sum() }\n", s.wholeModule, true},
		{"no advisory entry lists the module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\n" + box + "func (Box[T]) Run() { blake.Sum() }\n", s.noEntry, true},
		{"a method promoted from another package's type of the module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\ntype S struct{ blake.T }\n", s.narrow, false},
		{"a method promoted from the vulnerable package's type",
			"package lib\n\nimport \"example.com/vulnmod/ssh\"\n\ntype S struct{ ssh.Client }\n", s.narrow, true},
		{"a method promoted through another package's type that embeds the vulnerable package's type",
			"package lib\n\nimport \"example.com/vulnmod/emb\"\n\ntype S struct{ emb.T }\n", s.narrow, true},
		{"an alias to the vulnerable package's type",
			"package lib\n\nimport \"example.com/vulnmod/ssh\"\n\ntype A = ssh.Client\n", s.narrow, true},
		{"an alias to another package's alias of the vulnerable package's type",
			"package lib\n\nimport \"example.com/vulnmod/alias\"\n\ntype A = alias.C\n", s.narrow, true},
		{"an alias to another package's type of the module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\ntype A = blake.T\n", s.narrow, false},
		{"a generic method calls an interface the vulnerable package's type satisfies",
			"package lib\n\nimport \"example.com/vulnmod/iface\"\n\n" + box + "func (Box[T]) Run() { iface.Default.Dial() }\n", s.narrow, false},
		{"a generic type constrained by an interface the vulnerable package's type satisfies",
			"package lib\n\nimport \"example.com/vulnmod/iface\"\n\ntype Box[T iface.Dialer] struct{ v T }\n\nfunc (b Box[T]) Run() { b.v.Dial() }\n", s.narrow, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(narrowedModule, map[string]string{"internal/lib/lib.go": tc.lib}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if incompleteLoad(load.Packages) {
				t.Fatal("load incomplete")
			}
			res := withholdForUnsearchedMethods(narrowedRefutation(), tc.scanned, load.Packages)
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonUnsearchedMethods); declared != tc.withheld {
				t.Errorf("unsearched_methods declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestWithholdForLibraryEscape_VulnerablePackages: when the advisory names the module's vulnerable
// packages, an entry point withholds only when it reaches one of them, however a value of the
// vulnerable package's type would be handed through it; the module's other packages do not count,
// unless the advisory lists the module whole or not at all. A declaration that takes a package out
// of the entry points records an assumption only when that package reaches a vulnerable package.
func TestWithholdForLibraryEscape_VulnerablePackages(t *testing.T) {
	s := narrowedScans
	cases := []struct {
		name       string
		lib        string
		decl       string
		scanned    vulnScan
		withheld   bool
		assumption bool
	}{
		{"an entry point imports another package of the module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\nfunc Get() func() { return blake.Sum }\n", "auto", s.narrow, false, false},
		{"an entry point imports the vulnerable package",
			"package lib\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc Get() func() { return ssh.Dial }\n", "auto", s.narrow, true, false},
		{"an entry point reaches the vulnerable package through another package of the module",
			"package lib\n\nimport \"example.com/vulnmod/wrap\"\n\nfunc Get() func() { return wrap.Get() }\n", "auto", s.narrow, true, false},
		{"the advisory also lists the whole module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\nfunc Get() func() { return blake.Sum }\n", "auto", s.wholeModule, true, false},
		{"no advisory entry lists the module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\nfunc Get() func() { return blake.Sum }\n", "auto", s.noEntry, true, false},
		{"an entry point aliases another package's alias of the vulnerable package's type",
			"package lib\n\nimport \"example.com/vulnmod/alias\"\n\ntype C = alias.C\n", "auto", s.narrow, true, false},
		{"an entry point embeds another package's type that embeds the vulnerable package's type",
			"package lib\n\nimport \"example.com/vulnmod/emb\"\n\ntype S struct{ emb.T }\n", "auto", s.narrow, true, false},
		{"an entry point instantiates a generic type with the vulnerable package's type",
			"package lib\n\nimport \"example.com/vulnmod/ssh\"\n\ntype Box[T any] struct{ V T }\n\nvar B = Box[ssh.Client]{}\n", "auto", s.narrow, true, false},
		{"an entry point hands out an interface value the vulnerable package's init registers",
			"package lib\n\nimport \"example.com/vulnmod/iface\"\n\nfunc Get() iface.Dialer { return iface.Default }\n", "auto", s.narrow, false, false},
		{"an entry point calls an interface the vulnerable package's type satisfies",
			"package lib\n\nimport \"example.com/vulnmod/iface\"\n\nfunc Use(d iface.Dialer) { d.Dial() }\n", "auto", s.narrow, false, false},
		{"an entry point's generic function constrained by an interface the vulnerable package's type satisfies",
			"package lib\n\nimport \"example.com/vulnmod/iface\"\n\nfunc Use[T iface.Dialer](t T) { t.Dial() }\n", "auto", s.narrow, false, false},
		{"a declaration takes out a package that imports another package of the module",
			"package lib\n\nimport \"example.com/vulnmod/blake\"\n\nfunc Get() func() { return blake.Sum }\n", "none", s.narrow, false, false},
		{"a declaration takes out a package that imports the vulnerable package",
			"package lib\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc Get() func() { return ssh.Dial }\n", "none", s.narrow, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(narrowedModule, map[string]string{"lib/lib.go": tc.lib}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if incompleteLoad(load.Packages) {
				t.Fatal("load incomplete")
			}
			decl, err := plugin.ParseLibraryEntrypoints(tc.decl)
			if err != nil {
				t.Fatal(err)
			}
			entry := resolveEntrypoints(load.Packages, decl, dir)
			res := withholdForLibraryEscape(narrowedRefutation(), tc.scanned, load.Packages, entry)
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonLibraryEscape); declared != tc.withheld {
				t.Errorf("library_escape declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
			if !tc.withheld {
				if assumed := len(res.Refutation.Assumptions) > 0; assumed != tc.assumption {
					t.Errorf("assumption recorded = %v, want %v (%v)", assumed, tc.assumption, res.Refutation.Assumptions)
				}
			}
		})
	}
}

// TestNarrowedGates_StandardLibraryWidening: a standard-library refutation widens to every standard
// package in both gates when the advisory lists the standard library whole or lists none of its
// packages, even though a finding names the one it traced; otherwise only the listed packages count.
func TestNarrowedGates_StandardLibraryWidening(t *testing.T) {
	tree := map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.22\n",
		"lib/lib.go": "package lib\n\nimport \"strings\"\n\ntype Box[T any] struct{ v T }\n\nfunc (Box[T]) Run() string { return strings.ToUpper(\"x\") }\n\nfunc Get() func(string) string { return strings.ToUpper }\n",
	}
	listed := map[string][]string{"stdlib": {"net/http"}}
	scans := []struct {
		name     string
		scanned  vulnScan
		withheld bool
	}{
		{"the advisory lists only a package the build does not reach", vulnScan{imports: listed}, false},
		{"the advisory also lists the whole standard library", vulnScan{imports: listed, wholeModule: map[string]bool{"stdlib": true}}, true},
		{"no advisory entry lists a standard package, a finding names one", vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "stdlib", Package: "net/http"}}}}}, true},
	}
	gates := []struct {
		name   string
		reason string
		run    func(plugin.ReachabilityResult, vulnScan, []*packages.Package, entrypoints) plugin.ReachabilityResult
	}{
		{"unsearched methods", plugin.PartialReasonUnsearchedMethods, func(r plugin.ReachabilityResult, s vulnScan, pkgs []*packages.Package, _ entrypoints) plugin.ReachabilityResult {
			return withholdForUnsearchedMethods(r, s, pkgs)
		}},
		{"library escape", plugin.PartialReasonLibraryEscape, withholdForLibraryEscape},
	}
	dir := writeTree(t, tree)
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if incompleteLoad(load.Packages) {
		t.Fatal("load incomplete")
	}
	entry := resolveEntrypoints(load.Packages, plugin.LibraryEntrypoints{}, dir)
	for _, g := range gates {
		for _, tc := range scans {
			t.Run(g.name+"/"+tc.name, func(t *testing.T) {
				res := g.run(plugin.ReachabilityResult{
					Partiality: plugin.Complete(),
					Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/stdlib"},
				}, tc.scanned, load.Packages, entry)
				if withheld := res.Refutation == nil; withheld != tc.withheld {
					t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
				}
				if declared := slices.Contains(res.Partiality.Reasons, g.reason); declared != tc.withheld {
					t.Errorf("%s declared = %v, want %v (partiality %+v)", g.reason, declared, tc.withheld, res.Partiality)
				}
			})
		}
	}
}

// TestWithholdForUnsearchedMethods_DeclaringPackageNotLoaded: a method whose declaring package the
// load does not hold withholds, though that package would not reach the vulnerable one. The load is
// cut by hand: a complete load always holds it.
func TestWithholdForUnsearchedMethods_DeclaringPackageNotLoaded(t *testing.T) {
	dir := writeTree(t, merge(narrowedModule, map[string]string{
		"internal/lib/lib.go": "package lib\n\nimport \"example.com/vulnmod/blake\"\n\ntype S struct{ blake.T }\n",
	}))
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var lib *packages.Package
	for _, p := range load.Packages {
		if p.PkgPath == "example.com/m/internal/lib" {
			lib = p
		}
	}
	if lib == nil {
		t.Fatal("internal/lib not loaded")
	}
	lib.Imports = map[string]*packages.Package{}
	res := withholdForUnsearchedMethods(narrowedRefutation(), narrowedScans.narrow, []*packages.Package{lib})
	if res.Refutation != nil {
		t.Fatal("refutation stands, want withheld")
	}
	if !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonUnsearchedMethods) {
		t.Errorf("unsearched_methods not declared (partiality %+v)", res.Partiality)
	}
}
