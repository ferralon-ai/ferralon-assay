package goanalysis

import (
	"context"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reflectBase is a module whose main package calls only vulnmod.Safe directly; each case adds the
// call reflection makes, if any, that runs vulnmod.Bad.
var reflectBase = map[string]string{
	"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
	"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
	"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
}

// TestReconciledResult_WithholdsForReflectReach: a refutation is withheld, declaring reflection:call,
// when a method encoding/json calls on a value it read with reflect reaches one of the advisory's
// vulnerable symbols, and stands when it reaches none of them.
func TestReconciledResult_WithholdsForReflectReach(t *testing.T) {
	const tag = "package main\n\nimport (\n\t\"encoding/json\"\n\n\t\"example.com/vulnmod\"\n)\n\ntype Tag string\n\nfunc main() {\n\tvulnmod.Safe()\n\t_, _ = json.Marshal(Tag(\"x\"))\n}\n\n"
	finding := func(symbols map[string][]string) vulnScan {
		return vulnScan{
			findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}},
			imports:  map[string][]string{"example.com/vulnmod": {"example.com/vulnmod"}},
			symbols:  symbols,
		}
	}
	bad := map[string][]string{"example.com/vulnmod": {"Bad"}}
	cases := []struct {
		name     string
		main     string
		scanned  vulnScan
		withheld bool
	}{
		{"MarshalJSON calls a vulnerable symbol",
			tag + "func (Tag) MarshalJSON() ([]byte, error) { vulnmod.Bad(); return nil, nil }\n", finding(bad), true},
		{"MarshalJSON calls no vulnerable symbol",
			tag + "func (Tag) MarshalJSON() ([]byte, error) { vulnmod.Safe(); return nil, nil }\n", finding(bad), false},
		{"MarshalJSON calls a symbol the advisory does not list",
			tag + "func (Tag) MarshalJSON() ([]byte, error) { vulnmod.Bad(); return nil, nil }\n", finding(map[string][]string{"example.com/vulnmod": {"Other"}}), false},
		{"the advisory lists no symbols, so every function in the package is vulnerable",
			tag + "func (Tag) MarshalJSON() ([]byte, error) { vulnmod.Safe(); return nil, nil }\n", finding(nil), true},
		{"a method no interface call matches",
			tag + "func (Tag) Marshal() ([]byte, error) { vulnmod.Bad(); return nil, nil }\n", finding(bad), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(reflectBase, map[string]string{"main.go": tc.main}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			res, err := reconciledResult(context.Background(), tc.scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil })
			if err != nil {
				t.Fatal(err)
			}
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("refutation withheld = %v, want %v (result %+v)", withheld, tc.withheld, res)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonReflectiveCall); declared != tc.withheld {
				t.Errorf("reflection:call declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestReflectReachOf: what reflection's calls reach is bounded by the calls that make them. A function
// used as a value is reached once reflect's Call is live or a dynamic call matches its signature, and
// an exported method once reflect's MethodByName is live; neither is reached without them.
func TestReflectReachOf(t *testing.T) {
	const hidden = "func hidden(n int8) string { vulnmod.Bad(); return \"\" }\n\n"
	const hook = "type S struct{}\n\nfunc (S) Hook() { vulnmod.Bad() }\n\n"
	main := func(imports, body string) string {
		return "package main\n\nimport (\n" + imports + "\t\"example.com/vulnmod\"\n)\n\n" + body
	}
	cases := []struct {
		name    string
		main    string
		reached bool
	}{
		{"a function value reflect's Call runs",
			main("\t\"reflect\"\n", hidden+"func main() { vulnmod.Safe(); reflect.ValueOf(hidden).Call([]reflect.Value{reflect.ValueOf(int8(1))}) }\n"), true},
		{"a function value nothing calls",
			main("", hidden+"var keep any\n\nfunc main() { vulnmod.Safe(); keep = hidden }\n"), false},
		{"a function value reflection hands back and a call of its signature runs",
			main("\t\"reflect\"\n", hidden+"type holder struct{ F func(int8) string }\n\nfunc main() {\n\tvulnmod.Safe()\n\th := holder{F: hidden}\n\tf := reflect.ValueOf(h).Field(0).Interface().(func(int8) string)\n\t_ = f(1)\n}\n"), true},
		{"an exported method reflect's MethodByName names",
			main("\t\"reflect\"\n", hook+"func main() { vulnmod.Safe(); reflect.ValueOf(S{}).MethodByName(\"Hook\").Call(nil) }\n"), true},
		{"an exported method of a type converted to an interface, with no reflective method call",
			main("", hook+"var keep any\n\nfunc main() { vulnmod.Safe(); keep = S{} }\n"), false},
		{"a function reflect's MakeFunc wraps, called through the function it makes",
			main("\t\"reflect\"\n", "func impl(args []reflect.Value) []reflect.Value { vulnmod.Bad(); return []reflect.Value{reflect.ValueOf(\"\")} }\n\nfunc main() {\n\tvulnmod.Safe()\n\tvar f func(int8) string\n\treflect.ValueOf(&f).Elem().Set(reflect.MakeFunc(reflect.TypeOf(f), impl))\n\t_ = f(1)\n}\n"), true},
		{"a finalizer runtime.SetFinalizer sets, which the runtime calls",
			main("\t\"runtime\"\n", "type T struct{}\n\nfunc fin(*T) { vulnmod.Bad() }\n\nfunc main() {\n\tvulnmod.Safe()\n\truntime.SetFinalizer(new(T), fin)\n}\n"), true},
		{"a function value of any signature, once a finalizer is set through an interface",
			main("\t\"runtime\"\n", "type T struct{}\n\nvar keep = func(complex64, int8) { vulnmod.Bad() }\n\nfunc set(f any) { runtime.SetFinalizer(new(T), f) }\n\nfunc main() {\n\tvulnmod.Safe()\n\tset(func(*T) {})\n}\n"), true},
		{"a function value of another signature than the finalizer runtime.SetFinalizer sets",
			main("\t\"runtime\"\n", "type T struct{}\n\nvar keep = func(complex64, int8) { vulnmod.Bad() }\n\nfunc main() {\n\tvulnmod.Safe()\n\truntime.SetFinalizer(new(T), func(*T) {})\n}\n"), false},
		{"a function value of any signature, once runtime.SetFinalizer is called through a function value",
			main("\t\"runtime\"\n", "type T struct{}\n\nvar keep = func(complex64, int8) { vulnmod.Bad() }\n\nvar sf = runtime.SetFinalizer\n\nfunc main() {\n\tvulnmod.Safe()\n\tsf(new(T), func(*T) {})\n}\n"), true},
		{"a function value of any signature, when the finalizer runtime.SetFinalizer sets is nil",
			main("\t\"runtime\"\n", "type T struct{}\n\nvar keep = func(complex64, int8) { vulnmod.Bad() }\n\nfunc main() {\n\tvulnmod.Safe()\n\truntime.SetFinalizer(new(T), nil)\n}\n"), false},
		{"a pointer method of a struct field's type encoding/json decodes into",
			main("\t\"encoding/json\"\n", "type Inner struct{}\n\nfunc (*Inner) UnmarshalJSON([]byte) error { vulnmod.Bad(); return nil }\n\ntype Outer struct{ In Inner }\n\nfunc main() {\n\tvulnmod.Safe()\n\tvar o Outer\n\t_ = json.Unmarshal([]byte(\"{}\"), &o)\n}\n"), true},
		{"a method an interface call names before its type is converted",
			main("", "type I interface{ m() }\n\ntype T struct{}\n\nfunc (T) m() { vulnmod.Bad() }\n\nfunc mk() I { return T{} }\n\nfunc main() { vulnmod.Safe(); mk().m() }\n"), true},
		{"an exported method of a type converted after reflect's MethodByName is live",
			main("\t\"reflect\"\n", hook+"func mk3() any { return S{} }\n\nfunc mk2() any { return mk3() }\n\nfunc mk() any { return mk2() }\n\nfunc main() {\n\tvulnmod.Safe()\n\tx := mk()\n\tif m, ok := reflect.TypeOf(x).MethodByName(\"Hook\"); ok {\n\t\tm.Func.Call([]reflect.Value{reflect.ValueOf(x)})\n\t}\n}\n"), true},
		{"a function used as a value after reflect's Call is live",
			main("\t\"reflect\"\n", hidden+"func pick3() func(int8) string { return hidden }\n\nfunc pick2() func(int8) string { return pick3() }\n\nfunc pick() func(int8) string { return pick2() }\n\nfunc main() { vulnmod.Safe(); reflect.ValueOf(pick()).Call([]reflect.Value{reflect.ValueOf(int8(1))}) }\n"), true},
		{"an entry point reflect's Call runs, which govulncheck searched already",
			main("\t\"os\"\n\t\"reflect\"\n", "func main() {\n\tvulnmod.Bad()\n\tif len(os.Args) > 9 {\n\t\treflect.ValueOf(main).Call(nil)\n\t}\n}\n"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(reflectBase, map[string]string{"main.go": tc.main}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			_, reach, err := reflectReachOf(load)
			if err != nil {
				t.Fatal(err)
			}
			if reached := slices.Contains(reach["example.com/vulnmod"], "Bad"); reached != tc.reached {
				t.Errorf("vulnmod.Bad reached = %v, want %v (reach %v)", reached, tc.reached, reach["example.com/vulnmod"])
			}
		})
	}
}

// TestReflectReaches: with the advisory's vulnerable symbols known, only one of them in the reach
// counts; with no vulnerable package known, any function of the refuted module does.
func TestReflectReaches(t *testing.T) {
	reach := map[string][]string{"example.com/vulnmod": {"Safe"}, "example.com/other": {"Bad"}}
	for _, tc := range []struct {
		name       string
		module     string
		vulnerable map[string][]string
		want       bool
	}{
		{"a listed symbol reached", "example.com/vulnmod", map[string][]string{"example.com/vulnmod": {"Safe"}}, true},
		{"no listed symbol reached", "example.com/vulnmod", map[string][]string{"example.com/vulnmod": {"Bad"}}, false},
		{"no vulnerable package known, the module reached", "example.com/vulnmod", nil, true},
		{"no vulnerable package known, the module not reached", "example.com/absent", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reflectReaches(reach, tc.module, tc.vulnerable); got != tc.want {
				t.Errorf("reflectReaches(%s) = %v, want %v", tc.module, got, tc.want)
			}
		})
	}
}

// TestWithholdForReflectReach_UnknownReach: with no reach to read, a refutation is withheld.
func TestWithholdForReflectReach_UnknownReach(t *testing.T) {
	res := plugin.ReachabilityResult{Refutation: &plugin.Refutation{Package: "pkg:golang/example.com/vulnmod"}}
	got := withholdForReflectReach(res, vulnScan{}, nil)
	if got.Refutation != nil || !slices.Contains(got.Partiality.Reasons, plugin.PartialReasonReflectiveCall) {
		t.Errorf("withholdForReflectReach(nil reach) = %+v, want the refutation withheld as reflection:call", got)
	}
}

// TestReflectReachOf_IllTyped: the whole-program build makes no bodies for a package that does not
// type-check, so what reflection reaches through one is unknown.
func TestReflectReachOf_IllTyped(t *testing.T) {
	main := "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n"
	for _, tc := range []struct {
		name    string
		vulnmod string
		unknown bool
	}{
		{"every package type-checks", "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n", false},
		{"a dependency does not type-check", "package vulnmod\n\nfunc Safe() { var x int = \"s\"; _ = x }\n\nfunc Bad() {}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(reflectBase, map[string]string{"main.go": main, "_vulnmod/vulnmod.go": tc.vulnmod}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, reach, _ := reflectReachOf(load); (reach == nil) != tc.unknown {
				t.Errorf("reflectReachOf reach unknown = %v, want %v", reach == nil, tc.unknown)
			}
		})
	}
}

// TestWithholdForReflectReach_NotGo: a refutation of a package outside the Go ecosystem names no
// module the reach can be read for, so it is withheld.
func TestWithholdForReflectReach_NotGo(t *testing.T) {
	res := plugin.ReachabilityResult{Refutation: &plugin.Refutation{Package: "pkg:npm/vulnmod"}}
	got := withholdForReflectReach(res, vulnScan{}, map[string][]string{})
	if got.Refutation != nil || !slices.Contains(got.Partiality.Reasons, plugin.PartialReasonReflectiveCall) {
		t.Errorf("withholdForReflectReach(pkg:npm) = %+v, want the refutation withheld as reflection:call", got)
	}
}

// TestVulnerableSymbols: an advisory's symbols are listed by package; a package one of its entries
// lists without symbols stands for every function in it.
func TestVulnerableSymbols(t *testing.T) {
	const stream = `{"osv":{"id":"GO-2025-0001","affected":[{"package":{"name":"golang.org/x/text"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/text/language","symbols":["Parse","MustParse"]},{"path":"golang.org/x/text/language","symbols":["Parse"]},{"path":"golang.org/x/text/cases"}]}}]}}
{"osv":{"id":"GO-2025-0002","affected":[{"package":{"name":"golang.org/x/text"},"ecosystem_specific":{"imports":[{"path":"golang.org/x/text/cases","symbols":["Fold"]}]}}]}}
`
	scanned, err := parseFindings([]byte(stream), "GO-2025-0001")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"golang.org/x/text/language": {"MustParse", "Parse"}, "golang.org/x/text/cases": nil}
	if got := scanned.vulnerableSymbols("golang.org/x/text"); !reflect.DeepEqual(got, want) {
		t.Errorf("vulnerableSymbols = %v, want %v", got, want)
	}
}
