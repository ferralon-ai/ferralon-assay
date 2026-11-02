package goanalysis

import (
	"context"
	"os"
	"reflect"
	"slices"
	"strings"
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
			res, err := reconciledResult(context.Background(), tc.scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
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
			_, reach, err := reflectReachOf(load, nil)
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
// type-check, so what reflection reaches through one is unknown, unless a partial run could not load
// that package and reads the reach only outside what imports it.
func TestReflectReachOf_IllTyped(t *testing.T) {
	main := "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n"
	illTyped := "package vulnmod\n\nfunc Safe() { var x int = \"s\"; _ = x }\n\nfunc Bad() {}\n"
	for _, tc := range []struct {
		name    string
		vulnmod string
		known   []string
		unknown bool
	}{
		{"every package type-checks", "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n", nil, false},
		{"a dependency does not type-check", illTyped, nil, true},
		{"a partial run could not load it", illTyped, []string{"example.com/vulnmod"}, false},
		{"a partial run could not load another", illTyped, []string{"example.com/other"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(reflectBase, map[string]string{"main.go": main, "_vulnmod/vulnmod.go": tc.vulnmod}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, reach, _ := reflectReachOf(load, tc.known); (reach == nil) != tc.unknown {
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

// vulnmodFinding is a package-level govulncheck finding of example.com/vulnmod whose advisory lists
// vulnmod.Bad: govulncheck found no call path to it, so the result carries a refutation.
var vulnmodFinding = vulnScan{
	findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}},
	imports:  map[string][]string{"example.com/vulnmod": {"example.com/vulnmod"}},
	symbols:  map[string][]string{"example.com/vulnmod": {"Bad"}},
}

// reconcileFor loads the module files make and returns its reconcile graph and the reconciled
// result for scanned under entry.
func reconcileFor(t *testing.T, files map[string]string, scanned vulnScan, entry plugin.LibraryEntrypoints) (reconcileGraph, plugin.ReachabilityResult) {
	t.Helper()
	dir := writeTree(t, merge(reflectBase, files))
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	loadFn := func() (*LoadResult, error) { return load, nil }
	g, err := reconcileCallGraph(context.Background(), dir, nil, loadFn)
	if err != nil {
		t.Fatal(err)
	}
	res, err := reconciledResult(context.Background(), scanned, dir, append(os.Environ(), "GOWORK=off"), loadFn, entry)
	if err != nil {
		t.Fatal(err)
	}
	return g, res
}

// TestReconciledResult_ReflectAdmission: each program imports vulnmod, calls only vulnmod.Safe
// directly, and reaches CALLEE only through a call reflection or a template makes. With CALLEE Bad
// the refutation is withheld and reflection:call declared for this advisory; with CALLEE Safe the
// refutation stands and nothing declares reflection:call, so a program that runs templates or
// reflection and never calls the vulnerable symbol keeps its not_exploitable ground.
func TestReconciledResult_ReflectAdmission(t *testing.T) {
	const imports = "package main\n\nimport (\n\t\"os\"\n\t\"reflect\"\n\t\"text/template\"\n\n\t\"example.com/vulnmod\"\n)\n\nvar _, _, _ = os.Stdout, reflect.TypeOf, template.New\n\n"
	cases := []struct{ name, main string }{
		{"a value reflect builds from an interface method's parameter type",
			imports + "type Secret struct{}\n\nfunc (*Secret) Hook() { vulnmod.CALLEE() }\n\ntype Iface interface{ Take(*Secret) }\n\nfunc main() {\n\tvulnmod.Safe()\n\tit := reflect.TypeOf((*Iface)(nil)).Elem()\n\tp := reflect.New(it.Method(0).Type.In(0).Elem())\n\tp.MethodByName(\"Hook\").Call(nil)\n}\n"},
		{"a value reflect builds from an unexported interface method's parameter type",
			imports + "type Secret struct{}\n\nfunc (*Secret) Hook() { vulnmod.CALLEE() }\n\ntype Iface interface{ take(*Secret) }\n\nfunc main() {\n\tvulnmod.Safe()\n\tit := reflect.TypeOf((*Iface)(nil)).Elem()\n\tp := reflect.New(it.Method(0).Type.In(0).Elem())\n\tp.MethodByName(\"Hook\").Call(nil)\n}\n"},
		{"a value reflect builds from an embedded interface method's result type",
			imports + "type Secret struct{}\n\nfunc (*Secret) Hook() { vulnmod.CALLEE() }\n\ntype Inner interface{ Give() *Secret }\n\ntype Iface interface{ Inner }\n\nfunc main() {\n\tvulnmod.Safe()\n\tit := reflect.TypeOf((*Iface)(nil)).Elem()\n\tp := reflect.New(it.Method(0).Type.Out(0).Elem())\n\tp.MethodByName(\"Hook\").Call(nil)\n}\n"},
		{"MethodByName on a value of an admitted type",
			imports + "type S struct{}\n\nfunc (S) Hook() { vulnmod.CALLEE() }\n\nfunc main() {\n\tvulnmod.Safe()\n\treflect.ValueOf(S{}).MethodByName(\"Hook\").Call(nil)\n}\n"},
		{"reflect's Call on a function value",
			imports + "func hidden() { vulnmod.CALLEE() }\n\nvar f = hidden\n\nfunc main() {\n\tvulnmod.Safe()\n\treflect.ValueOf(f).Call(nil)\n}\n"},
		{"a method of a struct a template executes over",
			imports + "type D struct{}\n\nfunc (D) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ .Do }}\")).Execute(os.Stdout, D{})\n}\n"},
		{"a function in a template's FuncMap",
			imports + "func main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Funcs(template.FuncMap{\"f\": vulnmod.CALLEE}).Parse(\"{{ f }}\")).Execute(os.Stdout, nil)\n}\n"},
		{"a FuncMap function returning a concrete type with a method",
			imports + "type Client struct{}\n\nfunc (*Client) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc newClient() *Client { return &Client{} }\n\nfunc main() {\n\tvulnmod.Safe()\n\tt := template.Must(template.New(\"t\").Funcs(template.FuncMap{\"c\": newClient}).Parse(\"{{ c.Do }}\"))\n\t_ = t.Execute(os.Stdout, nil)\n}\n"},
		{"a method on a map value of a template's data",
			imports + "type V struct{}\n\nfunc (V) Do() string { vulnmod.CALLEE(); return \"\" }\n\ntype D struct{ M map[string]V }\n\nfunc main() {\n\tvulnmod.Safe()\n\tt := template.Must(template.New(\"t\").Parse(\"{{ .M.k.Do }}\"))\n\t_ = t.Execute(os.Stdout, D{M: map[string]V{\"k\": {}}})\n}\n"},
		{"a template's call builtin on a func field",
			imports + "func hidden() string { vulnmod.CALLEE(); return \"\" }\n\ntype D struct{ F func() string }\n\nfunc main() {\n\tvulnmod.Safe()\n\tt := template.Must(template.New(\"t\").Parse(\"{{ call .F }}\"))\n\t_ = t.Execute(os.Stdout, D{F: hidden})\n}\n"},
		{"a method on the result of a data method, in html/template",
			"package main\n\nimport (\n\t\"html/template\"\n\t\"os\"\n\n\t\"example.com/vulnmod\"\n)\n\ntype Inner struct{}\n\nfunc (Inner) Do() string { vulnmod.CALLEE(); return \"\" }\n\ntype D struct{}\n\nfunc (D) Get() Inner { return Inner{} }\n\nfunc main() {\n\tvulnmod.Safe()\n\tt := template.Must(template.New(\"t\").Parse(\"{{ .Get.Do }}\"))\n\t_ = t.Execute(os.Stdout, D{})\n}\n"},
		{"template data passed through a generic helper",
			imports + "type V struct{}\n\nfunc (V) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc render[T any](v T) { _ = template.Must(template.New(\"t\").Parse(\"{{ .Do }}\")).Execute(os.Stdout, v) }\n\nfunc main() {\n\tvulnmod.Safe()\n\trender(V{})\n}\n"},
		{"an embedded type's promoted method in a template",
			imports + "type base struct{}\n\nfunc (base) Do() string { vulnmod.CALLEE(); return \"\" }\n\ntype D struct{ base }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ .Do }}\")).Execute(os.Stdout, D{})\n}\n"},
		{"a method on an element of a slice a template ranges over",
			imports + "type V struct{}\n\nfunc (V) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ range . }}{{ .Do }}{{ end }}\")).Execute(os.Stdout, []V{{}})\n}\n"},
		{"a method on an element of an array a template ranges over",
			imports + "type V struct{}\n\nfunc (V) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ range . }}{{ .Do }}{{ end }}\")).Execute(os.Stdout, [1]V{})\n}\n"},
		{"a method on a value received from a channel a template ranges over",
			imports + "type V struct{}\n\nfunc (V) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc main() {\n\tvulnmod.Safe()\n\tc := make(chan V, 1)\n\tc <- V{}\n\tclose(c)\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ range . }}{{ .Do }}{{ end }}\")).Execute(os.Stdout, c)\n}\n"},
		{"a method on a map key a template ranges over",
			imports + "type V struct{}\n\nfunc (V) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ range $k, $v := . }}{{ $k.Do }}{{ end }}\")).Execute(os.Stdout, map[V]int{{}: 1})\n}\n"},
		{"a method on a type first returned as an interface from a template-called method",
			imports + "type Inner struct{}\n\nfunc (Inner) Do() string { vulnmod.CALLEE(); return \"\" }\n\ntype Mid struct{}\n\nfunc (Mid) Get() Inner { return Inner{} }\n\ntype D struct{}\n\nfunc (D) M() any { return Mid{} }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ .M.Get.Do }}\")).Execute(os.Stdout, D{})\n}\n"},
		{"a closure a template-called method declares and calls",
			imports + "type D struct{}\n\nfunc (D) Do() string {\n\tf := func() { vulnmod.CALLEE() }\n\tf()\n\treturn \"\"\n}\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ .Do }}\")).Execute(os.Stdout, D{})\n}\n"},
	}
	for _, tc := range cases {
		for _, callee := range []string{"Bad", "Safe"} {
			withheld := callee == "Bad"
			t.Run(tc.name+"/"+callee, func(t *testing.T) {
				_, res := reconcileFor(t, map[string]string{"main.go": strings.ReplaceAll(tc.main, "CALLEE", callee)}, vulnmodFinding, plugin.LibraryEntrypoints{})
				if got := res.Refutation == nil; got != withheld {
					t.Fatalf("refutation withheld = %v, want %v (result %+v)", got, withheld, res)
				}
				if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonReflectiveCall); declared != withheld {
					t.Errorf("reflection:call declared = %v, want %v (partiality %+v)", declared, withheld, res.Partiality)
				}
			})
		}
	}
}

// TestReconciledResult_ReflectivePluginLoad: a plugin.Open only a template's call reaches is still
// declared, though the call reaching it is bounded rather than declared.
func TestReconciledResult_ReflectivePluginLoad(t *testing.T) {
	main := "package main\n\nimport (\n\t\"os\"\n\t\"plugin\"\n\t\"text/template\"\n\n\t\"example.com/vulnmod\"\n)\n\ntype D struct{}\n\nfunc (D) Do() string { _, _ = plugin.Open(\"x.so\"); return \"\" }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ .Do }}\")).Execute(os.Stdout, D{})\n}\n"
	_, res := reconcileFor(t, map[string]string{"main.go": main}, vulnmodFinding, plugin.LibraryEntrypoints{})
	if !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonPluginLoad) {
		t.Errorf("plugin_load not declared (partiality %+v)", res.Partiality)
	}
}

// TestReconciledResult_IllTypedReach: a dependency that does not type-check below the top level
// still loads, but what reflection reaches through it is unknown, so the refutation never stands.
// Under auto the library_escape withhold also drops it; with no library entry points, only the
// unknown reach does.
func TestReconciledResult_IllTypedReach(t *testing.T) {
	files := map[string]string{
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() { var x int = \"s\"; _ = x }\n\nfunc Bad() {}\n",
	}
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"", plugin.PartialReasonLibraryEscape},
		{plugin.LibraryEntrypointsNone, plugin.PartialReasonReflectiveCall},
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			g, res := reconcileFor(t, files, vulnmodFinding, plugin.LibraryEntrypoints{Mode: tc.mode})
			if g.ReflectReach != nil {
				t.Errorf("reconcile ReflectReach = %v, want nil (unknown)", g.ReflectReach)
			}
			if res.Refutation != nil {
				t.Fatalf("refutation stands: %+v (partiality %+v)", res.Refutation, res.Partiality)
			}
			if !slices.Contains(res.Partiality.Reasons, tc.want) {
				t.Errorf("%s not declared (partiality %+v)", tc.want, res.Partiality)
			}
		})
	}
}

// TestWithholdForReflectReach_Searched: a Searched sink stands only when what reflection's calls
// reach is known and holds none of the vulnerable symbols of the modules the scan names. The reach
// is the one reconcile builds for each program.
func TestWithholdForReflectReach_Searched(t *testing.T) {
	const tmpl = "package main\n\nimport (\n\t\"os\"\n\t\"text/template\"\n\n\t\"example.com/vulnmod\"\n)\n\ntype D struct{}\n\nfunc (D) Do() string { vulnmod.CALLEE(); return \"\" }\n\nfunc main() {\n\tvulnmod.Safe()\n\t_ = template.Must(template.New(\"t\").Parse(\"{{ .Do }}\")).Execute(os.Stdout, D{})\n}\n"
	cases := []struct {
		name    string
		files   map[string]string
		scanned vulnScan
		stands  bool
	}{
		{"the reach holds the vulnerable symbol",
			map[string]string{"main.go": strings.ReplaceAll(tmpl, "CALLEE", "Bad")}, vulnmodFinding, false},
		{"the reach is unknown",
			map[string]string{
				"main.go":             strings.ReplaceAll(tmpl, "CALLEE", "Safe"),
				"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() { var x int = \"s\"; _ = x }\n\nfunc Bad() {}\n",
			}, vulnmodFinding, false},
		{"the scan names no module",
			map[string]string{"main.go": strings.ReplaceAll(tmpl, "CALLEE", "Safe")}, vulnScan{}, false},
		{"the reach is known and excludes the vulnerable symbol",
			map[string]string{"main.go": strings.ReplaceAll(tmpl, "CALLEE", "Safe")}, vulnmodFinding, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, res := reconcileFor(t, tc.files, tc.scanned, plugin.LibraryEntrypoints{})
			if len(res.Searched) != 0 {
				t.Fatalf("the Go lane listed Searched sinks %v; route them through withholdForReflectReach", res.Searched)
			}
			res.Searched = []string{"sink"}
			got := withholdForReflectReach(res, tc.scanned, g.ReflectReach)
			if stands := len(got.Searched) > 0; stands != tc.stands {
				t.Errorf("Searched stands = %v, want %v (reach %v)", stands, tc.stands, g.ReflectReach)
			}
			if declared := slices.Contains(got.Partiality.Reasons, plugin.PartialReasonReflectiveCall); declared == tc.stands {
				t.Errorf("reflection:call declared = %v with Searched standing = %v (partiality %+v)", declared, tc.stands, got.Partiality)
			}
		})
	}
}
