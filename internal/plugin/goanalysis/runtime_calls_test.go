package goanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_RunTimeCalls: Go code a program loads with plugin.Open is declared did-not-run when
// one of govulncheck's entry points reaches the load, and not when none does. A call the program
// picks at run time through reflect or a template is never declared run-wide: Reachability bounds it
// per advisory (withholdForReflectReach). The reflection itself stays declared as an inherent limit.
func TestCallGraph_RunTimeCalls(t *testing.T) {
	const head = "package main\n\nimport (\n\thtmltemplate \"html/template\"\n\t\"os\"\n\t\"plugin\"\n\t\"reflect\"\n\t\"text/template\"\n)\n\n" +
		"var _, _, _, _, _ = htmltemplate.New, os.Stdout, plugin.Open, reflect.TypeOf, template.New\n\n"
	const lib = "package lib\n\nimport \"plugin\"\n\n"
	const open = "_, _ = plugin.Open(\"x.so\")"
	reflection := []string{plugin.PartialReasonReflection}
	loads := []string{plugin.PartialReasonPluginLoad}
	cases := []struct {
		name  string
		main  string            // main.go after head; empty means no main package
		files map[string]string // further files of the module
		want  []string
	}{
		{"reflection that calls nothing", "func main() { _ = reflect.TypeOf(0).Name() }\n", nil, reflection},
		{"reflect.Value.Call", "func f() {}\n\nfunc main() { reflect.ValueOf(f).Call(nil) }\n", nil, reflection},
		{"reflect.Value.CallSlice", "func f(...int) {}\n\nfunc main() { reflect.ValueOf(f).CallSlice(nil) }\n", nil, reflection},
		{"reflect.Value.Method", "type T struct{}\n\nfunc (T) M() {}\n\nfunc main() { _ = reflect.ValueOf(T{}).Method(0) }\n", nil, reflection},
		{"reflect.Value.MethodByName", "type T struct{}\n\nfunc (T) M() {}\n\nfunc main() { _ = reflect.ValueOf(T{}).MethodByName(\"M\") }\n", nil, reflection},
		{"reflect.Type.Method", "type T struct{}\n\nfunc (T) M() {}\n\nfunc main() { _ = reflect.TypeOf(T{}).Method(0) }\n", nil, reflection},
		{"text/template Execute", "func main() { _ = template.Must(template.New(\"t\").Parse(\"{{.}}\")).Execute(os.Stdout, 1) }\n", nil, reflection},
		{"text/template ExecuteTemplate", "func main() { _ = template.Must(template.New(\"t\").Parse(\"{{.}}\")).ExecuteTemplate(os.Stdout, \"t\", 1) }\n", nil, reflection},
		{"html/template Execute", "func main() { _ = htmltemplate.Must(htmltemplate.New(\"t\").Parse(\"{{.}}\")).Execute(os.Stdout, 1) }\n", nil, reflection},
		{"html/template ExecuteTemplate", "func main() { _ = htmltemplate.Must(htmltemplate.New(\"t\").Parse(\"{{.}}\")).ExecuteTemplate(os.Stdout, \"t\", 1) }\n", nil, reflection},
		{"plugin load", "func main() { " + open + " }\n", nil, loads},
		{"a plugin load in a main package's init", "func init() { " + open + " }\n\nfunc main() {}\n", nil, loads},
		{"a plugin load no entry point reaches", "func unused() { " + open + " }\n\nfunc main() {}\n", nil, nil},
		{"an exported function of a main package is not an entry point", "func Unused() { " + open + " }\n\nfunc main() {}\n", nil, nil},
		{"an exported library function beside main", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "func Load() { " + open + " }\n",
		}, loads},
		{"an exported library method beside main", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "type T struct{}\n\nfunc (*T) Load() { " + open + " }\n",
		}, loads},
		{"a library's init beside main", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "func init() { " + open + " }\n",
		}, loads},
		{"an exported method of a library's generic type beside main", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "type Box[T any] struct{ v T }\n\nfunc (b Box[T]) Load() { " + open + " }\n",
		}, loads},
		{"an exported method of a generic type in a module without a main", "", map[string]string{
			"lib.go": "package m\n\nimport \"plugin\"\n\ntype Box[T any] struct{ v T }\n\nfunc (b *Box[T]) Load() { " + open + " }\n",
		}, loads},
		{"an unexported library function no entry point reaches", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "func load() { " + open + " }\n",
		}, nil},
		{"an exported function of a module without a main", "", map[string]string{
			"lib.go": "package m\n\nimport \"plugin\"\n\nfunc Load() { " + open + " }\n",
		}, loads},
		{"an unexported function no entry point reaches, in a module without a main", "", map[string]string{
			"lib.go": "package m\n\nimport \"plugin\"\n\nfunc load() { " + open + " }\n\nfunc Run() {}\n",
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := merge(map[string]string{"go.mod": "module example.com/m\n\ngo 1.22\n"}, tc.files)
			if tc.main != "" {
				files["main.go"] = head + tc.main
			}
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, files)})
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(res.Partiality.Reasons, plugin.PartialReasonReflectiveCall) {
				t.Errorf("%s declared run-wide (partiality %+v)", plugin.PartialReasonReflectiveCall, res.Partiality)
			}
			for _, r := range tc.want {
				if !slices.Contains(res.Partiality.Reasons, r) {
					t.Errorf("%s not declared (partiality %+v)", r, res.Partiality)
				}
			}
			if got, want := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonPluginLoad), slices.Contains(tc.want, plugin.PartialReasonPluginLoad); got != want {
				t.Errorf("%s declared = %v, want %v (partiality %+v)", plugin.PartialReasonPluginLoad, got, want, res.Partiality)
			}
		})
	}
}
