package goanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_RunTimeCalls: a call the program picks at run time through reflect or a template,
// or Go code it loads with plugin.Open, is declared did-not-run when one of govulncheck's entry
// points reaches it; reflection that calls nothing is not, and neither is a reflective call no
// entry point reaches.
func TestCallGraph_RunTimeCalls(t *testing.T) {
	const head = "package main\n\nimport (\n\thtmltemplate \"html/template\"\n\t\"os\"\n\t\"plugin\"\n\t\"reflect\"\n\t\"text/template\"\n)\n\n" +
		"var _, _, _, _, _ = htmltemplate.New, os.Stdout, plugin.Open, reflect.TypeOf, template.New\n\n"
	const lib = "package lib\n\nimport \"reflect\"\n\n"
	reflective := []string{plugin.PartialReasonReflectiveCall}
	cases := []struct {
		name  string
		main  string            // main.go after head; empty means no main package
		files map[string]string // further files of the module
		want  []string
	}{
		{"reflection that calls nothing", "func main() { _ = reflect.TypeOf(0).Name() }\n", nil, nil},
		{"reflect.Value.Call", "func f() {}\n\nfunc main() { reflect.ValueOf(f).Call(nil) }\n", nil, reflective},
		{"reflect.Value.CallSlice", "func f(...int) {}\n\nfunc main() { reflect.ValueOf(f).CallSlice(nil) }\n", nil, reflective},
		{"reflect.Value.Method", "type T struct{}\n\nfunc (T) M() {}\n\nfunc main() { _ = reflect.ValueOf(T{}).Method(0) }\n", nil, reflective},
		{"reflect.Value.MethodByName", "type T struct{}\n\nfunc (T) M() {}\n\nfunc main() { _ = reflect.ValueOf(T{}).MethodByName(\"M\") }\n", nil, reflective},
		{"text/template Execute", "func main() { _ = template.Must(template.New(\"t\").Parse(\"{{.}}\")).Execute(os.Stdout, 1) }\n", nil, reflective},
		{"text/template ExecuteTemplate", "func main() { _ = template.Must(template.New(\"t\").Parse(\"{{.}}\")).ExecuteTemplate(os.Stdout, \"t\", 1) }\n", nil, reflective},
		{"html/template Execute", "func main() { _ = htmltemplate.Must(htmltemplate.New(\"t\").Parse(\"{{.}}\")).Execute(os.Stdout, 1) }\n", nil, reflective},
		{"html/template ExecuteTemplate", "func main() { _ = htmltemplate.Must(htmltemplate.New(\"t\").Parse(\"{{.}}\")).ExecuteTemplate(os.Stdout, \"t\", 1) }\n", nil, reflective},
		{"plugin load", "func main() { _, _ = plugin.Open(\"x.so\") }\n", nil, []string{plugin.PartialReasonPluginLoad}},
		{"a reflective call in a main package's init", "func f() {}\n\nfunc init() { reflect.ValueOf(f).Call(nil) }\n\nfunc main() {}\n", nil, reflective},
		{"a reflective call no entry point reaches", "func f() {}\n\nfunc unused() { reflect.ValueOf(f).Call(nil) }\n\nfunc main() {}\n", nil, nil},
		{"an exported function of a main package is not an entry point", "func f() {}\n\nfunc Unused() { reflect.ValueOf(f).Call(nil) }\n\nfunc main() {}\n", nil, nil},
		{"an exported library function beside main", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "func Dispatch(v any) { reflect.ValueOf(v).Call(nil) }\n",
		}, reflective},
		{"an exported library method beside main", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "type T struct{}\n\nfunc (*T) Dispatch(v any) { reflect.ValueOf(v).Call(nil) }\n",
		}, reflective},
		{"a library's init beside main", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "func f() {}\n\nfunc init() { reflect.ValueOf(f).Call(nil) }\n",
		}, reflective},
		{"an unexported library function no entry point reaches", "func main() {}\n", map[string]string{
			"lib/lib.go": lib + "func dispatch(v any) { reflect.ValueOf(v).Call(nil) }\n",
		}, nil},
		{"an exported function of a module without a main", "", map[string]string{
			"lib.go": "package m\n\nimport \"reflect\"\n\nfunc Dispatch(v any) { reflect.ValueOf(v).Call(nil) }\n",
		}, reflective},
		{"an unexported function no entry point reaches, in a module without a main", "", map[string]string{
			"lib.go": "package m\n\nimport \"reflect\"\n\nfunc dispatch(v any) { reflect.ValueOf(v).Call(nil) }\n\nfunc Run() {}\n",
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
			for _, r := range []string{plugin.PartialReasonReflectiveCall, plugin.PartialReasonPluginLoad} {
				if got, want := slices.Contains(res.Partiality.Reasons, r), slices.Contains(tc.want, r); got != want {
					t.Errorf("%s declared = %v, want %v (partiality %+v)", r, got, want, res.Partiality)
				}
			}
		})
	}
}
