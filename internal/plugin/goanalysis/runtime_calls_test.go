package goanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_RunTimeCalls: a call the program picks at run time through reflect or a template,
// or Go code it loads with plugin.Open, is declared did-not-run; reflection that calls nothing is
// not, and neither is a reflective call no entry point reaches.
func TestCallGraph_RunTimeCalls(t *testing.T) {
	const head = "package main\n\nimport (\n\t\"os\"\n\t\"plugin\"\n\t\"reflect\"\n\t\"text/template\"\n)\n\n" +
		"var _, _, _, _ = os.Stdout, plugin.Open, reflect.TypeOf, template.New\n\n"
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"reflection that calls nothing", "func main() { _ = reflect.TypeOf(0).Name() }\n", nil},
		{"reflect.Value.Call", "func f() {}\n\nfunc main() { reflect.ValueOf(f).Call(nil) }\n", []string{plugin.PartialReasonReflectiveCall}},
		{"reflect.Value.MethodByName", "type T struct{}\n\nfunc (T) M() {}\n\nfunc main() { _ = reflect.ValueOf(T{}).MethodByName(\"M\") }\n", []string{plugin.PartialReasonReflectiveCall}},
		{"template execution", "func main() { _ = template.Must(template.New(\"t\").Parse(\"{{.}}\")).Execute(os.Stdout, 1) }\n", []string{plugin.PartialReasonReflectiveCall}},
		{"plugin load", "func main() { _, _ = plugin.Open(\"x.so\") }\n", []string{plugin.PartialReasonPluginLoad}},
		{"a reflective call no entry point reaches", "func f() {}\n\nfunc unused() { reflect.ValueOf(f).Call(nil) }\n\nfunc main() {}\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{"main.go": head + tc.body})
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
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
