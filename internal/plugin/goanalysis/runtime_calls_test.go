package goanalysis

import (
	"context"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_RunTimeCalls: Go code a program loads with plugin.Open is declared did-not-run when
// one of govulncheck's entry points reaches the load, and not when none does. A call the program
// picks at run time through reflect or a template is never declared run-wide: Reachability bounds it
// per advisory (withholdForReflectReach). The reflection itself stays declared as an inherent limit.
func TestCallGraph_RunTimeCalls(t *testing.T) {
	t.Parallel()
	const head = "package main\n\nimport (\n\thtmltemplate \"html/template\"\n\t\"os\"\n\t\"plugin\"\n\t\"reflect\"\n\t\"text/template\"\n)\n\n" +
		"var _, _, _, _, _ = htmltemplate.New, os.Stdout, plugin.Open, reflect.TypeOf, template.New\n\n"
	const lib = "package lib\n\nimport \"plugin\"\n\n"
	const open = "_, _ = plugin.Open(\"x.so\")"
	reflection := []string{plugin.PartialReasonReflection}
	// What a reached load declares follows the host's own build (TestCallGraph_PluginLoadByBuild).
	load := hostPluginLoad(t)
	var loads []string
	if load != "" {
		loads = []string{load}
	}
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
			for _, r := range []string{plugin.PartialReasonPluginLoad, plugin.PartialReasonPluginLoadCgoOff} {
				if got, want := slices.Contains(res.Partiality.Reasons, r), slices.Contains(tc.want, r); got != want {
					t.Errorf("%s declared = %v, want %v (partiality %+v)", r, got, want, res.Partiality)
				}
			}
		})
	}
}

// hostPluginLoad returns the reason a reached plugin.Open declares in a build under the host's own
// GOOS and cgo setting: plugin_load, plugin_load:cgo_off where cgo resolves off, or "" on a GOOS
// that has no plugins.
func hostPluginLoad(t *testing.T) string {
	t.Helper()
	if !slices.Contains([]string{"linux", "darwin", "freebsd"}, runtime.GOOS) {
		return ""
	}
	out, err := exec.Command("go", "env", "CGO_ENABLED").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "1" {
		return plugin.PartialReasonPluginLoadCgoOff
	}
	return plugin.PartialReasonPluginLoad
}

// TestCallGraph_PluginLoadByBuild: what a reached plugin.Open declares follows the package plugin
// the build compiles. The real one (cgo on, a GOOS that has plugins) declares plugin_load. The stub
// compiled only because cgo is off declares plugin_load:cgo_off, since the same program built with
// cgo on loads plugins. On a GOOS that has no plugins nothing is declared.
func TestCallGraph_PluginLoadByBuild(t *testing.T) {
	const src = "package main\n\nimport \"plugin\"\n\nfunc main() { _, _ = plugin.Open(\"x.so\") }\n"
	pluginGOOS := slices.Contains([]string{"linux", "darwin", "freebsd"}, runtime.GOOS)
	cases := []struct {
		name string
		goos string // "" is the host's
		cgo  string
		want string // the one reason declared, "" for neither
	}{
		{"cgo on", "", "1", plugin.PartialReasonPluginLoad},
		{"cgo off", "", "0", plugin.PartialReasonPluginLoadCgoOff},
		{"a GOOS without plugins", "windows", "0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.goos == "" && !pluginGOOS {
				t.Skip("the host's GOOS has no plugins")
			}
			if tc.cgo == "1" {
				cc, err := exec.Command("go", "env", "CC").Output()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := exec.LookPath(strings.Fields(string(cc) + " cc")[0]); err != nil {
					t.Skip("no C compiler")
				}
			}
			t.Setenv("CGO_ENABLED", tc.cgo)
			if tc.goos != "" {
				t.Setenv("GOOS", tc.goos)
			}
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeModule(t, map[string]string{"main.go": src})})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range []string{plugin.PartialReasonPluginLoad, plugin.PartialReasonPluginLoadCgoOff} {
				if got := slices.Contains(res.Partiality.Reasons, r); got != (r == tc.want) {
					t.Errorf("%s declared = %v, want %v (partiality %+v)", r, got, r == tc.want, res.Partiality)
				}
			}
		})
	}
}

// TestReflectReach_PluginLoadByBuild: a plugin.Open the program can only call reflectively declares
// the same reason a direct call does.
func TestReflectReach_PluginLoadByBuild(t *testing.T) {
	if !slices.Contains([]string{"linux", "darwin", "freebsd"}, runtime.GOOS) {
		t.Skip("the host's GOOS has no plugins")
	}
	const src = "package main\n\nimport (\n\t\"plugin\"\n\t\"reflect\"\n)\n\nfunc main() { reflect.ValueOf(plugin.Open).Call([]reflect.Value{reflect.ValueOf(\"x.so\")}) }\n"
	t.Setenv("CGO_ENABLED", "0")
	res, err := LoadProgram(context.Background(), writeModule(t, map[string]string{"main.go": src}))
	if err != nil {
		t.Fatal(err)
	}
	reasons, _, err := reflectReachOf(res, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(reasons, plugin.PartialReasonPluginLoadCgoOff) || slices.Contains(reasons, plugin.PartialReasonPluginLoad) {
		t.Errorf("reasons = %v, want %s and not %s", reasons, plugin.PartialReasonPluginLoadCgoOff, plugin.PartialReasonPluginLoad)
	}
}

// TestStatePluginScope: a refutation kept beside plugin_load:cgo_off says in its detail that it
// holds for CGO_ENABLED=0. Any other result is unchanged.
func TestStatePluginScope(t *testing.T) {
	refuted := func(detail string, reasons ...string) plugin.ReachabilityResult {
		return plugin.ReachabilityResult{
			Partiality: plugin.Partial(reasons...),
			Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod", Detail: detail},
		}
	}
	cases := []struct {
		name string
		in   plugin.ReachabilityResult
		want string
	}{
		{"beside plugin_load:cgo_off", refuted("no call path", plugin.PartialReasonPluginLoadCgoOff), "no call path; " + pluginScopeDetail},
		{"an empty detail", refuted("", plugin.PartialReasonPluginLoadCgoOff), pluginScopeDetail},
		{"beside plugin_load", refuted("no call path", plugin.PartialReasonPluginLoad), "no call path"},
		{"beside another limit", refuted("no call path", plugin.PartialReasonExcludedFilesBuildConstraint), "no call path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.in.Refutation.Detail
			if got := statePluginScope(tc.in).Refutation.Detail; got != tc.want {
				t.Errorf("detail = %q, want %q", got, tc.want)
			}
			if tc.in.Refutation.Detail != before {
				t.Error("the input refutation was changed in place")
			}
		})
	}
	none := plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonPluginLoadCgoOff)}
	if got := statePluginScope(none); got.Refutation != nil {
		t.Errorf("a result with no refutation gained one: %+v", got.Refutation)
	}
}
