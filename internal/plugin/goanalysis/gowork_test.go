package goanalysis

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestWithGoWork: the analyzer runs under the GOWORK the request names, off when it names none, and
// refuses one it cannot place: a relative go.work would resolve against each go command's directory.
func TestWithGoWork(t *testing.T) {
	cases := []struct {
		name, req, want string
		wantErr         bool
	}{
		{"none", "", "off", false},
		{"off", "off", "off", false},
		{"absolute", "/repo/go.work", "/repo/go.work", false},
		{"relative", "go.work", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := withGoWork(context.Background(), tc.req)
			if (err != nil) != tc.wantErr {
				t.Fatalf("withGoWork(%q) error = %v, want error %v", tc.req, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got := goWork(ctx); got != tc.want {
				t.Fatalf("goWork = %q, want %q", got, tc.want)
			}
			env := buildEnv(ctx, []string{"GOWORK=/developer/go.work", "HOME=/h"})
			if env[len(env)-1] != "GOWORK="+tc.want {
				t.Fatalf("buildEnv does not end with GOWORK=%s: %v", tc.want, env)
			}
		})
	}
	if got := goWork(context.Background()); got != "off" {
		t.Fatalf("goWork with no request = %q, want off", got)
	}
}

// TestWorkspaceMembers: under a go.work the modules it uses are built from source, so an advisory on
// one resolves in that module's packages — never to a same-named symbol elsewhere in the program —
// and the call graph runs through their bodies. A member the build does not import holds nothing.
func TestWorkspaceMembers(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	tree, err := filepath.EvalSymlinks(writeTree(t, map[string]string{
		"go.work":      "go 1.22\n\nuse (\n\t./a\n\t./b\n\t./c\n)\n",
		"a/go.mod":     "module example.com/mono/a\n\ngo 1.22\n",
		"a/main.go":    "package main\n\nimport \"example.com/mono/b/pkg\"\n\nfunc main() { pkg.Wrap(); Vuln() }\n\nfunc Vuln() {}\n",
		"b/go.mod":     "module example.com/mono/b\n\ngo 1.22\n",
		"b/pkg/pkg.go": "package pkg\n\nfunc Wrap() { helper() }\n\nfunc helper() { Vuln() }\n\nfunc Vuln() {}\n",
		"c/go.mod":     "module example.com/mono/c\n\ngo 1.22\n",
		"c/pkg/pkg.go": "package pkg\n\nfunc Vuln() {}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, buildDir, work := context.Background(), filepath.Join(tree, "a"), filepath.Join(tree, "go.work")

	resolve := func(module string) []plugin.Symbol {
		t.Helper()
		res, err := ResolveDependencySymbols(ctx, plugin.ResolveSymbolsRequest{
			BuildDir: buildDir, GoWork: work, PURL: "pkg:golang/" + module, AdvisorySymbols: []string{module + "/pkg.Vuln"},
		})
		if err != nil {
			t.Fatalf("ResolveDependencySymbols(%s): %v", module, err)
		}
		return res.Resolved
	}
	got := resolve("example.com/mono/b")
	if len(got) != 1 || got[0].Package != "example.com/mono/b/pkg" {
		t.Fatalf("member b advisory resolved %+v, want b/pkg.Vuln alone", got)
	}
	if got := resolve("example.com/mono/c"); len(got) != 0 {
		t.Fatalf("unimported member c advisory resolved %+v, want nothing", got)
	}

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: buildDir, GoWork: work})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	for _, e := range cg.Edges {
		if e.Callee.SCIP == got[0].SCIP && strings.Contains(e.Caller.SCIP, "helper") {
			return
		}
	}
	t.Fatalf("no edge from the member's helper into its Vuln (%s) among %d edges", got[0].SCIP, len(cg.Edges))
}
