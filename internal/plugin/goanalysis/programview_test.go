package goanalysis

import (
	"context"
	"errors"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestShippedMains: a main package the build ships is one with compiled files in a main module and
// no example or test element below the module path; a library, and a main under cmd, is judged by
// those alone.
func TestShippedMains(t *testing.T) {
	pkg := func(path, name string, files int, main bool) *packages.Package {
		return &packages.Package{PkgPath: path, Name: name, GoFiles: make([]string, files), Module: &packages.Module{Path: "example.com/m", Main: main}}
	}
	for _, tc := range []struct {
		name string
		pkgs []*packages.Package
		want []string
	}{
		{"a program under cmd", []*packages.Package{pkg("example.com/m/cmd/tool", "main", 1, true)}, []string{"example.com/m/cmd/tool"}},
		{"a program at the root", []*packages.Package{pkg("example.com/m", "main", 1, true)}, []string{"example.com/m"}},
		{"no main package", []*packages.Package{pkg("example.com/m/lib", "lib", 1, true)}, nil},
		{"a main with no compiled files", []*packages.Package{pkg("example.com/m/cmd/tool", "main", 0, true)}, nil},
		{"a main of another module", []*packages.Package{pkg("example.com/m/cmd/tool", "main", 1, false)}, nil},
		{"an example and a test program", []*packages.Package{pkg("example.com/m/examples/a", "main", 1, true), pkg("example.com/m/pkg/test/b", "main", 1, true)}, nil},
		{"sorted", []*packages.Package{pkg("example.com/m/cmd/b", "main", 1, true), pkg("example.com/m/cmd/a", "main", 1, true)}, []string{"example.com/m/cmd/a", "example.com/m/cmd/b"}},
	} {
		var got []string
		for _, p := range shippedMains(tc.pkgs) {
			got = append(got, p.PkgPath)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: shipped mains = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestProgramView: when the library view withholds its refutation because an importable package
// reaches the module, the program view, started from the shipped main alone, rules the advisory out
// and names the binary; the library view's own result is unchanged. Every step the view rests on that
// is missing, partial or contradicted leaves no view: one row each, against programView itself.
func TestProgramView(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Bad() {}\n",
		"pkg/lib/lib.go":      "package lib\n\nimport \"example.com/vulnmod\"\n\nfunc Get() func() { return vulnmod.Bad }\n",
		"cmd/tool/main.go":    "package main\n\nfunc main() {}\n",
		// No package holds this file; the left-out row hands it to the main as a file its build left out.
		"_leftout/plugin.go": "package main\n\nimport \"example.com/vulnmod\"\n\nfunc init() { vulnmod.Bad() }\n",
	}
	vuln := vulnFrame{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}
	module := `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/vulnmod","version":"v0.0.0","package":"example.com/vulnmod"}]}}`
	symbol := `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/vulnmod","version":"v0.0.0","package":"example.com/vulnmod","function":"Bad"},{"module":"example.com/m","package":"example.com/m/cmd/tool","function":"main"}]}}`
	other := `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/othermod","version":"v0.0.0","package":"example.com/othermod"}]}}`
	dir := writeTree(t, files)
	ctx := context.Background()
	load, err := LoadProgram(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded := func() (*LoadResult, error) { return load, nil }
	env := append(os.Environ(), "GOWORK=off")
	defer func(prev func(context.Context, string, []string, []string) ([]byte, error)) { programStream = prev }(programStream)
	stream := func(out string, err error) {
		programStream = func(_ context.Context, _ string, _, patterns []string) ([]byte, error) {
			if !slices.Equal(patterns, []string{"example.com/m/cmd/tool"}) {
				t.Errorf("patterns = %q, want the one main", patterns)
			}
			return []byte(out), err
		}
	}
	scanned := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{vuln}}}, vulnID: "GO-1"}

	// The whole of Reachability's reconciliation, once: the library view is withheld and the program
	// view stands beside it.
	stream(module, nil)
	res, err := reconciledResult(ctx, scanned, dir, env, loaded, plugin.LibraryEntrypoints{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refutation != nil || !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonLibraryEscape) {
		t.Fatalf("library view = %+v / %+v, want its refutation withheld as library_escape", res.Refutation, res.Partiality)
	}
	if v := res.ProgramView; v == nil || v.Module != "example.com/m" || !slices.Equal(v.Binaries, []string{"cmd/tool"}) ||
		v.Refutation.Package != "pkg:golang/example.com/vulnmod" || !strings.Contains(v.Refutation.Detail, "cmd/tool only") {
		t.Fatalf("program view = %+v, want cmd/tool's refutation of example.com/vulnmod", v)
	}

	g, err := reconcileCallGraph(ctx, dir, nil, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if g.ReflectReach == nil {
		t.Fatal("reflection's reach unknown for a build with no reflection")
	}
	evidence := evidenceResult(scanned.findings, g.CallGraph, env)
	if evidence.Refutation == nil {
		t.Fatal("no library-view refutation to withhold")
	}
	// withPkgs is the load with its packages replaced by what edit returns.
	withPkgs := func(edit func([]*packages.Package) []*packages.Package) func() (*LoadResult, error) {
		l := *load
		l.Packages = edit(slices.Clone(load.Packages))
		return func() (*LoadResult, error) { return &l, nil }
	}
	mainPkg := func(path, mod string) *packages.Package {
		return &packages.Package{PkgPath: path, Name: "main", GoFiles: []string{"main.go"}, Types: types.NewPackage(path, "main"), Module: &packages.Module{Path: mod, Main: true}}
	}
	type input struct {
		res       plugin.ReachabilityResult
		scanned   vulnScan
		g         reconcileGraph
		load      func() (*LoadResult, error)
		stream    string
		streamErr error
	}
	for _, tc := range []struct {
		name string
		edit func(*input)
		want bool
	}{
		{"the program does not reach the module", func(*input) {}, true},
		{"the program reaches the module", func(in *input) { in.stream = symbol }, false},
		{"the program run knows nothing of the advisory", func(in *input) { in.stream = "" }, false},
		{"the program run refutes another module", func(in *input) { in.stream = other }, false},
		{"govulncheck fails over the programs", func(in *input) { in.streamErr = errors.New("exit status 1") }, false},
		{"the library view already refutes", func(in *input) { in.res.Refutation = evidence.Refutation }, false},
		{"the library run was partial", func(in *input) { in.scanned.partial = &partialRun{} }, false},
		{"a main is traced as a finding's entry", func(in *input) {
			in.scanned.findings = append(slices.Clone(in.scanned.findings), vulnFinding{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Package: "example.com/vulnmod", Function: "Bad"}, {Module: "example.com/m", Package: "example.com/m/cmd/tool", Function: "main"}}})
		}, false},
		{"the load fails", func(in *input) {
			in.load = func() (*LoadResult, error) { return nil, errors.New("go list failed") }
		}, false},
		{"the load is incomplete", func(in *input) {
			in.load = withPkgs(func(pkgs []*packages.Package) []*packages.Package {
				return append(pkgs, &packages.Package{PkgPath: "example.com/m/broken", Errors: []packages.Error{{Msg: "type error"}}})
			})
		}, false},
		{"the load could not tell whether cgo is on", func(in *input) {
			l := *load
			l.cgoUnresolved = true
			in.load = func() (*LoadResult, error) { return &l, nil }
		}, false},
		{"no main is shipped", func(in *input) {
			in.load = withPkgs(func(pkgs []*packages.Package) []*packages.Package { return slices.DeleteFunc(pkgs, isMain) })
		}, false},
		{"the mains are in several modules", func(in *input) {
			in.load = withPkgs(func(pkgs []*packages.Package) []*packages.Package {
				return append(pkgs, mainPkg("example.com/other/cmd/x", "example.com/other"))
			})
		}, false},
		{"a file the build left out calls into the module", func(in *input) {
			in.load = withPkgs(func(pkgs []*packages.Package) []*packages.Package {
				for i, p := range pkgs {
					if isMain(p) {
						c := *p
						c.IgnoredFiles = []string{filepath.Join(dir, "_leftout", "plugin.go")}
						pkgs[i] = &c
					}
				}
				return pkgs
			})
		}, false},
		{"reflection's reach is unknown", func(in *input) { in.g.ReflectReach = nil }, false},
		{"a call reflection makes reaches the module", func(in *input) {
			in.g.ReflectReach = map[string][]string{"example.com/vulnmod": {"Bad"}}
		}, false},
		{"the program run declares a step that did not run", func(in *input) {
			in.g.CallGraph.Partiality = plugin.Partial(plugin.PartialReasonToolFailure)
		}, false},
		{"the program run declares only limits of the method", func(in *input) {
			in.g.CallGraph.Partiality = plugin.Partial(plugin.PartialReasonDynamicDispatch, plugin.PartialReasonReflection)
		}, true},
		{"the program run declares a limit bounded to the module", func(in *input) {
			in.g.CallGraph.Partiality = plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonCgo, Targets: []string{"pkg:golang/example.com/vulnmod"}}}}
		}, false},
		{"the program run declares an unbounded scoped limit", func(in *input) {
			in.g.CallGraph.Partiality = plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/othermod"}}}
		}, false},
		{"the program run declares a limit bounded elsewhere", func(in *input) {
			in.g.CallGraph.Partiality = plugin.Partiality{Scoped: []plugin.ScopedReason{{Reason: plugin.PartialReasonCgo, Package: "pkg:golang/example.com/othermod", Targets: []string{"pkg:golang/example.com/othermod"}}}}
		}, true},
	} {
		in := input{res: plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonLibraryEscape)}, scanned: scanned, g: g, load: loaded, stream: module}
		tc.edit(&in)
		stream(in.stream, in.streamErr)
		v := programView(ctx, in.res, evidence, in.scanned, in.g, dir, env, in.load)
		if (v != nil) != tc.want {
			t.Errorf("%s: program view = %+v, want present %v", tc.name, v, tc.want)
		}
	}

	// A finding entered at a main is never ruled out by the program view, and one with no symbol trace
	// says nothing about the programs.
	mains := []string{"example.com/m/cmd/tool"}
	if !tracedFromMain([]vulnFinding{{Trace: []vulnFrame{{Function: "Bad", Package: "example.com/vulnmod"}, {Function: "main", Package: mains[0]}}}}, mains) {
		t.Error("a finding entered at a main was not traced from it")
	}
	if tracedFromMain([]vulnFinding{{Trace: []vulnFrame{vuln}}}, mains) {
		t.Error("a module-level finding was traced from a main")
	}
}
