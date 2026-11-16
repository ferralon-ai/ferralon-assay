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
// and names the binary; the library view's own result is unchanged. A program that reaches the
// module, a program traced as the entry of a finding, and a build with no main leave no program view.
func TestProgramView(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Bad() {}\n",
		"pkg/lib/lib.go":      "package lib\n\nimport \"example.com/vulnmod\"\n\nfunc Get() func() { return vulnmod.Bad }\n",
		"cmd/tool/main.go":    "package main\n\nfunc main() {}\n",
	}
	vuln := vulnFrame{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}
	module := `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/vulnmod","version":"v0.0.0","package":"example.com/vulnmod"}]}}`
	symbol := `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/vulnmod","version":"v0.0.0","package":"example.com/vulnmod","function":"Bad"},{"module":"example.com/m","package":"example.com/m/cmd/tool","function":"main"}]}}`
	dir := writeTree(t, files)
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOWORK=off")
	defer func(prev func(context.Context, string, []string, []string) ([]byte, error)) { programStream = prev }(programStream)

	for _, tc := range []struct {
		name    string
		stream  string
		library []vulnFrame
		want    bool
	}{
		{"the program does not reach the module", module, []vulnFrame{vuln}, true},
		{"the program reaches the module", symbol, []vulnFrame{vuln}, false},
		{"the program run knows nothing of the advisory", "", []vulnFrame{vuln}, false},
	} {
		programStream = func(_ context.Context, _ string, _, patterns []string) ([]byte, error) {
			if !slices.Equal(patterns, []string{"example.com/m/cmd/tool"}) {
				t.Errorf("%s: patterns = %q, want the one main", tc.name, patterns)
			}
			return []byte(tc.stream), nil
		}
		scanned := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: tc.library}}, vulnID: "GO-1"}
		res, err := reconciledResult(context.Background(), scanned, dir, env, func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Refutation != nil || !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonLibraryEscape) {
			t.Fatalf("%s: library view = %+v / %+v, want its refutation withheld as library_escape", tc.name, res.Refutation, res.Partiality)
		}
		v := res.ProgramView
		if (v != nil) != tc.want {
			t.Fatalf("%s: program view = %+v, want present %v", tc.name, v, tc.want)
		}
		if v != nil && (v.Module != "example.com/m" || !slices.Equal(v.Binaries, []string{"cmd/tool"}) ||
			v.Refutation.Package != "pkg:golang/example.com/vulnmod" || !strings.Contains(v.Refutation.Detail, "cmd/tool only")) {
			t.Errorf("%s: program view = %+v", tc.name, v)
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
