package goanalysis

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestRestateNotImported: a module refutation becomes analyzer_package_not_imported only when the
// advisory lists the module's vulnerable packages, govulncheck matched the module alone, and the
// complete load holds none of those packages. Every other refutation keeps its basis.
func TestRestateNotImported(t *testing.T) {
	const (
		importsBlake = "package main\n\nimport \"example.com/vulnmod/blake\"\n\nfunc main() { blake.Sum() }\n"
		importsSSH   = "package main\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc main() { _ = ssh.Client{} }\n"
		importsWrap  = "package main\n\nimport \"example.com/vulnmod/wrap\"\n\nfunc main() { _ = wrap.Get }\n"
	)
	s := narrowedScans
	moduleFinding := vulnScan{
		imports:  s.narrow.imports,
		findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0"}}}},
	}
	packageFinding := vulnScan{
		imports:  s.narrow.imports,
		findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod/ssh"}}}},
	}
	cases := []struct {
		name     string
		main     string
		scanned  vulnScan
		restated bool
		files    map[string]string // further files of the module
	}{
		{"the build imports another package of the module", importsBlake, moduleFinding, true, nil},
		{"the build imports the vulnerable package", importsSSH, moduleFinding, false, nil},
		{"the build imports the vulnerable package through another package of the module", importsWrap, moduleFinding, false, nil},
		{"the advisory also lists the whole module", importsBlake, s.wholeModule, false, nil},
		{"no advisory entry lists the module's packages", importsBlake, vulnScan{findings: moduleFinding.findings}, false, nil},
		{"a package-level finding", importsBlake, packageFinding, false, nil},
		{"a file for another platform calls the vulnerable symbol", importsBlake, moduleFinding, false, map[string]string{
			"main_windows.go": "package main\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc init() { ssh.Dial() }\n",
		}},
		{"a file for another platform imports the vulnerable package and calls nothing listed", importsBlake, moduleFinding, false, map[string]string{
			"main_windows.go": "package main\n\nimport \"example.com/vulnmod/ssh\"\n\nvar _ = ssh.Client{}\n",
		}},
		{"a file behind a build tag imports the vulnerable package", importsBlake, moduleFinding, false, map[string]string{
			"tagged.go": "//go:build sshsupport\n\npackage main\n\nimport _ \"example.com/vulnmod/ssh\"\n",
		}},
		{"a package the build does not load imports the vulnerable package", importsBlake, moduleFinding, false, map[string]string{
			"extra/extra.go": "package extra\n\nimport \"example.com/vulnmod/ssh\"\n\nvar V = ssh.Client{}\n",
			"use_windows.go": "package main\n\nimport _ \"example.com/m/extra\"\n",
		}},
		{"a file for another platform imports another package of the module", importsBlake, moduleFinding, true, map[string]string{
			"main_windows.go": "package main\n\nimport \"example.com/vulnmod/blake\"\n\nfunc init() { blake.Sum() }\n",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(merge(narrowedModule, map[string]string{"main.go": tc.main}), tc.files))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if incompleteLoad(load.Packages, nil) {
				t.Fatal("load incomplete")
			}
			in := narrowedRefutation()
			in.Refutation.Detail = "govulncheck traced no call"
			env := append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
			res := restateNotImported(context.Background(), in, tc.scanned, load.Packages, load.buildRelease(), dir, env)
			if res.Refutation == nil {
				t.Fatal("refutation dropped")
			}
			want := plugin.RefutationAnalyzerSymbolNotReached
			if tc.restated {
				want = plugin.RefutationAnalyzerPackageNotImported
			}
			if res.Refutation.Basis != want {
				t.Fatalf("basis = %q, want %q", res.Refutation.Basis, want)
			}
			if named := strings.Contains(res.Refutation.Detail, "example.com/vulnmod/ssh"); named != tc.restated {
				t.Errorf("detail %q names the vulnerable package = %v, want %v", res.Refutation.Detail, named, tc.restated)
			}
			if stated := strings.Contains(res.Refutation.Detail, "CGO_ENABLED=0"); stated != tc.restated {
				t.Errorf("detail %q states the cgo setting = %v, want %v", res.Refutation.Detail, stated, tc.restated)
			}
			if in.Refutation.Basis != plugin.RefutationAnalyzerSymbolNotReached {
				t.Error("the input refutation was changed in place")
			}
		})
	}
}

// TestRestateNotImported_IncompleteLoad: a load that could not type-check a package cannot say the
// vulnerable package is absent, so the refutation keeps its basis.
func TestRestateNotImported_IncompleteLoad(t *testing.T) {
	dir := writeTree(t, merge(narrowedModule, map[string]string{
		"internal/broken/b.go": "package broken\n\nfunc F() { undefined() }\n",
		"main.go":              "package main\n\nimport (\n\t\"example.com/m/internal/broken\"\n\t\"example.com/vulnmod/blake\"\n)\n\nfunc main() { blake.Sum(); broken.F() }\n",
	}))
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Skipf("load refused the broken tree: %v", err)
	}
	if !incompleteLoad(load.Packages, nil) {
		t.Fatal("load complete")
	}
	scanned := vulnScan{
		imports:  narrowedScans.narrow.imports,
		findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0"}}}},
	}
	if res := restateNotImported(context.Background(), narrowedRefutation(), scanned, load.Packages, load.buildRelease(), dir, append(os.Environ(), "GOWORK=off")); res.Refutation.Basis != plugin.RefutationAnalyzerSymbolNotReached {
		t.Fatalf("basis = %q, want it kept", res.Refutation.Basis)
	}
}

// TestResultFromGraph_RestatesNotImported: the reachability result of a module-level finding states
// analyzer_package_not_imported when the build imports none of the module's vulnerable packages, and
// analyzer_symbol_not_reached when a file for another platform imports one.
func TestResultFromGraph_RestatesNotImported(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no file imports the vulnerable package", nil, plugin.RefutationAnalyzerPackageNotImported},
		{"a file for another platform imports it", map[string]string{
			"main_windows.go": "package main\n\nimport \"example.com/vulnmod/ssh\"\n\nvar _ = ssh.Client{}\n",
		}, plugin.RefutationAnalyzerSymbolNotReached},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(narrowedModule, tc.files))
			loaded, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			loaded.buildGoVersion = loaded.goVersion
			scanned := vulnScan{
				imports:  narrowedScans.narrow.imports,
				symbols:  map[string][]string{"example.com/vulnmod/ssh": {"Dial"}},
				findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0"}}}},
			}
			g := reconcileGraph{CallGraph: plugin.CallGraphResult{Partiality: plugin.Complete()}, ReflectReach: map[string][]string{}}
			ctx := WithRunCacheDir(context.Background(), t.TempDir())
			res, err := resultFromGraph(ctx, scanned, g, dir, summaryEnv(), func() (*LoadResult, error) { return loaded, nil }, plugin.LibraryEntrypoints{})
			if err != nil {
				t.Fatal(err)
			}
			if res.Refutation == nil {
				t.Fatalf("no refutation (partiality %+v)", res.Partiality)
			}
			if res.Refutation.Basis != tc.want {
				t.Errorf("basis = %q, want %q (detail %q)", res.Refutation.Basis, tc.want, res.Refutation.Detail)
			}
		})
	}
}

// TestRestateNotImported_StandardLibrary: the standard library is a module like any other here. A
// build that imports none of the advisory's standard-library packages restates; a file for another
// platform importing one keeps the basis.
func TestRestateNotImported_StandardLibrary(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no file imports the package", nil, plugin.RefutationAnalyzerPackageNotImported},
		{"a file for another platform imports it", map[string]string{
			"main_windows.go": "package main\n\nimport _ \"net/http/cgi\"\n",
		}, plugin.RefutationAnalyzerSymbolNotReached},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(narrowedModule, tc.files))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			scanned := vulnScan{
				imports:  map[string][]string{"stdlib": {"net/http/cgi"}},
				findings: []vulnFinding{{OSV: "GO-2", Trace: []vulnFrame{{Module: "stdlib", Version: "v1.22.0"}}}},
			}
			in := plugin.ReachabilityResult{
				Partiality: plugin.Complete(),
				Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/stdlib"},
			}
			res := restateNotImported(context.Background(), in, scanned, load.Packages, load.buildRelease(), dir, append(os.Environ(), "GOWORK=off"))
			if res.Refutation.Basis != tc.want {
				t.Errorf("basis = %q, want %q (detail %q)", res.Refutation.Basis, tc.want, res.Refutation.Detail)
			}
		})
	}
}
