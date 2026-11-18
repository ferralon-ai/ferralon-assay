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

		importsBlakeAndLib = "package main\n\nimport (\n\t_ \"example.com/lib/base\"\n\t\"example.com/vulnmod/blake\"\n)\n\nfunc main() { blake.Sum() }\n"
	)
	// libModule is a dependency replaced by a local directory, whose package win imports the
	// vulnerable package. Its go.mod requires the vulnerable module only when asked to.
	libModule := func(requires bool) map[string]string {
		libmod := "module example.com/lib\n\ngo 1.22\n"
		if requires {
			libmod += "\nrequire example.com/vulnmod v0.0.0\n"
		}
		return map[string]string{
			"go.mod":          "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/lib v0.0.0\n\texample.com/vulnmod v0.0.0\n)\n\nreplace example.com/vulnmod => ./_vulnmod\n\nreplace example.com/lib => ./_lib\n",
			"_lib/go.mod":     libmod,
			"_lib/base/b.go":  "package base\n\nfunc F() {}\n",
			"_lib/win/win.go": "package win\n\nimport _ \"example.com/vulnmod/ssh\"\n",
		}
	}
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
			"extra/extra_windows.go": "package extra\n\nimport \"example.com/vulnmod/ssh\"\n\nvar V = ssh.Client{}\n",
			"use_windows.go":         "package main\n\nimport _ \"example.com/m/extra\"\n",
		}},
		{"a directory built only for another platform, imported by nothing, imports the vulnerable package", importsBlake, moduleFinding, false, map[string]string{
			"cmd/w/w_windows.go": "package main\n\nimport _ \"example.com/vulnmod/ssh\"\n\nfunc main() {}\n",
		}},
		{"a file for another platform imports an unloaded package of the module that imports the vulnerable one there", importsBlake, moduleFinding, false, map[string]string{
			"_vulnmod/agent/a.go":         "package agent\n",
			"_vulnmod/agent/a_windows.go": "package agent\n\nimport _ \"example.com/vulnmod/ssh\"\n",
			"main_windows.go":             "package main\n\nimport _ \"example.com/vulnmod/agent\"\n",
		}},
		{"a file for another platform reaches the vulnerable package through a dependency that requires the module", importsBlakeAndLib, moduleFinding, false, merge(libModule(true), map[string]string{
			"main_windows.go": "package main\n\nimport _ \"example.com/lib/win\"\n",
		})},
		{"a loaded dependency package's file for another platform imports the vulnerable package", importsBlakeAndLib, moduleFinding, false, merge(libModule(true), map[string]string{
			"_lib/base/b_windows.go": "package base\n\nimport _ \"example.com/vulnmod/ssh\"\n",
		})},
		{"a file for another platform imports a package no module holds", importsBlake, moduleFinding, false, map[string]string{
			"main_windows.go": "package main\n\nimport _ \"example.com/nowhere/x\"\n",
		}},
		{"a file for another platform reaches the vulnerable package through a dependency whose go.mod does not require the module", importsBlakeAndLib, moduleFinding, false, merge(libModule(false), map[string]string{
			"main_windows.go": "package main\n\nimport _ \"example.com/lib/win\"\n",
		})},
		{"a dependency holds an unloaded package importing the vulnerable one, and nothing imports it", importsBlakeAndLib, moduleFinding, true, libModule(false)},
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

// TestRestateNotImported_OtherCgoSetting: the build is loaded under one cgo setting, and a file only
// the other setting compiles is still read. One that imports the vulnerable package keeps the basis,
// with cgo off (a file importing "C" is dropped) and with cgo on (a file marked !cgo is).
func TestRestateNotImported_OtherCgoSetting(t *testing.T) {
	const (
		cgoSSH     = "package main\n\n// void run(void) {}\nimport \"C\"\n\nimport _ \"example.com/vulnmod/ssh\"\n\nfunc init() { C.run() }\n"
		cgoBlake   = "package main\n\n// void run(void) {}\nimport \"C\"\n\nimport \"example.com/vulnmod/blake\"\n\nfunc init() { C.run(); blake.Sum() }\n"
		noCgoSSH   = "//go:build !cgo\n\npackage main\n\nimport _ \"example.com/vulnmod/ssh\"\n"
		noCgoBlake = "//go:build !cgo\n\npackage main\n\nimport \"example.com/vulnmod/blake\"\n\nfunc init() { blake.Sum() }\n"
	)
	scanned := vulnScan{
		imports:  narrowedScans.narrow.imports,
		findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0"}}}},
	}
	cases := []struct {
		name     string
		cgo      string
		file     string
		restated bool
	}{
		{"cgo off, a dropped cgo file imports the vulnerable package", "0", cgoSSH, false},
		{"cgo off, a dropped cgo file imports another package of the module", "0", cgoBlake, true},
		{"cgo on, a file built only with cgo off imports the vulnerable package", "1", noCgoSSH, false},
		{"cgo on, a file built only with cgo off imports another package of the module", "1", noCgoBlake, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CGO_ENABLED", tc.cgo)
			dir := writeTree(t, merge(narrowedModule, map[string]string{"other.go": tc.file}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if incompleteLoad(load.Packages, nil) {
				t.Fatal("load incomplete")
			}
			var left []string
			for _, p := range load.Packages {
				left = append(left, p.IgnoredFiles...)
			}
			if len(left) != 1 || !strings.HasSuffix(left[0], "other.go") {
				t.Fatalf("files the build left out = %v, want other.go alone", left)
			}
			res := restateNotImported(context.Background(), narrowedRefutation(), scanned, load.Packages, load.buildRelease(), dir, append(os.Environ(), "GOWORK=off"))
			if res.Refutation == nil {
				t.Fatal("refutation dropped")
			}
			want := plugin.RefutationAnalyzerSymbolNotReached
			if tc.restated {
				want = plugin.RefutationAnalyzerPackageNotImported
			}
			if res.Refutation.Basis != want {
				t.Fatalf("basis = %q, want %q (detail %q)", res.Refutation.Basis, want, res.Refutation.Detail)
			}
			if stated := strings.Contains(res.Refutation.Detail, "CGO_ENABLED="+tc.cgo); stated != tc.restated {
				t.Errorf("detail %q states the cgo setting = %v, want %v", res.Refutation.Detail, stated, tc.restated)
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
