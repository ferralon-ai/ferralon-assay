package goanalysis

import (
	"context"
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
	}{
		{"the build imports another package of the module", importsBlake, moduleFinding, true},
		{"the build imports the vulnerable package", importsSSH, moduleFinding, false},
		{"the build imports the vulnerable package through another package of the module", importsWrap, moduleFinding, false},
		{"the advisory also lists the whole module", importsBlake, s.wholeModule, false},
		{"no advisory entry lists the module's packages", importsBlake, vulnScan{findings: moduleFinding.findings}, false},
		{"a package-level finding", importsBlake, packageFinding, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(narrowedModule, map[string]string{"main.go": tc.main}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			if incompleteLoad(load.Packages, nil) {
				t.Fatal("load incomplete")
			}
			in := narrowedRefutation()
			in.Refutation.Detail = "govulncheck traced no call"
			res := restateNotImported(in, tc.scanned, load.Packages)
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
	if res := restateNotImported(narrowedRefutation(), scanned, load.Packages); res.Refutation.Basis != plugin.RefutationAnalyzerSymbolNotReached {
		t.Fatalf("basis = %q, want it kept", res.Refutation.Basis)
	}
}
