package goanalysis

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReconciledResult_LibraryEntrypoints: the library-escape withhold judges the entry points the
// caller's statement resolves to. A refutation stands only when no entry point reaches the refuted
// module, it carries an assumption exactly when a declaration took a reaching package out of auto's
// entry points, and the result records the resolved set and its source.
func TestReconciledResult_LibraryEntrypoints(t *testing.T) {
	base := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Bad() {}\n",
	}
	reaches := func(name string) string {
		return "package " + name + "\n\nimport \"example.com/vulnmod\"\n\nfunc Get() func() { return vulnmod.Bad }\n"
	}
	clean := func(name string) string {
		return "package " + name + "\n\nfunc Two() int { return 2 }\n"
	}
	moduleFinding := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}}
	stdlibFinding := vulnScan{
		findings: []vulnFinding{{OSV: "GO-2", Trace: []vulnFrame{{Module: "stdlib", Version: "v1.22.0"}}}},
		imports:  map[string][]string{"stdlib": {"strconv"}},
	}
	const module = "which reach example.com/vulnmod"
	cases := []struct {
		name       string
		input      string
		files      map[string]string
		scanned    vulnScan
		withheld   bool
		assumption string // a substring of the one assumption, or "" for none
		source     string
		packages   []string
		unmatched  []string
	}{
		{"auto, an entry point reaches the module", "auto", map[string]string{
			"pkg/lib/lib.go": reaches("lib"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/lib"}, nil},
		{"none, a library package reaches the module", "none", map[string]string{
			"pkg/lib/lib.go": reaches("lib"),
		}, moduleFinding, false, `library-entrypoints "none": no code outside the build imports example.com/m/pkg/lib, ` + module,
			plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
		{"auto excluding the reaching package", "!pkg/lib", map[string]string{
			"pkg/lib/lib.go": reaches("lib"),
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, false, `library-entrypoints "!pkg/lib": no code outside the build imports example.com/m/pkg/lib, ` + module,
			plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/api"}, nil},
		{"a path list leaving out the reaching package", "pkg/api", map[string]string{
			"pkg/lib/lib.go": reaches("lib"),
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, false, "imports example.com/m/pkg/lib, " + module,
			plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/api"}, nil},
		{"a path list naming the reaching package", "./pkg/lib/...", map[string]string{
			"pkg/lib/lib.go": reaches("lib"),
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/lib"}, nil},
		{"a path list covering a subtree", "pkg", map[string]string{
			"pkg/lib/lib.go": reaches("lib"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/lib"}, nil},
		{"exclusion wins over inclusion", "pkg,!pkg/lib", map[string]string{
			"pkg/lib/lib.go": reaches("lib"),
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, false, "imports example.com/m/pkg/lib, " + module,
			plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/api"}, nil},
		{"a path list naming a path the build does not hold", "pkg/nope", map[string]string{
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{}, []string{"pkg/nope"}},
		{"auto plus a path the build does not hold", "auto,pkg/nope", map[string]string{
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/api"}, []string{"pkg/nope"}},
		{"an exclusion of a path the build does not hold", "!pkg/nope", map[string]string{
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/api"}, []string{"!pkg/nope"}},
		{"auto, a library under cmd reaches the module", "auto", map[string]string{
			"cmd/tool/flags/flags.go": reaches("flags"),
			"cmd/tool/main.go":        "package main\n\nimport \"example.com/m/cmd/tool/flags\"\n\nfunc main() { _ = flags.Get() }\n",
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceAuto, []string{}, nil},
		{"auto, an example reaches the module", "auto", map[string]string{
			"examples/basic/basic.go": reaches("basic"),
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceAuto, []string{}, nil},
		{"auto, a test helper package reaches the module", "auto", map[string]string{
			"test/helpers/helpers.go": reaches("helpers"),
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceAuto, []string{}, nil},
		{"auto, a package named like a test directory without being one", "auto", map[string]string{
			"pkg/testing2/t.go": reaches("testing2"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/testing2"}, nil},
		{"auto, the module's own path holds an excluded element", "auto", map[string]string{
			"go.mod":     strings.Replace(base["go.mod"], "module example.com/m\n", "module example.com/examples/m\n", 1),
			"lib/lib.go": reaches("lib"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/examples/m/lib"}, nil},
		{"a path list naming a cmd library", "auto,cmd/tool", map[string]string{
			"cmd/tool/flags/flags.go": reaches("flags"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/cmd/tool/flags"}, nil},
		{"auto, a load that does not type-check", "auto", map[string]string{
			"pkg/lib/lib.go": "package lib\n\nvar N int = \"x\"\n",
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/lib"}, nil},
		{"none, a load that does not type-check", "none", map[string]string{
			"pkg/lib/lib.go": "package lib\n\nvar N int = \"x\"\n",
		}, moduleFinding, false, "imports example.com/m/pkg/lib, which may reach (the load is incomplete) example.com/vulnmod",
			plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
		{"a path list, a load that does not type-check", "pkg/api", map[string]string{
			"pkg/lib/lib.go": "package lib\n\nvar N int = \"x\"\n",
			"pkg/api/api.go": clean("api"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/api"}, nil},
		{"none, more reaching packages than the assumption names", "none", map[string]string{
			"a/a.go": reaches("a"), "b/b.go": reaches("b"), "c/c.go": reaches("c"),
			"d/d.go": reaches("d"), "e/e.go": reaches("e"), "f/f.go": reaches("f"),
		}, moduleFinding, false, "imports example.com/m/a, example.com/m/b, example.com/m/c, example.com/m/d, example.com/m/e, 1 more, " + module,
			plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
		{"none, standard-library refutation", "none", map[string]string{
			"lib/lib.go": "package lib\n\nimport \"strconv\"\n\nfunc Itoa(i int) string { return strconv.Itoa(i) }\n",
		}, stdlibFinding, false, "imports example.com/m/lib, which reach a vulnerable standard-library package",
			plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
		{"none, nothing reaches the module", "none", map[string]string{
			"lib/lib.go": clean("lib"),
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := plugin.ParseLibraryEntrypoints(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			dir := writeTree(t, merge(base, tc.files))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			res, err := reconciledResult(context.Background(), tc.scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, entry)
			if err != nil {
				t.Fatal(err)
			}
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("refutation withheld = %v, want %v (result %+v)", withheld, tc.withheld, res)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonLibraryEscape); declared != tc.withheld {
				t.Errorf("library_escape declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
			if r := res.Refutation; r != nil {
				switch {
				case tc.assumption == "" && len(r.Assumptions) > 0:
					t.Errorf("assumptions = %q, want none", r.Assumptions)
				case tc.assumption != "" && (len(r.Assumptions) != 1 || !strings.Contains(r.Assumptions[0], tc.assumption)):
					t.Errorf("assumptions = %q, want one containing %q", r.Assumptions, tc.assumption)
				}
			}
			rec := res.LibraryEntrypoints
			if rec == nil {
				t.Fatal("no resolved library entry points recorded")
			}
			if rec.Source != tc.source || rec.Input != entry.String() {
				t.Errorf("record source, input = %q, %q, want %q, %q", rec.Source, rec.Input, tc.source, entry.String())
			}
			if !slices.Equal(rec.Packages, tc.packages) {
				t.Errorf("record packages = %q, want %q", rec.Packages, tc.packages)
			}
			if !slices.Equal(rec.Unmatched, tc.unmatched) {
				t.Errorf("record unmatched = %q, want %q", rec.Unmatched, tc.unmatched)
			}
		})
	}
}
