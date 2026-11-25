package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

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
		imports:  map[string][]string{"stdlib": {"encoding/xml"}},
	}
	const module = "which reach example.com/vulnmod"
	// app is a build that ships a program: a main under cmd/ that imports pkg/x.
	app := map[string]string{
		"cmd/app/main.go": "package main\n\nimport \"example.com/m/pkg/x\"\n\nfunc main() { _ = x.Get() }\n",
		"pkg/x/x.go":      reaches("x"),
	}
	const appAssumption = `library-entrypoints "auto": treated as an application: 1 main package; no code outside the build imports example.com/m/pkg/x, which reach example.com/vulnmod; library mode: go:library=.`
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
		{"auto, a build with no main whose library under cmd reaches the module", "auto", map[string]string{
			"cmd/tool/flags/flags.go": reaches("flags"),
			"pkg/api/api.go":          clean("api"),
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/api"}, nil},
		{"auto, a library under cmd reaches the module", "auto", map[string]string{
			"cmd/tool/flags/flags.go": reaches("flags"),
			"cmd/tool/main.go":        "package main\n\nimport \"example.com/m/cmd/tool/flags\"\n\nfunc main() { _ = flags.Get() }\n",
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceMains, []string{}, nil},
		{"auto, an application whose library package reaches the module", "auto", app,
			moduleFinding, false, appAssumption, plugin.LibraryEntrypointsSourceMains, []string{}, nil},
		{"nothing stated, an application whose library package reaches the module", "", app,
			moduleFinding, false, appAssumption, plugin.LibraryEntrypointsSourceMains, []string{}, nil},
		{"auto, an application with two mains", "auto", merge(app, map[string]string{
			"cmd/gen/main.go": "package main\n\nfunc main() {}\n",
		}), moduleFinding, false, `treated as an application: 2 main packages; no code outside the build imports example.com/m/pkg/x, ` + module,
			plugin.LibraryEntrypointsSourceMains, []string{}, nil},
		{"auto, an application whose library packages do not reach the module", "auto", map[string]string{
			"cmd/app/main.go": "package main\n\nfunc main() {}\n",
			"pkg/x/x.go":      clean("x"),
		}, moduleFinding, false, "", plugin.LibraryEntrypointsSourceMains, []string{}, nil},
		{"auto, a main at the module root", "auto", map[string]string{
			"main.go":    "package main\n\nimport \"example.com/m/pkg/x\"\n\nfunc main() { _ = x.Get() }\n",
			"pkg/x/x.go": reaches("x"),
		}, moduleFinding, false, appAssumption, plugin.LibraryEntrypointsSourceMains, []string{}, nil},
		// grpc's shape: a library whose only mains are benchmark and interop programs. They ship
		// beside the library, not as the product, so the build stays a library.
		{"auto, mains only under benchmark and interop", "auto", map[string]string{
			"benchmark/worker/main.go": "package main\n\nimport \"example.com/m/pkg/x\"\n\nfunc main() { _ = x.Get() }\n",
			"interop/client/main.go":   "package main\n\nfunc main() {}\n",
			"pkg/x/x.go":               reaches("x"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/x"}, nil},
		{"auto, a main only under internal", "auto", map[string]string{
			"internal/gen/main.go": "package main\n\nfunc main() {}\n",
			"pkg/x/x.go":           reaches("x"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/x"}, nil},
		{"auto, a main only under examples", "auto", map[string]string{
			"examples/demo/main.go": "package main\n\nimport \"example.com/m/pkg/x\"\n\nfunc main() { _ = x.Get() }\n",
			"pkg/x/x.go":            reaches("x"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/x"}, nil},
		{"the whole tree as library, an application", ".", app,
			moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/x"}, nil},
		{"a path list naming the reaching package, an application", "pkg/x", app,
			moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/x"}, nil},
		{"auto plus a path, an application", "auto,pkg/x", app,
			moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/x"}, nil},
		{"auto plus a path to another package, an application", "auto,pkg/y", merge(app, map[string]string{
			"pkg/y/y.go": clean("y"),
		}), moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/x", "example.com/m/pkg/y"}, nil},
		{"an exclusion of another package, an application", "!pkg/y", merge(app, map[string]string{
			"pkg/y/y.go": clean("y"),
		}), moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/x"}, nil},
		{"none, an application", "none", app,
			moduleFinding, false, `library-entrypoints "none": no code outside the build imports example.com/m/pkg/x, ` + module,
			plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
		{"auto, an application whose load does not type-check", "auto", map[string]string{
			"cmd/app/main.go": "package main\n\nfunc main() {}\n",
			"pkg/x/x.go":      reaches("x"),
			"pkg/y/y.go":      "package y\n\nvar N int = \"x\"\n",
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/x", "example.com/m/pkg/y"}, nil},
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
			"lib/lib.go": "package lib\n\nimport \"encoding/xml\"\n\nfunc New() *xml.Decoder { return xml.NewDecoder(nil) }\n",
		}, stdlibFinding, false, "imports example.com/m/lib, which reach a vulnerable standard-library package",
			plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
		{"auto plus a program path, a test helper that does not type-check", "auto,cmd/tool", map[string]string{
			"cmd/tool/main.go":        "package main\n\nfunc main() {}\n",
			"cmd/tool/flags/flags.go": clean("flags"),
			"test/helpers/helpers.go": "package helpers\n\nimport \"example.com/vulnmod\"\n\nvar N int = \"x\"\n\nvar F = vulnmod.Bad\n",
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/cmd/tool/flags"}, nil},
		{"a path list naming only a program", "cmd/tool", map[string]string{
			"cmd/tool/main.go": "package main\n\nfunc main() {}\n",
			"pkg/api/api.go":   clean("api"),
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{}, []string{"cmd/tool"}},
		// Only a tightened package is left and it does not type-check: auto's set is empty, but what
		// the helper imports is unknown, so auto alone withholds.
		{"auto, only a test helper that does not type-check", "auto", map[string]string{
			"cmd/tool/main.go":        "package main\n\nfunc main() {}\n",
			"test/helpers/helpers.go": "package helpers\n\nvar N int = \"x\"\n",
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceAuto, []string{}, nil},
		{"an exclusion that matches nothing removes nothing, a test helper that does not type-check", "!nope", map[string]string{
			"cmd/tool/main.go":        "package main\n\nfunc main() {}\n",
			"test/helpers/helpers.go": "package helpers\n\nvar N int = \"x\"\n",
		}, moduleFinding, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{}, []string{"!nope"}},
		{"an exclusion naming the test helper that does not type-check", "!test", map[string]string{
			"cmd/tool/main.go":        "package main\n\nfunc main() {}\n",
			"test/helpers/helpers.go": "package helpers\n\nvar N int = \"x\"\n",
		}, moduleFinding, false, "imports example.com/m/test/helpers, which may reach (the load is incomplete) example.com/vulnmod",
			plugin.LibraryEntrypointsSourceDeclared, []string{}, nil},
		{"none, a test helper that does not type-check", "none", map[string]string{
			"pkg/api/api.go":          clean("api"),
			"test/helpers/helpers.go": "package helpers\n\nvar N int = \"x\"\n",
		}, moduleFinding, false, "imports example.com/m/pkg/api, example.com/m/test/helpers, which may reach (the load is incomplete) example.com/vulnmod",
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
			env := append(os.Environ(), "GOWORK=off")
			res, err := reconciledResult(context.Background(), tc.scanned, dir, env, func() (*LoadResult, error) { return load, nil }, entry)
			if err != nil {
				t.Fatal(err)
			}
			illTyped := false
			packages.Visit(load.Packages, nil, func(p *packages.Package) { illTyped = illTyped || p.IllTyped })
			if illTyped && !tc.withheld {
				// What reflection reaches through a package that does not type-check is unknown, so
				// no refutation stands; the library-escape withhold's own decision is read before it.
				if res.Refutation != nil || !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonReflectiveCall) {
					t.Fatalf("ill-typed load: refutation %+v, partiality %+v, want it withheld as reflection:call", res.Refutation, res.Partiality)
				}
				escaped := withholdRefutation(context.Background(), plugin.ReachabilityResult{Refutation: moduleRefutation(tc.scanned.findings, env)},
					tc.scanned, load.Packages, load.buildRelease(), dir, env, resolveEntrypoints(load.Packages, entry, dir, false))
				res.Refutation, res.Partiality = escaped.Refutation, escaped.Partiality
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

// TestResolveEntrypoints_Placement: declared paths are read from Base when the host sets it (the
// checkout root above a nested module), and a package that cannot be placed under it, with no
// directory or one outside it, keeps auto's answer and is an entry point under a path list.
func TestResolveEntrypoints_Placement(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "svc")
	for _, d := range []string{"svc/pkg/api", "svc/pkg/lib", "outside"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mod := &packages.Module{Path: "example.com/svc"}
	pkg := func(path, dir string) *packages.Package {
		return &packages.Package{PkgPath: path, Name: "x", Module: mod, Dir: dir}
	}
	api := pkg("example.com/svc/pkg/api", filepath.Join(module, "pkg/api"))
	lib := pkg("example.com/svc/pkg/lib", filepath.Join(module, "pkg/lib"))
	nodir := pkg("example.com/svc/gen", "")
	testdir := pkg("example.com/svc/test/gen", "")
	nomod := &packages.Package{PkgPath: "example.com/svc/test/fixtures", Name: "x", Dir: filepath.Join(module, "pkg/lib")}
	outside := pkg("example.com/svc/outside", filepath.Join(root, "outside"))
	all := []*packages.Package{api, lib, nodir, outside}
	cases := []struct {
		name      string
		input     string
		base      string
		pkgs      []*packages.Package
		entries   []string
		unmatched []string
	}{
		{"repository-relative path, based at the checkout root", "svc/pkg/api", root, []*packages.Package{api, lib},
			[]string{"example.com/svc/pkg/api"}, nil},
		{"repository-relative path, no base, read from the build directory", "svc/pkg/api", "", []*packages.Package{api, lib},
			[]string{}, []string{"svc/pkg/api"}},
		{"an unplaced package is an entry point under a path list", "pkg/api", "", []*packages.Package{api, nodir},
			[]string{"example.com/svc/gen", "example.com/svc/pkg/api"}, nil},
		{"an unplaced package auto excludes is an entry point under a path list", "pkg/api", "", []*packages.Package{api, testdir},
			[]string{"example.com/svc/pkg/api", "example.com/svc/test/gen"}, nil},
		{"a package with no module to measure from is never auto-excluded", "auto", "", []*packages.Package{api, nomod},
			[]string{"example.com/svc/pkg/api", "example.com/svc/test/fixtures"}, nil},
		{"a package outside the root is not placed", "pkg/api", "", []*packages.Package{api, outside},
			[]string{"example.com/svc/outside", "example.com/svc/pkg/api"}, nil},
		{"an unplaced package keeps auto's answer under an exclusion", "!.", "", all,
			[]string{"example.com/svc/gen", "example.com/svc/outside"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decl, err := plugin.ParseLibraryEntrypoints(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			decl.Base = tc.base
			rec := resolveEntrypoints(tc.pkgs, decl, module, false).record()
			if !slices.Equal(rec.Packages, tc.entries) {
				t.Errorf("entry points = %q, want %q", rec.Packages, tc.entries)
			}
			if !slices.Equal(rec.Unmatched, tc.unmatched) {
				t.Errorf("unmatched = %q, want %q", rec.Unmatched, tc.unmatched)
			}
		})
	}
}

// TestWithholdForLibraryEscape_IncompleteLoad: a withhold the incomplete load contributes to declares
// tool_failure beside library_escape; one a complete load makes because a package reaches does not.
func TestWithholdForLibraryEscape_IncompleteLoad(t *testing.T) {
	base := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Bad() {}\n",
	}
	scanned := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}}
	cases := []struct {
		name   string
		lib    string
		failed bool
	}{
		{"a load that does not type-check", "package lib\n\nvar N int = \"x\"\n", true},
		{"a complete load that reaches the module", "package lib\n\nimport \"example.com/vulnmod\"\n\nfunc Get() func() { return vulnmod.Bad }\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := plugin.ParseLibraryEntrypoints("auto")
			if err != nil {
				t.Fatal(err)
			}
			dir := writeTree(t, merge(base, map[string]string{"pkg/lib/lib.go": tc.lib}))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			refuted := plugin.ReachabilityResult{
				Partiality: plugin.Complete(),
				Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod"},
			}
			res := withholdForLibraryEscape(refuted, scanned, load.Packages, resolveEntrypoints(load.Packages, entry, dir, false))
			if res.Refutation != nil || !slices.Contains(res.Partiality.Reasons, plugin.PartialReasonLibraryEscape) {
				t.Fatalf("result %+v, want the refutation withheld as library_escape", res)
			}
			if failed := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonToolFailure); failed != tc.failed {
				t.Errorf("tool_failure declared = %v, want %v (partiality %+v)", failed, tc.failed, res.Partiality)
			}
		})
	}
}

// TestApplicationMains: only a shipped main at its module's root or under cmd reads a build as an
// application, and only in a build of one main module: a go.work library module beside a tool
// module stays a library even though the tool's main sits under cmd. LoadProgram's roots come from
// one module today, so the workspace case is built by hand.
func TestApplicationMains(t *testing.T) {
	pkg := func(path, module string, main bool) *packages.Package {
		p := &packages.Package{PkgPath: path, Name: "lib", GoFiles: []string{"f.go"}, Module: &packages.Module{Path: module, Main: true}}
		if main {
			p.Name = "main"
		}
		return p
	}
	const m = "example.com/m"
	for _, tc := range []struct {
		name string
		pkgs []*packages.Package
		want []string
	}{
		{"root and cmd mains", []*packages.Package{
			pkg(m, m, true), pkg(m+"/cmd", m, true), pkg(m+"/cmd/app", m, true), pkg(m+"/pkg/x", m, false),
		}, []string{m, m + "/cmd", m + "/cmd/app"}},
		{"grpc's shape: benchmark and interop mains", []*packages.Package{
			pkg(m+"/benchmark/worker", m, true), pkg(m+"/interop/client", m, true), pkg(m+"/pkg/x", m, false),
		}, nil},
		{"generators and tools", []*packages.Package{
			pkg(m+"/internal/gen", m, true), pkg(m+"/hack/tool", m, true), pkg(m+"/tools/lint", m, true),
			pkg(m+"/profiling/p", m, true), pkg(m+"/cmdline", m, true),
		}, nil},
		{"a cmd main under examples", []*packages.Package{pkg(m+"/examples/cmd/demo", m, true)}, nil},
		{"a library module beside a tool module", []*packages.Package{
			pkg(m+"/x", m, false), pkg(m+"/tools/cmd/t", m+"/tools", true),
		}, nil},
		{"a dependency beside the main module", []*packages.Package{
			pkg(m+"/cmd/app", m, true), {PkgPath: "example.com/dep", Name: "dep", GoFiles: []string{"f.go"}, Module: &packages.Module{Path: "example.com/dep"}},
		}, []string{m + "/cmd/app"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, p := range applicationMains(tc.pkgs) {
				got = append(got, p.PkgPath)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("applicationMains = %q, want %q", got, tc.want)
			}
		})
	}
}

// A strict request reads auto as a library even where practical mode reads the build as an
// application; a declaration applies in both modes.
func TestReconciledResult_LibraryEntrypointsStrict(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Bad() {}\n",
		"cmd/app/main.go":     "package main\n\nimport \"example.com/m/pkg/x\"\n\nfunc main() { _ = x.Get() }\n",
		"pkg/x/x.go":          "package x\n\nimport \"example.com/vulnmod\"\n\nfunc Get() func() { return vulnmod.Bad }\n",
	}
	scanned := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}}
	const appAssumption = "treated as an application: 1 main package; no code outside the build imports example.com/m/pkg/x"
	cases := []struct {
		name       string
		input      string
		strict     bool
		withheld   bool
		assumption string
		source     string
		packages   []string
	}{
		{"auto, practical", "auto", false, false, appAssumption, plugin.LibraryEntrypointsSourceMains, []string{}},
		{"auto, strict", "auto", true, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/x"}},
		{"nothing stated, practical", "", false, false, appAssumption, plugin.LibraryEntrypointsSourceMains, []string{}},
		{"nothing stated, strict", "", true, true, "", plugin.LibraryEntrypointsSourceAuto, []string{"example.com/m/pkg/x"}},
		{"none, practical", "none", false, false, `library-entrypoints "none": no code outside the build imports example.com/m/pkg/x`, plugin.LibraryEntrypointsSourceDeclared, []string{}},
		{"none, strict", "none", true, false, `library-entrypoints "none": no code outside the build imports example.com/m/pkg/x`, plugin.LibraryEntrypointsSourceDeclared, []string{}},
		{"the whole tree as library, practical", ".", false, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/x"}},
		{"the whole tree as library, strict", ".", true, true, "", plugin.LibraryEntrypointsSourceDeclared, []string{"example.com/m/pkg/x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := plugin.ParseLibraryEntrypoints(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			dir := writeTree(t, files)
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			ctx := withStrict(context.Background(), tc.strict)
			res, err := reconciledResult(ctx, scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, entry)
			if err != nil {
				t.Fatal(err)
			}
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("refutation withheld = %v, want %v (result %+v)", withheld, tc.withheld, res)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonLibraryEscape); declared != tc.withheld {
				t.Errorf("library_escape declared = %v, want %v", declared, tc.withheld)
			}
			if r := res.Refutation; r != nil && (len(r.Assumptions) != 1 || !strings.Contains(r.Assumptions[0], tc.assumption)) {
				t.Errorf("assumptions = %q, want one containing %q", r.Assumptions, tc.assumption)
			}
			rec := res.LibraryEntrypoints
			if rec == nil {
				t.Fatal("no library_entrypoints record")
			}
			if rec.Source != tc.source || !slices.Equal(rec.Packages, tc.packages) {
				t.Errorf("record = source %q packages %q, want %q %q", rec.Source, rec.Packages, tc.source, tc.packages)
			}
		})
	}
}
