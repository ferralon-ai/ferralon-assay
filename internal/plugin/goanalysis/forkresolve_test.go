package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReplacedResolution: an advisory on a module the build compiles from a replacement resolves in
// the code the build compiles for the advisory's package, and lists a symbol in OutsideBuild only
// when its qualifying package is absent from the build's resolved package set. Every module is a
// local directory, so nothing is downloaded.
func TestReplacedResolution(t *testing.T) {
	const (
		v3  = "example.com/vuln.MapClaims.VerifyAudience"
		v4  = "example.com/vuln/v4.MapClaims.VerifyAudience"
		app = "package main\n\nimport \"example.com/vuln\"\n\nfunc main() { _ = vuln.MapClaims{} }\n"
	)
	fork := "package vuln\n\ntype MapClaims map[string]any\n\nfunc (m MapClaims) VerifyAudience(string, bool) bool { return false }\n"
	v4pkg := "package vuln\n\ntype MapClaims map[string]any\n\nfunc (m MapClaims) VerifyAudience(string, bool) bool { return false }\n"
	forkMod := "module example.com/fork\n\ngo 1.22\n"

	cases := []struct {
		name          string
		pkg           string // the advisory's package; "" = example.com/vuln
		files         map[string]string
		symbols       []string
		wantOK        bool
		wantMatched   []string
		wantOutside   []string
		wantUnresolve bool
	}{
		{
			name: "fork defines the symbol; v4 qualifier absent from the build narrows",
			files: map[string]string{
				"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":       app,
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
			},
			symbols:     []string{v3, v4},
			wantOK:      true,
			wantMatched: []string{v3},
			wantOutside: []string{v4},
		},
		{
			name: "v4 qualifier compiled under its own path stays required",
			files: map[string]string{
				"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire (\n\texample.com/vuln v0.0.0\n\texample.com/vuln/v4 v4.0.0\n)\n\n" +
					"replace (\n\texample.com/vuln => ./_fork\n\texample.com/vuln/v4 => ./_v4\n)\n",
				"main.go":       "package main\n\nimport (\n\t\"example.com/vuln\"\n\tv4 \"example.com/vuln/v4\"\n)\n\nfunc main() { _ = vuln.MapClaims{}; _ = v4.MapClaims{} }\n",
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
				"_v4/go.mod":    "module example.com/vuln/v4\n\ngo 1.22\n",
				"_v4/vuln.go":   v4pkg,
			},
			symbols:       []string{v3, v4},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "v4 qualifier the source of a build-list replace, not imported, stays required",
			files: map[string]string{
				"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire (\n\texample.com/vuln v0.0.0\n\texample.com/vuln/v4 v4.0.0\n)\n\n" +
					"replace (\n\texample.com/vuln => ./_fork\n\texample.com/vuln/v4 => ./_v4\n)\n",
				"main.go":       app,
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
				"_v4/go.mod":    "module example.com/v4fork\n\ngo 1.22\n",
				"_v4/vuln.go":   v4pkg,
			},
			symbols:       []string{v3, v4},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "v4 qualifier the source of a go.mod replace outside the build list stays required",
			files: map[string]string{
				"go.mod": "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\n" +
					"replace (\n\texample.com/vuln => ./_fork\n\texample.com/vuln/v4 => ./_v4\n)\n",
				"main.go":       app,
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
				"_v4/go.mod":    "module example.com/v4fork\n\ngo 1.22\n",
				"_v4/vuln.go":   v4pkg,
			},
			symbols:       []string{v3, v4},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "v4 qualifier a package directory of the replacement's tree stays required",
			files: map[string]string{
				"go.mod":           "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":          app,
				"_fork/go.mod":     forkMod,
				"_fork/vuln.go":    fork,
				"_fork/v4/vuln.go": v4pkg,
			},
			symbols:       []string{v3, v4},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "a package of the replaced module the fork lacks stays required",
			files: map[string]string{
				"go.mod":             "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":            "package main\n\nimport (\n\t\"example.com/vuln\"\n\t\"example.com/vuln/decoder\"\n)\n\nfunc main() { _ = vuln.MapClaims{}; decoder.Decode() }\n",
				"_fork/go.mod":       forkMod,
				"_fork/vuln.go":      fork,
				"_fork/decoder/d.go": "package decoder\n\nfunc Decode() {}\n",
			},
			symbols:       []string{v3, "example.com/vuln/dec.Decode"},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "a package under a major-version directory of the fork's tree stays required",
			files: map[string]string{
				"go.mod":              "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":             "package main\n\nimport (\n\t\"example.com/vuln\"\n\t\"example.com/vuln/v2/parse\"\n)\n\nfunc main() { _ = vuln.MapClaims{}; parse.Parse() }\n",
				"_fork/go.mod":        forkMod,
				"_fork/vuln.go":       fork,
				"_fork/v2/parse/p.go": "package parse\n\nfunc Parse() {}\n",
			},
			symbols:       []string{v3, "example.com/vuln/v2/parser.Parse"},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "a major-version suffix of a module path carrying one stays required",
			pkg:  "example.com/vuln/v2",
			files: map[string]string{
				"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln/v2 v2.0.0\n\nreplace example.com/vuln/v2 => ./_fork\n",
				"main.go":       "package main\n\nimport \"example.com/vuln/v2\"\n\nfunc main() { _ = vuln.MapClaims{} }\n",
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
			},
			symbols:       []string{"example.com/vuln/v2.MapClaims.VerifyAudience", "example.com/vuln/v2/v3.Do"},
			wantOK:        true,
			wantMatched:   []string{"example.com/vuln/v2.MapClaims.VerifyAudience"},
			wantUnresolve: true,
		},
		{
			name: "a dotted directory of the replaced module the fork lacks stays required",
			files: map[string]string{
				"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":       app,
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
			},
			symbols: []string{v3, "example.com/vuln/v2.5/foo.F", "example.com/vuln/v2.5.F", "example.com/vuln/v2.Foo/x.F",
				"example.com/vuln/v2.Foo.Bar.Baz", "example.com/vuln/v2.a-b.F", "example.com/vuln/v2._.F", "example.com/vuln/v2.F."},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "a dotted directory of the fork's tree stays required",
			files: map[string]string{
				"go.mod":            "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":           app,
				"_fork/go.mod":      forkMod,
				"_fork/vuln.go":     fork,
				"_fork/v2.Foo/f.go": "package foo\n\nfunc Bar() {}\n",
			},
			symbols:       []string{v3, "example.com/vuln/v2.Foo.Bar"},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "a qualifier compiled from the main module stays required",
			files: map[string]string{
				"go.mod":         "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":        "package main\n\nimport (\n\t\"example.com/app/inner\"\n\t\"example.com/vuln\"\n)\n\nfunc main() { _ = vuln.MapClaims{}; inner.G() }\n",
				"inner/inner.go": "package inner\n\nfunc G() {}\n",
				"_fork/go.mod":   forkMod,
				"_fork/vuln.go":  fork,
			},
			symbols:       []string{v3, "example.com/app/inner.F"},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "a partial load does not narrow",
			files: map[string]string{
				"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":       app,
				"broken.go":     "package main\n\nvar _ int = \"x\"\n",
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
			},
			symbols:       []string{v3, v4},
			wantOK:        true,
			wantMatched:   []string{v3},
			wantUnresolve: true,
		},
		{
			name: "a replacement compiled with errors is not read",
			files: map[string]string{
				"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":       app,
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork + "\nvar _ int = \"x\"\n",
			},
			symbols: []string{v3},
		},
		{
			name: "fork without the symbol leaves it unresolved",
			files: map[string]string{
				"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":       app,
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": "package vuln\n\ntype MapClaims map[string]any\n",
			},
			symbols:       []string{v3},
			wantOK:        true,
			wantUnresolve: true,
		},
		{
			name: "a method promoted by embedding is not the type's own",
			files: map[string]string{
				"go.mod":       "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":      app,
				"_fork/go.mod": forkMod,
				"_fork/vuln.go": "package vuln\n\ntype base struct{}\n\nfunc (base) VerifyAudience(string, bool) bool { return false }\n\n" +
					"type MapClaims struct{ base }\n",
			},
			symbols:       []string{v3},
			wantOK:        true,
			wantUnresolve: true,
		},
		{
			name: "package the build does not compile is not read",
			files: map[string]string{
				"go.mod":         "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
				"main.go":        "package main\n\nimport _ \"example.com/vuln/sub\"\n\nfunc main() {}\n",
				"_fork/go.mod":   forkMod,
				"_fork/vuln.go":  fork,
				"_fork/sub/s.go": "package sub\n",
			},
			symbols: []string{v3},
		},
		{
			name: "a module with no replace is not read",
			files: map[string]string{
				"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n",
				"main.go":       app,
				"_fork/go.mod":  forkMod,
				"_fork/vuln.go": fork,
			},
			symbols: []string{v3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			mods, err := listModules(context.Background(), dir)
			if err != nil && tc.wantOK {
				t.Fatalf("listModules: %v", err)
			}
			pkg := tc.pkg
			if pkg == "" {
				pkg = "example.com/vuln"
			}
			res, ok := replacedResolution(context.Background(), dir, pkg, tc.symbols)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (modules %+v)", ok, tc.wantOK, mods)
			}
			if !ok {
				return
			}
			var matched []string
			for sym, scips := range res.Matched {
				for _, s := range scips {
					if res.Origins[s] != "pkg:golang/"+pkg {
						t.Errorf("origin of %s = %q", s, res.Origins[s])
					}
				}
				matched = append(matched, sym)
			}
			slices.Sort(matched)
			if !slices.Equal(matched, tc.wantMatched) {
				t.Errorf("matched = %v, want %v", matched, tc.wantMatched)
			}
			if !slices.Equal(res.OutsideBuild, tc.wantOutside) {
				t.Errorf("OutsideBuild = %v, want %v", res.OutsideBuild, tc.wantOutside)
			}
			if got := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonAdvisorySymbolUnresolved); got != tc.wantUnresolve {
				t.Errorf("unresolved reason = %v, want %v (partiality %+v)", got, tc.wantUnresolve, res.Partiality)
			}
		})
	}
}

// TestReplaceSources: a replacement whose tree cannot be read holds every path below its module, and a
// go.work replace on a module outside the build list holds its source path.
func TestReplaceSources(t *testing.T) {
	const v4 = "example.com/vuln/v4"
	type replace = struct{ Path, Version, Dir string }
	unreadable := t.TempDir()
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o755) })
	cases := []struct {
		name    string
		path    string // "" = v4
		treeDir string
		goWork  string
		want    bool
	}{
		{name: "a readable tree without the vN directory does not hold it", treeDir: t.TempDir()},
		{name: "a module of the build list with no replace holds nothing", path: "example.com/other/v2", treeDir: t.TempDir()},
		{name: "a replacement with no directory holds it", want: true},
		{name: "an unreadable tree holds it", treeDir: unreadable, want: true},
		{name: "a go.work replace outside the build list holds it", treeDir: t.TempDir(), goWork: "go 1.22\n\nuse .\n\nreplace example.com/vuln/v4 => ./_v4\n", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.treeDir == unreadable && os.Geteuid() == 0 {
				t.Skip("root reads any directory")
			}
			files := map[string]string{"go.mod": "module example.com/app\n\ngo 1.22\n"}
			if tc.goWork != "" {
				files["go.work"] = tc.goWork
			}
			buildDir := writeTree(t, files)
			work := ""
			if tc.goWork != "" {
				work = filepath.Join(buildDir, "go.work")
			}
			mods := []listedModule{
				{Path: "example.com/other", Version: "v1.0.0"},
				{Path: "example.com/vuln", Replace: &replace{Path: "example.com/fork", Dir: tc.treeDir}},
			}
			held, err := replaceSources(buildDir, work, mods)
			if err != nil {
				t.Fatal(err)
			}
			p := tc.path
			if p == "" {
				p = v4
			}
			if got := held(p, "F"); got != tc.want {
				t.Errorf("held(%s) = %v, want %v", p, got, tc.want)
			}
		})
	}
}

// TestResolveDependencySymbols_Replaced: the resolver answers an advisory on a replaced dependency
// module from the replacement's compiled code instead of the empty dependency answer.
func TestResolveDependencySymbols_Replaced(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.22\n\nrequire example.com/vuln v0.0.0\n\nreplace example.com/vuln => ./_fork\n",
		"main.go":       "package main\n\nimport \"example.com/vuln\"\n\nfunc main() { _ = vuln.MapClaims{} }\n",
		"_fork/go.mod":  "module example.com/fork\n\ngo 1.22\n",
		"_fork/vuln.go": "package vuln\n\ntype MapClaims map[string]any\n\nfunc (m MapClaims) VerifyAudience(string, bool) bool { return false }\n",
	})
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        dir,
		PURL:            "pkg:golang/example.com/vuln",
		AdvisorySymbols: []string{"example.com/vuln.MapClaims.VerifyAudience"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Resolved) != 1 || len(res.Matched["example.com/vuln.MapClaims.VerifyAudience"]) != 1 {
		t.Fatalf("resolved %+v matched %+v", res.Resolved, res.Matched)
	}
}
