package goanalysis

import (
	"context"
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
