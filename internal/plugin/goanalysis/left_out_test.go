package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeTree lays out files under a fresh directory, path → contents.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestWithholdForLeftOutFiles: govulncheck never traces a file the build left out, so a file for
// another platform or behind a tag that may call into the refuted module withholds the refutation.
func TestWithholdForLeftOutFiles(t *testing.T) {
	base := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/vulnmod v0.0.0\n\texample.com/dep v0.0.0\n\texample.com/other v0.0.0\n)\n\n" +
			"replace (\n\texample.com/vulnmod => ./_vulnmod\n\texample.com/dep => ./_dep\n\texample.com/other => ./_other\n)\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"mid/mid.go":          "package mid\n\nimport \"example.com/vulnmod\"\n\nfunc Call() { vulnmod.Bad() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
		"_dep/go.mod":         "module example.com/dep\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
		"_dep/dep.go":         "package dep\n\nimport \"example.com/vulnmod\"\n\nfunc Call() { vulnmod.Bad() }\n",
		"_other/go.mod":       "module example.com/other\n\ngo 1.22\n",
		"_other/other.go":     "package other\n\nfunc Call() {}\n",
	}
	leftOut := func(constraint, imp string) string {
		return "//go:build " + constraint + "\n\npackage main\n\nimport _ \"" + imp + "\"\n"
	}
	cases := []struct {
		name     string
		files    map[string]string
		withheld bool
	}{
		{"no file left out", nil, false},
		{"a tagged file imports the module", map[string]string{"prod.go": leftOut("prod", "example.com/vulnmod")}, true},
		{"another platform's file imports the module", map[string]string{"run_plan9.go": "package main\n\nimport _ \"example.com/vulnmod\"\n"}, true},
		{"a tagged file imports a loaded package that imports the module", map[string]string{"prod.go": leftOut("prod", "example.com/m/mid")}, true},
		{"a tagged file imports an unloaded module that requires the module", map[string]string{"prod.go": leftOut("prod", "example.com/dep")}, true},
		{"a tagged file imports an unloaded module that does not require it", map[string]string{"prod.go": leftOut("prod", "example.com/other")}, false},
		{"a tagged file imports only the standard library", map[string]string{"prod.go": leftOut("prod", "net/http")}, false},
		{"an ignore-tagged file is never built", map[string]string{"gen.go": leftOut("ignore", "example.com/vulnmod")}, false},
		{"a tagged package wholly left out imports the module", map[string]string{"prodonly/p.go": "//go:build prod\n\npackage prodonly\n\nimport _ \"example.com/vulnmod\"\n"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range base {
				files[k] = v
			}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			refuted := plugin.ReachabilityResult{
				Partiality: plugin.Complete(),
				Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod"},
			}
			res := withholdForLeftOutFiles(context.Background(), refuted, load.Packages, dir, append(os.Environ(), "GOWORK=off"))
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != tc.withheld {
				t.Errorf("excluded_files declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestGoflagsTags: GOFLAGS carries the build tags every spawned go command uses, and the last
// -tags flag wins.
func TestGoflagsTags(t *testing.T) {
	cases := []struct {
		goflags string
		want    []string
	}{
		{"", nil},
		{"-mod=mod", nil},
		{"-tags=prod", []string{"prod"}},
		{"--tags=prod,netgo -mod=mod", []string{"prod", "netgo"}},
		{"-tags=a -tags=b", []string{"b"}},
	}
	for _, tc := range cases {
		if got := goflagsTags([]string{"GOFLAGS=" + tc.goflags}); !slices.Equal(got, tc.want) {
			t.Errorf("goflagsTags(%q) = %q, want %q", tc.goflags, got, tc.want)
		}
	}
}
