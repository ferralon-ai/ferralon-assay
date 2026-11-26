package main

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestStrictnessPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     string
		config  string
		want    report.Mode
		wantErr string
	}{
		{name: "nothing stated", want: report.Mode{Strictness: "practical", Source: "default"}},
		{name: "config key", config: "strict", want: report.Mode{Strictness: "strict", Source: "ferralon.yml"}},
		{name: "config practical", config: "practical", want: report.Mode{Strictness: "practical", Source: "ferralon.yml"}},
		{name: "env over config", env: "practical", config: "strict", want: report.Mode{Strictness: "practical", Source: "input"}},
		{name: "flag over env", args: []string{"-strictness=strict"}, env: "practical", want: report.Mode{Strictness: "strict", Source: "input"}},
		{name: "flag over config", args: []string{"-strictness", "practical"}, config: "strict", want: report.Mode{Strictness: "practical", Source: "input"}},
		{name: "blank flag is not stated", args: []string{"-strictness= "}, config: "strict", want: report.Mode{Strictness: "strict", Source: "ferralon.yml"}},
		{name: "invalid flag", args: []string{"-strictness=lenient"}, wantErr: `"lenient"`},
		{name: "invalid env", env: "lenient", wantErr: "ASSAY_STRICTNESS"},
		{name: "cased flag", args: []string{"-strictness=Strict"}, wantErr: `"Strict"`},
		{name: "invalid flag over valid config", args: []string{"-strictness=on"}, config: "strict", wantErr: "want practical or strict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envStrictness, tt.env)
			f := runFlagsFor(t, tt.args...)
			f.repoStrictness = tt.config
			checkErr := f.checkStrictness()
			got, err := f.resolveMode()
			if tt.wantErr != "" {
				for _, e := range []error{checkErr, err} {
					if e == nil || !strings.Contains(e.Error(), tt.wantErr) {
						t.Fatalf("error = %v, want one containing %q", e, tt.wantErr)
					}
				}
				return
			}
			if checkErr != nil || err != nil {
				t.Fatalf("checkStrictness = %v, resolveMode = %v", checkErr, err)
			}
			if got != tt.want {
				t.Errorf("mode = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Every assess path carries the resolved mode into the pipeline, and records it on the flags for the
// Report's source.
func TestStrictnessReachesEveryAssessPath(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	paths := map[string]func(*runFlags) ([]pipeline.AssessOption, error){
		"baseline": func(f *runFlags) ([]pipeline.AssessOption, error) {
			return f.baselineAssessOptions(func(*pipeline.AssessConfig) {}, "go")
		},
		"run": func(f *runFlags) ([]pipeline.AssessOption, error) {
			return f.runAssessOptions(func(*pipeline.AssessConfig) {}, "go")
		},
	}
	tests := []struct {
		name       string
		args       []string
		config     string
		wantStrict bool
		wantSource string
	}{
		{name: "default", wantSource: "default"},
		{name: "config strict", config: "strict", wantStrict: true, wantSource: "ferralon.yml"},
		{name: "flag strict", args: []string{"-strictness=strict"}, wantStrict: true, wantSource: "input"},
		{name: "flag practical over config strict", args: []string{"-strictness=practical"}, config: "strict", wantSource: "input"},
	}
	for path, build := range paths {
		for _, tt := range tests {
			t.Run(path+"/"+tt.name, func(t *testing.T) {
				t.Setenv(envStrictness, "")
				f := runFlagsFor(t, tt.args...)
				f.repoStrictness = tt.config
				opts, err := build(f)
				if err != nil {
					t.Fatal(err)
				}
				if got := pipeline.StrictOf(opts...); got != tt.wantStrict {
					t.Errorf("strict = %v, want %v", got, tt.wantStrict)
				}
				if f.resolvedMode.Source != tt.wantSource {
					t.Errorf("source = %q, want %q", f.resolvedMode.Source, tt.wantSource)
				}
			})
		}
		t.Run(path+"/invalid fails assembly", func(t *testing.T) {
			t.Setenv(envStrictness, "lenient")
			if _, err := build(runFlagsFor(t)); err == nil {
				t.Fatal("assembled options under an invalid strictness")
			}
		})
	}
}

// The strictness key of .github/ferralon.yml reaches the run through the acquired target.
func TestAcquireTarget_ReadsStrictnessKey(t *testing.T) {
	for _, tt := range []struct{ name, yml, want string }{
		{name: "none"},
		{name: "strict", yml: "strictness: strict\n", want: "strict"},
		{name: "practical", yml: "strictness: practical\n", want: "practical"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeT(t, filepath.Join(dir, "go.mod"), "module example.com/vendored\n\ngo 1.26\n")
			if tt.yml != "" {
				writeT(t, filepath.Join(dir, ".github", "ferralon.yml"), tt.yml)
			}
			acq, err := acquireTarget(context.Background(), dir, "r", "", "/fake/analyzer-bin", false, graphRequest{mode: buildGraphOff})
			if err != nil {
				t.Fatalf("acquireTarget: %v", err)
			}
			defer acq.cleanup()
			if acq.cfgStrictness != tt.want {
				t.Errorf("cfgStrictness = %q, want %q", acq.cfgStrictness, tt.want)
			}
		})
	}
	t.Run("invalid value fails the acquire", func(t *testing.T) {
		dir := t.TempDir()
		writeT(t, filepath.Join(dir, "go.mod"), "module example.com/vendored\n\ngo 1.26\n")
		writeT(t, filepath.Join(dir, ".github", "ferralon.yml"), "strictness: lenient\n")
		if _, err := acquireTarget(context.Background(), dir, "r", "", "/fake/analyzer-bin", false, graphRequest{mode: buildGraphOff}); err == nil {
			t.Fatal("acquired under an invalid strictness key")
		}
	})
}

// In strict the work-set inventory asks the reader under strict, so a version the JS lane reads
// only by assuming the install honours the lockfile does not pin the coordinate: it is admitted by
// name, unresolved, instead of by the assumed version.
func TestDependencyInventory_Strict(t *testing.T) {
	dir := t.TempDir()
	for f, body := range map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}}`,
		"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}},` +
			`"node_modules/express":{"version":"4.19.2"}}}`,
		"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . /app\nRUN npm install\n",
	} {
		writeT(t, filepath.Join(dir, f), body)
	}
	express := report.Package{Ecosystem: "npm", Name: "express"}
	for _, tc := range []struct {
		strict         bool
		wantResolved   []report.Package
		wantUnresolved []report.Package
	}{
		{strict: false, wantResolved: []report.Package{{Ecosystem: "npm", Name: "express", Version: "4.19.2"}}},
		{strict: true, wantUnresolved: []report.Package{express}},
	} {
		acq := &acquired{
			buildDir: dir, language: checkout.LangJS, repo: "example.com/fixture",
			plugin: jsInventory{unsearchingAnalyzer{language: checkout.LangJS}}, strict: tc.strict,
		}
		resolved, unresolved, notes := dependencyInventory(context.Background(), acq)
		if !slices.Equal(resolved, tc.wantResolved) || !slices.Equal(unresolved, tc.wantUnresolved) {
			t.Errorf("strict=%v: resolved=%+v unresolved=%+v notes=%+v, want resolved=%+v unresolved=%+v",
				tc.strict, resolved, unresolved, notes, tc.wantResolved, tc.wantUnresolved)
		}
	}
}

// scanWorkSet hands the run's resolved strictness to the work-set inventory, from the input and
// from the ferralon.yml key alike.
func TestScanWorkSet_CarriesStrict(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		config string
		want   bool
	}{
		{name: "default", want: false},
		{name: "input", args: []string{"-strictness=strict"}, want: true},
		{name: "config", config: "strict", want: true},
		{name: "input over config", args: []string{"-strictness=practical"}, config: "strict", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envStrictness, "")
			t.Setenv(envOSVWorkSet, "")
			trapEgress(t)
			f := runFlagsFor(t, tc.args...)
			f.repoStrictness = tc.config
			acq := goFixture(t, fixtureGoMod)
			_, _ = f.scanWorkSet(context.Background(), acq)
			if acq.strict != tc.want {
				t.Errorf("acq.strict = %v, want %v", acq.strict, tc.want)
			}
		})
	}
}
