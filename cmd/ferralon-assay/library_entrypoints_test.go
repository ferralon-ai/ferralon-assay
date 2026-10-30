package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestLibraryEntrypointsOption: -library-entrypoints, then its env, reaches AssessConfig on both the
// baseline and the run path; nothing stated leaves it unset; a statement that does not parse stops
// assembly.
func TestLibraryEntrypointsOption(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	paths := []struct {
		name  string
		build func(*runFlags) ([]pipeline.AssessOption, error)
	}{
		{"baseline", func(f *runFlags) ([]pipeline.AssessOption, error) {
			return f.baselineAssessOptions(func(*pipeline.AssessConfig) {})
		}},
		{"run", func(f *runFlags) ([]pipeline.AssessOption, error) {
			return f.runAssessOptions(func(*pipeline.AssessConfig) {})
		}},
	}
	cases := []struct {
		name    string
		env     string
		args    []string
		want    *plugin.LibraryEntrypoints
		wantErr bool
	}{
		{name: "nothing stated"},
		{name: "env", env: "none", want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsNone}},
		{name: "flag over env", env: "none", args: []string{"-library-entrypoints", "pkg/api,!pkg/api/x"},
			want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsPaths, Include: []string{"pkg/api"}, Exclude: []string{"pkg/api/x"}}},
		{name: "action default", env: "auto", want: &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsAuto}},
		{name: "unparsable", env: "none,../x", wantErr: true},
	}
	for _, p := range paths {
		for _, tc := range cases {
			t.Run(p.name+"/"+tc.name, func(t *testing.T) {
				t.Setenv(envLibraryEntrypoints, tc.env)
				opts, err := p.build(runFlagsFor(t, tc.args...))
				if (err != nil) != tc.wantErr {
					t.Fatalf("err = %v, want error %v", err, tc.wantErr)
				}
				if tc.wantErr {
					return
				}
				if got := applyAll(opts).LibraryEntrypoints; !reflect.DeepEqual(got, tc.want) {
					t.Errorf("LibraryEntrypoints = %+v, want %+v", got, tc.want)
				}
			})
		}
	}
}

// TestActionExportsLibraryEntrypoints: the Action input reaches the scanner only if action.yml exports
// exactly the env name run.go reads, through the step env.
func TestActionExportsLibraryEntrypoints(t *testing.T) {
	path := filepath.Join("..", "..", "action.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	yml := string(body)
	if !strings.Contains(yml, envLibraryEntrypoints+": ${{ inputs.library-entrypoints }}") {
		t.Errorf("action.yml does not export %s from the library-entrypoints input", envLibraryEntrypoints)
	}
	if !strings.Contains(yml, "\n  library-entrypoints:\n") {
		t.Error("action.yml declares no library-entrypoints input")
	}
}
