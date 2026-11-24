package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
)

// TestEntrypointsOptions: -entrypoints, its env, the alias -library-entrypoints and its env, in every
// combination, on the baseline and the run path. The flag beats its env; the two inputs reconcile
// when they state the same go library scope and fail the run, naming both, when they do not.
func TestEntrypointsOptions(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	paths := []struct {
		name  string
		build func(*runFlags, string) ([]pipeline.AssessOption, error)
	}{
		{"baseline", func(f *runFlags, lang string) ([]pipeline.AssessOption, error) {
			return f.baselineAssessOptions(func(*pipeline.AssessConfig) {}, lang)
		}},
		{"run", func(f *runFlags, lang string) ([]pipeline.AssessOption, error) {
			return f.runAssessOptions(func(*pipeline.AssessConfig) {}, lang)
		}},
	}
	none := &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsNone}
	api := &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsPaths, Include: []string{"pkg/api"}}
	apiX := &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsPaths, Include: []string{"pkg/api", "pkg/x"}}
	auto := &plugin.LibraryEntrypoints{Mode: plugin.LibraryEntrypointsAuto}
	cases := []struct {
		name        string
		lang        string
		env, libEnv string
		args        []string
		want        *plugin.LibraryEntrypoints
		wantStated  bool // the parsed input reaches AssessConfig.Entrypoints
		wantErr     []string
	}{
		{name: "nothing stated", lang: "go"},
		{name: "entrypoints env", lang: "go", env: "go:library=none", want: none, wantStated: true},
		{name: "entrypoints flag over its env", lang: "go", env: "go:library=none", args: []string{"-entrypoints", "go:library=pkg/api"}, want: api, wantStated: true},
		{name: "entrypoints bare auto", lang: "go", env: "auto", wantStated: true},
		{name: "alias env", lang: "go", libEnv: "none", want: none},
		{name: "alias flag over its env", lang: "go", libEnv: "none", args: []string{"-library-entrypoints", "pkg/api"}, want: api},
		{name: "alias at the Action's default", lang: "go", libEnv: "auto", want: auto},
		{name: "alias at its default beside entrypoints", lang: "go", env: "go:library=none", libEnv: "auto", want: none, wantStated: true},
		{name: "alias stated beside entrypoints bare auto", lang: "go", env: "auto", libEnv: "none", want: none, wantStated: true},
		{name: "alias stated beside an entrypoints go lane that states no library scope", lang: "go", env: "go:auto", libEnv: "none", want: none, wantStated: true},
		{name: "agree: identical", lang: "go", env: "go:library=none", libEnv: "none", want: none, wantStated: true},
		{name: "agree: same paths in another order", lang: "go", env: "go:library=pkg/x,go:library=pkg/api", libEnv: "pkg/api, pkg/x", want: apiX, wantStated: true},
		{name: "agree: flag and env mix", lang: "go", env: "go:library=pkg/api", libEnv: "none", args: []string{"-library-entrypoints", "pkg/api"}, want: api, wantStated: true},
		{name: "conflict: none against paths", lang: "go", env: "go:library=none", libEnv: "pkg/api",
			wantErr: []string{`"go:library=none"`, `"pkg/api"`, "different go library entry points"}},
		{name: "conflict: paths against none", lang: "go", env: "go:library=pkg/api", libEnv: "none", args: []string{"-library-entrypoints", "none"},
			wantErr: []string{"different go library entry points"}},
		{name: "conflict: include against exclude", lang: "go", env: "go:library=pkg/api", libEnv: "!pkg/api", wantErr: []string{"different go library entry points"}},
		{name: "conflict: auto plus a path against the path alone", lang: "go", env: "go:library=auto,go:library=pkg/api", libEnv: "pkg/api", wantErr: []string{"different go library entry points"}},
		{name: "entrypoints that does not parse", lang: "go", env: "pkg/api", wantErr: []string{"entrypoints:", "must name its lane"}},
		{name: "entrypoints unknown lane", lang: "go", env: "rust:none", wantErr: []string{`unknown lane "rust"`}},
		{name: "entrypoints that does not parse, beside a good alias", lang: "go", env: "go:../x", libEnv: "none", wantErr: []string{"leaves the repository root"}},
		{name: "alias that does not parse, beside good entrypoints", lang: "go", env: "go:library=none", libEnv: "none,../x", wantErr: []string{"library-entrypoints:"}},
		{name: "go main", lang: "go", env: "go:main=none", wantErr: []string{"lane go does not accept entry-point overrides yet"}},
		{name: "java clause on a java scan", lang: "java", env: "java:main=class:com.acme.Main", wantErr: []string{"lane java does not accept entry-point overrides yet"}},
		{name: "kotlin", lang: "kotlin", env: "!kotlin:handler=src/A.kt", wantErr: []string{"lane kotlin does not accept entry-point overrides yet"}},
		{name: "js module", lang: "js", env: "js:module=none", wantErr: []string{"js:module cannot be overridden"}},
		{name: "js bin allow", lang: "js", env: "js:bin=bin:x", wantErr: []string{"not accepted yet for js"}},
		{name: "js bin removal", lang: "js", env: "!js:bin=bin:storybook", wantStated: true},
		{name: "python", lang: "python", env: "python:handler=app/x.py", wantErr: []string{"lane python does not accept entry-point overrides yet"}},
		{name: "dotnet", lang: "dotnet", env: "dotnet:runtime=none", wantErr: []string{"lane dotnet does not accept entry-point overrides yet"}},
		{name: "a clause for a lane the scan does not run", lang: "go", env: "js:none", wantErr: []string{"lane js cannot honour this clause"}},
		{name: "js lane auto on a js scan", lang: "js", env: "js:auto", wantStated: true},
		{name: "java kind auto", lang: "java", env: "java:main=auto", wantStated: true},
		{name: "js lane auto with a deny", lang: "js", env: "js:auto,!js:bin:x", wantStated: true},
		{name: "bare none on a go scan", lang: "go", env: "none", wantErr: []string{"write go:library=none"}},
		{name: "bare none on a java scan", lang: "java", env: "none", wantErr: []string{"lane java does not accept entry-point overrides yet"}},
		{name: "bare none on a scan no lane runs", lang: "cfamily", env: "none", wantStated: true},
		{name: "bare auto on a java scan", lang: "java", env: "auto", wantStated: true},
		{name: "go library clause on a java scan is accepted", lang: "java", env: "go:library=none", want: none, wantStated: true},
	}
	for _, p := range paths {
		for _, tc := range cases {
			t.Run(p.name+"/"+tc.name, func(t *testing.T) {
				t.Setenv(envEntrypoints, tc.env)
				t.Setenv(envLibraryEntrypoints, tc.libEnv)
				opts, err := p.build(runFlagsFor(t, tc.args...), tc.lang)
				if len(tc.wantErr) > 0 {
					if err == nil {
						t.Fatalf("no error, want one containing %q", tc.wantErr)
					}
					for _, w := range tc.wantErr {
						if !strings.Contains(err.Error(), w) {
							t.Errorf("err = %q, want containing %q", err, w)
						}
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				cfg := applyAll(opts)
				if !reflect.DeepEqual(cfg.LibraryEntrypoints, tc.want) {
					t.Errorf("LibraryEntrypoints = %+v, want %+v", cfg.LibraryEntrypoints, tc.want)
				}
				if stated := len(cfg.Entrypoints) > 0; stated != tc.wantStated {
					t.Errorf("Entrypoints = %+v, want stated %v", cfg.Entrypoints, tc.wantStated)
				}
			})
		}
	}
}

// TestEntrypointsOptions_AliasEquivalence: the alias and the clauses it stands for hand the pipeline
// the same go library statement.
func TestEntrypointsOptions_AliasEquivalence(t *testing.T) {
	for _, in := range []string{"none", "pkg/api, pkg/client", "!internal/tools", "auto,cmd/x"} {
		t.Run(in, func(t *testing.T) {
			t.Setenv(envEntrypoints, "")
			t.Setenv(envLibraryEntrypoints, in)
			viaAlias, err := runFlagsFor(t).entrypointsOptions("go")
			if err != nil {
				t.Fatal(err)
			}
			le, err := plugin.ParseLibraryEntrypoints(in)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(envLibraryEntrypoints, "")
			t.Setenv(envEntrypoints, plugin.EntryOverrideForLibraryEntrypoints(le).Input)
			viaClauses, err := runFlagsFor(t).entrypointsOptions("go")
			if err != nil {
				t.Fatal(err)
			}
			if a, c := applyAll(viaAlias).LibraryEntrypoints, applyAll(viaClauses).LibraryEntrypoints; a == nil || !reflect.DeepEqual(a, c) {
				t.Errorf("alias gives %+v, clauses give %+v", a, c)
			}
		})
	}
}

// TestActionExportsEntrypoints: the Action input reaches the scanner only if action.yml exports
// exactly the env name run.go reads, through the step env, and declares the input.
func TestActionExportsEntrypoints(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := string(body)
	if !strings.Contains(yml, envEntrypoints+": ${{ inputs.entrypoints }}") {
		t.Errorf("action.yml does not export %s from the entrypoints input", envEntrypoints)
	}
	if !strings.Contains(yml, "\n  entrypoints:\n") {
		t.Error("action.yml declares no entrypoints input")
	}
}

// TestEntrypointsCheckedBeforeAcquisition: a malformed value, a clause no lane can honour, and two
// inputs that disagree stop every run mode before the target is touched. The target does not exist,
// so an acquisition that ran first would fail with its own error, not the entry-point one.
func TestEntrypointsCheckedBeforeAcquisition(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	missing := filepath.Join(t.TempDir(), "no-such-target")
	cases := []struct {
		name        string
		env, libEnv string
		wantErr     string
	}{
		{name: "malformed", env: "pkg/api", wantErr: "must name its lane"},
		{name: "unsupported lane clause", env: "java:main=class:com.acme.Main", wantErr: "lane java does not accept entry-point overrides yet"},
		{name: "go main", env: "go:main=none", wantErr: "lane go does not accept entry-point overrides yet"},
		{name: "malformed alias", libEnv: "none,../x", wantErr: "library-entrypoints:"},
		{name: "inputs disagree", env: "go:library=none", libEnv: "pkg/api", wantErr: "different go library entry points"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envEntrypoints, tc.env)
			t.Setenv(envLibraryEntrypoints, tc.libEnv)
			if _, err := runFlagsFor(t, "-target", missing).resolve(context.Background(), true); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("resolve err = %v, want containing %q", err, tc.wantErr)
			}
			if err := runBaseline([]string{"-target", missing}); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("baseline err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("a good value reaches acquisition", func(t *testing.T) {
		t.Setenv(envEntrypoints, "go:library=none")
		t.Setenv(envLibraryEntrypoints, "")
		_, err := runFlagsFor(t, "-target", missing).resolve(context.Background(), true)
		if err == nil || strings.Contains(err.Error(), "entrypoints") {
			t.Errorf("resolve err = %v, want an acquisition error", err)
		}
	})
}

// TestEntrypointsOnAnalyzerMissing: a tree whose language has no released analyzer still rejects a
// bad input, in every run mode, and publishes no Report. A bare "none" depends on the detected
// language, so it is checked once the language is known; a language no lane covers takes it as a
// no-op and the run publishes its did-not-run Report as before.
func TestEntrypointsOnAnalyzerMissing(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "main.c"), "int main(void) { return 0; }\n")
	t.Setenv("PATH", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv(envLinkToConsole, "")
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	args := os.Args
	t.Cleanup(func() { os.Args = args })

	cases := []struct {
		name        string
		env, libEnv string
		wantCode    int
	}{
		{name: "malformed", env: "pkg/api", wantCode: 1},
		{name: "unsupported lane clause", env: "js:module=none", wantCode: 1},
		{name: "inputs disagree", env: "go:library=none", libEnv: "pkg/api", wantCode: 1},
		{name: "bare none is a no-op on this tree", env: "none", wantCode: 0},
		{name: "a good go clause", env: "go:library=none", wantCode: 0},
	}
	for _, mode := range []string{"baseline", "pr-inherit", "cve-watch"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				t.Setenv(envEntrypoints, tc.env)
				t.Setenv(envLibraryEntrypoints, tc.libEnv)
				t.Setenv(envGitHubOut, filepath.Join(t.TempDir(), "github_output"))
				out := t.TempDir()
				os.Args = []string{"ferralon-assay", mode, "-target", src, "-out", out, "-revision", "main", "-commit", "abc123", "-git-dir", t.TempDir()}
				code := run()
				if (code == 0) != (tc.wantCode == 0) {
					t.Fatalf("exit code = %d, want %d", code, tc.wantCode)
				}
				published, err := os.ReadFile(filepath.Join(out, resultsink.FileReportJSON))
				if tc.wantCode != 0 && err == nil {
					t.Errorf("a Report was published for a rejected input: %s", published)
				}
				if tc.wantCode == 0 && err != nil {
					t.Errorf("no Report published: %v", err)
				}
			})
		}
	}
}
