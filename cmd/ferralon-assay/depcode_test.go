package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestDependencyCodeOption(t *testing.T) {
	tests := []struct {
		name, mode, cache, envMode string
		wantSource                 string // the dependency_code source the report will carry
		noHome, wantErr            bool
	}{
		{name: "default fetch", wantSource: report.DependencyCodeSourceFetch},
		{name: "default fetch with cache", cache: t.TempDir(), wantSource: report.DependencyCodeSourceFetch},
		{name: "explicit off", mode: "off", wantSource: report.DependencyCodeSourceOff},
		{name: "fetch with cache", mode: "fetch", cache: t.TempDir(), wantSource: report.DependencyCodeSourceFetch},
		{name: "fetch default cache", mode: "fetch", wantSource: report.DependencyCodeSourceFetch},
		{name: "offline with cache", mode: "offline", cache: t.TempDir(), wantSource: report.DependencyCodeSourceOffline},
		{name: "offline without cache", mode: "offline", wantErr: true},
		{name: "typo", mode: "fecth", wantErr: true},
		{name: "env enables offline", envMode: "offline", cache: t.TempDir(), wantSource: report.DependencyCodeSourceOffline},
		{name: "env off", envMode: "off", wantSource: report.DependencyCodeSourceOff},
		{name: "flag off beats env", mode: "off", envMode: "fetch", wantSource: report.DependencyCodeSourceOff},
		{name: "default fetch with no user cache directory", noHome: true, wantSource: report.DependencyCodeSourceFetch},
		{name: "explicit fetch with no user cache directory", mode: "fetch", noHome: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envDependencyCode, tt.envMode)
			t.Setenv(envDependencyCache, "")
			if tt.noHome {
				t.Setenv("HOME", "")
				t.Setenv("XDG_CACHE_HOME", "")
			}
			mode, cache, npmrcEnv, timeout := tt.mode, tt.cache, "", ""
			f := &runFlags{depCode: &mode, depCache: &cache, depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
			opt, err := f.dependencyCodeOption()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if wantOpt := tt.wantSource != report.DependencyCodeSourceOff; (opt != nil) != wantOpt {
				t.Fatalf("option set = %v, want %v", opt != nil, wantOpt)
			}
			if f.depRun == nil || f.depRun.source != tt.wantSource {
				t.Fatalf("depRun = %+v, want source %q", f.depRun, tt.wantSource)
			}
		})
	}
}

// The report stamp and exit status for one JS run: a run that read normally carries only its
// source; a run that fell back carries the cause and the named did_not_run reason and still
// exits as off does; a non-JS run carries nothing.
func TestDependencyCodeStampAndExit(t *testing.T) {
	cause := &pipeline.DependencyCodeCause{Kind: pipeline.UnreadNotServed, Detail: "pkg:npm/qs@6.5.2"}
	tests := []struct {
		name, lang string
		fell       *pipeline.DependencyCodeCause
		wantField  bool
	}{
		{name: "read", lang: "js", wantField: true},
		{name: "fell back", lang: "js", fell: cause, wantField: true},
		{name: "not js", lang: "go", fell: cause},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := &depCodeRun{source: report.DependencyCodeSourceFetch}
			if tt.fell != nil {
				run.observe(pipeline.DependencyAcquisitionResult{Fallback: tt.fell})
			}
			deps := run.forLanguage(tt.lang)
			rep := &report.Report{}
			deps.stamp(rep)
			if err := deps.err(); err != nil {
				t.Fatalf("err = %v: a fetch failure exits as off does", err)
			}
			if !tt.wantField {
				if rep.DependencyCode != nil || len(rep.Partiality) != 0 {
					t.Fatalf("non-JS run stamped %+v %+v", rep.DependencyCode, rep.Partiality)
				}
				return
			}
			if rep.DependencyCode == nil || rep.DependencyCode.Source != report.DependencyCodeSourceFetch {
				t.Fatalf("dependency_code = %+v", rep.DependencyCode)
			}
			if tt.fell == nil {
				if rep.DependencyCode.Cause != nil || len(rep.Partiality) != 0 {
					t.Fatalf("a run that read stamped %+v %+v", rep.DependencyCode.Cause, rep.Partiality)
				}
				return
			}
			want := report.PartialityNote{Reason: report.PartialReasonDependencyCodeUnavailable, Ecosystem: "npm",
				Class: report.PartialityDidNotRun, Detail: "not_served: pkg:npm/qs@6.5.2"}
			if c := rep.DependencyCode.Cause; c == nil || c.Kind != cause.Kind || c.Detail != cause.Detail {
				t.Fatalf("cause = %+v", rep.DependencyCode.Cause)
			}
			if len(rep.Partiality) != 1 || !reflect.DeepEqual(rep.Partiality[0], want) {
				t.Fatalf("partiality = %+v, want [%+v]", rep.Partiality, want)
			}
		})
	}
}

func TestDependencyAcquisitionConfigEnvAndTimeout(t *testing.T) {
	tests := []struct {
		name, npmrcEnv, envNPMRCEnv, timeout string
		wantAllow                            []string
		wantTimeout                          time.Duration
		wantErr                              bool
	}{
		{name: "defaults"},
		{name: "operator-added names", npmrcEnv: "CORP_TOKEN, ART_TOKEN", wantAllow: []string{"CORP_TOKEN", "ART_TOKEN"}},
		{name: "names from the environment", envNPMRCEnv: "CORP_TOKEN", wantAllow: []string{"CORP_TOKEN"}},
		{name: "malformed name", npmrcEnv: "CORP-TOKEN", wantErr: true},
		{name: "timeout", timeout: "90s", wantTimeout: 90 * time.Second},
		{name: "malformed timeout", timeout: "soon", wantErr: true},
		{name: "non-positive timeout", timeout: "0s", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envDependencyCode, "")
			t.Setenv(envDependencyCache, "")
			t.Setenv(envDependencyNPMRCEnv, tt.envNPMRCEnv)
			t.Setenv(envDependencyTimeout, "")
			mode, cache, npmrcEnv, timeout := "offline", t.TempDir(), tt.npmrcEnv, tt.timeout
			f := &runFlags{depCode: &mode, depCache: &cache, depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
			cfg, err := f.dependencyAcquisitionConfig()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !slices.Equal(cfg.AllowEnv, tt.wantAllow) || cfg.Timeout != tt.wantTimeout {
				t.Fatalf("AllowEnv %q Timeout %v, want %q %v", cfg.AllowEnv, cfg.Timeout, tt.wantAllow, tt.wantTimeout)
			}
		})
	}
}

// The Action reaches -dependency-code only through the env names depcode.go reads, and its input
// must default to empty so the scanner's own default applies. The cache it restores must be the
// directory it hands the scanner, or every run fetches from cold.
func TestActionWiresDependencyCode(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := string(body)
	const cacheDir = "${{ runner.temp }}/ferralon-assay-deps"
	for _, want := range []string{
		envDependencyCode + ": ${{ inputs.dependency-code }}",
		envDependencyCache + ": ${{ inputs.dependency-code != 'off' && format('{0}/ferralon-assay-deps', runner.temp) || '' }}",
		"path: " + cacheDir,
	} {
		if !strings.Contains(yml, want) {
			t.Errorf("action.yml lacks %q", want)
		}
	}
	in := yml[strings.Index(yml, "\n  dependency-code:\n"):]
	in = in[:strings.Index(in, "\n  issue:\n")]
	if !strings.Contains(in, `default: ""`) {
		t.Errorf("dependency-code input does not default to empty:\n%s", in)
	}
}
