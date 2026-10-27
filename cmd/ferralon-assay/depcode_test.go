package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

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
			t.Setenv(envDependencyUncredCache, "")
			t.Setenv(envDependencyUncredCache, "")
			if tt.noHome {
				t.Setenv("HOME", "")
				t.Setenv("XDG_CACHE_HOME", "")
				t.Setenv("TMPDIR", t.TempDir())
			}
			mode, cache, npmrcEnv, timeout := tt.mode, tt.cache, "", ""
			f := &runFlags{depCode: &mode, depCache: &cache, depUncredCache: new(string), depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
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

// With no user cache directory the default fetch gets a private per-run cache, never a shared
// temp path another local user could seed.
func TestDependencyCodeNoHomeCacheIsPerRun(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("TMPDIR", tmp)
	t.Setenv(envDependencyCode, "")
	t.Setenv(envDependencyCache, "")
	t.Setenv(envDependencyUncredCache, "")
	dirs := map[string]bool{}
	for range 2 {
		mode, cache, npmrcEnv, timeout := "", "", "", ""
		f := &runFlags{depCode: &mode, depCache: &cache, depUncredCache: new(string), depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
		cfg, err := f.dependencyAcquisitionConfig()
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(cfg.CacheDir) != filepath.Clean(tmp) {
			t.Fatalf("cache dir %q is not directly under TMPDIR %q", cfg.CacheDir, tmp)
		}
		fi, err := os.Stat(cfg.CacheDir)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Fatalf("cache dir mode = %o, want 700", perm)
		}
		dirs[cfg.CacheDir] = true
	}
	if len(dirs) != 2 {
		t.Fatalf("two runs shared a cache dir: %v", dirs)
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
			t.Setenv(envDependencyUncredCache, "")
			t.Setenv(envDependencyUncredCache, "")
			t.Setenv(envDependencyNPMRCEnv, tt.envNPMRCEnv)
			t.Setenv(envDependencyTimeout, "")
			mode, cache, npmrcEnv, timeout := "offline", t.TempDir(), tt.npmrcEnv, tt.timeout
			f := &runFlags{depCode: &mode, depCache: &cache, depUncredCache: new(string), depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
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

// actionStep returns the step with id in action.yml's composite steps.
func actionStep(t *testing.T, id string) (run string, with map[string]string, cond string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				ID   string            `yaml:"id"`
				Name string            `yaml:"name"`
				If   string            `yaml:"if"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(body, &action); err != nil {
		t.Fatal(err)
	}
	for _, st := range action.Runs.Steps {
		if st.ID == id || st.Name == id {
			return st.Run, st.With, st.If
		}
	}
	t.Fatalf("action.yml has no step %q", id)
	return "", nil, ""
}

// The Action reaches -dependency-code only through the env names depcode.go reads, and its input
// must default to empty so the scanner's own default applies. The directory the cache step
// persists must be the one the scanner is told holds only what the scope allows.
func TestActionWiresDependencyCode(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yml := string(body)
	for _, want := range []string{
		envDependencyCode + ": ${{ inputs.dependency-code }}",
		envDependencyCache + ": ${{ inputs.dependency-code != 'off' && steps.depcache.outputs.cache-dir || '' }}",
		envDependencyUncredCache + ": ${{ inputs.dependency-code != 'off' && steps.depcache.outputs.uncredentialed-dir || '' }}",
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

	_, with, cond := actionStep(t, "Restore the dependency code cache")
	const segment = "ferralon-assay-deps-v1-${{ steps.depcache.outputs.scope }}-${{ runner.os }}-"
	if !strings.HasPrefix(with["key"], segment) {
		t.Errorf("cache key %q does not start with %q", with["key"], segment)
	}
	for _, rk := range strings.Split(strings.TrimSpace(with["restore-keys"]), "\n") {
		if strings.TrimSpace(rk) != segment {
			t.Errorf("restore key %q is not %q", rk, segment)
		}
	}
	if !strings.Contains(cond, "steps.depcache.outputs.scope != 'none'") {
		t.Errorf("cache step runs whatever the scope: %q", cond)
	}
	if with["path"] != "${{ runner.temp }}/ferralon-assay-deps" {
		t.Fatalf("cache path = %q", with["path"])
	}
}

// The depcache step maps persist-dependency-cache and the event's repository visibility onto
// the scope and directories the scanner and the cache step read. It runs here as the Action runs
// it; the persisted directory is the cache step's path with runner.temp resolved.
func TestActionDependencyCacheScope(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	script, _, _ := actionStep(t, "depcache")
	_, with, _ := actionStep(t, "Restore the dependency code cache")
	tmp := t.TempDir()
	persisted := strings.ReplaceAll(with["path"], "${{ runner.temp }}", tmp)
	run := filepath.Join(tmp, "ferralon-assay-deps-run")
	tests := []struct {
		name, input, private, visibility string
		scope, cacheDir, uncredDir       string
		wantErr                          bool
	}{
		{name: "auto on a private repository persists everything", input: "auto", private: "true", visibility: "private", scope: "all", cacheDir: persisted},
		{name: "auto on an internal repository persists everything", input: "auto", private: "true", visibility: "internal", scope: "all", cacheDir: persisted},
		{name: "auto on internal visibility alone persists everything", input: "auto", visibility: "internal", scope: "all", cacheDir: persisted},
		{name: "auto on a public repository persists only uncredentialed tarballs", input: "auto", private: "false", visibility: "public", scope: "uncredentialed", cacheDir: run, uncredDir: persisted},
		{name: "auto with no repository in the payload counts as public", input: "auto", scope: "uncredentialed", cacheDir: run, uncredDir: persisted},
		{name: "always on a public repository persists everything", input: "always", private: "false", visibility: "public", scope: "all", cacheDir: persisted},
		{name: "never on a private repository persists nothing", input: "never", private: "true", visibility: "private", scope: "none", cacheDir: persisted},
		{name: "never on a public repository persists nothing", input: "never", private: "false", scope: "none", cacheDir: persisted},
		{name: "unknown value fails", input: "sometimes", wantErr: true},
		{name: "empty value fails", input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "output")
			if err := os.WriteFile(out, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-e", "-c", script)
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"RUNNER_TEMP=" + tmp,
				"GITHUB_OUTPUT=" + out,
				"PERSIST_DEPENDENCY_CACHE=" + tt.input,
				"REPO_PRIVATE=" + tt.private,
				"REPO_VISIBILITY=" + tt.visibility,
			}
			if b, err := cmd.CombinedOutput(); (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v: %s", err, tt.wantErr, b)
			}
			if tt.wantErr {
				return
			}
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				k, v, _ := strings.Cut(line, "=")
				got[k] = v
			}
			if got["scope"] != tt.scope || got["cache-dir"] != tt.cacheDir || got["uncredentialed-dir"] != tt.uncredDir {
				t.Fatalf("outputs = %v, want scope %q cache-dir %q uncredentialed-dir %q", got, tt.scope, tt.cacheDir, tt.uncredDir)
			}
			// Only an 'all' scope may hand the scanner the persisted directory as the one it
			// writes credentialed tarballs to.
			if got["scope"] == "uncredentialed" && got["cache-dir"] == persisted {
				t.Fatal("uncredentialed scope writes credentialed tarballs to the persisted directory")
			}
			// The scanner resolves those outputs, as the run step passes them, into the split the
			// pipeline routes on.
			t.Setenv(envDependencyCode, "")
			t.Setenv(envDependencyCache, got["cache-dir"])
			t.Setenv(envDependencyUncredCache, got["uncredentialed-dir"])
			t.Setenv(envDependencyNPMRCEnv, "")
			t.Setenv(envDependencyTimeout, "")
			mode, c, u, npmrcEnv, timeout := "", "", "", "", ""
			f := &runFlags{depCode: &mode, depCache: &c, depUncredCache: &u, depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
			cfg, err := f.dependencyAcquisitionConfig()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CacheDir != tt.cacheDir || cfg.UncredentialedDir != tt.uncredDir {
				t.Fatalf("scanner CacheDir %q UncredentialedDir %q, want %q %q", cfg.CacheDir, cfg.UncredentialedDir, tt.cacheDir, tt.uncredDir)
			}
		})
	}
}

// -dependency-uncredentialed-cache splits the cache only when set, and never onto a directory
// that overlaps -dependency-cache: a persisted uncredentialed cache must not carry the other.
func TestDependencyUncredentialedCacheOption(t *testing.T) {
	base := t.TempDir()
	cache := filepath.Join(base, "cache")
	tests := []struct {
		name, mode, flag, env string
		want                  string // UncredentialedDir; "" for one directory
		wantErr               bool
	}{
		{name: "unset keeps one directory", mode: "fetch"},
		{name: "flag splits", mode: "fetch", flag: filepath.Join(base, "shared"), want: filepath.Join(base, "shared")},
		{name: "environment splits", mode: "fetch", env: filepath.Join(base, "shared"), want: filepath.Join(base, "shared")},
		{name: "flag overrides environment", mode: "fetch", flag: filepath.Join(base, "a"), env: filepath.Join(base, "b"), want: filepath.Join(base, "a")},
		{name: "offline splits", mode: "offline", flag: filepath.Join(base, "shared"), want: filepath.Join(base, "shared")},
		{name: "same directory", mode: "fetch", flag: cache, wantErr: true},
		{name: "inside the cache", mode: "fetch", flag: filepath.Join(cache, "shared"), wantErr: true},
		{name: "holding the cache", mode: "fetch", flag: base, wantErr: true},
		{name: "sibling with a shared prefix", mode: "fetch", flag: cache + "-shared", want: cache + "-shared"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envDependencyCode, "")
			t.Setenv(envDependencyCache, "")
			t.Setenv(envDependencyUncredCache, tt.env)
			t.Setenv(envDependencyNPMRCEnv, "")
			t.Setenv(envDependencyTimeout, "")
			mode, c, flag, npmrcEnv, timeout := tt.mode, cache, tt.flag, "", ""
			f := &runFlags{depCode: &mode, depCache: &c, depUncredCache: &flag, depNPMRCEnv: &npmrcEnv, depTimeout: &timeout}
			cfg, err := f.dependencyAcquisitionConfig()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if cfg.CacheDir != cache || cfg.UncredentialedDir != tt.want {
				t.Fatalf("CacheDir %q UncredentialedDir %q, want %q %q", cfg.CacheDir, cfg.UncredentialedDir, cache, tt.want)
			}
		})
	}
}
