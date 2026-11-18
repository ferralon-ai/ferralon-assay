package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

func applyAll(opts []pipeline.AssessOption) pipeline.AssessConfig {
	cfg := pipeline.AssessConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// TestBaselineAssessOptions pins that baseline takes the subject's Go toolchain and the
// subject-toolchain reachability setting, as the run path does.
func TestBaselineAssessOptions(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	t.Setenv(envCIGoVersion, "")
	tests := []struct {
		name      string
		reach     string
		args      []string
		envGo     string
		wantGo    string
		wantReach bool
	}{
		{name: "declared by flag", reach: "1", args: []string{"-subject-go-version", "1.22.5"}, wantGo: "1.22.5", wantReach: true},
		{name: "declared by env", envGo: "1.25.14", wantGo: "1.25.14", wantReach: true},
		{name: "nothing stated", wantReach: true},
		{name: "reachability turned off", reach: "false", args: []string{"-subject-go-version", "1.22.5"}, wantGo: "1.22.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envSubjectToolchainReach, tt.reach)
			t.Setenv(envSubjectGoVersion, tt.envGo)
			pluginApplied := false
			opts, err := runFlagsFor(t, tt.args...).baselineAssessOptions(func(*pipeline.AssessConfig) { pluginApplied = true }, "go")
			if err != nil {
				t.Fatalf("baselineAssessOptions: %v", err)
			}
			cfg := applyAll(opts)
			if !pluginApplied {
				t.Error("plugin option dropped")
			}
			if cfg.SubjectGoVersion != tt.wantGo {
				t.Errorf("SubjectGoVersion = %q, want %q", cfg.SubjectGoVersion, tt.wantGo)
			}
			if cfg.SubjectToolchainReachability != tt.wantReach {
				t.Errorf("SubjectToolchainReachability = %v, want %v", cfg.SubjectToolchainReachability, tt.wantReach)
			}
		})
	}
}

// TestRunAssessOptions pins the run path's option list: every subject statement the flags and env
// carry reaches AssessConfig, after the plugin, and a corpus error stops assembly.
func TestRunAssessOptions(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	t.Run("all subject inputs", func(t *testing.T) {
		t.Setenv(envCIGoVersion, "")
		t.Setenv(envSubjectToolchainReach, "1")
		f := runFlagsFor(t, "-subject-go-version", "1.22.5")
		pluginApplied := false
		opts, err := f.runAssessOptions(func(*pipeline.AssessConfig) { pluginApplied = true }, "go")
		if err != nil {
			t.Fatalf("runAssessOptions: %v", err)
		}
		cfg := applyAll(opts)
		if !pluginApplied {
			t.Error("plugin option dropped")
		}
		if cfg.SubjectGoVersion != "1.22.5" {
			t.Errorf("SubjectGoVersion = %q, want 1.22.5", cfg.SubjectGoVersion)
		}
		if !cfg.SubjectToolchainReachability {
			t.Error("subject-toolchain reachability gate dropped")
		}
	})
	t.Run("nothing stated", func(t *testing.T) {
		t.Setenv(envSubjectGoVersion, "")
		t.Setenv(envCIGoVersion, "")
		t.Setenv(envSubjectToolchainReach, "")
		opts, err := runFlagsFor(t).runAssessOptions(func(*pipeline.AssessConfig) {}, "go")
		if err != nil {
			t.Fatalf("runAssessOptions: %v", err)
		}
		cfg := applyAll(opts)
		if cfg.SubjectGoVersion != "" {
			t.Errorf("unexpected subject statement: %+v", cfg)
		}
		if !cfg.SubjectToolchainReachability {
			t.Error("subject-toolchain reachability is not on by default")
		}
	})
	t.Run("subject-toolchain reachability turned off", func(t *testing.T) {
		t.Setenv(envSubjectToolchainReach, "false")
		opts, err := runFlagsFor(t).runAssessOptions(func(*pipeline.AssessConfig) {}, "go")
		if err != nil {
			t.Fatalf("runAssessOptions: %v", err)
		}
		if applyAll(opts).SubjectToolchainReachability {
			t.Error("subject-toolchain reachability stayed on after being turned off")
		}
	})
	t.Run("corpus error", func(t *testing.T) {
		if _, err := runFlagsFor(t, "-advisory-corpus-policy", "full").runAssessOptions(func(*pipeline.AssessConfig) {}, "go"); err == nil {
			t.Error("want the corpus policy error")
		}
	})
}
