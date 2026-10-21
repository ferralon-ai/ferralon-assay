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

// TestBaselineAssessOptions_KeepsTheSubjectGoToolchainOut pins that baseline keeps the subject Go
// toolchain and its reachability gate out of its options.
func TestBaselineAssessOptions_KeepsTheSubjectGoToolchainOut(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	t.Setenv(envCIGoVersion, "")
	t.Setenv(envSubjectToolchainReach, "1")
	f := runFlagsFor(t, "-subject-go-version", "1.22.5")
	pluginApplied := false
	opts, err := f.baselineAssessOptions(func(*pipeline.AssessConfig) { pluginApplied = true })
	if err != nil {
		t.Fatalf("baselineAssessOptions: %v", err)
	}
	cfg := applyAll(opts)
	if !pluginApplied {
		t.Error("plugin option dropped")
	}
	if cfg.SubjectGoVersion != "" {
		t.Errorf("baseline took the subject Go toolchain %q", cfg.SubjectGoVersion)
	}
	if cfg.SubjectToolchainReachability {
		t.Error("baseline took the run path's subject-toolchain reachability gate")
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
		opts, err := f.runAssessOptions(func(*pipeline.AssessConfig) { pluginApplied = true })
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
		opts, err := runFlagsFor(t).runAssessOptions(func(*pipeline.AssessConfig) {})
		if err != nil {
			t.Fatalf("runAssessOptions: %v", err)
		}
		if cfg := applyAll(opts); cfg.SubjectGoVersion != "" || cfg.SubjectToolchainReachability {
			t.Errorf("unexpected subject statement: %+v", cfg)
		}
	})
	t.Run("corpus error", func(t *testing.T) {
		if _, err := runFlagsFor(t, "-advisory-corpus-policy", "full").runAssessOptions(func(*pipeline.AssessConfig) {}); err == nil {
			t.Error("want the corpus policy error")
		}
	})
}
