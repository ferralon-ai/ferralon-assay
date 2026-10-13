package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// subjectMavenProfilesEnv is envSubjectMavenProfiles spelled out, so a rename of either side goes red.
const subjectMavenProfilesEnv = "ASSAY_SUBJECT_MAVEN_PROFILES"

func TestSubjectMavenProfilesOption(t *testing.T) {
	tests := []struct {
		name, flag, env, want string
	}{
		{"neither set", "", "", ""},
		{"flag", "release,!docs", "", "release,!docs"},
		{"env", "", "ci", "ci"},
		{"flag over env", "release", "ci", "release"},
		{"blank flag falls back to env", "  ", "ci", "ci"},
		{"none selected", ",", "", ","},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args []string
			if tt.flag != "" {
				args = []string{"-subject-maven-profiles", tt.flag}
			}
			f := runFlagsFor(t, args...)
			t.Setenv(subjectMavenProfilesEnv, tt.env)
			opt := f.subjectMavenProfilesOption()
			if tt.want == "" {
				if opt != nil {
					t.Fatal("want no option")
				}
				return
			}
			if opt == nil {
				t.Fatalf("want an option carrying %q", tt.want)
			}
			cfg := pipeline.AssessConfig{}
			opt(&cfg)
			if cfg.SubjectMavenProfiles != tt.want {
				t.Errorf("SubjectMavenProfiles = %q, want %q", cfg.SubjectMavenProfiles, tt.want)
			}
		})
	}
}

func applyAll(opts []pipeline.AssessOption) pipeline.AssessConfig {
	cfg := pipeline.AssessConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

func TestBaselineAssessOptions_CarriesSubjectMavenProfiles(t *testing.T) {
	t.Setenv(subjectJavaEnv, "")
	t.Setenv(subjectMavenProfilesEnv, "")
	f := runFlagsFor(t, "-subject-maven-profiles", "release")
	opts, err := f.baselineAssessOptions(func(*pipeline.AssessConfig) {})
	if err != nil {
		t.Fatalf("baselineAssessOptions: %v", err)
	}
	if got := applyAll(opts).SubjectMavenProfiles; got != "release" {
		t.Errorf("SubjectMavenProfiles = %q, want release", got)
	}
}

// TestBaselineAssessOptions_CarriesTheSharedSubjectConditions pins baseline to the Java version
// and Maven selection, and keeps the subject Go toolchain and its reachability gate out of it.
func TestBaselineAssessOptions_CarriesTheSharedSubjectConditions(t *testing.T) {
	t.Setenv(envAdvisoryCorpusDir, "")
	t.Setenv(envAdvisoryCorpusPolicy, "")
	t.Setenv(subjectJavaEnv, "")
	t.Setenv(subjectMavenProfilesEnv, "")
	t.Setenv(envCIGoVersion, "")
	t.Setenv(envSubjectToolchainReach, "1")
	f := runFlagsFor(t, "-subject-java-version", "17.0.12", "-subject-maven-profiles", "release,!docs", "-subject-go-version", "1.22.5")
	opts, err := f.baselineAssessOptions(func(*pipeline.AssessConfig) {})
	if err != nil {
		t.Fatalf("baselineAssessOptions: %v", err)
	}
	cfg := applyAll(opts)
	if cfg.SubjectJavaVersion != "17.0.12" || cfg.SubjectMavenProfiles != "release,!docs" {
		t.Errorf("subject conditions = java %q, profiles %q; want 17.0.12, release,!docs", cfg.SubjectJavaVersion, cfg.SubjectMavenProfiles)
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
		t.Setenv(subjectJavaEnv, "")
		t.Setenv(subjectMavenProfilesEnv, "")
		t.Setenv(envCIGoVersion, "")
		t.Setenv(envSubjectToolchainReach, "1")
		f := runFlagsFor(t, "-subject-java-version", "17.0.12", "-subject-maven-profiles", "release,!docs", "-subject-go-version", "1.22.5")
		pluginApplied := false
		opts, err := f.runAssessOptions(func(*pipeline.AssessConfig) { pluginApplied = true })
		if err != nil {
			t.Fatalf("runAssessOptions: %v", err)
		}
		cfg := applyAll(opts)
		if !pluginApplied {
			t.Error("plugin option dropped")
		}
		if cfg.SubjectJavaVersion != "17.0.12" {
			t.Errorf("SubjectJavaVersion = %q, want 17.0.12", cfg.SubjectJavaVersion)
		}
		if cfg.SubjectMavenProfiles != "release,!docs" {
			t.Errorf("SubjectMavenProfiles = %q, want release,!docs", cfg.SubjectMavenProfiles)
		}
		if cfg.SubjectGoVersion != "1.22.5" {
			t.Errorf("SubjectGoVersion = %q, want 1.22.5", cfg.SubjectGoVersion)
		}
		if !cfg.SubjectToolchainReachability {
			t.Error("subject-toolchain reachability gate dropped")
		}
	})
	t.Run("nothing stated", func(t *testing.T) {
		t.Setenv(subjectJavaEnv, "")
		t.Setenv(subjectMavenProfilesEnv, "")
		t.Setenv(envSubjectGoVersion, "")
		t.Setenv(envCIGoVersion, "")
		t.Setenv(envSubjectToolchainReach, "")
		opts, err := runFlagsFor(t).runAssessOptions(func(*pipeline.AssessConfig) {})
		if err != nil {
			t.Fatalf("runAssessOptions: %v", err)
		}
		if cfg := applyAll(opts); cfg.SubjectJavaVersion != "" || cfg.SubjectMavenProfiles != "" || cfg.SubjectGoVersion != "" || cfg.SubjectToolchainReachability {
			t.Errorf("unexpected subject statement: %+v", cfg)
		}
	})
	t.Run("corpus error", func(t *testing.T) {
		if _, err := runFlagsFor(t, "-advisory-corpus-policy", "full").runAssessOptions(func(*pipeline.AssessConfig) {}); err == nil {
			t.Error("want the corpus policy error")
		}
	})
}
