package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// subjectJavaEnv is envSubjectJavaVersion spelled out, so a rename of either side goes red.
const subjectJavaEnv = "ASSAY_SUBJECT_JAVA_VERSION"

func TestSubjectJavaOption(t *testing.T) {
	tests := []struct {
		name, flag, env, want string
	}{
		{"neither set", "", "", ""},
		{"flag", "17.0.12", "", "17.0.12"},
		{"env", "", "11.0.24", "11.0.24"},
		{"flag over env", "17.0.12", "11.0.24", "17.0.12"},
		{"blank flag falls back to env", "  ", "11", "11"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args []string
			if tt.flag != "" {
				args = []string{"-subject-java-version", tt.flag}
			}
			f := runFlagsFor(t, args...)
			t.Setenv(subjectJavaEnv, tt.env)
			opt := f.subjectJavaOption()
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
			if cfg.SubjectJavaVersion != tt.want {
				t.Errorf("SubjectJavaVersion = %q, want %q", cfg.SubjectJavaVersion, tt.want)
			}
		})
	}
}
