package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/telemetry"
)

// TestTelemetryConfig pins the mapping from the CLI's telemetry env vars onto telemetry.Config:
// an unset or unusable value must leave the field at the zero value telemetry.New treats as its
// default, never at a value that changes coverage.
func TestTelemetryConfig(t *testing.T) {
	cases := []struct {
		name      string
		level     string
		ratio     string
		env       string
		wantLevel telemetry.Level
		wantRatio *float64
		wantEnv   string
	}{
		{name: "all unset", wantLevel: telemetry.LevelEssential},
		{name: "standard", level: "standard", wantLevel: telemetry.LevelStandard},
		{name: "unrecognized level", level: "bogus", wantLevel: telemetry.LevelEssential},
		{name: "ratio", ratio: " 0.25 ", wantLevel: telemetry.LevelEssential, wantRatio: ptr(0.25)},
		{name: "zero ratio kept", ratio: "0", wantLevel: telemetry.LevelEssential, wantRatio: ptr(0)},
		{name: "unparseable ratio", ratio: "half", wantLevel: telemetry.LevelEssential},
		{name: "environment trimmed", env: " prod ", wantLevel: telemetry.LevelEssential, wantEnv: "prod"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(envOTelLevel, c.level)
			t.Setenv(envOTelSampleRatio, c.ratio)
			t.Setenv(envEnvironment, c.env)
			got := telemetryConfig()
			if got.Level != c.wantLevel {
				t.Errorf("Level = %v, want %v", got.Level, c.wantLevel)
			}
			switch {
			case c.wantRatio == nil && got.SampleRatio != nil:
				t.Errorf("SampleRatio = %v, want nil", *got.SampleRatio)
			case c.wantRatio != nil && (got.SampleRatio == nil || *got.SampleRatio != *c.wantRatio):
				t.Errorf("SampleRatio = %v, want %v", got.SampleRatio, *c.wantRatio)
			}
			if got.Environment != c.wantEnv {
				t.Errorf("Environment = %q, want %q", got.Environment, c.wantEnv)
			}
		})
	}
}

func ptr(v float64) *float64 { return &v }
