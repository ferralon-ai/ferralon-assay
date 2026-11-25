package main

import (
	"fmt"
	"os"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/repoconfig"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// envStrictness is the env channel for -strictness.
const envStrictness = brand.EnvPrefix + "_STRICTNESS"

// statedStrictness is -strictness, then envStrictness, "" when neither states one. A value other
// than practical or strict fails the run: the setting decides which clearances stand, so a typo must
// not fall back to a default.
func (f *runFlags) statedStrictness() (string, error) {
	v := flagOrEnv(*f.strictness, os.Getenv(envStrictness))
	if v != "" && !repoconfig.ValidStrictness(v) {
		return "", fmt.Errorf("strictness %q (-strictness or %s): want practical or strict", v, envStrictness)
	}
	return v, nil
}

// checkStrictness refuses an invalid strictness statement. It needs no scan, so it runs before the
// target is acquired, like checkEntrypoints.
func (f *runFlags) checkStrictness() error {
	_, err := f.statedStrictness()
	return err
}

// resolveMode decides the run's strictness: the input or flag, else the strictness key of
// .github/ferralon.yml (f.repoStrictness, read when the target was acquired), else practical.
func (f *runFlags) resolveMode() (report.Mode, error) {
	input, err := f.statedStrictness()
	if err != nil {
		return report.Mode{}, err
	}
	return modeFrom(input, f.repoStrictness), nil
}

// modeFrom applies the precedence input > config > default.
func modeFrom(input, config string) report.Mode {
	switch {
	case input != "":
		return report.Mode{Strictness: input, Source: report.ModeSourceInput}
	case config != "":
		return report.Mode{Strictness: config, Source: report.ModeSourceConfig}
	default:
		return report.Mode{Strictness: report.StrictnessPractical, Source: report.ModeSourceDefault}
	}
}

// strictnessOption resolves the mode, records it on f for the Report's source, and returns the
// option that selects it on the pipeline.
func (f *runFlags) strictnessOption() (pipeline.AssessOption, error) {
	mode, err := f.resolveMode()
	if err != nil {
		return nil, err
	}
	f.resolvedMode = mode
	return pipeline.WithStrict(mode.Strictness == report.StrictnessStrict), nil
}
