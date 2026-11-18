package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// subjectToolchainReachEnv is the env var name action.yml exports on the run step, duplicated here
// on purpose: a typo on either side of that seam would leave the Action input without effect, with
// no other test in the tree going red.
const subjectToolchainReachEnv = "ASSAY_SUBJECT_TOOLCHAIN_REACHABILITY"

// TestSubjectToolchainReachOption: the setting is on unless the value is a negative spelling, so an
// unset variable, an empty one and a typo all keep the default.
func TestSubjectToolchainReachOption(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"1", true},
		{"true", true},
		{"on", true},
		{"maybe", true},
		{"0", false},
		{"false", false},
		{"FALSE", false},
		{" off ", false},
		{"no", false},
	}
	for _, c := range cases {
		t.Setenv(subjectToolchainReachEnv, c.env)
		opt := subjectToolchainReachOption()
		if (opt != nil) != c.want {
			t.Errorf("%s=%q → option present %t, want %t", subjectToolchainReachEnv, c.env, opt != nil, c.want)
			continue
		}
		if opt == nil {
			continue
		}
		cfg := pipeline.AssessConfig{}
		opt(&cfg)
		if !cfg.SubjectToolchainReachability {
			t.Errorf("%s=%q produced an option that did not enable subject-toolchain reachability", subjectToolchainReachEnv, c.env)
		}
	}
}

// TestSubjectToolchainReachIsOnWhenUnset: a caller that sets nothing analyzes under the subject's
// toolchain.
func TestSubjectToolchainReachIsOnWhenUnset(t *testing.T) {
	if err := os.Unsetenv(subjectToolchainReachEnv); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(subjectToolchainReachEnv) })
	if subjectToolchainReachOption() == nil {
		t.Fatal("no option with the env var absent; the setting must default on")
	}
}

// TestActionExportsTheReachEnv: the Action input reaches the CLI only if action.yml exports exactly
// this env name on the run step, defaults the input to on, and turns it off only on an explicit
// 'false'.
func TestActionExportsTheReachEnv(t *testing.T) {
	path := filepath.Join("..", "..", "action.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	yml := string(body)
	if !strings.Contains(yml, subjectToolchainReachEnv+": ${{ inputs.subject-toolchain-reachability != 'false' }}") {
		t.Errorf("action.yml does not export %s as on unless the input is 'false'", subjectToolchainReachEnv)
	}
	input := yml[strings.Index(yml, "  subject-toolchain-reachability:"):]
	if next := strings.Index(input[1:], "\n  subject-"); next >= 0 {
		input = input[:next+1]
	}
	if !strings.Contains(input, `default: "true"`) {
		t.Error(`action.yml does not default the subject-toolchain-reachability input to "true"`)
	}
}
