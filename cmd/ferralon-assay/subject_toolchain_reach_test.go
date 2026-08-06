package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// subjectToolchainReachEnv is the env var name action.yml exports on the run step, duplicated here
// on purpose: a typo on either side of that seam would silently disable the M4 gate forever, with
// no other test in the tree going red. This is both the brand-derived and legacy name on the OSS
// default build (brand.EnvPrefix == "TEGRON") — see envSubjectToolchainReach/
// legacyEnvSubjectToolchainReach in run.go. Precedence (derived wins, legacy honored) is proven
// build-tag-independently in brand/brand_env_test.go.
const subjectToolchainReachEnv = "TEGRON_SUBJECT_TOOLCHAIN_REACHABILITY"

// TestSubjectToolchainReachOption covers the subject-toolchain reachability release gate. The default is
// OFF, and the table pins that only an affirmative spelling opens it: this gate guards a
// verdict-behavior change, so a typo, a stale "0", or a shell that exported an empty string must all
// leave it shut.
func TestSubjectToolchainReachOption(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{" yes ", true},
		{"on", true},
		{"0", false},
		{"false", false},
		{"off", false},
		{"no", false},
		{"2", false},
		{"maybe", false},
		{"1 1", false},
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

// TestSubjectToolchainReachIsUnsetByDefault pins the release gate's whole reason for existing: with
// nothing set — the state every caller other than an Action that opts in is in — no option is
// produced at all, so AssessStages is byte-identical to the pre-M4 assembly.
func TestSubjectToolchainReachIsUnsetByDefault(t *testing.T) {
	if err := os.Unsetenv(subjectToolchainReachEnv); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv(subjectToolchainReachEnv) })
	if opt := subjectToolchainReachOption(); opt != nil {
		t.Fatal("the M4 gate produced an option with its env var absent; it must default OFF")
	}
}

// TestActionExportsTheReachGateEnv closes the seam a comment cannot: the gate is only reachable from
// the shipped Action if action.yml exports exactly this env name on the run step. A rename on either
// side would otherwise disable the flag forever with nothing in the tree going red — the same shape
// of dead wiring the toolchain fact exists to repair, which is why this is an assertion and not a note.
func TestActionExportsTheReachGateEnv(t *testing.T) {
	path := filepath.Join("..", "..", "..", "action.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	yml := string(body)
	if !strings.Contains(yml, subjectToolchainReachEnv+":") {
		t.Errorf("action.yml exports no %s on the run step; the Action input cannot reach the gate", subjectToolchainReachEnv)
	}
	// The input must be opt-IN: gated on an explicit 'true', not on "anything but false". An
	// opt-OUT ternary here would turn M4 on for every caller that never named the input.
	if !strings.Contains(yml, "inputs.subject-toolchain-reachability == 'true'") {
		t.Error("action.yml does not gate subject-toolchain-reachability on an explicit 'true'; the M4 input must be opt-in")
	}
	if !strings.Contains(yml, "subject-toolchain-reachability:") {
		t.Error("action.yml declares no subject-toolchain-reachability input")
	}
}
