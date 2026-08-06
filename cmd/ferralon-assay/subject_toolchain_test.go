package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// The env var names action.yml exports on the run step, duplicated here on purpose: a typo on
// either side of that seam would silently disable the two exact toolchain tiers forever, with no
// other test in the tree going red — the same shape of dead wiring the toolchain fact exists to repair.
// Keep these in step with action.yml's "Run ferralon-assay" env block. These are both the
// brand-derived and legacy names on the OSS default build (brand.EnvPrefix == "TEGRON") — see
// envSubjectGoVersion/envCIGoVersion in run.go. Precedence (derived wins, legacy honored,
// regression guard) is proven build-tag-independently in brand/brand_env_test.go.
const (
	subjectGoEnv = "TEGRON_SUBJECT_GO_VERSION"
	ciGoEnv      = "TEGRON_CI_GO_VERSION"
	trustGoEnv   = "TEGRON_TRUST_OBSERVED_GO"
)

// optionToolchain applies an AssessOption and reports the toolchain sources it installed, so the
// assertions below are behavioral rather than merely non-nil.
func optionToolchain(opt pipeline.AssessOption) (declared, observed string, trust bool) {
	cfg := pipeline.AssessConfig{}
	opt(&cfg)
	return cfg.SubjectGoVersion, cfg.CIGoVersion, cfg.TrustCIGoVersion
}

// TestSubjectToolchainOption covers the resolve()-path selector for the two exact toolchain
// sources — the caller's declaration and the CI runner's observation. The declared
// value follows this CLI's flag > env precedence, the observed value is env-only, and absent both no
// option is produced (leaving the fact to the go.mod floors).
func TestSubjectToolchainOption(t *testing.T) {
	t.Run("neither set → no option, fact falls back to the go.mod floors", func(t *testing.T) {
		f := runFlagsFor(t)
		t.Setenv(subjectGoEnv, "")
		t.Setenv(ciGoEnv, "")
		t.Setenv(trustGoEnv, "")
		if opt := f.subjectToolchainOption(); opt != nil {
			t.Fatal("expected no option when neither source is present")
		}
	})

	t.Run("flag set only → declared from the flag", func(t *testing.T) {
		f := runFlagsFor(t, "-subject-go-version", "go1.21.3")
		t.Setenv(subjectGoEnv, "")
		t.Setenv(ciGoEnv, "")
		declared, observed := requireOption(t, f)
		if declared != "go1.21.3" || observed != "" {
			t.Fatalf("declared/observed = %q/%q, want go1.21.3/\"\"", declared, observed)
		}
	})

	t.Run("env set only → declared from the env", func(t *testing.T) {
		f := runFlagsFor(t)
		t.Setenv(subjectGoEnv, "go1.20.14")
		t.Setenv(ciGoEnv, "")
		declared, observed := requireOption(t, f)
		if declared != "go1.20.14" || observed != "" {
			t.Fatalf("declared/observed = %q/%q, want go1.20.14/\"\"", declared, observed)
		}
	})

	t.Run("both set → flag wins", func(t *testing.T) {
		f := runFlagsFor(t, "-subject-go-version", "go1.21.3")
		t.Setenv(subjectGoEnv, "go1.20.14")
		t.Setenv(ciGoEnv, "")
		declared, _ := requireOption(t, f)
		if declared != "go1.21.3" {
			t.Fatalf("declared = %q, want the flag value go1.21.3", declared)
		}
	})

	t.Run("the observed tier is env-only and reaches the option", func(t *testing.T) {
		f := runFlagsFor(t)
		t.Setenv(subjectGoEnv, "")
		t.Setenv(ciGoEnv, "go1.26.3")
		declared, observed := requireOption(t, f)
		if declared != "" || observed != "go1.26.3" {
			t.Fatalf("declared/observed = %q/%q, want \"\"/go1.26.3", declared, observed)
		}
	})

	t.Run("an observed value alone is enough to produce an option", func(t *testing.T) {
		f := runFlagsFor(t, "-subject-go-version", "go1.19.13")
		t.Setenv(subjectGoEnv, "")
		t.Setenv(ciGoEnv, "go1.26.3")
		declared, observed := requireOption(t, f)
		if declared != "go1.19.13" || observed != "go1.26.3" {
			t.Fatalf("declared/observed = %q/%q, want go1.19.13/go1.26.3 — both tiers must reach the resolver", declared, observed)
		}
	})
}

func requireOption(t *testing.T, f *runFlags) (declared, observed string) {
	t.Helper()
	declared, observed, _ = requireOptionFull(t, f)
	return declared, observed
}

func requireOptionFull(t *testing.T, f *runFlags) (declared, observed string, trust bool) {
	t.Helper()
	opt := f.subjectToolchainOption()
	if opt == nil {
		t.Fatal("expected an option")
	}
	return optionToolchain(opt)
}

// TestTrustObservedGoEnvSeam covers the ruling-7 gate at the CLI seam. The trust flag travels the same
// env channel as the measurement it qualifies, and it FAILS CLOSED: only an explicit true grants it, so
// a typo in a customer's workflow degrades to the go.mod floors rather than to a stronger claim than
// they asserted. A silent inversion here would restore the premise the ruling removed with no other
// test in the tree going red.
func TestTrustObservedGoEnvSeam(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want bool
		why  string
	}{
		{"true", true, "the value action.yml emits for an opted-in caller"},
		{"1", true, "ParseBool accepts 1"},
		{"TRUE", true, "ParseBool is case-tolerant"},
		{"t", true, "ParseBool accepts t"},
		{"  true  ", true, "surrounding whitespace is trimmed"},
		{"", false, "absent ⇒ untrusted, the shipped default"},
		{"0", false, "the value action.yml emits for a defaulted caller"},
		{"false", false, "explicit false"},
		{"yes", false, "not a ParseBool truth value ⇒ fails CLOSED, never trusted"},
		{"maybe", false, "junk fails closed"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			f := runFlagsFor(t)
			t.Setenv(subjectGoEnv, "")
			t.Setenv(ciGoEnv, "go1.26.4")
			t.Setenv(trustGoEnv, tc.env)
			_, observed, trust := requireOptionFull(t, f)
			if observed != "go1.26.4" {
				t.Fatalf("observed = %q, want go1.26.4 — the measurement is passed either way", observed)
			}
			if trust != tc.want {
				t.Errorf("trust for %q = %v, want %v (%s)", tc.env, trust, tc.want, tc.why)
			}
		})
	}
}

// TestTrustObservedGoIsNotAVersionSource pins that asserting trust with nothing observed produces no
// option at all — trust qualifies a measurement, it is not one.
func TestTrustObservedGoIsNotAVersionSource(t *testing.T) {
	f := runFlagsFor(t)
	t.Setenv(subjectGoEnv, "")
	t.Setenv(ciGoEnv, "")
	t.Setenv(trustGoEnv, "true")
	if opt := f.subjectToolchainOption(); opt != nil {
		t.Fatal("expected no option: trust alone establishes nothing about the subject")
	}
}
