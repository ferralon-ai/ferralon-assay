package github_test

import (
	"testing"

	ghsink "github.com/ferralon-ai/ferralon-assay/resultsink/github"
)

// TestDetectEnv_ReadsEnvironment asserts DetectEnv snapshots the documented env vars.
func TestDetectEnv_ReadsEnvironment(t *testing.T) {
	t.Setenv(ghsink.EnvActions, "true")
	t.Setenv(ghsink.EnvStepSummary, "/tmp/summary.md")
	t.Setenv(ghsink.EnvToken, "ghs_abc")
	t.Setenv(ghsink.EnvRepository, "owner/repo")
	t.Setenv(ghsink.EnvEventName, "push")
	t.Setenv(ghsink.EnvWorkspace, "/work")
	t.Setenv(ghsink.EnvPagesOptIn, "")

	env := ghsink.DetectEnv()
	if !env.InActions {
		t.Error("InActions should be true")
	}
	if env.StepSummaryPath != "/tmp/summary.md" {
		t.Errorf("StepSummaryPath = %q", env.StepSummaryPath)
	}
	if env.Token != "ghs_abc" {
		t.Errorf("Token = %q", env.Token)
	}
	if env.PagesOptIn {
		t.Error("PagesOptIn should default off")
	}
	// The three opt-OUT surfaces default ON when their env vars are absent.
	if !env.CodeScanningEnabled {
		t.Error("CodeScanningEnabled should default on (absent env)")
	}
	if !env.PRCommentEnabled {
		t.Error("PRCommentEnabled should default on (absent env)")
	}
	if !env.IssueEnabled {
		t.Error("IssueEnabled should default on (absent env)")
	}
}

// TestDetectEnv_OptOutToggles asserts the per-surface opt-OUT env vars are ENABLED
// unless set to an explicit "false"/"0", and that any other value (incl. absent)
// reads as enabled — the auto-on, opt-out contract.
func TestDetectEnv_OptOutToggles(t *testing.T) {
	cases := []struct {
		name        string
		value       string
		wantEnabled bool
	}{
		{"absent → enabled", "", true},
		{"true → enabled", "true", true},
		{"1 → enabled", "1", true},
		{`"false" → disabled`, "false", false},
		{`"0" → disabled`, "0", false},
		{"any other value → enabled", "yes", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(ghsink.EnvCodeScanning, tc.value)
			t.Setenv(ghsink.EnvPRComment, tc.value)
			t.Setenv(ghsink.EnvIssue, tc.value)

			env := ghsink.DetectEnv()
			if env.CodeScanningEnabled != tc.wantEnabled {
				t.Errorf("CodeScanningEnabled(%q) = %v, want %v", tc.value, env.CodeScanningEnabled, tc.wantEnabled)
			}
			if env.PRCommentEnabled != tc.wantEnabled {
				t.Errorf("PRCommentEnabled(%q) = %v, want %v", tc.value, env.PRCommentEnabled, tc.wantEnabled)
			}
			if env.IssueEnabled != tc.wantEnabled {
				t.Errorf("IssueEnabled(%q) = %v, want %v", tc.value, env.IssueEnabled, tc.wantEnabled)
			}
		})
	}
}

// TestDetect_SurfaceToggles proves that each per-surface opt-OUT toggle, when
// disabled, clears the matching capability EVEN with a write token, while the
// untoggled surfaces stay enabled — and that a forked PR (CanWrite=false) yields
// all-false regardless of any toggle, preserving forked-PR safety.
func TestDetect_SurfaceToggles(t *testing.T) {
	// A write-capable same-repo PR run with every surface enabled is the baseline.
	base := func() ghsink.Env {
		return ghsink.Env{
			StepSummaryPath:     "/s",
			Token:               "t",
			EventName:           "pull_request",
			PRNumber:            7,
			CodeScanningEnabled: true,
			PRCommentEnabled:    true,
			IssueEnabled:        true,
		}
	}

	t.Run("all surfaces enabled → all caps true", func(t *testing.T) {
		caps := ghsink.Detect(base())
		if !caps.CanSARIF || !caps.CanComment || !caps.CanIssue {
			t.Errorf("want all caps true, got SARIF=%v Comment=%v Issue=%v", caps.CanSARIF, caps.CanComment, caps.CanIssue)
		}
	})

	t.Run("code-scanning off clears CanSARIF only", func(t *testing.T) {
		env := base()
		env.CodeScanningEnabled = false
		caps := ghsink.Detect(env)
		if caps.CanSARIF {
			t.Error("CanSARIF must be false when code-scanning is toggled off (even with write token)")
		}
		if !caps.CanComment || !caps.CanIssue {
			t.Error("disabling code-scanning must not affect comment/issue")
		}
	})

	t.Run("pr-comment off clears CanComment only", func(t *testing.T) {
		env := base()
		env.PRCommentEnabled = false
		caps := ghsink.Detect(env)
		if caps.CanComment {
			t.Error("CanComment must be false when pr-comment is toggled off (even with write token + PR)")
		}
		if !caps.CanSARIF || !caps.CanIssue {
			t.Error("disabling pr-comment must not affect sarif/issue")
		}
	})

	t.Run("issue off clears CanIssue only", func(t *testing.T) {
		env := base()
		env.IssueEnabled = false
		caps := ghsink.Detect(env)
		if caps.CanIssue {
			t.Error("CanIssue must be false when issue is toggled off (even with write token)")
		}
		if !caps.CanSARIF || !caps.CanComment {
			t.Error("disabling issue must not affect sarif/comment")
		}
	})

	t.Run("forked PR: all surfaces enabled but no write → all caps false", func(t *testing.T) {
		env := base()
		env.HeadRepoFork = true // forked PR carries a read-only token
		caps := ghsink.Detect(env)
		if caps.CanWrite {
			t.Fatal("forked PR must not be write-capable")
		}
		if caps.CanSARIF || caps.CanComment || caps.CanIssue {
			t.Errorf("forked PR must clear all surfaces regardless of toggles, got SARIF=%v Comment=%v Issue=%v",
				caps.CanSARIF, caps.CanComment, caps.CanIssue)
		}
	})
}

func TestDetect_Capabilities(t *testing.T) {
	cases := []struct {
		name      string
		env       ghsink.Env
		wantMax   ghsink.Tier
		wantSumm  bool
		wantWrite bool
		wantPages bool
	}{
		{
			name:     "forked PR: summary path, no token → Tier 0 only",
			env:      ghsink.Env{StepSummaryPath: "/s", Token: "", EventName: "pull_request"},
			wantMax:  ghsink.Tier0,
			wantSumm: true,
		},
		{
			name:      "write token on push → Tier 1",
			env:       ghsink.Env{StepSummaryPath: "/s", Token: "t", EventName: "push"},
			wantMax:   ghsink.Tier1,
			wantSumm:  true,
			wantWrite: true,
		},
		{
			name:      "pages opt-in + write token → Tier 2",
			env:       ghsink.Env{StepSummaryPath: "/s", Token: "t", EventName: "push", PagesOptIn: true},
			wantMax:   ghsink.Tier2,
			wantSumm:  true,
			wantWrite: true,
			wantPages: true,
		},
		{
			name:      "pages opt-in without token → no Tier 2 (write required)",
			env:       ghsink.Env{StepSummaryPath: "/s", Token: "", PagesOptIn: true},
			wantMax:   ghsink.Tier0,
			wantSumm:  true,
			wantWrite: false,
			wantPages: false,
		},
		{
			name:    "no summary path (not in Actions) → Tier 0, summary unavailable",
			env:     ghsink.Env{StepSummaryPath: "", Token: ""},
			wantMax: ghsink.Tier0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caps := ghsink.Detect(tc.env)
			if caps.MaxTier != tc.wantMax {
				t.Errorf("MaxTier = %d, want %d", caps.MaxTier, tc.wantMax)
			}
			if caps.CanSummary != tc.wantSumm {
				t.Errorf("CanSummary = %v, want %v", caps.CanSummary, tc.wantSumm)
			}
			if caps.CanWrite != tc.wantWrite {
				t.Errorf("CanWrite = %v, want %v", caps.CanWrite, tc.wantWrite)
			}
			if caps.CanPages != tc.wantPages {
				t.Errorf("CanPages = %v, want %v", caps.CanPages, tc.wantPages)
			}
			// Tier 0 is always allowed.
			if !caps.Allows(ghsink.Tier0) {
				t.Error("Tier 0 must always be allowed")
			}
		})
	}
}
