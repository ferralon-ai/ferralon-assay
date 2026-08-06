package main

import (
	"context"
	"flag"
	"fmt"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/resultsink/ferralon"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/resultsink/github"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// sinkKinds names the concrete sink types selectSinks composed, in order, so a test
// can assert the active set without depending on the sinks' internals.
func sinkKinds(sinks []resultsink.ResultSink) []string {
	kinds := make([]string, 0, len(sinks))
	for _, s := range sinks {
		switch s.(type) {
		case *resultsink.Local:
			kinds = append(kinds, "local")
		case *github.Tier0Summary:
			kinds = append(kinds, "tier0")
		case *github.Tier1SARIF:
			kinds = append(kinds, "sarif")
		case *github.Tier1PRComment:
			kinds = append(kinds, "pr-comment")
		case *github.Tier1Issue:
			kinds = append(kinds, "issue")
		case *github.Tier2Pages:
			kinds = append(kinds, "pages")
		case *ferralon.RunSnapshot:
			kinds = append(kinds, "run-snapshot")
		default:
			kinds = append(kinds, fmt.Sprintf("unknown(%T)", s))
		}
	}
	return kinds
}

// baselineFlagsFor parses args through the SAME flag surface runBaseline uses (registerRunFlags),
// so the test exercises baseline's real flag wiring (-subject-repo + the StateStore flags).
func baselineFlagsFor(t *testing.T, args ...string) *runFlags {
	t.Helper()
	fs := flag.NewFlagSet("baseline-test", flag.ContinueOnError)
	f := registerRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse baseline flags: %v", err)
	}
	return f
}

// TestBaselineStoreSelection covers the baseline StateStore resolution: no store flag falls back to
// a throwaway temp git-ref store; -git-dir / -repo persist to the operator-selected store.
func TestBaselineStoreSelection(t *testing.T) {
	t.Run("no store flag → throwaway temp git-ref store", func(t *testing.T) {
		f := baselineFlagsFor(t)
		store, cleanup, err := baselineStore(f.sf)
		if err != nil {
			t.Fatalf("baselineStore: %v", err)
		}
		defer cleanup()
		if _, ok := store.(*statestore.GitRefStore); !ok {
			t.Fatalf("expected throwaway *GitRefStore, got %T", store)
		}
	})
	t.Run("-git-dir → persistent local store", func(t *testing.T) {
		f := baselineFlagsFor(t, "-git-dir", t.TempDir())
		store, cleanup, err := baselineStore(f.sf)
		if err != nil {
			t.Fatalf("baselineStore: %v", err)
		}
		defer cleanup()
		if _, ok := store.(*statestore.GitRefStore); !ok {
			t.Fatalf("expected *GitRefStore, got %T", store)
		}
	})
	t.Run("-repo → persistent GitHub store", func(t *testing.T) {
		f := baselineFlagsFor(t, "-repo", "octo/widget")
		store, cleanup, err := baselineStore(f.sf)
		if err != nil {
			t.Fatalf("baselineStore: %v", err)
		}
		defer cleanup()
		if _, ok := store.(*statestore.GitHubRefStore); !ok {
			t.Fatalf("expected *GitHubRefStore, got %T", store)
		}
	})
	t.Run("-subject-repo sets the Report identity flag", func(t *testing.T) {
		f := baselineFlagsFor(t, "-subject-repo", "owner/name")
		if *f.repo != "owner/name" {
			t.Fatalf("subject-repo = %q, want owner/name", *f.repo)
		}
	})
}

// TestBaselineSeedsPersistentRef proves the closed gap: a baseline against a -git-dir store seeds
// refs/tegron/state so a subsequent Read sees the baseline (what pr-inherit / cve-watch rely on).
func TestBaselineSeedsPersistentRef(t *testing.T) {
	dir := t.TempDir()
	if err := gitInitBare(dir); err != nil {
		t.Fatalf("git init bare: %v", err)
	}
	store := statestore.NewGitRefStore(statestore.Config{GitDir: dir})

	rep := seedReport()
	if _, err := store.Write(context.Background(), &statestore.State{Report: &rep, SBOM: rep.SBOM}); err != nil {
		t.Fatalf("seed baseline write: %v", err)
	}

	st, err := store.Read(context.Background())
	if err != nil {
		t.Fatalf("read seeded ref: %v", err)
	}
	if st.Report == nil {
		t.Fatalf("seeded ref has no report — pr-inherit/cve-watch would hit ErrNoBaseline")
	}
}

func TestSelectSinks(t *testing.T) {
	const summary = "/tmp/step-summary"

	tests := []struct {
		name string
		env  github.Env
		want []string
	}{
		{
			name: "local-only when not in GitHub Actions",
			env:  github.Env{InActions: false, Token: "tok"},
			want: []string{"local"},
		},
		{
			name: "forked PR (no usable token), all surfaces enabled → tier0 + local only (forked-PR safety dominates toggles)",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "read-only-tok",
				EventName:           "pull_request",
				PRNumber:            7,
				HeadRepoFork:        true,
				CodeScanningEnabled: true,
				PRCommentEnabled:    true,
				IssueEnabled:        true,
			},
			want: []string{"local", "tier0"},
		},
		{
			name: "same-repo PR with write token (all surfaces default-on) → tier0 + sarif + pr-comment + issue + local",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "write-tok",
				EventName:           "pull_request",
				PRNumber:            7,
				HeadRepoFork:        false,
				CodeScanningEnabled: true,
				PRCommentEnabled:    true,
				IssueEnabled:        true,
			},
			want: []string{"local", "tier0", "sarif", "pr-comment", "issue"},
		},
		{
			name: "code-scanning toggled off omits the sarif sink",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "write-tok",
				EventName:           "pull_request",
				PRNumber:            7,
				CodeScanningEnabled: false,
				PRCommentEnabled:    true,
				IssueEnabled:        true,
			},
			want: []string{"local", "tier0", "pr-comment", "issue"},
		},
		{
			name: "pr-comment toggled off omits the pr-comment sink",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "write-tok",
				EventName:           "pull_request",
				PRNumber:            7,
				CodeScanningEnabled: true,
				PRCommentEnabled:    false,
				IssueEnabled:        true,
			},
			want: []string{"local", "tier0", "sarif", "issue"},
		},
		{
			name: "issue toggled off omits the issue sink",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "write-tok",
				EventName:           "pull_request",
				PRNumber:            7,
				CodeScanningEnabled: true,
				PRCommentEnabled:    true,
				IssueEnabled:        false,
			},
			want: []string{"local", "tier0", "sarif", "pr-comment"},
		},
		{
			name: "push build with write token (all surfaces default-on) → tier0 + sarif + issue (no pr-comment)",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "write-tok",
				EventName:           "push",
				CodeScanningEnabled: true,
				PRCommentEnabled:    true,
				IssueEnabled:        true,
			},
			want: []string{"local", "tier0", "sarif", "issue"},
		},
		{
			name: "pages opt-in on push → adds tier2 pages",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "write-tok",
				EventName:           "push",
				PagesOptIn:          true,
				CodeScanningEnabled: true,
				PRCommentEnabled:    true,
				IssueEnabled:        true,
			},
			want: []string{"local", "tier0", "sarif", "issue", "pages"},
		},
		{
			name: "pages opt-in on forked PR does NOT activate tier2 (no write token)",
			env: github.Env{
				InActions:           true,
				StepSummaryPath:     summary,
				Token:               "read-only-tok",
				EventName:           "pull_request",
				PRNumber:            7,
				HeadRepoFork:        true,
				PagesOptIn:          true,
				CodeScanningEnabled: true,
				PRCommentEnabled:    true,
				IssueEnabled:        true,
			},
			want: []string{"local", "tier0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sinkKinds(selectSinks(tc.env, "out-dir", nil))
			if len(got) != len(tc.want) {
				t.Fatalf("sink composition = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("sink[%d] = %q, want %q (full: %v vs %v)", i, got[i], tc.want[i], got, tc.want)
				}
			}
		})
	}
}

// TestSelectRunSnapshotSink covers the default-branch + URL gate: the run-snapshot push
// fires ONLY when a URL is set AND the run is on the default branch; every other
// combination (no URL, PR ref, feature branch, missing default) stays nil so the run
// never files a report_run.
func TestSelectRunSnapshotSink(t *testing.T) {
	tok := ferralon.TokenSource(func(context.Context) string { return "tok" })
	tests := []struct {
		name       string
		url        string
		refName    string
		defBranch  string
		wantActive bool
	}{
		{"url set + on default branch → active", "https://api.example.com/runs", "main", "main", true},
		{"url set but on a PR merge ref → nil", "https://api.example.com/runs", "42/merge", "main", false},
		{"url set but on a feature branch → nil", "https://api.example.com/runs", "feature-x", "main", false},
		{"on default branch but no url → nil", "", "main", "main", false},
		{"url set but default branch unknown → nil", "https://api.example.com/runs", "main", "", false},
		{"url set but ref unknown → nil", "https://api.example.com/runs", "", "main", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := selectRunSnapshotSink(tc.url, tc.refName, tc.defBranch, tok)
			if tc.wantActive && got == nil {
				t.Fatalf("expected an active run-snapshot sink, got nil")
			}
			if !tc.wantActive && got != nil {
				t.Fatalf("expected no run-snapshot sink, got %T", got)
			}
		})
	}
}

// TestSelectSinksAppendsRunSnapshot confirms a non-nil run-snapshot sink is appended
// inside GitHub Actions and dropped on a non-Actions (local) run.
func TestSelectSinksAppendsRunSnapshot(t *testing.T) {
	rs := ferralon.NewRunSnapshot("https://api.example.com/runs", func(context.Context) string { return "tok" })

	inActions := sinkKinds(selectSinks(github.Env{InActions: true, StepSummaryPath: t.TempDir() + "/summary"}, "out-dir", rs))
	if last := inActions[len(inActions)-1]; last != "run-snapshot" {
		t.Fatalf("expected run-snapshot appended last in Actions, got %v", inActions)
	}

	local := sinkKinds(selectSinks(github.Env{InActions: false}, "out-dir", rs))
	for _, k := range local {
		if k == "run-snapshot" {
			t.Fatalf("run-snapshot must not appear on a local (non-Actions) run, got %v", local)
		}
	}
}
