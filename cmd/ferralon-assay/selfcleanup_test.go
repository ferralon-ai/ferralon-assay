package main

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// TestStateRefOfReportsTheConfiguredRef guards task #34: the self-cleanup actuator
// used to hardcode statestore.DefaultRef instead of asking the run's own StateStore
// what ref it was actually configured with, so an operator who set a custom
// state-ref (action.yml input -> -ref flag -> statestore.Config.Ref /
// statestore.GitHubConfig.Ref) had their real state ref left behind by an uninstall
// that told them it had been removed. stateRefOf must report the CONFIGURED ref for
// every StateStore a real run can construct (state.go's stateStoreFlags.resolve:
// GitRefStore for -git-dir, GitHubRefStore for -repo), not just the default.
func TestStateRefOfReportsTheConfiguredRef(t *testing.T) {
	const customRef = "refs/assay/env-staging/state"

	t.Run("GitRefStore default", func(t *testing.T) {
		store := statestore.NewGitRefStore(statestore.Config{GitDir: t.TempDir()})
		if got := stateRefOf(store); got != statestore.DefaultRef {
			t.Errorf("stateRefOf(default GitRefStore) = %q, want %q", got, statestore.DefaultRef)
		}
	})

	t.Run("GitRefStore custom ref", func(t *testing.T) {
		store := statestore.NewGitRefStore(statestore.Config{GitDir: t.TempDir(), Ref: customRef})
		if got := stateRefOf(store); got != customRef {
			t.Errorf("stateRefOf(custom GitRefStore) = %q, want %q — the configured -ref/state-ref never reached the cleanup path", got, customRef)
		}
	})

	t.Run("GitHubRefStore default", func(t *testing.T) {
		store := statestore.NewGitHubRefStore(statestore.GitHubConfig{Owner: "acme", Repo: "widget", Token: "ghs_x"})
		if got := stateRefOf(store); got != statestore.DefaultRef {
			t.Errorf("stateRefOf(default GitHubRefStore) = %q, want %q", got, statestore.DefaultRef)
		}
	})

	t.Run("GitHubRefStore custom ref", func(t *testing.T) {
		store := statestore.NewGitHubRefStore(statestore.GitHubConfig{Owner: "acme", Repo: "widget", Token: "ghs_x", Ref: customRef})
		if got := stateRefOf(store); got != customRef {
			t.Errorf("stateRefOf(custom GitHubRefStore) = %q, want %q — the configured -ref/state-ref never reached the cleanup path", got, customRef)
		}
	})

	t.Run("StateStore with no ref to report falls back to DefaultRef", func(t *testing.T) {
		store := statestore.NewMemStore()
		if got := stateRefOf(store); got != statestore.DefaultRef {
			t.Errorf("stateRefOf(MemStore) = %q, want %q (honest fallback, not a crash)", got, statestore.DefaultRef)
		}
	})
}
