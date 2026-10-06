package main

import (
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

// TestMain drops the repository-locating git variables a hook or `git rebase --exec` leaves in
// the environment, so code under test that execs git cannot reach the enclosing repository.
func TestMain(m *testing.M) {
	gittest.ScrubProcess()
	os.Exit(m.Run())
}
