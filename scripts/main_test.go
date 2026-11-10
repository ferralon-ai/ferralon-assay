package scripts

import (
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

// TestMain drops the repository-locating git variables a hook or `git rebase --exec` leaves in
// the environment, so code under test that execs git cannot reach the enclosing repository. It
// removes the shared pr-ready-check template repository after the run.
func TestMain(m *testing.M) {
	gittest.ScrubProcess()
	code := m.Run()
	if prReadyTpl != "" {
		os.RemoveAll(prReadyTpl)
	}
	os.Exit(code)
}
