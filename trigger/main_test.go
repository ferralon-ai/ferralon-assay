package trigger

import (
	"os"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// TestMain drops the repository-locating git variables a hook or `git rebase --exec` leaves in
// the environment, so code under test that execs git cannot reach the enclosing repository, and
// installs the fixture advisories as the default advisory source.
func TestMain(m *testing.M) {
	gittest.ScrubProcess()
	pipeline.SetDefaultAdvisorySource(fixtureSource())
	os.Exit(m.Run())
}
