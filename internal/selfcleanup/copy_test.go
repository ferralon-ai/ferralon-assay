package selfcleanup

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// TestCleanupCopyNamesTheRealStateRef guards against the class of defect closed by
// dispatch 30: the uninstall body text hand-spelling the state ref as a literal
// that silently diverges from the ref a run actually creates.
//
// Task #34 widened this: the original version only ever constructed the actuator
// with the default ref, so it passed while prBody/issueBody hardcoded
// statestore.DefaultRef regardless of what ActuatorConfig.StateRef actually carried
// (a run with a custom state-ref got told the DEFAULT ref had been removed — its
// real ref was never touched). This version exercises both the default AND a
// custom ref, and asserts the copy names whatever g.cfg.StateRef actually is — the
// SAME ref DeleteStateRef deletes — not a fixed literal, default or otherwise.
func TestCleanupCopyNamesTheRealStateRef(t *testing.T) {
	cases := []struct {
		name string
		ref  string
	}{
		{"default ref", statestore.DefaultRef},
		{"custom ref (operator-configured state-ref)", "refs/assay/env-staging/state"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &gitActuator{cfg: ActuatorConfig{
				WorkflowPath: ".github/workflows/ferralon-assay.yml",
				StateRef:     tc.ref,
			}}

			bodies := map[string]string{
				"prBody()":    g.prBody(),
				"issueBody()": g.issueBody(),
			}
			for name, body := range bodies {
				if !strings.Contains(body, tc.ref) {
					t.Errorf("%s does not name g.cfg.StateRef (%q) — the copy has drifted from the ref DeleteStateRef actually deletes", name, tc.ref)
				}
				// The regression this closes: a copy that silently reverts to naming
				// the default regardless of what StateRef actually is.
				if tc.ref != statestore.DefaultRef && strings.Contains(body, statestore.DefaultRef) {
					t.Errorf("%s names statestore.DefaultRef (%q) even though this run's configured ref is %q — an operator with a custom state-ref would be told the wrong ref was removed", name, statestore.DefaultRef, tc.ref)
				}
				if strings.Contains(body, "refs/tegron/state") && tc.ref != "refs/tegron/state" {
					t.Errorf("%s still contains the stale literal \"refs/tegron/state\"", name)
				}
			}
		})
	}
}
