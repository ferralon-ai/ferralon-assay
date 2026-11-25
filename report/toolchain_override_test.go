package report

import (
	"strings"
	"testing"
)

// TestGoToolchainRowsNameTheirOverride: a row undetermined for either Go toolchain reason names the
// Action input that resolves it, in the row's own detail and in its cause group's next action, so a
// reader learns what to set rather than only what was missing.
func TestGoToolchainRowsNameTheirOverride(t *testing.T) {
	for _, reason := range []string{ReasonGoToolchainUnresolved, ReasonGoToolchainNotScanned} {
		for name, text := range map[string]string{
			"detail":          UndeterminedDetail(reason),
			"withheld detail": WithheldDetail(reason, nil),
			"next action":     CauseOfReason(reason).NextAction(),
		} {
			if !strings.Contains(text, "subject-go-version") {
				t.Errorf("%s %s = %q, does not name the subject-go-version input", reason, name, text)
			}
		}
	}
}
