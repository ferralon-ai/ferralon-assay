package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The inventory note names the lane's cause after the fixed text and stays an inventory limit; with
// no cause the note is the fixed text alone.
func TestInventoryPartialityNotes_Cause(t *testing.T) {
	for cause, want := range map[string]string{
		"":                    inventoryLimitDetail,
		"go mod graph: no go": inventoryLimitDetail + ": go mod graph: no go",
	} {
		p := plugin.Partial(plugin.PartialReasonToolFailure)
		p.Cause = cause
		notes := inventoryPartialityNotes(p, "Go")
		if len(notes) != 1 || notes[0].Detail != want || len(inventoryLimits(notes)) != 1 {
			t.Fatalf("cause %q: notes = %+v, want one inventory limit with detail %q", cause, notes, want)
		}
	}
}
