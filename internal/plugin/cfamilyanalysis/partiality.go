package cfamilyanalysis

import (
	"sort"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// reasonSet accumulates partiality reasons and emits them deduplicated and sorted, so a result's
// Reasons never depend on the order the checks ran in.
type reasonSet map[string]struct{}

func newReasonSet() reasonSet { return reasonSet{} }

func (s reasonSet) add(reason string) { s[reason] = struct{}{} }

// partiality is Complete when no reason was added, otherwise declared-partial with every reason.
func (s reasonSet) partiality() plugin.Partiality {
	if len(s) == 0 {
		return plugin.Complete()
	}
	reasons := make([]string, 0, len(s))
	for r := range s {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return plugin.Partial(reasons...)
}
