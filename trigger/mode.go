package trigger

import (
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// modeStrictness is the strictness a run assessed with opts adjudicates under.
func modeStrictness(opts []pipeline.AssessOption) string {
	if pipeline.StrictOf(opts...) {
		return report.StrictnessStrict
	}
	return report.StrictnessPractical
}

// runMode is the Mode a run's Report records: the strictness opts select and the source the caller
// says decided it, default when it names none.
func runMode(opts []pipeline.AssessOption, source string) report.Mode {
	if source == "" {
		source = report.ModeSourceDefault
	}
	return report.Mode{Strictness: modeStrictness(opts), Source: source}
}
