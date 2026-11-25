package trigger

import (
	"github.com/ferralon-ai/ferralon-assay/artifact"
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

// subjectToolchain is the Go toolchain fact the assessment resolved, as the report records it; nil
// for an assessment of another language.
func subjectToolchain(store artifact.Store, assessmentID string) *report.SubjectToolchain {
	f, ok := pipeline.GoToolchain(store, assessmentID)
	if !ok {
		return nil
	}
	return &report.SubjectToolchain{Version: f.Version, Bound: f.Bound, Source: f.Source, Assumption: f.Assumption, StrictVersion: f.StrictVersion}
}

// carryToolchain records the toolchain this pass established, else the stored report's when the
// pass ran no Go assessment.
func carryToolchain(b *report.Builder, fresh []*report.SubjectToolchain, stored *report.Report) {
	for _, t := range fresh {
		b.WithSubjectToolchain(t)
	}
	b.WithSubjectToolchain(stored.SubjectToolchain)
}
