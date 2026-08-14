package reachcandidate

import (
	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// CaseFrom builds a measurement Case from a corpus fixture and its advisory facts — the exact
// bridge the live corpus runner uses (formerly inline in live_test.go:89-99). It is lifted here,
// out of _test.go, so callers outside the test (PLAN-221's symbol-resolution classifier) can
// synthesise the same Case per bound corpus record and drive RunCase over it — guaranteeing the
// per-record resolution is byte-identical to the live eval path rather than a re-driven
// resolver. BuildDir is resolved via corpus.ReproPath so it is correct regardless of the
// caller's working directory. expectedSinks is optional precision ground truth (nil ⇒ precision
// unmeasured for this case); it never influences resolution.
func CaseFrom(fix corpus.Fixture, facts pipeline.AdvisoryFacts, expectedSinks []string) Case {
	return Case{
		CaseID:        fix.ID, // unique fixture id (advisory id collides across variants)
		VulnID:        fix.Advisory.ID,
		Source:        fix.Advisory.Source,
		Aliases:       facts.Aliases,
		PURL:          facts.PURL,
		Symbols:       facts.Symbols,
		GuardSymbols:  facts.GuardSymbols,
		BuildDir:      corpus.ReproPath(fix.Codebase.Acquisition.Path),
		ExpectedSinks: expectedSinks,
	}
}
