package main

import (
	"github.com/ferralon-ai/ferralon-assay/internal/advisorytest"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// advisoryFixtures are the fixture advisories under corpus/testdata/advisories, loaded once and
// verified against their manifest pins.
var advisoryFixtures = advisorytest.MustLoad[pipeline.AdvisoryFacts]()

// fixtureSource serves advisoryFixtures.
func fixtureSource() pipeline.AdvisorySource {
	return advisorytest.Source[pipeline.AdvisoryFacts](advisoryFixtures)
}
