package trigger

import (
	"github.com/ferralon-ai/ferralon-assay/internal/advisorytest"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// advisoryFixtures are the fixture advisories under corpus/testdata/advisories. TestMain installs
// them as the process default source, so a pipeline run with no source of its own resolves them.
var advisoryFixtures = advisorytest.MustLoad[pipeline.AdvisoryFacts]()

// fixtureSource serves advisoryFixtures.
func fixtureSource() pipeline.AdvisorySource {
	return advisorytest.Source[pipeline.AdvisoryFacts](advisoryFixtures)
}
