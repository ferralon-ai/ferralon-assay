package pipeline

import "github.com/ferralon-ai/ferralon-assay/internal/advisorytest"

// advisoryFixtures are the fixture advisories under corpus/testdata/advisories, loaded once and
// verified against their manifest pins. TestMain installs them as the process default source, so a
// stage run with a nil source resolves them exactly as a scan resolves a corpus.
var advisoryFixtures = advisorytest.MustLoad[AdvisoryFacts]()

// fixtureSource serves advisoryFixtures.
func fixtureSource() AdvisorySource { return advisorytest.Source[AdvisoryFacts](advisoryFixtures) }
