package symbolresolution

import (
	"github.com/ferralon-ai/ferralon-assay/internal/advisorytest"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// advisoryFixtures is the advisory corpus these tests measure: the fixture corpus under
// corpus/testdata/advisories.
var advisoryFixtures = advisorytest.MustLoad[pipeline.AdvisoryFacts]()
