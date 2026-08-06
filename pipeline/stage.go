// internal/pipeline/stage.go
package pipeline

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// Stage is one pipeline stage. Stubs emit a placeholder artifact of the right type.
type Stage interface {
	Name() string              // stable stage name, used as artifact.ProducedBy
	Status() assessment.Status // coarse status this stage advances the Case to
	Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error
}
