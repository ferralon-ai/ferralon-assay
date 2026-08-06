// internal/pipeline/stage_test.go
package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// sampleStage is a trivial Stage used only to prove the interface is satisfiable.
type sampleStage struct{}

func (sampleStage) Name() string              { return "sample" }
func (sampleStage) Status() assessment.Status { return assessment.StatusInventory }
func (sampleStage) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	return nil
}

// Compile-time assertion: sampleStage must satisfy Stage.
var _ Stage = sampleStage{}

func TestSampleStageSatisfiesStage(t *testing.T) {
	var s Stage = sampleStage{}
	if s.Name() != "sample" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "sample")
	}
	if s.Status() != assessment.StatusInventory {
		t.Fatalf("Status() = %q, want %q", s.Status(), assessment.StatusInventory)
	}
	if err := s.Run(context.Background(), &assessment.Assessment{}, artifact.NewMemStore()); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
}
