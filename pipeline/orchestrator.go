// internal/pipeline/orchestrator.go
package pipeline

import (
	"context"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// StageError names the pipeline stage whose Run returned an error. The trigger layer
// reads Stage off it to disclose WHICH analysis step did not complete, instead of
// discarding the entire scan Report over one failed advisory. It wraps the underlying
// error, so errors.Is/As on the cause continue to work unchanged.
type StageError struct {
	Stage string
	Err   error
}

func (e *StageError) Error() string { return fmt.Sprintf("stage %s: %v", e.Stage, e.Err) }
func (e *StageError) Unwrap() error { return e.Err }

// Orchestrator runs the stages of the pipeline for an Assessment, advancing its status.
type Orchestrator struct {
	stages      []Stage
	assessments assessment.Store
	store       artifact.Store
	logf        func(format string, args ...any)
}

// OrchestratorOption configures an Orchestrator at construction.
type OrchestratorOption func(*Orchestrator)

// WithProgressLog makes the orchestrator emit one line per stage transition and at completion,
// using logf (e.g. log.Printf). Without it the orchestrator is silent — so library use and tests
// stay quiet by default; tegrond opts in to give an operator real-time lifecycle visibility.
func WithProgressLog(logf func(format string, args ...any)) OrchestratorOption {
	return func(o *Orchestrator) { o.logf = logf }
}

// NewOrchestrator wires the assessment store, artifact store, and ordered stages together.
func NewOrchestrator(assessments assessment.Store, store artifact.Store, stages []Stage, opts ...OrchestratorOption) *Orchestrator {
	o := &Orchestrator{stages: stages, assessments: assessments, store: store}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// log emits a progress line if a logger was injected; otherwise it is a no-op.
func (o *Orchestrator) log(format string, args ...any) {
	if o.logf != nil {
		o.logf(format, args...)
	}
}

// Run walks every stage in order for the given Assessment. For each stage it sets
// Assessment.Status = stage.Status(), persists, then calls stage.Run. On any stage error
// it sets Status = StatusFailed, persists, and returns the error. After all stages
// succeed it sets Status = StatusComplete and persists; the final stage is responsible
// for setting Assessment.VerdictID.
func (o *Orchestrator) Run(ctx context.Context, assessmentID string) error {
	c, err := o.assessments.Get(assessmentID)
	if err != nil {
		return err
	}
	// tegron.scan.count: one increment per scan attempt, unconditional on
	// stage outcome — a failed scan still consumed a scan's worth of compute.
	scanCounter.Add(ctx, 1)

	o.log("assessment=%s starting (%d stages)", assessmentID, len(o.stages))
	for i, stage := range o.stages {
		c.Status = stage.Status()
		if err := o.assessments.Update(c); err != nil {
			return err
		}
		o.log("assessment=%s stage=%s (%d/%d) status=%s", assessmentID, stage.Name(), i+1, len(o.stages), c.Status)
		if err := stage.Run(ctx, c, o.store); err != nil {
			c.Status = assessment.StatusFailed
			o.log("assessment=%s stage=%s FAILED: %v", assessmentID, stage.Name(), err)
			if uerr := o.assessments.Update(c); uerr != nil {
				return uerr
			}
			return &StageError{Stage: stage.Name(), Err: err}
		}
	}

	c.Status = assessment.StatusComplete
	o.log("assessment=%s complete verdict=%s", assessmentID, c.VerdictID)
	return o.assessments.Update(c)
}
