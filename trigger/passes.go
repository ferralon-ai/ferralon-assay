package trigger

import (
	"context"
	"fmt"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// advisoryPasses assesses a scan's advisories in two passes. The first takes every advisory
// through intake, inventory, malicious-presence and disqualification discovery, the stages that cost
// milliseconds, and notes which settle there. The second runs the stages after them, the plugin
// analysis, one advisory at a time in the scan's order, as assess(i) is called for each.
//
// A scan that stops during the second pass has still decided every advisory the first pass
// disqualified, where one serial pass would have lost every advisory behind the one it stopped in.
// Each stage runs once per advisory, in the order assess runs them, so a scan that never stops
// builds the Report assess builds.
type advisoryPasses struct {
	analysis context.Context
	analyze  []pipeline.Stage
	staged   []*stagedAssessment
}

// stagedAssessment is one advisory between the passes.
type stagedAssessment struct {
	vuln        assessment.VulnRef
	assessments assessment.Store
	store       artifact.Store
	id          string
	// elapsed is the time the first pass took.
	elapsed time.Duration
	// settled is whether disqualification discovery disqualified the advisory, which is all its row reads.
	settled bool
	// stopped is whether the scan stopped before or during the first pass.
	stopped bool
	err     error
}

// requestsFor is the assessment request for each of advisories against codebase.
func requestsFor(advisories []assessment.VulnRef, codebase assessment.CodebaseRef) []assessment.Request {
	reqs := make([]assessment.Request, len(advisories))
	for i, adv := range advisories {
		reqs[i] = assessment.Request{Vulnerability: adv, Codebase: codebase}
	}
	return reqs
}

// newAdvisoryPasses runs the first pass over reqs under analysis.
func newAdvisoryPasses(analysis context.Context, reqs []assessment.Request, opts []pipeline.AssessOption) *advisoryPasses {
	// As in assess: a disqualified advisory's row reads the discovery artifact alone.
	opts = append(opts[:len(opts):len(opts)], pipeline.WithSkipDisqualifiedAnalysis(true))
	settle, analyze := pipeline.SplitAssessStages(opts...)
	p := &advisoryPasses{analysis: analysis, analyze: analyze, staged: make([]*stagedAssessment, len(reqs))}
	for i, req := range reqs {
		p.staged[i] = settleWithin(analysis, req, settle)
	}
	return p
}

// settleWithin runs the first pass for one advisory. A stopped scan discards the result as
// assessWithin does: a stage may swallow the cancellation, and what it returns then rests on work
// it never finished.
func settleWithin(analysis context.Context, req assessment.Request, settle []pipeline.Stage) *stagedAssessment {
	s := &stagedAssessment{vuln: req.Vulnerability}
	if analysis.Err() != nil {
		s.stopped = true
		return s
	}
	start := time.Now()
	s.assessments = assessment.NewMemStore()
	s.store = artifact.NewMemStore()
	a, err := s.assessments.Create(req)
	if err != nil {
		s.err = fmt.Errorf("trigger: create assessment: %w", err)
		return s
	}
	s.id = a.ID
	err = pipeline.NewOrchestrator(s.assessments, s.store, settle).Run(analysis, a.ID)
	if analysis.Err() != nil {
		return &stagedAssessment{vuln: req.Vulnerability, stopped: true}
	}
	s.elapsed = time.Since(start)
	if err != nil {
		observeAssessed(analysis, req.Vulnerability, start)
		s.err = fmt.Errorf("trigger: assess %s: %w", req.Vulnerability.ID, err)
		return s
	}
	s.settled = pipeline.SettledByDisqualification(s.store, s.id)
	return s
}

// assess finishes the assessment of advisory i, in place of assessWithin(analysis, reqs[i], opts...):
// the same store, assessment id, stopped and error. Call it once per advisory.
//
// An advisory the first pass disqualified keeps its result when the scan has since stopped: nothing
// the later stages would add is read, and the stop cannot have touched work that finished before it.
// Every other advisory the scan stopped before finishing is stopped.
func (p *advisoryPasses) assess(i int) (artifact.Store, string, bool, error) {
	s := p.staged[i]
	p.staged[i] = nil
	if s == nil || s.stopped {
		return nil, "", true, nil
	}
	if s.err != nil {
		return nil, "", false, s.err
	}
	if p.analysis.Err() != nil {
		if !s.settled {
			return nil, "", true, nil
		}
		observeAssessed(p.analysis, s.vuln, time.Now().Add(-s.elapsed))
		return s.store, s.id, false, nil
	}
	start := time.Now()
	err := pipeline.NewOrchestrator(s.assessments, s.store, p.analyze, pipeline.ResumingRun()).Run(p.analysis, s.id)
	if p.analysis.Err() != nil && !s.settled {
		return nil, "", true, nil
	}
	observeAssessed(p.analysis, s.vuln, start.Add(-s.elapsed))
	if err != nil && p.analysis.Err() == nil {
		return nil, "", false, fmt.Errorf("trigger: assess %s: %w", s.vuln.ID, err)
	}
	return s.store, s.id, false, nil
}
