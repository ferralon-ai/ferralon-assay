package trigger

import (
	"context"
	"fmt"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// advisoryPasses assesses a scan's advisories in two passes that overlap. The first takes every
// advisory, in the scan's order, through intake, inventory, malicious-presence and disqualification
// discovery and notes which settle there. It runs on one goroutine ahead of the second, which runs
// the stages after them, the plugin analysis, one advisory at a time in the scan's order as assess(i)
// is called for each, and waits only for the first pass to reach advisory i.
//
// A scan that stops during the second pass has still decided every advisory the first pass had
// disqualified, where one serial pass would have lost every advisory behind the one it stopped in.
// The first pass never delays the second: advisory i's analysis starts no later than a serial pass
// would start it, because the first pass has done only the settle stages of advisories 0..i by then
// and they are all that precede it serially. A scan that stops at any time T has therefore settled or
// analysed every advisory a serial pass had finished by T, up to the contention the two goroutines
// put on the machine. Each stage still runs once per advisory, in the order assess runs them, so a
// scan that never stops builds the Report assess builds.
//
// The two goroutines share the checkout's reads and the plugin: plugin.Memoize, InventoryMemo and
// the nested-module memo are guarded by mutexes, and every other input is read-only. The first pass
// never reports to a timing hook; assess does, so the hooks stay single-goroutine.
type advisoryPasses struct {
	analysis context.Context
	analyze  []pipeline.Stage
	staged   []*stagedAssessment
	cancel   context.CancelFunc
	done     chan struct{}
}

// stagedAssessment is one advisory between the passes. Its fields are written by the first pass
// before ready is closed and read by assess after.
type stagedAssessment struct {
	ready       chan struct{}
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

// passesDoneKey carries a function the first pass calls when it has finished with every advisory.
type passesDoneKey struct{}

// requestsFor is the assessment request for each of advisories against codebase.
func requestsFor(advisories []assessment.VulnRef, codebase assessment.CodebaseRef) []assessment.Request {
	reqs := make([]assessment.Request, len(advisories))
	for i, adv := range advisories {
		reqs[i] = assessment.Request{Vulnerability: adv, Codebase: codebase}
	}
	return reqs
}

// newAdvisoryPasses starts the first pass over reqs under analysis. The caller must close the
// result.
func newAdvisoryPasses(analysis context.Context, reqs []assessment.Request, opts []pipeline.AssessOption) *advisoryPasses {
	// As in assess: a disqualified advisory's row reads the discovery artifact alone.
	opts = append(opts[:len(opts):len(opts)], pipeline.WithSkipDisqualifiedAnalysis(true))
	settle, analyze := pipeline.SplitAssessStages(opts...)
	first, cancel := context.WithCancel(analysis)
	p := &advisoryPasses{
		analysis: analysis, analyze: analyze, staged: make([]*stagedAssessment, len(reqs)),
		cancel: cancel, done: make(chan struct{}),
	}
	items := make([]*stagedAssessment, len(reqs))
	for i, req := range reqs {
		items[i] = &stagedAssessment{ready: make(chan struct{}), vuln: req.Vulnerability}
		p.staged[i] = items[i]
	}
	go func() {
		defer close(p.done)
		for i, req := range reqs {
			settleWithin(first, req, settle, items[i])
			close(items[i].ready)
		}
		if f, ok := analysis.Value(passesDoneKey{}).(func()); ok {
			f()
		}
	}()
	return p
}

// close stops the first pass and waits for it.
func (p *advisoryPasses) close() {
	p.cancel()
	<-p.done
}

// settleWithin runs the first pass for one advisory into s. A stopped scan discards the result as
// assessWithin does: a stage may swallow the cancellation, and what it returns then rests on work
// it never finished.
func settleWithin(ctx context.Context, req assessment.Request, settle []pipeline.Stage, s *stagedAssessment) {
	if ctx.Err() != nil {
		s.stopped = true
		return
	}
	start := time.Now()
	assessments, store := assessment.NewMemStore(), artifact.NewMemStore()
	a, err := assessments.Create(req)
	if err != nil {
		s.err = fmt.Errorf("trigger: create assessment: %w", err)
		return
	}
	err = pipeline.NewOrchestrator(assessments, store, settle).Run(ctx, a.ID)
	if ctx.Err() != nil {
		s.stopped = true
		return
	}
	s.assessments, s.store, s.id = assessments, store, a.ID
	s.elapsed = time.Since(start)
	if err != nil {
		s.err = fmt.Errorf("trigger: assess %s: %w", req.Vulnerability.ID, err)
		return
	}
	s.settled = pipeline.SettledByDisqualification(store, a.ID)
}

// settledStore is advisory i's store and assessment id once the first pass has settled it, nil when
// the scan stopped before the first pass finished with it or the first pass failed. Analysis adds to
// the same store, so call it before assess(i).
func (p *advisoryPasses) settledStore(i int) (artifact.Store, string) {
	s := p.staged[i]
	<-s.ready
	if s.stopped || s.err != nil {
		return nil, ""
	}
	return s.store, s.id
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
	<-s.ready
	if s.stopped {
		return nil, "", true, nil
	}
	if s.err != nil {
		if s.assessments != nil {
			observeAssessed(p.analysis, s.vuln, time.Now().Add(-s.elapsed))
		}
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
