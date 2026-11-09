package main

import (
	"cmp"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
)

// logPhase writes how long one phase of the scan took, so a slow scan shows where its time went.
func logPhase(w io.Writer, phase string, d time.Duration) {
	fmt.Fprintf(w, "%s: time: %s %s\n", brand.Name, phase, d.Round(time.Millisecond))
}

// slowestAdvisories is how many of the slowest advisories the summary line names.
const slowestAdvisories = 5

// advisoryTime is one advisory's assessment duration.
type advisoryTime struct {
	id  string
	d   time.Duration
	src string // the advisory's source; shown only when the same id is named twice
}

// phaseTimer receives the trigger's phase timings (trigger.WithTiming, trigger.WithAdvisoryTiming). It
// logs the inventory as it finishes and collects the per-advisory times for one summary line.
type phaseTimer struct {
	w          io.Writer
	mu         sync.Mutex
	advisories []advisoryTime
}

// observe logs the inventory phase. The advisory phase is collected by observeAdvisory, which also
// carries the advisory id.
func (p *phaseTimer) observe(phase string, d time.Duration) {
	if phase != "advisory" {
		logPhase(p.w, phase, d)
	}
}

func (p *phaseTimer) observeAdvisory(v assessment.VulnRef, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.advisories = append(p.advisories, advisoryTime{v.ID, d, v.Source})
}

// percentile is the nearest-rank q-quantile (0 < q <= 1) of the ascending durations s.
func percentile(s []time.Duration, q float64) time.Duration {
	return s[int(math.Ceil(q*float64(len(s))))-1]
}

// logAdvisories writes the per-advisory assessment p50, p95 and max, then the slowest few advisories
// with their durations; nothing when none was assessed.
func (p *phaseTimer) logAdvisories() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.advisories) == 0 {
		return
	}
	byTime := slices.Clone(p.advisories)
	// Slowest first; equal times by id, so the line is the same for the same durations.
	slices.SortStableFunc(byTime, func(a, b advisoryTime) int {
		if c := cmp.Compare(b.d, a.d); c != 0 {
			return c
		}
		if c := cmp.Compare(a.id, b.id); c != 0 {
			return c
		}
		return cmp.Compare(a.src, b.src)
	})
	s := make([]time.Duration, len(byTime))
	for i, a := range byTime {
		s[len(s)-1-i] = a.d
	}
	fmt.Fprintf(p.w, "%s: time: advisories %d assessed, p50 %s, p95 %s, max %s\n", brand.Name, len(s),
		s[(len(s)-1)/2].Round(time.Millisecond), percentile(s, 0.95).Round(time.Millisecond), s[len(s)-1].Round(time.Millisecond))
	top := byTime[:min(slowestAdvisories, len(byTime))]
	named := map[string]int{}
	for _, a := range top {
		named[a.id]++
	}
	parts := make([]string, len(top))
	for i, a := range top {
		label := a.id
		if named[a.id] > 1 && a.src != "" { // one id from two sources is valid input: tell the copies apart
			label = fmt.Sprintf("%s (%s)", a.id, a.src)
		}
		parts[i] = fmt.Sprintf("%s %s", label, a.d.Round(time.Millisecond))
	}
	fmt.Fprintf(p.w, "%s: time: slowest advisories: %s\n", brand.Name, strings.Join(parts, ", "))
}
