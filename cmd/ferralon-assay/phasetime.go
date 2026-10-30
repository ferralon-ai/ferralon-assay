package main

import (
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
)

// logPhase writes how long one phase of the scan took, so a slow scan shows where its time went.
func logPhase(w io.Writer, phase string, d time.Duration) {
	fmt.Fprintf(w, "%s: time: %s %s\n", brand.Name, phase, d.Round(time.Millisecond))
}

// phaseTimer receives the trigger's phase timings (trigger.WithTiming). It logs the inventory as it
// finishes and collects the per-advisory times for one summary line.
type phaseTimer struct {
	w          io.Writer
	mu         sync.Mutex
	advisories []time.Duration
}

func (p *phaseTimer) observe(phase string, d time.Duration) {
	if phase != "advisory" {
		logPhase(p.w, phase, d)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.advisories = append(p.advisories, d)
}

// logAdvisories writes the per-advisory assessment p50 and max; nothing when none was assessed.
func (p *phaseTimer) logAdvisories() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.advisories) == 0 {
		return
	}
	s := slices.Clone(p.advisories)
	slices.Sort(s)
	fmt.Fprintf(p.w, "%s: time: advisories %d assessed, p50 %s, max %s\n", brand.Name, len(s),
		s[(len(s)-1)/2].Round(time.Millisecond), s[len(s)-1].Round(time.Millisecond))
}
