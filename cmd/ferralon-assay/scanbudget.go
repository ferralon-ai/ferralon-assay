package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

const (
	envScanTimeout = brand.EnvPrefix + "_SCAN_TIMEOUT"
	envGitHubOut   = "GITHUB_OUTPUT"
)

// scanStarted is when the scan's time limit starts counting: process start, so the limit covers
// the clone and the build graph as well as the analysis.
var scanStarted = time.Now()

const (
	// signalFlushWindow is how long a scan the runner stopped has to publish what it has. The
	// runner sends SIGTERM 7.5s after SIGINT and kills the process tree 2.5s after that.
	signalFlushWindow = 8 * time.Second
	// maxFlushReserve caps the share of an in-band time limit held back from analysis for the
	// state write and the result surfaces; a limit under 20m keeps a tenth of itself.
	maxFlushReserve = 2 * time.Minute
)

var errRunnerStop = errors.New("the runner stopped the scan (a job timeout or a cancellation); raise the job's timeout-minutes to give it more time")

// scanTimeout resolves -scan-timeout / ASSAY_SCAN_TIMEOUT. Zero means no time limit: unset, a
// scan runs until it finishes or the runner stops it.
func (f *runFlags) scanTimeout() (time.Duration, error) {
	v := flagOrEnv(*f.scanTimeoutRaw, os.Getenv(envScanTimeout))
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("-scan-timeout=%q: want a positive duration such as 30m", v)
	}
	return d, nil
}

// scanBudget is a run's two contexts. analysis bounds acquisition, inventory and the advisory loop;
// once it is done every advisory not yet assessed is reported as cut short. flush bounds what
// follows (the state read and write, publishing, the post-scan beacon), so a stopped scan still
// publishes the findings it has.
type scanBudget struct {
	analysis context.Context
	flush    context.Context
	release  func()
}

// startScanBudget is newScanBudget on the process's own SIGINT and SIGTERM.
func startScanBudget(timeout time.Duration) *scanBudget {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	b := newScanBudget(timeout, scanStarted, sigs, signalFlushWindow, os.Stderr)
	release := b.release
	b.release = func() {
		signal.Stop(sigs)
		release()
	}
	return b
}

// newScanBudget derives the two contexts. With a timeout, analysis ends at started+timeout less the
// flush reserve and flush at started+timeout. The first value on signals ends analysis and gives
// flush window more; later ones are absorbed, so the runner's SIGTERM does not cut the flush short.
func newScanBudget(timeout time.Duration, started time.Time, signals <-chan os.Signal, window time.Duration, log io.Writer) *scanBudget {
	analysis, stopAnalysis := context.WithCancelCause(context.Background())
	flush, stopFlush := context.WithCancelCause(context.Background())
	cancels := []func(){func() { stopAnalysis(nil) }, func() { stopFlush(nil) }}
	if timeout > 0 {
		hardEnd := started.Add(timeout)
		limit := fmt.Errorf("the scan reached its %s time limit; raise the scan-timeout input (%s) to give it more time", timeout, envScanTimeout)
		var cancel context.CancelFunc
		analysis, cancel = context.WithDeadlineCause(analysis, hardEnd.Add(-flushReserve(timeout)), limit)
		cancels = append(cancels, cancel)
		flush, cancel = context.WithDeadlineCause(flush, hardEnd, limit)
		cancels = append(cancels, cancel)
	}

	done := make(chan struct{})
	go func() {
		select {
		case sig := <-signals:
			fmt.Fprintf(log, "%s: received %s; stopping analysis and publishing what was assessed\n", brand.Name, sig)
			stopAnalysis(errRunnerStop)
			t := time.AfterFunc(window, func() { stopFlush(errRunnerStop) })
			<-done
			t.Stop()
		case <-done:
		}
	}()
	return &scanBudget{
		analysis: analysis,
		flush:    flush,
		release: func() {
			close(done)
			for _, c := range cancels {
				c()
			}
		},
	}
}

// flushReserve is the part of a time limit held back from analysis for publishing.
func flushReserve(timeout time.Duration) time.Duration {
	return min(maxFlushReserve, timeout/10)
}

// scanTruncated reports whether rep discloses advisories the scan stopped before assessing.
func scanTruncated(rep *report.Report) bool {
	if rep == nil {
		return false
	}
	for _, n := range rep.Partiality {
		if n.Reason == report.ReasonScanCutShort {
			return true
		}
	}
	return false
}

// writeScanTruncated sets the Action's scan-truncated output when the run is inside GitHub Actions.
func writeScanTruncated(truncated bool) error {
	path := os.Getenv(envGitHubOut)
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open step output: %w", err)
	}
	if _, err := fmt.Fprintf(f, "scan-truncated=%t\n", truncated); err != nil {
		_ = f.Close()
		return fmt.Errorf("write step output: %w", err)
	}
	return f.Close()
}
