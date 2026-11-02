package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
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

var errScanStopped = errors.New("the scan was stopped before it finished (a job timeout, a cancellation, or an interrupt); if it was a job timeout, raise the job's timeout-minutes to give it more time")

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
	b := newScanBudget(timeout, scanStarted, sigs, signalFlushWindow, os.Stderr, os.Exit)
	release := b.release
	b.release = func() {
		signal.Stop(sigs)
		release()
	}
	return b
}

// newScanBudget derives the two contexts. With a timeout, analysis ends at started+timeout less the
// flush reserve and flush at started+timeout. The first value on signals ends analysis and gives
// flush window more; a second one calls exit at once, without publishing.
func newScanBudget(timeout time.Duration, started time.Time, signals <-chan os.Signal, window time.Duration, log io.Writer, exit func(int)) *scanBudget {
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
			fmt.Fprintf(log, "%s: received %s; stopping analysis and publishing what was assessed (signal again to exit now)\n", brand.Name, sig)
			stopAnalysis(errScanStopped)
			t := time.AfterFunc(window, func() { stopFlush(errScanStopped) })
			defer t.Stop()
			select {
			case sig := <-signals:
				fmt.Fprintf(log, "%s: received %s again; exiting without publishing\n", brand.Name, sig)
				exit(signalExitCode(sig))
			case <-done:
			}
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

// signalExitCode is the shell's convention for a process ended by sig: 128 plus its number.
func signalExitCode(sig os.Signal) int {
	if s, ok := sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	return 1
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
// A failed write is logged, never returned: the output must not keep the scan from publishing.
func writeScanTruncated(truncated bool, log io.Writer) {
	path := os.Getenv(envGitHubOut)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err == nil {
		_, err = fmt.Fprintf(f, "scan-truncated=%t\n", truncated)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintf(log, "warning: scan-truncated step output: %v\n", err)
	}
}

// markIfStopped sets scan-truncated when err ends a run the stop had already cut short, so a run
// that fails because it was stopped is not left looking complete. It returns err.
func markIfStopped(analysis context.Context, err error) error {
	if err != nil && analysis.Err() != nil {
		writeScanTruncated(true, os.Stderr)
	}
	return err
}

// warnUnqueried says a CVE-watch heartbeat was partial: Go modules the build root's module graph
// leaves out were not inventoried, so OSV was not queried for their dependencies.
func warnUnqueried(out, annotations io.Writer, res *trigger.CVEWatchResult) {
	if len(res.Unqueried) == 0 {
		return
	}
	var dirs []string
	for _, n := range res.Unqueried {
		if n.Path != "" {
			dirs = append(dirs, n.Path)
		}
	}
	fmt.Fprintf(out, "  partial:    Go modules outside the root module's graph were not inventoried, so their dependencies were not queried: %s\n", strings.Join(dirs, ", "))
	fmt.Fprintf(annotations, "::warning title=%s::%s\n", brand.Name, escapeWorkflowData("cve-watch is partial: the stored SBOM holds none of the dependencies of Go modules outside the root module's graph ("+strings.Join(dirs, ", ")+"), so a new advisory that affects only them goes unnoticed."))
}

// warnNoInventory annotates a CVE-watch heartbeat that had no dependency inventory to query.
func warnNoInventory(w io.Writer, res *trigger.CVEWatchResult) {
	if !res.NoInventory {
		return
	}
	fmt.Fprintf(w, "::warning title=%s::%s\n", brand.Name, escapeWorkflowData("cve-watch has nothing to query: the last baseline stopped before resolving its dependency inventory, so no stored SBOM exists. New advisories go unnoticed until a baseline completes its inventory; raise its scan-timeout or the job's timeout-minutes."))
}
