package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestScanTimeout_FlagOverEnv(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		env     string
		want    time.Duration
		wantErr bool
	}{
		{name: "unset is no limit"},
		{name: "env", env: "45m", want: 45 * time.Minute},
		{name: "flag over env", args: []string{"-scan-timeout=20m"}, env: "45m", want: 20 * time.Minute},
		{name: "blank flag falls back to env", args: []string{"-scan-timeout= "}, env: "45m", want: 45 * time.Minute},
		{name: "zero rejected", env: "0s", wantErr: true},
		{name: "negative rejected", args: []string{"-scan-timeout=-5m"}, wantErr: true},
		{name: "malformed rejected", env: "thirty minutes", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envScanTimeout, tc.env)
			fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
			f := registerRunFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			got, err := f.scanTimeout()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "want a positive duration") {
					t.Fatalf("err = %v, want a positive-duration error", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("scanTimeout() = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// TestScanBudget_Split: analysis ends a reserve before the hard end, which is a tenth of the limit
// capped at 2m; flush ends at the hard end. Without a limit neither has a deadline.
func TestScanBudget_Split(t *testing.T) {
	started := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		timeout      time.Duration
		wantAnalysis time.Duration
	}{
		{timeout: 0},
		{timeout: 5 * time.Minute, wantAnalysis: 4*time.Minute + 30*time.Second},
		{timeout: 20 * time.Minute, wantAnalysis: 18 * time.Minute},
		{timeout: 60 * time.Minute, wantAnalysis: 58 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.timeout.String(), func(t *testing.T) {
			b := newScanBudget(tc.timeout, started, nil, signalFlushWindow, io.Discard)
			defer b.release()
			ad, aok := b.analysis.Deadline()
			fd, fok := b.flush.Deadline()
			if tc.timeout == 0 {
				if aok || fok {
					t.Fatalf("no limit set, yet deadlines analysis=%v flush=%v", ad, fd)
				}
				return
			}
			if !aok || ad != started.Add(tc.wantAnalysis) {
				t.Errorf("analysis deadline = %v, want %v", ad, started.Add(tc.wantAnalysis))
			}
			if !fok || fd != started.Add(tc.timeout) {
				t.Errorf("flush deadline = %v, want %v", fd, started.Add(tc.timeout))
			}
		})
	}
}

// TestScanBudget_Stops: the limit and the runner's signal each end analysis with a cause naming the
// remedy, and the flush outlives the stop.
func TestScanBudget_Stops(t *testing.T) {
	cases := []struct {
		name      string
		timeout   time.Duration
		started   time.Time
		signal    bool
		wantCause string
	}{
		{
			name:      "limit passed",
			timeout:   30 * time.Minute,
			started:   time.Now().Add(-29 * time.Minute),
			wantCause: "the scan reached its 30m0s time limit; raise the scan-timeout input",
		},
		{
			name:      "signal, no limit",
			started:   time.Now(),
			signal:    true,
			wantCause: "the runner stopped the scan (a job timeout or a cancellation); raise the job's timeout-minutes",
		},
		{
			name:      "signal inside a limit",
			timeout:   time.Hour,
			started:   time.Now(),
			signal:    true,
			wantCause: "the runner stopped the scan",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs := make(chan os.Signal, 2)
			var log strings.Builder
			b := newScanBudget(tc.timeout, tc.started, sigs, time.Hour, &log)
			defer b.release()
			if tc.signal {
				sigs <- syscall.SIGINT
				sigs <- syscall.SIGTERM
			}
			<-b.analysis.Done()
			if got := context.Cause(b.analysis).Error(); !strings.Contains(got, tc.wantCause) {
				t.Errorf("cause = %q, want it to contain %q", got, tc.wantCause)
			}
			if b.flush.Err() != nil {
				t.Errorf("flush ended with analysis: %v", context.Cause(b.flush))
			}
			if tc.signal && !strings.Contains(log.String(), "received interrupt") {
				t.Errorf("stderr = %q, want the signal logged", log.String())
			}
		})
	}
}

// TestScanBudget_SignalFlushWindow: a signal leaves the flush its window, and the window ends it.
func TestScanBudget_SignalFlushWindow(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	b := newScanBudget(0, time.Now(), sigs, 0, io.Discard)
	defer b.release()
	sigs <- syscall.SIGTERM
	<-b.flush.Done()
	if !errors.Is(context.Cause(b.flush), errRunnerStop) {
		t.Fatalf("flush cause = %v, want errRunnerStop", context.Cause(b.flush))
	}
}

// TestRunExit_CutShort: a cut-short scan alone exits zero; a build-graph failure stays red even when
// the scan was also cut short.
func TestRunExit_CutShort(t *testing.T) {
	failed := &jvmGraph{source: report.BuildGraphSourceOff, failure: &buildgraph.Failure{Kind: buildgraph.KindToolFailed, Detail: "signal: killed"}}
	cases := []struct {
		name    string
		graph   *jvmGraph
		wantErr bool
	}{
		{name: "cut short, no graph"},
		{name: "cut short, graph resolved", graph: &jvmGraph{source: report.BuildGraphSourceOff}},
		{name: "cut short during the graph", graph: failed, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := runExit(tc.graph, nil); (err != nil) != tc.wantErr {
				t.Fatalf("runExit = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestWriteScanTruncated(t *testing.T) {
	cut := &report.Report{Partiality: []report.PartialityNote{{Reason: report.ReasonScanCutShort}}}
	other := &report.Report{Partiality: []report.PartialityNote{{Reason: report.ReasonBuildContextNotCompared}}}
	cases := []struct {
		name string
		rep  *report.Report
		want string
	}{
		{name: "cut short", rep: cut, want: "scan-truncated=true\n"},
		{name: "another limit", rep: other, want: "scan-truncated=false\n"},
		{name: "heartbeat", rep: nil, want: "scan-truncated=false\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "output")
			t.Setenv(envGitHubOut, out)
			if err := writeScanTruncated(scanTruncated(tc.rep)); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(out)
			if err != nil || string(got) != tc.want {
				t.Fatalf("step output = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
