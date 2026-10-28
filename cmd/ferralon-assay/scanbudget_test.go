package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
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
			b := newScanBudget(tc.timeout, started, nil, signalFlushWindow, io.Discard, noExit(t))
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

// noExit fails the test if the budget exits the process.
func noExit(t *testing.T) func(int) {
	return func(code int) { t.Errorf("exit(%d) called", code) }
}

// TestScanBudget_Stops: the limit and a signal each end analysis with a cause naming the
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
			wantCause: "the scan was stopped before it finished (a job timeout, a cancellation, or an interrupt); if it was a job timeout, raise the job's timeout-minutes",
		},
		{
			name:      "signal inside a limit",
			timeout:   time.Hour,
			started:   time.Now(),
			signal:    true,
			wantCause: "the scan was stopped before it finished",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs := make(chan os.Signal, 1)
			var log strings.Builder
			b := newScanBudget(tc.timeout, tc.started, sigs, time.Hour, &log, noExit(t))
			defer b.release()
			if tc.signal {
				sigs <- syscall.SIGINT
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
	b := newScanBudget(0, time.Now(), sigs, 0, io.Discard, noExit(t))
	defer b.release()
	sigs <- syscall.SIGTERM
	<-b.flush.Done()
	if !errors.Is(context.Cause(b.flush), errScanStopped) {
		t.Fatalf("flush cause = %v, want errScanStopped", context.Cause(b.flush))
	}
}

// TestScanBudget_SecondSignalExits: a second signal exits at once with the signal's shell code,
// without waiting for the flush.
func TestScanBudget_SecondSignalExits(t *testing.T) {
	cases := []struct {
		name   string
		second os.Signal
		want   int
	}{
		{name: "interrupt then terminate", second: syscall.SIGTERM, want: 143},
		{name: "interrupt twice", second: syscall.SIGINT, want: 130},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs := make(chan os.Signal, 1)
			exited := make(chan int, 1)
			var log strings.Builder
			b := newScanBudget(0, time.Now(), sigs, time.Hour, &log, func(code int) { exited <- code })
			defer b.release()
			sigs <- syscall.SIGINT
			<-b.analysis.Done()
			sigs <- tc.second
			if got := <-exited; got != tc.want {
				t.Fatalf("exit code = %d, want %d", got, tc.want)
			}
			if b.flush.Err() != nil {
				t.Errorf("flush ended before the exit: %v", context.Cause(b.flush))
			}
			if !strings.Contains(log.String(), "again; exiting without publishing") {
				t.Errorf("stderr = %q, want the second signal logged", log.String())
			}
		})
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
		name        string
		rep         *report.Report
		unwritable  bool
		want        string
		wantWarning bool
	}{
		{name: "cut short", rep: cut, want: "scan-truncated=true\n"},
		{name: "another limit", rep: other, want: "scan-truncated=false\n"},
		{name: "heartbeat", rep: nil, want: "scan-truncated=false\n"},
		{name: "unwritable output is logged, not returned", rep: cut, unwritable: true, wantWarning: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "output")
			if tc.unwritable {
				if err := os.Mkdir(out, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(envGitHubOut, out)
			var log strings.Builder
			writeScanTruncated(scanTruncated(tc.rep), &log)
			if got := strings.HasPrefix(log.String(), "warning: scan-truncated step output: "); got != tc.wantWarning {
				t.Fatalf("log = %q, want warning %v", log.String(), tc.wantWarning)
			}
			if tc.unwritable {
				return
			}
			got, err := os.ReadFile(out)
			if err != nil || string(got) != tc.want {
				t.Fatalf("step output = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestPhaseTimer_Advisories(t *testing.T) {
	cases := []struct {
		name  string
		times []time.Duration
		want  string
	}{
		{name: "none assessed"},
		{name: "odd", times: []time.Duration{3 * time.Second, time.Second, 2 * time.Second}, want: brand.Name + ": time: advisories 3 assessed, p50 2s, max 3s\n"},
		{name: "even takes the lower middle", times: []time.Duration{4 * time.Second, time.Second, 2 * time.Second, 3 * time.Second}, want: brand.Name + ": time: advisories 4 assessed, p50 2s, max 4s\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w strings.Builder
			p := &phaseTimer{w: &w}
			p.observe("inventory", 1500*time.Millisecond)
			for _, d := range tc.times {
				p.observe("advisory", d)
			}
			p.logAdvisories()
			want := brand.Name + ": time: inventory 1.5s\n" + tc.want
			if w.String() != want {
				t.Fatalf("stderr = %q, want %q", w.String(), want)
			}
		})
	}
}

// TestCutWorkSet: the notes a stop causes give way to one scan_cut_short note naming the cause;
// limits the stop cannot have caused are kept.
func TestCutWorkSet(t *testing.T) {
	stop := errors.New("test stop")
	policy := report.PartialityNote{Reason: reasonWorkSetPolicyNotEnumerable}
	cut := report.PartialityNote{Reason: report.ReasonScanCutShort, Ecosystem: "Go", Detail: "the scan stopped while choosing advisories, so some it would have assessed may be missing: test stop"}
	cases := []struct {
		name string
		in   []report.PartialityNote
		want []report.PartialityNote
	}{
		{name: "no notes", want: []report.PartialityNote{cut}},
		{
			name: "stop-caused notes dropped",
			in: []report.PartialityNote{
				{Reason: reasonWorkSetNoInventory, Ecosystem: "Go"},
				{Reason: reasonWorkSetNotWidened, Ecosystem: "Go"},
				{Reason: reasonWorkSetDependencyUnreadable, Ecosystem: "Go", Package: "example.com/a"},
			},
			want: []report.PartialityNote{cut},
		},
		{name: "other limits kept", in: []report.PartialityNote{policy, {Reason: reasonWorkSetNotWidened}}, want: []report.PartialityNote{policy, cut}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cutWorkSet(workSet{ecosystem: "Go", partiality: tc.in, unreadable: []string{"example.com/a"}}, stop)
			if !reflect.DeepEqual(got.partiality, tc.want) {
				t.Errorf("partiality = %+v, want %+v", got.partiality, tc.want)
			}
			if got.unreadable != nil {
				t.Errorf("unreadable = %v, want none: the stop, not the reader, failed them", got.unreadable)
			}
		})
	}
}

// TestScanWorkSet_Stopped: a stop during selection keeps what was chosen and discloses the stop, or,
// when nothing was chosen, fails naming the stop rather than an empty work set.
func TestScanWorkSet_Stopped(t *testing.T) {
	cases := []struct {
		name    string
		empty   bool
		wantErr string
	}{
		{name: "floor chosen before the stop"},
		{name: "nothing chosen", empty: true, wantErr: "the scan stopped while choosing advisories, before any was chosen: test stop"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trapEgress(t)
			f := runFlagsFor(t)
			acq := treeFor(t, checkout.LangGo, false)
			if tc.empty {
				acq = emptyFloorFor(t, checkout.LangGo, false)
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(errors.New("test stop"))
			ws, err := f.scanWorkSet(ctx, acq)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || len(ws.advisories) == 0 {
				t.Fatalf("scanWorkSet = %d advisories, %v; want the floor", len(ws.advisories), err)
			}
			if !scanTruncated(&report.Report{Partiality: ws.partiality}) {
				t.Errorf("partiality = %+v, want a scan_cut_short note", ws.partiality)
			}
		})
	}
}
