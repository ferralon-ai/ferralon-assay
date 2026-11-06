//go:build unix

package scripts

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stoppableScanner stands in for the scanner: it says "ready", says "TERM" each time it gets
// SIGTERM, and once the test writes to $STUB_RELEASE writes its Report and SARIF when
// $STUB_PUBLISHES is set, says "exit", and exits 7. Its stdout is the step's. It creates
// $STUB_READY, when set, as it says "ready".
const stoppableScanner = `#!/usr/bin/env bash
trap 'echo TERM' TERM
head -c 1 "$STUB_RELEASE" >/dev/null &
c=$!
if [ -n "$STUB_READY" ]; then : > "$STUB_READY"; fi
echo ready
while kill -0 "$c" 2>/dev/null; do wait "$c"; done
if [ -n "$STUB_PUBLISHES" ]; then
  : > "$IN_OUT/report.json"
  : > "$IN_OUT/report.sarif.json"
fi
echo exit
exit 7
`

// TestScanStepForwardsTheRunnersStop runs action.yml's scan step verbatim and stops it the way the
// runner cancels a step: SIGINT to the step's shell, then SIGTERM. The scanner gets TERM once, for
// the first signal only, the shell waits for it to finish publishing, and the step exits with the
// scanner's own status, as it also does when nothing stops it. The out-dir and sarif-file outputs
// are set only when this run's scanner wrote the files they name, never for ones an earlier run left.
func TestScanStepForwardsTheRunnersStop(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	step := scanStep(t)
	cases := []struct {
		name      string
		signals   []syscall.Signal
		publishes bool
		// stale leaves a Report and SARIF from an earlier run in the out dir.
		stale bool
		// earlyStop has a stub sleep send the first SIGINT while the step is still polling for the
		// scanner's pid, so the stop lands before the pid is known.
		earlyStop bool
	}{
		{name: "not stopped", publishes: true},
		{name: "runner cancels", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}, publishes: true},
		{name: "scanner fails before writing", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}},
		{name: "scanner fails, earlier run's files left", stale: true},
		{name: "scanner rewrites an earlier run's files", stale: true, publishes: true},
		{name: "stopped before the scanner's pid is known", signals: []syscall.Signal{syscall.SIGTERM}, publishes: true, earlyStop: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "ferralon-assay-scan"), []byte(stoppableScanner), 0o755); err != nil {
				t.Fatal(err)
			}
			release := filepath.Join(root, "release")
			if err := syscall.Mkfifo(release, 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "github_output")
			pluginPath := bin
			sleepOnce := filepath.Join(root, "sleep-once")
			ready := filepath.Join(root, "ready")
			if tc.earlyStop {
				if signal.Ignored(syscall.SIGINT) {
					t.Skip("SIGINT is ignored here, so the step cannot trap it")
				}
				realSleep, err := exec.LookPath("sleep")
				if err != nil {
					t.Skip("sleep not on PATH")
				}
				pluginPath = filepath.Join(root, "plugin-path")
				if err := os.MkdirAll(pluginPath, 0o755); err != nil {
					t.Fatal(err)
				}
				// The stop waits for the scanner to be running, so the forwarded TERM reaches a scanner
				// that has its handler installed; the step still has not read the scanner's pid.
				stub := "#!/bin/sh\nif mkdir \"" + sleepOnce + "\" 2>/dev/null; then\n" +
					"  n=0; while [ ! -e \"$STUB_READY\" ] && [ $n -lt 1000 ]; do \"" + realSleep + "\" 0.005; n=$((n+1)); done\n" +
					"  kill -INT \"$PPID\"\nfi\nexec \"" + realSleep + "\" \"$@\"\n"
				if err := os.WriteFile(filepath.Join(pluginPath, "sleep"), []byte(stub), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.stale {
				out := filepath.Join(root, "out")
				if err := os.MkdirAll(out, 0o755); err != nil {
					t.Fatal(err)
				}
				earlier := time.Now().Add(-time.Hour)
				for _, name := range []string{"report.json", "report.sarif.json"} {
					path := filepath.Join(out, name)
					if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(path, earlier, earlier); err != nil {
						t.Fatal(err)
					}
				}
			}

			// A guard against a hang, not a timing assertion: on expiry the whole group is killed,
			// which closes the pipe the test reads from.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", step.Run)
			cmd.Dir = root
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
			cmd.Env = os.Environ()
			for k := range step.Env {
				cmd.Env = append(cmd.Env, k+"=")
			}
			cmd.Env = append(cmd.Env,
				"STUB_RELEASE="+release, "BIN_DIR="+bin, "PLUGIN_PATH_DIR="+pluginPath, "RUNNER_TEMP="+root,
				"GITHUB_OUTPUT="+output, "IN_MODE=baseline", "IN_TARGET=.", "IN_OUT="+filepath.Join(root, "out"))
			if tc.earlyStop {
				cmd.Env = append(cmd.Env, "STUB_READY="+ready)
			}
			if tc.publishes {
				cmd.Env = append(cmd.Env, "STUB_PUBLISHES=1")
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewScanner(stdout)
			expect := func(want string) {
				t.Helper()
				if !lines.Scan() || lines.Text() != want {
					t.Fatalf("scanner said %q (%v), want %q", lines.Text(), lines.Err(), want)
				}
			}

			expect("ready")
			if tc.earlyStop {
				// The stop is sent by the step's first poll. If the pid file was already written by
				// then, the path under test was not reached this run.
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(sleepOnce); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Skip("the scanner's pid was known before the first poll; the early-stop path was not reached")
					}
					time.Sleep(5 * time.Millisecond)
				}
				expect("TERM")
			}
			for i, sig := range tc.signals {
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				if i == 0 && !tc.earlyStop {
					expect("TERM")
				}
			}
			// Release with a byte, not with EOF: on macOS a reader blocked opening a FIFO can miss
			// the EOF of a writer that opens and closes it straight away, and then reads forever.
			w, err := os.OpenFile(release, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte{'x'}); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			expect("exit")

			var exit *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 7 {
				t.Fatalf("step ended %v, want the scanner's own exit status 7", err)
			}
			if tc.earlyStop {
				// expect("exit") above would have failed on a second TERM; nothing may outlive the step.
				deadline := time.Now().Add(5 * time.Second)
				for syscall.Kill(-cmd.Process.Pid, 0) == nil {
					if time.Now().After(deadline) {
						t.Fatal("a process from the step's group outlived it")
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			got, err := os.ReadFile(output)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			for _, key := range []string{"out-dir=", "sarif-file="} {
				if strings.Contains(string(got), key) != tc.publishes {
					t.Errorf("step output %q: %s set = %v, want %v", got, key, !tc.publishes, tc.publishes)
				}
			}
		})
	}
}
