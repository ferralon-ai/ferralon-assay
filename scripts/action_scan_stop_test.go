//go:build unix

package scripts

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stoppableScanner stands in for the scanner: it says "ready", says "TERM" each time it gets
// SIGTERM, and once the test writes to $STUB_RELEASE writes its Report and SARIF when
// $STUB_PUBLISHES is set (dated 2000 when $STUB_BACKDATES is set too), says "exit", and exits 7.
// Its stdout is the step's. It polls its reader rather than waiting on it: under bash 3.2 a TERM
// that lands as wait is entered can crash the shell, or be held until wait returns.
const stoppableScanner = `#!/usr/bin/env bash
trap 'echo TERM' TERM
head -c 1 "$STUB_RELEASE" >/dev/null &
c=$!
echo ready
while kill -0 "$c" 2>/dev/null; do sleep 0.01; done
if [ -n "$STUB_PUBLISHES" ]; then
  : > "$IN_OUT/report.json"
  : > "$IN_OUT/report.sarif.json"
  if [ -n "$STUB_BACKDATES" ]; then
    touch -t 200001010000 "$IN_OUT/report.json" "$IN_OUT/report.sarif.json"
  fi
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
		// backdates dates the scanner's files before the launch, as a clock stepped back would.
		backdates bool
		// earlyStop stops the step while a stub mktemp holds it just before the scanner's launch,
		// so the stop lands before the scanner's pid is known.
		earlyStop bool
	}{
		{name: "not stopped", publishes: true},
		{name: "runner cancels", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}, publishes: true},
		{name: "scanner fails before writing", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}},
		{name: "scanner fails, earlier run's files left", stale: true},
		{name: "scanner rewrites an earlier run's files", stale: true, publishes: true},
		{name: "scanner's clock steps back", stale: true, publishes: true, backdates: true},
		{name: "stopped before the scanner's pid is known", earlyStop: true},
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
			atLaunch := filepath.Join(root, "at-launch")
			launch := filepath.Join(root, "launch")
			if tc.earlyStop {
				realMktemp, err := exec.LookPath("mktemp")
				if err != nil {
					t.Skip("mktemp not on PATH")
				}
				realSleep, err := exec.LookPath("sleep")
				if err != nil {
					t.Skip("sleep not on PATH")
				}
				pluginPath = filepath.Join(root, "plugin-path")
				if err := os.MkdirAll(pluginPath, 0o755); err != nil {
					t.Fatal(err)
				}
				// The step's last command before the launch makes the status file; the stub holds it
				// there until the test has sent the stop.
				stub := "#!/bin/sh\ncase \"$1\" in\n*/scan-status.*)\n" +
					"  : > \"" + atLaunch + "\"\n" +
					"  n=0; while [ ! -e \"" + launch + "\" ] && [ $n -lt 2000 ]; do \"" + realSleep + "\" 0.005; n=$((n+1)); done\n" +
					";;\nesac\nexec \"" + realMktemp + "\" \"$@\"\n"
				if err := os.WriteFile(filepath.Join(pluginPath, "mktemp"), []byte(stub), 0o755); err != nil {
					t.Fatal(err)
				}
				// The forwarded TERM reaches this scanner as it starts, before any handler could be
				// installed, so it is one that TERM kills at any point and that otherwise outlasts the test.
				early := "#!/bin/sh\nexec \"" + realSleep + "\" 600\n"
				if err := os.WriteFile(filepath.Join(bin, "ferralon-assay-scan"), []byte(early), 0o755); err != nil {
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
			if tc.publishes {
				cmd.Env = append(cmd.Env, "STUB_PUBLISHES=1")
			}
			if tc.backdates {
				cmd.Env = append(cmd.Env, "STUB_BACKDATES=1")
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

			if tc.earlyStop {
				deadline := time.Now().Add(30 * time.Second)
				for {
					if _, err := os.Stat(atLaunch); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("the step never reached the scanner's launch")
					}
					time.Sleep(5 * time.Millisecond)
				}
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(launch, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				var exit *exec.ExitError
				if err := cmd.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 128+int(syscall.SIGTERM) {
					t.Fatalf("step ended %v, want the status of a scanner stopped by TERM, %d", err, 128+int(syscall.SIGTERM))
				}
				deadline = time.Now().Add(5 * time.Second)
				for syscall.Kill(-cmd.Process.Pid, 0) == nil {
					if time.Now().After(deadline) {
						t.Fatal("a process from the step's group outlived it")
					}
					time.Sleep(5 * time.Millisecond)
				}
				if got, err := os.ReadFile(output); err == nil && (strings.Contains(string(got), "out-dir=") || strings.Contains(string(got), "sarif-file=")) {
					t.Errorf("step output %q names files this run never wrote", got)
				}
				return
			}

			expect("ready")
			for i, sig := range tc.signals {
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
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
