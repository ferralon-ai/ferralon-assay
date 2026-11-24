package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// scanProcess is one analyzer subprocess kept for a whole scan, answering one newline-JSON
// Request per line in order (the serve mode JavaServeEnv selects). Each operation otherwise
// starts a fresh process, which parses the tree and opens the dependency JARs again; a kept
// process holds what the first request built for every later one (javaanalysis.WithSession).
//
// The exchange is the one execSubprocess performs, repeated on open pipes: a Response with Error
// set, a protocol mismatch and an undecodable line fail the request exactly as they fail a
// one-shot call. A process that dies or a context that ends mid-request fails that request; the
// process is gone and the next request starts another. A process that exits cleanly while a
// request is outstanding is a binary without serve mode, which answered one request and stopped:
// the plugin then runs every request one-shot, as it would have without the kept process.
//
// The owner calls close when the scan ends. The process also ends by itself when the owner's
// process does, since its stdin then closes.
type scanProcess struct {
	bin string
	env []string // added to the inherited environment, as for a one-shot call

	mu   sync.Mutex // held for one request at a time; a request that finds it held runs one-shot
	proc *servingProc
	// off is set once the binary is found not to serve, or the process was closed: every
	// request then runs one-shot.
	off bool
}

// servingProc is one started process and its pipes.
type servingProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *tailBuffer
	exited chan struct{} // closed once Wait returns
}

// exchange sends req to the kept process and returns its response. served is false when the
// request was not sent: the process is busy with another request, was closed, or the binary does
// not serve, and the caller runs req one-shot instead.
func (s *scanProcess) exchange(ctx context.Context, req Request) (resp *Response, served bool, err error) {
	if !s.mu.TryLock() {
		return nil, false, nil
	}
	defer s.mu.Unlock()
	if s.off {
		return nil, false, nil
	}
	if s.proc == nil {
		p, err := startServing(s.bin, s.env)
		if err != nil {
			return nil, false, nil // the one-shot call meets the same failure and reports it
		}
		s.proc = p
	}
	p := s.proc

	req.Protocol = ProtocolVersion
	line, err := json.Marshal(req)
	if err != nil {
		return nil, true, fmt.Errorf("plugin: marshal %s request: %w", req.Op, err)
	}

	type read struct {
		line []byte
		err  error
	}
	got := make(chan read, 1)
	go func() {
		if _, err := p.stdin.Write(append(line, '\n')); err != nil {
			got <- read{err: err}
			return
		}
		l, err := p.stdout.ReadBytes('\n')
		got <- read{l, err}
	}()

	var r read
	select {
	case r = <-got:
	case <-ctx.Done():
		s.stop()
		<-got
		return nil, true, fmt.Errorf("plugin: %s subprocess failed: %w (stderr: %s)", req.Op, ctx.Err(), p.stderr.String())
	}
	if r.err != nil {
		// The process stopped before it answered. Give it a moment to finish exiting, so a clean
		// exit can be told from a crash.
		select {
		case <-p.exited:
		case <-time.After(exitGrace):
			_ = p.cmd.Process.Kill()
			<-p.exited
		}
		s.proc = nil
		if p.cmd.ProcessState != nil && p.cmd.ProcessState.Success() {
			s.off = true
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("plugin: %s subprocess failed: %s (stderr: %s)", req.Op, exitDescription(p), p.stderr.String())
	}

	var out Response
	if err := json.Unmarshal(bytes.TrimSpace(r.line), &out); err != nil {
		s.stop()
		return nil, true, fmt.Errorf("plugin: %s produced no decodable response (stderr: %s)", req.Op, p.stderr.String())
	}
	if out.Protocol != ProtocolVersion {
		return nil, true, fmt.Errorf("plugin: %s response protocol %q != %q", req.Op, out.Protocol, ProtocolVersion)
	}
	if out.Error != "" {
		return nil, true, fmt.Errorf("plugin: %s failed: %s", req.Op, out.Error)
	}
	return &out, true, nil
}

// close ends the kept process, waiting for a request in flight to finish first. Every later
// request runs one-shot.
func (s *scanProcess) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.off = true
	s.stop()
	return nil
}

// stop kills the current process, if any, and waits for it. The caller holds s.mu.
func (s *scanProcess) stop() {
	p := s.proc
	if p == nil {
		return
	}
	s.proc = nil
	_ = p.stdin.Close()
	_ = p.cmd.Process.Kill()
	<-p.exited
}

// startServing starts bin in serve mode with env added to the inherited environment.
func startServing(bin string, env []string) (*servingProc, error) {
	cmd := exec.Command(bin)
	cmd.Env = append(append(os.Environ(), env...), JavaServeEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// A plain pipe rather than StdoutPipe: Wait then leaves the read end open, so a response
	// written just before the process exits is still read.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = pw
	stderr := &tailBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	_ = pw.Close()
	p := &servingProc{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(pr), stderr: stderr, exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		_ = pr.Close()
		close(p.exited)
	}()
	return p, nil
}

// exitDescription says how an exited process ended.
func exitDescription(p *servingProc) string {
	if st := p.cmd.ProcessState; st != nil {
		return st.String()
	}
	return "exited"
}

// exitGrace is how long a process whose pipes closed is given to exit before it is killed.
const exitGrace = 5 * time.Second

// tailBufferCap bounds the stderr a kept process retains for error messages.
const tailBufferCap = 64 << 10

// tailBuffer keeps the last tailBufferCap bytes written to it; the process writes it while a
// request reads it.
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - tailBufferCap; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
