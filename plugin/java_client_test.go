package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// These hermetic tests exercise the javaPlugin exec + newline-JSON/stdio
// transport WITHOUT the real assay-plugin-java binary. They reuse the shared
// TestHelperProcess re-exec harness (defined in client_test.go): newHelperPlugin
// points a goPlugin at the test binary, and javaPlugin shares the identical
// transport, so we construct a javaPlugin bound to the same helper command.

func newJavaHelperPlugin(t *testing.T, mode string) *javaPlugin {
	t.Helper()
	return &javaPlugin{bin: helperCmd(t, mode)}
}

func TestJavaPlugin_Language(t *testing.T) {
	if got := (&javaPlugin{}).Language(); got != "java" {
		t.Errorf("Language() = %q, want %q", got, "java")
	}
}

func TestJavaPlugin_IndexSymbolsSuccess(t *testing.T) {
	p := newJavaHelperPlugin(t, "success")
	res, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"})
	if err != nil {
		t.Fatalf("IndexSymbols: unexpected error: %v", err)
	}
	if !res.Partiality.Complete {
		t.Errorf("want Complete partiality, got %+v", res.Partiality)
	}
	if len(res.Symbols) != 1 || res.Symbols[0].SCIP != "scip:helper#Foo" {
		t.Errorf("decoded payload mismatch: %+v", res.Symbols)
	}
}

func TestJavaPlugin_ResponseErrorIsWrappedGoError(t *testing.T) {
	p := newJavaHelperPlugin(t, "error")
	_, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"})
	if err == nil {
		t.Fatal("want error from Response.Error, got nil")
	}
	if !strings.Contains(err.Error(), "canned hard error from helper") {
		t.Errorf("error should wrap Response.Error, got: %v", err)
	}
}

func TestJavaPlugin_NonZeroExitIsError(t *testing.T) {
	p := newJavaHelperPlugin(t, "nonzero")
	_, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"})
	if err == nil {
		t.Fatal("want error from non-zero exit, got nil")
	}
}

func TestJavaPlugin_ProtocolMismatchIsError(t *testing.T) {
	p := newJavaHelperPlugin(t, "badproto")
	_, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"})
	if err == nil {
		t.Fatal("want error from protocol mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Errorf("error should mention protocol mismatch, got: %v", err)
	}
}

func TestNewJavaPlugin_ExplicitPathWins(t *testing.T) {
	p, err := NewJavaPlugin(WithJavaBinaryPath("/some/explicit/assay-plugin-java"))
	if err != nil {
		t.Fatalf("NewJavaPlugin: %v", err)
	}
	jp, ok := p.(*javaPlugin)
	if !ok {
		t.Fatalf("want *javaPlugin, got %T", p)
	}
	if jp.bin != "/some/explicit/assay-plugin-java" {
		t.Errorf("explicit path should win, got %q", jp.bin)
	}
}

// serveHelper is TestHelperProcess's "serve" mode: it answers each IndexSymbols request with this
// process's pid as the one symbol, or with Error for BuildDir "fail", one per line until stdin
// closes when JavaServeEnv is "1", and the first request only otherwise.
func serveHelper() {
	in := bufio.NewReader(os.Stdin)
	for {
		line, err := in.ReadBytes('\n')
		if len(line) > 0 {
			var req Request
			_ = json.Unmarshal(line, &req)
			resp := Response{Protocol: ProtocolVersion}
			if req.IndexSymbols != nil && req.IndexSymbols.BuildDir == "fail" {
				resp.Error = "canned hard error from helper"
			} else {
				resp.SymbolIndex = &SymbolIndexResult{Partiality: Complete(), Symbols: []Symbol{{SCIP: strconv.Itoa(os.Getpid())}}}
			}
			out, _ := json.Marshal(resp)
			os.Stdout.Write(append(out, '\n'))
		}
		if err != nil || os.Getenv(JavaServeEnv) != "1" {
			os.Exit(0)
		}
	}
}

// servedBy returns the pid of the process that answered an IndexSymbols request.
func servedBy(t *testing.T, p *javaPlugin, buildDir string) (string, error) {
	t.Helper()
	res, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: buildDir})
	if err != nil {
		return "", err
	}
	return res.Symbols[0].SCIP, nil
}

// WithJavaScanProcess sends every request to one kept process: a failed request is an error and
// the process goes on serving; after Close each request runs in a process of its own.
func TestJavaPlugin_ScanProcessServesEveryRequest(t *testing.T) {
	p := &javaPlugin{bin: helperCmd(t, "serve"), keep: true}
	p.scan = &scanProcess{bin: p.bin}
	t.Cleanup(func() { _ = p.Close() })

	first, err := servedBy(t, p, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := servedBy(t, p, "fail"); err == nil || !strings.Contains(err.Error(), "canned hard error from helper") {
		t.Fatalf("a failed request must be its error, got %v", err)
	}
	for range 2 {
		if pid, err := servedBy(t, p, "/x"); err != nil || pid != first {
			t.Fatalf("request served by %s (%v), want the kept process %s", pid, err, first)
		}
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	a, errA := servedBy(t, p, "/x")
	b, errB := servedBy(t, p, "/x")
	if errA != nil || errB != nil || a == first || a == b {
		t.Fatalf("after Close each request runs one-shot: got %s (%v), %s (%v), kept was %s", a, errA, b, errB, first)
	}
}

// A binary without serve mode answers one request and exits cleanly; the plugin then runs every
// request one-shot, and none fails.
func TestJavaPlugin_ScanProcessFallsBackForABinaryThatDoesNotServe(t *testing.T) {
	p := &javaPlugin{bin: helperCmd(t, "success"), keep: true}
	p.scan = &scanProcess{bin: p.bin}
	t.Cleanup(func() { _ = p.Close() })
	for i := range 3 {
		if _, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if !p.scan.off {
		t.Error("a binary that stops after one request must turn the kept process off")
	}
}
