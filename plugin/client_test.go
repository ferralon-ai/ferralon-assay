package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These hermetic tests exercise the exec + newline-JSON/stdio transport WITHOUT the real
// assay-plugin-go binary, network, or govulncheck. The pattern is the standard
// TestHelperProcess re-exec: each test points goPlugin at this test binary itself, with
// an env flag that makes TestHelperProcess read the Request and emit a CANNED Response.
// The env vars select the canned behavior.

const (
	helperModeEnv = "GO_PLUGIN_HELPER_MODE"
	helperFlag    = "GO_WANT_HELPER_PROCESS"
)

// newHelperPlugin returns a goPlugin that re-execs this test binary into
// TestHelperProcess with the given canned mode.
func newHelperPlugin(t *testing.T, mode string) *goPlugin {
	t.Helper()
	return &goPlugin{bin: helperCmd(t, mode)}
}

// helperCmd builds the argv0 + env trick by writing a tiny wrapper: we cannot set per-exec
// env on goPlugin directly, so we resolve the test binary path and rely on env inheritance.
// goPlugin uses exec.CommandContext(ctx, p.bin); we set p.bin to the test binary and pass
// the mode through the process environment, which the child inherits.
func helperCmd(t *testing.T, mode string) string {
	t.Helper()
	// Set the env on the current process so the re-exec'd child inherits it. Each test
	// runs serially (no t.Parallel), so this is safe.
	os.Setenv(helperFlag, "1")
	os.Setenv(helperModeEnv, mode)
	t.Cleanup(func() {
		os.Unsetenv(helperFlag)
		os.Unsetenv(helperModeEnv)
	})
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

// TestHelperProcess is not a real test: when GO_WANT_HELPER_PROCESS=1 it acts as the
// assay-plugin-go subprocess, reading one Request and writing one canned Response per the
// GO_PLUGIN_HELPER_MODE env var. Run only as a re-exec child.
func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperFlag) != "1" {
		return
	}
	mode := os.Getenv(helperModeEnv)

	line, _ := bufio.NewReader(os.Stdin).ReadBytes('\n')
	var req Request
	_ = json.Unmarshal(line, &req)

	var resp Response
	resp.Protocol = ProtocolVersion

	switch mode {
	case "success":
		resp.SymbolIndex = &SymbolIndexResult{
			Partiality: Complete(),
			Symbols:    []Symbol{{SCIP: "scip:helper#Foo", DisplayName: "h.Foo", Package: "h"}},
		}
	case "error":
		resp.Error = "canned hard error from helper"
	case "nonzero":
		// Write nothing parseable, then exit non-zero — pure transport/exit failure.
		fmt.Fprintln(os.Stderr, "helper crashing on purpose")
		os.Exit(3)
	case "partial":
		resp.Reachability = &ReachabilityResult{
			Partiality: Partial(PartialReasonDynamicDispatch),
			Paths: []ReachPath{
				{
					Sink:    Symbol{Kind: SymbolKindFunction, Package: "example.com/dep", Name: "V", SCIP: "scip:vuln#V"},
					Ingress: Symbol{Kind: SymbolKindFunction, Package: "example.com/helper", Name: "main", SCIP: "scip:helper#main"},
					Trace: []Symbol{
						{Kind: SymbolKindFunction, Package: "example.com/helper", Name: "main", SCIP: "scip:helper#main"},
						{Kind: SymbolKindFunction, Package: "example.com/dep", Name: "V", SCIP: "scip:vuln#V"},
					},
				},
			},
		}
	case "badproto":
		resp.Protocol = "tegron.plugin.vBOGUS"
		resp.SymbolIndex = &SymbolIndexResult{Partiality: Complete()}
	default:
		resp.Error = "unknown helper mode: " + mode
	}

	out, _ := json.Marshal(resp)
	out = append(out, '\n')
	os.Stdout.Write(out)
	os.Exit(0)
}

func TestGoPlugin_SuccessReturnsDecodedPayload(t *testing.T) {
	p := newHelperPlugin(t, "success")
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

func TestGoPlugin_ResponseErrorIsWrappedGoError(t *testing.T) {
	p := newHelperPlugin(t, "error")
	_, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"})
	if err == nil {
		t.Fatal("want error from Response.Error, got nil")
	}
	if !strings.Contains(err.Error(), "canned hard error from helper") {
		t.Errorf("error should wrap Response.Error, got: %v", err)
	}
}

func TestGoPlugin_NonZeroExitIsError(t *testing.T) {
	p := newHelperPlugin(t, "nonzero")
	_, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"})
	if err == nil {
		t.Fatal("want error from non-zero exit, got nil")
	}
}

func TestGoPlugin_PartialSuccessReturnsResultNoError(t *testing.T) {
	p := newHelperPlugin(t, "partial")
	res, err := p.Reachability(context.Background(), ReachabilityRequest{BuildDir: "/x", VulnID: "GO-X"})
	if err != nil {
		t.Fatalf("partial-but-successful payload must return (result, nil), got err: %v", err)
	}
	if res.Partiality.Complete {
		t.Errorf("want Complete=false for partial payload, got %+v", res.Partiality)
	}
	if len(res.Paths) != 1 {
		t.Errorf("want 1 reach path, got %d", len(res.Paths))
	}
}

func TestGoPlugin_ProtocolMismatchIsError(t *testing.T) {
	p := newHelperPlugin(t, "badproto")
	_, err := p.IndexSymbols(context.Background(), IndexSymbolsRequest{BuildDir: "/x"})
	if err == nil {
		t.Fatal("want error from protocol mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "protocol") {
		t.Errorf("error should mention protocol mismatch, got: %v", err)
	}
}

func TestNewGoPlugin_ExplicitPathWins(t *testing.T) {
	p, err := NewGoPlugin(WithBinaryPath("/some/explicit/assay-plugin-go"))
	if err != nil {
		t.Fatalf("NewGoPlugin: %v", err)
	}
	gp, ok := p.(*goPlugin)
	if !ok {
		t.Fatalf("want *goPlugin, got %T", p)
	}
	if gp.bin != "/some/explicit/assay-plugin-go" {
		t.Errorf("explicit path should win, got %q", gp.bin)
	}
}

func TestBinaryName(t *testing.T) {
	for _, tc := range []struct {
		language string
		want     string
	}{
		{"go", "assay-plugin-go"},
		{"java", "assay-plugin-java"},
		{"kotlin", "assay-plugin-kotlin"},
		{"js", "assay-plugin-js"},
		{"python", "assay-plugin-python"},
		{"dotnet", "assay-plugin-dotnet"},
	} {
		if got := BinaryName(tc.language); got != tc.want {
			t.Errorf("BinaryName(%q) = %q, want %q", tc.language, got, tc.want)
		}
	}
}

// TestConstructorsDiscoverBinaryName pins that every client resolves exactly BinaryName(language)
// on PATH: a caller that stages the binary under that name is found, and a miss names it.
func TestConstructorsDiscoverBinaryName(t *testing.T) {
	for _, tc := range []struct {
		language string
		ctor     func() (LanguagePlugin, error)
	}{
		{"go", func() (LanguagePlugin, error) { return NewGoPlugin() }},
		{"java", func() (LanguagePlugin, error) { return NewJavaPlugin() }},
		{"kotlin", func() (LanguagePlugin, error) { return NewKotlinPlugin() }},
		{"js", func() (LanguagePlugin, error) { return NewJSPlugin() }},
		{"python", func() (LanguagePlugin, error) { return NewPythonPlugin() }},
		{"dotnet", func() (LanguagePlugin, error) { return NewDotNetPlugin() }},
	} {
		t.Run(tc.language, func(t *testing.T) {
			name := BinaryName(tc.language)

			t.Setenv("PATH", t.TempDir())
			_, err := tc.ctor()
			if err == nil {
				t.Fatalf("constructor succeeded with no %s on PATH", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("discovery error does not name %s: %v", name, err)
			}

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			p, err := tc.ctor()
			if err != nil {
				t.Fatalf("constructor did not find %s on PATH: %v", name, err)
			}
			if got := p.Language(); got != tc.language {
				t.Errorf("Language() = %q, want %q", got, tc.language)
			}
		})
	}
}
