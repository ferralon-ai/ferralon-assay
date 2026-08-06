package plugin

import (
	"context"
	"strings"
	"testing"
)

// These hermetic tests exercise the javaPlugin exec + newline-JSON/stdio
// transport WITHOUT the real tegron-plugin-java binary. They reuse the shared
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
	p, err := NewJavaPlugin(WithJavaBinaryPath("/some/explicit/tegron-plugin-java"))
	if err != nil {
		t.Fatalf("NewJavaPlugin: %v", err)
	}
	jp, ok := p.(*javaPlugin)
	if !ok {
		t.Fatalf("want *javaPlugin, got %T", p)
	}
	if jp.bin != "/some/explicit/tegron-plugin-java" {
		t.Errorf("explicit path should win, got %q", jp.bin)
	}
}
