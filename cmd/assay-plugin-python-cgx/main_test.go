package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythoncgx"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestNewLane_RejectsBadConfiguration(t *testing.T) {
	for _, tc := range []struct{ key, value, want string }{
		{envTransport, "nativ", envTransport},
		{envMinConfidence, "likely", envMinConfidence},
		{envPoolSize, "0", envPoolSize},
		{envPoolSize, "many", envPoolSize},
		{envFallback, "wasm", envFallback},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(envCacheDir, t.TempDir())
			t.Setenv(tc.key, tc.value)
			if _, err := newLane(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("newLane: err = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

// The non-graph operations never reach the lane: they are the lexical analyzer's answers.
func TestDispatch_DelegatedOperations(t *testing.T) {
	ctx := context.Background()
	resp, err := dispatch(ctx, nil, plugin.Request{Op: plugin.OpCapabilityManifest})
	if err != nil || resp.Manifest == nil || resp.Manifest.Language != "python" || resp.Manifest.Supported {
		t.Fatalf("capability_manifest = %+v, %v", resp.Manifest, err)
	}
	resp, err = dispatch(ctx, nil, plugin.Request{Op: plugin.OpGenerateHarness, GenerateHarness: &plugin.GenerateHarnessRequest{}})
	if err != nil || resp.Harness == nil || resp.Harness.Partiality.Complete {
		t.Fatalf("generate_harness = %+v, %v; want Unsupported", resp.Harness, err)
	}
	if _, err := dispatch(ctx, nil, plugin.Request{Op: plugin.OpCallGraph}); err == nil {
		t.Error("call_graph with no payload: want error")
	}
	if _, err := dispatch(ctx, nil, plugin.Request{Op: "nope"}); err == nil {
		t.Error("unknown op: want error")
	}
}

func TestNewLane_FallbackNeedsTheNativeBinary(t *testing.T) {
	module := filepath.Join(t.TempDir(), "cgx.wasm")
	if err := os.WriteFile(module, []byte("module"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envCacheDir, t.TempDir())
	t.Setenv(envTransport, "wasm")
	t.Setenv(envWasm, module)
	t.Setenv(envFallback, "native")
	t.Setenv(envBin, filepath.Join(t.TempDir(), "absent-cgx"))
	if _, err := newLane(); err == nil || !strings.Contains(err.Error(), envFallback) {
		t.Fatalf("newLane: err = %v, want an error naming %s", err, envFallback)
	}
	t.Setenv(envBin, module)
	if _, err := newLane(); err != nil {
		t.Fatalf("newLane with a fallback binary: %v", err)
	}
}

func TestWithRemedy_NamesTheConfiguration(t *testing.T) {
	plain := errors.New("boom")
	if got := withRemedy(plain); got != plain {
		t.Errorf("withRemedy(non-index error) = %v, want it unchanged", got)
	}
	f := &pythoncgx.IndexFailure{Transport: pythoncgx.TransportWasm, Tree: "abc", Kind: pythoncgx.EngineMemoryLimit, Detail: "limit"}
	got := withRemedy(fmt.Errorf("op: %w", f))
	for _, want := range []string{"tool_failure:cgx_index_failed", envTransport + "=native", envBin, envFallback + "=native"} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("withRemedy = %q, want it to contain %q", got, want)
		}
	}
	if !errors.As(got, &f) {
		t.Error("withRemedy dropped the IndexFailure from the chain")
	}
}
