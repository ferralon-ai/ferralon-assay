package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
		{envFailureTTL, "soon", envFailureTTL},
		{envFailureTTL, "-1m", envFailureTTL},
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

func digest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestNewLane_FallbackNeedsTheNativeBinary(t *testing.T) {
	module := filepath.Join(t.TempDir(), "cgx.wasm")
	if err := os.WriteFile(module, []byte("module"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envCacheDir, t.TempDir())
	t.Setenv(envTransport, "wasm")
	t.Setenv(envWasm, module)
	t.Setenv(envWasmSHA256, digest(t, module))
	t.Setenv(envFallback, "native")
	t.Setenv(envBin, filepath.Join(t.TempDir(), "absent-cgx"))
	if _, err := newLane(); err == nil || !strings.Contains(err.Error(), envFallback) {
		t.Fatalf("newLane: err = %v, want an error naming %s", err, envFallback)
	}
	t.Setenv(envBin, module)
	t.Setenv(envBinSHA256, digest(t, module))
	if _, err := newLane(); err != nil {
		t.Fatalf("newLane with a fallback binary: %v", err)
	}
}

func TestNewLane_EngineFilesArePinned(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "cgx")
	if err := os.WriteFile(bin, []byte("build"), 0o755); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(dir, "cgx.wasm")
	if err := os.WriteFile(module, []byte("module"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A cgx on PATH is never used.
	t.Setenv("PATH", dir)
	other := strings.Repeat("0", 64)
	for _, tc := range []struct {
		name      string
		env       map[string]string
		baked     string   // bakedCgxBinSHA256
		bakedWasm string   // bakedCgxWasmSHA256
		wantErr   []string // nil: newLane succeeds
	}{
		{name: "native without a binary", env: map[string]string{envTransport: "native", envBinSHA256: digest(t, bin)},
			wantErr: []string{"absolute path", envBin}},
		{name: "native with a relative binary", env: map[string]string{envTransport: "native", envBin: "cgx", envBinSHA256: digest(t, bin)},
			wantErr: []string{"absolute path", envBin}},
		{name: "native unpinned", env: map[string]string{envTransport: "native", envBin: bin},
			wantErr: []string{"tool_failure:cgx_engine_unverified", "no pinned sha256", envBinSHA256}},
		{name: "native mismatch", env: map[string]string{envTransport: "native", envBin: bin, envBinSHA256: other},
			wantErr: []string{"tool_failure:cgx_engine_unverified", digest(t, bin), envBinSHA256}},
		{name: "native baked pin", env: map[string]string{envTransport: "native", envBin: bin}, baked: digest(t, bin)},
		{name: "native environment pin overrides the baked one", env: map[string]string{envTransport: "native", envBin: bin, envBinSHA256: other},
			baked: digest(t, bin), wantErr: []string{"tool_failure:cgx_engine_unverified"}},
		{name: "wasm file unpinned", env: map[string]string{envWasm: module},
			wantErr: []string{"tool_failure:cgx_engine_unverified", envWasmSHA256}},
		{name: "wasm file baked pin", env: map[string]string{envWasm: module}, bakedWasm: digest(t, module)},
		{name: "wasm file mismatch", env: map[string]string{envWasm: module, envWasmSHA256: other},
			wantErr: []string{"tool_failure:cgx_engine_unverified"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{envTransport, envBin, envBinSHA256, envWasm, envWasmSHA256} {
				t.Setenv(k, "")
			}
			t.Setenv(envCacheDir, t.TempDir())
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			bakedCgxBinSHA256, bakedCgxWasmSHA256 = tc.baked, tc.bakedWasm
			t.Cleanup(func() { bakedCgxBinSHA256, bakedCgxWasmSHA256 = "", "" })
			_, err := newLane()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("newLane: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("newLane: want an error")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("newLane: err = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// A plain build bakes no pins; the release recipe sets them with -X.
func TestBakedPinsAreEmptyInAPlainBuild(t *testing.T) {
	if bakedCgxBinSHA256 != "" || bakedCgxWasmSHA256 != "" {
		t.Fatalf("baked pins must be empty in an unstamped build, got bin=%q wasm=%q", bakedCgxBinSHA256, bakedCgxWasmSHA256)
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
