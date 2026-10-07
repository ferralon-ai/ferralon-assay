package pythoncgx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/cgx/sdk/go/cgx"
)

func TestCacheKey_FollowsTheEngineBytes(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "cgx")
	if err := os.WriteFile(bin, []byte("build one"), 0o755); err != nil {
		t.Fatal(err)
	}
	k1, err := CacheKey(Config{Transport: TransportNative, CgxBin: bin})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(k1, "native-") {
		t.Errorf("native key %q lacks its transport prefix", k1)
	}
	if err := os.WriteFile(bin, []byte("build two"), 0o755); err != nil {
		t.Fatal(err)
	}
	k2, err := CacheKey(Config{Transport: TransportNative, CgxBin: bin})
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Error("a different cgx binary must get a different cache key")
	}

	mod := filepath.Join(dir, "cgx.wasm")
	if err := os.WriteFile(mod, []byte("build one"), 0o644); err != nil {
		t.Fatal(err)
	}
	kw, err := CacheKey(Config{Transport: TransportWasm, WasmModule: mod})
	if err != nil {
		t.Fatal(err)
	}
	if kw == k1 || !strings.HasPrefix(kw, "wasm-") {
		t.Errorf("wasm key %q must differ from the native key for the same bytes", kw)
	}
}

func TestCacheKey_Errors(t *testing.T) {
	if _, err := CacheKey(Config{Transport: TransportNative, CgxBin: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Error("missing native binary: want error")
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := CacheKey(Config{Transport: TransportNative}); err == nil {
		t.Error("native transport with no cgx on PATH: want error")
	}
}

func TestEngineFailure_ClassifiesTheSDKErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want EngineFailureKind
	}{
		{&cgx.EngineError{Transport: "wasm", Op: "cgx_index_finish", Kind: cgx.KindTrap, Err: fmt.Errorf("%w: at peak 3857 MiB", cgx.ErrMemoryLimit)}, EngineMemoryLimit},
		{&cgx.EngineError{Transport: "wasm", Op: "cgx_extract", Kind: cgx.KindTrap, Err: errors.New("unreachable")}, EngineTrap},
		{&cgx.EngineError{Transport: "native", Op: "index", Kind: cgx.KindExit, Err: errors.New("signal: killed")}, EngineExit},
		{&cgx.EngineError{Transport: "native", Op: "index", Kind: cgx.KindInternal, Err: errors.New("lock timeout")}, ""},
		{errors.New("plain"), ""},
	} {
		var f *EngineFailure
		got := engineFailure(tc.err)
		if ok := errors.As(got, &f); ok != (tc.want != "") || (ok && f.Kind != tc.want) {
			t.Errorf("engineFailure(%v) = %v, want kind %q", tc.err, got, tc.want)
		}
		if !errors.Is(got, tc.err) {
			t.Errorf("engineFailure(%v) dropped the SDK error from the chain", tc.err)
		}
	}
	if engineFailure(nil) != nil {
		t.Error("engineFailure(nil) != nil")
	}
}
