package pythoncgx

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

	"github.com/ferralon-ai/cgx/sdk/go/cgx"
)

func sum(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestCacheKey_FollowsTheEngineBytes(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "cgx")
	if err := os.WriteFile(bin, []byte("build one"), 0o755); err != nil {
		t.Fatal(err)
	}
	k1, err := CacheKey(Config{Transport: TransportNative, CgxBin: bin, CgxBinSHA256: sum(t, bin)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(k1, "native-") {
		t.Errorf("native key %q lacks its transport prefix", k1)
	}
	if err := os.WriteFile(bin, []byte("build two"), 0o755); err != nil {
		t.Fatal(err)
	}
	k2, err := CacheKey(Config{Transport: TransportNative, CgxBin: bin, CgxBinSHA256: strings.ToUpper(sum(t, bin))})
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
	kw, err := CacheKey(Config{Transport: TransportWasm, WasmModule: mod, WasmModuleSHA256: sum(t, mod)})
	if err != nil {
		t.Fatal(err)
	}
	if kw == k1 || !strings.HasPrefix(kw, "wasm-") {
		t.Errorf("wasm key %q must differ from the native key for the same bytes", kw)
	}
}

func TestCacheKey_Errors(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "cgx")
	if err := os.WriteFile(bin, []byte("build"), 0o755); err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(dir, "cgx.wasm")
	if err := os.WriteFile(mod, []byte("module"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("0", 64)
	// A cgx on PATH must not be found: the native transport takes only an absolute path.
	pathDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pathDir, "cgx"), []byte("build"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)
	for _, tc := range []struct {
		name string
		cfg  Config
		want error
	}{
		{"native, no binary", Config{Transport: TransportNative, CgxBinSHA256: sum(t, bin)}, ErrNativeBinPath},
		{"native, relative binary", Config{Transport: TransportNative, CgxBin: "cgx", CgxBinSHA256: sum(t, bin)}, ErrNativeBinPath},
		{"native, missing binary", Config{Transport: TransportNative, CgxBin: filepath.Join(dir, "absent"), CgxBinSHA256: other}, os.ErrNotExist},
		{"native, unpinned", Config{Transport: TransportNative, CgxBin: bin}, ErrEngineUnverified},
		{"native, wrong pin", Config{Transport: TransportNative, CgxBin: bin, CgxBinSHA256: other}, ErrEngineUnverified},
		{"wasm file, unpinned", Config{Transport: TransportWasm, WasmModule: mod}, ErrEngineUnverified},
		{"wasm file, wrong pin", Config{Transport: TransportWasm, WasmModule: mod, WasmModuleSHA256: other}, ErrEngineUnverified},
		// The native pin does not stand in for the module's.
		{"wasm file, native pin only", Config{Transport: TransportWasm, WasmModule: mod, CgxBinSHA256: sum(t, mod)}, ErrEngineUnverified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CacheKey(tc.cfg)
			if !errors.Is(err, tc.want) {
				t.Fatalf("CacheKey = %v, want %v", err, tc.want)
			}
			if tc.want == ErrEngineUnverified && !strings.HasPrefix(err.Error(), reasonEngineUnverified+": ") {
				t.Errorf("error %q does not lead with %s", err, reasonEngineUnverified)
			}
		})
	}
}

// OpenSDK re-checks the pin on the bytes it hands the SDK, so a module swapped after CacheKey
// read it is not run.
func TestOpenSDK_ChecksTheWasmModuleItRuns(t *testing.T) {
	mod := filepath.Join(t.TempDir(), "cgx.wasm")
	if err := os.WriteFile(mod, []byte("module one"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Transport: TransportWasm, WasmModule: mod, WasmModuleSHA256: sum(t, mod), CacheDir: t.TempDir()}
	if _, err := CacheKey(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mod, []byte("module two"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSDK(context.Background(), t.TempDir(), cfg); !errors.Is(err, ErrEngineUnverified) {
		t.Fatalf("OpenSDK on a swapped module = %v, want ErrEngineUnverified", err)
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

// The native binary is checked against its pin when it is opened, not only when the lane is
// configured.
func TestOpenSDK_ChecksTheNativeBinaryItRuns(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "cgx")
	if err := os.WriteFile(bin, []byte("build one"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Transport: TransportNative, CgxBin: bin, CgxBinSHA256: sum(t, bin), CacheDir: t.TempDir()}
	if err := os.WriteFile(bin, []byte("build two"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSDK(context.Background(), t.TempDir(), cfg); !errors.Is(err, ErrEngineUnverified) {
		t.Fatalf("OpenSDK on a swapped binary = %v, want ErrEngineUnverified", err)
	}
}
