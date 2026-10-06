package pythoncgx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
