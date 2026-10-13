package cfamilycgx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// The SDK version go.mod requires is the one the engine pin names: a re-pin that moves one
// without the other fails here.
func TestPinnedSDKVersion_MatchesGoMod(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require"))
		if len(f) >= 2 && f[0] == SDKModule {
			got = f[1]
		}
	}
	if got != PinnedSDKVersion {
		t.Errorf("go.mod requires %s %q; PinnedSDKVersion is %q", SDKModule, got, PinnedSDKVersion)
	}
	if strings.Contains(string(b), "replace "+SDKModule) || strings.Contains(string(b), "\t"+SDKModule+" =>") {
		t.Errorf("go.mod replaces %s; the pin must resolve to the published pseudo-version", SDKModule)
	}
}

func withBuildInfo(t *testing.T, info *debug.BuildInfo, ok bool) {
	t.Helper()
	prev := readBuildInfo
	readBuildInfo = func() (*debug.BuildInfo, bool) { return info, ok }
	t.Cleanup(func() { readBuildInfo = prev })
}

func TestCheckSDKBuild(t *testing.T) {
	pinned := &debug.Module{Path: SDKModule, Version: PinnedSDKVersion}
	for _, c := range []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want error
	}{
		{"pinned", &debug.BuildInfo{Deps: []*debug.Module{pinned}}, true, nil},
		{"no_build_info", nil, false, ErrEngineMismatch},
		{"other_version", &debug.BuildInfo{Deps: []*debug.Module{{Path: SDKModule, Version: "v0.0.0-20990101000000-000000000000"}}}, true, ErrEngineMismatch},
		{"replaced", &debug.BuildInfo{Deps: []*debug.Module{{Path: SDKModule, Version: PinnedSDKVersion, Replace: &debug.Module{Path: "../cgx/sdk/go"}}}}, true, ErrEngineMismatch},
		{"missing", &debug.BuildInfo{}, true, ErrEngineMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			withBuildInfo(t, c.info, c.ok)
			err := checkSDKBuild()
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Errorf("checkSDKBuild() = %v, want %v", err, c.want)
			}
		})
	}
}

func writeFile(t *testing.T, content string) (path, sum string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "engine")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(s[:])
}

// CacheKey verifies the engine before anything runs: the wasm module must be the one pinned
// beside the SDK version, the native binary must match its own pin, and every engine path must
// be absolute. Each refusal is an engine-state error the lane declares, never a crash.
func TestCacheKey_EngineVerification(t *testing.T) {
	withBuildInfo(t, &debug.BuildInfo{Deps: []*debug.Module{{Path: SDKModule, Version: PinnedSDKVersion}}}, true)
	notPinned, notPinnedSum := writeFile(t, "not the pinned module")
	for _, c := range []struct {
		name string
		cfg  Config
		want error
	}{
		{"embedded", Config{Transport: TransportWasm}, nil},
		{"wasm_relative", Config{Transport: TransportWasm, WasmModule: "cgx.wasm"}, ErrEngineUnconfigured},
		{"wasm_missing", Config{Transport: TransportWasm, WasmModule: "/nonexistent/cgx.wasm"}, ErrEngineUnconfigured},
		{"wasm_other_commit", Config{Transport: TransportWasm, WasmModule: notPinned}, ErrEngineMismatch},
		{"wasm_env_pin_other_commit", Config{Transport: TransportWasm, WasmModule: notPinned, WasmModuleSHA256: notPinnedSum}, ErrEngineMismatch},
		{"native_no_bin", Config{Transport: TransportNative}, ErrEngineUnconfigured},
		{"native_relative", Config{Transport: TransportNative, CgxBin: "cgx"}, ErrEngineUnconfigured},
		{"native_unpinned", Config{Transport: TransportNative, CgxBin: notPinned}, ErrEngineUnverified},
		{"native_wrong_pin", Config{Transport: TransportNative, CgxBin: notPinned, CgxBinSHA256: strings.Repeat("0", 64)}, ErrEngineUnverified},
		{"native_pinned", Config{Transport: TransportNative, CgxBin: notPinned, CgxBinSHA256: strings.ToUpper(notPinnedSum)}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, err := CacheKey(c.cfg)
			if c.want == nil {
				if err != nil || key == "" {
					t.Errorf("CacheKey = %q, %v", key, err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Errorf("CacheKey err = %v, want %v", err, c.want)
			}
			if engineReason(err) == "" {
				t.Errorf("%v declares no engine-state reason", err)
			}
		})
	}

	// A wrong SDK in the build refuses every engine.
	withBuildInfo(t, &debug.BuildInfo{}, true)
	if _, err := CacheKey(Config{Transport: TransportWasm}); !errors.Is(err, ErrEngineMismatch) {
		t.Errorf("CacheKey with no SDK in the build: %v", err)
	}
	l := NewSDK(Config{Transport: TransportWasm})
	if !errors.Is(l.unavailable, ErrEngineMismatch) {
		t.Errorf("NewSDK unavailable = %v, want a mismatch", l.unavailable)
	}
}

// The native binary runs from a private, read-only copy checked as it was written: replacing
// the configured binary after the check cannot change what runs, a copy that fails its pin is
// never left behind, and release removes the copy and its directory.
func TestPrivateNative_RunsTheBytesItChecked(t *testing.T) {
	bin, sum := writeFile(t, "pinned engine")
	cache := t.TempDir()
	cfg := Config{Transport: TransportNative, CgxBin: bin, CgxBinSHA256: sum, CacheDir: cache}

	copied, release, err := privateNative(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(copied, cache+string(filepath.Separator)) {
		t.Errorf("copy %s is not under the cache dir %s", copied, cache)
	}
	if err := os.WriteFile(bin, []byte("swapped after the check"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(copied); err != nil || string(got) != "pinned engine" {
		t.Errorf("copy holds %q, %v; want the checked bytes", got, err)
	}
	for path, want := range map[string]os.FileMode{copied: 0o500, filepath.Dir(copied): 0o700} {
		if fi, err := os.Stat(path); err != nil {
			t.Error(err)
		} else if fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
	release()
	if _, err := os.Stat(filepath.Dir(copied)); !os.IsNotExist(err) {
		t.Errorf("release left %s: %v", filepath.Dir(copied), err)
	}

	// The configured binary now differs from its pin: refused, nothing left in the cache dir.
	if _, _, err := privateNative(cfg); !errors.Is(err, ErrEngineUnverified) {
		t.Errorf("privateNative after the swap = %v, want ErrEngineUnverified", err)
	}
	if ents, err := os.ReadDir(cache); err != nil || len(ents) != 0 {
		t.Errorf("cache dir holds %v, %v after a refused copy", ents, err)
	}
}
