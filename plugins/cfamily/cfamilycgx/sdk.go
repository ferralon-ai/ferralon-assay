package cfamilycgx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/cgx/sdk/go/cgx"
)

// OpenSDK is the Opener backed by the cgx Go SDK. The SDK's compile cache lives under
// cfg.CacheDir so the plugin writes nowhere else.
//
// The engine is verified again here, in the bytes the SDK is handed: the wasm module must be
// the one pinned beside the SDK version (PinnedWasmSHA256) and the native binary must match its
// configured pin. The native binary runs from a private copy hashed as it was written, so the
// bytes checked are the bytes run. The native process gets the SDK's minimal environment and nothing else of
// this process's. Engine-state failures come back wrapping ErrEngineUnconfigured,
// ErrEngineUnverified or ErrEngineMismatch so the lane declares them rather than failing.
func OpenSDK(ctx context.Context, repo string, cfg Config) (Graph, error) {
	if err := checkSDKBuild(); err != nil {
		return nil, err
	}
	opts := []cgx.Option{cgx.WithCacheDir(filepath.Join(cfg.CacheDir, "wazero"))}
	release := func() {}
	switch cfg.Transport {
	case TransportNative:
		bin, rel, err := privateNative(cfg)
		if err != nil {
			return nil, err
		}
		release = rel
		opts = append(opts, cgx.WithTransport(cgx.Native(bin)))
	default:
		opts = append(opts, cgx.WithTransport(cgx.Wasm()))
		if cfg.WasmModule != "" {
			if err := checkWasmPath(cfg); err != nil {
				return nil, err
			}
			mod, err := os.ReadFile(cfg.WasmModule)
			if err != nil {
				return nil, fmt.Errorf("%w: read wasm module: %v", ErrEngineUnconfigured, err)
			}
			sum := sha256.Sum256(mod)
			if err := checkWasmSum(cfg, hex.EncodeToString(sum[:])); err != nil {
				return nil, err
			}
			opts = append(opts, cgx.WithModule(mod))
		}
	}
	if cfg.PoolSize > 0 {
		opts = append(opts, cgx.WithPoolSize(cfg.PoolSize))
	}
	g, err := cgx.Open(ctx, repo, opts...)
	if err != nil {
		release()
		return nil, engineStateError(err)
	}
	return sdkGraph{g: g, release: release}, nil
}

// engineStateError maps the SDK's engine-state sentinels to this package's.
func engineStateError(err error) error {
	switch {
	case errors.Is(err, cgx.ErrNoEmbeddedModule):
		return fmt.Errorf("%w: %v", ErrEngineUnconfigured, err)
	case errors.Is(err, cgx.ErrABIMismatch), errors.Is(err, cgx.ErrSchemaMismatch):
		return fmt.Errorf("%w: %v", ErrEngineMismatch, err)
	}
	return err
}

type sdkGraph struct {
	g       *cgx.Graph
	release func() // removes the private native binary copy; a no-op otherwise
}

func (s sdkGraph) Index(ctx context.Context) error {
	_, err := s.g.Index(ctx)
	return engineFailure(err)
}

// engineFailure wraps an engine trap or exit as an *EngineFailure; other errors pass through.
func engineFailure(err error) error {
	var ee *cgx.EngineError
	switch {
	case errors.Is(err, cgx.ErrMemoryLimit):
		return &EngineFailure{Kind: EngineMemoryLimit, Err: err}
	case errors.As(err, &ee) && ee.Kind == cgx.KindTrap:
		return &EngineFailure{Kind: EngineTrap, Err: err}
	case errors.As(err, &ee) && ee.Kind == cgx.KindExit:
		return &EngineFailure{Kind: EngineExit, Err: err}
	}
	return engineStateError(err)
}

func (s sdkGraph) Call(ctx context.Context, tool string, args map[string]any) (json.RawMessage, error) {
	raw, err := s.g.Call(ctx, tool, args)
	var te *cgx.ToolError
	if errors.As(err, &te) {
		switch te.Kind {
		case cgx.KindResolve:
			return nil, fmt.Errorf("%w: %v", ErrUnresolved, err)
		case cgx.KindInvalidParams:
			return nil, fmt.Errorf("%w: %v", ErrRejected, err)
		}
	}
	if err != nil {
		return nil, engineStateError(err)
	}
	return raw, nil
}

func (s sdkGraph) Stats() json.RawMessage {
	b, err := json.Marshal(s.g.Stats())
	if err != nil {
		return nil
	}
	return b
}

// Close closes the graph, then removes the private native binary, which the SDK may restart
// from until then.
func (s sdkGraph) Close() error {
	err := s.g.Close()
	s.release()
	return err
}

// CacheKey verifies the engine cfg selects and names its build. Indexes are kept per key
// because cgx reuses cached extraction results without checking which build wrote them.
//
// It fails with ErrEngineUnconfigured when there is no engine to run (no module or binary, or
// one not given by absolute path or unreadable), ErrEngineUnverified when the native binary is
// unpinned or does not match its pin, and ErrEngineMismatch when the SDK in the build or the
// wasm module is not the pinned pair.
func CacheKey(cfg Config) (string, error) {
	if err := checkSDKBuild(); err != nil {
		return "", err
	}
	var sum string
	var err error
	switch {
	case cfg.Transport == TransportNative:
		sum, err = nativeSum(cfg)
	case cfg.WasmModule != "":
		if err = checkWasmPath(cfg); err == nil {
			if sum, err = fileSum(cfg.WasmModule); err == nil {
				err = checkWasmSum(cfg, sum)
			}
		}
	default:
		return embeddedKey(), nil
	}
	if err != nil {
		return "", err
	}
	return string(cfg.Transport) + "-" + sum[:16], nil
}

// embeddedKey names the engine embedded in the pinned SDK. The SDK at the pinned commit embeds
// none (opening it is ErrEngineUnconfigured); a later SDK that does carries its engine with its
// version, so the version names it.
func embeddedKey() string {
	sum := sha256.Sum256([]byte(SDKModule + "@" + PinnedSDKVersion))
	return "wasm-embedded-" + hex.EncodeToString(sum[:8])
}

// checkWasmPath refuses a module not given by absolute path, and a configured expectation that
// names a module other than the one pinned beside the SDK version (an engine from another
// commit), before the module is read.
func checkWasmPath(cfg Config) error {
	if !filepath.IsAbs(cfg.WasmModule) {
		return fmt.Errorf("%w: the cgx wasm module must be given by absolute path, got %q", ErrEngineUnconfigured, cfg.WasmModule)
	}
	if want := strings.ToLower(strings.TrimSpace(cfg.WasmModuleSHA256)); want != "" && want != PinnedWasmSHA256 {
		return fmt.Errorf("%w: the configured cgx wasm sha256 %s is not the module pinned with SDK %s (%s)", ErrEngineMismatch, want, PinnedSDKVersion, PinnedWasmSHA256)
	}
	return nil
}

// checkWasmSum refuses a module other than the one pinned beside the SDK version.
func checkWasmSum(cfg Config, got string) error {
	if got != PinnedWasmSHA256 {
		return fmt.Errorf("%w: cgx wasm module %s has sha256 %s; SDK %s is pinned with %s", ErrEngineMismatch, cfg.WasmModule, got, PinnedSDKVersion, PinnedWasmSHA256)
	}
	return nil
}

// nativeSum returns the SHA-256 of the native cgx binary, checked against its pin. A native
// binary is a build of its own, so it carries its own pin rather than PinnedWasmSHA256; the SDK
// still refuses one that speaks another ABI or schema (ErrEngineMismatch at open).
func nativeSum(cfg Config) (string, error) {
	if err := checkNativePath(cfg); err != nil {
		return "", err
	}
	sum, err := fileSum(cfg.CgxBin)
	if err != nil {
		return "", err
	}
	return sum, checkNativeSum(cfg, sum)
}

func checkNativePath(cfg Config) error {
	if cfg.CgxBin == "" {
		return fmt.Errorf("%w: native transport with no cgx binary", ErrEngineUnconfigured)
	}
	if !filepath.IsAbs(cfg.CgxBin) {
		return fmt.Errorf("%w: the cgx binary must be given by absolute path (it is never looked up on PATH), got %q", ErrEngineUnconfigured, cfg.CgxBin)
	}
	return nil
}

func checkNativeSum(cfg Config, sum string) error {
	want := strings.ToLower(strings.TrimSpace(cfg.CgxBinSHA256))
	switch {
	case want == "":
		return fmt.Errorf("%w: cgx native binary %s has no pinned sha256", ErrEngineUnverified, cfg.CgxBin)
	case sum != want:
		return fmt.Errorf("%w: cgx native binary %s has sha256 %s, pinned %s", ErrEngineUnverified, cfg.CgxBin, sum, want)
	}
	return nil
}

// privateNative copies the native cgx binary into a new directory under cfg.CacheDir, hashing
// the bytes as it writes them, and checks that hash against the pin. The copy is read-only and
// its directory private to this user, so replacing the configured binary after the check cannot
// change what runs. release removes the copy and its directory.
func privateNative(cfg Config) (bin string, release func(), err error) {
	if err := checkNativePath(cfg); err != nil {
		return "", nil, err
	}
	src, err := os.Open(cfg.CgxBin)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrEngineUnconfigured, err)
	}
	defer src.Close()
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("%w: cgx binary copy: %v", ErrEngineUnconfigured, err)
	}
	dir, err := os.MkdirTemp(cfg.CacheDir, "cgx-bin-")
	if err != nil {
		return "", nil, fmt.Errorf("%w: cgx binary copy: %v", ErrEngineUnconfigured, err)
	}
	bin = filepath.Join(dir, "cgx")
	release = func() {
		_ = os.Remove(bin)
		_ = os.Remove(dir)
	}
	fail := func(err error) (string, func(), error) {
		release()
		return "", nil, err
	}
	dst, err := os.OpenFile(bin, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return fail(fmt.Errorf("%w: cgx binary copy: %v", ErrEngineUnconfigured, err))
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(dst, h), src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(fmt.Errorf("%w: cgx binary copy: %v", ErrEngineUnconfigured, err))
	}
	if err := checkNativeSum(cfg, hex.EncodeToString(h.Sum(nil))); err != nil {
		return fail(err)
	}
	if err := os.Chmod(bin, 0o500); err != nil {
		return fail(fmt.Errorf("%w: cgx binary copy: %v", ErrEngineUnconfigured, err))
	}
	return bin, release, nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEngineUnconfigured, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("%w: %v", ErrEngineUnconfigured, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// memoryLimitKey names the wasm linear-memory ceiling. The lane leaves it at the SDK's default,
// so the pinned SDK version identifies it.
func memoryLimitKey() string { return "sdk-default@" + PinnedSDKVersion }
