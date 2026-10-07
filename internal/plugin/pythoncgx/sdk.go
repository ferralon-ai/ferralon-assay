package pythoncgx

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
	"runtime/debug"
	"strings"

	"github.com/ferralon-ai/cgx/sdk/go/cgx"
)

// sdkModule is the cgx SDK's module path, for identifying the embedded engine in CacheKey.
const sdkModule = "github.com/ferralon-ai/cgx/sdk/go"

// OpenSDK is the Opener backed by the cgx Go SDK. The SDK's compile cache lives under
// cfg.CacheDir so the plugin writes nowhere else.
//
// An engine file the configuration names is checked against its pinned SHA-256 here, before
// the SDK runs it: the native binary is hashed again on every open, and the wasm module is
// hashed in the same bytes the SDK is handed. The native process gets the SDK's minimal
// environment (PATH, TMPDIR and git's no-fetch settings) and nothing else of this process's.
func OpenSDK(ctx context.Context, repo string, cfg Config) (Graph, error) {
	opts := []cgx.Option{cgx.WithCacheDir(filepath.Join(cfg.CacheDir, "wazero"))}
	switch cfg.Transport {
	case TransportNative:
		if _, err := nativeSum(cfg); err != nil {
			return nil, err
		}
		opts = append(opts, cgx.WithTransport(cgx.Native(cfg.CgxBin)))
	default:
		opts = append(opts, cgx.WithTransport(cgx.Wasm()))
		if cfg.WasmModule != "" {
			mod, err := os.ReadFile(cfg.WasmModule)
			if err != nil {
				return nil, fmt.Errorf("pythoncgx: read wasm module: %w", err)
			}
			sum := sha256.Sum256(mod)
			if err := checkPin("wasm module", cfg.WasmModule, hex.EncodeToString(sum[:]), cfg.WasmModuleSHA256); err != nil {
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
		return nil, err
	}
	return sdkGraph{g}, nil
}

type sdkGraph struct{ g *cgx.Graph }

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
	return err
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
	return raw, err
}

func (s sdkGraph) Stats() json.RawMessage {
	b, err := json.Marshal(s.g.Stats())
	if err != nil {
		return nil
	}
	return b
}

func (s sdkGraph) Close() error { return s.g.Close() }

// ErrEngineUnverified is returned for an engine file the configuration names whose SHA-256 is
// not pinned or does not match the pin. Its text is the tool_failure reason code.
var ErrEngineUnverified = errors.New(reasonEngineUnverified)

// ErrNativeBinPath is returned when the native transport's cgx binary is not an absolute path.
var ErrNativeBinPath = errors.New("pythoncgx: native transport: the cgx binary must be given by absolute path (it is never looked up on PATH)")

// CacheKey names the cgx build cfg selects: the SHA-256 of the native binary or of the wasm
// module file, or the SDK module version whose embedded engine is used. Indexes are kept per
// key because cgx reuses cached extraction results without checking which build wrote them.
// A named engine file must match its pinned SHA-256 (ErrEngineUnverified otherwise), and the
// native binary must be named by an absolute path: there is no PATH lookup.
func CacheKey(cfg Config) (string, error) {
	var sum string
	var err error
	switch {
	case cfg.Transport == TransportNative:
		sum, err = nativeSum(cfg)
	case cfg.WasmModule != "":
		if sum, err = fileSum(cfg.WasmModule); err == nil {
			err = checkPin("wasm module", cfg.WasmModule, sum, cfg.WasmModuleSHA256)
		}
	default:
		return embeddedKey()
	}
	if err != nil {
		return "", err
	}
	return string(cfg.Transport) + "-" + sum[:16], nil
}

// nativeSum returns the SHA-256 of the native cgx binary, checked against its pin.
func nativeSum(cfg Config) (string, error) {
	if !filepath.IsAbs(cfg.CgxBin) {
		return "", fmt.Errorf("%w, got %q", ErrNativeBinPath, cfg.CgxBin)
	}
	sum, err := fileSum(cfg.CgxBin)
	if err != nil {
		return "", err
	}
	return sum, checkPin("native binary", cfg.CgxBin, sum, cfg.CgxBinSHA256)
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("pythoncgx: identify cgx build: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("pythoncgx: identify cgx build: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// checkPin fails closed: an engine file with no pinned digest is not run.
func checkPin(what, path, got, want string) error {
	want = strings.ToLower(strings.TrimSpace(want))
	switch {
	case want == "":
		return fmt.Errorf("%w: cgx %s %s has no pinned sha256", ErrEngineUnverified, what, path)
	case got != want:
		return fmt.Errorf("%w: cgx %s %s has sha256 %s, pinned %s", ErrEngineUnverified, what, path, got, want)
	}
	return nil
}

func embeddedKey() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", errors.New("pythoncgx: no build info to identify the embedded cgx engine")
	}
	for _, dep := range info.Deps {
		if dep.Path != sdkModule {
			continue
		}
		if dep.Replace != nil || dep.Sum == "" {
			return "", errors.New("pythoncgx: the SDK is replaced or unversioned, so its embedded engine cannot be identified; set the wasm module file or use the native transport")
		}
		sum := sha256.Sum256([]byte(dep.Version + " " + dep.Sum))
		return "wasm-embedded-" + hex.EncodeToString(sum[:8]), nil
	}
	return "", errors.New("pythoncgx: cgx SDK not in build info")
}

// memoryLimitKey names the wasm linear-memory ceiling. The lane leaves it at the SDK's default,
// so the SDK version that sets the default identifies it.
func memoryLimitKey() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == sdkModule {
				return "sdk-default@" + dep.Version
			}
		}
	}
	return "sdk-default"
}
