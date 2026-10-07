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
	"os/exec"
	"path/filepath"
	"runtime/debug"

	"github.com/ferralon-ai/cgx/sdk/go/cgx"
)

// sdkModule is the cgx SDK's module path, for identifying the embedded engine in CacheKey.
const sdkModule = "github.com/ferralon-ai/cgx/sdk/go"

// OpenSDK is the Opener backed by the cgx Go SDK. The SDK's compile cache lives under
// cfg.CacheDir so the plugin writes nowhere else.
func OpenSDK(ctx context.Context, repo string, cfg Config) (Graph, error) {
	opts := []cgx.Option{cgx.WithCacheDir(filepath.Join(cfg.CacheDir, "wazero"))}
	switch cfg.Transport {
	case TransportNative:
		opts = append(opts, cgx.WithTransport(cgx.Native(cfg.CgxBin)))
	default:
		opts = append(opts, cgx.WithTransport(cgx.Wasm()))
		if cfg.WasmModule != "" {
			mod, err := os.ReadFile(cfg.WasmModule)
			if err != nil {
				return nil, fmt.Errorf("pythoncgx: read wasm module: %w", err)
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

// CacheKey names the cgx build cfg selects: the SHA-256 of the native binary or of the wasm
// module file, or the SDK module version whose embedded engine is used. Indexes are kept per
// key because cgx reuses cached extraction results without checking which build wrote them.
func CacheKey(cfg Config) (string, error) {
	var path string
	switch {
	case cfg.Transport == TransportNative:
		path = cfg.CgxBin
		if path == "" {
			p, err := exec.LookPath("cgx")
			if err != nil {
				return "", fmt.Errorf("pythoncgx: native transport: %w", err)
			}
			path = p
		}
	case cfg.WasmModule != "":
		path = cfg.WasmModule
	default:
		return embeddedKey()
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("pythoncgx: identify cgx build: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("pythoncgx: identify cgx build: %w", err)
	}
	return string(cfg.Transport) + "-" + hex.EncodeToString(h.Sum(nil))[:16], nil
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
