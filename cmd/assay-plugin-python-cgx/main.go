// Command assay-plugin-python-cgx is the cgx-backed Python analysis subprocess (inv.8). It
// speaks the same one-shot tegron.plugin.v1 protocol as assay-plugin-python — one
// newline-delimited JSON Request on stdin, one Response on stdout — and reports itself as the
// python lane, so the ordinary Python client drives it. The scanner selects it with
// ASSAY_PYTHON_LANE=cgx.
//
// Six operations are answered from a cgx call graph through the cgx Go SDK
// (internal/plugin/pythoncgx): index_symbols, resolve_symbols, call_graph, find_ingresses,
// reachability and compute_taint. The rest — resolve_versions, build_manifest,
// resolve_inventory, generate_harness, capability_manifest — are manifest and lockfile work
// with no graph in it, and are answered exactly as assay-plugin-python answers them.
//
// Each call snapshots the build directory into a git repository under the cache directory
// and warm-opens the cgx index stored there; the first call on a new tree indexes it. The
// scanned tree is only read. Configuration, all optional:
//
//	ASSAY_PYTHON_CGX_TRANSPORT       wasm (default) | native
//	ASSAY_PYTHON_CGX_BIN             native: cgx binary (default: cgx on PATH)
//	ASSAY_PYTHON_CGX_WASM            wasm: engine module file, for SDK builds that embed none
//	ASSAY_PYTHON_CGX_CACHE_DIR       index snapshots and compile cache (default: user cache dir)
//	ASSAY_PYTHON_CGX_POOL_SIZE       wasm extractor instances (default: the SDK's)
//	ASSAY_PYTHON_CGX_MIN_CONFIDENCE  call-graph edge floor: certain | probable (default) | possible
//	ASSAY_PYTHON_CGX_STATS           file to append one JSON timing record per operation to
//	ASSAY_PYTHON_CGX_FALLBACK        native: after the wasm engine traps while indexing (its
//	                                 memory limit included), retry once on the native transport
//	                                 with ASSAY_PYTHON_CGX_BIN (default: off)
//
// A configuration error, a failed open or a failed query is a hard error (inv.4): Response.Error
// is set and the process exits non-zero. Declared partiality is a success payload. An engine
// failure while indexing is recorded under the cache directory for the scan, so the scan's
// later operations on the same tree fail at once with the same error instead of indexing again.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythonanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythoncgx"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	envTransport     = brand.EnvPrefix + "_PYTHON_CGX_TRANSPORT"
	envBin           = brand.EnvPrefix + "_PYTHON_CGX_BIN"
	envWasm          = brand.EnvPrefix + "_PYTHON_CGX_WASM"
	envCacheDir      = brand.EnvPrefix + "_PYTHON_CGX_CACHE_DIR"
	envPoolSize      = brand.EnvPrefix + "_PYTHON_CGX_POOL_SIZE"
	envMinConfidence = brand.EnvPrefix + "_PYTHON_CGX_MIN_CONFIDENCE"
	envStats         = brand.EnvPrefix + "_PYTHON_CGX_STATS"
	envFallback      = brand.EnvPrefix + "_PYTHON_CGX_FALLBACK"
)

func main() {
	// git's location variables would redirect the SDK's git plumbing away from the snapshot
	// repository this process opens; the scanner's environment has no business there.
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR"} {
		_ = os.Unsetenv(k)
	}
	if err := run(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, stdin *os.File, stdout *os.File) error {
	line, err := bufio.NewReader(stdin).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return writeError(stdout, fmt.Sprintf("read request: %v", err))
	}
	var req plugin.Request
	if err := json.Unmarshal(line, &req); err != nil {
		return writeError(stdout, fmt.Sprintf("unmarshal request: %v", err))
	}
	if req.Protocol != plugin.ProtocolVersion {
		return writeError(stdout, fmt.Sprintf("protocol mismatch: got %q, want %q", req.Protocol, plugin.ProtocolVersion))
	}
	lane, err := newLane()
	if err != nil {
		return writeError(stdout, err.Error())
	}
	resp, err := dispatch(ctx, lane, req)
	if err != nil {
		return writeError(stdout, withRemedy(err).Error())
	}
	resp.Protocol = plugin.ProtocolVersion
	return writeResponse(stdout, resp)
}

// newLane reads the configuration from the environment.
func newLane() (*pythoncgx.Lane, error) {
	transport, err := pythoncgx.ParseTransport(os.Getenv(envTransport))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envTransport, err)
	}
	minConf, err := pythoncgx.ParseMinConfidence(os.Getenv(envMinConfidence))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envMinConfidence, err)
	}
	fallback, err := pythoncgx.ParseFallback(os.Getenv(envFallback))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envFallback, err)
	}
	cfg := pythoncgx.Config{
		Transport:     transport,
		CgxBin:        strings.TrimSpace(os.Getenv(envBin)),
		WasmModule:    strings.TrimSpace(os.Getenv(envWasm)),
		CacheDir:      strings.TrimSpace(os.Getenv(envCacheDir)),
		MinConfidence: minConf,
		StatsFile:     strings.TrimSpace(os.Getenv(envStats)),
		Fallback:      fallback,
	}
	if v := strings.TrimSpace(os.Getenv(envPoolSize)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("%s: want a positive integer, got %q", envPoolSize, v)
		}
		cfg.PoolSize = n
	}
	if cfg.CacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("no cache directory: set %s: %w", envCacheDir, err)
		}
		cfg.CacheDir = filepath.Join(base, brand.Name, "python-cgx")
	}
	key, err := pythoncgx.CacheKey(cfg)
	if err != nil {
		return nil, err
	}
	var fallbackKey string
	if cfg.Fallback != "" && cfg.Fallback != cfg.Transport {
		fb := cfg
		fb.Transport = cfg.Fallback
		if fallbackKey, err = pythoncgx.CacheKey(fb); err != nil {
			return nil, fmt.Errorf("%s: %w", envFallback, err)
		}
	}
	return pythoncgx.New(cfg, pythoncgx.OpenSDK, key, fallbackKey), nil
}

// withRemedy appends what an operator can change to an engine failure while indexing, in terms
// of this command's configuration.
func withRemedy(err error) error {
	var f *pythoncgx.IndexFailure
	if !errors.As(err, &f) {
		return err
	}
	switch {
	case f.Transport == pythoncgx.TransportWasm:
		return fmt.Errorf("%w; remedy: set %s=native (cgx binary via %s), or %s=native to retry on it", err, envTransport, envBin, envFallback)
	default:
		return fmt.Errorf("%w; remedy: the native cgx process exited; check its diagnostics and the memory available to it", err)
	}
}

// dispatch answers the six graph operations from the cgx lane and the rest exactly as
// assay-plugin-python does. An unknown op or a missing payload is a hard failure (inv.4).
func dispatch(ctx context.Context, lane *pythoncgx.Lane, req plugin.Request) (plugin.Response, error) {
	missing := func() (plugin.Response, error) {
		return plugin.Response{}, fmt.Errorf("%s: missing %s request", req.Op, req.Op)
	}
	switch req.Op {
	case plugin.OpIndexSymbols:
		if req.IndexSymbols == nil {
			return missing()
		}
		res, err := lane.IndexSymbols(ctx, *req.IndexSymbols)
		return plugin.Response{SymbolIndex: &res}, err

	case plugin.OpResolveSymbols:
		if req.ResolveSymbols == nil {
			return missing()
		}
		res, err := lane.ResolveDependencySymbols(ctx, *req.ResolveSymbols)
		return plugin.Response{SymbolResolution: &res}, err

	case plugin.OpCallGraph:
		if req.CallGraph == nil {
			return missing()
		}
		res, err := lane.CallGraph(ctx, *req.CallGraph)
		return plugin.Response{CallGraph: &res}, err

	case plugin.OpFindIngresses:
		if req.FindIngresses == nil {
			return missing()
		}
		res, err := lane.FindIngresses(ctx, *req.FindIngresses)
		return plugin.Response{Ingress: &res}, err

	case plugin.OpReachability:
		if req.Reachability == nil {
			return missing()
		}
		res, err := lane.Reachability(ctx, *req.Reachability)
		return plugin.Response{Reachability: &res}, err

	case plugin.OpComputeTaint:
		if req.ComputeTaint == nil {
			return missing()
		}
		res, err := lane.ComputeTaint(ctx, *req.ComputeTaint)
		return plugin.Response{Taint: &res}, err

	case plugin.OpResolveVersions:
		if req.ResolveVersions == nil {
			return missing()
		}
		res, err := pythonanalysis.ResolveDependencyVersions(ctx, *req.ResolveVersions)
		return plugin.Response{VersionResult: &res}, err

	case plugin.OpBuildManifest:
		if req.BuildManifest == nil {
			return missing()
		}
		res, err := pythonanalysis.BuildManifest(ctx, *req.BuildManifest)
		return plugin.Response{BuildManifest: &res}, err

	case plugin.OpResolveInventory:
		if req.ResolveInventory == nil {
			return missing()
		}
		res, err := pythonanalysis.ResolveInventory(ctx, *req.ResolveInventory)
		return plugin.Response{Inventory: &res}, err

	case plugin.OpGenerateHarness:
		if req.GenerateHarness == nil {
			return missing()
		}
		return plugin.Response{Harness: &plugin.HarnessResult{Partiality: plugin.Unsupported()}}, nil

	case plugin.OpCapabilityManifest:
		return plugin.Response{Manifest: &capability.Manifest{Supported: false, Language: "python"}}, nil

	default:
		return plugin.Response{}, fmt.Errorf("unknown op %q", req.Op)
	}
}

func writeResponse(stdout *os.File, resp plugin.Response) error {
	out, err := json.Marshal(resp)
	if err != nil {
		return writeError(stdout, fmt.Sprintf("marshal response: %v", err))
	}
	out = append(out, '\n')
	_, err = stdout.Write(out)
	return err
}

// writeError writes a structured error Response and returns a non-nil error so main exits
// non-zero (inv.4).
func writeError(stdout *os.File, msg string) error {
	out, _ := json.Marshal(plugin.Response{Protocol: plugin.ProtocolVersion, Error: msg})
	out = append(out, '\n')
	_, _ = stdout.Write(out)
	return fmt.Errorf("%s", msg)
}
