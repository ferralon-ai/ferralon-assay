// Command assay-plugin-cfamily is the out-of-process C/C++ (C-family) language analysis
// subprocess (inv.8). It reads exactly one newline-delimited JSON plugin.Request from stdin,
// dispatches on Op, and writes exactly one newline-delimited JSON plugin.Response to stdout. Any
// C/C++ analysis toolchain, the cgx engine included, links ONLY into this binary — never into
// the host binary.
//
// The graph operations (index_symbols, resolve_symbols, call_graph, find_ingresses,
// reachability, compute_taint) are answered from a cgx call graph through the cgx Go SDK
// (plugins/cfamily/cfamilycgx). The build-context and dependency-version ops are answered by
// internal/plugin/cfamilyanalysis; generate_harness and resolve_inventory are declared
// Unsupported. Every op keeps the nil-payload hard-error guard (inv.4).
//
// Each graph call stages the build directory's C/C++ sources into a git repository under the
// cache directory and warm-opens the cgx index stored there; the first call on a new tree
// indexes it. The scanned tree is only read. Configuration, all optional:
//
//	ASSAY_CFAMILY_CGX_TRANSPORT       wasm (default) | native
//	ASSAY_CFAMILY_CGX_WASM            wasm: absolute path of the engine module; it must be the
//	                                  module pinned with this build's cgx SDK
//	ASSAY_CFAMILY_CGX_WASM_SHA256     wasm: the module's expected sha256; refused unless it is
//	                                  the pinned one
//	ASSAY_CFAMILY_CGX_BIN             native: absolute path of the cgx binary (never looked up
//	                                  on PATH)
//	ASSAY_CFAMILY_CGX_BIN_SHA256      native: the binary's pinned sha256 (default: the digest
//	                                  baked into this build, if any)
//	ASSAY_CFAMILY_CGX_CACHE_DIR       index snapshots and the native binary's private copy
//	                                  (default: user cache dir)
//	ASSAY_CFAMILY_CGX_WASM_CACHE_DIR  wasm engine compilation cache: an absolute path to a
//	                                  directory (not a symlink) owned by this user, not
//	                                  writable or readable by group or other. ferralon-assay
//	                                  sets a private dir per scan when the operator sets none;
//	                                  unset, caches in memory only for the life of this process
//	ASSAY_CFAMILY_CGX_POOL_SIZE       wasm extractor instances (default: the SDK's)
//	ASSAY_CFAMILY_CGX_MIN_CONFIDENCE  call-graph edge floor: possible (default) | probable |
//	                                  certain
//	ASSAY_CFAMILY_CGX_STATS           file to append one JSON timing record per operation to
//	ASSAY_CFAMILY_CGX_FALLBACK        native: after the wasm engine traps while indexing, retry
//	                                  once on the native transport (default: off)
//	ASSAY_CFAMILY_CGX_FAILURE_TTL     how long an index failure that may not recur is replayed:
//	                                  a Go duration (default 30m; 0 never replays one)
//
// No engine, an unverified one, or one that is not the pinned SDK/module pair is not a hard
// error: every graph op then declares tool_failure:cgx_engine_{unconfigured,unverified,mismatch}
// and returns no graph, so the scan reports the finding undetermined rather than clean. A
// malformed setting is declared the same way (unconfigured), with the cause on stderr.
//
// The client (internal/plugin.cfamilyPlugin) owns the timeout via exec.CommandContext; this
// process runs to completion on a single request. A hard failure sets Response.Error and exits
// non-zero; declared partiality is a success payload.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/plugins/cfamily/cfamilycgx"
)

// Engine configuration, read once per process.
const (
	envTransport     = brand.EnvPrefix + "_CFAMILY_CGX_TRANSPORT"
	envBin           = brand.EnvPrefix + "_CFAMILY_CGX_BIN"
	envBinSHA256     = brand.EnvPrefix + "_CFAMILY_CGX_BIN_SHA256"
	envWasm          = brand.EnvPrefix + "_CFAMILY_CGX_WASM"
	envWasmSHA256    = brand.EnvPrefix + "_CFAMILY_CGX_WASM_SHA256"
	envCacheDir      = brand.EnvPrefix + "_CFAMILY_CGX_CACHE_DIR"
	envWasmCacheDir  = brand.EnvPrefix + "_CFAMILY_CGX_WASM_CACHE_DIR"
	envPoolSize      = brand.EnvPrefix + "_CFAMILY_CGX_POOL_SIZE"
	envMinConfidence = brand.EnvPrefix + "_CFAMILY_CGX_MIN_CONFIDENCE"
	envStats         = brand.EnvPrefix + "_CFAMILY_CGX_STATS"
	envFallback      = brand.EnvPrefix + "_CFAMILY_CGX_FALLBACK"
	envFailureTTL    = brand.EnvPrefix + "_CFAMILY_CGX_FAILURE_TTL"
)

// bakedCgxBinSHA256 is the native cgx binary's sha256, set at link time by a release build that
// ships one (-ldflags "-X main.bakedCgxBinSHA256=<hex>"). The wasm module's pin is not baked
// here: it is cfamilycgx.PinnedWasmSHA256, recorded beside the SDK version it must match.
var bakedCgxBinSHA256 string

func main() {
	// The snapshot repository's git commands are isolated in cfamilycgx; dropping inherited
	// location variables here also keeps them from the SDK's own git use.
	for _, v := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR"} {
		_ = os.Unsetenv(v)
	}
	if err := run(context.Background(), newLane(os.Stderr), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run reads one Request, dispatches, and writes one Response. It returns a non-nil error only
// for a hard failure (the caller exits non-zero); in that case it still writes a Response with
// Error set so the client can decode a structured failure.
func run(ctx context.Context, lane *cfamilycgx.Lane, stdin io.Reader, stdout io.Writer) error {
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

	resp, opErr := dispatch(ctx, lane, req)
	if opErr != nil {
		return writeError(stdout, withRemedy(opErr).Error())
	}
	resp.Protocol = plugin.ProtocolVersion
	return writeResponse(stdout, resp)
}

// newLane builds the graph lane from the environment. A setting that cannot be read leaves the
// lane without an engine (every graph op declares tool_failure:cgx_engine_unconfigured) and the
// cause on stderr; it never stops the plugin answering the other ops.
func newLane(stderr io.Writer) *cfamilycgx.Lane {
	cfg, err := readConfig()
	if err != nil {
		fmt.Fprintf(stderr, "assay-plugin-cfamily: cgx engine not configured: %v\n", err)
		return cfamilycgx.Unavailable(cfg, fmt.Errorf("%w: %v", cfamilycgx.ErrEngineUnconfigured, err))
	}
	return cfamilycgx.NewSDK(cfg)
}

func readConfig() (cfamilycgx.Config, error) {
	var cfg cfamilycgx.Config
	var err error
	if cfg.Transport, err = cfamilycgx.ParseTransport(os.Getenv(envTransport)); err != nil {
		return cfg, fmt.Errorf("%s: %w", envTransport, err)
	}
	if cfg.MinConfidence, err = cfamilycgx.ParseMinConfidence(os.Getenv(envMinConfidence)); err != nil {
		return cfg, fmt.Errorf("%s: %w", envMinConfidence, err)
	}
	if cfg.Fallback, err = cfamilycgx.ParseFallback(os.Getenv(envFallback)); err != nil {
		return cfg, fmt.Errorf("%s: %w", envFallback, err)
	}
	if cfg.FailureTTL, err = cfamilycgx.ParseFailureTTL(os.Getenv(envFailureTTL)); err != nil {
		return cfg, fmt.Errorf("%s: %w", envFailureTTL, err)
	}
	cfg.CgxBin = strings.TrimSpace(os.Getenv(envBin))
	cfg.WasmModule = strings.TrimSpace(os.Getenv(envWasm))
	cfg.CacheDir = strings.TrimSpace(os.Getenv(envCacheDir))
	cfg.WasmCacheDir = strings.TrimSpace(os.Getenv(envWasmCacheDir))
	cfg.StatsFile = strings.TrimSpace(os.Getenv(envStats))
	cfg.CgxBinSHA256 = strings.TrimSpace(os.Getenv(envBinSHA256))
	if cfg.CgxBinSHA256 == "" {
		cfg.CgxBinSHA256 = bakedCgxBinSHA256
	}
	cfg.WasmModuleSHA256 = strings.TrimSpace(os.Getenv(envWasmSHA256))
	if v := strings.TrimSpace(os.Getenv(envPoolSize)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return cfg, fmt.Errorf("%s: want a positive integer, got %q", envPoolSize, v)
		}
		cfg.PoolSize = n
	}
	if cfg.CacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return cfg, fmt.Errorf("no cache directory: set %s: %w", envCacheDir, err)
		}
		cfg.CacheDir = filepath.Join(base, brand.Name, "cfamily-cgx")
	}
	return cfg, nil
}

// withRemedy appends what an operator can change to an engine failure while indexing, in terms
// of this command's configuration.
func withRemedy(err error) error {
	var f *cfamilycgx.IndexFailure
	if !errors.As(err, &f) {
		return err
	}
	switch {
	case f.Kind == cfamilycgx.EngineContext:
		return fmt.Errorf("%w; remedy: indexing outlived the call's deadline; it is attempted again once %s has passed", err, envFailureTTL)
	case f.Transport == cfamilycgx.TransportWasm:
		return fmt.Errorf("%w; remedy: set %s=native (cgx binary via %s and %s), or %s=native to retry on it", err, envTransport, envBin, envBinSHA256, envFallback)
	default:
		return fmt.Errorf("%w; remedy: the native cgx process exited; check its diagnostics and the memory available to it (attempted again once %s has passed)", err, envFailureTTL)
	}
}

// dispatch answers the graph operations and resolve_symbols from the cgx lane and the
// build-context ops from cfamilyanalysis. An unknown op or a missing payload is a hard failure
// (inv.4).
func dispatch(ctx context.Context, lane *cfamilycgx.Lane, req plugin.Request) (plugin.Response, error) {
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
		res, err := cfamilyanalysis.ResolveDependencyVersions(ctx, *req.ResolveVersions)
		return plugin.Response{VersionResult: &res}, err

	case plugin.OpGenerateHarness:
		if req.GenerateHarness == nil {
			return missing()
		}
		res, err := cfamilyanalysis.GenerateHarness(ctx, *req.GenerateHarness)
		return plugin.Response{Harness: &res}, err

	case plugin.OpBuildManifest:
		if req.BuildManifest == nil {
			return missing()
		}
		res, err := cfamilyanalysis.BuildManifest(ctx, *req.BuildManifest)
		return plugin.Response{BuildManifest: &res}, err

	case plugin.OpResolveInventory:
		if req.ResolveInventory == nil {
			return missing()
		}
		res, err := cfamilyanalysis.ResolveInventory(ctx, *req.ResolveInventory)
		return plugin.Response{Inventory: &res}, err

	case plugin.OpCapabilityManifest:
		manifest := cfamilyanalysis.CapabilityManifest()
		return plugin.Response{Manifest: &manifest}, nil

	default:
		return plugin.Response{}, fmt.Errorf("unknown op %q", req.Op)
	}
}

func writeResponse(stdout io.Writer, resp plugin.Response) error {
	out, err := json.Marshal(resp)
	if err != nil {
		return writeError(stdout, fmt.Sprintf("marshal response: %v", err))
	}
	out = append(out, '\n')
	_, err = stdout.Write(out)
	return err
}

// writeError writes a structured error Response (so the client decodes a clean failure) and
// returns a non-nil error so main exits non-zero (inv.4).
func writeError(stdout io.Writer, msg string) error {
	out, _ := json.Marshal(plugin.Response{Protocol: plugin.ProtocolVersion, Error: msg})
	out = append(out, '\n')
	_, _ = stdout.Write(out)
	return fmt.Errorf("%s", msg)
}
