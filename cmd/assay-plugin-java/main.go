// Command assay-plugin-java is the out-of-process Java language analysis
// subprocess (inv.8). It reads exactly one newline-delimited JSON plugin.Request
// from stdin, dispatches on Op to the in-process javaanalysis functions, and
// writes exactly one newline-delimited JSON plugin.Response to stdout. The Java
// source parser links ONLY into this binary — never into the host binary.
//
// This binary deliberately mirrors cmd/assay-plugin-go: same one-shot protocol,
// same hard-error-vs-declared-partiality contract. Nine ops are live (index_symbols,
// resolve_symbols, resolve_versions, call_graph, find_ingresses, reachability,
// compute_taint, build_manifest, resolve_inventory); generate_harness returns its result
// type carrying Unsupported() partiality because Java's effect proof rides the
// repro-runtime sandbox rather than a plugin-generated harness.
//
// The client (internal/plugin.javaPlugin) owns the timeout via exec.CommandContext;
// this process runs to completion on a single request. A hard failure sets
// Response.Error and exits non-zero; declared partiality is a success payload.
//
// With plugin.JavaServeEnv set to "1" (plugin.WithJavaScanProcess) it serves a whole scan
// instead: one Response per request line, in order, until stdin closes, keeping the parsed
// tree, call graph and ingresses between requests (javaanalysis.WithSession). A failed request
// is answered with Response.Error and the process goes on to the next.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Env var names for the Prove-path analyzer container seam. This binary is the only place they
// are read; javaanalysis takes the values as explicit options, and plugin.WithJavaAnalyzerImage /
// plugin.WithJavaAnalyzerDocker set them on this process's environment.
const (
	envAnalyzerImage  = brand.EnvPrefix + "_JAVA_ANALYZER_IMAGE"
	envAnalyzerDocker = brand.EnvPrefix + "_JAVA_ANALYZER_DOCKER"
)

// envRunCacheDir carries the per-scan run cache directory the host sets for this subprocess (see
// plugin.WithJavaRunCacheDir); empty or unset, nothing is cached.
const envRunCacheDir = brand.EnvPrefix + "_JAVA_RUN_CACHE_DIR"

func main() {
	ctx := javaanalysis.WithRunCacheDir(context.Background(), os.Getenv(envRunCacheDir))
	if os.Getenv(plugin.JavaServeEnv) == "1" {
		if err := serve(javaanalysis.WithSession(ctx), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run reads one Request, dispatches, and writes one Response. It returns a
// non-nil error only for a hard failure (the caller exits non-zero); in that case
// it still writes a Response with Error set so the client can decode a structured
// failure.
func run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	line, err := bufio.NewReader(stdin).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return writeError(stdout, fmt.Sprintf("read request: %v", err))
	}
	return answer(ctx, line, stdout)
}

// serve is the process plugin.WithJavaScanProcess keeps for one scan: it answers one Request per
// line, in order, until stdin closes, carrying ctx's session (javaanalysis.WithSession) from one
// request to the next so the source tree is parsed and the dependency JARs opened once per scan. A
// request that fails is answered with Error set, exactly as run answers it, and the next is read;
// only a response that cannot be written ends the loop with an error.
func serve(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	r := bufio.NewReader(stdin)
	w := &recordingWriter{w: stdout}
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			_ = answer(ctx, line, w)
			if w.err != nil {
				return fmt.Errorf("write response: %w", w.err)
			}
		}
		if err != nil {
			return nil // stdin closed: the scan is over
		}
	}
}

// recordingWriter keeps the first write error, which serve checks after each response.
type recordingWriter struct {
	w   io.Writer
	err error
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.w.Write(p)
	r.err = err
	return n, err
}

// answer decodes one request line, dispatches it and writes its one Response line. A non-nil
// error is a failed request, already answered with Error set.
func answer(ctx context.Context, line []byte, stdout io.Writer) error {
	var req plugin.Request
	if err := json.Unmarshal(line, &req); err != nil {
		return writeError(stdout, fmt.Sprintf("unmarshal request: %v", err))
	}
	if req.Protocol != plugin.ProtocolVersion {
		return writeError(stdout, fmt.Sprintf("protocol mismatch: got %q, want %q", req.Protocol, plugin.ProtocolVersion))
	}

	opts := analyzerOptions()
	if err := javaanalysis.CheckBuildGraph(opts...); err != nil {
		return writeError(stdout, err.Error())
	}
	resp, opErr := dispatch(ctx, req, opts...)
	if opErr != nil {
		return writeError(stdout, opErr.Error())
	}
	resp.Protocol = plugin.ProtocolVersion
	return writeResponse(stdout, resp)
}

// analyzerOptions hands the ops the build graph the host accepted (plugin.BuildGraphEnv), and
// opens the javaanalysis Prove-path gate when envAnalyzerImage is set, with the docker binary
// override from envAnalyzerDocker. Without the image the gate stays closed (pure-Go only).
func analyzerOptions() []javaanalysis.Option {
	opts := []javaanalysis.Option{javaanalysis.WithBuildGraph(os.Getenv(plugin.BuildGraphEnv)), javaanalysis.WithCompileNote(os.Getenv(plugin.BuildCompileEnv))}
	image := os.Getenv(envAnalyzerImage)
	if image == "" {
		return opts
	}
	opts = append(opts, javaanalysis.WithAnalyzerImage(image))
	if bin := os.Getenv(envAnalyzerDocker); bin != "" {
		opts = append(opts, javaanalysis.WithAnalyzerDocker(bin))
	}
	return opts
}

// dispatch runs the requested operation. index_symbols, resolve_symbols,
// call_graph, and find_ingresses call the real source-level Java analysis (Java
// Increment 1); resolve_versions and resolve_inventory read the build graph; reachability and compute_taint compute first-party
// call-graph reachability / path-presence taint over that same graph (Assess
// parity). generate_harness and build_manifest remain contract-present stubs:
// Java's effect proof rides the repro-runtime sandbox, not a plugin-generated
// harness. An unknown op, or a missing per-op payload, is a hard failure (inv.4).
func dispatch(ctx context.Context, req plugin.Request, opts ...javaanalysis.Option) (plugin.Response, error) {
	switch req.Op {
	case plugin.OpIndexSymbols:
		if req.IndexSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing index_symbols request", req.Op)
		}
		res, err := javaanalysis.IndexSymbols(ctx, *req.IndexSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolIndex: &res}, nil

	case plugin.OpResolveSymbols:
		if req.ResolveSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_symbols request", req.Op)
		}
		res, err := javaanalysis.ResolveDependencySymbols(ctx, *req.ResolveSymbols, opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolResolution: &res}, nil

	case plugin.OpResolveVersions:
		if req.ResolveVersions == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_versions request", req.Op)
		}
		res, err := javaanalysis.ResolveDependencyVersions(ctx, *req.ResolveVersions, opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{VersionResult: &res}, nil

	case plugin.OpCallGraph:
		if req.CallGraph == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing call_graph request", req.Op)
		}
		res, err := javaanalysis.CallGraph(ctx, *req.CallGraph, opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{CallGraph: &res}, nil

	case plugin.OpFindIngresses:
		if req.FindIngresses == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing find_ingresses request", req.Op)
		}
		res, err := javaanalysis.FindIngresses(ctx, *req.FindIngresses, opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Ingress: &res}, nil

	case plugin.OpReachability:
		if req.Reachability == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing reachability request", req.Op)
		}
		res, err := javaanalysis.Reachability(ctx, *req.Reachability, opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Reachability: &res}, nil

	case plugin.OpComputeTaint:
		if req.ComputeTaint == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing compute_taint request", req.Op)
		}
		res, err := javaanalysis.ComputeTaint(ctx, *req.ComputeTaint, opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Taint: &res}, nil

	case plugin.OpGenerateHarness:
		if req.GenerateHarness == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing generate_harness request", req.Op)
		}
		return plugin.Response{Harness: &plugin.HarnessResult{Partiality: plugin.Unsupported()}}, nil

	case plugin.OpBuildManifest:
		if req.BuildManifest == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing build_manifest request", req.Op)
		}
		res, err := javaanalysis.BuildManifest(ctx, *req.BuildManifest, "java", opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{BuildManifest: &res}, nil

	case plugin.OpResolveInventory:
		if req.ResolveInventory == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_inventory request", req.Op)
		}
		res, err := javaanalysis.ResolveInventory(ctx, *req.ResolveInventory, opts...)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Inventory: &res}, nil

	case plugin.OpCapabilityManifest:
		// Honest absence (Supported:false), never a Supported:true manifest with empty axes.
		return plugin.Response{Manifest: &capability.Manifest{Supported: false, Language: "java"}}, nil

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

// writeError writes a structured error Response (so the client decodes a clean
// failure) and returns a non-nil error so main exits non-zero (inv.4).
func writeError(stdout io.Writer, msg string) error {
	out, _ := json.Marshal(plugin.Response{Protocol: plugin.ProtocolVersion, Error: msg})
	out = append(out, '\n')
	_, _ = stdout.Write(out)
	return fmt.Errorf("%s", msg)
}
