// Command tegron-plugin-python is the out-of-process Python language analysis
// subprocess (inv.8). It reads exactly one newline-delimited JSON plugin.Request from
// stdin, dispatches on Op to the in-process pythonanalysis functions, and writes exactly
// one newline-delimited JSON plugin.Response to stdout. The Python source scanner links
// ONLY into this binary — never into tegrond.
//
// This binary deliberately mirrors cmd/tegron-plugin-js: same one-shot protocol, same
// hard-error-vs-declared-partiality contract. Seven ops are LIVE, all backed by the real
// pure-Go lexical source analysis (no scip-python container on the Assess path):
// index_symbols, resolve_symbols, resolve_versions (installed versions from
// requirements.txt / poetry.lock / Pipfile.lock / PEP 621 pyproject.toml), call_graph,
// find_ingresses (Flask/FastAPI route decorators), reachability, and compute_taint.
// reachability and compute_taint are ALWAYS declared Partial(dynamic_dispatch) — Python
// static reachability is structurally weak (dynamic dispatch, getattr, monkeypatching), so
// "not reached" is UNKNOWN, never "safe", and the effect trial adjudicates. call_graph is
// likewise always Partial. generate_harness and build_manifest stay CONTRACT-PRESENT
// Unsupported (as on the Assess path; the Python effect rides the corpus repro-runtime
// sandbox, exactly as the Go/Java/JS plugins ship them).
//
// The client (internal/plugin.pythonPlugin) owns the timeout via exec.CommandContext;
// this process runs to completion on a single request. A hard failure sets
// Response.Error and exits non-zero; declared partiality is a success payload.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythonanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func main() {
	if err := run(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run reads one Request, dispatches, and writes one Response. It returns a non-nil error
// only for a hard failure (the caller exits non-zero); in that case it still writes a
// Response with Error set so the client can decode a structured failure.
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

	resp, opErr := dispatch(ctx, req)
	if opErr != nil {
		return writeError(stdout, opErr.Error())
	}
	resp.Protocol = plugin.ProtocolVersion
	return writeResponse(stdout, resp)
}

// dispatch runs the requested operation. index_symbols, resolve_symbols, resolve_versions,
// call_graph, find_ingresses, reachability, and compute_taint call the real source-level
// Python analysis (reachability/compute_taint always declared Partial). generate_harness
// and build_manifest remain contract-present ops returning their result type with
// Unsupported() partiality (the Python effect rides the corpus repro-runtime sandbox). An
// unknown op, or a missing per-op payload, is a hard failure (inv.4).
func dispatch(ctx context.Context, req plugin.Request) (plugin.Response, error) {
	switch req.Op {
	case plugin.OpIndexSymbols:
		if req.IndexSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing index_symbols request", req.Op)
		}
		res, err := pythonanalysis.IndexSymbols(ctx, *req.IndexSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolIndex: &res}, nil

	case plugin.OpResolveSymbols:
		if req.ResolveSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_symbols request", req.Op)
		}
		res, err := pythonanalysis.ResolveDependencySymbols(ctx, *req.ResolveSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolResolution: &res}, nil

	case plugin.OpResolveVersions:
		if req.ResolveVersions == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_versions request", req.Op)
		}
		res, err := pythonanalysis.ResolveDependencyVersions(ctx, *req.ResolveVersions)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{VersionResult: &res}, nil

	case plugin.OpCallGraph:
		if req.CallGraph == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing call_graph request", req.Op)
		}
		res, err := pythonanalysis.CallGraph(ctx, *req.CallGraph)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{CallGraph: &res}, nil

	case plugin.OpFindIngresses:
		if req.FindIngresses == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing find_ingresses request", req.Op)
		}
		res, err := pythonanalysis.FindIngresses(ctx, *req.FindIngresses)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Ingress: &res}, nil

	case plugin.OpReachability:
		if req.Reachability == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing reachability request", req.Op)
		}
		res, err := pythonanalysis.Reachability(ctx, *req.Reachability)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Reachability: &res}, nil

	case plugin.OpComputeTaint:
		if req.ComputeTaint == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing compute_taint request", req.Op)
		}
		res, err := pythonanalysis.ComputeTaint(ctx, *req.ComputeTaint)
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
		return plugin.Response{BuildManifest: &plugin.BuildManifestResult{Partiality: plugin.Unsupported()}}, nil

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

// writeError writes a structured error Response (so the client decodes a clean failure)
// and returns a non-nil error so main exits non-zero (inv.4).
func writeError(stdout *os.File, msg string) error {
	out, _ := json.Marshal(plugin.Response{Protocol: plugin.ProtocolVersion, Error: msg})
	out = append(out, '\n')
	_, _ = stdout.Write(out)
	return fmt.Errorf("%s", msg)
}
