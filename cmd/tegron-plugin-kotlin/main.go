// Command tegron-plugin-kotlin is the out-of-process Kotlin language analysis subprocess
// (inv.8). It reads exactly one newline-delimited JSON plugin.Request from stdin, dispatches
// on Op to the in-process kotlinanalysis functions, and writes exactly one newline-delimited
// JSON plugin.Response to stdout. The Kotlin bytecode analyzer links ONLY into this binary —
// never into tegrond.
//
// This binary deliberately mirrors cmd/tegron-plugin-java / cmd/tegron-plugin-dotnet: same
// one-shot protocol, same hard-error-vs-declared-partiality contract. Four ops are LIVE,
// backed by the shared JVM-bytecode substrate (index_symbols, call_graph, find_ingresses,
// reachability); capability_manifest publishes the lane's honest capability manifest. The
// remaining ops (resolve_symbols, resolve_versions, compute_taint, build_manifest,
// resolve_inventory, generate_harness) are CONTRACT-PRESENT and return their result type
// carrying declared partiality (honest absence), never an empty-but-complete result. Every
// op keeps the nil-payload hard-error guard (inv.4).
//
// The client (internal/plugin.kotlinPlugin) owns the timeout via exec.CommandContext; this
// process runs to completion on a single request. A hard failure sets Response.Error and
// exits non-zero; declared partiality is a success payload.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/kotlinanalysis"
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

// dispatch runs the requested operation. index_symbols, call_graph, find_ingresses, and
// reachability call the real bytecode analysis over the compiled build output;
// capability_manifest returns the lane's honest manifest. The remaining ops are
// contract-present and return declared partiality. An unknown op, or a missing per-op
// payload, is a hard failure (inv.4).
func dispatch(ctx context.Context, req plugin.Request) (plugin.Response, error) {
	switch req.Op {
	case plugin.OpIndexSymbols:
		if req.IndexSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing index_symbols request", req.Op)
		}
		res, err := kotlinanalysis.IndexSymbols(ctx, *req.IndexSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolIndex: &res}, nil

	case plugin.OpResolveSymbols:
		if req.ResolveSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_symbols request", req.Op)
		}
		res, err := kotlinanalysis.ResolveDependencySymbols(ctx, *req.ResolveSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolResolution: &res}, nil

	case plugin.OpResolveVersions:
		if req.ResolveVersions == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_versions request", req.Op)
		}
		res, err := kotlinanalysis.ResolveDependencyVersions(ctx, *req.ResolveVersions)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{VersionResult: &res}, nil

	case plugin.OpCallGraph:
		if req.CallGraph == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing call_graph request", req.Op)
		}
		res, err := kotlinanalysis.CallGraph(ctx, *req.CallGraph)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{CallGraph: &res}, nil

	case plugin.OpFindIngresses:
		if req.FindIngresses == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing find_ingresses request", req.Op)
		}
		res, err := kotlinanalysis.FindIngresses(ctx, *req.FindIngresses)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Ingress: &res}, nil

	case plugin.OpReachability:
		if req.Reachability == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing reachability request", req.Op)
		}
		res, err := kotlinanalysis.Reachability(ctx, *req.Reachability)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Reachability: &res}, nil

	case plugin.OpComputeTaint:
		if req.ComputeTaint == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing compute_taint request", req.Op)
		}
		res, err := kotlinanalysis.ComputeTaint(ctx, *req.ComputeTaint)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Taint: &res}, nil

	case plugin.OpGenerateHarness:
		if req.GenerateHarness == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing generate_harness request", req.Op)
		}
		res, err := kotlinanalysis.GenerateHarness(ctx, *req.GenerateHarness)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Harness: &res}, nil

	case plugin.OpBuildManifest:
		if req.BuildManifest == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing build_manifest request", req.Op)
		}
		res, err := kotlinanalysis.BuildManifest(ctx, *req.BuildManifest)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{BuildManifest: &res}, nil

	case plugin.OpResolveInventory:
		if req.ResolveInventory == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_inventory request", req.Op)
		}
		res, err := kotlinanalysis.ResolveInventory(ctx, *req.ResolveInventory)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Inventory: &res}, nil

	case plugin.OpCapabilityManifest:
		manifest := kotlinanalysis.CapabilityManifest()
		return plugin.Response{Manifest: &manifest}, nil

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

// writeError writes a structured error Response (so the client decodes a clean failure) and
// returns a non-nil error so main exits non-zero (inv.4).
func writeError(stdout *os.File, msg string) error {
	out, _ := json.Marshal(plugin.Response{Protocol: plugin.ProtocolVersion, Error: msg})
	out = append(out, '\n')
	_, _ = stdout.Write(out)
	return fmt.Errorf("%s", msg)
}
