// Command tegron-plugin-dotnet is the out-of-process .NET/C# language analysis subprocess
// (inv.8). It reads exactly one newline-delimited JSON plugin.Request from stdin, dispatches
// on Op to the in-process dotnetanalysis functions, and writes exactly one newline-delimited
// JSON plugin.Response to stdout. The C# source scanner links ONLY into this binary — never
// into tegrond.
//
// This binary deliberately mirrors cmd/tegron-plugin-js / cmd/tegron-plugin-python: same
// one-shot protocol, same hard-error-vs-declared-partiality contract. At full Assess-parity
// SEVEN ops are LIVE, backed by the real pure-Go lexical source analysis (no scip-dotnet
// container on the Assess path): index_symbols, resolve_symbols, resolve_versions (installed
// versions from packages.lock.json / .csproj PackageReference / packages.config), call_graph,
// find_ingresses, reachability, and compute_taint. reachability and compute_taint are
// declared Partial(dynamic_dispatch) ALWAYS — never Complete — because a lexical C# scan
// cannot see interface/virtual/DI/reflection dispatch (scope §5 R1). resolve_inventory is LIVE
// (PLAN-150): a pure-lexical whole-graph NuGet resolver over the checkout's
// project.assets.json / packages.lock.json / declared PackageReference text — it never runs
// dotnet/MSBuild/NuGet. build_manifest is LIVE (PLAN-151): a pure-lexical read of the checkout's
// .csproj/.fsproj/.vbproj, Directory.Build.props/.targets, global.json, and restore-output
// PRESENCE, projected into the flat ecosystem-neutral BuildManifestResult with declared partiality
// where the shape cannot carry a fact — it too never runs dotnet/MSBuild/NuGet. generate_harness
// stays CONTRACT-PRESENT Unsupported (Prove-tier; the .NET effect rides the corpus repro-runtime
// sandbox, exactly as the Go/Java/JS/Python plugins ship it). Every op keeps the nil-payload
// hard-error guard (inv.4).
//
// The client (internal/plugin.dotnetPlugin) owns the timeout via exec.CommandContext; this
// process runs to completion on a single request. A hard failure sets Response.Error and
// exits non-zero; declared partiality is a success payload.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis"
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

// dispatch runs the requested operation. index_symbols, resolve_symbols, and resolve_versions
// call the real source-level .NET analysis (Assess-foundation pass); call_graph, find_ingresses,
// reachability, and compute_taint are LIVE (reachability/compute_taint always Partial(dynamic_dispatch));
// resolve_inventory is LIVE (PLAN-150) and build_manifest is LIVE (PLAN-151). generate_harness
// remains Unsupported (Prove-tier). An unknown op, or a missing per-op payload, is a hard failure
// (inv.4).
func dispatch(ctx context.Context, req plugin.Request) (plugin.Response, error) {
	switch req.Op {
	case plugin.OpIndexSymbols:
		if req.IndexSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing index_symbols request", req.Op)
		}
		res, err := dotnetanalysis.IndexSymbols(ctx, *req.IndexSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolIndex: &res}, nil

	case plugin.OpResolveSymbols:
		if req.ResolveSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_symbols request", req.Op)
		}
		res, err := dotnetanalysis.ResolveDependencySymbols(ctx, *req.ResolveSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolResolution: &res}, nil

	case plugin.OpResolveVersions:
		if req.ResolveVersions == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_versions request", req.Op)
		}
		res, err := dotnetanalysis.ResolveDependencyVersions(ctx, *req.ResolveVersions)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{VersionResult: &res}, nil

	case plugin.OpCallGraph:
		if req.CallGraph == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing call_graph request", req.Op)
		}
		res, err := dotnetanalysis.CallGraph(ctx, *req.CallGraph)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{CallGraph: &res}, nil

	case plugin.OpFindIngresses:
		if req.FindIngresses == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing find_ingresses request", req.Op)
		}
		res, err := dotnetanalysis.FindIngresses(ctx, *req.FindIngresses)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Ingress: &res}, nil

	case plugin.OpReachability:
		if req.Reachability == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing reachability request", req.Op)
		}
		res, err := dotnetanalysis.Reachability(ctx, *req.Reachability)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Reachability: &res}, nil

	case plugin.OpComputeTaint:
		if req.ComputeTaint == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing compute_taint request", req.Op)
		}
		res, err := dotnetanalysis.ComputeTaint(ctx, *req.ComputeTaint)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Taint: &res}, nil

	case plugin.OpResolveInventory:
		if req.ResolveInventory == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_inventory request", req.Op)
		}
		res, err := dotnetanalysis.ResolveInventory(ctx, *req.ResolveInventory)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Inventory: &res}, nil

	case plugin.OpGenerateHarness:
		if req.GenerateHarness == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing generate_harness request", req.Op)
		}
		return plugin.Response{Harness: &plugin.HarnessResult{Partiality: plugin.Unsupported()}}, nil

	case plugin.OpBuildManifest:
		if req.BuildManifest == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing build_manifest request", req.Op)
		}
		res, err := dotnetanalysis.BuildManifest(ctx, *req.BuildManifest)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{BuildManifest: &res}, nil

	case plugin.OpCapabilityManifest:
		// Capability manifest CONTENT is Phase-4; this cycle returns honest absence
		// (Supported:false), never a Supported:true manifest with empty axes.
		return plugin.Response{Manifest: &capability.Manifest{Supported: false, Language: "dotnet"}}, nil

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
