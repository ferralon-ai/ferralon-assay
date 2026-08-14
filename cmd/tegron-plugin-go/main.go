// Command tegron-plugin-go is the out-of-process Go language analysis subprocess
// (inv.8). It reads exactly one newline-delimited JSON plugin.Request from stdin,
// dispatches on Op to the in-process goanalysis functions (the 5 live ops) or returns a
// declared-Unsupported partiality (the 3 Phase-1 contract stubs), and writes exactly one
// newline-delimited JSON plugin.Response to stdout. The analysis libraries (go/packages,
// x/tools, x/vuln) link ONLY into this binary — never into tegrond.
//
// The client (internal/plugin.goPlugin) owns the timeout via exec.CommandContext; this
// process runs to completion on a single request. A hard failure sets Response.Error and
// exits non-zero; declared partiality is a success payload, not an error.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ferralon-ai/ferralon-assay/capability"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func main() {
	// This process exists ONLY to analyze a single standalone module dir (the analyzed
	// target's own module) — it must NEVER consult an ambient Go workspace, e.g. Tegron's
	// own go.work when the plugin runs during development or from the live corpus suite
	// (whose repro modules live UNDER the ferralon-assay module tree and are not go.work
	// members). LoadProgram already forces GOWORK=off per-call, but Reachability runs
	// govulncheck in-process via x/vuln/scan, which reads the ambient GOWORK and would
	// fail with "directory prefix . does not contain modules listed in go.work". Neutralize
	// it once at entry so every in-process analyzer is workspace-blind.
	_ = os.Setenv("GOWORK", "off")
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

// dispatch runs the requested operation. The 5 live ops call goanalysis and set the
// matching payload; the 3 stub ops return their result type with Unsupported partiality.
// A returned error is a hard failure (inv.4) — no retry, surfaced to the client.
func dispatch(ctx context.Context, req plugin.Request) (plugin.Response, error) {
	switch req.Op {
	case plugin.OpIndexSymbols:
		if req.IndexSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing index_symbols request", req.Op)
		}
		res, err := goanalysis.IndexSymbols(ctx, *req.IndexSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolIndex: &res}, nil

	case plugin.OpResolveSymbols:
		if req.ResolveSymbols == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_symbols request", req.Op)
		}
		res, err := goanalysis.ResolveDependencySymbols(ctx, *req.ResolveSymbols)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{SymbolResolution: &res}, nil

	case plugin.OpResolveVersions:
		if req.ResolveVersions == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing resolve_versions request", req.Op)
		}
		// Go dependency versions come from go.mod, resolved in-pipeline (not via this op);
		// the Go plugin declares the pom/gradle version op Unsupported.
		return plugin.Response{VersionResult: &plugin.DependencyVersionResult{Partiality: plugin.Unsupported()}}, nil

	case plugin.OpCallGraph:
		if req.CallGraph == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing call_graph request", req.Op)
		}
		res, err := goanalysis.CallGraph(ctx, *req.CallGraph)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{CallGraph: &res}, nil

	case plugin.OpFindIngresses:
		if req.FindIngresses == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing find_ingresses request", req.Op)
		}
		res, err := goanalysis.FindIngresses(ctx, *req.FindIngresses)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Ingress: &res}, nil

	case plugin.OpReachability:
		if req.Reachability == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing reachability request", req.Op)
		}
		res, err := goanalysis.Reachability(ctx, *req.Reachability)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Reachability: &res}, nil

	case plugin.OpComputeTaint:
		if req.ComputeTaint == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing compute_taint request", req.Op)
		}
		res, err := goanalysis.ComputeTaint(ctx, *req.ComputeTaint)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Taint: &res}, nil

	case plugin.OpGenerateHarness:
		if req.GenerateHarness == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing generate_harness request", req.Op)
		}
		res, err := goanalysis.GenerateHarness(ctx, *req.GenerateHarness)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{Harness: &res}, nil

	case plugin.OpBuildManifest:
		if req.BuildManifest == nil {
			return plugin.Response{}, fmt.Errorf("%s: missing build_manifest request", req.Op)
		}
		res, err := goanalysis.BuildManifest(ctx, *req.BuildManifest)
		if err != nil {
			return plugin.Response{}, err
		}
		return plugin.Response{BuildManifest: &res}, nil

	case plugin.OpResolveInventory:
		// Go's whole-graph dependency resolver is PLAN-140; this cycle lands the op
		// wired to a declared-Unsupported inventory (never a Complete() zero-node
		// graph, which would falsely claim "no dependencies"). §5 C5.
		return plugin.Response{Inventory: &plugin.DependencyInventory{Partiality: plugin.Unsupported()}}, nil

	case plugin.OpCapabilityManifest:
		// Go's capability manifest CONTENT is Phase-4 (PLAN-4x0); this cycle lands the op
		// wired to honest absence (Supported:false), never a Supported:true manifest with
		// empty axes.
		return plugin.Response{Manifest: &capability.Manifest{Supported: false, Language: "go"}}, nil

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
