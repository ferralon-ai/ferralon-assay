package plugin

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/capability"
)

// dotnetPlugin is the out-of-process client for the .NET/C# language plugin. It is the
// exact analog of goPlugin/javaPlugin/jsPlugin/pythonPlugin: it implements LanguagePlugin
// by execing the tegron-plugin-dotnet subprocess once per operation and exchanging a single
// newline-delimited JSON Request/Response over the child's stdin/stdout. Like the others it
// imports neither internal/plugin/dotnetanalysis nor any parsing code — the .NET analysis
// links only into the subprocess binary (inv.8).
type dotnetPlugin struct {
	bin string // resolved path to the tegron-plugin-dotnet binary

	metricsOnce sync.Once
	metrics     pluginMetrics
}

var _ LanguagePlugin = (*dotnetPlugin)(nil)

// DotNetOption configures a dotnetPlugin during construction.
type DotNetOption func(*dotnetPlugin)

// WithDotNetBinaryPath sets an explicit path to the tegron-plugin-dotnet binary, taking
// precedence over PATH lookup.
func WithDotNetBinaryPath(path string) DotNetOption {
	return func(p *dotnetPlugin) { p.bin = path }
}

// NewDotNetPlugin constructs the subprocess-backed .NET plugin client. Binary discovery
// mirrors NewGoPlugin/NewJSPlugin/NewPythonPlugin: an explicit path via WithDotNetBinaryPath
// takes precedence; otherwise exec.LookPath resolves "tegron-plugin-dotnet" on PATH.
func NewDotNetPlugin(opts ...DotNetOption) (LanguagePlugin, error) {
	p := &dotnetPlugin{}
	for _, opt := range opts {
		opt(p)
	}
	if p.bin == "" {
		bin, err := exec.LookPath("tegron-plugin-dotnet")
		if err != nil {
			return nil, fmt.Errorf("plugin: discover tegron-plugin-dotnet: %w", err)
		}
		p.bin = bin
	}
	return p, nil
}

func (*dotnetPlugin) Language() string { return "dotnet" }

// run meters one language-plugin subprocess call around the
// shared bounded exchange execSubprocess performs, via the single record site
// runSubprocessCall that every language plugin's run funnels through (see subprocess.go) —
// identical in shape to goPlugin.run/javaPlugin.run/jsPlugin.run/pythonPlugin.run.
func (p *dotnetPlugin) run(ctx context.Context, req Request) (*Response, error) {
	p.ensureMetrics()
	return runSubprocessCall(ctx, p.bin, p.Language(), &p.metrics, req)
}

// ensureMetrics lazily creates the client's instruments on first use, mirroring
// goPlugin.ensureMetrics (see metrics.go).
func (p *dotnetPlugin) ensureMetrics() {
	p.metricsOnce.Do(func() { p.metrics = newPluginMetrics() })
}

// IndexSymbols drives the subprocess's real source indexer.
func (p *dotnetPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	resp, err := p.run(ctx, Request{Op: OpIndexSymbols, IndexSymbols: &req})
	if err != nil {
		return SymbolIndexResult{}, err
	}
	if resp.SymbolIndex == nil {
		return SymbolIndexResult{}, fmt.Errorf("plugin: %s response missing symbol_index payload", OpIndexSymbols)
	}
	return *resp.SymbolIndex, nil
}

func (p *dotnetPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveSymbols, ResolveSymbols: &req})
	if err != nil {
		return SymbolResolutionResult{}, err
	}
	if resp.SymbolResolution == nil {
		return SymbolResolutionResult{}, fmt.Errorf("plugin: %s response missing symbol_resolution payload", OpResolveSymbols)
	}
	return *resp.SymbolResolution, nil
}

func (p *dotnetPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveVersions, ResolveVersions: &req})
	if err != nil {
		return DependencyVersionResult{}, err
	}
	if resp.VersionResult == nil {
		return DependencyVersionResult{}, fmt.Errorf("plugin: %s response missing version_result payload", OpResolveVersions)
	}
	return *resp.VersionResult, nil
}

func (p *dotnetPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	resp, err := p.run(ctx, Request{Op: OpCallGraph, CallGraph: &req})
	if err != nil {
		return CallGraphResult{}, err
	}
	if resp.CallGraph == nil {
		return CallGraphResult{}, fmt.Errorf("plugin: %s response missing call_graph payload", OpCallGraph)
	}
	return *resp.CallGraph, nil
}

func (p *dotnetPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	resp, err := p.run(ctx, Request{Op: OpFindIngresses, FindIngresses: &req})
	if err != nil {
		return IngressResult{}, err
	}
	if resp.Ingress == nil {
		return IngressResult{}, fmt.Errorf("plugin: %s response missing ingress payload", OpFindIngresses)
	}
	return *resp.Ingress, nil
}

func (p *dotnetPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	resp, err := p.run(ctx, Request{Op: OpReachability, Reachability: &req})
	if err != nil {
		return ReachabilityResult{}, err
	}
	if resp.Reachability == nil {
		return ReachabilityResult{}, fmt.Errorf("plugin: %s response missing reachability payload", OpReachability)
	}
	return *resp.Reachability, nil
}

func (p *dotnetPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	resp, err := p.run(ctx, Request{Op: OpComputeTaint, ComputeTaint: &req})
	if err != nil {
		return TaintResult{}, err
	}
	if resp.Taint == nil {
		return TaintResult{}, fmt.Errorf("plugin: %s response missing taint payload", OpComputeTaint)
	}
	return *resp.Taint, nil
}

func (p *dotnetPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	resp, err := p.run(ctx, Request{Op: OpGenerateHarness, GenerateHarness: &req})
	if err != nil {
		return HarnessResult{}, err
	}
	if resp.Harness == nil {
		return HarnessResult{}, fmt.Errorf("plugin: %s response missing harness payload", OpGenerateHarness)
	}
	return *resp.Harness, nil
}

func (p *dotnetPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	resp, err := p.run(ctx, Request{Op: OpBuildManifest, BuildManifest: &req})
	if err != nil {
		return BuildManifestResult{}, err
	}
	if resp.BuildManifest == nil {
		return BuildManifestResult{}, fmt.Errorf("plugin: %s response missing build_manifest payload", OpBuildManifest)
	}
	return *resp.BuildManifest, nil
}

func (p *dotnetPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveInventory, ResolveInventory: &req})
	if err != nil {
		return DependencyInventory{}, err
	}
	if resp.Inventory == nil {
		return DependencyInventory{}, fmt.Errorf("plugin: %s response missing inventory payload", OpResolveInventory)
	}
	return *resp.Inventory, nil
}

func (p *dotnetPlugin) CapabilityManifest(ctx context.Context, req CapabilityManifestRequest) (capability.Manifest, error) {
	resp, err := p.run(ctx, Request{Op: OpCapabilityManifest, CapabilityManifest: &req})
	if err != nil {
		return capability.Manifest{}, err
	}
	if resp.Manifest == nil {
		return capability.Manifest{}, fmt.Errorf("plugin: %s response missing manifest payload", OpCapabilityManifest)
	}
	return *resp.Manifest, nil
}
