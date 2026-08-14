package plugin

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
)

// pythonPlugin is the out-of-process client for the Python language plugin. It is the
// exact analog of goPlugin/javaPlugin/jsPlugin: it implements LanguagePlugin by execing
// the tegron-plugin-python subprocess once per operation and exchanging a single
// newline-delimited JSON Request/Response over the child's stdin/stdout. Like the
// others it imports neither internal/plugin/pythonanalysis nor any parsing code — the
// Python analysis links only into the subprocess binary (inv.8).
type pythonPlugin struct {
	bin string // resolved path to the tegron-plugin-python binary

	metricsOnce sync.Once
	metrics     pluginMetrics
}

var _ LanguagePlugin = (*pythonPlugin)(nil)

// PythonOption configures a pythonPlugin during construction.
type PythonOption func(*pythonPlugin)

// WithPythonBinaryPath sets an explicit path to the tegron-plugin-python binary, taking
// precedence over PATH lookup.
func WithPythonBinaryPath(path string) PythonOption {
	return func(p *pythonPlugin) { p.bin = path }
}

// NewPythonPlugin constructs the subprocess-backed Python plugin client. Binary
// discovery mirrors NewGoPlugin/NewJSPlugin: an explicit path via WithPythonBinaryPath
// takes precedence; otherwise exec.LookPath resolves "tegron-plugin-python" on PATH.
func NewPythonPlugin(opts ...PythonOption) (LanguagePlugin, error) {
	p := &pythonPlugin{}
	for _, opt := range opts {
		opt(p)
	}
	if p.bin == "" {
		bin, err := exec.LookPath("tegron-plugin-python")
		if err != nil {
			return nil, fmt.Errorf("plugin: discover tegron-plugin-python: %w", err)
		}
		p.bin = bin
	}
	return p, nil
}

func (*pythonPlugin) Language() string { return "python" }

// run meters one language-plugin subprocess call around the
// shared bounded exchange execSubprocess performs, via the single record site
// runSubprocessCall that every language plugin's run funnels through (see subprocess.go) —
// identical in shape to goPlugin.run/javaPlugin.run/jsPlugin.run/dotnetPlugin.run.
func (p *pythonPlugin) run(ctx context.Context, req Request) (*Response, error) {
	p.ensureMetrics()
	return runSubprocessCall(ctx, p.bin, p.Language(), &p.metrics, req)
}

// ensureMetrics lazily creates the client's instruments on first use, mirroring
// goPlugin.ensureMetrics (see metrics.go).
func (p *pythonPlugin) ensureMetrics() {
	p.metricsOnce.Do(func() { p.metrics = newPluginMetrics() })
}

// IndexSymbols drives the subprocess's real source indexer.
func (p *pythonPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	resp, err := p.run(ctx, Request{Op: OpIndexSymbols, IndexSymbols: &req})
	if err != nil {
		return SymbolIndexResult{}, err
	}
	if resp.SymbolIndex == nil {
		return SymbolIndexResult{}, fmt.Errorf("plugin: %s response missing symbol_index payload", OpIndexSymbols)
	}
	return *resp.SymbolIndex, nil
}

func (p *pythonPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveSymbols, ResolveSymbols: &req})
	if err != nil {
		return SymbolResolutionResult{}, err
	}
	if resp.SymbolResolution == nil {
		return SymbolResolutionResult{}, fmt.Errorf("plugin: %s response missing symbol_resolution payload", OpResolveSymbols)
	}
	return *resp.SymbolResolution, nil
}

func (p *pythonPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveVersions, ResolveVersions: &req})
	if err != nil {
		return DependencyVersionResult{}, err
	}
	if resp.VersionResult == nil {
		return DependencyVersionResult{}, fmt.Errorf("plugin: %s response missing version_result payload", OpResolveVersions)
	}
	return *resp.VersionResult, nil
}

func (p *pythonPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	resp, err := p.run(ctx, Request{Op: OpCallGraph, CallGraph: &req})
	if err != nil {
		return CallGraphResult{}, err
	}
	if resp.CallGraph == nil {
		return CallGraphResult{}, fmt.Errorf("plugin: %s response missing call_graph payload", OpCallGraph)
	}
	return *resp.CallGraph, nil
}

func (p *pythonPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	resp, err := p.run(ctx, Request{Op: OpFindIngresses, FindIngresses: &req})
	if err != nil {
		return IngressResult{}, err
	}
	if resp.Ingress == nil {
		return IngressResult{}, fmt.Errorf("plugin: %s response missing ingress payload", OpFindIngresses)
	}
	return *resp.Ingress, nil
}

func (p *pythonPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	resp, err := p.run(ctx, Request{Op: OpReachability, Reachability: &req})
	if err != nil {
		return ReachabilityResult{}, err
	}
	if resp.Reachability == nil {
		return ReachabilityResult{}, fmt.Errorf("plugin: %s response missing reachability payload", OpReachability)
	}
	return *resp.Reachability, nil
}

func (p *pythonPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	resp, err := p.run(ctx, Request{Op: OpComputeTaint, ComputeTaint: &req})
	if err != nil {
		return TaintResult{}, err
	}
	if resp.Taint == nil {
		return TaintResult{}, fmt.Errorf("plugin: %s response missing taint payload", OpComputeTaint)
	}
	return *resp.Taint, nil
}

func (p *pythonPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	resp, err := p.run(ctx, Request{Op: OpGenerateHarness, GenerateHarness: &req})
	if err != nil {
		return HarnessResult{}, err
	}
	if resp.Harness == nil {
		return HarnessResult{}, fmt.Errorf("plugin: %s response missing harness payload", OpGenerateHarness)
	}
	return *resp.Harness, nil
}

func (p *pythonPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	resp, err := p.run(ctx, Request{Op: OpBuildManifest, BuildManifest: &req})
	if err != nil {
		return BuildManifestResult{}, err
	}
	if resp.BuildManifest == nil {
		return BuildManifestResult{}, fmt.Errorf("plugin: %s response missing build_manifest payload", OpBuildManifest)
	}
	return *resp.BuildManifest, nil
}

func (p *pythonPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveInventory, ResolveInventory: &req})
	if err != nil {
		return DependencyInventory{}, err
	}
	if resp.Inventory == nil {
		return DependencyInventory{}, fmt.Errorf("plugin: %s response missing inventory payload", OpResolveInventory)
	}
	return *resp.Inventory, nil
}
