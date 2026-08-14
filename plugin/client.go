package plugin

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
)

// goPlugin is the out-of-process client stub: it implements LanguagePlugin by execing
// the tegron-plugin-go subprocess once per operation and exchanging a single
// newline-delimited JSON Request/Response over the child's stdin/stdout (§4.1). It
// deliberately imports neither internal/plugin/goanalysis nor the heavy analysis
// libraries (x/tools, x/vuln) — the analysis code links only into the subprocess
// binary. That import-light boundary is the inv.8 mechanism (§6).
type goPlugin struct {
	bin string // resolved path to the tegron-plugin-go binary

	metricsOnce sync.Once
	metrics     pluginMetrics
}

var _ LanguagePlugin = (*goPlugin)(nil)

// Option configures a goPlugin during construction.
type Option func(*goPlugin)

// WithBinaryPath sets an explicit path to the tegron-plugin-go binary, taking
// precedence over PATH lookup (§4.4).
func WithBinaryPath(path string) Option {
	return func(p *goPlugin) { p.bin = path }
}

// NewGoPlugin constructs the subprocess-backed plugin client. Binary discovery (§4.4):
// an explicit path via WithBinaryPath takes precedence; otherwise exec.LookPath resolves
// "tegron-plugin-go" on PATH.
func NewGoPlugin(opts ...Option) (LanguagePlugin, error) {
	p := &goPlugin{}
	for _, opt := range opts {
		opt(p)
	}
	if p.bin == "" {
		bin, err := exec.LookPath("tegron-plugin-go")
		if err != nil {
			return nil, fmt.Errorf("plugin: discover tegron-plugin-go: %w", err)
		}
		p.bin = bin
	}
	return p, nil
}

func (*goPlugin) Language() string { return "go" }

// run meters one language-plugin subprocess call around the
// shared bounded exchange execSubprocess performs, via the single record site
// runSubprocessCall that every language plugin's run funnels through (see subprocess.go) — one
// instrument site covers them all, and it cannot drift per-language since there is only one body.
func (p *goPlugin) run(ctx context.Context, req Request) (*Response, error) {
	p.ensureMetrics()
	return runSubprocessCall(ctx, p.bin, p.Language(), &p.metrics, req)
}

func (p *goPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	resp, err := p.run(ctx, Request{Op: OpIndexSymbols, IndexSymbols: &req})
	if err != nil {
		return SymbolIndexResult{}, err
	}
	if resp.SymbolIndex == nil {
		return SymbolIndexResult{}, fmt.Errorf("plugin: %s response missing symbol_index payload", OpIndexSymbols)
	}
	return *resp.SymbolIndex, nil
}

func (p *goPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveSymbols, ResolveSymbols: &req})
	if err != nil {
		return SymbolResolutionResult{}, err
	}
	if resp.SymbolResolution == nil {
		return SymbolResolutionResult{}, fmt.Errorf("plugin: %s response missing symbol_resolution payload", OpResolveSymbols)
	}
	return *resp.SymbolResolution, nil
}

func (p *goPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveVersions, ResolveVersions: &req})
	if err != nil {
		return DependencyVersionResult{}, err
	}
	if resp.VersionResult == nil {
		return DependencyVersionResult{}, fmt.Errorf("plugin: %s response missing version_result payload", OpResolveVersions)
	}
	return *resp.VersionResult, nil
}

func (p *goPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	resp, err := p.run(ctx, Request{Op: OpCallGraph, CallGraph: &req})
	if err != nil {
		return CallGraphResult{}, err
	}
	if resp.CallGraph == nil {
		return CallGraphResult{}, fmt.Errorf("plugin: %s response missing call_graph payload", OpCallGraph)
	}
	return *resp.CallGraph, nil
}

func (p *goPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	resp, err := p.run(ctx, Request{Op: OpFindIngresses, FindIngresses: &req})
	if err != nil {
		return IngressResult{}, err
	}
	if resp.Ingress == nil {
		return IngressResult{}, fmt.Errorf("plugin: %s response missing ingress payload", OpFindIngresses)
	}
	return *resp.Ingress, nil
}

func (p *goPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	resp, err := p.run(ctx, Request{Op: OpReachability, Reachability: &req})
	if err != nil {
		return ReachabilityResult{}, err
	}
	if resp.Reachability == nil {
		return ReachabilityResult{}, fmt.Errorf("plugin: %s response missing reachability payload", OpReachability)
	}
	return *resp.Reachability, nil
}

func (p *goPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	resp, err := p.run(ctx, Request{Op: OpComputeTaint, ComputeTaint: &req})
	if err != nil {
		return TaintResult{}, err
	}
	if resp.Taint == nil {
		return TaintResult{}, fmt.Errorf("plugin: %s response missing taint payload", OpComputeTaint)
	}
	return *resp.Taint, nil
}

func (p *goPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	resp, err := p.run(ctx, Request{Op: OpGenerateHarness, GenerateHarness: &req})
	if err != nil {
		return HarnessResult{}, err
	}
	if resp.Harness == nil {
		return HarnessResult{}, fmt.Errorf("plugin: %s response missing harness payload", OpGenerateHarness)
	}
	return *resp.Harness, nil
}

func (p *goPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	resp, err := p.run(ctx, Request{Op: OpBuildManifest, BuildManifest: &req})
	if err != nil {
		return BuildManifestResult{}, err
	}
	if resp.BuildManifest == nil {
		return BuildManifestResult{}, fmt.Errorf("plugin: %s response missing build_manifest payload", OpBuildManifest)
	}
	return *resp.BuildManifest, nil
}

func (p *goPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveInventory, ResolveInventory: &req})
	if err != nil {
		return DependencyInventory{}, err
	}
	if resp.Inventory == nil {
		return DependencyInventory{}, fmt.Errorf("plugin: %s response missing inventory payload", OpResolveInventory)
	}
	return *resp.Inventory, nil
}
