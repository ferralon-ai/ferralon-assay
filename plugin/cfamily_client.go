package plugin

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/capability"
)

// cfamilyPlugin is the out-of-process client for the C/C++ (C-family) language plugin. It is
// the exact analog of goPlugin/javaPlugin/kotlinPlugin/dotnetPlugin: it implements
// LanguagePlugin by execing the assay-plugin-cfamily subprocess once per operation and
// exchanging a single newline-delimited JSON Request/Response over the child's stdin/stdout.
// Like the others it imports no analysis code — the C-family analysis (when it lands in
// Phase 1) links only into the subprocess binary (inv.8). At Phase 0 the lane is a skeleton:
// every operation returns declared partiality (honest absence), never a fabricated result.
type cfamilyPlugin struct {
	bin string // resolved path to the assay-plugin-cfamily binary

	metricsOnce sync.Once
	metrics     pluginMetrics
}

var _ LanguagePlugin = (*cfamilyPlugin)(nil)

// CFamilyOption configures a cfamilyPlugin during construction.
type CFamilyOption func(*cfamilyPlugin)

// WithCFamilyBinaryPath sets an explicit path to the assay-plugin-cfamily binary, taking
// precedence over PATH lookup.
func WithCFamilyBinaryPath(path string) CFamilyOption {
	return func(p *cfamilyPlugin) { p.bin = path }
}

// NewCFamilyPlugin constructs the subprocess-backed C-family plugin client. Binary discovery
// mirrors NewKotlinPlugin: an explicit path via WithCFamilyBinaryPath takes precedence;
// otherwise exec.LookPath resolves BinaryName("cfamily") on PATH.
func NewCFamilyPlugin(opts ...CFamilyOption) (LanguagePlugin, error) {
	p := &cfamilyPlugin{}
	for _, opt := range opts {
		opt(p)
	}
	if p.bin == "" {
		bin, err := exec.LookPath(BinaryName("cfamily"))
		if err != nil {
			return nil, fmt.Errorf("plugin: discover %s: %w", BinaryName("cfamily"), err)
		}
		p.bin = bin
	}
	return p, nil
}

func (*cfamilyPlugin) Language() string { return "cfamily" }

// run meters one language-plugin subprocess call around the shared bounded exchange
// execSubprocess performs, via the single record site runSubprocessCall that every language
// plugin's run funnels through (see subprocess.go).
func (p *cfamilyPlugin) run(ctx context.Context, req Request) (*Response, error) {
	p.ensureMetrics()
	return runSubprocessCall(ctx, p.bin, p.Language(), &p.metrics, req)
}

// ensureMetrics lazily creates the client's instruments on first use, mirroring
// kotlinPlugin.ensureMetrics (see metrics.go).
func (p *cfamilyPlugin) ensureMetrics() {
	p.metricsOnce.Do(func() { p.metrics = newPluginMetrics() })
}

func (p *cfamilyPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	resp, err := p.run(ctx, Request{Op: OpIndexSymbols, IndexSymbols: &req})
	if err != nil {
		return SymbolIndexResult{}, err
	}
	if resp.SymbolIndex == nil {
		return SymbolIndexResult{}, fmt.Errorf("plugin: %s response missing symbol_index payload", OpIndexSymbols)
	}
	return *resp.SymbolIndex, nil
}

func (p *cfamilyPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveSymbols, ResolveSymbols: &req})
	if err != nil {
		return SymbolResolutionResult{}, err
	}
	if resp.SymbolResolution == nil {
		return SymbolResolutionResult{}, fmt.Errorf("plugin: %s response missing symbol_resolution payload", OpResolveSymbols)
	}
	return *resp.SymbolResolution, nil
}

func (p *cfamilyPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveVersions, ResolveVersions: &req})
	if err != nil {
		return DependencyVersionResult{}, err
	}
	if resp.VersionResult == nil {
		return DependencyVersionResult{}, fmt.Errorf("plugin: %s response missing version_result payload", OpResolveVersions)
	}
	return *resp.VersionResult, nil
}

func (p *cfamilyPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	resp, err := p.run(ctx, Request{Op: OpCallGraph, CallGraph: &req})
	if err != nil {
		return CallGraphResult{}, err
	}
	if resp.CallGraph == nil {
		return CallGraphResult{}, fmt.Errorf("plugin: %s response missing call_graph payload", OpCallGraph)
	}
	return *resp.CallGraph, nil
}

func (p *cfamilyPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	resp, err := p.run(ctx, Request{Op: OpFindIngresses, FindIngresses: &req})
	if err != nil {
		return IngressResult{}, err
	}
	if resp.Ingress == nil {
		return IngressResult{}, fmt.Errorf("plugin: %s response missing ingress payload", OpFindIngresses)
	}
	return *resp.Ingress, nil
}

func (p *cfamilyPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	resp, err := p.run(ctx, Request{Op: OpReachability, Reachability: &req})
	if err != nil {
		return ReachabilityResult{}, err
	}
	if resp.Reachability == nil {
		return ReachabilityResult{}, fmt.Errorf("plugin: %s response missing reachability payload", OpReachability)
	}
	return *resp.Reachability, nil
}

func (p *cfamilyPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	resp, err := p.run(ctx, Request{Op: OpComputeTaint, ComputeTaint: &req})
	if err != nil {
		return TaintResult{}, err
	}
	if resp.Taint == nil {
		return TaintResult{}, fmt.Errorf("plugin: %s response missing taint payload", OpComputeTaint)
	}
	return *resp.Taint, nil
}

func (p *cfamilyPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	resp, err := p.run(ctx, Request{Op: OpGenerateHarness, GenerateHarness: &req})
	if err != nil {
		return HarnessResult{}, err
	}
	if resp.Harness == nil {
		return HarnessResult{}, fmt.Errorf("plugin: %s response missing harness payload", OpGenerateHarness)
	}
	return *resp.Harness, nil
}

func (p *cfamilyPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	resp, err := p.run(ctx, Request{Op: OpBuildManifest, BuildManifest: &req})
	if err != nil {
		return BuildManifestResult{}, err
	}
	if resp.BuildManifest == nil {
		return BuildManifestResult{}, fmt.Errorf("plugin: %s response missing build_manifest payload", OpBuildManifest)
	}
	return *resp.BuildManifest, nil
}

func (p *cfamilyPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveInventory, ResolveInventory: &req})
	if err != nil {
		return DependencyInventory{}, err
	}
	if resp.Inventory == nil {
		return DependencyInventory{}, fmt.Errorf("plugin: %s response missing inventory payload", OpResolveInventory)
	}
	return *resp.Inventory, nil
}

func (p *cfamilyPlugin) CapabilityManifest(ctx context.Context, req CapabilityManifestRequest) (capability.Manifest, error) {
	resp, err := p.run(ctx, Request{Op: OpCapabilityManifest, CapabilityManifest: &req})
	if err != nil {
		return capability.Manifest{}, err
	}
	if resp.Manifest == nil {
		return capability.Manifest{}, fmt.Errorf("plugin: %s response missing manifest payload", OpCapabilityManifest)
	}
	return *resp.Manifest, nil
}
