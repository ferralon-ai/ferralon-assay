package plugin

import (
	"context"
	"fmt"
	"os/exec"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/capability"
)

// javaPlugin is the out-of-process client for the Java language plugin. It is the
// exact analog of goPlugin: it implements LanguagePlugin by execing the
// tegron-plugin-java subprocess once per operation and exchanging a single
// newline-delimited JSON Request/Response over the child's stdin/stdout. Like
// goPlugin it imports neither internal/plugin/javaanalysis nor any heavy parsing
// code — the Java analysis links only into the subprocess binary (inv.8).
type javaPlugin struct {
	bin string // resolved path to the tegron-plugin-java binary

	metricsOnce sync.Once
	metrics     pluginMetrics
}

var _ LanguagePlugin = (*javaPlugin)(nil)

// JavaOption configures a javaPlugin during construction.
type JavaOption func(*javaPlugin)

// WithJavaBinaryPath sets an explicit path to the tegron-plugin-java binary,
// taking precedence over PATH lookup.
func WithJavaBinaryPath(path string) JavaOption {
	return func(p *javaPlugin) { p.bin = path }
}

// NewJavaPlugin constructs the subprocess-backed Java plugin client. Binary
// discovery mirrors NewGoPlugin: an explicit path via WithJavaBinaryPath takes
// precedence; otherwise exec.LookPath resolves "tegron-plugin-java" on PATH.
func NewJavaPlugin(opts ...JavaOption) (LanguagePlugin, error) {
	p := &javaPlugin{}
	for _, opt := range opts {
		opt(p)
	}
	if p.bin == "" {
		bin, err := exec.LookPath("tegron-plugin-java")
		if err != nil {
			return nil, fmt.Errorf("plugin: discover tegron-plugin-java: %w", err)
		}
		p.bin = bin
	}
	return p, nil
}

func (*javaPlugin) Language() string { return "java" }

// run meters one language-plugin subprocess call around the
// shared bounded exchange execSubprocess performs, via the single record site
// runSubprocessCall that every language plugin's run funnels through (see subprocess.go) —
// identical in shape to goPlugin.run/jsPlugin.run/pythonPlugin.run/dotnetPlugin.run.
func (p *javaPlugin) run(ctx context.Context, req Request) (*Response, error) {
	p.ensureMetrics()
	return runSubprocessCall(ctx, p.bin, p.Language(), &p.metrics, req)
}

// ensureMetrics lazily creates the client's instruments on first use, mirroring
// goPlugin.ensureMetrics (see metrics.go).
func (p *javaPlugin) ensureMetrics() {
	p.metricsOnce.Do(func() { p.metrics = newPluginMetrics() })
}

// IndexSymbols is the one LIVE Java op: it drives the subprocess's real source
// indexer and returns its SymbolIndexResult (with declared partiality).
func (p *javaPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	resp, err := p.run(ctx, Request{Op: OpIndexSymbols, IndexSymbols: &req})
	if err != nil {
		return SymbolIndexResult{}, err
	}
	if resp.SymbolIndex == nil {
		return SymbolIndexResult{}, fmt.Errorf("plugin: %s response missing symbol_index payload", OpIndexSymbols)
	}
	return *resp.SymbolIndex, nil
}

// The remaining ops are CONTRACT-PRESENT for Java but not yet implemented in this
// increment. Each calls the subprocess, which returns its result type carrying
// Unsupported() partiality (the same convention the Go plugin uses for its
// Phase-1 stub ops). This is a real seam: the next Java dispatch implements the
// op in javaanalysis + the subprocess switch, and the client decode below is
// already correct.

func (p *javaPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveSymbols, ResolveSymbols: &req})
	if err != nil {
		return SymbolResolutionResult{}, err
	}
	if resp.SymbolResolution == nil {
		return SymbolResolutionResult{}, fmt.Errorf("plugin: %s response missing symbol_resolution payload", OpResolveSymbols)
	}
	return *resp.SymbolResolution, nil
}

func (p *javaPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveVersions, ResolveVersions: &req})
	if err != nil {
		return DependencyVersionResult{}, err
	}
	if resp.VersionResult == nil {
		return DependencyVersionResult{}, fmt.Errorf("plugin: %s response missing version_result payload", OpResolveVersions)
	}
	return *resp.VersionResult, nil
}

func (p *javaPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	resp, err := p.run(ctx, Request{Op: OpCallGraph, CallGraph: &req})
	if err != nil {
		return CallGraphResult{}, err
	}
	if resp.CallGraph == nil {
		return CallGraphResult{}, fmt.Errorf("plugin: %s response missing call_graph payload", OpCallGraph)
	}
	return *resp.CallGraph, nil
}

func (p *javaPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	resp, err := p.run(ctx, Request{Op: OpFindIngresses, FindIngresses: &req})
	if err != nil {
		return IngressResult{}, err
	}
	if resp.Ingress == nil {
		return IngressResult{}, fmt.Errorf("plugin: %s response missing ingress payload", OpFindIngresses)
	}
	return *resp.Ingress, nil
}

func (p *javaPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	resp, err := p.run(ctx, Request{Op: OpReachability, Reachability: &req})
	if err != nil {
		return ReachabilityResult{}, err
	}
	if resp.Reachability == nil {
		return ReachabilityResult{}, fmt.Errorf("plugin: %s response missing reachability payload", OpReachability)
	}
	return *resp.Reachability, nil
}

func (p *javaPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	resp, err := p.run(ctx, Request{Op: OpComputeTaint, ComputeTaint: &req})
	if err != nil {
		return TaintResult{}, err
	}
	if resp.Taint == nil {
		return TaintResult{}, fmt.Errorf("plugin: %s response missing taint payload", OpComputeTaint)
	}
	return *resp.Taint, nil
}

func (p *javaPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	resp, err := p.run(ctx, Request{Op: OpGenerateHarness, GenerateHarness: &req})
	if err != nil {
		return HarnessResult{}, err
	}
	if resp.Harness == nil {
		return HarnessResult{}, fmt.Errorf("plugin: %s response missing harness payload", OpGenerateHarness)
	}
	return *resp.Harness, nil
}

func (p *javaPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	resp, err := p.run(ctx, Request{Op: OpBuildManifest, BuildManifest: &req})
	if err != nil {
		return BuildManifestResult{}, err
	}
	if resp.BuildManifest == nil {
		return BuildManifestResult{}, fmt.Errorf("plugin: %s response missing build_manifest payload", OpBuildManifest)
	}
	return *resp.BuildManifest, nil
}

func (p *javaPlugin) ResolveInventory(ctx context.Context, req ResolveInventoryRequest) (DependencyInventory, error) {
	resp, err := p.run(ctx, Request{Op: OpResolveInventory, ResolveInventory: &req})
	if err != nil {
		return DependencyInventory{}, err
	}
	if resp.Inventory == nil {
		return DependencyInventory{}, fmt.Errorf("plugin: %s response missing inventory payload", OpResolveInventory)
	}
	return *resp.Inventory, nil
}

func (p *javaPlugin) CapabilityManifest(ctx context.Context, req CapabilityManifestRequest) (capability.Manifest, error) {
	resp, err := p.run(ctx, Request{Op: OpCapabilityManifest, CapabilityManifest: &req})
	if err != nil {
		return capability.Manifest{}, err
	}
	if resp.Manifest == nil {
		return capability.Manifest{}, fmt.Errorf("plugin: %s response missing manifest payload", OpCapabilityManifest)
	}
	return *resp.Manifest, nil
}
