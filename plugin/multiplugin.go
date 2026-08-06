package plugin

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// PartialReasonNoPlugin is the canonical partiality reason for a codebase whose detected
// source language has no registered analyzer plugin (or whose build tree could not be
// classified). The multiplexer withholds evidence rather than fabricating a
// confident-empty result: absence of reachability evidence fails OPEN (inv.5), it never
// refutes.
const PartialReasonNoPlugin = "no_language_plugin"

// multiPlugin routes each LanguagePlugin operation to the sub-plugin whose Language()
// matches the source language of the codebase under analysis, detected from the
// operation's BuildDir via checkout.DetectLanguage — the same classification the pipeline's
// codebase_inventory stage uses, so routing and inventory agree. It is the seam that lets
// the pipeline's single WithPlugin injection serve every language: the pipeline holds one
// LanguagePlugin; this multiplexer fans the call out by language.
//
// Soundness (inv.5; unified-program §4): reachability is evidence that NARROWS toward
// candidate, and its ABSENCE fails open. A codebase whose language has no registered
// plugin — or a BuildDir that cannot be classified — yields a declared-PARTIAL empty
// result, never an error and never a confident-empty result. Constructing this multiplexer
// therefore adds no path by which zero-resolved-symbols could refute; a plugin that cannot
// resolve only adds or WITHHOLDS candidate evidence.
type multiPlugin struct {
	byLang  map[string]LanguagePlugin
	primary LanguagePlugin // answers Language() and serves ops that carry no BuildDir to route on
}

var _ LanguagePlugin = (*multiPlugin)(nil)

// NewMultiPlugin builds a language-routing multiplexer over the given plugins, keyed by
// each plugin's Language(). The FIRST non-nil plugin is the primary: it answers Language()
// — which the codebase_inventory version/manifest gate compares against the detected
// codebase language — and serves any operation that carries no BuildDir to route on. A
// later plugin with a duplicate Language() is ignored (first wins). Passing a single plugin
// yields a multiplexer indistinguishable from that plugin for its own language.
func NewMultiPlugin(plugins ...LanguagePlugin) LanguagePlugin {
	m := &multiPlugin{byLang: make(map[string]LanguagePlugin, len(plugins))}
	for _, p := range plugins {
		if p == nil {
			continue
		}
		if m.primary == nil {
			m.primary = p
		}
		if _, ok := m.byLang[p.Language()]; !ok {
			m.byLang[p.Language()] = p
		}
	}
	return m
}

// forDir selects the sub-plugin for the codebase rooted at buildDir, classifying the tree
// with checkout.DetectLanguage. It returns (nil, false) when the language is unrecognized
// or has no registered plugin — the caller then withholds (declared-partial), never errs.
func (m *multiPlugin) forDir(buildDir string) (LanguagePlugin, bool) {
	p, ok := m.byLang[checkout.DetectLanguage(buildDir)]
	return p, ok
}

// Language reports the primary plugin's language. It is consulted only by the
// codebase_inventory stage's version/manifest gate (Language() == detected language); the
// per-operation routing above is what actually serves each language. With the Go plugin
// passed first, the Go inventory path is preserved byte-for-byte, while a non-Go language
// whose plugin-based version read is not selected here simply falls OPEN (that version-axis
// lightup is the VersionScheme slice's concern, not plugin construction).
func (m *multiPlugin) Language() string {
	if m.primary != nil {
		return m.primary.Language()
	}
	return ""
}

func (m *multiPlugin) IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.IndexSymbols(ctx, req)
	}
	return SymbolIndexResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

func (m *multiPlugin) ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.ResolveDependencySymbols(ctx, req)
	}
	return SymbolResolutionResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

func (m *multiPlugin) ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.ResolveDependencyVersions(ctx, req)
	}
	return DependencyVersionResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

func (m *multiPlugin) CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.CallGraph(ctx, req)
	}
	return CallGraphResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

func (m *multiPlugin) FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.FindIngresses(ctx, req)
	}
	return IngressResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

func (m *multiPlugin) Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.Reachability(ctx, req)
	}
	return ReachabilityResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

func (m *multiPlugin) ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.ComputeTaint(ctx, req)
	}
	return TaintResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

func (m *multiPlugin) BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error) {
	if p, ok := m.forDir(req.BuildDir); ok {
		return p.BuildManifest(ctx, req)
	}
	return BuildManifestResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}

// GenerateHarnessRequest carries no BuildDir to route on (it names a sink/ingress/kind), so
// the multiplexer serves it from the primary plugin. This is a Phase-1 contract stub across
// every language (Unsupported), so there is nothing per-language to route.
func (m *multiPlugin) GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error) {
	if m.primary != nil {
		return m.primary.GenerateHarness(ctx, req)
	}
	return HarnessResult{Partiality: Partial(PartialReasonNoPlugin)}, nil
}
