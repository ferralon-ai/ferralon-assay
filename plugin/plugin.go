// Package plugin defines the LanguagePlugin contract: the interface a
// language-specific evidence producer implements, the value types it exchanges with
// the pipeline, the first-class Partiality declaration (inv.5), and an in-memory
// StubPlugin used by hermetic tests.
//
// This package is import-light by design: tegrond (internal/pipeline) imports it, and
// it MUST NOT import internal/plugin/goanalysis (which links the heavy analysis
// libraries). That import boundary is the inv.8 mechanism — analysis code lives only in
// the cmd/tegron-plugin-go subprocess binary, never in-process in the daemon.
package plugin

import "context"

// LanguagePlugin is the contract for one language's evidence production. Every operation
// returns artifacts (as typed results the pipeline marshals), never verdicts: the
// language-agnostic core forms the verdict, so that judgment stays uniform across languages
// (inv.6). Partiality is first-class: an operation that cannot fully resolve its answer
// declares it, never returns a confident-looking incomplete result.
type LanguagePlugin interface {
	// Language returns the language tag this plugin serves, e.g. "go".
	Language() string

	// --- LIVE in Phase 1 (Go) ---

	// IndexSymbols emits SCIP-qualified symbol ids stable across app + dependencies.
	IndexSymbols(ctx context.Context, req IndexSymbolsRequest) (SymbolIndexResult, error)

	// ResolveDependencySymbols maps an advisory's vulnerable symbol(s) to concrete symbols
	// in this codebase. The advisory identifiers are GIVEN (inv.7) — the plugin never
	// originates them.
	ResolveDependencySymbols(ctx context.Context, req ResolveSymbolsRequest) (SymbolResolutionResult, error)

	// ResolveDependencyVersions reads the codebase's declared dependency versions
	// (pom.xml / build.gradle for Java; Phase-1 Go: Unsupported) for the given advisory
	// coordinate. It NEVER guesses a version: a coordinate it cannot resolve confidently
	// (BOM-managed, unresolvable property indirection) is returned with Resolved=false so
	// the disqualification predicate fails OPEN (inv.5: unknown is never not-affected).
	ResolveDependencyVersions(ctx context.Context, req ResolveVersionsRequest) (DependencyVersionResult, error)

	// CallGraph builds the (possibly partial) call graph for the codebase.
	CallGraph(ctx context.Context, req CallGraphRequest) (CallGraphResult, error)

	// FindIngresses identifies framework-idiomatic entry points (HTTP routes, handlers).
	FindIngresses(ctx context.Context, req FindIngressesRequest) (IngressResult, error)

	// Reachability derives reachable (ingress, sink, path) candidate pairs for the given
	// vulnerable symbols, via govulncheck reconciled with the call graph.
	Reachability(ctx context.Context, req ReachabilityRequest) (ReachabilityResult, error)

	// --- CONTRACT-PRESENT STUBS in Phase 1 (return declared partiality, Unsupported) ---

	// ComputeTaint computes source→sink taint flows. Phase-1 Go: Unsupported.
	ComputeTaint(ctx context.Context, req ComputeTaintRequest) (TaintResult, error)

	// GenerateHarness scaffolds a fuzz/unit/integration harness. Phase-1 Go: Unsupported.
	GenerateHarness(ctx context.Context, req GenerateHarnessRequest) (HarnessResult, error)

	// BuildManifest produces enough to build and run the app under test. Phase-1 Go: Unsupported.
	BuildManifest(ctx context.Context, req BuildManifestRequest) (BuildManifestResult, error)
}

// Partiality declares whether an operation fully resolved its answer. A plugin that cannot
// (reflection, dynamic dispatch, cgo, tool failure) returns Complete=false with one or more
// machine-readable Reasons rather than a confident-looking incomplete result.
// It NEVER renders an unknown as "safe"/"not reachable" — the inv.5 boundary.
type Partiality struct {
	Complete bool     `json:"complete"`
	Reasons  []string `json:"reasons,omitempty"` // canonical reason codes; see PartialReason*
}

// Canonical partiality reason codes (machine-readable, stable strings).
const (
	PartialReasonReflection      = "reflection"         // calls via reflect.* invisible to static analysis
	PartialReasonDynamicDispatch = "dynamic_dispatch"   // interface dispatch not fully resolved
	PartialReasonCgo             = "cgo"                // native-code boundary (cgo) crossed
	PartialReasonUnsupported     = "unsupported_phase1" // operation is a Phase-1 contract stub
	PartialReasonToolFailure     = "tool_failure"       // a wrapped tool failed; surfaced, not retried (inv.4)
	PartialReasonNoIngress       = "no_known_ingress"   // reachable sink, no entry point found
	PartialReasonNoManifest      = "no_manifest"        // no lockfile/manifest to read installed versions from

	// PartialReasonReachabilityUndetermined is declared when a reachability pass could
	// not reach a determination — the advisory applies to this module and the analysis
	// neither found a path to the vulnerable code nor established that none exists.
	//
	// It exists to keep that case OFF the reflection/dynamic_dispatch codes. Those two
	// name limits of the METHOD, true of every scan of a language, and surfaces disclose
	// them quietly (report.ClassifyPartialityReason). An undetermined result is the
	// opposite: it is specific to THIS run and it is precisely what the run failed to
	// establish, so it must be disclosed as loudly as any other step that did not
	// happen. Overloading the quiet codes for it renders an unknown as a clean scan —
	// the inv.5 boundary this vocabulary exists to hold.
	PartialReasonReachabilityUndetermined = "reachability_undetermined"
)

// Complete is the constructor for a fully-resolved result.
func Complete() Partiality { return Partiality{Complete: true} }

// Partial constructs a declared-partial result with the given reason codes.
func Partial(reasons ...string) Partiality { return Partiality{Complete: false, Reasons: reasons} }

// Unsupported is the canonical Phase-1 contract-stub partiality.
func Unsupported() Partiality { return Partial(PartialReasonUnsupported) }

// --- shared inputs (the plugin is GIVEN ground truth; inv.7) ---

// IndexSymbolsRequest carries the buildable module to index.
type IndexSymbolsRequest struct {
	BuildDir string `json:"build_dir"` // checked-out module root (contains go.mod)
}

// CallGraphRequest carries the buildable module and the desired graph algorithm.
type CallGraphRequest struct {
	BuildDir  string `json:"build_dir"`
	Algorithm string `json:"algorithm,omitempty"` // "vta" (default) | "rta" | "cha"
}

// FindIngressesRequest carries the buildable module to scan for entry points.
type FindIngressesRequest struct {
	BuildDir string `json:"build_dir"`
}

// ResolveSymbolsRequest carries advisory identifiers from authoritative sources (inv.7).
type ResolveSymbolsRequest struct {
	BuildDir        string   `json:"build_dir"`
	PURL            string   `json:"purl"`             // e.g. pkg:golang/github.com/x/y@v1.2.3
	AdvisorySymbols []string `json:"advisory_symbols"` // vulnerable symbols from the advisory
	VulnID          string   `json:"vuln_id"`          // e.g. GO-2021-0001 (for govulncheck)
}

// ResolveVersionsRequest carries the advisory's dependency coordinate whose declared
// version the plugin should read from the build files. Coordinate identifies the wanted
// dependency in the language's native form ("groupId:artifactId" for Maven); the plugin
// matches it against the parsed pom.xml/build.gradle dependency declarations.
type ResolveVersionsRequest struct {
	BuildDir   string `json:"build_dir"`
	Coordinate string `json:"coordinate"` // e.g. "com.fasterxml.jackson.core:jackson-databind"
}

// ResolvedDependency is one declared dependency coordinate with its resolved version.
// Resolved is false (and Version empty) when the version could not be determined
// confidently (BOM-managed, unresolvable property indirection): an UNRESOLVED marker the
// disqualification predicate treats as "unknown" and fails OPEN on (inv.5).
type ResolvedDependency struct {
	Coordinate string `json:"coordinate"`        // "groupId:artifactId"
	Version    string `json:"version,omitempty"` // declared version; empty when Resolved=false
	Resolved   bool   `json:"resolved"`          // true ONLY when a concrete version was determined
	Source     string `json:"source,omitempty"`  // "pom" | "gradle" (provenance, informational)
}

// DependencyVersionResult reports the resolved declared version for the requested
// coordinate. Match is the dependency the plugin found for the request coordinate (with
// Resolved indicating whether its version is known); Found is false when no declaration of
// that coordinate exists in the build files at all.
type DependencyVersionResult struct {
	Partiality Partiality           `json:"partiality"`
	Found      bool                 `json:"found"` // a declaration of the request coordinate exists
	Match      ResolvedDependency   `json:"match"`
	All        []ResolvedDependency `json:"all,omitempty"` // every parsed declaration (evidence)
}

// ReachabilityRequest carries the resolved sinks to trace toward.
type ReachabilityRequest struct {
	BuildDir string   `json:"build_dir"`
	VulnID   string   `json:"vuln_id"` // drives govulncheck's advisory selection
	Symbols  []string `json:"symbols"` // resolved SCIP/symbol strings to confirm reachable
	// GoToolchain is the SUBJECT's Go toolchain the analysis must execute under, normalized
	// "go1.21.3". Empty — the default and the only value any non-Go lane ever sees —
	// means "run under whatever toolchain the analyzer already has", i.e. today's behavior.
	//
	// The caller sets it ONLY when it holds an EXACT subject-toolchain fact: absence of a symbol is
	// evidence about the toolchain the analysis actually ran on, so a lower bound licenses nothing
	// here. A plugin that cannot honor the request must fall back and say so via
	// ReachabilityResult.ScanToolchain rather than failing the scan.
	GoToolchain string `json:"go_toolchain,omitempty"`
}

// --- result payloads ---

// Symbol is one SCIP-qualified symbol id plus its human-readable form.
type Symbol struct {
	SCIP        string `json:"scip"`         // self-emitted SCIP symbol string
	DisplayName string `json:"display_name"` // e.g. github.com/x/y.(*T).Method
	Package     string `json:"package"`      // import path
}

// SymbolIndexResult is IndexSymbols' response: the SCIP-qualified symbols it found.
type SymbolIndexResult struct {
	Partiality Partiality `json:"partiality"`
	Symbols    []Symbol   `json:"symbols"`
}

// SymbolResolutionResult is ResolveDependencySymbols' response: the given advisory
// symbols mapped onto concrete symbols in this codebase.
type SymbolResolutionResult struct {
	Partiality Partiality `json:"partiality"`
	Resolved   []Symbol   `json:"resolved"` // advisory symbol → concrete codebase symbols
}

// CallEdge is one directed call-graph edge by SCIP symbol id.
type CallEdge struct {
	Caller string `json:"caller"`
	Callee string `json:"callee"`
}

// CallGraphResult is CallGraph's response: the graph edges and roots actually built,
// plus which algorithm produced them.
type CallGraphResult struct {
	Partiality Partiality `json:"partiality"`
	Algorithm  string     `json:"algorithm"` // the algorithm actually used
	Edges      []CallEdge `json:"edges"`
	Roots      []string   `json:"roots"` // entrypoint symbols (main, init, etc.)
}

// Ingress is one framework-idiomatic entry point.
type Ingress struct {
	Kind     string `json:"kind"`     // "http_route" | "main" | "handler" | ...
	Symbol   string `json:"symbol"`   // SCIP id of the entry function
	Selector string `json:"selector"` // e.g. "GET /users/{id}" when known
}

// IngressResult is FindIngresses' response: the entry points found in the codebase.
type IngressResult struct {
	Partiality Partiality `json:"partiality"`
	Ingresses  []Ingress  `json:"ingresses"`
}

// ReachPath is one govulncheck-derived (ingress, sink, path) trace.
type ReachPath struct {
	Sink    string   `json:"sink"`              // vuln symbol SCIP id (the resolved sink)
	Ingress string   `json:"ingress,omitempty"` // entrypoint symbol; empty if unknown (partial)
	Trace   []string `json:"trace"`             // ordered SCIP ids ingress→sink
}

// ReachabilityResult is Reachability's response: the candidate (ingress, sink, path)
// traces the plugin found, reconciling govulncheck with the call graph.
type ReachabilityResult struct {
	Partiality Partiality  `json:"partiality"`
	Paths      []ReachPath `json:"paths"`
	// ScanToolchain is the Go toolchain the analysis ACTUALLY executed under, populated only when
	// the request asked for one (ReachabilityRequest.GoToolchain). It equals the requested version
	// exactly when the request was honored; any other value — including empty — means it was not,
	// and the caller must treat the empty path set as evidence about the analyzer's toolchain
	// rather than the subject's. It is a measurement, never a promise: the caller compares.
	ScanToolchain string `json:"scan_toolchain,omitempty"`
}

// --- stub-only results ---

// ComputeTaintRequest carries the buildable module and the resolved sinks to trace
// source→sink flows toward. Phase-1 Go: Unsupported.
type ComputeTaintRequest struct {
	BuildDir string   `json:"build_dir"`
	Sinks    []string `json:"sinks,omitempty"` // resolved sink SCIP ids to trace toward
}

// TaintResult is ComputeTaint's response: the source→sink graph paths found.
type TaintResult struct {
	Partiality Partiality `json:"partiality"`
	// Paths holds the ingress→sink graph paths that exist over the call graph.
	// Minimal taint is call-graph PATH PRESENCE, not variable-level dataflow —
	// PrecisionNote records that limit so the result never overclaims dataflow.
	Paths         []ReachPath `json:"paths,omitempty"`
	PrecisionNote string      `json:"precision_note,omitempty"`
}

// GenerateHarnessRequest names the sink (and optionally the ingress) to scaffold a
// reproducer harness for. Phase-1 Go: Unsupported.
type GenerateHarnessRequest struct {
	Sink    string `json:"sink"`
	Ingress string `json:"ingress,omitempty"`
	Kind    string `json:"kind"` // "fuzz" | "unit" | "integration"
}

// HarnessResult is GenerateHarness's response: the generated reproducer skeleton.
type HarnessResult struct {
	Partiality Partiality `json:"partiality"`
	// Source is the generated runnable reproducer SKELETON (Go source text) that
	// imports the sink's package and calls the sink symbol. Skeleton is always
	// true: it compiles structurally but does NOT prove exploitability.
	Source   string `json:"source,omitempty"`
	Skeleton bool   `json:"skeleton,omitempty"`
}

// BuildManifestRequest carries the buildable module to derive a build manifest for.
// Phase-1 Go: Unsupported.
type BuildManifestRequest struct {
	BuildDir string `json:"build_dir"`
}

// BuildManifestResult is BuildManifest's response: enough to build and run the app
// under test.
type BuildManifestResult struct {
	Partiality Partiality `json:"partiality"`
	// Module/GoVersion/BuildCommand are derived from a single-module go.mod parse.
	Module       string `json:"module,omitempty"`
	GoVersion    string `json:"go_version,omitempty"`
	BuildCommand string `json:"build_command,omitempty"`
	// ToolchainVersion is the manifest's explicit toolchain declaration when it carries one,
	// verbatim ("go1.21.3" from a go.mod `toolchain` directive). It is a DIFFERENT and stronger
	// floor than GoVersion (the `go` directive, a minimum LANGUAGE version) and the two are
	// reported separately so the caller can order them; neither pins the build. Empty when the
	// manifest declares no toolchain, which is the common case.
	ToolchainVersion string `json:"toolchain_version,omitempty"`
}

// StubPlugin implements LanguagePlugin with canned, in-memory results — the analog of
// episode.StubModel and the sandbox fakes. The live ops return fixed payloads; the three
// Phase-1 contract stubs return Unsupported(). It performs no I/O, no subprocess, no
// network, so it backs the hermetic test suite and the pipeline seam tests.
//
// When Partial is true, the live ops flip their Partiality to declared-partial (keeping a
// reachable-but-partial payload) so L3's seam test can exercise the CandidatePair.Partial
// = true mapping.
type StubPlugin struct {
	// Partial flips the live ops to declared-partial results.
	Partial bool
}

var _ LanguagePlugin = StubPlugin{}

// stubLivePartiality returns the partiality the live ops should carry given the variant.
func (p StubPlugin) stubLivePartiality() Partiality {
	if p.Partial {
		return Partial(PartialReasonDynamicDispatch)
	}
	return Complete()
}

// Language returns "go" — StubPlugin always identifies as the Go plugin.
func (StubPlugin) Language() string { return "go" }

// IndexSymbols returns one canned Symbol. Live op — see StubPlugin: the result is a
// fixed fixture, not a real index, and embedding StubPlugin to override only some
// methods leaves this one fabricating evidence.
func (p StubPlugin) IndexSymbols(_ context.Context, _ IndexSymbolsRequest) (SymbolIndexResult, error) {
	return SymbolIndexResult{
		Partiality: p.stubLivePartiality(),
		Symbols: []Symbol{
			{SCIP: "scip:stub#Foo", DisplayName: "example.com/stub.Foo", Package: "example.com/stub"},
		},
	}, nil
}

// ResolveDependencySymbols returns one canned resolved Symbol. Live op — see
// StubPlugin: the result is a fixed fixture, not a real resolution, and embedding
// StubPlugin to override only some methods leaves this one fabricating evidence.
func (p StubPlugin) ResolveDependencySymbols(_ context.Context, _ ResolveSymbolsRequest) (SymbolResolutionResult, error) {
	return SymbolResolutionResult{
		Partiality: p.stubLivePartiality(),
		Resolved: []Symbol{
			{SCIP: "scip:vuln#Vulnerable", DisplayName: "example.com/dep.Vulnerable", Package: "example.com/dep"},
		},
	}, nil
}

// CallGraph returns one canned two-edge graph. Live op — see StubPlugin: the result
// is a fixed fixture, not a real call graph, and embedding StubPlugin to override
// only some methods leaves this one fabricating evidence.
func (p StubPlugin) CallGraph(_ context.Context, _ CallGraphRequest) (CallGraphResult, error) {
	return CallGraphResult{
		Partiality: p.stubLivePartiality(),
		Algorithm:  "vta",
		Edges: []CallEdge{
			{Caller: "scip:stub#main", Callee: "scip:stub#Foo"},
			{Caller: "scip:stub#Foo", Callee: "scip:vuln#Vulnerable"},
		},
		Roots: []string{"scip:stub#main"},
	}, nil
}

// FindIngresses returns one canned "main" ingress. Live op — see StubPlugin: the
// result is a fixed fixture, not a real scan, and embedding StubPlugin to override
// only some methods leaves this one fabricating evidence.
func (p StubPlugin) FindIngresses(_ context.Context, _ FindIngressesRequest) (IngressResult, error) {
	return IngressResult{
		Partiality: p.stubLivePartiality(),
		Ingresses: []Ingress{
			{Kind: "main", Symbol: "scip:stub#main", Selector: ""},
		},
	}, nil
}

// Reachability returns one canned ingress-to-sink path. Live op — see StubPlugin:
// the result is a fixed fixture, not a real reachability analysis, and embedding
// StubPlugin to override only some methods leaves this one fabricating evidence.
func (p StubPlugin) Reachability(_ context.Context, _ ReachabilityRequest) (ReachabilityResult, error) {
	return ReachabilityResult{
		Partiality: p.stubLivePartiality(),
		Paths: []ReachPath{
			{
				Sink:    "scip:vuln#Vulnerable",
				Ingress: "scip:stub#main",
				Trace:   []string{"scip:stub#main", "scip:stub#Foo", "scip:vuln#Vulnerable"},
			},
		},
	}, nil
}

// ResolveDependencyVersions is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) ResolveDependencyVersions(_ context.Context, _ ResolveVersionsRequest) (DependencyVersionResult, error) {
	return DependencyVersionResult{Partiality: Unsupported()}, nil
}

// ComputeTaint is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) ComputeTaint(_ context.Context, _ ComputeTaintRequest) (TaintResult, error) {
	return TaintResult{Partiality: Unsupported()}, nil
}

// GenerateHarness is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) GenerateHarness(_ context.Context, _ GenerateHarnessRequest) (HarnessResult, error) {
	return HarnessResult{Partiality: Unsupported()}, nil
}

// BuildManifest is a Phase-1 contract stub: it always returns Unsupported.
func (StubPlugin) BuildManifest(_ context.Context, _ BuildManifestRequest) (BuildManifestResult, error) {
	return BuildManifestResult{Partiality: Unsupported()}, nil
}
